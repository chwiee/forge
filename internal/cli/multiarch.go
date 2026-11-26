package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/chwiee/forge/internal/builder"
	"github.com/chwiee/forge/internal/registry"
	"github.com/chwiee/forge/internal/ui"
)

// Distributed multi-arch: one runner per architecture (e.g. a GitHub Actions
// matrix on ARC runner pods scheduled by Karpenter on amd64 and arm64 nodes).
//
//	each runner: build natively → gates → push <tag>-<arch> labelled with the
//	             build id → if every expected arch of this build id is in the
//	             registry, write the multi-arch index to <tag>
//
// Safe without a join job and without registry locking: every runner pushes
// before it checks, so the last one to check always sees all architectures;
// when two runners both see them, they write the same index byte for byte.
const (
	labelBuildID  = "dev.forge.build-id"
	labelGates    = "dev.forge.gates"
	labelPlatform = "dev.forge.platform"
)

// defaultBuildID identifies one CI execution; it must be equal on every runner.
func defaultBuildID() string {
	switch {
	case os.Getenv("GITHUB_RUN_ID") != "":
		return os.Getenv("GITHUB_RUN_ID") + "-" + envOr("GITHUB_RUN_ATTEMPT", "1")
	case os.Getenv("CI_PIPELINE_ID") != "":
		return "gl-" + os.Getenv("CI_PIPELINE_ID")
	case os.Getenv("BUILD_BUILDID") != "":
		return "ado-" + os.Getenv("BUILD_BUILDID")
	}
	return ""
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// archSuffix is the per-architecture tag suffix: amd64, arm64, armv7.
func archSuffix(p v1.Platform) string { return p.Architecture + p.Variant }

// ownPlatform picks the platform this runner builds in --multiarch mode.
func ownPlatform(expected []v1.Platform, requested string) (v1.Platform, error) {
	own := builder.HostPlatform()
	if requested != "" {
		ps, err := builder.ParsePlatforms(requested)
		if err != nil {
			return own, err
		}
		if len(ps) != 1 {
			return own, fmt.Errorf("with --multiarch, --platform selects the one platform this runner builds")
		}
		own = ps[0]
	}
	for _, p := range expected {
		if p.Architecture == own.Architecture && (p.Variant == "" || p.Variant == own.Variant) {
			return p, nil
		}
	}
	return own, fmt.Errorf("this runner is %s, which is not in --multiarch", builder.PlatformString(own))
}

// stamp records the build id and gate result in the image config labels.
func stamp(img v1.Image, buildID string, p v1.Platform) (v1.Image, error) {
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	cfg := cf.Config
	labels := map[string]string{}
	for k, v := range cfg.Labels {
		labels[k] = v
	}
	labels[labelBuildID] = buildID
	labels[labelGates] = gatesPassed
	labels[labelPlatform] = builder.PlatformString(p)
	if sha := envOr("GITHUB_SHA", os.Getenv("CI_COMMIT_SHA")); sha != "" {
		labels["org.opencontainers.image.revision"] = sha
	}
	cfg.Labels = labels
	return mutate.Config(img, cfg)
}

// stagingTarget is the same repository with <tag>-<arch> tags.
func stagingTarget(t *registry.Target, p v1.Platform) *registry.Target {
	st := *t
	st.Tags = make([]string, len(t.Tags))
	for i, tag := range t.Tags {
		st.Tags[i] = tag + "-" + archSuffix(p)
	}
	return &st
}

// publishArch pushes this runner's image and joins the multi-arch tag when complete.
func publishArch(ctx context.Context, u *ui.UI, img v1.Image, p v1.Platform, t *registry.Target, expected []v1.Platform, buildID string) (archRef, indexDigest string, joined bool, err error) {
	img, err = stamp(img, buildID, p)
	if err != nil {
		return "", "", false, err
	}
	staging := stagingTarget(t, p)
	if _, err := doPush(ctx, u, img, staging); err != nil {
		return "", "", false, err
	}
	archRef = staging.String()

	st := u.Start("Join")
	st.Detail("checking the other architectures of build "+buildID, false)
	var items []registry.PlatformImage
	var missing []string
	for _, want := range expected {
		ref := t.Repo.Tag(t.Tags[0] + "-" + archSuffix(want))
		other, err := remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(registry.Keychain()))
		if err != nil {
			missing = append(missing, builder.PlatformString(want))
			continue
		}
		cf, err := other.ConfigFile()
		if err != nil {
			return archRef, "", false, err
		}
		if cf.Config.Labels[labelBuildID] != buildID || cf.Config.Labels[labelGates] != gatesPassed {
			// an older run's image (or one that did not pass) is never joined
			missing = append(missing, builder.PlatformString(want))
			continue
		}
		items = append(items, registry.PlatformImage{Image: other, Platform: want})
	}
	if len(missing) > 0 {
		st.Skip("waiting for " + strings.Join(missing, ", ") + " — the last runner of build " + buildID + " publishes " + t.String())
		return archRef, "", false, nil
	}
	// deterministic order: every runner that gets here writes the identical index
	sort.Slice(items, func(i, j int) bool {
		return builder.PlatformString(items[i].Platform) < builder.PlatformString(items[j].Platform)
	})
	idx, err := registry.Index(items)
	if err != nil {
		return archRef, "", false, err
	}
	st.Detail("writing multi-arch index to "+t.String(), false)
	dg, err := registry.Push(ctx, idx, t, nil)
	if err != nil {
		st.Fail("failed")
		return archRef, "", false, err
	}
	names := make([]string, len(items))
	for i, it := range items {
		names[i] = archSuffix(it.Platform)
	}
	st.Done(fmt.Sprintf("%s → %s", t.String(), strings.Join(names, " · ")))
	return archRef, dg.String(), true, nil
}
