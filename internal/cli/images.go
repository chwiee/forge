package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/spf13/cobra"

	"github.com/chwiee/forge/internal/builder"
	"github.com/chwiee/forge/internal/emulation"
	"github.com/chwiee/forge/internal/registry"
	"github.com/chwiee/forge/internal/ui"
)

// OCI layout annotation recording whether the image passed forge's gates.
const (
	gatesAnnotation = "dev.forge.gates"
	gatesPassed     = "passed"
	gatesFailed     = "failed"
	gatesUnscanned  = "unscanned"
)

// saveRuns writes every platform image into one OCI layout directory.
func saveRuns(runs []*platformRun, dir, gates string) error {
	_ = os.RemoveAll(dir)
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		return err
	}
	for _, r := range runs {
		plat := r.platform
		if err := p.AppendImage(r.image, layout.WithPlatform(plat),
			layout.WithAnnotations(map[string]string{gatesAnnotation: gates})); err != nil {
			return err
		}
	}
	return nil
}

// source is one image found in an OCI layout or a registry reference.
type source struct {
	image    v1.Image
	platform v1.Platform
	gates    string // passed | failed | unscanned | "" (registry: pushed by a gated run)
	from     string
}

// loadSources expands OCI layout dirs and registry refs (images or indexes) into images.
func loadSources(ctx context.Context, srcs []string) ([]source, error) {
	var out []source
	for _, src := range srcs {
		if fi, err := os.Stat(src); err == nil && fi.IsDir() {
			p, err := layout.FromPath(src)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", src, err)
			}
			idx, err := p.ImageIndex()
			if err != nil {
				return nil, err
			}
			m, err := idx.IndexManifest()
			if err != nil {
				return nil, err
			}
			for _, d := range m.Manifests {
				img, err := idx.Image(d.Digest)
				if err != nil {
					return nil, err
				}
				plat, err := platformOf(img, d.Platform)
				if err != nil {
					return nil, err
				}
				g := d.Annotations[gatesAnnotation]
				if g == "" {
					g = gatesUnscanned
				}
				out = append(out, source{image: img, platform: plat, gates: g, from: src})
			}
			continue
		}
		ref, err := name.ParseReference(src)
		if err != nil {
			return nil, fmt.Errorf("%s: not a directory nor an image reference", src)
		}
		desc, err := remote.Get(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(registry.Keychain()))
		if err != nil {
			return nil, err
		}
		if desc.MediaType.IsIndex() {
			idx, err := desc.ImageIndex()
			if err != nil {
				return nil, err
			}
			m, err := idx.IndexManifest()
			if err != nil {
				return nil, err
			}
			for _, d := range m.Manifests {
				if d.Platform == nil || d.Platform.OS == "unknown" { // attestation manifests
					continue
				}
				img, err := idx.Image(d.Digest)
				if err != nil {
					return nil, err
				}
				out = append(out, source{image: img, platform: *d.Platform, from: src})
			}
			continue
		}
		img, err := desc.Image()
		if err != nil {
			return nil, err
		}
		plat, err := platformOf(img, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, source{image: img, platform: plat, from: src})
	}
	return out, nil
}

func platformOf(img v1.Image, hint *v1.Platform) (v1.Platform, error) {
	if hint != nil && hint.Architecture != "" {
		return *hint, nil
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return v1.Platform{}, err
	}
	return v1.Platform{OS: cf.OS, Architecture: cf.Architecture, Variant: cf.Variant}, nil
}

// ---- build ----

func newBuildCmd(g *globalFlags) *cobra.Command {
	bf := &buildFlags{}
	var ociOut, tarOut, tarRef string
	c := &cobra.Command{
		Use:   "build [context]",
		Short: "Build and slim only; save as OCI layout (and/or docker tar). No scan, no push",
		Example: `  forge build . --oci .forge/image
  forge build . --platform linux/amd64,linux/arm64 --oci .forge/image
  forge build . --tar app.tar --tar-ref myapp:dev`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contextDir := "."
			if len(args) == 1 {
				contextDir = args[0]
			}
			contextDir, _ = filepath.Abs(contextDir)
			platforms, err := builder.ParsePlatforms(bf.platforms)
			if err != nil {
				return err
			}
			multi := len(platforms) > 1
			if multi && tarOut != "" {
				return fmt.Errorf("--tar holds a single platform; use --oci for multi-platform builds")
			}
			u := ui.New(g.verbose)
			defer u.Close()
			u.Banner(Version, "build · slim")
			u.Info("context", contextDir)
			warnWindowsMount(u, contextDir, g.cacheDir)

			var runs []*platformRun
			for _, p := range platforms {
				label := platformLabel(p, multi)
				u.Line("")
				if multi {
					u.Line("  " + u.Accent("◆ "+builder.PlatformString(p)))
				}
				res, err := doBuild(cmd.Context(), u, g, bf, contextDir, p, label)
				if err != nil {
					return err
				}
				sr, err := doSlim(u, g, bf, res, label)
				if err != nil {
					return err
				}
				runs = append(runs, &platformRun{platform: res.Platform, image: sr.Image})
			}
			u.Line("")
			st := u.Start("Save")
			var out []string
			if ociOut != "" {
				if err := saveRuns(runs, ociOut, gatesUnscanned); err != nil {
					st.Fail("failed")
					return err
				}
				out = append(out, "oci:"+ociOut)
			}
			if tarOut != "" {
				ref, err := name.NewTag(tarRef)
				if err != nil {
					return err
				}
				if err := tarball.WriteToFile(tarOut, ref, runs[0].image); err != nil {
					st.Fail("failed")
					return err
				}
				out = append(out, "tar:"+tarOut)
			}
			st.Done(strings.Join(out, " · "))
			u.Line("")
			return nil
		},
	}
	bf.register(c)
	c.Flags().StringVar(&ociOut, "oci", ".forge/image", "OCI layout output directory (input for forge scan/push)")
	c.Flags().StringVar(&tarOut, "tar", "", "also write a docker-archive tar (single platform; docker load / kind load)")
	c.Flags().StringVar(&tarRef, "tar-ref", "forge.local/app:latest", "image name stored inside the tar")
	return c
}

// ---- scan ----

func newScanCmd(g *globalFlags) *cobra.Command {
	gf := &gateFlags{}
	var jsonOut, platformFilter string
	c := &cobra.Command{
		Use:   "scan <oci-dir | image-ref>",
		Short: "Scan an image (every platform of a multi-arch image) for CVEs",
		Example: `  forge scan .forge/image
  forge scan ghcr.io/acme/api:1.2.0 --fail-on high
  forge scan ghcr.io/acme/api:1.2.0 --platform linux/arm64`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			u := ui.New(g.verbose)
			defer u.Close()
			u.Banner(Version, "scan")
			u.Info("image", args[0])
			srcs, err := loadSources(cmd.Context(), args)
			if err != nil {
				return err
			}
			srcs, err = filterPlatforms(srcs, platformFilter)
			if err != nil {
				return err
			}
			multi := len(srcs) > 1
			failed := []string{}
			results := map[string]any{}
			for _, s := range srcs {
				u.Line("")
				label := platformLabel(s.platform, multi)
				r, err := doScan(cmd.Context(), u, g, gf, nil, s.image, label, sbomFor(gf.sbom, s.platform, multi))
				if err != nil {
					return err
				}
				title := ""
				if multi {
					title = builder.PlatformString(s.platform)
				}
				printDetails(u, title, r, nil, nil, gf.policy(), detailCtx{})
				results[builder.PlatformString(s.platform)] = r
				if r.Failed {
					failed = append(failed, builder.PlatformString(s.platform)+": "+r.Reason)
				}
			}
			u.Line("")
			if jsonOut != "" {
				b, _ := json.MarshalIndent(results, "", "  ")
				if err := os.WriteFile(jsonOut, b, 0o644); err != nil {
					return err
				}
			}
			if len(failed) > 0 {
				return &gateError{msg: strings.Join(failed, "; ")}
			}
			return nil
		},
	}
	gf.register(c)
	c.Flags().StringVar(&jsonOut, "json", "", "write the CVE report(s) as JSON")
	c.Flags().StringVar(&platformFilter, "platform", "", "only these platforms of a multi-arch image")
	return c
}

func filterPlatforms(srcs []source, filter string) ([]source, error) {
	if strings.TrimSpace(filter) == "" {
		return srcs, nil
	}
	want, err := builder.ParsePlatforms(filter)
	if err != nil {
		return nil, err
	}
	var out []source
	for _, s := range srcs {
		for _, w := range want {
			if s.platform.Architecture == w.Architecture && (w.Variant == "" || s.platform.Variant == w.Variant) {
				out = append(out, s)
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no image matches --platform %s", filter)
	}
	return out, nil
}

// ---- push / manifest ----

func newPushCmd(g *globalFlags) *cobra.Command {
	gf := &gateFlags{}
	pf := &pushFlags{}
	var skipScan bool
	c := &cobra.Command{
		Use:     "push <oci-dir | image-ref>...",
		Aliases: []string{"manifest"},
		Short:   "Push one image, or join several (one per platform) into a multi-arch tag",
		Long: `Pushes images produced by forge. With several sources — OCI dirs from native
runners (forge run --no-push --oci ...) or images already in a registry — it
publishes ONE multi-arch tag (manifest list / OCI index).

Gate rules: sources marked "failed" by forge run are refused; "unscanned"
sources (forge build, or OCI written elsewhere) are scanned first.`,
		Example: `  # two native runners, then one job joins them:
  forge run . --no-push --oci out/amd64            # x86 runner
  forge run . --no-push --oci out/arm64            # Graviton runner
  forge manifest out/amd64 out/arm64 --registry ecr --name api --tag v1`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if pf.registry == "" {
				return fmt.Errorf("--registry ecr|ghcr is required")
			}
			u := ui.New(g.verbose)
			defer u.Close()
			u.Banner(Version, "push")
			target, err := registry.Resolve(ctx, pf.options())
			if err != nil {
				return err
			}
			u.Info("target", u.Value(target.String()))
			srcs, err := loadSources(ctx, args)
			if err != nil {
				return err
			}
			// one image per platform
			seen := map[string]string{}
			for _, s := range srcs {
				k := builder.PlatformString(s.platform)
				if prev, dup := seen[k]; dup {
					return fmt.Errorf("platform %s appears twice (%s and %s)", k, prev, s.from)
				}
				seen[k] = s.from
			}
			multi := len(srcs) > 1
			keys := make([]string, 0, len(seen))
			for k := range seen {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			u.Info("platforms", u.Value(strings.Join(keys, " · ")))

			for _, s := range srcs {
				label := platformLabel(s.platform, multi)
				switch {
				case s.gates == gatesFailed:
					u.Line("")
					u.Start("Push").Fail(builder.PlatformString(s.platform) + " failed forge gates in " + s.from)
					return &gateError{msg: "refusing to publish an image that failed the gates"}
				case s.gates == gatesUnscanned && !skipScan:
					u.Line("")
					r, err := doScan(ctx, u, g, gf, nil, s.image, label, "")
					if err != nil {
						return err
					}
					if r.Failed {
						printDetails(u, builder.PlatformString(s.platform), r, nil, nil, gf.policy(), detailCtx{})
						u.Start("Push").Fail("blocked: " + r.Reason)
						return &gateError{msg: r.Reason}
					}
				}
			}
			if skipScan {
				u.Warn("--skip-scan: pushing without the CVE gate")
			}

			var art registry.Artifact = srcs[0].image
			if multi {
				items := make([]registry.PlatformImage, len(srcs))
				for i, s := range srcs {
					items[i] = registry.PlatformImage{Image: s.image, Platform: s.platform}
				}
				if art, err = registry.Index(items); err != nil {
					return err
				}
			}
			u.Line("")
			if _, err := doPush(ctx, u, art, target); err != nil {
				return err
			}
			u.Line("")
			return nil
		},
	}
	gf.register(c)
	pf.register(c)
	c.Flags().BoolVar(&skipScan, "skip-scan", false, "push unscanned sources without the CVE gate (not recommended)")
	return c
}

// ---- emulation ----

func newEmulationCmd(g *globalFlags) *cobra.Command {
	c := &cobra.Command{Use: "emulation", Short: "QEMU emulation for foreign-architecture RUN steps (binfmt_misc)"}
	c.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show which architectures can run here",
		RunE: func(*cobra.Command, []string) error {
			u := ui.New(false)
			defer u.Close()
			u.Banner(Version, "emulation")
			hs, err := emulation.Status()
			if err != nil {
				u.Warn(err.Error())
			}
			byArch := map[string]emulation.Handler{}
			for _, h := range hs {
				byArch[h.Arch] = h
			}
			for _, a := range emulation.Supported() {
				switch h, ok := byArch[a]; {
				case emulation.Native(v1.Platform{Architecture: a}):
					u.Line(fmt.Sprintf("  %s %-8s %s", u.Good("✔"), a, u.Muted("native")))
				case ok && h.Enabled:
					owner := "registered by another tool"
					if h.Ours {
						owner = "registered by forge"
					}
					u.Line(fmt.Sprintf("  %s %-8s %s", u.Good("✔"), a, u.Muted("emulated · "+owner+" · "+h.Interpreter)))
				default:
					u.Line(fmt.Sprintf("  %s %-8s %s", u.Muted("○"), a, u.Muted("enabled on demand (needs root)")))
				}
			}
			u.Line("")
			return nil
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "install [arch...]",
		Short: "Enable emulation now (default: arm64 on x86, amd64 on arm)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				if builder.HostPlatform().Architecture == "amd64" {
					args = []string{"arm64"}
				} else {
					args = []string{"amd64"}
				}
			}
			m := &emulation.Manager{CacheDir: g.cacheDir, Keychain: remote.WithAuthFromKeychain(registry.Keychain())}
			for _, a := range args {
				a = builder.PlatformArch(a)
				if err := m.Ensure(cmd.Context(), a); err != nil {
					return err
				}
				fmt.Printf("✔ %s ready\n", a)
			}
			return nil
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "uninstall",
		Short: "Remove the handlers forge registered",
		RunE: func(*cobra.Command, []string) error {
			n, err := emulation.Uninstall()
			if err != nil {
				return err
			}
			fmt.Printf("removed %d handler(s)\n", n)
			return nil
		},
	})
	return c
}
