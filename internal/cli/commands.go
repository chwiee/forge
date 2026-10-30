package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/spf13/cobra"

	"github.com/chwiee/forge/internal/cache"
	"github.com/chwiee/forge/internal/dbmirror"
	"github.com/chwiee/forge/internal/registry"
	"github.com/chwiee/forge/internal/sandbox"
	"github.com/chwiee/forge/internal/scan"
	"github.com/chwiee/forge/internal/ui"
)

// ---- build ----

func newBuildCmd(g *globalFlags) *cobra.Command {
	bf := &buildFlags{}
	var ociOut, tarOut, tarRef string
	c := &cobra.Command{
		Use:   "build [context]",
		Short: "Build and slim only; save the image as OCI layout (and/or docker tar)",
		Example: `  forge build . --oci .forge/image
  forge build . --tar app.tar --tar-ref myapp:dev`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contextDir := "."
			if len(args) == 1 {
				contextDir = args[0]
			}
			contextDir, _ = filepath.Abs(contextDir)
			u := ui.New(g.verbose)
			defer u.Close()
			u.Banner(Version, "build · slim")
			u.Info("context", contextDir)
			warnWindowsMount(u, contextDir, g.cacheDir)
			u.Line("")
			res, err := doBuild(cmd.Context(), u, g, bf, contextDir)
			if err != nil {
				return err
			}
			sr, err := doSlim(u, g, bf, res)
			if err != nil {
				return err
			}
			st := u.Start("Save")
			var out []string
			if ociOut != "" {
				if err := saveOCI(sr.Image, ociOut); err != nil {
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
				if err := tarball.WriteToFile(tarOut, ref, sr.Image); err != nil {
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
	c.Flags().StringVar(&tarOut, "tar", "", "also write a docker-archive tar (docker load / kind load)")
	c.Flags().StringVar(&tarRef, "tar-ref", "forge.local/app:latest", "image name stored inside the tar")
	return c
}

func saveOCI(img v1.Image, dir string) error {
	_ = os.RemoveAll(dir)
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		return err
	}
	return p.AppendImage(img)
}

// loadImage reads an OCI layout dir or pulls a registry reference.
func loadImage(ctx context.Context, src string) (v1.Image, error) {
	if fi, err := os.Stat(src); err == nil && fi.IsDir() {
		p, err := layout.FromPath(src)
		if err != nil {
			return nil, err
		}
		idx, err := p.ImageIndex()
		if err != nil {
			return nil, err
		}
		m, err := idx.IndexManifest()
		if err != nil {
			return nil, err
		}
		if len(m.Manifests) == 0 {
			return nil, fmt.Errorf("%s: empty OCI layout", src)
		}
		return idx.Image(m.Manifests[len(m.Manifests)-1].Digest)
	}
	ref, err := name.ParseReference(src)
	if err != nil {
		return nil, err
	}
	return remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(registry.Keychain()),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: hostArch()}))
}

// ---- scan ----

func newScanCmd(g *globalFlags) *cobra.Command {
	gf := &gateFlags{}
	var jsonOut string
	c := &cobra.Command{
		Use:   "scan <oci-dir | image-ref>",
		Short: "Scan an image for CVEs (Grype)",
		Example: `  forge scan .forge/image
  forge scan ghcr.io/acme/api:1.2.0 --fail-on high`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			u := ui.New(g.verbose)
			defer u.Close()
			u.Banner(Version, "scan")
			u.Info("image", args[0])
			u.Line("")
			img, err := loadImage(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			r, err := doScan(cmd.Context(), u, g, gf, img)
			if err != nil {
				return err
			}
			printDetails(u, r, nil, nil)
			u.Line("")
			if jsonOut != "" {
				b, _ := json.MarshalIndent(r, "", "  ")
				if err := os.WriteFile(jsonOut, b, 0o644); err != nil {
					return err
				}
			}
			if r.Failed {
				return &gateError{msg: r.Reason}
			}
			return nil
		},
	}
	gf.register(c)
	c.Flags().StringVar(&jsonOut, "json", "", "write the CVE report as JSON")
	return c
}

// ---- push ----

func newPushCmd(g *globalFlags) *cobra.Command {
	gf := &gateFlags{}
	pf := &pushFlags{}
	var skipScan bool
	c := &cobra.Command{
		Use:     "push <oci-dir>",
		Short:   "Push a built image (CVE gate runs first)",
		Example: `  forge build . && forge push .forge/image --registry ghcr --name api --tag v1`,
		Args:    cobra.ExactArgs(1),
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
			u.Line("")
			img, err := loadImage(ctx, args[0])
			if err != nil {
				return err
			}
			if !skipScan {
				r, err := doScan(ctx, u, g, gf, img)
				if err != nil {
					return err
				}
				if r.Failed {
					st := u.Start("Push")
					st.Fail("blocked: " + r.Reason)
					printDetails(u, r, nil, nil)
					return &gateError{msg: r.Reason}
				}
			} else {
				u.Warn("--skip-scan: pushing without the CVE gate")
			}
			if _, err := doPush(ctx, u, img, target); err != nil {
				return err
			}
			u.Line("")
			return nil
		},
	}
	gf.register(c)
	pf.register(c)
	c.Flags().BoolVar(&skipScan, "skip-scan", false, "push without the CVE gate (not recommended)")
	return c
}

// ---- db ----

func newDBCmd(g *globalFlags) *cobra.Command {
	c := &cobra.Command{Use: "db", Short: "Vulnerability database: update, mirror, serve"}

	var dir, upstream, addr string
	var every time.Duration

	sync := &cobra.Command{
		Use:   "sync",
		Short: "Download the latest Grype DB archive into a mirror directory",
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := dbmirror.Sync(cmd.Context(), dir, upstream)
			if err != nil {
				return err
			}
			b, _ := json.MarshalIndent(st, "", "  ")
			fmt.Println(string(b))
			return nil
		},
	}
	sync.Flags().StringVar(&dir, "dir", "/data/grype", "mirror directory")
	sync.Flags().StringVar(&upstream, "upstream", dbmirror.DefaultUpstream, "upstream distribution URL")

	serve := &cobra.Command{
		Use:   "serve",
		Short: "Serve the DB mirror over HTTP and re-sync on an interval (run as a pod)",
		Long: `Runs a small HTTP server with the same layout as grype.anchore.io.
Runners use it with:  FORGE_DB_URL=http://<service>:8080/databases`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s := &dbmirror.Server{Dir: dir, Upstream: upstream, Every: every, Log: slog.New(slog.NewJSONHandler(os.Stdout, nil))}
			return s.Run(cmd.Context(), addr)
		},
	}
	serve.Flags().StringVar(&dir, "dir", "/data/grype", "mirror directory")
	serve.Flags().StringVar(&upstream, "upstream", dbmirror.DefaultUpstream, "upstream distribution URL")
	serve.Flags().StringVar(&addr, "addr", ":8080", "listen address")
	serve.Flags().DurationVar(&every, "sync-every", 24*time.Hour, "re-sync interval")

	var dbURL string
	update := &cobra.Command{
		Use:   "update",
		Short: "Update the local DB cache used by scans (warm a runner cache)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, info, err := scan.LoadDB(scan.Options{CacheDir: g.cacheDir, DBURL: dbURL, Version: Version})
			if err != nil {
				return err
			}
			fmt.Printf("vulnerability DB ready: built %s (schema %s) from %s\n", info.Built.Format(time.RFC3339), info.Schema, info.Source)
			return nil
		},
	}
	update.Flags().StringVar(&dbURL, "db-url", os.Getenv("FORGE_DB_URL"), "mirror URL [$FORGE_DB_URL]")

	c.AddCommand(sync, serve, update)
	return c
}

// ---- cache ----

func newCacheCmd(g *globalFlags) *cobra.Command {
	c := &cobra.Command{Use: "cache", Short: "Inspect or prune the build cache"}
	c.AddCommand(&cobra.Command{
		Use:   "ls",
		Short: "Show cache usage",
		RunE: func(*cobra.Command, []string) error {
			s, err := cache.Open(filepath.Join(g.cacheDir, "layers"))
			if err != nil {
				return err
			}
			st, _ := s.Stat()
			fmt.Printf("cache dir   %s\nstep keys   %d\nlayers      %d (%s)\nbase images %s\nvuln DB     %s\n",
				g.cacheDir, st.Keys, st.Blobs, ui.HumanBytes(st.Bytes),
				ui.HumanBytes(dirSize(filepath.Join(g.cacheDir, "images"))), ui.HumanBytes(dirSize(filepath.Join(g.cacheDir, "grype-db"))))
			return nil
		},
	})
	var olderThan time.Duration
	var all bool
	prune := &cobra.Command{
		Use:   "prune",
		Short: "Remove cache entries not used recently",
		RunE: func(*cobra.Command, []string) error {
			if all {
				for _, d := range []string{"layers", "images", "work"} {
					_ = os.RemoveAll(filepath.Join(g.cacheDir, d))
				}
				fmt.Println("cache cleared (vulnerability DB kept)")
				return nil
			}
			s, err := cache.Open(filepath.Join(g.cacheDir, "layers"))
			if err != nil {
				return err
			}
			n, freed, err := s.Prune(time.Now().Add(-olderThan))
			if err != nil {
				return err
			}
			fmt.Printf("removed %d layers, freed %s\n", n, ui.HumanBytes(freed))
			return nil
		},
	}
	prune.Flags().DurationVar(&olderThan, "older-than", 7*24*time.Hour, "remove steps unused for this long")
	prune.Flags().BoolVar(&all, "all", false, "remove everything except the vulnerability DB")
	c.AddCommand(prune)
	return c
}

func dirSize(p string) int64 {
	var n int64
	_ = filepath.Walk(p, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			n += fi.Size()
		}
		return nil
	})
	return n
}

// ---- doctor ----

func newDoctorCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check what this machine/pod supports (isolation, cache, DB, credentials)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			u := ui.New(false)
			defer u.Close()
			u.Banner(Version, "doctor")
			ok := func(k, v string) { u.Line(fmt.Sprintf("  %s %-11s %s", u.Good("✔"), k, v)) }
			warn := func(k, v string) { u.Line(fmt.Sprintf("  %s %-11s %s", u.Warning("▲"), k, v)) }
			bad := func(k, v string) { u.Line(fmt.Sprintf("  %s %-11s %s", u.Bad("✖"), k, v)) }

			ok("user", fmt.Sprintf("uid=%d", os.Geteuid()))
			switch lvl := sandbox.Level(); lvl {
			case sandbox.Full:
				ok("isolation", "full (namespaces + /proc + chroot)")
			case sandbox.UserNS:
				ok("isolation", "user namespace (root, no CAP_SYS_ADMIN needed) + /proc + chroot")
			case sandbox.Rootless:
				warn("isolation", "rootless user namespace: USER/chown inside RUN map to root")
			case sandbox.Chroot:
				warn("isolation", "chroot only: RUN works but without /proc (Go/Java/.NET builds may fail).")
				u.Line("              " + u.Muted("fix: pod seccompProfile Unconfined (+ AppArmor unconfined on Ubuntu nodes), or add CAP_SYS_ADMIN"))
			default:
				bad("isolation", "none: run as root or enable unprivileged user namespaces")
			}
			if err := os.MkdirAll(g.cacheDir, 0o755); err != nil {
				bad("cache", err.Error())
			} else {
				ok("cache", g.cacheDir)
			}
			warnWindowsMount(u, g.cacheDir)
			if url := os.Getenv("FORGE_DB_URL"); url != "" {
				ok("db mirror", url)
			} else {
				warn("db mirror", "FORGE_DB_URL not set: DB comes from grype.anchore.io")
			}
			if os.Getenv("GITHUB_TOKEN") != "" || os.Getenv("GHCR_TOKEN") != "" {
				ok("ghcr", "token found in environment")
			} else {
				warn("ghcr", "no GHCR_TOKEN/GITHUB_TOKEN (docker config.json is used if present)")
			}
			if os.Getenv("AWS_REGION") != "" || os.Getenv("AWS_PROFILE") != "" || os.Getenv("AWS_ROLE_ARN") != "" || os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") != "" {
				ok("ecr", "AWS environment detected")
			} else {
				warn("ecr", "no AWS env vars (instance/pod identity or ~/.aws may still work)")
			}
			u.Line("")
			return nil
		},
	}
}
