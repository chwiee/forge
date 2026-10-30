package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/spf13/cobra"

	"github.com/chwiee/forge/internal/builder"
	"github.com/chwiee/forge/internal/ignore"
	"github.com/chwiee/forge/internal/leaks"
	"github.com/chwiee/forge/internal/registry"
	"github.com/chwiee/forge/internal/report"
	"github.com/chwiee/forge/internal/scan"
	"github.com/chwiee/forge/internal/slim"
	"github.com/chwiee/forge/internal/ui"
)

type pushFlags struct {
	registry   string
	name       string
	tags       []string
	ecrAccount string
	region     string
	owner      string
	createRepo bool
	immutable  bool
}

func (f *pushFlags) register(c *cobra.Command) {
	c.Flags().StringVar(&f.registry, "registry", "", "push target: ecr | ghcr")
	c.Flags().StringVar(&f.name, "name", "", "repository name in the registry (e.g. team/payments-api)")
	c.Flags().StringArrayVarP(&f.tags, "tag", "t", nil, "tag (repeatable; default: commit sha from CI, else latest)")
	c.Flags().StringVar(&f.ecrAccount, "ecr-account", "", "ECR account id (default: from AWS credentials) [$FORGE_ECR_ACCOUNT]")
	c.Flags().StringVar(&f.region, "region", "", "ECR region (default: AWS_REGION / AWS config) [$FORGE_ECR_REGION]")
	c.Flags().StringVar(&f.owner, "owner", "", "GHCR owner/org (default: GITHUB_REPOSITORY_OWNER) [$FORGE_GHCR_OWNER]")
	c.Flags().BoolVar(&f.createRepo, "create-repo", false, "ECR: create the repository if it does not exist")
	c.Flags().BoolVar(&f.immutable, "immutable", false, "ECR: create the repository with immutable tags")
}

func (f *pushFlags) options() registry.Options {
	return registry.Options{
		Kind: strings.ToLower(f.registry), Name: f.name, Tags: append([]string{}, f.tags...),
		ECRAccount: f.ecrAccount, Region: f.region, GHCROwner: f.owner,
		CreateRepo: f.createRepo, Immutable: f.immutable,
	}
}

// platformRun holds everything produced for one platform.
type platformRun struct {
	platform v1.Platform
	image    v1.Image
	rep      report.Platform
}

func newRunCmd(g *globalFlags) *cobra.Command {
	bf := &buildFlags{}
	gf := &gateFlags{}
	pf := &pushFlags{}
	var noPush, failFast bool
	var reportPath, ociOut string
	var jobs int

	c := &cobra.Command{
		Use:   "run [context]",
		Short: "Build → Slim → Scan → Sec → Leaks → Push, concurrently (one or many platforms)",
		Long: `Runs the whole pipeline as a dependency graph:

  registry preflight, vulnerability DB and build-context leaks start together
  with the build; each platform builds in parallel; scan, sec and leaks of an
  image run in parallel as soon as it is built; the tag is written only after
  every gate passed.

A technical error anywhere cancels everything and names the failing stage.
A failed gate lets the checks of that image finish (complete report), cancels
the remaining builds and blocks the push; --fail-fast cancels at once.`,
		Example: `  forge run . --registry ecr --name payments-api --tag v1.4.0
  forge run . --registry ghcr --name api --platform linux/amd64,linux/arm64
  forge run . --no-push --oci out/arm64     # native runner; join later with forge manifest`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contextDir := "."
			if len(args) == 1 {
				contextDir = args[0]
			}
			contextDir, _ = filepath.Abs(contextDir)
			if !noPush && pf.registry == "" {
				return fmt.Errorf("--registry ecr|ghcr is required (or use --no-push)")
			}
			platforms, err := builder.ParsePlatforms(bf.platforms)
			if err != nil {
				return err
			}
			multi := len(platforms) > 1
			if jobs <= 0 || jobs > len(platforms) {
				jobs = len(platforms)
			}

			u := ui.New(g.verbose)
			defer u.Close()
			start := time.Now()
			u.Banner(Version, "build · slim · scan · sec · leaks · push")
			u.Info("context", contextDir)
			if multi || platforms[0].Architecture != builder.HostPlatform().Architecture {
				names := make([]string, len(platforms))
				for i, p := range platforms {
					names[i] = builder.PlatformString(p)
				}
				u.Info("platforms", u.Value(strings.Join(names, " · ")))
			}
			warnWindowsMount(u, contextDir, g.cacheDir)
			u.Line("")
			u.SetConcurrent(multi)

			rep := &report.Report{Version: Version, Started: start.UTC(), Context: contextDir, Dockerfile: bf.file}
			if rep.Dockerfile == "" {
				rep.Dockerfile = filepath.Join(contextDir, "Dockerfile")
			}

			// errgroup: the first technical error cancels gctx for every task.
			grp, gctx := errgroup.WithContext(cmd.Context())
			// builds get their own context so a failed gate can stop them without
			// interrupting the checks already running.
			buildCtx, cancelBuilds := context.WithCancelCause(gctx)
			defer cancelBuilds(nil)

			// ---- preflight: registry ----
			var target *registry.Target
			if !noPush {
				grp.Go(func() error {
					st := u.Start("Registry")
					st.Detail("resolving "+pf.registry+" target", false)
					t, err := registry.Resolve(gctx, pf.options())
					if err == nil {
						st.Detail("checking push permission on "+t.String(), false)
						err = registry.Preflight(gctx, t)
					}
					if err != nil {
						if !cancelled(gctx, st) {
							st.Fail("not ready")
						}
						return stageErr("registry", err)
					}
					target = t
					st.Done(t.String() + " · push allowed")
					return nil
				})
			}

			// ---- preflight: vulnerability DB ----
			var scanner *scan.Scanner
			dbReady := make(chan struct{})
			grp.Go(func() error {
				st := u.Start("VulnDB")
				s, err := scan.Open(scan.Options{CacheDir: g.cacheDir, DBURL: gf.dbURL, Version: Version,
					OnDB: func(m string) { st.Detail(m, false) }})
				if err != nil {
					if !cancelled(gctx, st) {
						st.Fail("unavailable")
					}
					return stageErr("vulnerability DB", err)
				}
				scanner = s
				close(dbReady)
				st.Done(fmt.Sprintf("ready · built %s", s.Info().Built.Format("2006-01-02 15:04")))
				return nil
			})
			defer func() {
				if scanner != nil {
					scanner.Close()
				}
			}()

			// ---- preflight: secrets in the build context (once) ----
			grp.Go(func() error {
				st := u.Start("Context")
				st.Detail("scanning build context for secrets", false)
				ig, err := ignore.Load(contextDir)
				if err != nil {
					st.Fail("error")
					return stageErr("context", err)
				}
				r, err := leaks.Scan(gctx, leaks.Options{ContextDir: contextDir, Ignore: ig, FailOnContext: gf.failOnContext})
				if err != nil {
					if !cancelled(gctx, st) {
						st.Fail("error")
					}
					return stageErr("context leaks", err)
				}
				rep.ContextLeaks = r
				switch {
				case r.Failed:
					st.Fail(fmt.Sprintf("%d secret(s) in the build context", len(r.Findings)))
				case len(r.Findings) > 0:
					st.Warn(fmt.Sprintf("%d secret(s) in the build context (not shipped)", len(r.Findings)))
				default:
					st.Done(fmt.Sprintf("no secrets · %d files", r.Scanned))
				}
				return nil
			})

			// ---- one pipeline per platform ----
			runs := make([]*platformRun, len(platforms))
			sem := make(chan struct{}, jobs)
			for i, p := range platforms {
				grp.Go(func() error {
					label := platformLabel(p, multi)
					stage := "build" + label
					select {
					case sem <- struct{}{}:
					case <-buildCtx.Done():
						return nil
					}
					res, err := doBuild(buildCtx, u, g, bf, contextDir, p, label)
					if err == nil {
						var sr *slim.Result
						if sr, err = doSlim(u, g, bf, res, label); err == nil {
							runs[i] = &platformRun{platform: res.Platform, image: sr.Image}
							runs[i].rep.Slim = &report.Slim{Applied: sr.Applied, Reason: sr.Reason, SizeBefore: sr.SizeBefore, SizeAfter: sr.SizeAfter, LayersBefore: sr.LayersBefore, LayersAfter: sr.LayersAfter, Removed: sr.Removed}
						}
					}
					<-sem
					if err != nil {
						if errors.Is(context.Cause(buildCtx), errGatesFailed) {
							return nil // stopped on purpose; the gate failure is reported
						}
						return stageErr(stage, err)
					}
					pr := runs[i]
					pr.rep.Platform = builder.PlatformString(res.Platform)
					pr.rep.Build = report.Build{Steps: res.Steps, Cached: res.Cached, Isolation: res.Isolation, Duration: res.Duration.Round(time.Millisecond).String()}
					dg, _ := pr.image.Digest()
					layers, _ := pr.image.Layers()
					pr.rep.Image = report.Image{Digest: dg.String(), Base: res.BaseRef, Size: imageSize(pr.image), Layers: len(layers)}

					// scan · sec · leaks in parallel (scan waits for the DB task)
					vg, vctx := errgroup.WithContext(gctx)
					vg.Go(func() error {
						select {
						case <-dbReady:
						case <-vctx.Done():
							return vctx.Err()
						}
						r, err := doScan(vctx, u, g, gf, scanner, pr.image, label, sbomFor(gf.sbom, res.Platform, multi))
						pr.rep.CVE = r
						return stageErr("scan"+label, err)
					})
					vg.Go(func() error {
						r, err := doSec(vctx, u, gf, res, pr.image, label)
						pr.rep.Sec = r
						return stageErr("sec"+label, err)
					})
					vg.Go(func() error {
						r, err := doLeaks(vctx, u, gf, res, pr.image, "", label)
						pr.rep.Leaks = r
						return stageErr("leaks"+label, err)
					})
					if err := vg.Wait(); err != nil {
						return err
					}
					if reason := gateFailure(pr.rep); reason != "" {
						if failFast {
							return &gateError{msg: pr.rep.Platform + ": " + reason}
						}
						cancelBuilds(errGatesFailed)
					}
					return nil
				})
			}

			err = grp.Wait()
			var ge *gateError
			if err != nil && !errors.As(err, &ge) {
				return err // technical failure: root cause, stage-prefixed
			}

			for i, r := range runs {
				if r != nil && r.rep.Platform != "" {
					rep.Platforms = append(rep.Platforms, r.rep)
				} else {
					rep.Cancelled = append(rep.Cancelled, builder.PlatformString(platforms[i]))
				}
			}
			summarize(rep)
			if len(rep.Cancelled) > 0 {
				rep.Passed = false
				if len(rep.Failures) == 0 {
					rep.Failures = append(rep.Failures, "not built: "+strings.Join(rep.Cancelled, ", "))
				}
			}

			// what gets pushed: one image, or an index pointing at every platform
			var art registry.Artifact
			if len(rep.Platforms) == len(platforms) {
				if multi {
					items := make([]registry.PlatformImage, len(runs))
					for i, r := range runs {
						items[i] = registry.PlatformImage{Image: r.image, Platform: r.platform}
					}
					idx, err := registry.Index(items)
					if err != nil {
						return err
					}
					art = idx
					if d, err := idx.Digest(); err == nil {
						rep.Digest = d.String()
					}
				} else {
					art = runs[0].image
				}
				if ociOut != "" {
					if err := saveRuns(runs, ociOut, gateState(rep.Passed)); err != nil {
						return err
					}
				}
			}

			u.Line("")
			switch {
			case noPush:
				u.Start("Push").Skip("skipped (--no-push)")
			case !rep.Passed:
				u.Start("Push").Fail("blocked by security gates")
				rep.Push = &report.Push{Registry: pf.registry, Skipped: "gates failed"}
			default:
				digest, err := doPush(cmd.Context(), u, art, target)
				if err != nil {
					return stageErr("push", err)
				}
				refs := []string{}
				for i := range target.Tags {
					refs = append(refs, target.Ref(i).String())
				}
				rep.Push = &report.Push{Registry: target.Kind, Refs: refs, Digest: digest}
			}

			if rep.ContextLeaks != nil && len(rep.ContextLeaks.Findings) > 0 {
				printDetails(u, "", nil, nil, rep.ContextLeaks)
			}
			for _, p := range rep.Platforms {
				title := ""
				if multi {
					title = p.Platform
				}
				printDetails(u, title, p.CVE, p.Sec, p.Leaks)
			}

			rep.Duration = time.Since(start).Round(time.Millisecond).String()
			if err := rep.Write(reportPath); err != nil {
				u.Warn("report: " + err.Error())
			}
			printSummary(u, rep, target, time.Since(start), reportPath)

			if !rep.Passed {
				return &gateError{msg: strings.Join(rep.Failures, "; ")}
			}
			return nil
		},
	}
	bf.register(c)
	gf.register(c)
	pf.register(c)
	c.Flags().BoolVar(&noPush, "no-push", false, "run everything except the push")
	c.Flags().BoolVar(&failFast, "fail-fast", false, "cancel everything at the first failed gate (default: finish the checks of that image for a complete report)")
	c.Flags().IntVar(&jobs, "jobs", 0, "platforms built at the same time (default: all)")
	c.Flags().StringVar(&reportPath, "report", ".forge/report.json", "JSON report path (empty disables)")
	c.Flags().StringVar(&ociOut, "oci", "", "also save the result as an OCI layout directory (input for forge push/manifest)")
	return c
}

// gateFailure returns why one platform failed its gates ("" = passed).
func gateFailure(p report.Platform) string {
	var r []string
	if p.CVE != nil && p.CVE.Failed {
		r = append(r, "cve: "+p.CVE.Reason)
	}
	if p.Sec != nil && p.Sec.Failed {
		r = append(r, "sec: "+p.Sec.Reason)
	}
	if p.Leaks != nil && p.Leaks.Failed {
		r = append(r, "leaks: "+p.Leaks.Reason)
	}
	return strings.Join(r, "; ")
}

func gateState(passed bool) string {
	if passed {
		return gatesPassed
	}
	return gatesFailed
}

func printSummary(u *ui.UI, rep *report.Report, target *registry.Target, d time.Duration, reportPath string) {
	rows := []ui.Row{}
	if rep.Push != nil && len(rep.Push.Refs) > 0 {
		rows = append(rows, ui.Row{Key: "image", Value: u.Value(rep.Push.Refs[0])})
	} else if target != nil {
		rows = append(rows, ui.Row{Key: "image", Value: u.Muted(target.String() + " (not pushed)")})
	}
	if len(rep.Platforms) == 1 && len(rep.Cancelled) == 0 {
		p := rep.Platforms[0]
		rows = append(rows, ui.Row{Key: "digest", Value: u.Muted(shortDigest(p.Image.Digest))})
		rows = append(rows, ui.Row{Key: "base", Value: u.Muted(shortRef(p.Image.Base))})
		if s := p.Slim; s != nil && s.Applied {
			pct := 100 * float64(s.SizeBefore-s.SizeAfter) / float64(s.SizeBefore)
			rows = append(rows, ui.Row{Key: "size", Value: fmt.Sprintf("%s → %s  %s", ui.HumanBytes(s.SizeBefore), u.Bold(ui.HumanBytes(s.SizeAfter)), u.Good(fmt.Sprintf("−%.1f%%", pct)))})
			rows = append(rows, ui.Row{Key: "layers", Value: fmt.Sprintf("%d → %d", s.LayersBefore, s.LayersAfter)})
		} else {
			rows = append(rows, ui.Row{Key: "size", Value: ui.HumanBytes(p.Image.Size)})
			rows = append(rows, ui.Row{Key: "layers", Value: fmt.Sprintf("%d", p.Image.Layers)})
		}
		rows = append(rows, ui.Row{Key: "cves", Value: severityLine(u, p.CVE)})
		rows = append(rows, scoreRow(u, p))
		rows = append(rows, secretsRow(u, p))
	} else {
		if rep.Digest != "" {
			rows = append(rows, ui.Row{Key: "index", Value: u.Muted(shortDigest(rep.Digest))})
		}
		for _, p := range rep.Platforms {
			arch := strings.TrimPrefix(p.Platform, "linux/")
			size := ui.HumanBytes(p.Image.Size)
			if s := p.Slim; s != nil && s.Applied {
				size = fmt.Sprintf("%s → %s", ui.HumanBytes(s.SizeBefore), ui.HumanBytes(s.SizeAfter))
			}
			crit, high := 0, 0
			if p.CVE != nil {
				crit, high = p.CVE.Counts["Critical"], p.CVE.Counts["High"]
			}
			score := "—"
			if p.Sec != nil {
				score = fmt.Sprintf("%d", p.Sec.Score)
			}
			rows = append(rows, ui.Row{Key: arch, Value: fmt.Sprintf("%s · %s/%s cve · score %s",
				u.Bold(size), colorIf(u.Bad, crit, "C"), colorIf(u.Warning, high, "H"), score)})
		}
		for _, c := range rep.Cancelled {
			rows = append(rows, ui.Row{Key: strings.TrimPrefix(c, "linux/"), Value: u.Muted("cancelled (not built)")})
		}
	}
	if reportPath != "" {
		rows = append(rows, ui.Row{Key: "report", Value: u.Muted(reportPath)})
	}
	verdict := u.Good("✔ passed")
	if !rep.Passed {
		verdict = u.Bad("✖ " + strings.Join(rep.Failures, " · "))
	}
	rows = append(rows, ui.Row{Key: "result", Value: verdict + u.Muted("  in "+ui.FmtDuration(d))})
	u.Box("forge", rows)
	u.Line("")
}

func scoreRow(u *ui.UI, p report.Platform) ui.Row {
	if p.Sec == nil {
		return ui.Row{Key: "score", Value: u.Muted("—")}
	}
	sc := fmt.Sprintf("%d/100 (%s)", p.Sec.Score, p.Sec.Grade)
	switch {
	case p.Sec.Score >= 75:
		sc = u.Good(sc)
	case p.Sec.Failed:
		sc = u.Bad(sc)
	default:
		sc = u.Warning(sc)
	}
	return ui.Row{Key: "score", Value: sc}
}

func secretsRow(u *ui.UI, p report.Platform) ui.Row {
	if p.Leaks == nil {
		return ui.Row{Key: "secrets", Value: u.Muted("—")}
	}
	v := u.Good("none in the image")
	if p.Leaks.Blocking > 0 {
		v = u.Bad(fmt.Sprintf("%d in the image", p.Leaks.Blocking))
	}
	if p.Leaks.Warnings > 0 {
		v += u.Muted(fmt.Sprintf(" · %d in context", p.Leaks.Warnings))
	}
	return ui.Row{Key: "secrets", Value: v}
}

func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}

func shortRef(r string) string {
	if i := strings.Index(r, "@sha256:"); i > 0 && len(r) > i+20 {
		return r[:i+20] + "…"
	}
	return r
}
