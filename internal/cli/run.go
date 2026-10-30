package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/spf13/cobra"

	"github.com/chwiee/forge/internal/builder"
	"github.com/chwiee/forge/internal/registry"
	"github.com/chwiee/forge/internal/report"
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
	var noPush bool
	var reportPath, ociOut string

	c := &cobra.Command{
		Use:   "run [context]",
		Short: "Build → Slim → Scan → Sec → Leaks → Push (the whole pipeline, one or many platforms)",
		Example: `  forge run . --registry ecr --name payments-api --tag v1.4.0
  forge run . --registry ghcr --name api --platform linux/amd64,linux/arm64
  forge run . --no-push --oci out/arm64     # native runner; join later with forge manifest`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
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

			rep := &report.Report{Version: Version, Started: start.UTC(), Context: contextDir}

			// resolve the destination first: bad credentials fail in seconds, not after the build
			var target *registry.Target
			if !noPush {
				if target, err = registry.Resolve(ctx, pf.options()); err != nil {
					return err
				}
				u.Info("target", u.Value(target.String()))
			}

			var runs []*platformRun
			for i, p := range platforms {
				label := platformLabel(p, multi)
				u.Line("")
				if multi {
					u.Line("  " + u.Accent("◆ "+builder.PlatformString(p)))
				}
				res, err := doBuild(ctx, u, g, bf, contextDir, p, label)
				if err != nil {
					return err
				}
				rep.Dockerfile = res.Parsed.Path
				pr := &platformRun{platform: res.Platform}
				pr.rep.Platform = builder.PlatformString(res.Platform)
				pr.rep.Build = report.Build{Steps: res.Steps, Cached: res.Cached, Isolation: res.Isolation, Duration: res.Duration.Round(time.Millisecond).String()}

				sr, err := doSlim(u, g, bf, res, label)
				if err != nil {
					return err
				}
				pr.image = sr.Image
				pr.rep.Slim = &report.Slim{Applied: sr.Applied, Reason: sr.Reason, SizeBefore: sr.SizeBefore, SizeAfter: sr.SizeAfter, LayersBefore: sr.LayersBefore, LayersAfter: sr.LayersAfter, Removed: sr.Removed}

				if pr.rep.CVE, err = doScan(ctx, u, g, gf, pr.image, label, sbomFor(gf.sbom, res.Platform, multi)); err != nil {
					return err
				}
				if pr.rep.Sec, err = doSec(u, gf, res, pr.image, label); err != nil {
					return err
				}
				ctxDir := ""
				if i == 0 {
					ctxDir = contextDir // the build context is the same for every platform
				}
				if pr.rep.Leaks, err = doLeaks(ctx, u, gf, res, pr.image, ctxDir, label); err != nil {
					return err
				}
				dg, _ := pr.image.Digest()
				layers, _ := pr.image.Layers()
				pr.rep.Image = report.Image{Digest: dg.String(), Base: res.BaseRef, Size: imageSize(pr.image), Layers: len(layers)}
				rep.Platforms = append(rep.Platforms, pr.rep)
				runs = append(runs, pr)
			}
			summarize(rep)

			// what gets pushed: one image, or an index pointing at every platform
			var art registry.Artifact = runs[0].image
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
			}

			if ociOut != "" {
				if err := saveRuns(runs, ociOut, gateState(rep.Passed)); err != nil {
					return err
				}
			}

			u.Line("")
			switch {
			case noPush:
				u.Start("Push").Skip("skipped (--no-push)")
			case !rep.Passed:
				u.Start("Push").Fail("blocked by security gates")
				rep.Push = &report.Push{Registry: target.Kind, Skipped: "gates failed"}
			default:
				digest, err := doPush(ctx, u, art, target)
				if err != nil {
					return err
				}
				refs := []string{}
				for i := range target.Tags {
					refs = append(refs, target.Ref(i).String())
				}
				rep.Push = &report.Push{Registry: target.Kind, Refs: refs, Digest: digest}
			}

			for _, r := range runs {
				title := ""
				if multi {
					title = r.rep.Platform
				}
				printDetails(u, title, r.rep.CVE, r.rep.Sec, r.rep.Leaks)
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
	c.Flags().StringVar(&reportPath, "report", ".forge/report.json", "JSON report path (empty disables)")
	c.Flags().StringVar(&ociOut, "oci", "", "also save the result as an OCI layout directory (input for forge push/manifest)")
	return c
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
	if len(rep.Platforms) == 1 {
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
		rows = append(rows, ui.Row{Key: "index", Value: u.Muted(shortDigest(rep.Digest))})
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
