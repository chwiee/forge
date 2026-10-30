package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

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

func newRunCmd(g *globalFlags) *cobra.Command {
	bf := &buildFlags{}
	gf := &gateFlags{}
	pf := &pushFlags{}
	var noPush bool
	var reportPath, ociOut string

	c := &cobra.Command{
		Use:   "run [context]",
		Short: "Build → Slim → Scan → Sec → Leaks → Push (the whole pipeline)",
		Example: `  forge run . --registry ecr --name payments-api --tag v1.4.0
  forge run ./app --registry ghcr --name payments-api --fail-on high
  forge run . --no-push --report out/forge.json`,
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

			u := ui.New(g.verbose)
			defer u.Close()
			start := time.Now()
			u.Banner(Version, "build · slim · scan · sec · leaks · push")
			u.Info("context", contextDir)
			warnWindowsMount(u, contextDir, g.cacheDir)

			rep := &report.Report{Version: Version, Started: start.UTC()}

			// resolve the destination first: bad credentials fail in seconds, not after the build
			var target *registry.Target
			if !noPush {
				var err error
				if target, err = registry.Resolve(ctx, pf.options()); err != nil {
					return err
				}
				u.Info("target", u.Value(target.String()))
			}
			u.Line("")

			res, err := doBuild(ctx, u, g, bf, contextDir)
			if err != nil {
				return err
			}
			rep.Build = report.Build{Dockerfile: res.Parsed.Path, Context: contextDir, Steps: res.Steps, Cached: res.Cached, Isolation: res.Isolation, Duration: res.Duration.Round(time.Millisecond).String()}

			sr, err := doSlim(u, g, bf, res)
			if err != nil {
				return err
			}
			img := sr.Image
			rep.Slim = &report.Slim{Applied: sr.Applied, Reason: sr.Reason, SizeBefore: sr.SizeBefore, SizeAfter: sr.SizeAfter, LayersBefore: sr.LayersBefore, LayersAfter: sr.LayersAfter, Removed: sr.Removed}

			if rep.CVE, err = doScan(ctx, u, g, gf, img); err != nil {
				return err
			}
			if rep.Sec, err = doSec(u, gf, res, img); err != nil {
				return err
			}
			if rep.Leaks, err = doLeaks(ctx, u, gf, res, img, contextDir); err != nil {
				return err
			}
			summarize(rep)

			dg, _ := img.Digest()
			layers, _ := img.Layers()
			rep.Image = report.Image{Digest: dg.String(), Base: res.BaseRef, Size: imageSize(img), Layers: len(layers)}

			if ociOut != "" {
				if err := saveOCI(img, ociOut); err != nil {
					return err
				}
			}

			switch {
			case noPush:
				st := u.Start("Push")
				st.Skip("skipped (--no-push)")
			case !rep.Passed:
				st := u.Start("Push")
				st.Fail("blocked by security gates")
				rep.Push = &report.Push{Registry: target.Kind, Skipped: "gates failed"}
			default:
				digest, err := doPush(ctx, u, img, target)
				if err != nil {
					return err
				}
				refs := []string{}
				for i := range target.Tags {
					refs = append(refs, target.Ref(i).String())
				}
				rep.Push = &report.Push{Registry: target.Kind, Refs: refs, Digest: digest}
			}

			printDetails(u, rep.CVE, rep.Sec, rep.Leaks)

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
	c.Flags().StringVar(&ociOut, "oci", "", "also save the final image as an OCI layout directory")
	return c
}

func printSummary(u *ui.UI, rep *report.Report, target *registry.Target, d time.Duration, reportPath string) {
	rows := []ui.Row{}
	if rep.Push != nil && len(rep.Push.Refs) > 0 {
		rows = append(rows, ui.Row{Key: "image", Value: u.Value(rep.Push.Refs[0])})
	} else if target != nil {
		rows = append(rows, ui.Row{Key: "image", Value: u.Muted(target.String() + " (not pushed)")})
	}
	rows = append(rows, ui.Row{Key: "digest", Value: u.Muted(shortDigest(rep.Image.Digest))})
	rows = append(rows, ui.Row{Key: "base", Value: u.Muted(shortRef(rep.Image.Base))})
	if s := rep.Slim; s != nil && s.Applied {
		pct := 100 * float64(s.SizeBefore-s.SizeAfter) / float64(s.SizeBefore)
		rows = append(rows, ui.Row{Key: "size", Value: fmt.Sprintf("%s → %s  %s", ui.HumanBytes(s.SizeBefore), u.Bold(ui.HumanBytes(s.SizeAfter)), u.Good(fmt.Sprintf("−%.1f%%", pct)))})
		rows = append(rows, ui.Row{Key: "layers", Value: fmt.Sprintf("%d → %d", s.LayersBefore, s.LayersAfter)})
	} else {
		rows = append(rows, ui.Row{Key: "size", Value: ui.HumanBytes(rep.Image.Size)})
		rows = append(rows, ui.Row{Key: "layers", Value: fmt.Sprintf("%d", rep.Image.Layers)})
	}
	rows = append(rows, ui.Row{Key: "cves", Value: severityLine(u, rep.CVE)})
	if rep.Sec != nil {
		sc := fmt.Sprintf("%d/100 (%s)", rep.Sec.Score, rep.Sec.Grade)
		switch {
		case rep.Sec.Score >= 75:
			sc = u.Good(sc)
		case rep.Sec.Failed:
			sc = u.Bad(sc)
		default:
			sc = u.Warning(sc)
		}
		rows = append(rows, ui.Row{Key: "score", Value: sc})
	}
	if rep.Leaks != nil {
		v := u.Good("none in the image")
		if rep.Leaks.Blocking > 0 {
			v = u.Bad(fmt.Sprintf("%d in the image", rep.Leaks.Blocking))
		}
		if rep.Leaks.Warnings > 0 {
			v += u.Muted(fmt.Sprintf(" · %d in context", rep.Leaks.Warnings))
		}
		rows = append(rows, ui.Row{Key: "secrets", Value: v})
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
