package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/spf13/cobra"

	"github.com/chwiee/forge/internal/builder"
	"github.com/chwiee/forge/internal/cache"
	"github.com/chwiee/forge/internal/leaks"
	"github.com/chwiee/forge/internal/registry"
	"github.com/chwiee/forge/internal/report"
	"github.com/chwiee/forge/internal/sandbox"
	"github.com/chwiee/forge/internal/scan"
	"github.com/chwiee/forge/internal/sec"
	"github.com/chwiee/forge/internal/slim"
	"github.com/chwiee/forge/internal/ui"
)

// buildFlags are shared by run and build.
type buildFlags struct {
	file      string
	target    string
	buildArgs []string
	noCache   bool
	slim      string
	squash    string
}

func (f *buildFlags) register(c *cobra.Command) {
	c.Flags().StringVarP(&f.file, "file", "f", "", "Dockerfile path (default <context>/Dockerfile)")
	c.Flags().StringVar(&f.target, "target", "", "build this stage (default: last)")
	c.Flags().StringArrayVar(&f.buildArgs, "build-arg", nil, "build argument KEY=VALUE (repeatable; KEY alone reads the environment)")
	c.Flags().BoolVar(&f.noCache, "no-cache", false, "do not reuse cached steps")
	c.Flags().StringVar(&f.slim, "slim", slim.Safe, "cleanup profile: off | safe | aggressive")
	c.Flags().StringVar(&f.squash, "squash", slim.SquashApp, "layer squash: app (Dockerfile layers) | all | off")
}

// gateFlags configure the security gates.
type gateFlags struct {
	failOn        string
	onlyFixed     bool
	minScore      int
	ignoreCVE     []string
	dbURL         string
	sbom          string
	failOnContext bool
}

func (f *gateFlags) register(c *cobra.Command) {
	c.Flags().StringVar(&f.failOn, "fail-on", "critical", "CVE gate: critical | high | medium | low | none")
	c.Flags().BoolVar(&f.onlyFixed, "only-fixed", true, "CVE gate counts only vulnerabilities with a fix available")
	c.Flags().IntVar(&f.minScore, "min-score", 50, "hardening gate: minimum score 0-100 (0 disables)")
	c.Flags().StringSliceVar(&f.ignoreCVE, "ignore-cve", nil, "CVE/GHSA ids accepted by the team (comma separated)")
	c.Flags().StringVar(&f.dbURL, "db-url", os.Getenv("FORGE_DB_URL"), "vulnerability DB mirror, e.g. http://forge-db.forge.svc:8080/databases [$FORGE_DB_URL]")
	c.Flags().StringVar(&f.sbom, "sbom", "", "write the SBOM (CycloneDX JSON) to this file")
	c.Flags().BoolVar(&f.failOnContext, "leaks-fail-on-context", false, "secrets found in the build context also block (default: only what ships in the image)")
}

func parseBuildArgs(in []string) map[string]string {
	m := map[string]string{}
	for _, a := range in {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			v = os.Getenv(k)
		}
		m[k] = v
	}
	return m
}

// ---- build ----

type buildEvents struct {
	u    *ui.UI
	step *ui.Step
	cur  string
	n    int
	tot  int
}

func (e *buildEvents) StepStart(n, total int, stage, text string) {
	e.n, e.tot = n, total
	e.cur = fmt.Sprintf("[%d/%d] %s", n, total, text)
	e.step.Detail(e.cur, false)
}

func (e *buildEvents) StepDone(text, status string, d time.Duration) {
	label := fmt.Sprintf("%-7s %s", fmt.Sprintf("%d/%d", e.n, e.tot), clip(text, 88))
	switch status {
	case builder.StatusCached:
		e.step.SubCached(label + e.u.Muted("  cached"))
		return
	case builder.StatusMeta:
		e.step.Sub(e.u.Muted("·"), e.u.Muted(label))
		return
	}
	if d > 200*time.Millisecond {
		label += "  " + ui.FmtDuration(d)
	}
	e.step.SubOK(label)
}

func (e *buildEvents) Output(line string) { e.step.Detail(e.cur+"  › "+line, false) }
func (e *buildEvents) Warn(msg string)    { e.step.SubWarn(msg) }

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func doBuild(ctx context.Context, u *ui.UI, g *globalFlags, f *buildFlags, contextDir string) (*builder.Result, error) {
	st := u.Start("Build")
	ev := &buildEvents{u: u, step: st}
	opts := builder.Options{
		ContextDir: contextDir,
		Dockerfile: f.file,
		Target:     f.target,
		BuildArgs:  parseBuildArgs(f.buildArgs),
		CacheDir:   g.cacheDir,
		NoCache:    f.noCache,
		Events:     ev,
	}
	if u.Verbose() {
		opts.Verbose = os.Stderr
	}
	res, err := builder.Build(ctx, opts)
	if err != nil {
		st.Fail("failed")
		var re *builder.RunError
		if errors.As(err, &re) && len(re.Tail) > 0 && !u.Verbose() {
			u.Line("    " + u.Muted("── last output ──"))
			for _, l := range re.Tail {
				u.Line("    " + u.Muted("│ ") + l)
			}
		}
		if errors.As(err, &re) {
			switch sandbox.LevelIfProbed() {
			case sandbox.Rootless:
				u.Warn("rootless mode maps only your user: adduser/chown to other uids fail here.")
				u.Line("    " + u.Muted("fix: run `sudo forge ...` on WSL, or run forge as root in the runner pod (no privileged needed)"))
			case sandbox.Chroot:
				u.Warn("chroot mode has no /proc: Go, Java and .NET toolchains need it.")
				u.Line("    " + u.Muted("fix: pod securityContext seccompProfile Unconfined (+ AppArmor unconfined on Ubuntu nodes)"))
			}
		}
		return nil, err
	}
	layers, _ := res.Image.Layers()
	size := imageSize(res.Image)
	msg := fmt.Sprintf("%d steps · %d cached · %d layers · %s", res.Steps, res.Cached, len(layers), ui.HumanBytes(size))
	st.Done(msg)
	return res, nil
}

func imageSize(img v1.Image) int64 {
	layers, err := img.Layers()
	if err != nil {
		return 0
	}
	var n int64
	for _, l := range layers {
		if s, err := l.Size(); err == nil {
			n += s
		}
	}
	return n
}

// ---- slim ----

func doSlim(u *ui.UI, g *globalFlags, f *buildFlags, res *builder.Result) (*slim.Result, error) {
	st := u.Start("Slim")
	if f.slim == slim.Off && f.squash == slim.SquashOff {
		st.Skip("disabled")
		layers, _ := res.Image.Layers()
		s := imageSize(res.Image)
		return &slim.Result{Image: res.Image, SizeBefore: s, SizeAfter: s, LayersBefore: len(layers), LayersAfter: len(layers), Reason: "disabled"}, nil
	}
	st.Detail("squashing Dockerfile layers, removing build leftovers", false)
	store, err := cache.Open(filepath.Join(g.cacheDir, "layers"))
	if err != nil {
		return nil, err
	}
	r, err := slim.Slim(res.Image, res.BaseLayers, slim.Options{Profile: f.slim, Squash: f.squash, Store: store})
	if err != nil {
		st.Fail("failed — keeping original image")
		u.Warn(err.Error())
		layers, _ := res.Image.Layers()
		s := imageSize(res.Image)
		return &slim.Result{Image: res.Image, SizeBefore: s, SizeAfter: s, LayersBefore: len(layers), LayersAfter: len(layers), Reason: err.Error()}, nil
	}
	if !r.Applied {
		st.Skip(r.Reason)
		return r, nil
	}
	pct := 100 * float64(r.SizeBefore-r.SizeAfter) / float64(r.SizeBefore)
	msg := fmt.Sprintf("%s → %s  (−%.1f%%) · %d → %d layers", ui.HumanBytes(r.SizeBefore), ui.HumanBytes(r.SizeAfter), pct, r.LayersBefore, r.LayersAfter)
	if r.Cached {
		msg += " · cached"
	}
	st.Done(msg)
	for cat, n := range r.Removed {
		if n > 0 {
			st.SubOK(fmt.Sprintf("removed %s of %s", ui.HumanBytes(n), cat))
		}
	}
	return r, nil
}

// ---- scan ----

func doScan(ctx context.Context, u *ui.UI, g *globalFlags, gf *gateFlags, img v1.Image) (*scan.Report, error) {
	st := u.Start("Scan")
	st.Detail("loading vulnerability database", false)
	work := filepath.Join(g.cacheDir, "work")
	_ = os.MkdirAll(work, 0o755)
	r, err := scan.Image(ctx, img, work, scan.Options{
		CacheDir: g.cacheDir, DBURL: gf.dbURL, FailOn: gf.failOn, OnlyFixed: gf.onlyFixed,
		Ignore: gf.ignoreCVE, SBOMPath: gf.sbom, Version: Version,
		OnDB: func(m string) { st.Detail(m, false) },
	})
	if err != nil {
		st.Fail("error")
		return nil, err
	}
	parts := []string{}
	for _, sev := range []string{"Critical", "High", "Medium", "Low"} {
		n := r.Counts[sev]
		txt := fmt.Sprintf("%d %s", n, strings.ToLower(sev))
		if n > 0 {
			switch sev {
			case "Critical":
				txt = u.Bad(txt)
			case "High":
				txt = u.Warning(txt)
			}
		}
		parts = append(parts, txt)
	}
	fixable := 0
	for _, n := range r.Fixable {
		fixable += n
	}
	msg := strings.Join(parts, " · ") + fmt.Sprintf(" · %d fixable · %d packages", fixable, r.Packages)
	if r.Failed {
		st.Fail(msg)
	} else {
		st.Done(msg)
	}
	return r, nil
}

// ---- sec ----

func doSec(u *ui.UI, gf *gateFlags, res *builder.Result, img v1.Image) (*sec.Report, error) {
	st := u.Start("Sec")
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	r, err := sec.Check(sec.Input{Parsed: res.Parsed, Config: cf, AppLayers: appLayers(img, res.BaseLayers), MinScore: gf.minScore})
	if err != nil {
		st.Fail("error")
		return nil, err
	}
	msg := fmt.Sprintf("score %d/100 (%s) · %d findings", r.Score, r.Grade, len(r.Findings))
	switch {
	case r.Failed:
		st.Fail(msg)
	case r.Score < 75:
		st.Warn(msg)
	default:
		st.Done(msg)
	}
	return r, nil
}

func appLayers(img v1.Image, base int) []v1.Layer {
	layers, err := img.Layers()
	if err != nil || base > len(layers) {
		return nil
	}
	return layers[base:]
}

// ---- leaks ----

func doLeaks(ctx context.Context, u *ui.UI, gf *gateFlags, res *builder.Result, img v1.Image, contextDir string) (*leaks.Report, error) {
	st := u.Start("Leaks")
	st.Detail("scanning image files, config and build context", false)
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	r, err := leaks.Scan(ctx, leaks.Options{
		ContextDir: contextDir, Ignore: res.Ignore, AppLayers: appLayers(img, res.BaseLayers),
		Config: cf, FailOnContext: gf.failOnContext,
	})
	if err != nil {
		st.Fail("error")
		return nil, err
	}
	switch {
	case r.Failed:
		st.Fail(fmt.Sprintf("%d secret(s) in the image · %d in context", r.Blocking, r.Warnings))
	case r.Warnings > 0:
		st.Warn(fmt.Sprintf("no secrets in the image · %d in build context (not shipped)", r.Warnings))
	default:
		st.Done(fmt.Sprintf("no secrets · %d files checked", r.Scanned))
	}
	return r, nil
}

// ---- push ----

func doPush(ctx context.Context, u *ui.UI, img v1.Image, t *registry.Target) (string, error) {
	st := u.Start("Push")
	st.Detail(t.String(), false)
	st.Progress(0)
	dg, err := registry.Push(ctx, img, t, func(done, total int64) {
		st.Progress(int(done * 100 / total))
		st.Detail(fmt.Sprintf("%s / %s", ui.HumanBytes(done), ui.HumanBytes(total)), false)
	})
	st.Progress(-1)
	if err != nil {
		st.Fail("failed")
		return "", err
	}
	st.Done(t.String())
	return dg.String(), nil
}

// ---- details ----

func printDetails(u *ui.UI, cve *scan.Report, s *sec.Report, lk *leaks.Report) {
	if cve != nil && len(cve.Vulns) > 0 {
		var rows [][]string
		for _, v := range cve.Vulns {
			if scan.Rank(v.Severity) > 1 || len(rows) >= 12 {
				continue
			}
			fix := v.FixedIn
			if fix == "" {
				fix = "—"
			}
			id := v.ID
			if v.KEV {
				id += " (KEV)"
			}
			rows = append(rows, []string{v.Severity, id, v.Package, v.Version, fix})
		}
		if len(rows) > 0 {
			u.Line("")
			u.Line("  " + u.Bold("Critical & high vulnerabilities"))
			sevColor := func(s string) string {
				if s == "Critical" {
					return u.Bad(s)
				}
				return u.Warning(s)
			}
			u.Table([]string{"SEVERITY", "ID", "PACKAGE", "VERSION", "FIXED IN"}, rows, []func(string) string{sevColor, u.Value, nil, u.Muted, u.Good})
			total := cve.Counts["Critical"] + cve.Counts["High"]
			if total > len(rows) {
				u.Line("    " + u.Muted(fmt.Sprintf("… %d more in the JSON report", total-len(rows))))
			}
		}
	}
	if s != nil && len(s.Findings) > 0 {
		u.Line("")
		u.Line("  " + u.Bold("Hardening"))
		for _, f := range s.Findings {
			if f.Penalty == 0 {
				continue
			}
			icon := u.Muted("·")
			switch f.Severity {
			case sec.High:
				icon = u.Bad("●")
			case sec.Medium:
				icon = u.Warning("●")
			case sec.Low:
				icon = u.Value("●")
			}
			line := fmt.Sprintf("    %s %s %s", icon, u.Muted(f.ID), f.Title)
			if f.Line > 0 {
				line += u.Muted(" (line " + strconv.Itoa(f.Line) + ")")
			}
			line += u.Muted(fmt.Sprintf("  −%d", f.Penalty))
			u.Line(line)
			if f.Detail != "" {
				u.Line("        " + u.Muted(f.Detail))
			}
			if f.Fix != "" {
				u.Line("        " + u.Good("↳ ") + u.Muted(f.Fix))
			}
		}
	}
	if lk != nil && len(lk.Findings) > 0 {
		u.Line("")
		u.Line("  " + u.Bold("Secrets"))
		for _, f := range lk.Findings {
			icon := u.Bad("●")
			if f.Where == leaks.InContext {
				icon = u.Warning("●")
			}
			loc := f.File
			if f.Line > 0 {
				loc += ":" + strconv.Itoa(f.Line)
			}
			u.Line(fmt.Sprintf("    %s %-8s %s  %s  %s", icon, f.Where, u.Value(f.Rule), loc, u.Muted(f.Secret)))
		}
		u.Line("    " + u.Muted("accept a false positive: add its fingerprint (file:rule:line) to .gitleaksignore"))
	}
}

func severityLine(u *ui.UI, r *scan.Report) string {
	if r == nil {
		return u.Muted("not scanned")
	}
	return fmt.Sprintf("%s · %s · %d medium · %d low",
		colorIf(u.Bad, r.Counts["Critical"], "critical"), colorIf(u.Warning, r.Counts["High"], "high"),
		r.Counts["Medium"], r.Counts["Low"])
}

func colorIf(c func(string) string, n int, label string) string {
	s := fmt.Sprintf("%d %s", n, label)
	if n > 0 {
		return c(s)
	}
	return s
}

func summarize(rep *report.Report) {
	if rep.CVE != nil && rep.CVE.Failed {
		rep.Failures = append(rep.Failures, "cve: "+rep.CVE.Reason)
	}
	if rep.Sec != nil && rep.Sec.Failed {
		rep.Failures = append(rep.Failures, "sec: "+rep.Sec.Reason)
	}
	if rep.Leaks != nil && rep.Leaks.Failed {
		rep.Failures = append(rep.Failures, "leaks: "+rep.Leaks.Reason)
	}
	rep.Passed = len(rep.Failures) == 0
}
