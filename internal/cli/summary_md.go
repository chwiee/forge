package cli

import (
	"fmt"
	"strings"

	"github.com/chwiee/forge/internal/ci"
	"github.com/chwiee/forge/internal/leaks"
	"github.com/chwiee/forge/internal/registry"
	"github.com/chwiee/forge/internal/report"
	"github.com/chwiee/forge/internal/ui"
)

// GitHub caps a step summary at 1 MiB; keep the vulnerability list well below.
const maxSummaryVulns = 300

// writeStepSummary renders the run as Markdown on the GitHub Actions run page.
func writeStepSummary(rep *report.Report, target *registry.Target) error {
	if ci.Detect() != ci.GitHub {
		return nil
	}
	var b strings.Builder
	if rep.Passed {
		b.WriteString("## ✅ forge — passed\n\n")
	} else {
		b.WriteString("## ❌ forge — push blocked\n\n")
		for _, f := range rep.Failures {
			fmt.Fprintf(&b, "- **%s**\n", md(f))
		}
		b.WriteString("\n")
	}
	switch {
	case rep.Push != nil && len(rep.Push.Refs) > 0:
		for _, r := range rep.Push.Refs {
			fmt.Fprintf(&b, "📦 `%s`  \n", r)
		}
		if rep.Push.Digest != "" {
			fmt.Fprintf(&b, "digest `%s`\n\n", rep.Push.Digest)
		}
	case target != nil:
		fmt.Fprintf(&b, "📦 `%s` (not pushed)\n\n", target.String())
	}

	b.WriteString("| platform | size | layers | critical | high | medium | fixable | score | secrets in image |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
	for _, p := range rep.Platforms {
		size := ui.HumanBytes(p.Image.Size)
		layers := fmt.Sprintf("%d", p.Image.Layers)
		if s := p.Slim; s != nil && s.Applied {
			size = fmt.Sprintf("%s → **%s**", ui.HumanBytes(s.SizeBefore), ui.HumanBytes(s.SizeAfter))
			layers = fmt.Sprintf("%d → %d", s.LayersBefore, s.LayersAfter)
		}
		crit, high, med, fix := 0, 0, 0, 0
		if p.CVE != nil {
			crit, high, med = p.CVE.Counts["Critical"], p.CVE.Counts["High"], p.CVE.Counts["Medium"]
			for _, n := range p.CVE.Fixable {
				fix += n
			}
		}
		score, secrets := "—", "—"
		if p.Sec != nil {
			score = fmt.Sprintf("%d (%s)", p.Sec.Score, p.Sec.Grade)
		}
		if p.Leaks != nil {
			secrets = fmt.Sprintf("%d", p.Leaks.Blocking)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %d | %s | %s |\n", p.Platform, size, layers, crit, high, med, fix, score, secrets)
	}
	for _, c := range rep.Cancelled {
		fmt.Fprintf(&b, "| %s | cancelled | | | | | | | |\n", c)
	}

	what := "≥ " + strings.ToLower(rep.Gates.FailOn)
	if rep.Gates.OnlyFixed {
		what += " with a fix"
	}
	fmt.Fprintf(&b, "\n**Gates:** CVE fails on %s · hardening score ≥ %d · no secret in the image\n", what, rep.Gates.MinScore)

	for _, p := range rep.Platforms {
		block := gateVulns(p.CVE, rep.Gates)
		var secrets []leaks.Finding
		if p.Leaks != nil && p.Leaks.Failed {
			for _, f := range p.Leaks.Findings {
				if f.Where != leaks.InContext {
					secrets = append(secrets, f)
				}
			}
		}
		if (p.CVE == nil || !p.CVE.Failed) && len(secrets) == 0 && (p.Sec == nil || !p.Sec.Failed) {
			continue
		}
		fmt.Fprintf(&b, "\n### Why `%s` was blocked\n\n", p.Platform)
		if p.CVE != nil && p.CVE.Failed {
			b.WriteString("| severity | id | package | version | fixed in | where |\n|---|---|---|---|---|---|\n")
			for _, v := range block {
				fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | `%s` |\n", v.Severity, v.ID, md(v.Package), md(v.Version), md(v.FixedIn), v.Path)
			}
			b.WriteString("\n")
		}
		for _, f := range secrets {
			fmt.Fprintf(&b, "- 🔑 **%s** in `%s` (%s) — value redacted\n", f.Rule, loc(f), f.Where)
		}
		if p.Sec != nil && p.Sec.Failed {
			fmt.Fprintf(&b, "- 🛡️ hardening score **%d** below %d\n", p.Sec.Score, rep.Gates.MinScore)
		}
	}

	for _, p := range rep.Platforms {
		if p.CVE == nil || len(p.CVE.Vulns) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n<details><summary>All %d vulnerabilities — %s</summary>\n\n", len(p.CVE.Vulns), p.Platform)
		b.WriteString("| severity | id | package | version | fixed in | where |\n|---|---|---|---|---|---|\n")
		for i, v := range p.CVE.Vulns {
			if i == maxSummaryVulns {
				fmt.Fprintf(&b, "\n… %d more in the job log and in the JSON report artifact\n", len(p.CVE.Vulns)-i)
				break
			}
			fix := v.FixedIn
			if fix == "" {
				fix = "—"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | `%s` |\n", v.Severity, v.ID, md(v.Package), md(v.Version), md(fix), v.Path)
		}
		b.WriteString("\n</details>\n")
	}
	b.WriteString("\n")
	return ci.StepSummary(b.String())
}

// md escapes characters that break a Markdown table cell.
func md(s string) string { return strings.NewReplacer("|", "\\|", "\n", " ").Replace(s) }
