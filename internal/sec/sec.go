// Package sec checks Dockerfile and image hardening practices and produces a
// 0-100 score. Each finding carries the fix, so the report teaches as it gates.
package sec

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"

	"github.com/chwiee/forge/internal/dockerfile"
)

// Severities.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
	Info   = "info"
)

// Finding is one failed check.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Line     int    `json:"line,omitempty"`
	Fix      string `json:"fix"`
	Penalty  int    `json:"penalty"`
}

// Report is the result.
type Report struct {
	Score    int       `json:"score"`
	Grade    string    `json:"grade"`
	Findings []Finding `json:"findings"`
	Failed   bool      `json:"failed"`
	Reason   string    `json:"reason,omitempty"`
}

// Input is what the checks look at.
type Input struct {
	Parsed    *dockerfile.Parsed
	Config    *v1.ConfigFile
	AppLayers []v1.Layer
	MinScore  int
}

var (
	secretName  = regexp.MustCompile(`(?i)(passw(or)?d|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key)`)
	pipeToShell = regexp.MustCompile(`(?i)(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`)
	chmod777    = regexp.MustCompile(`chmod\s+(-R\s+)?0?777\b`)
	aptInstall  = regexp.MustCompile(`apt-get\s+(-\S+\s+)*install\b`)
)

// Check runs every rule.
func Check(in Input) (*Report, error) {
	var fs []Finding
	addF := func(f Finding) { fs = append(fs, f) }

	// --- image config ---
	if in.Config != nil {
		u := strings.TrimSpace(in.Config.Config.User)
		if u == "" || u == "root" || u == "0" || strings.HasPrefix(u, "0:") || strings.HasPrefix(u, "root:") {
			addF(Finding{ID: "SEC001", Severity: High, Penalty: 20, Title: "container runs as root",
				Fix: "create a user and add `USER 10001` (numeric uid works on Kubernetes runAsNonRoot)"})
		}
		for _, e := range in.Config.Config.Env {
			k, v, _ := strings.Cut(e, "=")
			if secretName.MatchString(k) && v != "" {
				addF(Finding{ID: "SEC004", Severity: High, Penalty: 20, Title: "secret-like value baked into ENV " + k,
					Fix: "pass secrets at runtime (Kubernetes Secret, AWS Secrets Manager), never in the image"})
			}
		}
		for p := range in.Config.Config.ExposedPorts {
			if strings.HasPrefix(p, "22/") {
				addF(Finding{ID: "SEC007", Severity: Medium, Penalty: 5, Title: "SSH port 22 exposed",
					Fix: "remove sshd; use kubectl exec / SSM for access"})
			}
		}
		if in.Config.Config.Healthcheck == nil {
			addF(Finding{ID: "SEC008", Severity: Info, Penalty: 2, Title: "no HEALTHCHECK",
				Fix: "add HEALTHCHECK (or rely on Kubernetes liveness/readiness probes)"})
		}
	}

	// --- Dockerfile ---
	if in.Parsed != nil {
		stageNames := map[string]bool{}
		for _, s := range in.Parsed.Stages {
			if s.Name != "" {
				stageNames[strings.ToLower(s.Name)] = true
			}
		}
		for _, s := range in.Parsed.Stages {
			base := strings.ToLower(s.BaseName)
			if !stageNames[base] && base != "scratch" && !strings.Contains(base, "$") {
				line := 0
				if len(s.Location) > 0 {
					line = s.Location[0].Start.Line
				}
				if !strings.Contains(base, "@sha256:") {
					last := base[strings.LastIndex(base, "/")+1:]
					if !strings.Contains(last, ":") || strings.HasSuffix(last, ":latest") {
						addF(Finding{ID: "SEC002", Severity: Medium, Penalty: 10, Line: line, Title: "base image without a fixed tag: " + s.BaseName,
							Fix: "pin a version tag, e.g. FROM node:22.11-bookworm-slim"})
					} else {
						addF(Finding{ID: "SEC003", Severity: Low, Penalty: 2, Line: line, Title: "base image not pinned by digest: " + s.BaseName,
							Fix: "pin with @sha256:<digest> for reproducible, tamper-proof builds"})
					}
				}
			}
			for _, c := range s.Commands {
				line := dockerfile.Line(c)
				switch c := c.(type) {
				case *instructions.RunCommand:
					cmd := strings.Join(c.CmdLine, " ")
					for _, f := range c.Files {
						cmd += "\n" + f.Data
					}
					if pipeToShell.MatchString(cmd) {
						addF(Finding{ID: "SEC006", Severity: Medium, Penalty: 8, Line: line, Title: "remote script piped to shell",
							Fix: "download, verify the checksum, then execute"})
					}
					if chmod777.MatchString(cmd) {
						addF(Finding{ID: "SEC013", Severity: Low, Penalty: 3, Line: line, Title: "chmod 777",
							Fix: "grant only what is needed (e.g. chown to the app user, 0755/0644)"})
					}
					if aptInstall.MatchString(cmd) && !strings.Contains(cmd, "--no-install-recommends") {
						addF(Finding{ID: "SEC012", Severity: Low, Penalty: 2, Line: line, Title: "apt-get install without --no-install-recommends",
							Fix: "add --no-install-recommends (smaller image, fewer CVEs)"})
					}
				case *instructions.AddCommand:
					for _, src := range c.SourcePaths {
						if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
							if c.Checksum == "" {
								addF(Finding{ID: "SEC005", Severity: Medium, Penalty: 8, Line: line, Title: "ADD from URL without --checksum",
									Fix: "use ADD --checksum=sha256:<hash> <url> or download + verify in RUN"})
							}
						} else if !isArchive(src) {
							addF(Finding{ID: "SEC014", Severity: Low, Penalty: 1, Line: line, Title: "ADD used for a plain file",
								Fix: "use COPY (ADD auto-extracts archives and fetches URLs)"})
						}
					}
				case *instructions.ArgCommand:
					for _, kv := range c.Args {
						if secretName.MatchString(kv.Key) {
							addF(Finding{ID: "SEC004", Severity: High, Penalty: 15, Line: line, Title: "secret passed as build ARG " + kv.Key,
								Fix: "build args are visible in image history; use RUN --mount=type=secret or fetch at runtime"})
						}
					}
				}
			}
		}
		lintPenalty := 0
		for _, l := range in.Parsed.Lint {
			p := 0
			if lintPenalty < 5 {
				p = 1
				lintPenalty++
			}
			addF(Finding{ID: "LINT", Severity: Low, Penalty: p, Line: l.Line, Title: l.Rule + ": " + l.Message, Fix: l.URL})
		}
	}

	// --- files added by the build ---
	var suid, ww []string
	sudo := false
	for _, l := range in.AppLayers {
		err := eachHeader(l, func(name string, h *tar.Header) {
			if h.Typeflag != tar.TypeReg {
				return
			}
			if h.Mode&0o6000 != 0 {
				suid = append(suid, "/"+name)
			}
			if h.Mode&0o002 != 0 && !strings.HasPrefix(name, "tmp/") && !strings.HasPrefix(name, "var/tmp/") {
				ww = append(ww, "/"+name)
			}
			if name == "usr/bin/sudo" {
				sudo = true
			}
		})
		if err != nil {
			return nil, err
		}
	}
	if len(suid) > 0 {
		addF(Finding{ID: "SEC009", Severity: Medium, Penalty: 5, Title: fmt.Sprintf("%d setuid/setgid file(s) added", len(suid)),
			Detail: sample(suid), Fix: "remove the bit: RUN chmod u-s,g-s <file> (or don't install the package)"})
	}
	if len(ww) > 0 {
		addF(Finding{ID: "SEC010", Severity: Low, Penalty: 3, Title: fmt.Sprintf("%d world-writable file(s) added", len(ww)),
			Detail: sample(ww), Fix: "use 0644/0755 and chown to the app user"})
	}
	if sudo {
		addF(Finding{ID: "SEC011", Severity: Medium, Penalty: 5, Title: "sudo installed",
			Fix: "do not install sudo in runtime images"})
	}

	score := 100
	for _, f := range fs {
		score -= f.Penalty
	}
	if score < 0 {
		score = 0
	}
	sort.SliceStable(fs, func(i, j int) bool { return sevRank(fs[i].Severity) < sevRank(fs[j].Severity) })
	r := &Report{Score: score, Grade: grade(score), Findings: fs}
	if in.MinScore > 0 && score < in.MinScore {
		r.Failed = true
		r.Reason = fmt.Sprintf("score %d below minimum %d", score, in.MinScore)
	}
	return r, nil
}

func sample(list []string) string {
	if len(list) > 5 {
		return strings.Join(list[:5], ", ") + fmt.Sprintf(" (+%d)", len(list)-5)
	}
	return strings.Join(list, ", ")
}

func isArchive(s string) bool {
	s = strings.ToLower(s)
	for _, ext := range []string{".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.zst"} {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}
	return false
}

func grade(s int) string {
	switch {
	case s >= 90:
		return "A"
	case s >= 75:
		return "B"
	case s >= 60:
		return "C"
	case s >= 40:
		return "D"
	}
	return "F"
}

func sevRank(s string) int {
	switch s {
	case High:
		return 0
	case Medium:
		return 1
	case Low:
		return 2
	}
	return 3
}

func eachHeader(l v1.Layer, fn func(name string, h *tar.Header)) error {
	rc, err := l.Uncompressed()
	if err != nil {
		return err
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		fn(strings.TrimPrefix(path.Clean("/"+h.Name), "/"), h)
	}
}
