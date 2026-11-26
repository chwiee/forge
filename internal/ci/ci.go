// Package ci speaks the log dialect of each CI system, so everything a user
// needs is in the pipeline log (they never get a shell in the runner pod):
//
//	collapsible sections   GitHub ::group::, GitLab section_start, Azure ##[group]
//	annotations            GitHub ::error file=,line=  / Azure ##vso[task.logissue]
//	job summary            GitHub $GITHUB_STEP_SUMMARY (Markdown on the run page)
package ci

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// Provider is the detected CI system.
type Provider int

// Known providers.
const (
	None Provider = iota
	GitHub
	GitLab
	Azure
)

// Detect reads the standard environment variables of each CI.
func Detect() Provider {
	switch {
	case os.Getenv("GITHUB_ACTIONS") == "true":
		return GitHub
	case os.Getenv("GITLAB_CI") != "":
		return GitLab
	case os.Getenv("TF_BUILD") != "":
		return Azure
	}
	return None
}

// String names the provider.
func (p Provider) String() string {
	return [...]string{"", "github", "gitlab", "azure"}[p]
}

var sectionSeq atomic.Int64

var notWord = regexp.MustCompile(`[^a-z0-9_]+`)

// Group writes a collapsed section around body (no-op wrapper when not in CI).
func (p Provider) Group(w io.Writer, title string, body func()) {
	switch p {
	case GitHub:
		fmt.Fprintf(w, "::group::%s\n", title)
		body()
		fmt.Fprintln(w, "::endgroup::")
	case Azure:
		fmt.Fprintf(w, "##[group]%s\n", title)
		body()
		fmt.Fprintln(w, "##[endgroup]")
	case GitLab:
		name := fmt.Sprintf("forge_%d_%s", sectionSeq.Add(1), notWord.ReplaceAllString(strings.ToLower(title), "_"))
		fmt.Fprintf(w, "\x1b[0Ksection_start:%d:%s[collapsed=true]\r\x1b[0K%s\n", time.Now().Unix(), name, title)
		body()
		fmt.Fprintf(w, "\x1b[0Ksection_end:%d:%s\r\x1b[0K\n", time.Now().Unix(), name)
	default:
		body()
	}
}

// Level of an annotation.
type Level string

// Annotation levels.
const (
	Error   Level = "error"
	Warning Level = "warning"
)

// Annotation points at a problem; File is relative to the repository root.
type Annotation struct {
	Level Level
	Title string
	Msg   string
	File  string
	Line  int
}

// maxAnnotations: GitHub shows at most 10 errors and 10 warnings per step.
const maxAnnotations = 10

// Annotate emits annotations (GitHub/Azure); extra ones are folded into one.
func (p Provider) Annotate(w io.Writer, as []Annotation) {
	if p != GitHub && p != Azure {
		return
	}
	count := map[Level]int{}
	var dropped []Annotation
	for _, a := range as {
		if count[a.Level] >= maxAnnotations-1 {
			dropped = append(dropped, a)
			continue
		}
		count[a.Level]++
		p.annotate(w, a)
	}
	if len(dropped) > 0 {
		p.annotate(w, Annotation{Level: dropped[0].Level, Title: "forge",
			Msg: fmt.Sprintf("%d more finding(s) — see the forge log for the complete list", len(dropped))})
	}
}

func (p Provider) annotate(w io.Writer, a Annotation) {
	switch p {
	case GitHub:
		var props []string
		if a.File != "" {
			props = append(props, "file="+escapeProp(a.File))
			if a.Line > 0 {
				props = append(props, fmt.Sprintf("line=%d", a.Line))
			}
		}
		if a.Title != "" {
			props = append(props, "title="+escapeProp(a.Title))
		}
		fmt.Fprintf(w, "::%s %s::%s\n", a.Level, strings.Join(props, ","), escapeData(a.Msg))
	case Azure:
		props := "type=" + string(a.Level)
		if a.File != "" {
			props += ";sourcepath=" + a.File
			if a.Line > 0 {
				props += fmt.Sprintf(";linenumber=%d", a.Line)
			}
		}
		msg := a.Msg
		if a.Title != "" {
			msg = a.Title + ": " + msg
		}
		fmt.Fprintf(w, "##vso[task.logissue %s]%s\n", props, strings.ReplaceAll(msg, "\n", " "))
	}
}

func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func escapeProp(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}

// RepoPath makes an absolute path relative to the checkout, for annotations.
func RepoPath(abs string) string {
	for _, root := range []string{os.Getenv("GITHUB_WORKSPACE"), os.Getenv("BUILD_SOURCESDIRECTORY"), os.Getenv("CI_PROJECT_DIR")} {
		if root == "" {
			continue
		}
		if rel, err := filepath.Rel(root, abs); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return ""
}

// StepSummary appends Markdown to the GitHub Actions job summary.
func StepSummary(md string) error {
	p := os.Getenv("GITHUB_STEP_SUMMARY")
	if p == "" {
		return nil
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.WriteString(f, md)
	return err
}
