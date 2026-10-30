// Package leaks finds hardcoded secrets with Gitleaks (used as a library) in:
//   - files the Dockerfile put into the image   (blocking)
//   - image config: ENV, LABEL, build history   (blocking)
//   - the build context not excluded by ignore  (warning: may never ship)
package leaks

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/rs/zerolog"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"

	"github.com/chwiee/forge/internal/ignore"
)

// Where a finding was found.
const (
	InImage   = "image"
	InConfig  = "config"
	InContext = "context"
)

const maxFileSize = 2 << 20 // 2 MiB: larger files are almost never config/source

// Finding is one detected secret (value redacted).
type Finding struct {
	Rule        string `json:"rule"`
	Description string `json:"description"`
	Where       string `json:"where"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Secret      string `json:"secret"`
	Fingerprint string `json:"fingerprint"`
}

// Report is the leaks result.
type Report struct {
	Findings []Finding `json:"findings"`
	Blocking int       `json:"blocking"`
	Warnings int       `json:"warnings"`
	Scanned  int       `json:"filesScanned"`
	Failed   bool      `json:"failed"`
	Reason   string    `json:"reason,omitempty"`
}

// Options configures the scan.
type Options struct {
	ContextDir    string
	Ignore        *ignore.Matcher
	AppLayers     []v1.Layer
	Config        *v1.ConfigFile
	FailOnContext bool // treat context findings as blocking too
	Enabled       bool
}

// Scan runs all sources.
func Scan(ctx context.Context, o Options) (*Report, error) {
	logging.Logger = zerolog.Nop()
	det, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("gitleaks: %w", err)
	}
	allow := loadIgnore(filepath.Join(o.ContextDir, ".gitleaksignore"))
	r := &Report{}
	add := func(where, file string, content []byte) {
		r.Scanned++
		for _, f := range det.DetectContext(ctx, detect.Fragment{Raw: string(content), FilePath: file}) {
			fp := fmt.Sprintf("%s:%s:%d", file, f.RuleID, f.StartLine)
			if allow[fp] || allow[f.Fingerprint] {
				continue
			}
			r.Findings = append(r.Findings, Finding{
				Rule: f.RuleID, Description: f.Description, Where: where, File: file,
				Line: f.StartLine, Secret: redact(f.Secret), Fingerprint: fp,
			})
		}
	}

	// 1. image config
	if o.Config != nil {
		var b strings.Builder
		for _, e := range o.Config.Config.Env {
			b.WriteString("ENV " + e + "\n")
		}
		keys := make([]string, 0, len(o.Config.Config.Labels))
		for k := range o.Config.Config.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString("LABEL " + k + "=" + o.Config.Config.Labels[k] + "\n")
		}
		for _, h := range o.Config.History {
			b.WriteString(h.CreatedBy + "\n")
		}
		add(InConfig, "image-config", []byte(b.String()))
	}

	// 2. files added by the Dockerfile
	for _, l := range o.AppLayers {
		if err := scanLayer(l, func(name string, data []byte) { add(InImage, "/"+name, data) }); err != nil {
			return nil, err
		}
	}

	// 3. build context
	if o.ContextDir != "" {
		err := filepath.WalkDir(o.ContextDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			rel, _ := filepath.Rel(o.ContextDir, p)
			rel = filepath.ToSlash(rel)
			if rel == "." {
				return nil
			}
			if o.Ignore.Ignored(rel) {
				if d.IsDir() && !o.Ignore.Exclusions() {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			fi, err := d.Info()
			if err != nil || fi.Size() > maxFileSize || fi.Size() == 0 {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil || isBinary(data) {
				return nil
			}
			add(InContext, rel, data)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	for _, f := range r.Findings {
		if f.Where == InContext && !o.FailOnContext {
			r.Warnings++
		} else {
			r.Blocking++
		}
	}
	if r.Blocking > 0 {
		r.Failed = true
		r.Reason = fmt.Sprintf("%d secret(s) shipped in the image", r.Blocking)
	}
	sort.SliceStable(r.Findings, func(i, j int) bool { return order(r.Findings[i].Where) < order(r.Findings[j].Where) })
	return r, nil
}

func order(w string) int {
	switch w {
	case InImage:
		return 0
	case InConfig:
		return 1
	}
	return 2
}

func scanLayer(l v1.Layer, fn func(name string, data []byte)) error {
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
		if h.Typeflag != tar.TypeReg || h.Size == 0 || h.Size > maxFileSize {
			continue
		}
		name := strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		if strings.HasPrefix(path.Base(name), ".wh.") || skipImagePath(name) {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		if isBinary(data) {
			continue
		}
		fn(name, data)
	}
}

// skipImagePath avoids noise from package databases and vendored test fixtures.
func skipImagePath(p string) bool {
	for _, pre := range []string{"var/lib/dpkg/", "var/lib/apt/", "var/cache/", "usr/share/doc/", "usr/share/man/", "lib/apk/db/", "var/lib/rpm/", "etc/ssl/certs/", "usr/share/ca-certificates/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func isBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(b[:n], 0) >= 0
}

func redact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 6 {
		return "****"
	}
	return s[:4] + strings.Repeat("*", 8)
}

// loadIgnore reads .gitleaksignore fingerprints ("file:rule:line").
func loadIgnore(p string) map[string]bool {
	m := map[string]bool{}
	f, err := os.Open(p)
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			m[l] = true
		}
	}
	return m
}
