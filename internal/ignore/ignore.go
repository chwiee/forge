// Package ignore loads .forgeignore (or .dockerignore) and decides which build
// context files never reach the image. Syntax is identical to .dockerignore.
package ignore

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/patternmatcher"
	"github.com/moby/patternmatcher/ignorefile"
)

// Files looked up in the context root, first match wins.
var Files = []string{".forgeignore", ".dockerignore"}

// Defaults are always applied first; users can re-include with "!pattern".
var Defaults = []string{".git", ".forge"}

// Matcher filters context-relative paths (slash separated).
type Matcher struct {
	pm     *patternmatcher.PatternMatcher
	Source string // file the patterns came from ("" = defaults only)
}

// Load reads the ignore file from contextDir.
func Load(contextDir string) (*Matcher, error) {
	patterns := append([]string{}, Defaults...)
	source := ""
	for _, name := range Files {
		f, err := os.Open(filepath.Join(contextDir, name))
		if err != nil {
			continue
		}
		ps, err := ignorefile.ReadAll(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, ps...)
		source = name
		break
	}
	pm, err := patternmatcher.New(patterns)
	if err != nil {
		return nil, err
	}
	return &Matcher{pm: pm, Source: source}, nil
}

// New builds a matcher from explicit patterns (used for COPY --exclude).
func New(patterns []string) (*Matcher, error) {
	pm, err := patternmatcher.New(patterns)
	if err != nil {
		return nil, err
	}
	return &Matcher{pm: pm}, nil
}

// Ignored reports whether rel (context-relative) is excluded.
func (m *Matcher) Ignored(rel string) bool {
	if m == nil || m.pm == nil {
		return false
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	rel = strings.TrimPrefix(rel, "./")
	if rel == "." || rel == "" {
		return false
	}
	ok, err := m.pm.MatchesOrParentMatches(rel)
	return err == nil && ok
}

// Exclusions reports whether any pattern re-includes paths ("!pattern"); when true a
// ignored directory must still be walked because a child might be re-included.
func (m *Matcher) Exclusions() bool {
	return m != nil && m.pm != nil && m.pm.Exclusions()
}
