// Package dockerfile parses Dockerfiles with BuildKit's official parser (used as a
// library, no daemon) and collects BuildKit's lint warnings.
package dockerfile

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// Lint is one BuildKit lint warning.
type Lint struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
	Line    int    `json:"line"`
	URL     string `json:"url,omitempty"`
}

// Parsed is a parsed Dockerfile.
type Parsed struct {
	Path        string
	Stages      []instructions.Stage
	MetaArgs    []instructions.ArgCommand
	EscapeToken rune
	Lint        []Lint
	Raw         []byte
}

// Parse reads and parses path.
func Parse(path string) (*Parsed, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	res, err := parser.Parse(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p := &Parsed{Path: path, Raw: raw, EscapeToken: res.EscapeToken}
	lint := linter.New(&linter.Config{
		Warn: func(rule, _ /*description*/, url, msg string, loc []parser.Range) {
			line := 0
			if len(loc) > 0 {
				line = loc[0].Start.Line
			}
			p.Lint = append(p.Lint, Lint{Rule: rule, Message: msg, Line: line, URL: url})
		},
	})
	for _, w := range res.Warnings {
		line := 0
		if w.Location != nil {
			line = w.Location.Start.Line
		}
		p.Lint = append(p.Lint, Lint{Rule: "Parser", Message: w.Short, Line: line, URL: w.URL})
	}
	stages, metaArgs, err := instructions.Parse(res.AST, lint)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(stages) == 0 {
		return nil, fmt.Errorf("%s: no FROM instruction", path)
	}
	p.Stages, p.MetaArgs = stages, metaArgs
	return p, nil
}

// StageIndex resolves a stage name or numeric index; -1 if none.
func (p *Parsed) StageIndex(ref string) int {
	ref = strings.ToLower(ref)
	for i, s := range p.Stages {
		if strings.ToLower(s.Name) == ref && s.Name != "" {
			return i
		}
	}
	if n, err := strconv.Atoi(ref); err == nil && n >= 0 && n < len(p.Stages) {
		return n
	}
	return -1
}

// Line returns the first source line of a command (1-based), 0 if unknown.
func Line(c instructions.Command) int {
	if loc := c.Location(); len(loc) > 0 {
		return loc[0].Start.Line
	}
	return 0
}

// Text returns the original source text of a command.
func Text(c any) string {
	if s, ok := c.(fmt.Stringer); ok {
		return s.String()
	}
	return fmt.Sprintf("%T", c)
}
