// Package report is the machine-readable result of a forge run (JSON), meant
// for pipelines, dashboards and audits.
package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/chwiee/forge/internal/leaks"
	"github.com/chwiee/forge/internal/scan"
	"github.com/chwiee/forge/internal/sec"
)

// Report aggregates every stage of every platform.
type Report struct {
	Version    string     `json:"forgeVersion"`
	Started    time.Time  `json:"started"`
	Duration   string     `json:"duration"`
	Dockerfile string     `json:"dockerfile"`
	Context    string     `json:"context"`
	Digest     string     `json:"digest,omitempty"` // index digest when multi-platform
	Platforms  []Platform `json:"platforms"`
	// ContextLeaks is the build-context secret scan (done once, not per platform).
	ContextLeaks *leaks.Report `json:"contextLeaks,omitempty"`
	// Cancelled lists platforms whose build was stopped (gate failure elsewhere).
	Cancelled []string `json:"cancelled,omitempty"`
	Push      *Push    `json:"push,omitempty"`
	Passed    bool     `json:"passed"`
	Failures  []string `json:"failures,omitempty"`
}

// Platform is the result for one architecture.
type Platform struct {
	Platform string        `json:"platform"`
	Image    Image         `json:"image"`
	Build    Build         `json:"build"`
	Slim     *Slim         `json:"slim,omitempty"`
	CVE      *scan.Report  `json:"cve,omitempty"`
	Sec      *sec.Report   `json:"sec,omitempty"`
	Leaks    *leaks.Report `json:"leaks,omitempty"`
}

// Image describes one platform image.
type Image struct {
	Digest string `json:"digest,omitempty"`
	Base   string `json:"base"`
	Size   int64  `json:"compressedSize"`
	Layers int    `json:"layers"`
}

// Build summarizes the build step.
type Build struct {
	Steps     int    `json:"steps"`
	Cached    int    `json:"cached"`
	Isolation string `json:"isolation,omitempty"`
	Duration  string `json:"duration"`
}

// Slim summarizes size reduction.
type Slim struct {
	Applied      bool             `json:"applied"`
	Reason       string           `json:"reason,omitempty"`
	SizeBefore   int64            `json:"sizeBefore"`
	SizeAfter    int64            `json:"sizeAfter"`
	LayersBefore int              `json:"layersBefore"`
	LayersAfter  int              `json:"layersAfter"`
	Removed      map[string]int64 `json:"removedBytes,omitempty"`
}

// Push records where the image went.
type Push struct {
	Registry string   `json:"registry"`
	Refs     []string `json:"refs,omitempty"`
	Digest   string   `json:"digest,omitempty"`
	Skipped  string   `json:"skipped,omitempty"`
}

// Write saves the report as indented JSON.
func (r *Report) Write(p string) error {
	if p == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}
