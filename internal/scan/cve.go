// Package scan finds known vulnerabilities (CVEs) with Syft (SBOM) + Grype
// (matching), both used as libraries. The Grype database is cached locally and
// can come from an internal mirror (forge db serve) via --db-url / FORGE_DB_URL.
package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/sbom"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

// Severity order, most severe first.
var Severities = []string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}

// Options configures a scan.
type Options struct {
	CacheDir  string
	DBURL     string // mirror base URL ("" = public Anchore endpoint)
	FailOn    string // critical|high|medium|low|none
	OnlyFixed bool   // gate counts only vulnerabilities that have a fix
	Ignore    []string
	SBOMPath  string // optional CycloneDX JSON output
	Version   string
	OnDB      func(msg string)
}

// Vuln is one finding.
type Vuln struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Package  string `json:"package"`
	Version  string `json:"version"`
	Type     string `json:"type"`
	FixedIn  string `json:"fixedIn,omitempty"`
	Path     string `json:"path,omitempty"`
	KEV      bool   `json:"knownExploited,omitempty"`
}

// DBInfo describes the vulnerability database used.
type DBInfo struct {
	Built  time.Time `json:"built"`
	Schema string    `json:"schema"`
	Source string    `json:"source"`
}

// Report is the scan result.
type Report struct {
	Vulns    []Vuln         `json:"vulnerabilities"`
	Counts   map[string]int `json:"counts"`
	Fixable  map[string]int `json:"fixable"`
	Packages int            `json:"packages"`
	Distro   string         `json:"distro,omitempty"`
	DB       DBInfo         `json:"db"`
	Failed   bool           `json:"failed"`
	Reason   string         `json:"reason,omitempty"`
}

// LoadDB opens (and updates if due) the vulnerability database.
func LoadDB(o Options) (vulnerability.Provider, DBInfo, error) {
	id := clio.Identification{Name: "forge", Version: o.Version}
	inst := v6inst.DefaultConfig(id)
	inst.DBRootDir = filepath.Join(o.CacheDir, "grype-db")
	inst.MaxAllowedBuiltAge = 7 * 24 * time.Hour

	urls := []string{}
	if u := strings.TrimSpace(o.DBURL); u != "" {
		urls = append(urls, u)
	}
	urls = append(urls, v6dist.DefaultConfig().LatestURL)

	var lastErr error
	for i, u := range urls {
		dist := v6dist.DefaultConfig()
		dist.ID = id
		dist.LatestURL = u
		dist.RequireUpdateCheck = i < len(urls)-1 // mirror must answer, else try next
		if o.OnDB != nil {
			o.OnDB("vulnerability DB from " + u)
		}
		vp, status, err := grype.LoadVulnerabilityDB(dist, inst, true)
		if err == nil {
			info := DBInfo{Source: u}
			if status != nil {
				info.Built, info.Schema = status.Built, status.SchemaVersion
				if status.From != "" {
					info.Source = status.From
				}
			}
			return vp, info, nil
		}
		lastErr = err
	}
	return nil, DBInfo{}, fmt.Errorf("vulnerability database unavailable: %w", lastErr)
}

// Image scans an image, loading the database just for this call.
func Image(ctx context.Context, img v1.Image, workDir string, o Options) (*Report, error) {
	s, err := Open(o)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Image(ctx, img, workDir, o)
}

// Scanner holds a loaded database; share one across platforms. Scans are
// serialized (Syft/Grype are not documented as safe for concurrent use).
type Scanner struct {
	vp   vulnerability.Provider
	info DBInfo
	mu   sync.Mutex
}

// Open loads the database (update if due, mirror then public endpoint).
func Open(o Options) (*Scanner, error) {
	vp, info, err := LoadDB(o)
	if err != nil {
		return nil, err
	}
	return &Scanner{vp: vp, info: info}, nil
}

// Close releases the database.
func (s *Scanner) Close() error { return s.vp.Close() }

// Image scans one image with the loaded database.
func (sc *Scanner) Image(ctx context.Context, img v1.Image, workDir string, o Options) (*Report, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	vp, dbInfo := sc.vp, sc.info

	dir, err := os.MkdirTemp(workDir, "oci-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		return nil, err
	}
	if err := p.AppendImage(img); err != nil {
		return nil, fmt.Errorf("prepare image for scan: %w", err)
	}

	cfg := syft.DefaultCreateSBOMConfig()
	cfg.Compliance.MissingVersion = cataloging.ComplianceActionDrop
	pcfg := pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{SBOMOptions: cfg, Name: "image"},
	}
	pkgs, pctx, s, err := pkg.Provide("oci-dir:"+dir, pcfg)
	if err != nil {
		return nil, fmt.Errorf("catalog packages: %w", err)
	}
	if o.SBOMPath != "" && s != nil {
		if err := writeSBOM(o.SBOMPath, *s); err != nil {
			return nil, err
		}
	}

	m := grype.VulnerabilityMatcher{
		VulnerabilityProvider: vp,
		Matchers:              matcher.NewDefaultMatchers(matcher.Config{}),
		NormalizeByCVE:        true,
	}
	matches, _, err := m.FindMatchesContext(ctx, pkgs, pctx)
	if err != nil {
		return nil, err
	}
	doc, err := models.NewDocument(clio.Identification{Name: "forge", Version: o.Version}, pkgs, pctx, *matches, nil, vp, nil, nil, models.SortBySeverity, false, nil)
	if err != nil {
		return nil, err
	}

	ignored := map[string]bool{}
	for _, id := range o.Ignore {
		ignored[strings.ToUpper(strings.TrimSpace(id))] = true
	}
	r := &Report{Counts: map[string]int{}, Fixable: map[string]int{}, Packages: len(pkgs), DB: dbInfo}
	if doc.Distro.Name != "" {
		r.Distro = strings.TrimSpace(doc.Distro.Name + " " + doc.Distro.Version)
	}
	seen := map[string]bool{}
	for _, mm := range doc.Matches {
		v := Vuln{
			ID:       mm.Vulnerability.ID,
			Severity: normSeverity(mm.Vulnerability.Severity),
			Package:  mm.Artifact.Name,
			Version:  mm.Artifact.Version,
			Type:     string(mm.Artifact.Type),
			KEV:      len(mm.Vulnerability.KnownExploited) > 0,
		}
		if ignored[strings.ToUpper(v.ID)] {
			continue
		}
		if mm.Vulnerability.Fix.State == "fixed" && len(mm.Vulnerability.Fix.Versions) > 0 {
			v.FixedIn = strings.Join(mm.Vulnerability.Fix.Versions, ", ")
		}
		if locs := mm.Artifact.Locations; len(locs) > 0 {
			v.Path = locs[0].RealPath
		}
		k := v.ID + "|" + v.Package + "|" + v.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		r.Vulns = append(r.Vulns, v)
		r.Counts[v.Severity]++
		if v.FixedIn != "" {
			r.Fixable[v.Severity]++
		}
	}
	sort.SliceStable(r.Vulns, func(i, j int) bool {
		a, b := rank(r.Vulns[i].Severity), rank(r.Vulns[j].Severity)
		if a != b {
			return a < b
		}
		if (r.Vulns[i].FixedIn != "") != (r.Vulns[j].FixedIn != "") {
			return r.Vulns[i].FixedIn != ""
		}
		return r.Vulns[i].ID < r.Vulns[j].ID
	})
	r.gate(o)
	return r, nil
}

func (r *Report) gate(o Options) {
	threshold := rank(normSeverity(o.FailOn))
	if strings.EqualFold(o.FailOn, "none") || o.FailOn == "" {
		return
	}
	n := 0
	for _, v := range r.Vulns {
		if rank(v.Severity) <= threshold && (!o.OnlyFixed || v.FixedIn != "") {
			n++
		}
	}
	if n > 0 {
		r.Failed = true
		kind := ""
		if o.OnlyFixed {
			kind = " with a fix available"
		}
		r.Reason = fmt.Sprintf("%d vulnerabilities at or above %s%s", n, strings.ToLower(normSeverity(o.FailOn)), kind)
	}
}

func normSeverity(s string) string {
	for _, sev := range Severities {
		if strings.EqualFold(s, sev) {
			return sev
		}
	}
	return "Unknown"
}

func rank(sev string) int {
	for i, s := range Severities {
		if s == sev {
			return i
		}
	}
	return len(Severities)
}

// Rank is exported for presentation ordering.
func Rank(sev string) int { return rank(sev) }

func writeSBOM(p string, s sbom.SBOM) error {
	enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	defer f.Close()
	return enc.Encode(f, s)
}

// ErrGate is returned by callers when a gate fails.
var ErrGate = errors.New("security gate failed")

// Info describes the loaded database.
func (sc *Scanner) Info() DBInfo { return sc.info }
