// Package dbmirror keeps a local copy of the Grype vulnerability database and
// serves it over HTTP in the same layout as grype.anchore.io, so CI runners
// point FORGE_DB_URL at an in-cluster pod instead of the internet.
//
//	<dir>/v6/latest.json
//	<dir>/v6/vulnerability-db_v6..._<ts>.tar.zst
package dbmirror

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultUpstream is Anchore's public distribution endpoint.
const DefaultUpstream = "https://grype.anchore.io/databases"

// Latest mirrors grype's latest.json document.
type Latest struct {
	Status        string `json:"status"`
	SchemaVersion string `json:"schemaVersion"`
	Built         string `json:"built"`
	Path          string `json:"path"`
	Checksum      string `json:"checksum"`
}

// Status is reported by /healthz and `forge db sync`.
type Status struct {
	Latest     Latest    `json:"latest"`
	SyncedAt   time.Time `json:"syncedAt"`
	Downloaded bool      `json:"downloaded"`
	Bytes      int64     `json:"bytes"`
	Error      string    `json:"error,omitempty"`
}

var client = &http.Client{Timeout: 15 * time.Minute}

// Sync downloads the latest archive if it is not already present.
func Sync(ctx context.Context, dir, upstream string) (Status, error) {
	if upstream == "" {
		upstream = DefaultUpstream
	}
	latestURL := strings.TrimRight(upstream, "/") + "/v6/latest.json"
	v6 := filepath.Join(dir, "v6")
	if err := os.MkdirAll(v6, 0o755); err != nil {
		return Status{}, err
	}

	raw, err := get(ctx, latestURL)
	if err != nil {
		return Status{}, err
	}
	var l Latest
	if err := json.Unmarshal(raw, &l); err != nil {
		return Status{}, fmt.Errorf("parse latest.json: %w", err)
	}
	if l.Path == "" || strings.Contains(l.Path, "..") || strings.Contains(l.Path, "/") {
		return Status{}, fmt.Errorf("unexpected archive path %q", l.Path)
	}
	st := Status{Latest: l, SyncedAt: time.Now().UTC()}
	archive := filepath.Join(v6, l.Path)

	want := strings.TrimPrefix(l.Checksum, "sha256:")
	if fileSHA(archive) != want {
		u, err := url.Parse(latestURL)
		if err != nil {
			return st, err
		}
		u.Path = path.Join(path.Dir(u.Path), l.Path)
		n, got, err := download(ctx, u.String(), archive+".tmp")
		if err != nil {
			return st, err
		}
		if got != want {
			os.Remove(archive + ".tmp")
			return st, fmt.Errorf("checksum mismatch for %s", l.Path)
		}
		if err := os.Rename(archive+".tmp", archive); err != nil {
			return st, err
		}
		st.Downloaded, st.Bytes = true, n
	}
	// publish latest.json only after the archive is in place
	if err := os.WriteFile(filepath.Join(v6, "latest.json.tmp"), raw, 0o644); err != nil {
		return st, err
	}
	if err := os.Rename(filepath.Join(v6, "latest.json.tmp"), filepath.Join(v6, "latest.json")); err != nil {
		return st, err
	}
	prune(v6, l.Path, 2)
	return st, nil
}

func get(ctx context.Context, u string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func download(ctx context.Context, u, dst string) (int64, string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return n, hex.EncodeToString(h.Sum(nil)), err
}

func fileSHA(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// prune keeps the current archive plus the newest (keep-1) others.
func prune(dir, current string, keep int) {
	entries, _ := os.ReadDir(dir)
	var archives []os.DirEntry
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "vulnerability-db_") && e.Name() != current && !strings.HasSuffix(e.Name(), ".tmp") {
			archives = append(archives, e)
		}
	}
	sort.Slice(archives, func(i, j int) bool { return archives[i].Name() > archives[j].Name() })
	for i, e := range archives {
		if i >= keep-1 {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// Server serves the mirror and re-syncs on an interval.
type Server struct {
	Dir      string
	Upstream string
	Every    time.Duration
	Log      *slog.Logger

	mu     sync.RWMutex
	status Status
}

// Run blocks until ctx is done.
func (s *Server) Run(ctx context.Context, addr string) error {
	s.syncOnce(ctx)
	go func() {
		t := time.NewTicker(s.Every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.syncOnce(ctx)
			}
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/databases/", http.StripPrefix("/databases/", http.FileServer(http.Dir(s.Dir))))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.RLock()
		st := s.status
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		if st.Latest.Path == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(st)
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	s.Log.Info("serving vulnerability DB mirror", "addr", addr, "path", "/databases", "sync_every", s.Every.String())
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) syncOnce(ctx context.Context) {
	st, err := Sync(ctx, s.Dir, s.Upstream)
	if err != nil {
		s.Log.Error("db sync failed (serving previous copy)", "err", err)
		s.mu.Lock()
		s.status.Error = err.Error()
		s.mu.Unlock()
		return
	}
	s.Log.Info("db synced", "built", st.Latest.Built, "archive", st.Latest.Path, "downloaded", st.Downloaded, "bytes", st.Bytes)
	s.mu.Lock()
	s.status = st
	s.mu.Unlock()
}
