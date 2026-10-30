// Package cache stores build-step layers by content and indexes them by step key,
// so unchanged Dockerfile steps are reused across builds (and across pipelines
// when the cache dir is a persistent volume).
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/klauspost/compress/gzip"
)

// Store is a directory: blobs/<sha256>.tar.gz + keys/<key>.json
type Store struct {
	Dir string

	locks sync.Map // key -> *sync.Mutex (singleflight between concurrent builds)
}

// Lock serializes work on one step key inside this process: when two platform
// builds reach the same step (FROM --platform=$BUILDPLATFORM), the second waits
// and then finds the layer in the cache instead of building it again.
func (s *Store) Lock(key string) func() {
	m, _ := s.locks.LoadOrStore(key, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// Entry is the cached result of one build step.
type Entry struct {
	Empty   bool      `json:"empty"`
	Digest  string    `json:"digest,omitempty"` // sha256 of the gzip blob
	DiffID  string    `json:"diffId,omitempty"` // sha256 of the uncompressed tar
	Size    int64     `json:"size,omitempty"`   // compressed size
	Created time.Time `json:"created"`
	Step    string    `json:"step,omitempty"`
}

// stores keeps one Store per directory so locks are shared by every build in the process.
var (
	storesMu sync.Mutex
	stores   = map[string]*Store{}
)

// Open creates the directory layout if needed and returns the shared Store for dir.
func Open(dir string) (*Store, error) {
	storesMu.Lock()
	defer storesMu.Unlock()
	if s, ok := stores[dir]; ok {
		return s, nil
	}
	for _, d := range []string{"blobs", "keys", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return nil, err
		}
	}
	s := &Store{Dir: dir}
	stores[dir] = s
	return s, nil
}

// Key hashes the parts of a step into a cache key.
func Key(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns the entry for key, if present and its blob still exists.
func (s *Store) Get(key string) (*Entry, bool) {
	b, err := os.ReadFile(filepath.Join(s.Dir, "keys", key+".json"))
	if err != nil {
		return nil, false
	}
	var e Entry
	if json.Unmarshal(b, &e) != nil {
		return nil, false
	}
	if !e.Empty {
		if _, err := os.Stat(s.blobPath(e.Digest)); err != nil {
			return nil, false
		}
	}
	// touch for LRU-style pruning
	now := time.Now()
	_ = os.Chtimes(filepath.Join(s.Dir, "keys", key+".json"), now, now)
	return &e, true
}

// Put records an entry for key.
func (s *Store) Put(key string, e Entry) error {
	b, _ := json.Marshal(e)
	f, err := os.CreateTemp(filepath.Join(s.Dir, "tmp"), "key-*")
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), filepath.Join(s.Dir, "keys", key+".json"))
}

func (s *Store) blobPath(digest string) string {
	if len(digest) > 7 && digest[:7] == "sha256:" {
		digest = digest[7:]
	}
	return filepath.Join(s.Dir, "blobs", digest+".tar.gz")
}

// WriteLayer runs fn with a writer for the uncompressed tar, gzips it into the
// store and returns digests. entries==0 means the step changed nothing.
func (s *Store) WriteLayer(fn func(w io.Writer) (entries int, err error)) (Entry, error) {
	f, err := os.CreateTemp(filepath.Join(s.Dir, "tmp"), "layer-*")
	if err != nil {
		return Entry{}, err
	}
	defer os.Remove(f.Name())

	compHash := sha256.New()
	counter := &countWriter{}
	gz, _ := gzip.NewWriterLevel(io.MultiWriter(f, compHash, counter), gzip.DefaultCompression)
	diffHash := sha256.New()

	n, err := fn(io.MultiWriter(gz, diffHash))
	if err != nil {
		f.Close()
		return Entry{}, err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return Entry{}, err
	}
	if err := f.Close(); err != nil {
		return Entry{}, err
	}
	if n == 0 {
		return Entry{Empty: true, Created: time.Now()}, nil
	}
	e := Entry{
		Digest:  "sha256:" + hexOf(compHash),
		DiffID:  "sha256:" + hexOf(diffHash),
		Size:    counter.n,
		Created: time.Now(),
	}
	if err := os.Rename(f.Name(), s.blobPath(e.Digest)); err != nil {
		return Entry{}, err
	}
	return e, nil
}

func hexOf(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// Layer returns a v1.Layer backed by the cached blob.
func (s *Store) Layer(e Entry, mt types.MediaType) (v1.Layer, error) {
	if e.Empty {
		return nil, errors.New("empty layer has no blob")
	}
	d, err := v1.NewHash(e.Digest)
	if err != nil {
		return nil, err
	}
	di, err := v1.NewHash(e.DiffID)
	if err != nil {
		return nil, err
	}
	return &blobLayer{path: s.blobPath(e.Digest), digest: d, diffID: di, size: e.Size, mt: mt}, nil
}

type blobLayer struct {
	path   string
	digest v1.Hash
	diffID v1.Hash
	size   int64
	mt     types.MediaType
}

func (l *blobLayer) Digest() (v1.Hash, error)            { return l.digest, nil }
func (l *blobLayer) DiffID() (v1.Hash, error)            { return l.diffID, nil }
func (l *blobLayer) Size() (int64, error)                { return l.size, nil }
func (l *blobLayer) MediaType() (types.MediaType, error) { return l.mt, nil }
func (l *blobLayer) Compressed() (io.ReadCloser, error)  { return os.Open(l.path) }
func (l *blobLayer) Uncompressed() (io.ReadCloser, error) {
	f, err := os.Open(l.path)
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", l.path, err)
	}
	return &readCloser{Reader: gz, close: func() error { gz.Close(); return f.Close() }}, nil
}

type readCloser struct {
	io.Reader
	close func() error
}

func (r *readCloser) Close() error { return r.close() }

// Stats summarizes the store.
type Stats struct {
	Keys  int
	Blobs int
	Bytes int64
}

// Stat walks the store.
func (s *Store) Stat() (Stats, error) {
	var st Stats
	keys, _ := os.ReadDir(filepath.Join(s.Dir, "keys"))
	st.Keys = len(keys)
	blobs, _ := os.ReadDir(filepath.Join(s.Dir, "blobs"))
	for _, b := range blobs {
		if fi, err := b.Info(); err == nil {
			st.Blobs++
			st.Bytes += fi.Size()
		}
	}
	return st, nil
}

// Prune removes keys not used since cutoff and blobs no key references.
func (s *Store) Prune(cutoff time.Time) (removed int, freed int64, err error) {
	keysDir := filepath.Join(s.Dir, "keys")
	keys, _ := os.ReadDir(keysDir)
	live := map[string]bool{}
	for _, k := range keys {
		p := filepath.Join(keysDir, k.Name())
		fi, err := k.Info()
		if err != nil {
			continue
		}
		if fi.ModTime().Before(cutoff) {
			_ = os.Remove(p)
			continue
		}
		var e Entry
		if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &e) == nil && !e.Empty {
			live[filepath.Base(s.blobPath(e.Digest))] = true
		}
	}
	blobs, _ := os.ReadDir(filepath.Join(s.Dir, "blobs"))
	for _, b := range blobs {
		if live[b.Name()] {
			continue
		}
		if fi, err := b.Info(); err == nil {
			freed += fi.Size()
		}
		if os.Remove(filepath.Join(s.Dir, "blobs", b.Name())) == nil {
			removed++
		}
	}
	return removed, freed, nil
}
