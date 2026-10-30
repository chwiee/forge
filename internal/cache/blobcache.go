package cache

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	ggcrcache "github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

// BlobCache caches registry layers on disk, safe for concurrent builds:
// blobs are written to a temp file, verified against their digest and only then
// renamed into place (go-containerregistry's own fs cache writes in place, so a
// concurrent or interrupted pull can leave a truncated blob that is later
// served as valid).
//
//	blobs/<digest-hex>     compressed layer as stored in the registry
//	diff/<diffid-hex>      text file with the digest of the blob (lookup by diffID)
//	meta/<digest-hex>     {"diffID","mediaType"} (lookup by digest keeps both)
type BlobCache struct {
	dir string
}

// NewBlobCache returns a cache rooted at dir.
func NewBlobCache(dir string) *BlobCache {
	_ = os.MkdirAll(filepath.Join(dir, "blobs"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "diff"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "meta"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "tmp"), 0o755)
	return &BlobCache{dir: dir}
}

var _ ggcrcache.Cache = (*BlobCache)(nil)

func (c *BlobCache) blob(h v1.Hash) string { return filepath.Join(c.dir, "blobs", h.Hex) }
func (c *BlobCache) diff(h v1.Hash) string { return filepath.Join(c.dir, "diff", h.Hex) }
func (c *BlobCache) meta(h v1.Hash) string { return filepath.Join(c.dir, "meta", h.Hex+".json") }

type blobMeta struct {
	DiffID    string          `json:"diffID"`
	MediaType types.MediaType `json:"mediaType"`
}

func (c *BlobCache) open(digest v1.Hash) *cachedBlob {
	b := &cachedBlob{path: c.blob(digest), digest: digest, mt: types.DockerLayer}
	if raw, err := os.ReadFile(c.meta(digest)); err == nil {
		var m blobMeta
		if json.Unmarshal(raw, &m) == nil {
			if h, err := v1.NewHash(m.DiffID); err == nil {
				b.diffID = h
			}
			if m.MediaType != "" {
				b.mt = m.MediaType
			}
		}
	}
	return b
}

// Get finds a layer by digest or by diffID.
func (c *BlobCache) Get(h v1.Hash) (v1.Layer, error) {
	if _, err := os.Stat(c.blob(h)); err == nil {
		return c.open(h), nil
	}
	if b, err := os.ReadFile(c.diff(h)); err == nil {
		d, err := v1.NewHash(strings.TrimSpace(string(b)))
		if err == nil {
			if _, err := os.Stat(c.blob(d)); err == nil {
				b := c.open(d)
				b.diffID = h
				return b, nil
			}
		}
	}
	return nil, ggcrcache.ErrNotFound
}

// Put wraps l so that fully consuming it stores a verified copy.
func (c *BlobCache) Put(l v1.Layer) (v1.Layer, error) {
	return &teeLayer{Layer: l, c: c}, nil
}

// Delete removes a blob.
func (c *BlobCache) Delete(h v1.Hash) error {
	err := os.Remove(c.blob(h))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// ---- cached layer ----

type cachedBlob struct {
	path   string
	digest v1.Hash
	diffID v1.Hash
	mt     types.MediaType
}

func (b *cachedBlob) Digest() (v1.Hash, error) { return b.digest, nil }
func (b *cachedBlob) DiffID() (v1.Hash, error) {
	if b.diffID.Hex != "" {
		return b.diffID, nil
	}
	// older entry without metadata: hash the uncompressed stream
	rc, err := b.Uncompressed()
	if err != nil {
		return v1.Hash{}, err
	}
	defer rc.Close()
	h, _, err := v1.SHA256(rc)
	if err != nil {
		return v1.Hash{}, err
	}
	b.diffID = h
	return h, nil
}
func (b *cachedBlob) Size() (int64, error) {
	fi, err := os.Stat(b.path)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}
func (b *cachedBlob) MediaType() (types.MediaType, error) { return b.mt, nil }
func (b *cachedBlob) Compressed() (io.ReadCloser, error)  { return os.Open(b.path) }
func (b *cachedBlob) Uncompressed() (io.ReadCloser, error) {
	f, err := os.Open(b.path)
	if err != nil {
		return nil, err
	}
	return decompress(f)
}

// decompress detects gzip/zstd/plain tar and closes src on Close.
func decompress(src io.ReadCloser) (io.ReadCloser, error) {
	br := bufio.NewReader(src)
	magic, _ := br.Peek(4)
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		gz, err := gzip.NewReader(br)
		if err != nil {
			src.Close()
			return nil, err
		}
		return &readCloser{Reader: gz, close: func() error { gz.Close(); return src.Close() }}, nil
	case len(magic) == 4 && string(magic) == "\x28\xb5\x2f\xfd":
		z, err := zstd.NewReader(br)
		if err != nil {
			src.Close()
			return nil, err
		}
		return &readCloser{Reader: z, close: func() error { z.Close(); return src.Close() }}, nil
	}
	return &readCloser{Reader: br, close: src.Close}, nil
}

// ---- write-through layer ----

type teeLayer struct {
	v1.Layer
	c *BlobCache
}

func (t *teeLayer) Compressed() (io.ReadCloser, error) {
	rc, err := t.Layer.Compressed()
	if err != nil {
		return nil, err
	}
	digest, err := t.Layer.Digest()
	if err != nil {
		rc.Close()
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Join(t.c.dir, "tmp"), "blob-*")
	if err != nil {
		return rc, nil // caching is best effort
	}
	h := sha256.New()
	return &teeReader{src: rc, tmp: tmp, h: h, r: io.TeeReader(rc, io.MultiWriter(tmp, h)), layer: t, digest: digest}, nil
}

func (t *teeLayer) Uncompressed() (io.ReadCloser, error) {
	rc, err := t.Compressed()
	if err != nil {
		return nil, err
	}
	return decompress(rc)
}

type teeReader struct {
	src    io.ReadCloser
	tmp    *os.File
	h      hash.Hash
	r      io.Reader
	layer  *teeLayer
	digest v1.Hash
}

func (t *teeReader) Read(p []byte) (int, error) { return t.r.Read(p) }

// Close drains the stream (tar readers stop before the compressed EOF), verifies
// the digest and publishes the blob atomically.
func (t *teeReader) Close() error {
	_, drainErr := io.Copy(io.Discard, t.r)
	srcErr := t.src.Close()
	t.tmp.Close()
	defer os.Remove(t.tmp.Name())
	if drainErr != nil || hex.EncodeToString(t.h.Sum(nil)) != t.digest.Hex {
		return srcErr // incomplete or corrupt: do not cache
	}
	c := t.layer.c
	if err := os.Rename(t.tmp.Name(), c.blob(t.digest)); err != nil {
		return srcErr
	}
	meta := blobMeta{}
	if mt, err := t.layer.Layer.MediaType(); err == nil {
		meta.MediaType = mt
	}
	if diffID, err := t.layer.Layer.DiffID(); err == nil {
		meta.DiffID = diffID.String()
		if f, err := os.CreateTemp(filepath.Join(c.dir, "tmp"), "diff-*"); err == nil {
			_, _ = f.Write([]byte(t.digest.String()))
			f.Close()
			_ = os.Rename(f.Name(), c.diff(diffID))
		}
	}
	if raw, err := json.Marshal(meta); err == nil {
		if f, err := os.CreateTemp(filepath.Join(c.dir, "tmp"), "meta-*"); err == nil {
			_, _ = f.Write(raw)
			f.Close()
			_ = os.Rename(f.Name(), c.meta(t.digest))
		}
	}
	return srcErr
}
