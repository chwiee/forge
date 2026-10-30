package cache

import (
	"io"
	"sync"
	"testing"

	ggcrcache "github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

func TestBlobCacheConcurrentAndLookups(t *testing.T) {
	c := NewBlobCache(t.TempDir())
	img, _ := random.Image(4096, 1)
	ls, _ := img.Layers()
	l := ls[0]
	digest, _ := l.Digest()
	diffID, _ := l.DiffID()

	// two goroutines pull the same layer at once: no corruption, one verified blob
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pl, _ := c.Put(l)
			rc, err := pl.Uncompressed()
			if err != nil {
				t.Error(err)
				return
			}
			buf := make([]byte, 10) // read only a little: Close must drain and verify
			_, _ = rc.Read(buf)
			if err := rc.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	for _, h := range []string{digest.String(), diffID.String()} {
		_ = h
	}
	byDigest, err := c.Get(digest)
	if err != nil {
		t.Fatalf("lookup by digest: %v", err)
	}
	if d, err := byDigest.DiffID(); err != nil || d != diffID {
		t.Fatalf("diffID via digest = %v %v, want %v", d, err, diffID)
	}
	byDiff, err := c.Get(diffID)
	if err != nil {
		t.Fatalf("lookup by diffID: %v", err)
	}
	rc, _ := byDiff.Uncompressed()
	n, _ := io.Copy(io.Discard, rc)
	rc.Close()
	if n == 0 {
		t.Fatal("cached layer is empty")
	}
	img2, _ := random.Image(64, 1)
	other, _ := img2.Layers()
	od, _ := other[0].Digest()
	if _, err := c.Get(od); err != ggcrcache.ErrNotFound {
		t.Fatalf("missing layer: %v", err)
	}
}
