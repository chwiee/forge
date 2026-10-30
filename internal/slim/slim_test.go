package slim

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"sort"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/chwiee/forge/internal/cache"
)

type entry struct {
	name string
	data string
	dir  bool
}

func layer(t *testing.T, es ...entry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(e.data))}
		if e.dir {
			h.Typeflag, h.Mode, h.Size = tar.TypeDir, 0o755, 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if !e.dir {
			_, _ = tw.Write([]byte(e.data))
		}
	}
	_ = tw.Close()
	b := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func names(t *testing.T, l v1.Layer) []string {
	t.Helper()
	rc, err := l.Uncompressed()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	var out []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, h.Name)
	}
	sort.Strings(out)
	return out
}

func TestSquashDropsDeletedAndJunk(t *testing.T) {
	base := layer(t,
		entry{name: "etc/", dir: true},
		entry{name: "etc/os-release", data: "x"},
		entry{name: "usr/share/old.txt", data: "base file"},
	)
	l1 := layer(t,
		entry{name: "var/cache/apt/archives/big.deb", data: string(make([]byte, 50000))},
		entry{name: "app/", dir: true},
		entry{name: "app/tmp.bin", data: string(make([]byte, 40000))},
		entry{name: "app/main", data: "v1"},
	)
	l2 := layer(t,
		entry{name: "app/.wh.tmp.bin"},       // deleted later: must vanish
		entry{name: "usr/share/.wh.old.txt"}, // hides a base file: whiteout kept
		entry{name: "app/main", data: "v2"},  // overwritten: only v2 kept
	)
	img, err := mutate.AppendLayers(empty.Image, base, l1, l2)
	if err != nil {
		t.Fatal(err)
	}
	store, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := Slim(img, 1, Options{Profile: Safe, Squash: SquashApp, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Applied {
		t.Fatalf("slim not applied: %s", r.Reason)
	}
	if r.LayersAfter != 2 {
		t.Fatalf("layers after = %d, want 2", r.LayersAfter)
	}
	ls, _ := r.Image.Layers()
	got := names(t, ls[1])
	want := []string{"app/", "app/main", "usr/share/.wh.old.txt"}
	if len(got) != len(want) {
		t.Fatalf("squashed entries = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("squashed entries = %v, want %v", got, want)
		}
	}
	if r.Removed["apt cache"] == 0 {
		t.Fatalf("apt cache not reported as removed: %v", r.Removed)
	}
	if r.SizeAfter >= r.SizeBefore {
		t.Fatalf("size did not shrink: %d -> %d", r.SizeBefore, r.SizeAfter)
	}
}

func TestJunkCategory(t *testing.T) {
	cases := map[string]string{
		"var/lib/apt/lists/deb.debian.org_dists": "apt cache",
		"var/cache/apk/APKINDEX.tar.gz":          "apk cache",
		"tmp/build.log":                          "temp files",
		"root/.cache/pip/http/x":                 "tool caches",
		"home/app/.npm/_cacache/index":           "tool caches",
		"root/.bash_history":                     "shell history",
		"app/main.py":                            "",
		"usr/share/doc/curl/copyright":           "",
		"etc/apt/sources.list":                   "",
	}
	for p, want := range cases {
		if got := junkCategory(p, Safe); got != want {
			t.Errorf("safe %q = %q, want %q", p, got, want)
		}
	}
	if junkCategory("usr/share/doc/curl/copyright", Aggressive) == "" {
		t.Error("aggressive should remove docs")
	}
	if junkCategory("app/__pycache__/m.cpython-312.pyc", Aggressive) == "" {
		t.Error("aggressive should remove python bytecode")
	}
}
