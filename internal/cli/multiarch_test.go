package cli

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/chwiee/forge/internal/registry"
	"github.com/chwiee/forge/internal/ui"
)

var (
	amd64 = v1.Platform{OS: "linux", Architecture: "amd64"}
	arm64 = v1.Platform{OS: "linux", Architecture: "arm64"}
)

func testImage(t *testing.T, p v1.Platform) v1.Image {
	t.Helper()
	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	cf, _ := img.ConfigFile()
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = p.OS, p.Architecture
	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func testTarget(t *testing.T, host, repo, tag string) *registry.Target {
	t.Helper()
	r, err := name.NewRepository(host+"/"+repo, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	return &registry.Target{Kind: registry.GHCR, Repo: r, Tags: []string{tag}}
}

// Two runners finishing at the same moment must always produce a complete index.
func TestPublishArchConcurrentJoin(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	u := ui.New(false)
	expected := []v1.Platform{amd64, arm64}

	for round := 0; round < 30; round++ {
		tgt := testTarget(t, host, "app", fmt.Sprintf("v%d", round))
		buildID := fmt.Sprintf("run-%d", round)
		var wg sync.WaitGroup
		joined := make([]bool, 2)
		for i, p := range expected {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, j, err := publishArch(context.Background(), u, testImage(t, p), p, tgt, expected, buildID)
				if err != nil {
					t.Error(err)
				}
				joined[i] = j
			}()
		}
		wg.Wait()
		if !joined[0] && !joined[1] {
			t.Fatalf("round %d: nobody wrote the multi-arch tag", round)
		}
		idx, err := remote.Index(tgt.Ref(0))
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		m, _ := idx.IndexManifest()
		if len(m.Manifests) != 2 {
			t.Fatalf("round %d: index has %d platforms, want 2", round, len(m.Manifests))
		}
	}
}

// An arm64 image left by an older run must never be joined with a new amd64.
func TestPublishArchIgnoresOtherBuild(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	u := ui.New(false)
	expected := []v1.Platform{amd64, arm64}
	tgt := testTarget(t, host, "app", "latest")

	if _, _, _, err := publishArch(context.Background(), u, testImage(t, arm64), arm64, tgt, expected, "old-run"); err != nil {
		t.Fatal(err)
	}
	_, _, joined, err := publishArch(context.Background(), u, testImage(t, amd64), amd64, tgt, expected, "new-run")
	if err != nil {
		t.Fatal(err)
	}
	if joined {
		t.Fatal("joined with an arm64 image from another build")
	}
	if _, err := remote.Index(tgt.Ref(0)); err == nil {
		t.Fatal("the multi-arch tag must not exist yet")
	}
}
