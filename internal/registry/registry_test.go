package registry

import (
	"context"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestSanitizeTag(t *testing.T) {
	cases := map[string]string{
		"refs/tags/v1.2.3":   "v1.2.3",
		"refs/heads/feat/x":  "feat-x",
		"refs/pull/42/merge": "42-merge",
		"..weird":            "weird",
		"":                   "latest",
	}
	for in, want := range cases {
		if got := SanitizeTag(in); got != want {
			t.Errorf("SanitizeTag(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveGHCR(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY_OWNER", "")
	t.Setenv("GITHUB_REPOSITORY", "Acme/payments")
	tg, err := Resolve(context.Background(), Options{Kind: GHCR, Name: "Payments-API", Tags: []string{"refs/tags/v1"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := tg.String(); got != "ghcr.io/acme/payments-api:v1" {
		t.Fatalf("ref = %s", got)
	}
	if _, err := Resolve(context.Background(), Options{Kind: GHCR, Name: "bad name!"}); err == nil {
		t.Fatal("invalid name accepted")
	}
	if _, err := Resolve(context.Background(), Options{Kind: "dockerhub", Name: "x"}); err == nil {
		t.Fatal("unsupported registry accepted")
	}
}

func TestIndexMediaType(t *testing.T) {
	img1, _ := random.Image(64, 1)
	img2, _ := random.Image(64, 1)
	idx, err := Index([]PlatformImage{
		{Image: img1, Platform: v1.Platform{OS: "linux", Architecture: "amd64"}},
		{Image: img2, Platform: v1.Platform{OS: "linux", Architecture: "arm64"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Manifests) != 2 || m.Manifests[1].Platform.Architecture != "arm64" {
		t.Fatalf("manifests = %+v", m.Manifests)
	}
	mt, _ := idx.MediaType()
	if mt != types.DockerManifestList { // random.Image is Docker schema 2
		t.Fatalf("media type = %s", mt)
	}
}
