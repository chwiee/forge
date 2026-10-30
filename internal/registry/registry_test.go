package registry

import (
	"context"
	"testing"
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
