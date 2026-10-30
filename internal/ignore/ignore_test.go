package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadForgeignoreWins(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".dockerignore"), []byte("*.md\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, ".forgeignore"), []byte("secrets/\n**/*.log\n!keep.log\n"), 0o644)
	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.Source != ".forgeignore" {
		t.Fatalf("source = %s", m.Source)
	}
	cases := map[string]bool{
		".git/config":     true, // default
		"secrets/key.pem": true,
		"app/debug.log":   true,
		"keep.log":        false, // re-included
		"debug.log":       true,  // **/*.log also matches the root
		"README.md":       false, // .dockerignore not used when .forgeignore exists
		"src/main.go":     false,
	}
	for p, want := range cases {
		if got := m.Ignored(p); got != want {
			t.Errorf("Ignored(%q) = %v, want %v", p, got, want)
		}
	}
}
