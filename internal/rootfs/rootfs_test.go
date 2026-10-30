//go:build linux

package rootfs

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, p, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiffCatchesPreservedMtime(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "a/keep.txt"), "same")
	write(t, filepath.Join(root, "a/edit.txt"), "aaaa")
	write(t, filepath.Join(root, "gone/x.txt"), "x")
	before, err := Take(root)
	if err != nil {
		t.Fatal(err)
	}

	// same size + restored mtime: only ctime reveals the change ("cp -p" style)
	p := filepath.Join(root, "a/edit.txt")
	fi, _ := os.Stat(p)
	time.Sleep(10 * time.Millisecond)
	write(t, p, "bbbb")
	_ = os.Chtimes(p, fi.ModTime(), fi.ModTime())

	if err := os.RemoveAll(filepath.Join(root, "gone")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "new.txt"), "n")
	write(t, filepath.Join(root, "proc/ignored"), "never in a layer")

	after, _ := Take(root)
	changed, deleted := Diff(before, after)

	has := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}
	if !has(changed, "a/edit.txt") {
		t.Errorf("edited file with preserved mtime not detected: %v", changed)
	}
	if has(changed, "a/keep.txt") {
		t.Errorf("unchanged file reported: %v", changed)
	}
	if !has(changed, "new.txt") {
		t.Errorf("new file missing: %v", changed)
	}
	if has(changed, "proc/ignored") {
		t.Errorf("excluded path leaked into diff: %v", changed)
	}
	if len(deleted) != 1 || deleted[0] != "gone" {
		t.Errorf("deleted = %v, want only the topmost [gone]", deleted)
	}
}

func TestLayerRoundTrip(t *testing.T) {
	src := t.TempDir()
	write(t, filepath.Join(src, "app/bin"), "#!/bin/sh\necho hi\n")
	_ = os.Chmod(filepath.Join(src, "app/bin"), 0o755)
	_ = os.Symlink("bin", filepath.Join(src, "app/link"))
	_ = os.Link(filepath.Join(src, "app/bin"), filepath.Join(src, "app/hard"))

	var buf bytes.Buffer
	n, err := WriteLayer(&buf, src, []string{"app", "app/bin", "app/hard", "app/link"}, []string{"old"}, IDMap{})
	if err != nil || n != 5 {
		t.Fatalf("WriteLayer n=%d err=%v", n, err)
	}

	// a destination that has the whiteout target
	dst := t.TempDir()
	write(t, filepath.Join(dst, "old/file"), "x")
	if err := Apply(dst, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "old")); !os.IsNotExist(err) {
		t.Error("whiteout did not remove /old")
	}
	fi, err := os.Stat(filepath.Join(dst, "app/bin"))
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("app/bin mode = %v err=%v", fi, err)
	}
	if l, _ := os.Readlink(filepath.Join(dst, "app/link")); l != "bin" {
		t.Errorf("symlink = %q", l)
	}
	a, _ := os.Stat(filepath.Join(dst, "app/bin"))
	b, _ := os.Stat(filepath.Join(dst, "app/hard"))
	if !os.SameFile(a, b) {
		t.Error("hardlink not preserved")
	}

	// the tar must contain a TypeLink entry for the second name
	tr := tar.NewReader(bytes.NewReader(buf.Bytes()))
	links := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if h.Typeflag == tar.TypeLink {
			links++
		}
	}
	if links != 1 {
		t.Errorf("hardlink entries = %d, want 1", links)
	}
}

func TestApplyRejectsEscape(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: "/etc"})
	_ = tw.WriteHeader(&tar.Header{Name: "evil/passwd", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()

	root := t.TempDir()
	if err := Apply(root, &buf); err != nil {
		t.Fatal(err)
	}
	// the file must land inside root (symlink resolved within root), never on the host /etc
	if _, err := os.Stat(filepath.Join(root, "etc/passwd")); err != nil {
		t.Errorf("entry was not confined to the rootfs: %v", err)
	}
}
