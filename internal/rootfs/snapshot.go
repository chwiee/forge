package rootfs

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// Entry is the change-detection fingerprint of one path.
// ctime is set by the kernel on every content/metadata change and cannot be
// forged from userspace, so "cp -p" or "touch -r" style copies are still caught.
type Entry struct {
	Mode  uint32
	Size  int64
	Mtime int64
	Ctime int64
	Uid   uint32
	Gid   uint32
	Ino   uint64
	Link  string
}

// Snapshot maps a root-relative path ("usr/bin/env") to its fingerprint.
type Snapshot map[string]Entry

// Excluded paths never become part of a layer: runtime mounts and files the
// sandbox injects (DNS, hosts) during RUN.
var Excluded = []string{"proc", "sys", "dev", "etc/resolv.conf", "etc/hosts", "etc/hostname", ".forge-run"}

func excluded(rel string) bool {
	for _, e := range Excluded {
		if rel == e || strings.HasPrefix(rel, e+"/") {
			return true
		}
	}
	return false
}

// Take walks root and fingerprints every path.
func Take(root string) (Snapshot, error) {
	snap := Snapshot{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if excluded(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			return nil // vanished between readdir and stat
		}
		e := Entry{
			Mode:  st.Mode,
			Size:  st.Size,
			Mtime: st.Mtim.Nano(),
			Ctime: st.Ctim.Nano(),
			Uid:   st.Uid,
			Gid:   st.Gid,
			Ino:   st.Ino,
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			e.Link, _ = os.Readlink(p)
		}
		snap[rel] = e
		return nil
	})
	return snap, err
}

// Diff returns paths added/changed in after and the topmost paths deleted.
func Diff(before, after Snapshot) (changed, deleted []string) {
	for p, a := range after {
		if b, ok := before[p]; !ok || b != a {
			changed = append(changed, p)
		}
	}
	for p := range before {
		if _, ok := after[p]; ok {
			continue
		}
		// only emit the topmost deleted path
		parent := filepath.ToSlash(filepath.Dir(p))
		if parent != "." {
			if _, inBefore := before[parent]; inBefore {
				if _, inAfter := after[parent]; !inAfter {
					continue
				}
			}
		}
		deleted = append(deleted, p)
	}
	sort.Strings(changed)
	sort.Strings(deleted)
	return changed, deleted
}
