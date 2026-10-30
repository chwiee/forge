// Package rootfs materializes image layers into a directory, detects what a build
// step changed, and turns that change set back into an OCI layer tarball.
package rootfs

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"golang.org/x/sys/unix"
)

const (
	whiteoutPrefix = ".wh."
	whiteoutOpaque = ".wh..wh..opq"
)

// Apply extracts an uncompressed layer tar stream into root, honoring OCI
// whiteouts. Ownership errors are ignored when running without root (rootless),
// in that case files end up owned by the current user.
func Apply(root string, r io.Reader) error {
	tr := tar.NewReader(r)
	seen := map[string]bool{} // paths written by this layer (opaque dirs keep them)
	type dirTime struct {
		p string
		t time.Time
	}
	var dirs []dirTime

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read layer: %w", err)
		}
		name := strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		if name == "" {
			continue
		}
		dir, base := path.Split(name)
		dir = strings.TrimSuffix(dir, "/")

		parent, err := securejoin.SecureJoin(root, dir)
		if err != nil {
			return err
		}

		// whiteouts
		if base == whiteoutOpaque {
			if err := clearOpaque(parent, dir, seen); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(base, whiteoutPrefix) {
			if err := os.RemoveAll(filepath.Join(parent, strings.TrimPrefix(base, whiteoutPrefix))); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(parent, 0o755); err != nil {
			return err
		}
		target := filepath.Join(parent, base)

		if fi, err := os.Lstat(target); err == nil {
			if !(fi.IsDir() && hdr.Typeflag == tar.TypeDir) {
				if err := os.RemoveAll(target); err != nil {
					return err
				}
			}
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(target, 0o755); err != nil && !os.IsExist(err) {
				return err
			}
			dirs = append(dirs, dirTime{target, hdr.ModTime})
		case tar.TypeReg, tar.TypeRegA: //nolint:staticcheck // old layers still use TypeRegA
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		case tar.TypeLink:
			src, err := securejoin.SecureJoin(root, strings.TrimPrefix(path.Clean("/"+hdr.Linkname), "/"))
			if err != nil {
				return err
			}
			if err := os.Link(src, target); err != nil {
				return fmt.Errorf("hardlink %s: %w", name, err)
			}
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			mode := uint32(hdr.Mode & 0o7777)
			switch hdr.Typeflag {
			case tar.TypeChar:
				mode |= unix.S_IFCHR
			case tar.TypeBlock:
				mode |= unix.S_IFBLK
			default:
				mode |= unix.S_IFIFO
			}
			dev := unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor))
			if err := unix.Mknod(target, mode, int(dev)); err != nil {
				// rootless or missing CAP_MKNOD: device nodes are never needed at build time
				continue
			}
		default:
			continue
		}
		seen[name] = true

		if hdr.Typeflag != tar.TypeLink {
			_ = unix.Lchown(target, hdr.Uid, hdr.Gid) // fails harmlessly when rootless
			for k, v := range hdr.PAXRecords {
				if attr, ok := strings.CutPrefix(k, "SCHILY.xattr."); ok {
					_ = unix.Lsetxattr(target, attr, []byte(v), 0)
				}
			}
			if hdr.Typeflag != tar.TypeSymlink {
				mode := hdr.FileInfo().Mode()
				if hdr.Typeflag == tar.TypeDir && os.Geteuid() != 0 {
					mode |= 0o700 // rootless: keep read-only dirs writable for later layers
				}
				if err := os.Chmod(target, mode); err != nil {
					return err
				}
			}
			if hdr.Typeflag != tar.TypeDir {
				setTimes(target, hdr.ModTime)
			}
		}
	}
	// directory mtimes last: creating children bumps them
	for i := len(dirs) - 1; i >= 0; i-- {
		setTimes(dirs[i].p, dirs[i].t)
	}
	return nil
}

// clearOpaque removes children of dir that were not written by the current layer.
func clearOpaque(abs, rel string, seen map[string]bool) error {
	entries, err := os.ReadDir(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(abs, 0o755)
		}
		return err
	}
	for _, e := range entries {
		child := path.Join(rel, e.Name())
		if seen[child] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(abs, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func setTimes(p string, t time.Time) {
	if t.IsZero() {
		return
	}
	ts := unix.NsecToTimespec(t.UnixNano())
	_ = unix.UtimesNanoAt(unix.AT_FDCWD, p, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW)
}
