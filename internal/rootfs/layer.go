package rootfs

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// IDMap translates on-disk ownership to in-image ownership. In rootless mode
// files written inside the user namespace as root show up as the host user.
type IDMap struct {
	HostUID, HostGID int
	Rootless         bool
}

func (m IDMap) uid(id uint32) int {
	if m.Rootless && int(id) == m.HostUID {
		return 0
	}
	return int(id)
}

func (m IDMap) gid(id uint32) int {
	if m.Rootless && int(id) == m.HostGID {
		return 0
	}
	return int(id)
}

// CurrentIDMap returns the mapping for this process.
func CurrentIDMap() IDMap {
	return IDMap{HostUID: os.Geteuid(), HostGID: os.Getegid(), Rootless: os.Geteuid() != 0}
}

// WriteLayer streams an uncompressed OCI layer with changed paths (taken from
// root) and whiteouts for deleted paths. It returns the number of entries.
func WriteLayer(w io.Writer, root string, changed, deleted []string, ids IDMap) (int, error) {
	tw := tar.NewWriter(w)
	n := 0

	type item struct {
		name     string
		whiteout bool
	}
	items := make([]item, 0, len(changed)+len(deleted))
	for _, d := range deleted {
		items = append(items, item{name: d, whiteout: true})
	}
	for _, c := range changed {
		items = append(items, item{name: c})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].name < items[j].name })

	links := map[uint64]string{} // inode -> first path written in this layer

	for _, it := range items {
		if it.whiteout {
			dir, base := path.Split(it.name)
			hdr := &tar.Header{
				Name:     dir + whiteoutPrefix + base,
				Typeflag: tar.TypeReg,
				Mode:     0,
				Format:   tar.FormatPAX,
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return n, err
			}
			n++
			continue
		}
		abs := filepath.Join(root, filepath.FromSlash(it.name))
		fi, err := os.Lstat(abs)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return n, err
		}
		var st unix.Stat_t
		if err := unix.Lstat(abs, &st); err != nil {
			return n, err
		}
		link := ""
		if fi.Mode()&os.ModeSymlink != 0 {
			if link, err = os.Readlink(abs); err != nil {
				return n, err
			}
		}
		hdr, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			// sockets and other special files are not representable: skip
			continue
		}
		hdr.Name = it.name
		if fi.IsDir() {
			hdr.Name += "/"
		}
		hdr.Uid = ids.uid(st.Uid)
		hdr.Gid = ids.gid(st.Gid)
		hdr.Uname, hdr.Gname = "", ""
		hdr.AccessTime, hdr.ChangeTime = timeZero, timeZero
		hdr.Format = tar.FormatPAX
		if st.Mode&unix.S_IFMT == unix.S_IFCHR || st.Mode&unix.S_IFMT == unix.S_IFBLK {
			hdr.Devmajor = int64(unix.Major(uint64(st.Rdev)))
			hdr.Devminor = int64(unix.Minor(uint64(st.Rdev)))
		}
		if fi.Mode().IsRegular() && st.Nlink > 1 {
			if first, ok := links[st.Ino]; ok {
				hdr.Typeflag = tar.TypeLink
				hdr.Linkname = first
				hdr.Size = 0
			} else {
				links[st.Ino] = it.name
			}
		}
		if capb, ok := getXattr(abs, "security.capability"); ok {
			hdr.PAXRecords = map[string]string{"SCHILY.xattr.security.capability": string(capb)}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return n, fmt.Errorf("%s: %w", it.name, err)
		}
		if hdr.Typeflag == tar.TypeReg && hdr.Size > 0 {
			f, err := os.Open(abs)
			if err != nil {
				return n, err
			}
			_, err = io.CopyN(tw, f, hdr.Size)
			f.Close()
			if err != nil {
				return n, fmt.Errorf("%s: %w", it.name, err)
			}
		}
		n++
	}
	return n, tw.Close()
}

var timeZero time.Time

func getXattr(p, name string) ([]byte, bool) {
	buf := make([]byte, 256)
	sz, err := unix.Lgetxattr(p, name, buf)
	if err != nil || sz <= 0 {
		return nil, false
	}
	return buf[:sz], true
}

// IsWhiteout reports whether a tar entry name is a whiteout marker.
func IsWhiteout(name string) bool {
	return strings.HasPrefix(path.Base(name), whiteoutPrefix)
}
