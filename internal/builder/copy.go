package builder

import (
	"archive/tar"
	"bufio"
	"compress/bzip2"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/ulikunitz/xz"

	"github.com/chwiee/forge/internal/cache"
	"github.com/chwiee/forge/internal/ignore"
	"github.com/chwiee/forge/internal/rootfs"
)

type copyReq struct {
	srcs     []string
	dest     string
	from     string
	chown    string
	chmod    string
	exclude  []string
	parents  bool
	inline   []instructions.SourceContent
	add      bool
	unpack   bool
	checksum string
}

// source is one resolved input of COPY/ADD.
type source struct {
	abs   string // absolute path on the host (context or other stage rootfs)
	rel   string // path relative to its root, for hashing and --parents
	isDir bool
	url   string
}

func (b *builder) copy(st *stage, r copyReq, text string) (bool, error) {
	var (
		srcRoot  string
		useIgn   *ignore.Matcher
		keyParts = []string{st.key, text, r.dest, workdirOf(st), r.chown, r.chmod, strings.Join(r.exclude, ",")}
	)
	excl, err := ignore.New(r.exclude)
	if err != nil {
		return false, err
	}

	switch {
	case r.from != "":
		src, err := b.fromStage(r.from)
		if err != nil {
			return false, err
		}
		if err := b.materialize(src); err != nil {
			return false, err
		}
		srcRoot = src.root
		keyParts = append(keyParts, "from:"+src.key)
	default:
		srcRoot = b.opts.ContextDir
		useIgn = b.ignore
	}

	var sources []source
	wildcard := false
	for _, s := range r.srcs {
		if r.add && isURL(s) {
			sources = append(sources, source{url: s, rel: path.Base(urlPath(s))})
			keyParts = append(keyParts, "url:"+s, r.checksum)
			continue
		}
		if strings.ContainsAny(s, "*?[") {
			wildcard = true
		}
		matched, err := resolveSources(srcRoot, s, useIgn)
		if err != nil {
			return false, err
		}
		sources = append(sources, matched...)
	}
	for _, ic := range r.inline {
		keyParts = append(keyParts, "inline:"+ic.Path+"\x00"+ic.Data)
	}
	if len(sources) == 0 && len(r.inline) == 0 {
		return false, fmt.Errorf("no source files matched %v", r.srcs)
	}
	if r.from == "" {
		h, err := hashSources(sources, useIgn, excl, srcRoot)
		if err != nil {
			return false, err
		}
		keyParts = append(keyParts, h)
	} else {
		for _, s := range sources {
			keyParts = append(keyParts, s.rel)
		}
	}
	key := cache.Key(keyParts...)

	return b.fsStep(st, key, text, func(root string) error {
		owner := -1
		group := -1
		if r.chown != "" {
			u, err := resolveChown(root, r.chown)
			if err != nil {
				return err
			}
			owner, group = u.uid, u.gid
		} else {
			owner, group = 0, 0
		}
		var mode *os.FileMode
		if r.chmod != "" {
			m, err := strconv.ParseUint(r.chmod, 8, 32)
			if err != nil {
				return fmt.Errorf("--chmod %q: only octal modes are supported", r.chmod)
			}
			fm := os.FileMode(m)
			mode = &fm
		}
		c := &copier{
			root: root, owner: owner, group: group, mode: mode,
			ign: useIgn, excl: excl, ctxRoot: srcRoot, ids: b.ids,
		}

		dest := r.dest
		if !path.IsAbs(dest) {
			dest = path.Join(workdirOf(st), dest)
			if strings.HasSuffix(r.dest, "/") {
				dest += "/"
			}
		}
		destIsDir := strings.HasSuffix(r.dest, "/") || len(sources)+len(r.inline) > 1 || wildcard
		if !destIsDir {
			if abs, err := secure(root, dest); err == nil {
				if fi, err := os.Stat(abs); err == nil && fi.IsDir() {
					destIsDir = true
				}
			}
		}

		for _, ic := range r.inline {
			target := dest
			if destIsDir {
				target = path.Join(dest, ic.Path)
			}
			if err := c.writeFile(target, []byte(ic.Data), 0o644); err != nil {
				return err
			}
		}
		for _, s := range sources {
			switch {
			case s.url != "":
				if err := c.download(s.url, dest, destIsDir, r.checksum); err != nil {
					return err
				}
			case s.isDir:
				target := dest
				if r.parents {
					target = path.Join(dest, s.rel)
				}
				if err := c.copyTree(s.abs, s.rel, target); err != nil {
					return err
				}
			default:
				if r.add && r.unpack {
					ok, err := c.tryUnpack(s.abs, dest)
					if err != nil {
						return err
					}
					if ok {
						continue
					}
				}
				target := dest
				if destIsDir {
					target = path.Join(dest, path.Base(s.rel))
					if r.parents {
						target = path.Join(dest, s.rel)
					}
				}
				if err := c.copyOne(s.abs, s.rel, target); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (b *builder) fromStage(ref string) (*stage, error) {
	if j := b.parsed.StageIndex(ref); j >= 0 {
		st := b.stages[j]
		if !st.built {
			return nil, fmt.Errorf("COPY --from=%s: stage not built yet", ref)
		}
		return st, nil
	}
	// external image: treat as a stage with no instructions
	if st, ok := b.external[ref]; ok {
		return st, nil
	}
	img, resolved, err := b.pull(ref, b.target)
	if err != nil {
		return nil, err
	}
	layers, _ := img.Layers()
	st := &stage{idx: 1000 + len(b.external), baseImg: img, baseRef: resolved, baseLayers: len(layers), key: cache.Key("FROM", resolved), built: true}
	b.external[ref] = st
	return st, nil
}

// resolveSources expands one COPY source (wildcards allowed) inside root.
func resolveSources(root, src string, ign *ignore.Matcher) ([]source, error) {
	clean := strings.TrimPrefix(path.Clean("/"+filepath.ToSlash(src)), "/")
	var rels []string
	if strings.ContainsAny(clean, "*?[") {
		pattern, err := securejoin.SecureJoin(root, path.Dir(clean))
		if err != nil {
			return nil, err
		}
		matches, err := filepath.Glob(filepath.Join(pattern, path.Base(clean)))
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			rel, _ := filepath.Rel(root, m)
			rels = append(rels, filepath.ToSlash(rel))
		}
	} else {
		rels = []string{clean}
	}
	var out []source
	for _, rel := range rels {
		if rel != "" && ign.Ignored(rel) && !ign.Exclusions() {
			continue
		}
		abs, err := securejoin.SecureJoin(root, rel)
		if err != nil {
			return nil, err
		}
		fi, err := os.Stat(abs)
		if err != nil {
			if os.IsNotExist(err) && !strings.ContainsAny(clean, "*?[") {
				return nil, fmt.Errorf("%s: not found in build context (or excluded by ignore file)", src)
			}
			continue
		}
		if rel == "" {
			rel = "."
		}
		out = append(out, source{abs: abs, rel: rel, isDir: fi.IsDir()})
	}
	return out, nil
}

// hashSources fingerprints the contents that would be copied.
func hashSources(srcs []source, ign, excl *ignore.Matcher, root string) (string, error) {
	h := sha256.New()
	add := func(abs, rel string, d fs.FileInfo) error {
		fmt.Fprintf(h, "%s\x00%o\x00", rel, d.Mode())
		switch {
		case d.Mode()&os.ModeSymlink != 0:
			l, _ := os.Readlink(abs)
			h.Write([]byte(l))
		case d.Mode().IsRegular():
			f, err := os.Open(abs)
			if err != nil {
				return err
			}
			_, err = io.Copy(h, bufio.NewReader(f))
			f.Close()
			if err != nil {
				return err
			}
		}
		h.Write([]byte{0})
		return nil
	}
	for _, s := range srcs {
		if s.url != "" {
			continue
		}
		if !s.isDir {
			fi, err := os.Lstat(s.abs)
			if err != nil {
				return "", err
			}
			if err := add(s.abs, s.rel, fi); err != nil {
				return "", err
			}
			continue
		}
		err := filepath.WalkDir(s.abs, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relCtx, _ := filepath.Rel(root, p)
			relCtx = filepath.ToSlash(relCtx)
			relSrc, _ := filepath.Rel(s.abs, p)
			relSrc = filepath.ToSlash(relSrc)
			if p != s.abs && (ign.Ignored(relCtx) || excl.Ignored(relSrc)) {
				if d.IsDir() && !ign.Exclusions() {
					return filepath.SkipDir
				}
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				return err
			}
			return add(p, relSrc, fi)
		})
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copier writes files into a rootfs with Docker COPY semantics.
type copier struct {
	root         string
	owner, group int
	mode         *os.FileMode
	ign, excl    *ignore.Matcher
	ctxRoot      string
	ids          rootfs.IDMap
}

func secure(root, p string) (string, error) {
	return securejoin.SecureJoin(root, strings.TrimPrefix(path.Clean("/"+p), "/"))
}

func (c *copier) ensureParent(target string) (string, error) {
	abs, err := secure(c.root, target)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(abs)
	if _, err := os.Stat(parent); os.IsNotExist(err) {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return "", err
		}
	}
	return abs, nil
}

func (c *copier) chown(p string) {
	if c.owner >= 0 {
		_ = os.Lchown(p, c.owner, c.group)
	}
}

func (c *copier) writeFile(target string, data []byte, perm os.FileMode) error {
	abs, err := c.ensureParent(target)
	if err != nil {
		return err
	}
	_ = os.RemoveAll(abs)
	if c.mode != nil {
		perm = *c.mode
	}
	if err := os.WriteFile(abs, data, perm); err != nil {
		return err
	}
	_ = os.Chmod(abs, perm)
	c.chown(abs)
	return nil
}

func (c *copier) copyOne(srcAbs, rel, target string) error {
	fi, err := os.Lstat(srcAbs)
	if err != nil {
		return err
	}
	abs, err := c.ensureParent(target)
	if err != nil {
		return err
	}
	if existing, err := os.Lstat(abs); err == nil && !(existing.IsDir() && fi.IsDir()) {
		if err := os.RemoveAll(abs); err != nil {
			return err
		}
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		l, err := os.Readlink(srcAbs)
		if err != nil {
			return err
		}
		if err := os.Symlink(l, abs); err != nil {
			return err
		}
		c.chown(abs)
		return nil
	case fi.IsDir():
		if err := os.MkdirAll(abs, 0o755); err != nil {
			return err
		}
	case fi.Mode().IsRegular():
		if err := copyFileData(srcAbs, abs); err != nil {
			return err
		}
	default:
		return nil // sockets, devices: skipped like Docker
	}
	perm := fi.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	if c.mode != nil {
		perm = *c.mode
	}
	if err := os.Chmod(abs, perm); err != nil {
		return err
	}
	c.chown(abs)
	_ = os.Chtimes(abs, fi.ModTime(), fi.ModTime())
	return nil
}

func (c *copier) copyTree(srcAbs, srcRel, target string) error {
	if abs, err := c.ensureParent(path.Join(target, "x")); err == nil {
		dir := filepath.Dir(abs)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return filepath.WalkDir(srcAbs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relSrc, _ := filepath.Rel(srcAbs, p)
		relSrc = filepath.ToSlash(relSrc)
		if p == srcAbs {
			return nil
		}
		if c.ign != nil {
			relCtx, _ := filepath.Rel(c.ctxRoot, p)
			if c.ign.Ignored(filepath.ToSlash(relCtx)) {
				if d.IsDir() && !c.ign.Exclusions() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if c.excl.Ignored(relSrc) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		return c.copyOne(p, relSrc, path.Join(target, relSrc))
	})
}

func copyFileData(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// ---- ADD extras ----

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func urlPath(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Path == "" || u.Path == "/" {
		return "index.html"
	}
	return u.Path
}

func (c *copier) download(u, dest string, destIsDir bool, checksum string) error {
	target := dest
	if destIsDir || strings.HasSuffix(dest, "/") {
		target = path.Join(dest, path.Base(urlPath(u)))
	}
	cl := &http.Client{Timeout: 10 * time.Minute}
	resp, err := cl.Get(u)
	if err != nil {
		return fmt.Errorf("ADD %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ADD %s: HTTP %d", u, resp.StatusCode)
	}
	abs, err := c.ensureParent(target)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if checksum != "" {
		want := strings.TrimPrefix(checksum, "sha256:")
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			return fmt.Errorf("ADD %s: checksum mismatch (got sha256:%s)", u, got)
		}
	}
	perm := os.FileMode(0o600)
	if c.mode != nil {
		perm = *c.mode
	}
	_ = os.Chmod(abs, perm)
	c.chown(abs)
	return nil
}

// tryUnpack extracts local tar archives (optionally compressed) into dest.
func (c *copier) tryUnpack(srcAbs, dest string) (bool, error) {
	f, err := os.Open(srcAbs)
	if err != nil {
		return false, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	magic, _ := br.Peek(512)
	var r io.Reader
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		gz, err := gzip.NewReader(br)
		if err != nil {
			return false, nil
		}
		r = gz
	case len(magic) >= 3 && string(magic[:3]) == "BZh":
		r = bzip2.NewReader(br)
	case len(magic) >= 6 && string(magic[:6]) == "\xfd7zXZ\x00":
		x, err := xz.NewReader(br)
		if err != nil {
			return false, nil
		}
		r = x
	case len(magic) >= 4 && string(magic[:4]) == "\x28\xb5\x2f\xfd":
		z, err := zstd.NewReader(br)
		if err != nil {
			return false, nil
		}
		defer z.Close()
		r = z
	case len(magic) >= 262 && string(magic[257:262]) == "ustar":
		r = br
	default:
		return false, nil
	}
	// validate it is a tar before touching the rootfs
	tr := tar.NewReader(r)
	if _, err := tr.Next(); err != nil {
		return false, nil
	}
	// reopen: tar.Reader cannot rewind
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	stream, err := decompress(f)
	if err != nil {
		return false, err
	}
	destAbs, err := secure(c.root, dest)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(destAbs, 0o755); err != nil {
		return false, err
	}
	if err := rootfs.Apply(destAbs, stream); err != nil {
		return false, fmt.Errorf("ADD unpack %s: %w", filepath.Base(srcAbs), err)
	}
	return true, nil
}

func decompress(f *os.File) (io.Reader, error) {
	br := bufio.NewReader(f)
	magic, _ := br.Peek(6)
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		return gzip.NewReader(br)
	case len(magic) >= 3 && string(magic[:3]) == "BZh":
		return bzip2.NewReader(br), nil
	case len(magic) >= 6 && string(magic[:6]) == "\xfd7zXZ\x00":
		return xz.NewReader(br)
	case len(magic) >= 4 && string(magic[:4]) == "\x28\xb5\x2f\xfd":
		return zstd.NewReader(br)
	}
	return br, nil
}

var errNoUser = errors.New("user not found")

// sortedKeys is a small helper for deterministic output.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
