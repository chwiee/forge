// Package emulation lets RUN steps execute binaries of another CPU architecture
// (e.g. arm64 on an x86 laptop) with no daemon and nothing installed:
//
//  1. static QEMU user-mode binaries are pulled from a pinned public image
//     (tonistiigi/binfmt, the same source BuildKit/buildx use), like any base image;
//  2. each one is registered in the kernel's binfmt_misc with the "F" flag, so the
//     kernel opens the interpreter once and it keeps working inside chroots and
//     namespaces.
//
// Registration needs root and lasts until reboot (WSL: until `wsl --shutdown`).
// Handlers registered by others (Docker Desktop, binfmt) are detected and reused.
package emulation

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	ggcrcache "github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sys/unix"
)

// QemuImage is pinned by digest: the emulators are executable code, they must not change silently.
const QemuImage = "docker.io/tonistiigi/binfmt:qemu-v10.2.3@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0"

const binfmtDir = "/proc/sys/fs/binfmt_misc"

// handler prefix for entries we register (so `forge emulation uninstall` only removes ours).
const prefix = "forge-"

type arch struct {
	binary string
	magic  string // escaped form, exactly as written to binfmt_misc/register
	mask   string
}

// Values from tonistiigi/binfmt cmd/binfmt/config.go (itself from qemu-binfmt-conf.sh).
var arches = map[string]arch{
	"amd64":   {"qemu-x86_64", `\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00`, `\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff`},
	"arm64":   {"qemu-aarch64", `\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00`, `\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff`},
	"arm":     {"qemu-arm", `\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00`, `\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff`},
	"riscv64": {"qemu-riscv64", `\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xf3\x00`, `\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff`},
	"ppc64le": {"qemu-ppc64le", `\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x15\x00`, `\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\x00`},
	"s390x":   {"qemu-s390x", `\x7fELF\x02\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x16`, `\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff`},
	"386":     {"qemu-i386", `\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00`, `\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff`},
}

// Supported lists the architectures forge can emulate.
func Supported() []string {
	return []string{"amd64", "arm64", "arm", "riscv64", "ppc64le", "s390x", "386"}
}

// Native reports whether binaries for p run on this machine without emulation.
func Native(p v1.Platform) bool {
	return p.Architecture == runtime.GOARCH || (runtime.GOARCH == "amd64" && p.Architecture == "386")
}

// Handler is one binfmt_misc entry relevant to forge.
type Handler struct {
	Name        string
	Arch        string
	Enabled     bool
	Flags       string // e.g. "POCF"
	Interpreter string
	Ours        bool
}

// Status lists registered handlers that match an architecture forge knows.
func Status() ([]Handler, error) {
	entries, err := os.ReadDir(binfmtDir)
	if err != nil {
		return nil, fmt.Errorf("binfmt_misc not available: %w", err)
	}
	var out []Handler
	for _, e := range entries {
		if e.Name() == "register" || e.Name() == "status" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(binfmtDir, e.Name()))
		if err != nil {
			continue
		}
		h := Handler{Name: e.Name(), Ours: strings.HasPrefix(e.Name(), prefix)}
		var magic string
		for _, line := range strings.Split(string(b), "\n") {
			switch {
			case line == "enabled":
				h.Enabled = true
			case strings.HasPrefix(line, "flags: "):
				h.Flags = strings.TrimPrefix(line, "flags: ")
			case strings.HasPrefix(line, "interpreter "):
				h.Interpreter = strings.TrimPrefix(line, "interpreter ")
			case strings.HasPrefix(line, "magic "):
				magic = strings.TrimPrefix(line, "magic ")
			}
		}
		for a, def := range arches {
			if magic != "" && magic == hexOf(def.magic) {
				h.Arch = a
			}
		}
		if h.Arch != "" {
			out = append(out, h)
		}
	}
	return out, nil
}

// hexOf turns `\x7fELF...` into the lowercase hex binfmt_misc shows ("7f454c46...").
func hexOf(escaped string) string {
	var b strings.Builder
	for i := 0; i < len(escaped); {
		if escaped[i] == '\\' && i+3 < len(escaped)+1 && escaped[i+1] == 'x' {
			b.WriteString(strings.ToLower(escaped[i+2 : i+4]))
			i += 4
			continue
		}
		fmt.Fprintf(&b, "%02x", escaped[i])
		i++
	}
	return b.String()
}

// Available reports whether an enabled handler exists for arch.
func Available(archName string) bool {
	hs, err := Status()
	if err != nil {
		return false
	}
	for _, h := range hs {
		if h.Arch == archName && h.Enabled {
			return true
		}
	}
	return false
}

// Manager installs emulators on demand.
type Manager struct {
	CacheDir  string
	Keychain  remote.Option
	OnInstall func(arch string) // UI notification

	mu sync.Mutex
}

// ErrNeedRoot explains why emulation cannot be enabled.
var ErrNeedRoot = errors.New("enabling emulation needs root (WSL: run with sudo; CI: use a native runner per architecture and `forge manifest`)")

// Ensure makes RUN steps for archName executable on this machine.
func (m *Manager) Ensure(ctx context.Context, archName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if Native(v1.Platform{Architecture: archName}) {
		return nil
	}
	// tonistiigi QEMU expects the original argv[0] (flag P): busybox applets dispatch on it.
	// Reuse a working handler; replace one of ours registered without P.
	if hs, err := Status(); err == nil {
		for _, h := range hs {
			if h.Arch != archName || !h.Enabled {
				continue
			}
			if !h.Ours || strings.Contains(h.Flags, "P") {
				return nil
			}
			_ = os.WriteFile(filepath.Join(binfmtDir, h.Name), []byte("-1"), 0)
		}
	}
	def, ok := arches[archName]
	if !ok {
		return fmt.Errorf("no emulator for architecture %q (supported: %s)", archName, strings.Join(Supported(), ", "))
	}
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	if err := mountBinfmt(); err != nil {
		return err
	}
	bin, err := m.fetch(ctx, def.binary)
	if err != nil {
		return err
	}
	line := fmt.Sprintf(":%s%s:M:0:%s:%s:%s:CFP", prefix, def.binary, def.magic, def.mask, bin)
	f, err := os.OpenFile(filepath.Join(binfmtDir, "register"), os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("binfmt_misc register: %w (in a pod this needs privileged; prefer native runners)", err)
	}
	_, err = f.Write([]byte(line))
	f.Close()
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("register %s emulator: %w", archName, err)
	}
	if m.OnInstall != nil {
		m.OnInstall(archName)
	}
	return nil
}

func mountBinfmt() error {
	if _, err := os.Stat(filepath.Join(binfmtDir, "register")); err == nil {
		return nil
	}
	if err := unix.Mount("binfmt_misc", binfmtDir, "binfmt_misc", 0, ""); err != nil {
		return fmt.Errorf("mount binfmt_misc: %w", err)
	}
	return nil
}

// fetch extracts usr/bin/<binary> from the pinned QEMU image into the cache.
func (m *Manager) fetch(ctx context.Context, binary string) (string, error) {
	dir := filepath.Join(m.CacheDir, "emulation", "qemu-v10.2.3")
	dst := filepath.Join(dir, binary)
	if fi, err := os.Stat(dst); err == nil && fi.Size() > 0 {
		return dst, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	ref, err := name.ParseReference(QemuImage)
	if err != nil {
		return "", err
	}
	opts := []remote.Option{remote.WithContext(ctx), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: runtime.GOARCH})}
	if m.Keychain != nil {
		opts = append(opts, m.Keychain)
	}
	img, err := remote.Image(ref, opts...)
	if err != nil {
		return "", fmt.Errorf("pull emulators: %w", err)
	}
	img = ggcrcache.Image(img, ggcrcache.NewFilesystemCache(filepath.Join(m.CacheDir, "images")))
	layers, err := img.Layers()
	if err != nil {
		return "", err
	}
	want := "usr/bin/" + binary
	for _, l := range layers {
		rc, err := l.Uncompressed()
		if err != nil {
			return "", err
		}
		tr := tar.NewReader(rc)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				rc.Close()
				return "", err
			}
			if strings.TrimPrefix(path.Clean("/"+h.Name), "/") != want {
				continue
			}
			tmp := dst + ".tmp"
			f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
			if err != nil {
				rc.Close()
				return "", err
			}
			_, err = io.Copy(f, tr)
			f.Close()
			rc.Close()
			if err != nil {
				return "", err
			}
			return dst, os.Rename(tmp, dst)
		}
		rc.Close()
	}
	return "", fmt.Errorf("%s not found in %s", binary, QemuImage)
}

// Uninstall removes the handlers forge registered.
func Uninstall() (int, error) {
	hs, err := Status()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, h := range hs {
		if !h.Ours {
			continue
		}
		if err := os.WriteFile(filepath.Join(binfmtDir, h.Name), []byte("-1"), 0); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
