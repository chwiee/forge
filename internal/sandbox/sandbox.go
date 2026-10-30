// Package sandbox runs Dockerfile RUN commands inside an extracted rootfs
// without any container runtime. forge re-executes itself ("forge __sandbox")
// in new Linux namespaces, prepares /proc and /dev, chroots and execs the command.
//
// Isolation levels, picked automatically (best first):
//
//	full     root + CAP_SYS_ADMIN: mount/pid/uts/ipc namespaces, /proc, /dev, chroot
//	rootless unprivileged user namespace mapping the caller to root
//	chroot   root without CAP_SYS_ADMIN (default pod): chroot only, no /proc
//
// Network is shared with the host, like a default "docker build".
package sandbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// ChildCommand is the hidden argv[1] that enters Child().
const ChildCommand = "__sandbox"

const specEnv = "FORGE_SANDBOX_SPEC"

// Isolation levels.
const (
	Full     = "full"     // root + CAP_SYS_ADMIN
	UserNS   = "userns"   // root without CAP_SYS_ADMIN: user namespace, identity uid map
	Rootless = "rootless" // non-root: user namespace mapping the caller to root
	Chroot   = "chroot"   // last resort: no namespaces, no /proc
)

// Spec describes one command execution.
type Spec struct {
	Rootfs    string   `json:"rootfs"`
	Args      []string `json:"args"`
	Env       []string `json:"env"`
	Workdir   string   `json:"workdir"`
	UID       int      `json:"uid"`
	GID       int      `json:"gid"`
	Groups    []int    `json:"groups,omitempty"`
	Hostname  string   `json:"hostname"`
	Isolation string   `json:"isolation"`
	Stdin     string   `json:"-"` // heredoc body fed to the command
}

var (
	detectOnce sync.Once
	detected   string
)

// Level returns the isolation level this process can use.
func Level() string {
	detectOnce.Do(func() { detected = probe() })
	return detected
}

// probe tries to spawn /bin/true-like child in each mode (cheap: the child exits at once).
// LevelIfProbed returns the level only if a RUN already triggered detection.
func LevelIfProbed() string { return detected }

func probe() string {
	candidates := []string{Rootless}
	if os.Geteuid() == 0 {
		candidates = []string{Full, UserNS, Chroot}
	}
	for _, lvl := range candidates {
		cmd := exec.Command("/proc/self/exe", ChildCommand)
		cmd.Env = []string{specEnv + "=probe:" + lvl}
		cmd.SysProcAttr = sysProcAttr(lvl)
		if err := cmd.Run(); err == nil {
			return lvl
		}
	}
	if os.Geteuid() == 0 {
		return Chroot
	}
	return ""
}

func sysProcAttr(level string) *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	switch level {
	case Full:
		attr.Cloneflags = unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC
	case UserNS:
		// creating a user namespace needs no capability; inside it we may mount /proc and /dev.
		// identity mapping keeps every uid real, so apt's _apt user and chown work.
		attr.Cloneflags = unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1 << 31}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1 << 31}}
		attr.GidMappingsEnableSetgroups = true
	case Rootless:
		attr.Cloneflags = unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}
		attr.GidMappingsEnableSetgroups = false
	}
	return attr
}

// ErrNoIsolation means no supported isolation level is available.
var ErrNoIsolation = errors.New("cannot run RUN steps: not root and unprivileged user namespaces are disabled " +
	"(run as root in the runner pod, or enable kernel.unprivileged_userns_clone)")

// Run executes spec and streams output. The sandbox injects the host DNS
// configuration into the rootfs for the duration of the command.
func Run(ctx context.Context, spec Spec, stdout, stderr io.Writer) error {
	level := Level()
	if level == "" {
		return ErrNoIsolation
	}
	spec.Isolation = level
	if level == Rootless && (spec.UID != 0 || spec.GID != 0) {
		// only root is mapped inside an unprivileged namespace
		spec.UID, spec.GID, spec.Groups = 0, 0, nil
	}

	restore, err := injectNetworkFiles(spec.Rootfs, spec.Hostname)
	if err != nil {
		return err
	}
	defer restore()

	raw, _ := json.Marshal(spec)
	cmd := exec.CommandContext(ctx, "/proc/self/exe", ChildCommand)
	cmd.Env = []string{specEnv + "=" + base64.StdEncoding.EncodeToString(raw)}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if spec.Stdin != "" {
		cmd.Stdin = strings.NewReader(spec.Stdin)
	}
	cmd.SysProcAttr = sysProcAttr(level)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return &ExitError{Code: ee.ExitCode()}
		}
		return err
	}
	return nil
}

// ExitError is a non-zero exit of the build command.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("command exited with code %d", e.Code) }

// injectNetworkFiles writes resolv.conf/hosts/hostname into the rootfs and
// returns a func that restores the image's own versions.
func injectNetworkFiles(root, hostname string) (func(), error) {
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		return nil, err
	}
	type saved struct {
		path    string
		existed bool
		data    []byte
		mode    os.FileMode
		link    string
	}
	var backups []saved
	files := map[string][]byte{
		"resolv.conf": readOr("/etc/resolv.conf", "nameserver 8.8.8.8\n"),
		"hosts":       []byte("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n127.0.1.1\t" + hostname + "\n"),
		"hostname":    []byte(hostname + "\n"),
	}
	for name, content := range files {
		p := filepath.Join(etc, name)
		s := saved{path: p}
		if fi, err := os.Lstat(p); err == nil {
			s.existed = true
			s.mode = fi.Mode()
			if fi.Mode()&os.ModeSymlink != 0 {
				s.link, _ = os.Readlink(p)
			} else {
				s.data, _ = os.ReadFile(p)
			}
			_ = os.Remove(p)
		}
		backups = append(backups, s)
		if err := os.WriteFile(p, content, 0o644); err != nil {
			return nil, err
		}
	}
	return func() {
		for _, s := range backups {
			_ = os.RemoveAll(s.path)
			if !s.existed {
				continue
			}
			if s.link != "" {
				_ = os.Symlink(s.link, s.path)
				continue
			}
			_ = os.WriteFile(s.path, s.data, s.mode.Perm())
		}
	}, nil
}

func readOr(p, def string) []byte {
	b, err := os.ReadFile(p)
	if err != nil || len(b) == 0 {
		return []byte(def)
	}
	return b
}
