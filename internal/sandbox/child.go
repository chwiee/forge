package sandbox

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// Child is the entry point of the re-executed process. It never returns.
func Child() {
	raw := os.Getenv(specEnv)
	if lvl, ok := strings.CutPrefix(raw, "probe:"); ok {
		// a level is usable only if we can make our mounts private (AppArmor may deny it)
		if lvl != Chroot && unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		fail("bad spec: %v", err)
	}
	var s Spec
	if err := json.Unmarshal(b, &s); err != nil {
		fail("bad spec: %v", err)
	}

	if s.Isolation != Chroot {
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			fail("make mounts private: %v", err)
		}
		mountProc(s.Rootfs)
		mountDev(s.Rootfs)
		if s.Hostname != "" {
			_ = unix.Sethostname([]byte(s.Hostname))
		}
	} else {
		mknodDev(s.Rootfs)
	}

	if err := unix.Chroot(s.Rootfs); err != nil {
		fail("chroot: %v", err)
	}
	wd := s.Workdir
	if wd == "" {
		wd = "/"
	}
	_ = os.MkdirAll(wd, 0o755)
	if err := os.Chdir(wd); err != nil {
		fail("workdir %s: %v", wd, err)
	}

	if s.UID != 0 || s.GID != 0 {
		groups := s.Groups
		if len(groups) == 0 {
			groups = []int{s.GID}
		}
		if err := unix.Setgroups(groups); err != nil {
			fail("setgroups: %v", err)
		}
		if err := unix.Setgid(s.GID); err != nil {
			fail("setgid %d: %v", s.GID, err)
		}
		if err := unix.Setuid(s.UID); err != nil {
			fail("setuid %d: %v", s.UID, err)
		}
	}

	env := s.Env
	pathVal := defaultPath
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "PATH="); ok {
			pathVal = v
		}
	}
	if !hasKey(env, "PATH") {
		env = append(env, "PATH="+defaultPath)
	}
	if !hasKey(env, "HOME") {
		env = append(env, "HOME=/root")
	}
	if len(s.Args) == 0 {
		fail("empty command")
	}
	_ = os.Setenv("PATH", pathVal)
	bin := s.Args[0]
	if !strings.Contains(bin, "/") {
		if p, err := exec.LookPath(bin); err == nil {
			bin = p
		} else {
			fail("%s: not found in PATH (%s)", s.Args[0], pathVal)
		}
	}
	if err := unix.Exec(bin, s.Args, env); err != nil {
		fail("exec %s: %v", bin, err)
	}
}

func hasKey(env []string, k string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, k+"=") {
			return true
		}
	}
	return false
}

func mountProc(root string) {
	p := filepath.Join(root, "proc")
	_ = os.MkdirAll(p, 0o555)
	if unix.Mount("proc", p, "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "") == nil {
		return
	}
	// nested containers mask parts of /proc: a fresh mount is refused, bind the host one
	_ = unix.Mount("/proc", p, "", unix.MS_BIND|unix.MS_REC, "")
}

var devNodes = []string{"null", "zero", "full", "random", "urandom", "tty"}

func mountDev(root string) {
	d := filepath.Join(root, "dev")
	_ = os.MkdirAll(d, 0o755)
	if err := unix.Mount("tmpfs", d, "tmpfs", unix.MS_NOSUID, "mode=755,size=65536k"); err != nil {
		return
	}
	for _, n := range devNodes {
		target := filepath.Join(d, n)
		if f, err := os.Create(target); err == nil {
			f.Close()
		}
		_ = unix.Mount("/dev/"+n, target, "", unix.MS_BIND, "")
	}
	for _, sub := range []string{"pts", "shm", "mqueue"} {
		_ = os.MkdirAll(filepath.Join(d, sub), 0o755)
	}
	_ = unix.Mount("tmpfs", filepath.Join(d, "shm"), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777,size=65536k")
	_ = os.Symlink("/proc/self/fd", filepath.Join(d, "fd"))
	_ = os.Symlink("/proc/self/fd/0", filepath.Join(d, "stdin"))
	_ = os.Symlink("/proc/self/fd/1", filepath.Join(d, "stdout"))
	_ = os.Symlink("/proc/self/fd/2", filepath.Join(d, "stderr"))
}

// mknodDev creates the basic device nodes when mounts are not allowed.
// /dev is excluded from layers, so nothing leaks into the image.
func mknodDev(root string) {
	d := filepath.Join(root, "dev")
	_ = os.MkdirAll(d, 0o755)
	nodes := map[string][2]uint32{"null": {1, 3}, "zero": {1, 5}, "full": {1, 7}, "random": {1, 8}, "urandom": {1, 9}}
	for n, mm := range nodes {
		p := filepath.Join(d, n)
		if _, err := os.Lstat(p); err == nil {
			continue
		}
		_ = unix.Mknod(p, unix.S_IFCHR|0o666, int(unix.Mkdev(mm[0], mm[1])))
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "forge sandbox: "+format+"\n", a...)
	os.Exit(125)
}
