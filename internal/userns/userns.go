// Package userns gives forge a full set of container uids without root, the
// same way rootless Podman/Buildah do:
//
//  1. a non-root forge re-executes itself in a new user namespace;
//  2. the parent maps the namespace with newuidmap/newgidmap (setuid helpers
//     from the "uidmap" package): ns 0 -> the caller, ns 1..N -> the caller's
//     /etc/subuid range;
//  3. the child waits for the mapping, then re-executes once more: the kernel
//     only grants the namespace capabilities on an execve done as uid 0.
//
// Inside, forge is "root" with every uid real, so extraction keeps file
// owners and RUN adduser/chown/apt behave like in a root build.
package userns

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	envStage = "FORGE_USERNS" // "wait" (mapping pending) | "ready" (inside, with caps)
	envRange = "FORGE_USERNS_RANGE"
	minRange = 65536
)

// Range is one subordinate id allocation from /etc/subuid or /etc/subgid.
type Range struct {
	Start, Count int
}

// Inside reports whether this process runs in forge's rootless namespace.
func Inside() bool { return os.Getenv(envStage) == "ready" }

// Describe returns e.g. "uids 100000-165535" when inside, else "".
func Describe() string { return os.Getenv(envRange) }

// Status explains whether rootless mode is possible for this user.
type Status struct {
	Possible bool
	Reason   string // why not, with the fix
	UID, GID Range
}

// Check inspects helpers and subordinate ranges for the current user.
func Check() Status {
	if os.Geteuid() == 0 {
		return Status{Reason: "running as root"}
	}
	for _, h := range []string{"newuidmap", "newgidmap"} {
		if _, err := exec.LookPath(h); err != nil {
			return Status{Reason: "uidmap not installed — run once: sudo apt install uidmap"}
		}
	}
	u, err := user.Current()
	if err != nil {
		return Status{Reason: "cannot identify the current user: " + err.Error()}
	}
	ur, err := lookup("/etc/subuid", u.Username, u.Uid)
	if err != nil {
		return Status{Reason: err.Error()}
	}
	gr, err := lookup("/etc/subgid", u.Username, u.Uid)
	if err != nil {
		return Status{Reason: err.Error()}
	}
	return Status{Possible: true, UID: ur, GID: gr}
}

func lookup(file, name, uid string) (Range, error) {
	f, err := os.Open(file)
	if err != nil {
		return Range{}, fmt.Errorf("%s missing — run once: sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 %s", file, name)
	}
	defer f.Close()
	best := Range{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(strings.TrimSpace(sc.Text()), ":")
		if len(parts) != 3 || (parts[0] != name && parts[0] != uid) {
			continue
		}
		start, err1 := strconv.Atoi(parts[1])
		count, err2 := strconv.Atoi(parts[2])
		if err1 == nil && err2 == nil && count > best.Count {
			best = Range{Start: start, Count: count}
		}
	}
	if best.Count < minRange {
		return Range{}, fmt.Errorf("no subordinate range of %d ids for %s in %s — run once: sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 %s", minRange, name, file, name)
	}
	return best, nil
}

// MaybeReexec moves a non-root forge into its rootless namespace. It returns
// normally when nothing needs to happen (root, already inside, helpers missing)
// and never returns when the namespaced child ran: the process exits with the
// child's exit code.
func MaybeReexec() {
	switch os.Getenv(envStage) {
	case "ready":
		return
	case "wait":
		finishInside()
		return // not reached
	}
	if os.Geteuid() == 0 || os.Getenv("FORGE_NO_USERNS") != "" {
		return
	}
	st := Check()
	if !st.Possible {
		return // falls back to the single-uid rootless sandbox (forge doctor explains)
	}
	os.Exit(runParent(st))
}

func runParent(st Status) int {
	r, w, err := os.Pipe()
	if err != nil {
		return fail(err)
	}
	cmd := exec.Command("/proc/self/exe", os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(),
		envStage+"=wait",
		fmt.Sprintf("%s=uids %d-%d", envRange, st.UID.Start, st.UID.Start+st.UID.Count-1))
	cmd.ExtraFiles = []*os.File{r} // fd 3: released once the mapping is written
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return fail(fmt.Errorf("user namespace: %w", err))
	}
	r.Close()

	pid := strconv.Itoa(cmd.Process.Pid)
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	maps := [][]string{
		{"newuidmap", pid, "0", uid, "1", "1", strconv.Itoa(st.UID.Start), strconv.Itoa(st.UID.Count)},
		{"newgidmap", pid, "0", gid, "1", "1", strconv.Itoa(st.GID.Start), strconv.Itoa(st.GID.Count)},
	}
	for _, m := range maps {
		if out, err := exec.Command(m[0], m[1:]...).CombinedOutput(); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fail(fmt.Errorf("%s: %v: %s", m[0], err, strings.TrimSpace(string(out))))
		}
	}
	_, _ = w.Write([]byte{1})
	w.Close()

	// forward Ctrl+C / SIGTERM so the child cancels cleanly
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	err = cmd.Wait()
	signal.Stop(sigs)
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		return fail(err)
	}
	return 0
}

// finishInside waits for the mapping, then re-executes so the new image starts
// as uid 0 of the namespace and receives its full capability set.
func finishInside() {
	sync := os.NewFile(3, "userns-sync")
	buf := make([]byte, 1)
	if n, _ := sync.Read(buf); n != 1 {
		os.Exit(fail(errors.New("user namespace mapping was not completed")))
	}
	sync.Close()
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, envStage+"=") {
			env = append(env, e)
		}
	}
	env = append(env, envStage+"=ready")
	if err := unix.Exec("/proc/self/exe", os.Args, env); err != nil {
		os.Exit(fail(err))
	}
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "forge: rootless setup failed:", err)
	fmt.Fprintln(os.Stderr, "       run with sudo, or set FORGE_NO_USERNS=1 to use the limited single-uid mode")
	return 2
}
