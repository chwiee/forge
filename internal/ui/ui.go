// Package ui renders forge's terminal output.
//
// Two modes:
//   - interactive (TTY): animated spinner per step, redrawn in place.
//   - plain (CI logs: Azure DevOps, GitLab, GitHub Actions, Jenkins): one line per
//     event, no carriage returns, colors kept when the CI log viewer supports ANSI.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

// Palette (ANSI 256 colors: renders the same in terminals and CI log viewers).
const (
	cEmber = 208 // brand / active
	cAmber = 214 // warnings
	cGreen = 42  // success
	cRed   = 203 // failure
	cCyan  = 81  // values
	cGray  = 245 // secondary text
	cDim   = 240 // tertiary text
	cWhite = 255
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// UI is safe for concurrent use.
type UI struct {
	out     io.Writer
	tty     bool
	color   bool
	verbose bool

	mu      sync.Mutex
	active  []*Step // steps running now (several when the pipeline runs in parallel)
	drawn   int     // spinner lines currently on screen (TTY)
	tagSubs bool    // prefix sub-lines with the step name (concurrent steps)
	nameW   int     // width of the step-name column
	stop    chan struct{}
	done    chan struct{}
	frame   int
	width   int
}

// New detects terminal capabilities from the environment.
func New(verbose bool) *UI {
	out := os.Stderr
	fd := int(out.Fd())
	tty := term.IsTerminal(fd)
	width := 100
	if tty {
		if w, _, err := term.GetSize(fd); err == nil && w > 20 {
			width = w
		}
	}
	return &UI{
		out:     out,
		tty:     tty && os.Getenv("FORGE_PLAIN") == "",
		color:   colorEnabled(tty),
		verbose: verbose,
		width:   width,
		nameW:   7,
	}
}

func colorEnabled(tty bool) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if v := os.Getenv("FORGE_COLOR"); v != "" {
		return v != "0" && v != "false"
	}
	if tty {
		return true
	}
	// CI log viewers that render ANSI colors.
	for _, k := range []string{"GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "BUILDKITE", "JENKINS_URL", "CI"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// Verbose reports whether full command output should be streamed.
func (u *UI) Verbose() bool { return u.verbose }

// Interactive reports whether the spinner is animated.
func (u *UI) Interactive() bool { return u.tty }

func (u *UI) paint(c int, s string) string {
	if !u.color || s == "" {
		return s
	}
	return fmt.Sprintf("\x1b[38;5;%dm%s\x1b[0m", c, s)
}

func (u *UI) bold(s string) string {
	if !u.color {
		return s
	}
	return "\x1b[1m" + s + "\x1b[22m"
}

// Color helpers for callers composing their own lines.
func (u *UI) Accent(s string) string  { return u.paint(cEmber, s) }
func (u *UI) Value(s string) string   { return u.paint(cCyan, s) }
func (u *UI) Muted(s string) string   { return u.paint(cGray, s) }
func (u *UI) Good(s string) string    { return u.paint(cGreen, s) }
func (u *UI) Bad(s string) string     { return u.paint(cRed, s) }
func (u *UI) Warning(s string) string { return u.paint(cAmber, s) }
func (u *UI) Bold(s string) string    { return u.bold(s) }

// Banner prints the header once per command.
func (u *UI) Banner(version, subtitle string) {
	u.println("")
	u.println("  " + u.bold(u.paint(cEmber, "▲ forge")) + " " + u.paint(cDim, version) + u.paint(cGray, "  ·  "+subtitle))
	u.println("")
}

// Info prints a dim key/value line ("context  ./app").
func (u *UI) Info(key, value string) {
	u.println(fmt.Sprintf("  %s %s", u.paint(cGray, pad(key, 9)), value))
}

// Line prints a raw line, clearing any spinner first.
func (u *UI) Line(s string) { u.println(s) }

// Warn prints a warning line.
func (u *UI) Warn(msg string) { u.println("  " + u.paint(cAmber, "!") + " " + u.paint(cAmber, msg)) }

func (u *UI) println(s string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.clearLocked()
	fmt.Fprintln(u.out, s)
	u.drawLocked()
}

// Step is one pipeline stage (Build, Slim, Scan, ...).
type Step struct {
	u      *UI
	name   string
	start  time.Time
	detail string
	pct    int // -1 = unknown
	ended  bool
}

// Start begins a step and its spinner.
func (u *UI) Start(name string) *Step {
	s := &Step{u: u, name: name, start: time.Now(), pct: -1}
	u.mu.Lock()
	u.clearLocked()
	if l := utf8.RuneCountInString(name); l > u.nameW {
		u.nameW = l
	}
	u.active = append(u.active, s)
	if !u.tty {
		fmt.Fprintf(u.out, "  %s %s\n", u.paint(cEmber, "▸"), u.bold(name))
	} else if u.stop == nil {
		u.stop = make(chan struct{})
		u.done = make(chan struct{})
		go u.animate(u.stop, u.done)
	}
	u.drawLocked()
	u.mu.Unlock()
	return s
}

// Detail sets the live sub-status shown next to the spinner.
// In plain mode it is printed only when log is true (avoid flooding CI logs).
func (s *Step) Detail(msg string, log bool) {
	u := s.u
	u.mu.Lock()
	defer u.mu.Unlock()
	s.detail = msg
	if !u.tty && log {
		fmt.Fprintf(u.out, "    %s %s\n", u.paint(cDim, "·"), u.paint(cGray, msg))
	}
}

// Progress sets a percentage (0-100) shown as a bar; -1 hides it.
func (s *Step) Progress(pct int) {
	s.u.mu.Lock()
	s.pct = pct
	s.u.mu.Unlock()
}

// Sub prints a permanent sub-line under the step (e.g. a finished Dockerfile instruction).
func (s *Step) Sub(icon, msg string) {
	u := s.u
	u.mu.Lock()
	defer u.mu.Unlock()
	u.clearLocked()
	if u.tagSubs {
		fmt.Fprintf(u.out, "    %s %s %s\n", u.paint(cDim, pad(s.name, u.nameW)+" │"), icon, msg)
	} else {
		fmt.Fprintf(u.out, "    %s %s\n", icon, msg)
	}
	u.drawLocked()
}

// SetConcurrent tells the UI several steps run at once: sub-lines get the step
// name so interleaved output stays readable (TTY and CI logs).
func (u *UI) SetConcurrent(on bool) {
	u.mu.Lock()
	u.tagSubs = on
	u.mu.Unlock()
}

// SubOK / SubCached / SubWarn are convenience wrappers over Sub.
func (s *Step) SubOK(msg string)     { s.Sub(s.u.paint(cGreen, "✓"), s.u.paint(cGray, msg)) }
func (s *Step) SubCached(msg string) { s.Sub(s.u.paint(cCyan, "↺"), s.u.paint(cDim, msg)) }
func (s *Step) SubWarn(msg string)   { s.Sub(s.u.paint(cAmber, "!"), s.u.paint(cAmber, msg)) }

// Done finishes the step successfully.
func (s *Step) Done(summary string) { s.finish(s.u.paint(cGreen, "✔"), summary, cGray) }

// Warn finishes the step with a warning (pipeline continues).
func (s *Step) Warn(summary string) { s.finish(s.u.paint(cAmber, "▲"), summary, cAmber) }

// Fail finishes the step with an error.
func (s *Step) Fail(summary string) { s.finish(s.u.paint(cRed, "✖"), summary, cRed) }

// Skip finishes the step as skipped.
func (s *Step) Skip(reason string) { s.finish(s.u.paint(cDim, "○"), reason, cDim) }

func (s *Step) finish(icon, summary string, c int) {
	u := s.u
	u.mu.Lock()
	defer u.mu.Unlock()
	if s.ended {
		return
	}
	s.ended = true
	u.clearLocked()
	el := u.paint(cDim, fmtDuration(time.Since(s.start)))
	fmt.Fprintf(u.out, "  %s %s %s %s\n", icon, u.bold(pad(s.name, u.nameW)), u.paint(c, summary), el)
	for i, a := range u.active {
		if a == s {
			u.active = append(u.active[:i], u.active[i+1:]...)
			break
		}
	}
	u.drawLocked()
}

// Close stops the animation goroutine. Call once at program end.
func (u *UI) Close() {
	u.mu.Lock()
	stop, done := u.stop, u.done
	u.stop = nil
	u.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
	u.mu.Lock()
	u.clearLocked()
	u.mu.Unlock()
}

func (u *UI) animate(stop, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(90 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			u.mu.Lock()
			u.frame++
			u.clearLocked()
			u.drawLocked()
			u.mu.Unlock()
		}
	}
}

// clearLocked erases the spinner region (TTY only); the cursor ends at its first line.
func (u *UI) clearLocked() {
	if !u.tty || u.drawn == 0 {
		return
	}
	fmt.Fprint(u.out, "\r\x1b[2K")
	for i := 1; i < u.drawn; i++ {
		fmt.Fprint(u.out, "\x1b[1A\x1b[2K")
	}
	u.drawn = 0
}

// drawLocked renders one spinner line per running step (TTY only, no trailing newline).
func (u *UI) drawLocked() {
	if !u.tty || len(u.active) == 0 {
		return
	}
	for i, s := range u.active {
		if i > 0 {
			fmt.Fprint(u.out, "\n")
		}
		u.drawStep(s)
	}
	u.drawn = len(u.active)
}

func (u *UI) drawStep(s *Step) {
	frame := u.paint(cEmber, spinnerFrames[u.frame%len(spinnerFrames)])
	head := fmt.Sprintf("  %s %s ", frame, u.bold(pad(s.name, u.nameW)))
	tail := " " + u.paint(cDim, fmtDuration(time.Since(s.start)))
	bar := ""
	if s.pct >= 0 {
		bar = progressBar(u, s.pct) + " "
	}
	// visible width budget for the detail text
	used := 2 + 2 + u.nameW + 1 + visibleLen(bar) + 8
	room := u.width - used - 1
	detail := truncate(oneLine(s.detail), room)
	fmt.Fprint(u.out, head+bar+u.paint(cGray, detail)+tail)
}

func progressBar(u *UI, pct int) string {
	if pct > 100 {
		pct = 100
	}
	const w = 20
	filled := pct * w / 100
	return u.paint(cEmber, strings.Repeat("━", filled)) + u.paint(cDim, strings.Repeat("━", w-filled)) +
		u.paint(cGray, fmt.Sprintf(" %3d%%", pct))
}

func visibleLen(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case r == '\x1b':
			esc = true
		case esc && r == 'm':
			esc = false
		case !esc:
			n++
		}
	}
	return n
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.Join(strings.Fields(s), " ")
}

func truncate(s string, n int) string {
	if n <= 1 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func pad(s string, n int) string {
	if l := utf8.RuneCountInString(s); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}

func fmtDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
}

// FmtDuration is exported for summaries.
func FmtDuration(d time.Duration) string { return fmtDuration(d) }

// HumanBytes formats a byte count (base 1000, like registries show).
func HumanBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}
