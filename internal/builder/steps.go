package builder

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"

	"github.com/chwiee/forge/internal/cache"
	"github.com/chwiee/forge/internal/dockerfile"
	"github.com/chwiee/forge/internal/sandbox"
)

func (b *builder) buildStage(st *stage) error {
	if err := b.initStage(st); err != nil {
		return err
	}
	label := st.name
	if label == "" {
		label = fmt.Sprintf("stage %d", st.idx)
	}
	for _, c := range st.def.Commands {
		b.step++
		text := oneLine(dockerfile.Text(c))
		if b.opts.Events != nil {
			b.opts.Events.StepStart(b.step, b.total, label, text)
		}
		start := time.Now()
		if ex, ok := c.(instructions.SupportsSingleWordExpansion); ok {
			if err := ex.Expand(b.expander(st)); err != nil {
				return stepErr(c, err)
			}
		}
		cached, err := b.dispatch(st, c, text)
		if err != nil {
			return stepErr(c, err)
		}
		status := StatusBuilt
		switch {
		case !isFSStep(c):
			status = StatusMeta
		case cached:
			status = StatusCached
			b.cached++
		}
		if b.opts.Events != nil {
			b.opts.Events.StepDone(text, status, time.Since(start))
		}
	}
	st.built = true
	return nil
}

func stepErr(c instructions.Command, err error) error {
	return fmt.Errorf("line %d: %s: %w", dockerfile.Line(c), oneLine(dockerfile.Text(c)), err)
}

// env used to expand words: declared ARGs overridden by ENV (Docker semantics).
func (b *builder) expandEnv(st *stage) map[string]string {
	m := map[string]string{}
	for k, v := range st.args {
		m[k] = v
	}
	for _, kv := range st.cfg.Env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

func (b *builder) expander(st *stage) instructions.SingleWordExpander {
	env := mapEnv(b.expandEnv(st))
	return func(word string) (string, error) {
		v, _, err := b.lex.ProcessWord(word, env)
		return v, err
	}
}

// dispatch executes one instruction; returns whether it was served from cache.
func (b *builder) dispatch(st *stage, c instructions.Command, text string) (bool, error) {
	switch c := c.(type) {
	case *instructions.EnvCommand:
		for _, kv := range c.Env {
			st.cfg.Env = setEnv(st.cfg.Env, kv.Key, kv.Value)
		}
		st.key = cache.Key(st.key, text, strings.Join(st.cfg.Env, "\n"))
		return true, nil

	case *instructions.ArgCommand:
		for _, kv := range c.Args {
			v, provided := b.opts.BuildArgs[kv.Key]
			if !provided {
				if kv.Value != nil {
					v = *kv.Value
				} else if mv, ok := b.meta[kv.Key]; ok {
					v = mv
				}
			}
			st.args[kv.Key] = v
			st.key = cache.Key(st.key, "ARG", kv.Key, v)
		}
		return true, nil

	case *instructions.LabelCommand:
		for _, kv := range c.Labels {
			st.cfg.Labels[kv.Key] = kv.Value
		}
		st.key = cache.Key(st.key, text)
		return true, nil

	case *instructions.MaintainerCommand:
		st.cfg.Labels["maintainer"] = c.Maintainer
		return true, nil

	case *instructions.UserCommand:
		st.cfg.User = c.User
		st.key = cache.Key(st.key, "USER", c.User)
		return true, nil

	case *instructions.ShellCommand:
		st.shell = append([]string{}, c.Shell...)
		st.cfg.Shell = append([]string{}, c.Shell...)
		st.key = cache.Key(st.key, "SHELL", strings.Join(c.Shell, "\x00"))
		return true, nil

	case *instructions.ExposeCommand:
		for _, p := range c.Ports {
			if !strings.Contains(p, "/") {
				p += "/tcp"
			}
			st.cfg.ExposedPorts[p] = struct{}{}
		}
		return true, nil

	case *instructions.VolumeCommand:
		for _, v := range c.Volumes {
			st.cfg.Volumes[v] = struct{}{}
		}
		return true, nil

	case *instructions.StopSignalCommand:
		st.cfg.StopSignal = c.Signal
		return true, nil

	case *instructions.HealthCheckCommand:
		if c.Health == nil || (len(c.Health.Test) == 1 && c.Health.Test[0] == "NONE") {
			st.cfg.Healthcheck = &v1.HealthConfig{Test: []string{"NONE"}}
			return true, nil
		}
		st.cfg.Healthcheck = &v1.HealthConfig{
			Test: c.Health.Test, Interval: c.Health.Interval, Timeout: c.Health.Timeout,
			StartPeriod: c.Health.StartPeriod, Retries: c.Health.Retries,
		}
		return true, nil

	case *instructions.CmdCommand:
		st.cfg.Cmd = b.cmdLine(st, c.CmdLine, c.PrependShell)
		st.cmdSet = true
		return true, nil

	case *instructions.EntrypointCommand:
		st.cfg.Entrypoint = b.cmdLine(st, c.CmdLine, c.PrependShell)
		if !st.cmdSet {
			st.cfg.Cmd = nil // Docker resets an inherited CMD when ENTRYPOINT changes
		}
		return true, nil

	case *instructions.OnbuildCommand:
		b.warn("ONBUILD is ignored by forge: " + c.Expression)
		return true, nil

	case *instructions.WorkdirCommand:
		p := c.Path
		if !path.IsAbs(p) {
			p = path.Join(workdirOf(st), p)
		}
		st.cfg.WorkingDir = p
		key := cache.Key(st.key, "WORKDIR", p, st.cfg.User)
		return b.fsStep(st, key, text, func(root string) error {
			return b.mkdirWorkdir(st, root, p)
		})

	case *instructions.RunCommand:
		return b.run(st, c, text)

	case *instructions.CopyCommand:
		return b.copy(st, copyReq{
			srcs: c.SourcePaths, dest: c.DestPath, from: c.From, chown: c.Chown, chmod: c.Chmod,
			exclude: c.ExcludePatterns, parents: c.Parents, inline: c.SourceContents,
		}, text)

	case *instructions.AddCommand:
		unpack := c.Unpack == nil || *c.Unpack
		return b.copy(st, copyReq{
			srcs: c.SourcePaths, dest: c.DestPath, chown: c.Chown, chmod: c.Chmod,
			exclude: c.ExcludePatterns, add: true, unpack: unpack, checksum: c.Checksum, inline: c.SourceContents,
		}, text)
	}
	b.warn(fmt.Sprintf("instruction %T is not supported, skipped", c))
	return true, nil
}

func (b *builder) warn(msg string) {
	if b.opts.Events != nil {
		b.opts.Events.Warn(msg)
	}
}

func workdirOf(st *stage) string {
	if st.cfg.WorkingDir == "" {
		return "/"
	}
	return st.cfg.WorkingDir
}

func (b *builder) cmdLine(st *stage, args []string, prependShell bool) []string {
	if prependShell {
		return append(append([]string{}, st.shell...), strings.Join(args, " "))
	}
	return append([]string{}, args...)
}

func (b *builder) mkdirWorkdir(st *stage, root, p string) error {
	abs, err := secure(root, p)
	if err != nil {
		return err
	}
	if fi, err := os.Stat(abs); err == nil && fi.IsDir() {
		return nil
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return err
	}
	if st.cfg.User != "" {
		if u, err := resolveUser(root, st.cfg.User); err == nil {
			_ = os.Lchown(abs, u.uid, u.gid)
		}
	}
	return nil
}

// ---- RUN ----

func (b *builder) run(st *stage, c *instructions.RunCommand, text string) (bool, error) {
	for _, f := range c.FlagsUsed {
		if f == "mount" || f == "network" || f == "security" {
			b.warn(fmt.Sprintf("RUN --%s is ignored by forge (runs without it)", f))
		}
	}
	args := c.CmdLine
	stdin := ""
	scriptName, scriptData := "", ""
	if len(c.Files) > 0 {
		if hd := parser.MustParseHeredoc(args[0]); hd != nil && len(args) == 1 {
			data := c.Files[0].Data
			if c.Files[0].Chomp {
				data = parser.ChompHeredocContent(data)
			}
			if strings.HasPrefix(data, "#!") {
				scriptName, scriptData = c.Files[0].Name, data
				args = []string{"/.forge-run/" + scriptName}
			} else {
				args = []string{data}
			}
		} else {
			var sb strings.Builder
			sb.WriteString(args[0])
			for _, f := range c.Files {
				sb.WriteString("\n" + f.Data + f.Name)
			}
			args = []string{sb.String()}
		}
	}
	argv := args
	if c.PrependShell && scriptName == "" {
		argv = append(append([]string{}, st.shell...), strings.Join(args, " "))
	}

	env := b.runEnv(st)
	key := cache.Key(st.key, "RUN", strings.Join(argv, "\x00"), strings.Join(env, "\n"), st.cfg.User, workdirOf(st), stdin, scriptData)

	return b.fsStep(st, key, text, func(root string) error {
		uid, gid, groups := 0, 0, []int(nil)
		if st.cfg.User != "" {
			u, err := resolveUser(root, st.cfg.User)
			if err != nil {
				return err
			}
			uid, gid, groups = u.uid, u.gid, u.groups
		}
		if scriptName != "" {
			dir := filepath.Join(root, ".forge-run")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			defer os.RemoveAll(dir)
			if err := os.WriteFile(filepath.Join(dir, scriptName), []byte(scriptData), 0o755); err != nil {
				return err
			}
		}
		out := newLineSink(b.opts.Events, b.opts.Verbose)
		err := sandbox.Run(b.ctx, sandbox.Spec{
			Rootfs: root, Args: argv, Env: env, Workdir: workdirOf(st),
			UID: uid, GID: gid, Groups: groups, Hostname: "forge", Stdin: stdin,
		}, out, out)
		out.Flush()
		if err != nil {
			return &RunError{Err: err, Tail: out.Tail()}
		}
		return nil
	})
}

// RunError carries the last output lines of a failed RUN.
type RunError struct {
	Err  error
	Tail []string
}

func (e *RunError) Error() string { return e.Err.Error() }
func (e *RunError) Unwrap() error { return e.Err }

// runEnv = image ENV + declared ARGs not shadowed by ENV.
func (b *builder) runEnv(st *stage) []string {
	env := append([]string{}, st.cfg.Env...)
	keys := make([]string, 0, len(st.args))
	for k := range st.args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !hasEnv(env, k) {
			env = append(env, k+"="+st.args[k])
		}
	}
	return env
}

// ---- helpers ----

type mapEnv map[string]string

func (m mapEnv) Get(k string) (string, bool) { v, ok := m[k]; return v, ok }
func (m mapEnv) Keys() []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func setEnv(env []string, k, v string) []string {
	for i, e := range env {
		if strings.HasPrefix(e, k+"=") {
			env[i] = k + "=" + v
			return env
		}
	}
	return append(env, k+"="+v)
}

func hasEnv(env []string, k string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, k+"=") {
			return true
		}
	}
	return false
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// lineSink forwards command output line by line to the UI and keeps a tail.
type lineSink struct {
	ev      Events
	verbose io.Writer
	buf     bytes.Buffer
	tail    []string
}

func newLineSink(ev Events, verbose io.Writer) *lineSink { return &lineSink{ev: ev, verbose: verbose} }

func (s *lineSink) Write(p []byte) (int, error) {
	if s.verbose != nil {
		_, _ = s.verbose.Write(p)
	}
	s.buf.Write(p)
	for {
		i := bytes.IndexByte(s.buf.Bytes(), '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(s.buf.Next(i+1)), "\r\n")
		s.push(line)
	}
	return len(p), nil
}

func (s *lineSink) push(line string) {
	if line == "" {
		return
	}
	if i := strings.LastIndexByte(line, '\r'); i >= 0 { // progress bars
		line = line[i+1:]
	}
	s.tail = append(s.tail, line)
	if len(s.tail) > 40 {
		s.tail = s.tail[len(s.tail)-40:]
	}
	if s.ev != nil {
		s.ev.Output(line)
	}
}

func (s *lineSink) Flush() {
	if s.buf.Len() > 0 {
		sc := bufio.NewScanner(&s.buf)
		for sc.Scan() {
			s.push(sc.Text())
		}
	}
}

func (s *lineSink) Tail() []string { return s.tail }

// Step outcomes reported to Events.
const (
	StatusBuilt  = "built"  // executed, layer produced
	StatusCached = "cached" // layer reused from cache
	StatusMeta   = "meta"   // config-only instruction (ENV, USER, CMD, ...)
)

func isFSStep(c instructions.Command) bool {
	switch c.(type) {
	case *instructions.RunCommand, *instructions.CopyCommand, *instructions.AddCommand, *instructions.WorkdirCommand:
		return true
	}
	return false
}
