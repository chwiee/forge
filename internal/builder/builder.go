// Package builder turns a Dockerfile into an OCI image without a container
// runtime: base layers are pulled with go-containerregistry, extracted into a
// directory, RUN steps execute in the forge sandbox and every filesystem step
// becomes a layer computed from a before/after snapshot diff.
//
// Steps are cached by key (parent key + instruction + inputs). The rootfs is
// only materialized when a step misses the cache, so a fully cached build
// never extracts anything.
package builder

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	ggcrcache "github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/shell"

	"github.com/chwiee/forge/internal/cache"
	"github.com/chwiee/forge/internal/dockerfile"
	"github.com/chwiee/forge/internal/ignore"
	"github.com/chwiee/forge/internal/registry"
	"github.com/chwiee/forge/internal/rootfs"
	"github.com/chwiee/forge/internal/sandbox"
)

// Events receives progress notifications.
type Events interface {
	StepStart(n, total int, stage, text string)
	StepDone(text, status string, d time.Duration)
	Output(line string)
	Warn(msg string)
}

// Options configures a build.
type Options struct {
	ContextDir string
	Dockerfile string
	Target     string
	BuildArgs  map[string]string
	CacheDir   string
	NoCache    bool
	Events     Events
	Verbose    io.Writer // full RUN output when not nil
}

// Result is a built image plus what later pipeline stages need.
type Result struct {
	Image      v1.Image
	BaseRef    string // remote base of the final stage ("scratch" if none)
	BaseLayers int    // layers inherited from that remote base
	Parsed     *dockerfile.Parsed
	Steps      int
	Cached     int
	Isolation  string
	Ignore     *ignore.Matcher
	Duration   time.Duration
}

type layerRec struct {
	entry cache.Entry
	by    string
}

type stage struct {
	idx  int
	name string
	def  instructions.Stage

	baseImg    v1.Image
	baseRef    string
	baseLayers int
	inherited  []layerRec
	layers     []layerRec
	cfg        v1.Config
	key        string
	shell      []string
	args       map[string]string
	cmdSet     bool

	root         string
	materialized bool
	snap         rootfs.Snapshot
	built        bool
}

type builder struct {
	ctx      context.Context
	opts     Options
	parsed   *dockerfile.Parsed
	store    *cache.Store
	imgCache ggcrcache.Cache
	work     string
	ignore   *ignore.Matcher
	ids      rootfs.IDMap
	lex      *shell.Lex
	meta     map[string]string
	stages   []*stage
	external map[string]*stage // COPY --from=<image ref>
	step     int
	total    int
	cached   int
	platform v1.Platform
}

// Build runs the whole Dockerfile and returns the target stage image.
func Build(ctx context.Context, o Options) (*Result, error) {
	start := time.Now()
	if o.Dockerfile == "" {
		o.Dockerfile = filepath.Join(o.ContextDir, "Dockerfile")
	}
	parsed, err := dockerfile.Parse(o.Dockerfile)
	if err != nil {
		return nil, err
	}
	store, err := cache.Open(filepath.Join(o.CacheDir, "layers"))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(o.CacheDir, "work"), 0o755); err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(filepath.Join(o.CacheDir, "work"), "build-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)

	ig, err := ignore.Load(o.ContextDir)
	if err != nil {
		return nil, fmt.Errorf("ignore file: %w", err)
	}

	b := &builder{
		ctx:      ctx,
		opts:     o,
		parsed:   parsed,
		store:    store,
		imgCache: ggcrcache.NewFilesystemCache(filepath.Join(o.CacheDir, "images")),
		work:     work,
		ignore:   ig,
		ids:      rootfs.CurrentIDMap(),
		lex:      shell.NewLex(parsed.EscapeToken),
		external: map[string]*stage{},
		platform: v1.Platform{OS: "linux", Architecture: runtime.GOARCH},
	}
	if runtime.GOARCH == "arm64" {
		b.platform.Variant = "v8"
	}
	b.meta = b.metaArgs()

	target := len(parsed.Stages) - 1
	if o.Target != "" {
		if target = parsed.StageIndex(o.Target); target < 0 {
			return nil, fmt.Errorf("target stage %q not found", o.Target)
		}
	}
	for i, s := range parsed.Stages {
		b.stages = append(b.stages, &stage{idx: i, name: strings.ToLower(s.Name), def: s})
	}
	order := b.buildOrder(target)
	for _, i := range order {
		b.total += len(parsed.Stages[i].Commands)
	}

	for _, i := range order {
		if err := b.buildStage(b.stages[i]); err != nil {
			return nil, err
		}
	}
	final := b.stages[target]
	img, err := b.image(final)
	if err != nil {
		return nil, err
	}
	return &Result{
		Image:      img,
		BaseRef:    final.baseRef,
		BaseLayers: final.baseLayers,
		Parsed:     parsed,
		Steps:      b.step,
		Cached:     b.cached,
		Isolation:  sandbox.LevelIfProbed(),
		Ignore:     ig,
		Duration:   time.Since(start),
	}, nil
}

// buildOrder returns the stages needed by target, dependencies first.
func (b *builder) buildOrder(target int) []int {
	seen := map[int]bool{}
	var order []int
	var visit func(i int)
	visit = func(i int) {
		if seen[i] {
			return
		}
		seen[i] = true
		s := b.parsed.Stages[i]
		if j := b.parsed.StageIndex(b.expandMeta(s.BaseName)); j >= 0 && j < i {
			visit(j)
		}
		for _, c := range s.Commands {
			if cp, ok := c.(*instructions.CopyCommand); ok && cp.From != "" {
				if j := b.parsed.StageIndex(cp.From); j >= 0 && j != i {
					visit(j)
				}
			}
		}
		order = append(order, i)
	}
	visit(target)
	return order
}

func (b *builder) metaArgs() map[string]string {
	m := b.platformArgs()
	for _, a := range b.parsed.MetaArgs {
		for _, kv := range a.Args {
			v, ok := b.opts.BuildArgs[kv.Key]
			if !ok && kv.Value != nil {
				v, _, _ = b.lex.ProcessWord(*kv.Value, mapEnv(m))
			}
			m[kv.Key] = v
		}
	}
	return m
}

func (b *builder) platformArgs() map[string]string {
	p := "linux/" + runtime.GOARCH
	return map[string]string{
		"TARGETPLATFORM": p, "TARGETOS": "linux", "TARGETARCH": runtime.GOARCH, "TARGETVARIANT": b.platform.Variant,
		"BUILDPLATFORM": p, "BUILDOS": "linux", "BUILDARCH": runtime.GOARCH, "BUILDVARIANT": b.platform.Variant,
	}
}

func (b *builder) expandMeta(word string) string {
	v, _, err := b.lex.ProcessWord(word, mapEnv(b.meta))
	if err != nil {
		return word
	}
	return v
}

// ---- base images ----

func (b *builder) pull(ref string) (v1.Image, string, error) {
	if strings.EqualFold(ref, "scratch") {
		img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
			OS: "linux", Architecture: runtime.GOARCH, Variant: b.platform.Variant,
			RootFS: v1.RootFS{Type: "layers"},
		})
		return img, "scratch", err
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, "", fmt.Errorf("base image %q: %w", ref, err)
	}
	img, err := remote.Image(r,
		remote.WithContext(b.ctx),
		remote.WithPlatform(b.platform),
		remote.WithAuthFromKeychain(registry.Keychain()),
	)
	if err != nil {
		return nil, "", fmt.Errorf("pull %s: %w", ref, err)
	}
	dg, err := img.Digest()
	if err != nil {
		return nil, "", err
	}
	return ggcrcache.Image(img, b.imgCache), r.Context().String() + "@" + dg.String(), nil
}

// ---- stage lifecycle ----

func (b *builder) initStage(st *stage) error {
	baseName := b.expandMeta(st.def.BaseName)
	st.args = map[string]string{}
	st.shell = []string{"/bin/sh", "-c"}
	if j := b.parsed.StageIndex(baseName); j >= 0 && j < st.idx {
		parent := b.stages[j]
		if !parent.built {
			return fmt.Errorf("stage %q used before it is built", baseName)
		}
		st.baseImg, st.baseRef, st.baseLayers = parent.baseImg, parent.baseRef, parent.baseLayers
		st.inherited = append(append([]layerRec{}, parent.inherited...), parent.layers...)
		st.cfg = copyConfig(parent.cfg)
		st.key = cache.Key("FROM-STAGE", parent.key)
		st.shell = append([]string{}, parent.shell...)
		return nil
	}
	img, resolved, err := b.pull(baseName)
	if err != nil {
		return err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return err
	}
	layers, err := img.Layers()
	if err != nil {
		return err
	}
	st.baseImg, st.baseRef, st.baseLayers = img, resolved, len(layers)
	st.cfg = copyConfig(cf.Config)
	if len(st.cfg.Shell) > 0 {
		st.shell = append([]string{}, st.cfg.Shell...)
	}
	st.key = cache.Key("FROM", resolved)
	return nil
}

// materialize extracts the stage filesystem (base + layers so far).
func (b *builder) materialize(st *stage) error {
	if st.materialized {
		return nil
	}
	st.root = filepath.Join(b.work, fmt.Sprintf("stage-%d", st.idx))
	if err := os.MkdirAll(st.root, 0o755); err != nil {
		return err
	}
	if b.opts.Events != nil {
		b.opts.Events.Output("extracting " + st.baseRef)
	}
	if st.baseRef != "scratch" {
		layers, err := st.baseImg.Layers()
		if err != nil {
			return err
		}
		for _, l := range layers {
			if err := applyLayer(st.root, l); err != nil {
				return fmt.Errorf("extract base layer: %w", err)
			}
		}
	}
	for _, rec := range append(append([]layerRec{}, st.inherited...), st.layers...) {
		if rec.entry.Empty {
			continue
		}
		if err := b.applyCached(st.root, rec.entry); err != nil {
			return err
		}
	}
	snap, err := rootfs.Take(st.root)
	if err != nil {
		return err
	}
	st.snap = snap
	st.materialized = true
	return nil
}

func applyLayer(root string, l v1.Layer) error {
	rc, err := l.Uncompressed()
	if err != nil {
		return err
	}
	defer rc.Close()
	return rootfs.Apply(root, rc)
}

func (b *builder) applyCached(root string, e cache.Entry) error {
	l, err := b.store.Layer(e, types.DockerLayer)
	if err != nil {
		return err
	}
	return applyLayer(root, l)
}

// fsStep runs a filesystem-changing step with caching.
func (b *builder) fsStep(st *stage, key, text string, fn func(root string) error) (bool, error) {
	if !b.opts.NoCache {
		if e, ok := b.store.Get(key); ok {
			if st.materialized && !e.Empty {
				if err := b.applyCached(st.root, *e); err != nil {
					return false, err
				}
				snap, err := rootfs.Take(st.root)
				if err != nil {
					return false, err
				}
				st.snap = snap
			}
			st.layers = append(st.layers, layerRec{entry: *e, by: text})
			st.key = key
			return true, nil
		}
	}
	if err := b.materialize(st); err != nil {
		return false, err
	}
	if err := fn(st.root); err != nil {
		return false, err
	}
	after, err := rootfs.Take(st.root)
	if err != nil {
		return false, err
	}
	changed, deleted := rootfs.Diff(st.snap, after)
	st.snap = after
	e, err := b.store.WriteLayer(func(w io.Writer) (int, error) {
		return rootfs.WriteLayer(w, st.root, changed, deleted, b.ids)
	})
	if err != nil {
		return false, err
	}
	e.Step = text
	if err := b.store.Put(key, e); err != nil {
		return false, err
	}
	st.layers = append(st.layers, layerRec{entry: e, by: text})
	st.key = key
	return false, nil
}

// image assembles the OCI image of a stage.
func (b *builder) image(st *stage) (v1.Image, error) {
	mt := types.OCILayer
	if m, err := st.baseImg.MediaType(); err == nil && m == types.DockerManifestSchema2 {
		mt = types.DockerLayer
	}
	var adds []mutate.Addendum
	now := v1.Time{Time: time.Now().UTC()}
	for _, rec := range append(append([]layerRec{}, st.inherited...), st.layers...) {
		if rec.entry.Empty {
			continue
		}
		h := v1.History{Created: now, CreatedBy: rec.by, Comment: "forge"}
		l, err := b.store.Layer(rec.entry, mt)
		if err != nil {
			return nil, err
		}
		adds = append(adds, mutate.Addendum{Layer: l, History: h, MediaType: mt})
	}
	img := st.baseImg
	var err error
	if len(adds) > 0 {
		if img, err = mutate.Append(img, adds...); err != nil {
			return nil, err
		}
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	cf = cf.DeepCopy()
	cf.Config = copyConfig(st.cfg)
	cf.Created = now
	cf.OS, cf.Architecture, cf.Variant = "linux", runtime.GOARCH, b.platform.Variant
	return mutate.ConfigFile(img, cf)
}

func copyConfig(c v1.Config) v1.Config {
	out := c
	out.Env = append([]string{}, c.Env...)
	out.Cmd = append([]string(nil), c.Cmd...)
	out.Entrypoint = append([]string(nil), c.Entrypoint...)
	out.Shell = append([]string(nil), c.Shell...)
	out.OnBuild = nil
	out.Labels = map[string]string{}
	for k, v := range c.Labels {
		out.Labels[k] = v
	}
	out.ExposedPorts = map[string]struct{}{}
	for k := range c.ExposedPorts {
		out.ExposedPorts[k] = struct{}{}
	}
	out.Volumes = map[string]struct{}{}
	for k := range c.Volumes {
		out.Volumes[k] = struct{}{}
	}
	if c.Healthcheck != nil {
		h := *c.Healthcheck
		out.Healthcheck = &h
	}
	return out
}
