// Package slim reduces image size without changing behavior:
//
//  1. squash: the layers created by the Dockerfile are merged into one, so files
//     deleted or overwritten by later steps stop costing bytes. Base image layers
//     are kept untouched (still shared/deduplicated in the registry).
//  2. cleanup: package-manager caches, temp files and install logs created by
//     the build are dropped. Files that came from the base image are never touched.
//
// If the result is not smaller, the original image is returned.
package slim

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/chwiee/forge/internal/cache"
)

// Profiles.
const (
	Off        = "off"
	Safe       = "safe"
	Aggressive = "aggressive"
)

// Squash modes.
const (
	SquashApp = "app" // merge Dockerfile layers, keep base layers
	SquashAll = "all" // single layer image (no sharing with base)
	SquashOff = "off"
)

// Options configures Slim.
type Options struct {
	Profile string
	Squash  string
	Store   *cache.Store
}

// Result describes what happened.
type Result struct {
	Image        v1.Image
	Applied      bool
	Reason       string
	SizeBefore   int64 // compressed bytes (what the registry stores / nodes pull)
	SizeAfter    int64
	LayersBefore int
	LayersAfter  int
	Removed      map[string]int64 // category -> uncompressed bytes dropped
	RemovedFiles int
	Cached       bool
}

const wh = ".wh."
const opq = ".wh..wh..opq"

// Slim processes img; baseLayers is how many leading layers belong to the base image.
func Slim(img v1.Image, baseLayers int, o Options) (*Result, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	before, err := sizeOf(layers)
	if err != nil {
		return nil, err
	}
	res := &Result{Image: img, SizeBefore: before, SizeAfter: before, LayersBefore: len(layers), LayersAfter: len(layers), Removed: map[string]int64{}}
	if o.Profile == Off && o.Squash == SquashOff {
		res.Reason = "disabled"
		return res, nil
	}
	if o.Squash == SquashAll {
		baseLayers = 0
	}
	if baseLayers > len(layers) {
		baseLayers = len(layers)
	}
	app := layers[baseLayers:]
	if len(app) == 0 {
		res.Reason = "no layers created by the Dockerfile"
		return res, nil
	}
	if len(app) == 1 && o.Profile == Off {
		res.Reason = "already a single application layer"
		return res, nil
	}

	mt := types.OCILayer
	if m, err := img.MediaType(); err == nil && m == types.DockerManifestSchema2 {
		mt = types.DockerLayer
	}

	// cache: same inputs -> same squashed layer
	keyParts := []string{"SLIM", o.Profile, o.Squash}
	for _, l := range layers {
		d, err := l.Digest()
		if err != nil {
			return nil, err
		}
		keyParts = append(keyParts, d.String())
	}
	key := cache.Key(keyParts...)
	var entry cache.Entry
	if e, ok := o.Store.Get(key); ok {
		entry = *e
		res.Cached = true
	} else {
		baseIdx, err := indexBase(layers[:baseLayers])
		if err != nil {
			return nil, err
		}
		plan, err := planSquash(app, baseIdx, o.Profile)
		if err != nil {
			return nil, err
		}
		if plan.abort != "" {
			res.Reason = plan.abort
			return res, nil
		}
		res.Removed, res.RemovedFiles = plan.removed, plan.removedFiles
		entry, err = o.Store.WriteLayer(func(w io.Writer) (int, error) { return writeSquashed(w, app, plan) })
		if err != nil {
			return nil, err
		}
		entry.Step = "forge slim"
		if err := o.Store.Put(key, entry); err != nil {
			return nil, err
		}
	}

	out, err := assemble(img, layers[:baseLayers], entry, o.Store, mt, len(app))
	if err != nil {
		return nil, err
	}
	newLayers, err := out.Layers()
	if err != nil {
		return nil, err
	}
	after, err := sizeOf(newLayers)
	if err != nil {
		return nil, err
	}
	if after >= before {
		res.Reason = "no gain (kept original)"
		return res, nil
	}
	res.Image, res.Applied, res.SizeAfter, res.LayersAfter = out, true, after, len(newLayers)
	return res, nil
}

func sizeOf(ls []v1.Layer) (int64, error) {
	var n int64
	for _, l := range ls {
		s, err := l.Size()
		if err != nil {
			return 0, err
		}
		n += s
	}
	return n, nil
}

// baseIndex: paths present after applying base layers, and dirs with children.
type baseIndex struct {
	paths    map[string]bool
	hasChild map[string]bool
}

func indexBase(layers []v1.Layer) (*baseIndex, error) {
	idx := &baseIndex{paths: map[string]bool{}, hasChild: map[string]bool{}}
	for _, l := range layers {
		err := eachEntry(l, func(name string, h *tar.Header, _ io.Reader) error {
			dir, base := path.Split(name)
			dir = strings.TrimSuffix(dir, "/")
			switch {
			case base == opq:
				removeUnder(idx.paths, dir)
			case strings.HasPrefix(base, wh):
				p := path.Join(dir, strings.TrimPrefix(base, wh))
				delete(idx.paths, p)
				removeUnder(idx.paths, p)
			default:
				idx.paths[name] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for p := range idx.paths {
		if d := path.Dir(p); d != "." {
			idx.hasChild[d] = true
		}
	}
	return idx, nil
}

func removeUnder(m map[string]bool, dir string) {
	prefix := dir + "/"
	for p := range m {
		if strings.HasPrefix(p, prefix) {
			delete(m, p)
		}
	}
}

type rec struct {
	layer int
	dir   bool
}

type plan struct {
	keep         map[string]rec
	whiteouts    []string // paths to hide from the base
	opaques      []string // dirs whose base children must be hidden
	removed      map[string]int64
	removedFiles int
	abort        string
}

func planSquash(app []v1.Layer, base *baseIndex, profile string) (*plan, error) {
	state := map[string]rec{}
	hidden := map[string]bool{} // whited-out (relative to base)
	opaque := map[string]bool{}
	sizes := map[string]int64{}
	linkTargets := map[string]bool{}

	for i, l := range app {
		err := eachEntry(l, func(name string, h *tar.Header, _ io.Reader) error {
			dir, b := path.Split(name)
			dir = strings.TrimSuffix(dir, "/")
			switch {
			case b == opq:
				for p, r := range state {
					if strings.HasPrefix(p, dir+"/") && r.layer < i {
						delete(state, p)
					}
				}
				opaque[dir] = true
				return nil
			case strings.HasPrefix(b, wh):
				p := path.Join(dir, strings.TrimPrefix(b, wh))
				for q, r := range state {
					if (q == p || strings.HasPrefix(q, p+"/")) && r.layer < i {
						delete(state, q)
					}
				}
				hidden[p] = true
				return nil
			}
			isDir := h.Typeflag == tar.TypeDir
			if !isDir {
				for q, r := range state { // a file replacing a directory
					if strings.HasPrefix(q, name+"/") && r.layer < i {
						delete(state, q)
					}
				}
			}
			state[name] = rec{layer: i, dir: isDir}
			sizes[name] = h.Size
			if h.Typeflag == tar.TypeLink {
				linkTargets[strings.TrimPrefix(path.Clean("/"+h.Linkname), "/")] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	p := &plan{keep: state, removed: map[string]int64{}}
	// hard links must point at an entry that survives in an earlier position
	for t := range linkTargets {
		if _, ok := state[t]; !ok && !base.paths[t] {
			p.abort = "hard link to a removed file (kept original)"
			return p, nil
		}
	}
	if profile != Off {
		for name, r := range state {
			if r.dir || linkTargets[name] || base.paths[name] {
				continue
			}
			if cat := junkCategory(name, profile); cat != "" {
				delete(state, name)
				p.removed[cat] += sizes[name]
				p.removedFiles++
			}
		}
	}
	for h := range hidden {
		r, recreated := state[h]
		switch {
		case !recreated && base.paths[h]:
			p.whiteouts = append(p.whiteouts, h)
		case recreated && r.dir && base.hasChild[h]:
			p.opaques = append(p.opaques, h)
		}
	}
	for d := range opaque {
		if base.hasChild[d] {
			p.opaques = append(p.opaques, d)
		}
	}
	return p, nil
}

func writeSquashed(w io.Writer, app []v1.Layer, p *plan) (int, error) {
	tw := tar.NewWriter(w)
	n := 0
	for _, d := range uniq(p.opaques) {
		if err := tw.WriteHeader(&tar.Header{Name: d + "/" + opq, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return n, err
		}
		n++
	}
	for _, d := range uniq(p.whiteouts) {
		dir, b := path.Split(d)
		if err := tw.WriteHeader(&tar.Header{Name: dir + wh + b, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return n, err
		}
		n++
	}
	for i, l := range app {
		err := eachEntry(l, func(name string, h *tar.Header, r io.Reader) error {
			if b := path.Base(name); strings.HasPrefix(b, wh) {
				return nil
			}
			if rr, ok := p.keep[name]; !ok || rr.layer != i {
				return nil
			}
			hdr := *h
			if hdr.Typeflag == tar.TypeDir && !strings.HasSuffix(hdr.Name, "/") {
				hdr.Name += "/"
			}
			if err := tw.WriteHeader(&hdr); err != nil {
				return err
			}
			if hdr.Typeflag == tar.TypeReg && hdr.Size > 0 {
				if _, err := io.CopyN(tw, r, hdr.Size); err != nil {
					return err
				}
			}
			n++
			return nil
		})
		if err != nil {
			return n, err
		}
	}
	return n, tw.Close()
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// eachEntry iterates a layer's tar entries with normalized names.
func eachEntry(l v1.Layer, fn func(name string, h *tar.Header, r io.Reader) error) error {
	rc, err := l.Uncompressed()
	if err != nil {
		return err
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		if name == "" {
			continue
		}
		if err := fn(name, h, tr); err != nil {
			return err
		}
	}
}

// assemble rebuilds the image: base layers + one squashed layer, same config.
func assemble(orig v1.Image, base []v1.Layer, e cache.Entry, store *cache.Store, mt types.MediaType, squashedCount int) (v1.Image, error) {
	ocf, err := orig.ConfigFile()
	if err != nil {
		return nil, err
	}
	cf := ocf.DeepCopy()

	manifestMT, err := orig.MediaType()
	if err != nil {
		return nil, err
	}
	img := mutate.MediaType(empty.Image, manifestMT)
	if manifestMT == types.DockerManifestSchema2 {
		img = mutate.ConfigMediaType(img, types.DockerConfigJSON)
	} else {
		img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
	}
	var adds []mutate.Addendum
	for _, l := range base {
		lmt, err := l.MediaType()
		if err != nil {
			return nil, err
		}
		adds = append(adds, mutate.Addendum{Layer: l, MediaType: lmt})
	}
	if !e.Empty {
		sl, err := store.Layer(e, mt)
		if err != nil {
			return nil, err
		}
		adds = append(adds, mutate.Addendum{Layer: sl, MediaType: mt})
	}
	img, err = mutate.Append(img, adds...)
	if err != nil {
		return nil, err
	}

	// history: keep base entries, then one entry for the squashed layer
	var hist []v1.History
	count := 0
	for _, h := range cf.History {
		if count == len(base) {
			break
		}
		hist = append(hist, h)
		if !h.EmptyLayer {
			count++
		}
	}
	var created v1.Time
	if len(cf.History) > 0 {
		created = cf.History[len(cf.History)-1].Created
	}
	if !e.Empty {
		hist = append(hist, v1.History{Created: created, CreatedBy: fmt.Sprintf("forge slim: %d Dockerfile layers squashed", squashedCount), Comment: "forge"})
	}
	diffIDs := make([]v1.Hash, 0, len(adds))
	for _, a := range adds {
		d, err := a.Layer.DiffID()
		if err != nil {
			return nil, err
		}
		diffIDs = append(diffIDs, d)
	}
	cf.History = hist
	cf.RootFS = v1.RootFS{Type: "layers", DiffIDs: diffIDs}
	return mutate.ConfigFile(img, cf)
}
