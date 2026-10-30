// Package registry resolves push targets (ECR, GHCR), provides credentials and
// pushes images with progress.
package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Kinds supported for push.
const (
	ECR  = "ecr"
	GHCR = "ghcr"
)

// Options configures target resolution.
type Options struct {
	Kind       string // ecr | ghcr
	Name       string // repository name (--name)
	Tags       []string
	ECRAccount string // optional, else STS
	Region     string // optional, else AWS config
	GHCROwner  string // optional, else GITHUB_REPOSITORY_OWNER
	CreateRepo bool   // ECR: create repository if missing
	Immutable  bool   // ECR: tag immutability when creating
}

// Target is a resolved destination.
type Target struct {
	Kind   string
	Repo   name.Repository
	Tags   []string
	Region string
}

// Ref returns repo:tag for the i-th tag.
func (t *Target) Ref(i int) name.Tag { return t.Repo.Tag(t.Tags[i]) }

// String returns the first reference.
func (t *Target) String() string { return t.Ref(0).String() }

var repoNameRe = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)

// Resolve builds the target and validates names.
func Resolve(ctx context.Context, o Options) (*Target, error) {
	repoName := strings.ToLower(strings.Trim(o.Name, "/"))
	if repoName == "" {
		return nil, errors.New("--name is required (repository name in the registry)")
	}
	if !repoNameRe.MatchString(repoName) {
		return nil, fmt.Errorf("invalid repository name %q (lowercase letters, digits, . _ - and /)", o.Name)
	}
	tags := o.Tags
	if len(tags) == 0 {
		tags = DefaultTags()
	}
	for i, t := range tags {
		tags[i] = SanitizeTag(t)
	}

	t := &Target{Kind: o.Kind, Tags: tags}
	var host string
	switch o.Kind {
	case GHCR:
		owner := strings.ToLower(firstNonEmpty(o.GHCROwner, os.Getenv("FORGE_GHCR_OWNER"), os.Getenv("GITHUB_REPOSITORY_OWNER"), ownerFromRepo(os.Getenv("GITHUB_REPOSITORY"))))
		if owner == "" {
			return nil, errors.New("ghcr: owner unknown, use --owner or set GITHUB_REPOSITORY_OWNER")
		}
		if !strings.HasPrefix(repoName, owner+"/") {
			repoName = owner + "/" + repoName
		}
		host = "ghcr.io"
	case ECR:
		region, err := ecrRegion(ctx, o.Region)
		if err != nil {
			return nil, err
		}
		account := firstNonEmpty(o.ECRAccount, os.Getenv("FORGE_ECR_ACCOUNT"))
		if account == "" {
			if account, err = callerAccount(ctx, region); err != nil {
				return nil, fmt.Errorf("ecr: cannot discover AWS account (use --ecr-account): %w", err)
			}
		}
		host = fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", account, region)
		t.Region = region
		if o.CreateRepo {
			if err := ensureECRRepo(ctx, region, repoName, o.Immutable); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("unsupported registry %q (use ecr or ghcr)", o.Kind)
	}
	repo, err := name.NewRepository(host + "/" + repoName)
	if err != nil {
		return nil, err
	}
	t.Repo = repo
	return t, nil
}

// DefaultTags derives a tag from the CI environment (commit sha), else "latest".
func DefaultTags() []string {
	for _, k := range []string{"FORGE_TAG", "CI_COMMIT_SHORT_SHA", "GITHUB_SHA", "BUILD_SOURCEVERSION", "GIT_COMMIT"} {
		if v := os.Getenv(k); v != "" {
			if len(v) > 12 && k != "FORGE_TAG" {
				v = v[:12]
			}
			return []string{v}
		}
	}
	return []string{"latest"}
}

var badTagChars = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

// SanitizeTag turns refs like "refs/tags/v1.2" or "feature/x" into valid tags.
func SanitizeTag(t string) string {
	for _, p := range []string{"refs/tags/", "refs/heads/", "refs/pull/"} {
		t = strings.TrimPrefix(t, p)
	}
	t = badTagChars.ReplaceAllString(t, "-")
	t = strings.TrimLeft(t, ".-")
	if len(t) > 128 {
		t = t[:128]
	}
	if t == "" {
		t = "latest"
	}
	return t
}

func ownerFromRepo(r string) string {
	if i := strings.Index(r, "/"); i > 0 {
		return r[:i]
	}
	return ""
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// ---- AWS helpers ----

func awsCfg(ctx context.Context, region string) (aws.Config, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	return awsconfig.LoadDefaultConfig(ctx, opts...)
}

func ecrRegion(ctx context.Context, flag string) (string, error) {
	if r := firstNonEmpty(flag, os.Getenv("FORGE_ECR_REGION"), os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION")); r != "" {
		return r, nil
	}
	cfg, err := awsCfg(ctx, "")
	if err == nil && cfg.Region != "" {
		return cfg.Region, nil
	}
	return "", errors.New("ecr: region unknown (use --region or AWS_REGION)")
}

func callerAccount(ctx context.Context, region string) (string, error) {
	cfg, err := awsCfg(ctx, region)
	if err != nil {
		return "", err
	}
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.Account), nil
}

func ensureECRRepo(ctx context.Context, region, repo string, immutable bool) error {
	cfg, err := awsCfg(ctx, region)
	if err != nil {
		return err
	}
	cli := ecr.NewFromConfig(cfg)
	_, err = cli.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{RepositoryNames: []string{repo}})
	if err == nil {
		return nil
	}
	var nf *ecrtypes.RepositoryNotFoundException
	if !errors.As(err, &nf) {
		return fmt.Errorf("ecr: describe %s: %w", repo, err)
	}
	mut := ecrtypes.ImageTagMutabilityMutable
	if immutable {
		mut = ecrtypes.ImageTagMutabilityImmutable
	}
	_, err = cli.CreateRepository(ctx, &ecr.CreateRepositoryInput{
		RepositoryName:             aws.String(repo),
		ImageTagMutability:         mut,
		ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{ScanOnPush: false},
		EncryptionConfiguration:    &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeAes256},
	})
	if err != nil {
		return fmt.Errorf("ecr: create repository %s: %w", repo, err)
	}
	return nil
}

// ---- credentials ----

var ecrHostRe = regexp.MustCompile(`^(\d{12})\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$`)

type ecrKeychain struct {
	mu    sync.Mutex
	cache map[string]authn.Authenticator
}

func (k *ecrKeychain) Resolve(res authn.Resource) (authn.Authenticator, error) {
	m := ecrHostRe.FindStringSubmatch(res.RegistryStr())
	if m == nil {
		return authn.Anonymous, nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if a, ok := k.cache[res.RegistryStr()]; ok {
		return a, nil
	}
	ctx := context.Background()
	cfg, err := awsCfg(ctx, m[2])
	if err != nil {
		return nil, err
	}
	out, err := ecr.NewFromConfig(cfg).GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("ecr: get authorization token: %w", err)
	}
	if len(out.AuthorizationData) == 0 {
		return nil, errors.New("ecr: empty authorization data")
	}
	raw, err := base64.StdEncoding.DecodeString(aws.ToString(out.AuthorizationData[0].AuthorizationToken))
	if err != nil {
		return nil, err
	}
	user, pass, _ := strings.Cut(string(raw), ":")
	a := authn.FromConfig(authn.AuthConfig{Username: user, Password: pass})
	if k.cache == nil {
		k.cache = map[string]authn.Authenticator{}
	}
	k.cache[res.RegistryStr()] = a
	return a, nil
}

type ghcrKeychain struct{}

func (ghcrKeychain) Resolve(res authn.Resource) (authn.Authenticator, error) {
	if res.RegistryStr() != "ghcr.io" {
		return authn.Anonymous, nil
	}
	token := firstNonEmpty(os.Getenv("GHCR_TOKEN"), os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return authn.Anonymous, nil
	}
	user := firstNonEmpty(os.Getenv("GHCR_USER"), os.Getenv("GITHUB_ACTOR"), "forge")
	return authn.FromConfig(authn.AuthConfig{Username: user, Password: token}), nil
}

// Keychain resolves ECR (AWS SDK), GHCR (token env) and finally docker config.json.
func Keychain() authn.Keychain { return keychain }

var keychain = authn.NewMultiKeychain(&ecrKeychain{}, ghcrKeychain{}, authn.DefaultKeychain)

// Artifact is what can be pushed: a v1.Image or a v1.ImageIndex (multi-arch).
type Artifact interface {
	remote.Taggable
	Digest() (v1.Hash, error)
}

// Push uploads art to every tag of t. progress receives (complete, total) bytes.
func Push(ctx context.Context, art Artifact, t *Target, progress func(done, total int64)) (v1.Hash, error) {
	updates := make(chan v1.Update, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for u := range updates {
			if progress != nil && u.Total > 0 {
				progress(u.Complete, u.Total)
			}
		}
	}()
	opts := []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(Keychain()), remote.WithProgress(updates), remote.WithJobs(4)}
	var err error
	switch a := art.(type) {
	case v1.ImageIndex:
		err = remote.WriteIndex(t.Ref(0), a, opts...)
	case v1.Image:
		err = remote.Write(t.Ref(0), a, opts...)
	default:
		close(updates)
		err = fmt.Errorf("cannot push %T", art)
	}
	<-done
	if err != nil {
		return v1.Hash{}, explain(t, err)
	}
	for i := 1; i < len(t.Tags); i++ {
		if err := remote.Tag(t.Ref(i), art, remote.WithContext(ctx), remote.WithAuthFromKeychain(Keychain())); err != nil {
			return v1.Hash{}, fmt.Errorf("tag %s: %w", t.Tags[i], err)
		}
	}
	return art.Digest()
}

// PlatformImage is one entry of a multi-arch index.
type PlatformImage struct {
	Image    v1.Image
	Platform v1.Platform
}

// Index builds a multi-platform index. Docker manifest list when every image is
// Docker schema 2 (widest compatibility), OCI image index otherwise.
func Index(items []PlatformImage) (v1.ImageIndex, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("no images for the index")
	}
	allDocker := true
	for _, it := range items {
		if mt, err := it.Image.MediaType(); err != nil || mt != types.DockerManifestSchema2 {
			allDocker = false
		}
	}
	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	if allDocker {
		idx = mutate.IndexMediaType(empty.Index, types.DockerManifestList)
	}
	adds := make([]mutate.IndexAddendum, 0, len(items))
	for _, it := range items {
		p := it.Platform
		mt, err := it.Image.MediaType()
		if err != nil {
			return nil, err
		}
		adds = append(adds, mutate.IndexAddendum{Add: it.Image, Descriptor: v1.Descriptor{MediaType: mt, Platform: &p}})
	}
	return mutate.AppendManifests(idx, adds...), nil
}

// explain turns registry auth failures into an actionable message.
func explain(t *Target, err error) error {
	var te *transport.Error
	denied := errors.As(err, &te) && (te.StatusCode == http.StatusUnauthorized || te.StatusCode == http.StatusForbidden)
	msg := err.Error()
	if !denied && !strings.Contains(msg, "DENIED") && !strings.Contains(msg, "UNAUTHORIZED") {
		return err
	}
	switch t.Kind {
	case GHCR:
		return fmt.Errorf("ghcr: push to %s denied — set GITHUB_TOKEN (job permission packages: write) or GHCR_TOKEN (PAT with write:packages) and make sure the owner %q is right", t.Repo, t.Repo.RepositoryStr())
	case ECR:
		return fmt.Errorf("ecr: push to %s denied — refresh credentials (`aws login`), and check ecr:InitiateLayerUpload/PutImage permissions and that the repository exists (--create-repo)", t.Repo)
	}
	return err
}
