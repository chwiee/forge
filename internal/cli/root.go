// Package cli wires forge's commands.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/chwiee/forge/internal/ui"
)

// Version is set at build time (-ldflags "-X github.com/chwiee/forge/internal/cli.Version=v0.1.0").
var Version = "dev"

// Exit codes: pipelines can tell "image rejected" from "forge broke".
const (
	ExitOK    = 0
	ExitGate  = 1
	ExitError = 2
)

// gateError signals a failed security gate (exit 1).
type gateError struct{ msg string }

func (e *gateError) Error() string { return e.msg }

type globalFlags struct {
	verbose  bool
	cacheDir string
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	g := &globalFlags{}
	root := &cobra.Command{
		Use:   "forge",
		Short: "Container builder: build, slim, scan, secure and push — no Docker required",
		Long: `forge builds OCI images from a Dockerfile without Docker, Podman or BuildKit,
shrinks them, scans CVEs (Grype), checks hardening (score 0-100), looks for
leaked secrets (Gitleaks) and pushes to ECR or GHCR — in one binary.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVarP(&g.verbose, "verbose", "v", false, "stream full RUN output")
	root.PersistentFlags().StringVar(&g.cacheDir, "cache-dir", defaultCacheDir(), "layer/image/DB cache (mount a volume here in CI) [$FORGE_CACHE_DIR]")

	root.AddCommand(newRunCmd(g), newBuildCmd(g), newScanCmd(g), newPushCmd(g), newDBCmd(g), newCacheCmd(g), newDoctorCmd(g), newVersionCmd())

	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	var ge *gateError
	if errors.As(err, &ge) {
		return ExitGate
	}
	u := ui.New(false)
	u.Line("  " + u.Bad("✖ "+err.Error()))
	return ExitError
}

func defaultCacheDir() string {
	if d := os.Getenv("FORGE_CACHE_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CACHE_HOME"); d != "" {
		return filepath.Join(d, "forge")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".cache", "forge")
	}
	return "/var/cache/forge"
}

// warnWindowsMount: on WSL, /mnt/c is a 9p mount without Linux ownership/permissions.
func warnWindowsMount(u *ui.UI, paths ...string) {
	for _, p := range paths {
		abs, _ := filepath.Abs(p)
		if strings.HasPrefix(abs, "/mnt/") && len(abs) > 6 && abs[6] == '/' {
			u.Warn(fmt.Sprintf("%s is on a Windows drive: builds are slow there and file ownership is lost; use the WSL filesystem (~/...)", abs))
		}
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run:   func(*cobra.Command, []string) { fmt.Println("forge", Version) },
	}
}
