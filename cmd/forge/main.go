//go:build linux

// Command forge builds, slims, scans and pushes container images without a
// container runtime.
package main

import (
	"os"

	"github.com/chwiee/forge/internal/cli"
	"github.com/chwiee/forge/internal/sandbox"
	"github.com/chwiee/forge/internal/userns"

	_ "golang.org/x/crypto/x509roots/fallback" // CA roots for scratch/distroless runners
)

func main() {
	// re-executed by the builder to run a RUN step inside the sandbox
	if len(os.Args) > 1 && os.Args[1] == sandbox.ChildCommand {
		sandbox.Child()
		return
	}
	// non-root: continue inside a user namespace with the caller's subuid range
	userns.MaybeReexec()
	os.Exit(cli.Execute())
}
