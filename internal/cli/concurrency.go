package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/chwiee/forge/internal/ui"
)

// errGatesFailed cancels pending builds once an image failed a gate.
var errGatesFailed = errors.New("cancelled: another platform failed the security gates")

// cancelled marks st as cancelled (not failed) when ctx was cancelled by
// another task, so only the root cause is shown as an error.
func cancelled(ctx context.Context, st *ui.Step) bool {
	if ctx.Err() == nil {
		return false
	}
	reason := "cancelled"
	if c := context.Cause(ctx); c != nil && !errors.Is(c, context.Canceled) {
		if errors.Is(c, errGatesFailed) {
			reason = "cancelled (gates failed on another platform)"
		} else {
			// the root cause is printed once at the end; here just name the stage
			stage, _, _ := strings.Cut(c.Error(), ":")
			reason = "cancelled (" + stage + " failed)"
		}
	}
	st.Skip(reason)
	return true
}

// stageErr prefixes the failing stage, e.g. "build arm64: line 12: RUN ...".
func stageErr(stage string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", stage, err)
}
