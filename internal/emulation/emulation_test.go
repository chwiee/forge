package emulation

import (
	"strings"
	"testing"
)

// binfmt_misc shows magic as lowercase hex; Status relies on matching it.
func TestHexOfMatchesKernelFormat(t *testing.T) {
	got := hexOf(arches["arm64"].magic)
	want := "7f454c460201010000000000000000000200b700"
	if got != want {
		t.Fatalf("hexOf = %s, want %s", got, want)
	}
	for a, d := range arches {
		if n := len(hexOf(d.magic)); n != 40 {
			t.Errorf("%s magic is %d hex chars, want 40 (20 bytes)", a, n)
		}
		if n := len(hexOf(d.mask)); n != 40 {
			t.Errorf("%s mask is %d hex chars, want 40", a, n)
		}
		if !strings.HasPrefix(d.binary, "qemu-") {
			t.Errorf("%s binary %q", a, d.binary)
		}
	}
}
