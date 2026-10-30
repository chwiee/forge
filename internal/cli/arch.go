package cli

import "runtime"

func hostArch() string { return runtime.GOARCH }
