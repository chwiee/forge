package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	arch, _ := os.ReadFile("/etc/forge-arch")
	fmt.Printf("hello from %s/%s (%s)\n", runtime.GOOS, runtime.GOARCH, string(arch))
}
