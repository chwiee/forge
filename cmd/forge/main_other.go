//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "forge runs on Linux: use WSL 2 (Ubuntu), a container or a CI runner pod")
	os.Exit(2)
}
