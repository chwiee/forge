package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Printf("hello from a forge-built image (uid=%d)\n", os.Getuid())
}
