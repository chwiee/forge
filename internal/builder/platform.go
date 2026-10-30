package builder

import (
	"fmt"
	"runtime"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// HostPlatform is the platform of this machine (BUILDPLATFORM).
func HostPlatform() v1.Platform {
	p := v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
	if runtime.GOARCH == "arm" {
		p.Variant = "v7"
	}
	return p
}

// ParsePlatform accepts "linux/arm64", "linux/arm/v7", "arm64" (OS defaults to linux).
func ParsePlatform(s string) (v1.Platform, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return HostPlatform(), nil
	}
	parts := strings.Split(s, "/")
	if len(parts) == 1 {
		parts = []string{"linux", parts[0]}
	}
	if parts[0] != "linux" {
		return v1.Platform{}, fmt.Errorf("only linux images are supported, got %q", s)
	}
	p := v1.Platform{OS: "linux", Architecture: normalizeArch(parts[1])}
	if len(parts) > 2 {
		p.Variant = parts[2]
	}
	if p.Architecture == "arm" && p.Variant == "" {
		p.Variant = "v7"
	}
	if p.Architecture == "arm64" && p.Variant == "v8" {
		p.Variant = "" // registries list arm64 with or without v8; empty matches both
	}
	return p, nil
}

func normalizeArch(a string) string {
	switch a {
	case "x86_64", "x86-64":
		return "amd64"
	case "aarch64":
		return "arm64"
	case "armhf", "armv7", "armv7l":
		return "arm"
	case "i386", "i686":
		return "386"
	}
	return a
}

// ParsePlatforms parses a comma separated list, removing duplicates.
func ParsePlatforms(s string) ([]v1.Platform, error) {
	if strings.TrimSpace(s) == "" {
		return []v1.Platform{HostPlatform()}, nil
	}
	var out []v1.Platform
	seen := map[string]bool{}
	for _, item := range strings.Split(s, ",") {
		p, err := ParsePlatform(item)
		if err != nil {
			return nil, err
		}
		k := PlatformString(p)
		if !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// PlatformString renders "linux/arm/v7".
func PlatformString(p v1.Platform) string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// PlatformArch normalizes an architecture or platform string to its arch ("linux/arm64" -> "arm64").
func PlatformArch(s string) string {
	p, err := ParsePlatform(s)
	if err != nil {
		return s
	}
	return p.Architecture
}
