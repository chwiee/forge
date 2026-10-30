package builder

import "testing"

func TestParsePlatform(t *testing.T) {
	cases := map[string]string{
		"linux/amd64":    "linux/amd64",
		"arm64":          "linux/arm64",
		"linux/arm64/v8": "linux/arm64",
		"aarch64":        "linux/arm64",
		"linux/arm":      "linux/arm/v7",
		"linux/arm/v6":   "linux/arm/v6",
		"x86_64":         "linux/amd64",
	}
	for in, want := range cases {
		p, err := ParsePlatform(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got := PlatformString(p); got != want {
			t.Errorf("ParsePlatform(%q) = %s, want %s", in, got, want)
		}
	}
	if _, err := ParsePlatform("windows/amd64"); err == nil {
		t.Error("windows accepted")
	}
	ps, err := ParsePlatforms("linux/amd64, arm64,linux/amd64")
	if err != nil || len(ps) != 2 {
		t.Fatalf("ParsePlatforms dedupe: %v %v", ps, err)
	}
}
