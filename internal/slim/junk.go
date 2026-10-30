package slim

import (
	"path"
	"strings"
)

// rule matches files (never directories) created by the build.
type rule struct {
	category string
	prefixes []string // children of these dirs
	files    []string // exact paths
	suffixes []string // file name suffixes anywhere
	dirName  string   // any file under a directory with this name, anywhere
	homeDirs []string // ".cache/" style dirs under root/ and home/*/
}

// safeRules never remove anything an application reads at runtime.
var safeRules = []rule{
	{category: "apt cache", prefixes: []string{"var/cache/apt/", "var/lib/apt/lists/"}, files: []string{"var/cache/debconf/templates.dat-old", "var/cache/debconf/config.dat-old"}},
	{category: "apk cache", prefixes: []string{"var/cache/apk/", "etc/apk/cache/"}},
	{category: "dnf/yum cache", prefixes: []string{"var/cache/yum/", "var/cache/dnf/", "var/cache/zypp/", "var/lib/dnf/repos/"}},
	{category: "install logs", prefixes: []string{"var/log/apt/"}, files: []string{"var/log/dpkg.log", "var/log/alternatives.log", "var/log/yum.log", "var/log/dnf.log", "var/log/dnf.librepo.log", "var/log/dnf.rpm.log", "var/log/hawkey.log", "var/log/bootstrap.log", "var/log/faillog", "var/log/lastlog"}},
	{category: "temp files", prefixes: []string{"tmp/", "var/tmp/"}},
	{category: "tool caches", homeDirs: []string{".cache/", ".npm/_cacache/", ".npm/_logs/", ".pnpm-store/", ".yarn/berry/cache/"}, prefixes: []string{"usr/local/share/.cache/"}},
	{category: "shell history", homeDirs: []string{".bash_history", ".python_history", ".wget-hsts", ".lesshst", ".viminfo"}},
}

// aggressiveRules trade docs/compiled-bytecode/dependency caches for size.
var aggressiveRules = []rule{
	{category: "docs & man pages", prefixes: []string{"usr/share/doc/", "usr/share/man/", "usr/share/info/", "usr/share/gtk-doc/", "usr/local/share/man/", "usr/local/share/doc/"}},
	{category: "python bytecode", dirName: "__pycache__", suffixes: []string{".pyc", ".pyo"}},
	{category: "dependency caches", homeDirs: []string{".m2/repository/", ".gradle/caches/", ".nuget/packages/", "go/pkg/mod/", ".cargo/registry/", ".composer/cache/"}, prefixes: []string{"go/pkg/mod/", "usr/local/cargo/registry/"}},
}

// junkCategory returns the rule category name for p, or "".
func junkCategory(p, profile string) string {
	rules := safeRules
	if profile == Aggressive {
		rules = append(append([]rule{}, safeRules...), aggressiveRules...)
	}
	for _, r := range rules {
		if r.match(p) {
			return r.category
		}
	}
	return ""
}

func (r rule) match(p string) bool {
	for _, pre := range r.prefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	for _, f := range r.files {
		if p == f {
			return true
		}
	}
	for _, s := range r.suffixes {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	if r.dirName != "" && strings.Contains("/"+path.Dir(p)+"/", "/"+r.dirName+"/") {
		return true
	}
	for _, h := range r.homeDirs {
		if under(p, "root/"+h) {
			return true
		}
		if strings.HasPrefix(p, "home/") {
			parts := strings.SplitN(p, "/", 3)
			if len(parts) == 3 && under(parts[2], h) {
				return true
			}
		}
	}
	return false
}

// under: h ending with "/" matches children, otherwise the exact file.
func under(p, h string) bool {
	if strings.HasSuffix(h, "/") {
		return strings.HasPrefix(p, h)
	}
	return p == h
}
