package builder

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type ids struct {
	uid, gid int
	groups   []int
}

// resolveUser resolves USER "name|uid[:group|gid]" against the rootfs files.
func resolveUser(root, spec string) (ids, error) {
	userPart, groupPart, hasGroup := strings.Cut(spec, ":")
	out := ids{}

	passwd := readColonFile(root, "etc/passwd")
	if n, err := strconv.Atoi(userPart); err == nil {
		out.uid = n
		out.gid = n
		for _, f := range passwd {
			if len(f) > 3 && f[2] == userPart {
				out.gid, _ = strconv.Atoi(f[3])
				break
			}
		}
	} else {
		found := false
		for _, f := range passwd {
			if len(f) > 3 && f[0] == userPart {
				out.uid, _ = strconv.Atoi(f[2])
				out.gid, _ = strconv.Atoi(f[3])
				found = true
				break
			}
		}
		if !found {
			return out, fmt.Errorf("USER %q: no such user in /etc/passwd", userPart)
		}
	}

	groups := readColonFile(root, "etc/group")
	if hasGroup {
		if n, err := strconv.Atoi(groupPart); err == nil {
			out.gid = n
		} else {
			found := false
			for _, f := range groups {
				if len(f) > 2 && f[0] == groupPart {
					out.gid, _ = strconv.Atoi(f[2])
					found = true
					break
				}
			}
			if !found {
				return out, fmt.Errorf("USER %q: no such group", groupPart)
			}
		}
	}
	// supplementary groups
	name := userPart
	for _, f := range passwd {
		if len(f) > 2 && f[2] == strconv.Itoa(out.uid) {
			name = f[0]
			break
		}
	}
	out.groups = []int{out.gid}
	for _, f := range groups {
		if len(f) < 4 {
			continue
		}
		for _, m := range strings.Split(f[3], ",") {
			if m == name {
				if g, err := strconv.Atoi(f[2]); err == nil && g != out.gid {
					out.groups = append(out.groups, g)
				}
			}
		}
	}
	return out, nil
}

// resolveChown handles --chown=user[:group]; numeric ids need no lookup.
func resolveChown(root, spec string) (ids, error) {
	u, g, hasGroup := strings.Cut(spec, ":")
	uid, uerr := strconv.Atoi(u)
	if uerr == nil && (!hasGroup || isNum(g)) {
		gid := uid
		if hasGroup {
			gid, _ = strconv.Atoi(g)
		}
		return ids{uid: uid, gid: gid}, nil
	}
	r, err := resolveUser(root, spec)
	if err != nil {
		return r, fmt.Errorf("--chown: %w", err)
	}
	if !hasGroup {
		// Docker: --chown=user without group uses the user's primary group
		return r, nil
	}
	return r, nil
}

func isNum(s string) bool { _, err := strconv.Atoi(s); return err == nil }

func readColonFile(root, rel string) [][]string {
	abs, err := secure(root, rel)
	if err != nil {
		return nil
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Split(line, ":"))
	}
	return out
}
