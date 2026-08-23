package ztagents

import "strings"

// hostGlob is a compiled label-aware hostname pattern for the agent
// ACL. Each dot-separated label is either a literal or "*", and "*"
// matches exactly ONE label: "*.eu.example.com" matches
// "a.eu.example.com" but not "eu.example.com" or "a.b.eu.example.com".
// This is deliberately tighter than the edge firewall's "*.suffix"
// (one-or-more labels) — the ACL is an authorization boundary.
// Matching is case-insensitive.
type hostGlob struct {
	labels []string // lowercase; "*" is the wildcard label
}

func compileHostGlob(pattern string) hostGlob {
	return hostGlob{labels: strings.Split(strings.ToLower(pattern), ".")}
}

func (g hostGlob) matches(host string) bool {
	hostLabels := strings.Split(strings.ToLower(host), ".")
	if len(hostLabels) != len(g.labels) {
		return false
	}
	for i, l := range g.labels {
		if l != "*" && l != hostLabels[i] {
			return false
		}
	}
	return true
}

// compileHostGlobs compiles an ACL entry's patterns.
func compileHostGlobs(patterns []string) []hostGlob {
	globs := make([]hostGlob, 0, len(patterns))
	for _, p := range patterns {
		globs = append(globs, compileHostGlob(p))
	}
	return globs
}

// hostAllowed reports whether host matches any glob. An empty glob
// list means "no restriction" (legacy / unlisted-allowed agents).
func hostAllowed(globs []hostGlob, host string) bool {
	if len(globs) == 0 {
		return true
	}
	for _, g := range globs {
		if g.matches(host) {
			return true
		}
	}
	return false
}
