package security

import (
	"fmt"
	"net"
	gopath "path"
	"strings"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// hostGlob matches a request Host. Supported forms: "*" (any),
// "*.suffix" (any subdomain of suffix, one or more labels), exact.
type hostGlob struct {
	any    bool
	suffix string // non-empty for "*.suffix"; includes the leading dot
	exact  string
}

func compileHostGlob(pattern string) hostGlob {
	switch {
	case pattern == "*":
		return hostGlob{any: true}
	case strings.HasPrefix(pattern, "*."):
		return hostGlob{suffix: pattern[1:]} // ".suffix"
	default:
		return hostGlob{exact: strings.ToLower(pattern)}
	}
}

func (g hostGlob) matches(host string) bool {
	switch {
	case g.any:
		return true
	case g.suffix != "":
		return strings.HasSuffix(host, strings.ToLower(g.suffix)) && len(host) > len(g.suffix)
	default:
		return host == g.exact
	}
}

// pathGlob matches a cleaned request path. Same semantics as the
// agent's route matcher: "" / "*" / "/*" match all; "…/*" matches the
// base and its subtree; "…*" is a plain prefix; otherwise exact.
type pathGlob struct {
	matchAll bool
	exact    string
	prefix   string // set for wildcard patterns
	subtree  bool   // prefix ends with "/": also match the base without it
}

func compilePathGlob(pattern string) pathGlob {
	switch {
	case pattern == "" || pattern == "*" || pattern == "/*":
		return pathGlob{matchAll: true}
	case strings.HasSuffix(pattern, "/*"):
		return pathGlob{prefix: pattern[:len(pattern)-1], subtree: true}
	case strings.HasSuffix(pattern, "*"):
		return pathGlob{prefix: pattern[:len(pattern)-1]}
	default:
		return pathGlob{exact: pattern}
	}
}

func (g pathGlob) matches(path string) bool {
	switch {
	case g.matchAll:
		return true
	case g.exact != "":
		return path == g.exact
	case g.subtree:
		return path == strings.TrimSuffix(g.prefix, "/") || strings.HasPrefix(path, g.prefix)
	default:
		return strings.HasPrefix(path, g.prefix)
	}
}

// CleanPath normalizes a decoded request path the same way upstreams
// will resolve it (collapse dot segments, preserve a trailing slash),
// so neither firewall rules nor rate-limit host matching can be dodged
// with "/../" tricks.
func CleanPath(p string) string {
	if p == "" {
		return p
	}
	cleaned := gopath.Clean(p)
	if strings.HasSuffix(p, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

// fwRule is one compiled firewall rule. It matches when every non-empty
// clause matches (clauses AND-ed, values within a clause OR-ed).
type fwRule struct {
	name    string
	allow   bool
	hosts   []hostGlob
	paths   []pathGlob
	methods map[string]bool
	cidrs   []*net.IPNet
}

func (r *fwRule) matches(host, path, method string, ip net.IP) bool {
	if len(r.hosts) > 0 && !anyHost(r.hosts, host) {
		return false
	}
	if len(r.paths) > 0 && !anyPath(r.paths, path) {
		return false
	}
	if len(r.methods) > 0 && !r.methods[method] {
		return false
	}
	if len(r.cidrs) > 0 {
		if ip == nil {
			return false
		}
		found := false
		for _, c := range r.cidrs {
			if c.Contains(ip) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func anyHost(globs []hostGlob, host string) bool {
	for _, g := range globs {
		if g.matches(host) {
			return true
		}
	}
	return false
}

func anyPath(globs []pathGlob, path string) bool {
	for _, g := range globs {
		if g.matches(path) {
			return true
		}
	}
	return false
}

// firewallSet is a compiled, immutable rule list. Swapped atomically on
// hot reload; the hot path takes no locks.
type firewallSet struct {
	rules           []fwRule
	maxRequestBytes int64
}

func compileFirewall(cfg serverconfig.FirewallConfig) (*firewallSet, error) {
	fs := &firewallSet{maxRequestBytes: cfg.MaxRequestBytes}
	for _, rc := range cfg.Rules {
		r := fwRule{name: rc.Name, allow: rc.Action == "allow"}
		for _, h := range rc.When.Hosts {
			r.hosts = append(r.hosts, compileHostGlob(h))
		}
		for _, p := range rc.When.Paths {
			r.paths = append(r.paths, compilePathGlob(p))
		}
		if len(rc.When.Methods) > 0 {
			r.methods = make(map[string]bool, len(rc.When.Methods))
			for _, m := range rc.When.Methods {
				r.methods[strings.ToUpper(m)] = true
			}
		}
		for _, c := range rc.When.SourceCIDRs {
			_, ipNet, err := net.ParseCIDR(c)
			if err != nil {
				return nil, fmt.Errorf("firewall rule %q: invalid CIDR %q", rc.Name, c)
			}
			r.cidrs = append(r.cidrs, ipNet)
		}
		fs.rules = append(fs.rules, r)
	}
	return fs, nil
}

// decision evaluates the ordered rule list: first match wins; no match
// allows. The returned rule name labels metrics and logs on deny.
func (f *firewallSet) decision(host, path, method string, ip net.IP) (denied bool, rule string) {
	for i := range f.rules {
		if f.rules[i].matches(host, path, method, ip) {
			return !f.rules[i].allow, f.rules[i].name
		}
	}
	return false, ""
}
