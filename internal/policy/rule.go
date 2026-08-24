package policy

import (
	"fmt"
	"net"
	"strings"

	"github.com/devhatro/zero-trust-proxy/internal/security"
	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// compiledRule is one access rule, fully pre-compiled: globs parsed,
// CIDRs parsed, methods normalized. Immutable after compilation.
type compiledRule struct {
	name    string
	allow   bool
	hosts   []security.HostPattern
	paths   []security.PathPattern
	methods map[string]bool
	require *compiledRequire // nil = no identity needed (public)
}

// compiledRequire is the identity predicate. Clauses are AND-ed;
// values within a clause are any-of.
type compiledRequire struct {
	authenticated bool
	groups        []string
	emails        map[string]bool // lowercase
	emailDomains  []string        // lowercase, no leading @
	provider      string
	cidrs         []*net.IPNet
}

// identityBased reports whether the predicate involves the caller's
// identity (as opposed to purely network clauses). Decides whether a
// failing anonymous caller is offered login (RequireAuth) or just
// denied — logging in cannot fix a wrong source IP.
func (r *compiledRequire) identityBased() bool {
	return r.authenticated || len(r.groups) > 0 || len(r.emails) > 0 ||
		len(r.emailDomains) > 0 || r.provider != ""
}

func compileRules(rules []serverconfig.AccessRule) ([]compiledRule, error) {
	out := make([]compiledRule, 0, len(rules))
	for _, rc := range rules {
		r := compiledRule{name: rc.Name, allow: rc.Action == "allow"}
		for _, h := range rc.When.Hosts {
			r.hosts = append(r.hosts, security.CompileHostPattern(h))
		}
		for _, p := range rc.When.Paths {
			r.paths = append(r.paths, security.CompilePathPattern(p))
		}
		if len(rc.When.Methods) > 0 {
			r.methods = make(map[string]bool, len(rc.When.Methods))
			for _, m := range rc.When.Methods {
				r.methods[strings.ToUpper(m)] = true
			}
		}
		if rc.Require != nil {
			req := &compiledRequire{
				authenticated: rc.Require.Authenticated,
				groups:        rc.Require.Groups,
				provider:      rc.Require.IdentityProvider,
			}
			if len(rc.Require.Emails) > 0 {
				req.emails = make(map[string]bool, len(rc.Require.Emails))
				for _, e := range rc.Require.Emails {
					req.emails[strings.ToLower(e)] = true
				}
			}
			for _, d := range rc.Require.EmailsDomain {
				req.emailDomains = append(req.emailDomains, strings.ToLower(d))
			}
			for _, c := range rc.Require.SourceCIDRs {
				// Validation also rejects bad CIDRs, but compilation must
				// not silently drop one — that would delete a network
				// restriction while the rule's other clauses keep allowing
				// (fail-open). An error here keeps the previous snapshot
				// in force on reload.
				_, ipNet, err := net.ParseCIDR(c)
				if err != nil {
					return nil, fmt.Errorf("rule %q: invalid CIDR %q", rc.Name, c)
				}
				req.cidrs = append(req.cidrs, ipNet)
			}
			r.require = req
		}
		out = append(out, r)
	}
	return out, nil
}

// matches reports whether the rule applies to the request. Empty
// clauses match anything; specified clauses are AND-ed.
func (r *compiledRule) matches(host, path, method string) bool {
	if len(r.hosts) > 0 {
		ok := false
		for _, h := range r.hosts {
			if h.Matches(host) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return r.matchesPathMethod(path, method)
}

// matchesPathMethod checks the path and method clauses only, ignoring the
// host clause. Used by the agent policy_ref gap-fill, where the agent's
// own host substitutes for the referenced rule's host scope — but its
// path/method scope must still be honoured.
func (r *compiledRule) matchesPathMethod(path, method string) bool {
	if len(r.paths) > 0 {
		ok := false
		for _, p := range r.paths {
			if p.Matches(path) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.methods) > 0 && !r.methods[method] {
		return false
	}
	return true
}

// satisfies reports whether the identity (plus source IP) meets the
// predicate. Fails closed on missing inputs: a nil IP fails any CIDR
// clause, an empty email fails any email clause — and a predicate with
// no clauses at all is unsatisfiable, never a free pass. (Validation
// rejects empty require blocks; this is the defence-in-depth layer for
// any future caller that bypasses it.)
func (r *compiledRequire) satisfies(id *Identity, srcIP net.IP) bool {
	if !r.identityBased() && len(r.cidrs) == 0 {
		return false
	}
	if r.authenticated && id.Anonymous() {
		return false
	}
	if len(r.groups) > 0 {
		ok := false
		for _, g := range r.groups {
			// A blank group entry never matches, even if an identity were
			// (mis)configured with an empty group name.
			if g != "" && id.InGroup(g) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.emails) > 0 {
		// id.Email == "" must fail closed: anonymous identities carry an
		// empty email, and a blank allow-list entry (e.g. a template
		// variable that rendered empty) must never turn into a match.
		if id == nil || id.Email == "" || !r.emails[strings.ToLower(id.Email)] {
			return false
		}
	}
	if len(r.emailDomains) > 0 {
		if !emailInDomains(id, r.emailDomains) {
			return false
		}
	}
	if r.provider != "" {
		if id == nil || id.Provider != r.provider {
			return false
		}
	}
	if len(r.cidrs) > 0 {
		if srcIP == nil {
			return false
		}
		ok := false
		for _, c := range r.cidrs {
			if c.Contains(srcIP) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func emailInDomains(id *Identity, domains []string) bool {
	if id == nil || id.Email == "" {
		return false
	}
	at := strings.LastIndexByte(id.Email, '@')
	if at < 0 {
		return false
	}
	domain := strings.ToLower(id.Email[at+1:])
	for _, d := range domains {
		if domain == d {
			return true
		}
	}
	return false
}
