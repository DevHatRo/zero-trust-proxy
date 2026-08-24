package policy

import (
	"net/http"
	"testing"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// agentPolicyEngine builds an engine whose rules only match their own
// hosts, plus a host→policy_ref resolver, to exercise the agent-policy
// gap-fill path.
func agentPolicyEngine(t *testing.T, allow bool, defaultAction string, hostRef map[string]string) *Engine {
	t.Helper()
	cfg := testConfig(t, func(c *serverconfig.AccessConfig) {
		c.AllowAgentPolicy = allow
		c.DefaultAction = defaultAction
		c.ServiceTokens = append(c.ServiceTokens,
			serverconfig.ServiceToken{Name: "staffer", Hash: hashOf("staff-token"), Groups: []string{"staff"}})
		c.Rules = []serverconfig.AccessRule{
			// Matches only hr.example.com; agents on other hosts reference it.
			{Name: "staff-only", When: serverconfig.AccessMatch{Hosts: []string{"hr.example.com"}},
				Action: "allow", Require: &serverconfig.AccessRequire{Groups: []string{"staff"}}},
			// Path-scoped rule: a ref must honour its /admin/* scope, not
			// widen the requirement to the whole host.
			{Name: "admin-staff", When: serverconfig.AccessMatch{Hosts: []string{"hr.example.com"}, Paths: []string{"/admin/*"}},
				Action: "allow", Require: &serverconfig.AccessRequire{Groups: []string{"staff"}}},
			// Public rule an agent must not be able to borrow to bypass auth.
			{Name: "public", When: serverconfig.AccessMatch{Hosts: []string{"www.example.com"}}, Action: "allow"},
			// Network-only rule: satisfiable anonymously, so borrowing it via
			// a ref must be refused (not an identity requirement).
			{Name: "net-only", When: serverconfig.AccessMatch{Hosts: []string{"lan.example.com"}},
				Action: "allow", Require: &serverconfig.AccessRequire{SourceCIDRs: []string{"9.0.0.0/8"}}},
			// Explicit deny that must always win over a ref.
			{Name: "blocked", When: serverconfig.AccessMatch{Hosts: []string{"blocked.example.com"}}, Action: "deny"},
		}
	})
	e, err := New(cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	e.SetHostPolicyResolver(func(host string) string { return hostRef[host] })
	return e
}

func staffToken(r *http.Request) { r.Header.Set("Authorization", "Bearer staff-token") }

func TestAgentPolicyRefGapFill(t *testing.T) {
	// app.example.com has no server rule of its own; the agent refs staff-only.
	e := agentPolicyEngine(t, true, "deny", map[string]string{"app.example.com": "staff-only"})
	hit := false
	h := e.Wrap(okHandler(&hit))

	// Anonymous → the referenced rule's identity requirement kicks in (401).
	if rr := send(t, h, "GET", "http://app.example.com/x", "9.9.9.9", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous under ref: %d, want 401", rr.Code)
	}
	// Staff token → allowed by the referenced rule.
	rr := send(t, h, "GET", "http://app.example.com/x", "9.9.9.9", staffToken)
	if rr.Code != 200 || !hit {
		t.Fatalf("staff under ref: %d hit=%v, want 200", rr.Code, hit)
	}
}

func TestAgentPolicyRefIgnoredWhenDisabled(t *testing.T) {
	// Same ref, but allow_agent_policy is off → ref ignored → default deny.
	e := agentPolicyEngine(t, false, "deny", map[string]string{"app.example.com": "staff-only"})
	h := e.Wrap(okHandler(nil))
	if rr := send(t, h, "GET", "http://app.example.com/x", "9.9.9.9", staffToken); rr.Code != http.StatusForbidden {
		t.Fatalf("ref must be ignored when disabled: %d, want 403", rr.Code)
	}
}

func TestAgentPolicyRefNeverOverridesServerRule(t *testing.T) {
	// blocked.example.com is explicitly denied by a server rule; a ref must
	// not override it, even for an authorized identity.
	e := agentPolicyEngine(t, true, "deny", map[string]string{"blocked.example.com": "staff-only"})
	h := e.Wrap(okHandler(nil))
	if rr := send(t, h, "GET", "http://blocked.example.com/x", "9.9.9.9", staffToken); rr.Code != http.StatusForbidden {
		t.Fatalf("explicit deny must win over ref: %d, want 403", rr.Code)
	}
}

func TestAgentPolicyRefRejectsNonIdentityRefs(t *testing.T) {
	// A public (no-require) rule, a network-only rule (satisfiable
	// anonymously), and an unknown name must all be refused — the request
	// falls through to the default action rather than being granted. The
	// source IP 9.9.9.9 is inside net-only's 9.0.0.0/8, so a missing
	// identity-requirement check would wrongly allow it.
	for _, ref := range []string{"public", "net-only", "ghost"} {
		e := agentPolicyEngine(t, true, "deny", map[string]string{"app.example.com": ref})
		h := e.Wrap(okHandler(nil))
		if rr := send(t, h, "GET", "http://app.example.com/x", "9.9.9.9", nil); rr.Code != http.StatusForbidden {
			t.Fatalf("ref=%q must not grant access: %d, want 403", ref, rr.Code)
		}
	}
}

// The referenced rule's own path scope must be honoured — a /admin/*
// rule referenced by an agent applies only under /admin, not the whole host.
func TestAgentPolicyRefHonoursPathScope(t *testing.T) {
	e := agentPolicyEngine(t, true, "deny", map[string]string{"app.example.com": "admin-staff"})
	h := e.Wrap(okHandler(nil))

	// Under /admin/*: the ref applies → staff allowed.
	if rr := send(t, h, "GET", "http://app.example.com/admin/panel", "9.9.9.9", staffToken); rr.Code != 200 {
		t.Fatalf("staff under /admin: %d, want 200", rr.Code)
	}
	// Outside the ref rule's path scope: it does not apply → default deny,
	// even for the same staff identity (the requirement must not widen).
	if rr := send(t, h, "GET", "http://app.example.com/other", "9.9.9.9", staffToken); rr.Code != http.StatusForbidden {
		t.Fatalf("staff outside /admin: %d, want 403 (ref must not widen scope)", rr.Code)
	}
}

// Under default_action: allow, an agent ref must NOT be able to restrict a
// host the operator left open — server-authoritative default wins.
func TestAgentPolicyRefDoesNotOverrideDefaultAllow(t *testing.T) {
	e := agentPolicyEngine(t, true, "allow", map[string]string{"app.example.com": "staff-only"})
	hit := false
	h := e.Wrap(okHandler(&hit))

	// Anonymous request to an otherwise-unmatched host: default allow stands.
	rr := send(t, h, "GET", "http://app.example.com/x", "9.9.9.9", func(r *http.Request) {
		r.Header.Set("Accept", "text/html")
	})
	if rr.Code != 200 || !hit {
		t.Fatalf("default-allow must win over ref: %d hit=%v, want 200", rr.Code, hit)
	}
}
