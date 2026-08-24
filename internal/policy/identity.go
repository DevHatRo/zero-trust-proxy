// Package policy implements the identity-based access layer: every
// inbound request is resolved to an Identity (service token, session
// cookie, or anonymous) and evaluated against an ordered rule set —
// at the proxy, before the request is dispatched to an agent. The
// agent is on the customer network and is the less-trusted side;
// access decisions never live there.
package policy

import (
	"github.com/devhatro/zero-trust-proxy/internal/logger"
)

var log = logger.WithComponent("access")

// Identity sources, in resolution order.
const (
	SourceNone         = ""              // anonymous
	SourceSession      = "session"       // signed cookie minted by the login flow
	SourceServiceToken = "service_token" // Authorization: Bearer / X-ZTP-Token
)

// Identity is the resolved caller.
type Identity struct {
	Source   string
	Subject  string   // token name, or OIDC `sub`
	Email    string   // sessions only
	Groups   []string // token groups, or the OIDC groups claim
	Provider string   // IdP name for sessions; "" for tokens
}

// Anonymous reports whether no identity was presented.
func (id *Identity) Anonymous() bool { return id == nil || id.Source == SourceNone }

// InGroup reports whether the identity holds the given group.
func (id *Identity) InGroup(group string) bool {
	if id == nil {
		return false
	}
	for _, g := range id.Groups {
		if g == group {
			return true
		}
	}
	return false
}
