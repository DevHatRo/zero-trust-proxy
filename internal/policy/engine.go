package policy

import (
	"net"
	"sync/atomic"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// Decision is the outcome of evaluating a request.
type Decision int

const (
	// Allow lets the request through to the router.
	Allow Decision = iota
	// Deny rejects with 403 — re-authenticating would not help
	// (authenticated-but-unauthorized, an explicit deny rule, or the
	// default action).
	Deny
	// RequireAuth means an anonymous caller hit an identity-based
	// requirement: browsers get the login flow, APIs get 401.
	RequireAuth
)

// Verdict pairs the decision with the rule that produced it (for
// metrics and logs; never sent to the client).
type Verdict struct {
	Decision Decision
	Rule     string // "" when the default action decided
}

// snapshot is the compiled, immutable policy state: swapped atomically
// on SIGHUP so rules and service tokens hot-reload without locking the
// request path.
type snapshot struct {
	rules        []compiledRule
	tokens       *tokenTable
	defaultAllow bool
}

// Engine evaluates requests. The session manager and OTP flow are
// fixed at startup (their config is restart-only); rules and tokens
// live in the snapshot.
type Engine struct {
	snap    atomic.Pointer[snapshot]
	session *SessionManager
	otp     *otpManager  // nil when email_otp is disabled
	oidc    *oidcManager // nil when no identity_providers are configured
	hooks   Hooks
}

// Hooks are optional metric callbacks; nil funcs are skipped.
type Hooks struct {
	Allowed      func(rule string)
	Denied       func(rule string)
	AuthRequired func()
	OTPSent      func()
	OTPVerified  func()
	OTPFailed    func()
	AuthRedirect func() // browser bounced to an IdP
	OIDCLogin    func() // successful OIDC login
	OIDCError    func() // OIDC discovery/exchange/verify failure
}

// New compiles the access config into an Engine. Callers pass a
// validated config (Validate resolves the session secret).
func New(cfg serverconfig.AccessConfig, hooks Hooks) (*Engine, error) {
	e := &Engine{hooks: hooks}
	e.session = NewSessionManager(
		cfg.Session.ResolvedSecret(),
		cfg.Session.EffectiveCookieName(),
		cfg.Session.EffectiveTTL(),
	)
	if cfg.EmailOTP.Enabled {
		e.otp = newOTPManager(
			newOTPStore(cfg.EmailOTP.EffectiveCodeTTL()),
			newCodeSender(cfg.EmailOTP),
			cfg.EmailOTP.From,
			cfg.EmailOTP.EffectiveSubject(),
		)
	}
	if len(cfg.IdentityProviders) > 0 {
		e.oidc = newOIDCManager(cfg.IdentityProviders)
	}
	if err := e.install(cfg); err != nil {
		return nil, err
	}
	return e, nil
}

// Reload recompiles rules and service tokens and swaps them in.
// Session and identity-provider changes are restart-only and ignored
// here by design (diffed and rejected upstream in server.Reload).
func (e *Engine) Reload(cfg serverconfig.AccessConfig) error {
	return e.install(cfg)
}

func (e *Engine) install(cfg serverconfig.AccessConfig) error {
	tokens, err := compileTokens(cfg.ServiceTokens)
	if err != nil {
		return err
	}
	rules, err := compileRules(cfg.Rules)
	if err != nil {
		return err
	}
	e.snap.Store(&snapshot{
		rules:        rules,
		tokens:       tokens,
		defaultAllow: cfg.DefaultAction == "allow", // ""/deny → deny
	})
	return nil
}

// Evaluate runs the ordered rule set for a request. First matching
// rule wins:
//
//	deny rule            → Deny
//	allow, no require    → Allow (public)
//	allow, require holds → Allow
//	require fails, caller anonymous, predicate identity-based → RequireAuth
//	require fails otherwise → Deny (authenticated-but-unauthorized:
//	                          re-authenticating will not help; and a
//	                          wrong source IP is not fixed by login)
//
// No rule matched → the default action.
func (s *snapshot) evaluate(host, path, method string, srcIP net.IP, id *Identity) Verdict {
	for i := range s.rules {
		r := &s.rules[i]
		if !r.matches(host, path, method) {
			continue
		}
		if !r.allow {
			return Verdict{Decision: Deny, Rule: r.name}
		}
		if r.require == nil {
			return Verdict{Decision: Allow, Rule: r.name}
		}
		if r.require.satisfies(id, srcIP) {
			return Verdict{Decision: Allow, Rule: r.name}
		}
		if id.Anonymous() && r.require.identityBased() {
			return Verdict{Decision: RequireAuth, Rule: r.name}
		}
		return Verdict{Decision: Deny, Rule: r.name}
	}
	if s.defaultAllow {
		return Verdict{Decision: Allow}
	}
	return Verdict{Decision: Deny}
}
