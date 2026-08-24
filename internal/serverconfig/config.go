// Package serverconfig defines the YAML configuration schema for the
// zero-trust-proxy server, plus a loader and validator. No runtime
// behavior lives here — see internal/server for the orchestrator that
// consumes these structs.
package serverconfig

import "time"

// Config is the top-level YAML schema.
type Config struct {
	Listen   ListenConfig   `yaml:"listen" json:"listen"`
	TLS      TLSConfig      `yaml:"tls" json:"tls"`
	Agents   AgentsConfig   `yaml:"agents" json:"agents"`
	Router   RouterConfig   `yaml:"router" json:"router"`
	Logging  LoggingConfig  `yaml:"logging" json:"logging"`
	Metrics  MetricsConfig  `yaml:"metrics" json:"metrics"`
	Security SecurityConfig `yaml:"security,omitempty" json:"security,omitempty"`
	Access   AccessConfig   `yaml:"access,omitempty" json:"access,omitempty"`
}

// AccessConfig is the identity-based access-policy layer: every inbound
// request is evaluated against the ordered rule set before it is
// dispatched to an agent. Identity comes from a service token
// (machine) or a signed session cookie (human, minted by the OIDC
// flow). Disabled by default — an absent block changes nothing.
type AccessConfig struct {
	Enabled           bool               `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Session           SessionConfig      `yaml:"session,omitempty" json:"session,omitempty"`
	ServiceTokens     []ServiceToken     `yaml:"service_tokens,omitempty" json:"service_tokens,omitempty"`
	IdentityProviders []IdentityProvider `yaml:"identity_providers,omitempty" json:"identity_providers,omitempty"`
	// DefaultAction applies when no rule matches: allow | deny.
	// Defaults to deny when the layer is enabled (zero trust).
	DefaultAction string       `yaml:"default_action,omitempty" json:"default_action,omitempty"`
	Rules         []AccessRule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// SessionConfig signs the browser session cookie. Secret is either an
// inline value or an environment reference in the form "${VAR}"
// (recommended, keeps the secret out of the YAML file); resolved at
// validation time.
type SessionConfig struct {
	Secret     string        `yaml:"secret,omitempty" json:"secret,omitempty"`
	CookieName string        `yaml:"cookie_name,omitempty" json:"cookie_name,omitempty"` // default ztp_session
	TTL        time.Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`                 // default 8h

	secret []byte // resolved (env-expanded) during Validate; never serialized
}

// ResolvedSecret returns the session-signing secret after env
// expansion (populated by Validate). Empty until validation has run.
func (s *SessionConfig) ResolvedSecret() []byte { return s.secret }

// EffectiveCookieName returns the configured cookie name or the default.
func (s *SessionConfig) EffectiveCookieName() string {
	if s.CookieName == "" {
		return "ztp_session"
	}
	return s.CookieName
}

// EffectiveTTL returns the configured session lifetime or the default 8h.
func (s *SessionConfig) EffectiveTTL() time.Duration {
	if s.TTL <= 0 {
		return 8 * time.Hour
	}
	return s.TTL
}

// ServiceToken is a machine identity: the SHA-256 of the bearer secret
// (never the secret itself) plus the groups it grants.
type ServiceToken struct {
	Name   string   `yaml:"name" json:"name"`
	Hash   string   `yaml:"hash" json:"hash"` // "sha256:<64 hex>"
	Groups []string `yaml:"groups,omitempty" json:"groups,omitempty"`
}

// IdentityProvider is an OIDC provider. Credentials support "${VAR}"
// env expansion. The login flow ships in a later increment; until it
// does, validation rejects a non-empty provider list so the config
// never claims a capability the proxy cannot deliver.
type IdentityProvider struct {
	Name         string   `yaml:"name" json:"name"`
	Type         string   `yaml:"type" json:"type"` // oidc
	Issuer       string   `yaml:"issuer" json:"issuer"`
	ClientID     string   `yaml:"client_id" json:"client_id"`
	ClientSecret string   `yaml:"client_secret" json:"client_secret"`
	Scopes       []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
}

// AccessRule is one ordered policy rule: match conditions, an action,
// and an optional identity requirement. Rules are evaluated top-down;
// first match wins.
type AccessRule struct {
	Name    string         `yaml:"name" json:"name"`
	When    AccessMatch    `yaml:"when,omitempty" json:"when,omitempty"`
	Action  string         `yaml:"action" json:"action"` // allow | deny
	Require *AccessRequire `yaml:"require,omitempty" json:"require,omitempty"`
}

// AccessMatch selects which requests a rule applies to. Hosts use the
// edge glob style (exact, "*", "*.suffix"); paths use exact / "…*"
// prefix / "…/*" subtree, matched after percent-decoding and
// dot-segment collapse.
type AccessMatch struct {
	Hosts   []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Paths   []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
}

// AccessRequire is the identity predicate an allow rule may demand.
// All specified clauses must hold (AND); list values are any-of (OR).
type AccessRequire struct {
	Authenticated    bool     `yaml:"authenticated,omitempty" json:"authenticated,omitempty"`
	Groups           []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	Emails           []string `yaml:"emails,omitempty" json:"emails,omitempty"`
	EmailsDomain     []string `yaml:"emails_domain,omitempty" json:"emails_domain,omitempty"`
	IdentityProvider string   `yaml:"identity_provider,omitempty" json:"identity_provider,omitempty"`
	SourceCIDRs      []string `yaml:"source_cidrs,omitempty" json:"source_cidrs,omitempty"`
}

// SecurityConfig groups the pre-dispatch edge protections: a firewall
// (ordered allow/deny rules + request-size cap) and a rate limiter.
// Both run before any request reaches the agent dispatch path; they
// complement the finer-grained per-service route policies the agent
// enforces (ip_whitelist / rate_limit in the agent's routes: section).
type SecurityConfig struct {
	RateLimit RateLimitConfig `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
	Firewall  FirewallConfig  `yaml:"firewall,omitempty" json:"firewall,omitempty"`
}

// RateLimitConfig is the edge token-bucket limiter. `default` applies
// to every host; `overrides` (first hostname match wins) replace it
// for specific hosts.
type RateLimitConfig struct {
	Enabled   bool                `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Default   RateLimitRule       `yaml:"default,omitempty" json:"default,omitempty"`
	Overrides []RateLimitOverride `yaml:"overrides,omitempty" json:"overrides,omitempty"`
}

// RateLimitRule is one limiter's parameters. Key selects the bucket
// key: "ip" (default), "host", or "ip+host". Rate is "<n>/<s|m|h>"
// (full words second/minute/hour also accepted). Burst defaults to the
// rate count when 0.
type RateLimitRule struct {
	Key   string `yaml:"key,omitempty" json:"key,omitempty"`
	Rate  string `yaml:"rate,omitempty" json:"rate,omitempty"`
	Burst int    `yaml:"burst,omitempty" json:"burst,omitempty"`
}

// RateLimitOverride applies a different rule to hosts matching any of
// the listed patterns (exact, "*", or "*.suffix").
type RateLimitOverride struct {
	Hosts         []string `yaml:"hosts" json:"hosts"`
	RateLimitRule `yaml:",inline" json:",inline"`
}

// FirewallConfig is an ordered allow/deny rule list plus a hard
// request-size cap. First matching rule wins; no match = allow.
type FirewallConfig struct {
	Enabled         bool           `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Rules           []FirewallRule `yaml:"rules,omitempty" json:"rules,omitempty"`
	MaxRequestBytes int64          `yaml:"max_request_bytes,omitempty" json:"max_request_bytes,omitempty"`
}

// FirewallRule matches when every non-empty clause in When matches
// (clauses AND-ed, values within a clause OR-ed).
type FirewallRule struct {
	Name   string            `yaml:"name" json:"name"`
	Action string            `yaml:"action" json:"action"` // allow | deny
	When   FirewallRuleMatch `yaml:"when,omitempty" json:"when,omitempty"`
}

// FirewallRuleMatch holds the match clauses. Hosts: exact, "*", or
// "*.suffix". Paths: exact, "…/*" subtree, "…*" prefix, or "/*" all.
type FirewallRuleMatch struct {
	Hosts       []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Paths       []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	Methods     []string `yaml:"methods,omitempty" json:"methods,omitempty"`
	SourceCIDRs []string `yaml:"source_cidrs,omitempty" json:"source_cidrs,omitempty"`
}

// MetricsConfig configures the optional Prometheus exporter. When
// `addr` is non-empty, an HTTP listener on that address serves
// `/metrics` in the Prometheus text format. Bind to a private
// interface — there is no auth on this endpoint.
type MetricsConfig struct {
	Addr string `yaml:"addr,omitempty" json:"addr,omitempty"`
}

type ListenConfig struct {
	HTTP         string `yaml:"http,omitempty" json:"http,omitempty"`
	HTTPS        string `yaml:"https,omitempty" json:"https,omitempty"`
	HTTP3        string `yaml:"http3,omitempty" json:"http3,omitempty"` // optional UDP address (e.g. ":443") for QUIC/HTTP3
	HTTPRedirect bool   `yaml:"http_redirect,omitempty" json:"http_redirect,omitempty"`
}

// TLSMode selects how the HTTPS listener obtains certificates.
type TLSMode string

const (
	TLSModeManual TLSMode = "manual"
	TLSModeSNI    TLSMode = "sni"
	TLSModeACME   TLSMode = "acme"
	TLSModeNone   TLSMode = "none"
)

type TLSConfig struct {
	Mode   TLSMode               `yaml:"mode" json:"mode"`
	Manual *ManualCert           `yaml:"manual,omitempty" json:"manual,omitempty"`
	SNI    map[string]ManualCert `yaml:"sni,omitempty" json:"sni,omitempty"`
	ACME   *ACMEConfig           `yaml:"acme,omitempty" json:"acme,omitempty"`
}

type ManualCert struct {
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
}

type ACMEConfig struct {
	StorageDir string `yaml:"storage_dir" json:"storage_dir"`
	Email      string `yaml:"email,omitempty" json:"email,omitempty"`
	CAURL      string `yaml:"ca_url,omitempty" json:"ca_url,omitempty"`
}

type AgentsConfig struct {
	Listen     string `yaml:"listen" json:"listen"`
	CertFile   string `yaml:"cert_file" json:"cert_file"`
	KeyFile    string `yaml:"key_file" json:"key_file"`
	CAFile     string `yaml:"ca_file" json:"ca_file"`
	CheckAddr  string `yaml:"check_addr,omitempty" json:"check_addr,omitempty"`
	TCPPortMin int    `yaml:"tcp_port_min,omitempty" json:"tcp_port_min,omitempty"`
	TCPPortMax int    `yaml:"tcp_port_max,omitempty" json:"tcp_port_max,omitempty"`

	Identity   IdentityConfig   `yaml:"identity,omitempty" json:"identity,omitempty"`
	ACL        ACLConfig        `yaml:"acl,omitempty" json:"acl,omitempty"`
	Revocation RevocationConfig `yaml:"revocation,omitempty" json:"revocation,omitempty"`
}

// IdentityConfig binds the agent's register ID to its client
// certificate. bind_to: "cn" requires ID == cert Subject CommonName,
// "san" requires ID == the first DNS SAN, "none" (default) keeps the
// legacy unverified behavior but still logs and counts mismatches so
// operators can observe before flipping.
type IdentityConfig struct {
	BindTo string `yaml:"bind_to,omitempty" json:"bind_to,omitempty"` // cn | san | none
}

// ACLConfig scopes each agent to the hostnames it may register.
// Patterns are label-aware globs: "*" matches exactly one DNS label
// ("*.eu.example.com" matches "a.eu.example.com", not "eu.example.com"
// or "a.b.eu.example.com"). An agent absent from the list is rejected
// at register time unless allow_unlisted is true.
type ACLConfig struct {
	AllowUnlisted *bool           `yaml:"allow_unlisted,omitempty" json:"allow_unlisted,omitempty"` // default true (legacy)
	Agents        []AgentACLEntry `yaml:"agents,omitempty" json:"agents,omitempty"`
}

type AgentACLEntry struct {
	ID           string   `yaml:"id" json:"id"`
	AllowedHosts []string `yaml:"allowed_hosts" json:"allowed_hosts"`
}

// Unlisted reports the effective allow_unlisted value (default true so
// an empty config preserves today's behavior).
func (a *ACLConfig) Unlisted() bool {
	if a.AllowUnlisted == nil {
		return true
	}
	return *a.AllowUnlisted
}

// RevocationConfig rejects specific client certificates at the TLS
// handshake: an inline serial denylist and/or a CRL file. The CRL is
// re-read on SIGHUP.
type RevocationConfig struct {
	CRLFile       string   `yaml:"crl_file,omitempty" json:"crl_file,omitempty"`
	DeniedSerials []string `yaml:"denied_serials,omitempty" json:"denied_serials,omitempty"` // hex
}

type RouterConfig struct {
	RequestTimeout time.Duration `yaml:"request_timeout,omitempty" json:"request_timeout,omitempty"`
}

type LoggingConfig struct {
	Level     string `yaml:"level,omitempty" json:"level,omitempty"`
	Format    string `yaml:"format,omitempty" json:"format,omitempty"`
	AccessLog bool   `yaml:"access_log,omitempty" json:"access_log,omitempty"`
}

// Defaults returns a Config populated with sensible built-in defaults.
// Callers overlay user YAML on top.
func Defaults() Config {
	return Config{
		Listen: ListenConfig{
			HTTP:         ":80",
			HTTPS:        ":443",
			HTTPRedirect: true,
		},
		TLS: TLSConfig{Mode: TLSModeNone},
		Agents: AgentsConfig{
			Listen:    ":8443",
			CheckAddr: ":2020",
		},
		Router: RouterConfig{
			RequestTimeout: 2 * time.Minute,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "console",
		},
	}
}
