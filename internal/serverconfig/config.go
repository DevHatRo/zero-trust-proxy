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
