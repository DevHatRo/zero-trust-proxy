// Package serverconfig defines the YAML configuration schema for the
// zero-trust-proxy server, plus a loader and validator. No runtime
// behavior lives here — see internal/server for the orchestrator that
// consumes these structs.
package serverconfig

import "time"

// Config is the top-level YAML schema.
type Config struct {
	Listen  ListenConfig  `yaml:"listen" json:"listen"`
	TLS     TLSConfig     `yaml:"tls" json:"tls"`
	Agents  AgentsConfig  `yaml:"agents" json:"agents"`
	Router  RouterConfig  `yaml:"router" json:"router"`
	Logging LoggingConfig `yaml:"logging" json:"logging"`
	Metrics MetricsConfig `yaml:"metrics" json:"metrics"`
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
	Mode   TLSMode                 `yaml:"mode" json:"mode"`
	Manual *ManualCert             `yaml:"manual,omitempty" json:"manual,omitempty"`
	SNI    map[string]ManualCert   `yaml:"sni,omitempty" json:"sni,omitempty"`
	ACME   *ACMEConfig             `yaml:"acme,omitempty" json:"acme,omitempty"`
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
	Listen      string `yaml:"listen" json:"listen"`
	CertFile    string `yaml:"cert_file" json:"cert_file"`
	KeyFile     string `yaml:"key_file" json:"key_file"`
	CAFile      string `yaml:"ca_file" json:"ca_file"`
	CheckAddr   string `yaml:"check_addr,omitempty" json:"check_addr,omitempty"`
	TCPPortMin  int    `yaml:"tcp_port_min,omitempty" json:"tcp_port_min,omitempty"`
	TCPPortMax  int    `yaml:"tcp_port_max,omitempty" json:"tcp_port_max,omitempty"`
}

type RouterConfig struct {
	RequestTimeout time.Duration `yaml:"request_timeout,omitempty" json:"request_timeout,omitempty"`
}

type LoggingConfig struct {
	Level     string `yaml:"level,omitempty" json:"level,omitempty"`
	Format    string `yaml:"format,omitempty" json:"format,omitempty"`
	AccessLog bool   `yaml:"access_log,omitempty" json:"access_log,omitempty"`
}

// Defaults returns a Config populated with the same defaults the legacy
// Caddyfile.example produces. Callers overlay user YAML on top.
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
