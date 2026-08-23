package serverconfig

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Validate enforces structural rules on the parsed config. Returns the
// first violation as an error (callers can wrap it with the source
// path).
func (c *Config) Validate() error {
	if err := c.Listen.validate(); err != nil {
		return err
	}
	if err := c.TLS.validate(); err != nil {
		return err
	}
	if err := c.Agents.validate(); err != nil {
		return err
	}
	if err := c.Logging.validate(); err != nil {
		return err
	}
	if err := c.Security.validate(); err != nil {
		return err
	}
	if c.Listen.HTTPS != "" && c.TLS.Mode == TLSModeNone {
		return fmt.Errorf("listen.https=%q requires tls.mode != none", c.Listen.HTTPS)
	}
	return nil
}

// rateSpecRe matches "<n>/<unit>": 100/s, 20/minute, 5/h.
var rateSpecRe = regexp.MustCompile(`^[1-9][0-9]*/(s|m|h|second|minute|hour)$`)

func (s *SecurityConfig) validate() error {
	if s.RateLimit.Enabled {
		if err := s.RateLimit.Default.validate("security.rate_limit.default"); err != nil {
			return err
		}
		for i, o := range s.RateLimit.Overrides {
			where := fmt.Sprintf("security.rate_limit.overrides[%d]", i)
			if len(o.Hosts) == 0 {
				return fmt.Errorf("%s: hosts must list at least one pattern", where)
			}
			for _, h := range o.Hosts {
				if h == "" {
					return fmt.Errorf("%s: empty host pattern", where)
				}
			}
			if err := o.RateLimitRule.validate(where); err != nil {
				return err
			}
		}
	}
	if s.Firewall.Enabled {
		if s.Firewall.MaxRequestBytes < 0 {
			return fmt.Errorf("security.firewall.max_request_bytes must be >= 0")
		}
		names := make(map[string]bool, len(s.Firewall.Rules))
		for i, r := range s.Firewall.Rules {
			where := fmt.Sprintf("security.firewall.rules[%d]", i)
			if r.Name == "" {
				return fmt.Errorf("%s: name required (labels metrics and logs)", where)
			}
			if names[r.Name] {
				return fmt.Errorf("%s: duplicate rule name %q", where, r.Name)
			}
			names[r.Name] = true
			if r.Action != "allow" && r.Action != "deny" {
				return fmt.Errorf("%s (%s): action must be allow|deny, got %q", where, r.Name, r.Action)
			}
			for _, c := range r.When.SourceCIDRs {
				if _, _, err := net.ParseCIDR(c); err != nil {
					return fmt.Errorf("%s (%s): invalid CIDR %q", where, r.Name, c)
				}
			}
			for _, p := range r.When.Paths {
				if p == "" {
					return fmt.Errorf("%s (%s): empty path pattern", where, r.Name)
				}
			}
			for _, h := range r.When.Hosts {
				if h == "" {
					return fmt.Errorf("%s (%s): empty host pattern", where, r.Name)
				}
			}
		}
	}
	return nil
}

func (r *RateLimitRule) validate(where string) error {
	if r.Rate == "" {
		return fmt.Errorf("%s: rate required (e.g. \"100/s\")", where)
	}
	if !rateSpecRe.MatchString(r.Rate) {
		return fmt.Errorf("%s: invalid rate %q, expected \"<n>/<s|m|h>\"", where, r.Rate)
	}
	if r.Burst < 0 {
		return fmt.Errorf("%s: burst must be >= 0 (0 = default to the rate count)", where)
	}
	switch r.Key {
	case "", "ip", "host", "ip+host":
	case "identity":
		// Explicitly rejected until the access-policy layer (Phase 2)
		// exists — accepting it now would be silently-unenforced config.
		return fmt.Errorf("%s: key \"identity\" requires the access-policy layer (not yet implemented)", where)
	default:
		return fmt.Errorf("%s: key must be ip|host|ip+host, got %q", where, r.Key)
	}
	return nil
}

func (l *ListenConfig) validate() error {
	if l.HTTP == "" && l.HTTPS == "" {
		return fmt.Errorf("listen: at least one of http/https must be set")
	}
	if l.HTTPRedirect && l.HTTP == "" {
		return fmt.Errorf("listen: http_redirect=true requires listen.http")
	}
	if l.HTTP3 != "" && l.HTTPS == "" {
		return fmt.Errorf("listen: http3 requires listen.https (HTTP/3 reuses the TLS configuration)")
	}
	return nil
}

func (t *TLSConfig) validate() error {
	switch t.Mode {
	case TLSModeNone:
		if t.Manual != nil || len(t.SNI) > 0 || t.ACME != nil {
			return fmt.Errorf("tls.mode=none must not set manual/sni/acme blocks")
		}
	case TLSModeManual:
		if t.Manual == nil {
			return fmt.Errorf("tls.mode=manual requires tls.manual block")
		}
		if t.Manual.CertFile == "" || t.Manual.KeyFile == "" {
			return fmt.Errorf("tls.manual: cert_file and key_file required")
		}
		if len(t.SNI) > 0 || t.ACME != nil {
			return fmt.Errorf("tls.mode=manual conflicts with tls.sni/tls.acme")
		}
	case TLSModeSNI:
		if len(t.SNI) == 0 {
			return fmt.Errorf("tls.mode=sni requires at least one tls.sni entry")
		}
		for host, c := range t.SNI {
			if host == "" {
				return fmt.Errorf("tls.sni: empty hostname")
			}
			if c.CertFile == "" || c.KeyFile == "" {
				return fmt.Errorf("tls.sni[%q]: cert_file and key_file required", host)
			}
		}
		if t.Manual != nil || t.ACME != nil {
			return fmt.Errorf("tls.mode=sni conflicts with tls.manual/tls.acme")
		}
	case TLSModeACME:
		if t.ACME == nil {
			return fmt.Errorf("tls.mode=acme requires tls.acme block")
		}
		if t.ACME.StorageDir == "" {
			return fmt.Errorf("tls.acme.storage_dir required")
		}
		if t.Manual != nil || len(t.SNI) > 0 {
			return fmt.Errorf("tls.mode=acme conflicts with tls.manual/tls.sni")
		}
	default:
		return fmt.Errorf("tls.mode=%q: must be one of manual|sni|acme|none", t.Mode)
	}
	return nil
}

func (a *AgentsConfig) validate() error {
	if a.Listen == "" {
		return fmt.Errorf("agents.listen required")
	}
	if a.CertFile == "" || a.KeyFile == "" || a.CAFile == "" {
		return fmt.Errorf("agents: cert_file, key_file, ca_file all required")
	}
	if (a.TCPPortMin > 0 || a.TCPPortMax > 0) && a.TCPPortMin >= a.TCPPortMax {
		return fmt.Errorf("agents: tcp_port_min (%d) must be less than tcp_port_max (%d)", a.TCPPortMin, a.TCPPortMax)
	}
	return nil
}

func (l *LoggingConfig) validate() error {
	if l.Level != "" {
		switch strings.ToLower(l.Level) {
		case "debug", "info", "warn", "warning", "error":
		default:
			return fmt.Errorf("logging.level=%q: must be debug|info|warn|error", l.Level)
		}
	}
	if l.Format != "" {
		switch strings.ToLower(l.Format) {
		case "console", "json":
		default:
			return fmt.Errorf("logging.format=%q: must be console|json", l.Format)
		}
	}
	return nil
}
