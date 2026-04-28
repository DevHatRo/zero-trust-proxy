package serverconfig

import (
	"fmt"
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
	if c.Listen.HTTPS != "" && c.TLS.Mode == TLSModeNone {
		return fmt.Errorf("listen.https=%q requires tls.mode != none", c.Listen.HTTPS)
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
