package serverconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	d := Defaults()
	if d.Listen.HTTP != ":80" || d.Listen.HTTPS != ":443" {
		t.Fatalf("unexpected listen defaults: %+v", d.Listen)
	}
	if !d.Listen.HTTPRedirect {
		t.Fatal("http_redirect should default to true")
	}
	if d.Router.RequestTimeout != 2*time.Minute {
		t.Fatalf("router.request_timeout default = %v, want 2m", d.Router.RequestTimeout)
	}
	if d.TLS.Mode != TLSModeNone {
		t.Fatalf("tls.mode default = %q, want none", d.TLS.Mode)
	}
	if d.Agents.Listen != ":8443" || d.Agents.CheckAddr != ":2020" {
		t.Fatalf("unexpected agents defaults: %+v", d.Agents)
	}
}

func TestParse_ACMEMinimal(t *testing.T) {
	yaml := `
tls:
  mode: acme
  acme:
    storage_dir: /var/lib/ztp/acme
    email: ops@example.com
agents:
  listen: ":8443"
  cert_file: /etc/certs/server.crt
  key_file:  /etc/certs/server.key
  ca_file:   /etc/certs/ca.crt
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.TLS.Mode != TLSModeACME {
		t.Fatalf("tls.mode = %q, want acme", cfg.TLS.Mode)
	}
	if cfg.TLS.ACME.Email != "ops@example.com" {
		t.Fatalf("tls.acme.email = %q", cfg.TLS.ACME.Email)
	}
	if cfg.Listen.HTTP != ":80" {
		t.Fatalf("default listen.http lost: %q", cfg.Listen.HTTP)
	}
}

func TestParse_ManualTLS(t *testing.T) {
	yaml := `
tls:
  mode: manual
  manual:
    cert_file: /tmp/srv.crt
    key_file:  /tmp/srv.key
agents:
  listen: ":8443"
  cert_file: /tmp/a.crt
  key_file:  /tmp/a.key
  ca_file:   /tmp/ca.crt
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.TLS.Manual == nil || cfg.TLS.Manual.CertFile != "/tmp/srv.crt" {
		t.Fatalf("manual cert lost: %+v", cfg.TLS.Manual)
	}
}

func TestParse_SNI(t *testing.T) {
	yaml := `
tls:
  mode: sni
  sni:
    "a.example.com":
      cert_file: /tmp/a.crt
      key_file:  /tmp/a.key
    "b.example.com":
      cert_file: /tmp/b.crt
      key_file:  /tmp/b.key
agents:
  listen: ":8443"
  cert_file: /tmp/a.crt
  key_file:  /tmp/a.key
  ca_file:   /tmp/ca.crt
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.TLS.SNI) != 2 {
		t.Fatalf("sni map size = %d, want 2", len(cfg.TLS.SNI))
	}
}

func TestValidate_Rejections(t *testing.T) {
	cases := map[string]string{
		"acme_without_block": `
tls: { mode: acme }
agents: { listen: ":8443", cert_file: a, key_file: b, ca_file: c }
`,
		"manual_without_block": `
tls: { mode: manual }
agents: { listen: ":8443", cert_file: a, key_file: b, ca_file: c }
`,
		"sni_empty": `
tls: { mode: sni, sni: {} }
agents: { listen: ":8443", cert_file: a, key_file: b, ca_file: c }
`,
		"acme_with_manual": `
tls:
  mode: acme
  acme: { storage_dir: /tmp }
  manual: { cert_file: a, key_file: b }
agents: { listen: ":8443", cert_file: a, key_file: b, ca_file: c }
`,
		"unknown_mode": `
tls: { mode: weird }
agents: { listen: ":8443", cert_file: a, key_file: b, ca_file: c }
`,
		"agents_missing_ca": `
tls: { mode: none }
listen: { http: ":80", https: "" }
agents: { listen: ":8443", cert_file: a, key_file: b }
`,
		"https_without_tls": `
listen: { http: ":80", https: ":443" }
tls: { mode: none }
agents: { listen: ":8443", cert_file: a, key_file: b, ca_file: c }
`,
		"bad_log_level": `
logging: { level: trace }
tls: { mode: none }
listen: { http: ":80", https: "" }
agents: { listen: ":8443", cert_file: a, key_file: b, ca_file: c }
`,
		"redirect_without_http": `
listen: { http: "", https: ":443", http_redirect: true }
tls:
  mode: manual
  manual: { cert_file: a, key_file: b }
agents: { listen: ":8443", cert_file: a, key_file: b, ca_file: c }
`,
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(yaml)); err == nil {
				t.Fatalf("expected validation error, got nil")
			}
		})
	}
}

func TestLoad_FromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	body := `
tls:
  mode: manual
  manual:
    cert_file: /tmp/x.crt
    key_file:  /tmp/x.key
agents:
  listen: ":8443"
  cert_file: /tmp/a.crt
  key_file:  /tmp/a.key
  ca_file:   /tmp/ca.crt
router:
  request_timeout: 90s
logging:
  level: debug
  format: json
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Router.RequestTimeout != 90*time.Second {
		t.Fatalf("router.request_timeout = %v, want 90s", cfg.Router.RequestTimeout)
	}
	if cfg.Logging.Level != "debug" || cfg.Logging.Format != "json" {
		t.Fatalf("logging = %+v", cfg.Logging)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "read config") {
		t.Fatalf("error message = %q", err.Error())
	}
}
