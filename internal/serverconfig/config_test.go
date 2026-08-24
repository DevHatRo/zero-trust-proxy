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

func TestSecurityValidation(t *testing.T) {
	base := func() Config {
		c := Defaults()
		c.TLS = TLSConfig{Mode: TLSModeNone}
		c.Listen = ListenConfig{HTTP: ":80"}
		c.Agents = AgentsConfig{Listen: ":8443", CertFile: "c", KeyFile: "k", CAFile: "ca"}
		return c
	}

	good := base()
	good.Security = SecurityConfig{
		RateLimit: RateLimitConfig{
			Enabled: true,
			Default: RateLimitRule{Key: "ip", Rate: "100/s", Burst: 200},
			Overrides: []RateLimitOverride{
				{Hosts: []string{"api.example.com"}, RateLimitRule: RateLimitRule{Rate: "20/s"}},
			},
		},
		Firewall: FirewallConfig{
			Enabled: true,
			Rules: []FirewallRule{
				{Name: "probes", Action: "deny", When: FirewallRuleMatch{Paths: []string{"/.env"}}},
				{Name: "office", Action: "allow", When: FirewallRuleMatch{SourceCIDRs: []string{"203.0.113.0/24"}}},
			},
			MaxRequestBytes: 1 << 25,
		},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid security config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing rate", func(c *Config) { c.Security.RateLimit.Default.Rate = "" }},
		{"bad rate", func(c *Config) { c.Security.RateLimit.Default.Rate = "fast" }},
		{"bad key", func(c *Config) { c.Security.RateLimit.Default.Key = "cookie" }},
		{"identity key rejected until phase 2", func(c *Config) { c.Security.RateLimit.Default.Key = "identity" }},
		{"override without hosts", func(c *Config) { c.Security.RateLimit.Overrides[0].Hosts = nil }},
		{"rule without name", func(c *Config) { c.Security.Firewall.Rules[0].Name = "" }},
		{"duplicate rule name", func(c *Config) { c.Security.Firewall.Rules[1].Name = "probes" }},
		{"bad action", func(c *Config) { c.Security.Firewall.Rules[0].Action = "block" }},
		{"bad cidr", func(c *Config) { c.Security.Firewall.Rules[1].When.SourceCIDRs = []string{"nope"} }},
	}
	for _, tc := range cases {
		cfg := good // copy
		cfg.Security.RateLimit.Overrides = append([]RateLimitOverride(nil), good.Security.RateLimit.Overrides...)
		cfg.Security.Firewall.Rules = append([]FirewallRule(nil), good.Security.Firewall.Rules...)
		tc.mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
	}

	// Disabled sections are not validated (dormant config is allowed).
	off := base()
	off.Security.RateLimit = RateLimitConfig{Enabled: false, Default: RateLimitRule{Rate: "garbage"}}
	if err := off.Validate(); err != nil {
		t.Fatalf("disabled section should not be validated: %v", err)
	}
}

func TestAgentsIdentityValidation(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	base := func() Config {
		c := Defaults()
		c.TLS = TLSConfig{Mode: TLSModeNone}
		c.Listen = ListenConfig{HTTP: ":80"}
		c.Agents = AgentsConfig{Listen: ":8443", CertFile: "c", KeyFile: "k", CAFile: "ca"}
		return c
	}

	good := base()
	good.Agents.Identity = IdentityConfig{BindTo: "cn"}
	good.Agents.ACL = ACLConfig{
		AllowUnlisted: boolPtr(false),
		Agents: []AgentACLEntry{
			{ID: "synology", AllowedHosts: []string{"*.local.example.com"}},
			{ID: "edge-eu", AllowedHosts: []string{"*.eu.example.com", "status.example.com"}},
		},
	}
	good.Agents.Revocation = RevocationConfig{DeniedSerials: []string{"0A1B2C3D", "ff"}}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid identity config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"bad bind_to", func(c *Config) { c.Agents.Identity.BindTo = "spiffe" }},
		{"acl entry without id", func(c *Config) { c.Agents.ACL.Agents[0].ID = "" }},
		{"duplicate acl id", func(c *Config) { c.Agents.ACL.Agents[1].ID = "synology" }},
		{"acl entry without hosts", func(c *Config) { c.Agents.ACL.Agents[0].AllowedHosts = nil }},
		{"bad host pattern chars", func(c *Config) { c.Agents.ACL.Agents[0].AllowedHosts = []string{"bad host!"} }},
		{"empty label in pattern", func(c *Config) { c.Agents.ACL.Agents[0].AllowedHosts = []string{"a..b"} }},
		{"non-hex serial", func(c *Config) { c.Agents.Revocation.DeniedSerials = []string{"xyz"} }},
		{"missing crl file", func(c *Config) { c.Agents.Revocation.CRLFile = "/does/not/exist.crl" }},
	}
	for _, tc := range cases {
		cfg := good
		cfg.Agents.ACL.Agents = append([]AgentACLEntry(nil), good.Agents.ACL.Agents...)
		cfg.Agents.Revocation.DeniedSerials = append([]string(nil), good.Agents.Revocation.DeniedSerials...)
		tc.mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
	}

	// Defaults: unset ACL means allow_unlisted=true, bind_to none.
	d := base()
	if !d.Agents.ACL.Unlisted() {
		t.Fatal("default allow_unlisted must be true (legacy behavior)")
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("default agents config should validate: %v", err)
	}
}

func TestAccessValidation(t *testing.T) {
	t.Setenv("ZTP_SESSION_SECRET_T", "0123456789abcdef0123456789abcdef")
	t.Setenv("ZTP_GOOG_ID", "client-id")
	t.Setenv("ZTP_GOOG_SECRET", "client-secret")

	base := func() Config {
		c := Defaults()
		c.TLS = TLSConfig{Mode: TLSModeNone}
		c.Listen = ListenConfig{HTTP: ":80"}
		c.Agents = AgentsConfig{Listen: ":8443", CertFile: "c", KeyFile: "k", CAFile: "ca"}
		return c
	}

	good := base()
	good.Access = AccessConfig{
		Enabled: true,
		Session: SessionConfig{Secret: "${ZTP_SESSION_SECRET_T}"},
		ServiceTokens: []ServiceToken{
			{Name: "ci", Hash: "sha256:" + strings.Repeat("ab", 32), Groups: []string{"ci"}},
		},
		DefaultAction: "deny",
		Rules: []AccessRule{
			{Name: "public", When: AccessMatch{Hosts: []string{"www.example.com"}}, Action: "allow"},
			{Name: "internal", When: AccessMatch{Hosts: []string{"*.internal.example.com"}}, Action: "allow",
				Require: &AccessRequire{Groups: []string{"staff"},
					SourceCIDRs: []string{"10.0.0.0/8"}}},
		},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid access config rejected: %v", err)
	}
	if len(good.Access.Session.ResolvedSecret()) < 32 {
		t.Fatal("Validate must resolve the session secret")
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing secret", func(c *Config) { c.Access.Session.Secret = "" }},
		{"unset secret env ref", func(c *Config) { c.Access.Session.Secret = "${ZTP_DOES_NOT_EXIST}" }},
		{"bad default action", func(c *Config) { c.Access.DefaultAction = "maybe" }},
		{"plaintext token hash", func(c *Config) { c.Access.ServiceTokens[0].Hash = "hunter2" }},
		{"duplicate token name", func(c *Config) {
			c.Access.ServiceTokens = append(c.Access.ServiceTokens, c.Access.ServiceTokens[0])
		}},
		{"identity provider without issuer", func(c *Config) {
			c.Access.IdentityProviders = []IdentityProvider{{Name: "google", Type: "oidc",
				ClientID: "${ZTP_GOOG_ID}", ClientSecret: "${ZTP_GOOG_SECRET}"}}
		}},
		{"identity provider with http issuer", func(c *Config) {
			c.Access.IdentityProviders = []IdentityProvider{{Name: "google", Type: "oidc",
				Issuer: "http://accounts.google.com", ClientID: "${ZTP_GOOG_ID}", ClientSecret: "${ZTP_GOOG_SECRET}"}}
		}},
		{"identity provider with non-oidc type", func(c *Config) {
			c.Access.IdentityProviders = []IdentityProvider{{Name: "saml", Type: "saml",
				Issuer: "https://idp.example.com", ClientID: "${ZTP_GOOG_ID}", ClientSecret: "${ZTP_GOOG_SECRET}"}}
		}},
		{"identity_provider require names unknown provider", func(c *Config) {
			c.Access.Rules[1].Require.IdentityProvider = "ghost"
		}},
		{"empty require fails closed at validation", func(c *Config) {
			c.Access.Rules[1].Require = &AccessRequire{}
		}},
		{"emails without a login flow", func(c *Config) {
			c.Access.Rules[1].Require.Emails = []string{"ceo@example.com"}
		}},
		{"emails_domain without a login flow", func(c *Config) {
			c.Access.Rules[1].Require.EmailsDomain = []string{"example.com"}
		}},
		{"blank group in require", func(c *Config) {
			c.Access.Rules[1].Require.Groups = []string{"staff", ""}
		}},
		{"blank group on token", func(c *Config) {
			c.Access.ServiceTokens[0].Groups = []string{""}
		}},
		{"rule without name", func(c *Config) { c.Access.Rules[0].Name = "" }},
		{"duplicate rule name", func(c *Config) { c.Access.Rules[1].Name = "public" }},
		{"bad rule action", func(c *Config) { c.Access.Rules[0].Action = "block" }},
		{"require on deny rule", func(c *Config) {
			c.Access.Rules[0].Action = "deny"
			c.Access.Rules[0].Require = &AccessRequire{Authenticated: true}
		}},
		{"bad cidr", func(c *Config) { c.Access.Rules[1].Require.SourceCIDRs = []string{"nope"} }},
		{"bad email domain", func(c *Config) { c.Access.Rules[1].Require.EmailsDomain = []string{"@example.com"} }},
	}
	for _, tc := range cases {
		cfg := good
		cfg.Access.ServiceTokens = append([]ServiceToken(nil), good.Access.ServiceTokens...)
		cfg.Access.Rules = append([]AccessRule(nil), good.Access.Rules...)
		req := *good.Access.Rules[1].Require
		cfg.Access.Rules[1].Require = &req
		tc.mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
	}

	// A configured OIDC provider unlocks the identity_provider / emails
	// clauses and resolves credentials from the environment.
	withOIDC := base()
	withOIDC.Access = AccessConfig{
		Enabled: true,
		Session: SessionConfig{Secret: "${ZTP_SESSION_SECRET_T}"},
		IdentityProviders: []IdentityProvider{{Name: "google", Type: "oidc",
			Issuer: "https://accounts.google.com", ClientID: "${ZTP_GOOG_ID}", ClientSecret: "${ZTP_GOOG_SECRET}"}},
		DefaultAction: "deny",
		Rules: []AccessRule{
			{Name: "corp", When: AccessMatch{Hosts: []string{"app.example.com"}}, Action: "allow",
				Require: &AccessRequire{IdentityProvider: "google", EmailsDomain: []string{"example.com"}}},
		},
	}
	if err := withOIDC.Validate(); err != nil {
		t.Fatalf("valid OIDC provider config rejected: %v", err)
	}
	if got := withOIDC.Access.IdentityProviders[0].ResolvedClientID(); got != "client-id" {
		t.Errorf("client_id env not resolved, got %q", got)
	}
	if got := withOIDC.Access.IdentityProviders[0].ResolvedClientSecret(); got != "client-secret" {
		t.Errorf("client_secret env not resolved, got %q", got)
	}

	// Duplicate provider names rejected.
	dup := withOIDC
	dup.Access.IdentityProviders = append([]IdentityProvider(nil), withOIDC.Access.IdentityProviders...)
	dup.Access.IdentityProviders = append(dup.Access.IdentityProviders, withOIDC.Access.IdentityProviders[0])
	if err := dup.Validate(); err == nil {
		t.Error("duplicate provider names must be rejected")
	}

	// Short secret rejected.
	t.Setenv("ZTP_SHORT", "tooshort")
	short := base()
	short.Access = AccessConfig{Enabled: true, Session: SessionConfig{Secret: "${ZTP_SHORT}"}}
	if err := short.Validate(); err == nil {
		t.Error("short session secret must be rejected")
	}

	// Disabled block is dormant — not validated.
	off := base()
	off.Access = AccessConfig{Enabled: false, ServiceTokens: []ServiceToken{{Name: "x", Hash: "garbage"}}}
	if err := off.Validate(); err != nil {
		t.Fatalf("disabled access block should not be validated: %v", err)
	}
}

// The hostile-review scenario: a misspelled require key must fail the
// load, never silently produce an empty (fail-open) predicate.
func TestStrictParsingRejectsMisspelledKeys(t *testing.T) {
	t.Setenv("ZTP_S", "0123456789abcdef0123456789abcdef")
	_, err := Parse([]byte(`
listen: {http: ":80"}
tls: {mode: none}
agents: {listen: ":8443", cert_file: c, key_file: k, ca_file: ca}
access:
  enabled: true
  session: {secret: "${ZTP_S}"}
  default_action: deny
  rules:
    - name: admin
      when: {hosts: ["admin.example.com"]}
      action: allow
      require: {group: ["admins"]}   # typo: group vs groups
`))
	if err == nil {
		t.Fatal("misspelled require key must fail the parse")
	}
	if !strings.Contains(err.Error(), "group") && !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error should name the unknown field: %v", err)
	}
}

// A stray `---` must not silently discard the rest of the config
// (e.g. an entire access policy living in the second document).
func TestParseRejectsMultipleDocuments(t *testing.T) {
	_, err := Parse([]byte(`
tls: {mode: none}
listen: {http: ":80"}
agents: {listen: ":8443", cert_file: c, key_file: k, ca_file: ca}
---
access:
  enabled: true
`))
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("expected multiple-documents rejection, got %v", err)
	}
}

func TestExpandSecretDistinguishesUnsetFromEmpty(t *testing.T) {
	t.Setenv("ZTP_EMPTY_SECRET", "")
	if _, err := ExpandSecret("${ZTP_EMPTY_SECRET}"); err == nil || !strings.Contains(err.Error(), "set but empty") {
		t.Fatalf("empty var: got %v, want 'set but empty'", err)
	}
	if _, err := ExpandSecret("${ZTP_NEVER_SET_ANYWHERE}"); err == nil || !strings.Contains(err.Error(), "is not set") {
		t.Fatalf("unset var: got %v, want 'is not set'", err)
	}
	t.Setenv("ZTP_REAL_SECRET", "value-123")
	if v, err := ExpandSecret("${ZTP_REAL_SECRET}"); err != nil || v != "value-123" {
		t.Fatalf("set var: got (%q,%v)", v, err)
	}
	if v, err := ExpandSecret("literal-inline"); err != nil || v != "literal-inline" {
		t.Fatalf("literal: got (%q,%v)", v, err)
	}
	// Partial/embedded forms are literals, not expansions.
	if v, _ := ExpandSecret("prefix-${X}-suffix"); v != "prefix-${X}-suffix" {
		t.Fatalf("embedded form must stay literal, got %q", v)
	}
}

func TestEmailOTPValidation(t *testing.T) {
	t.Setenv("ZTP_S2", "0123456789abcdef0123456789abcdef")
	t.Setenv("ZTP_BREVO_KEY", "xkeysib-test")
	base := func() Config {
		c := Defaults()
		c.TLS = TLSConfig{Mode: TLSModeNone}
		c.Listen = ListenConfig{HTTP: ":80"}
		c.Agents = AgentsConfig{Listen: ":8443", CertFile: "c", KeyFile: "k", CAFile: "ca"}
		c.Access = AccessConfig{
			Enabled: true,
			Session: SessionConfig{Secret: "${ZTP_S2}"},
			EmailOTP: EmailOTPConfig{
				Enabled: true,
				From:    "auth@example.com",
				Brevo:   &BrevoConfig{APIKey: "${ZTP_BREVO_KEY}"},
			},
			Rules: []AccessRule{
				{Name: "media", When: AccessMatch{Hosts: []string{"*.home.example.com"}}, Action: "allow",
					Require: &AccessRequire{Emails: []string{"me@example.com"}, EmailsDomain: []string{"example.com"}}},
			},
		}
		return c
	}

	good := base()
	if err := good.Validate(); err != nil {
		t.Fatalf("valid otp config rejected: %v", err)
	}
	if good.Access.EmailOTP.Brevo.ResolvedAPIKey() != "xkeysib-test" {
		t.Fatal("brevo api key must be env-expanded")
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing from", func(c *Config) { c.Access.EmailOTP.From = "" }},
		{"from without @", func(c *Config) { c.Access.EmailOTP.From = "not-an-address" }},
		{"no sender", func(c *Config) { c.Access.EmailOTP.Brevo = nil }},
		{"both senders", func(c *Config) { c.Access.EmailOTP.SMTP = &SMTPConfig{Host: "smtp.example.com"} }},
		{"smtp without host", func(c *Config) {
			c.Access.EmailOTP.Brevo = nil
			c.Access.EmailOTP.SMTP = &SMTPConfig{}
		}},
		{"brevo key env unset", func(c *Config) { c.Access.EmailOTP.Brevo = &BrevoConfig{APIKey: "${ZTP_NOPE_KEY}"} }},
		{"emails clause without any login flow", func(c *Config) { c.Access.EmailOTP.Enabled = false }},
	}
	for _, tc := range cases {
		cfg := base()
		tc.mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
	}

	// SMTP variant with env-expanded password validates.
	t.Setenv("ZTP_SMTP_PW", "hunter2-but-long")
	smtp := base()
	smtp.Access.EmailOTP.Brevo = nil
	smtp.Access.EmailOTP.SMTP = &SMTPConfig{Host: "smtp.example.com", Username: "auth", Password: "${ZTP_SMTP_PW}"}
	if err := smtp.Validate(); err != nil {
		t.Fatalf("smtp variant rejected: %v", err)
	}
	if smtp.Access.EmailOTP.SMTP.ResolvedPassword() != "hunter2-but-long" || smtp.Access.EmailOTP.SMTP.EffectivePort() != 587 {
		t.Fatal("smtp password/port resolution wrong")
	}
}
