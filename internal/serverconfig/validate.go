package serverconfig

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
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
	if err := c.Access.validate(); err != nil {
		return err
	}
	if c.Listen.HTTPS != "" && c.TLS.Mode == TLSModeNone {
		return fmt.Errorf("listen.https=%q requires tls.mode != none", c.Listen.HTTPS)
	}
	return nil
}

// tokenHashRe matches the required service-token hash form.
var tokenHashRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// envRefRe matches a whole-value environment reference: "${VAR}".
var envRefRe = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// ExpandSecret resolves a secret-bearing config value: a "${VAR}" form
// reads the environment (recommended — keeps the secret out of YAML);
// anything else is taken literally. An env reference to an unset or
// empty variable is an error, never an empty secret — the two cases
// are reported distinctly so the operator fixes the right thing.
func ExpandSecret(v string) (string, error) {
	m := envRefRe.FindStringSubmatch(v)
	if m == nil {
		return v, nil
	}
	resolved, ok := os.LookupEnv(m[1])
	if !ok {
		return "", fmt.Errorf("environment variable %s is not set", m[1])
	}
	if resolved == "" {
		return "", fmt.Errorf("environment variable %s is set but empty", m[1])
	}
	return resolved, nil
}

// validate checks the access block and resolves env-referenced secrets
// (session secret, provider credentials). A disabled block is not
// validated — dormant config is allowed, and enabling it is
// restart-only so the validation runs before it ever takes effect.
func (a *AccessConfig) validate() error {
	if !a.Enabled {
		return nil
	}

	switch a.DefaultAction {
	case "", "allow", "deny":
	default:
		return fmt.Errorf("access.default_action=%q: must be allow|deny", a.DefaultAction)
	}

	// Session secret: required whenever the layer is enabled — the
	// cookie path must never run unsigned.
	if a.Session.Secret == "" {
		return fmt.Errorf("access.session.secret required when access is enabled (inline or \"${VAR}\")")
	}
	secret, err := ExpandSecret(a.Session.Secret)
	if err != nil {
		return fmt.Errorf("access.session.secret: %w", err)
	}
	if len(secret) < 32 {
		return fmt.Errorf("access.session.secret must be at least 32 bytes (got %d)", len(secret))
	}
	a.Session.secret = []byte(secret)

	tokenNames := make(map[string]bool, len(a.ServiceTokens))
	for i, t := range a.ServiceTokens {
		where := fmt.Sprintf("access.service_tokens[%d]", i)
		if t.Name == "" {
			return fmt.Errorf("%s: name required", where)
		}
		if tokenNames[t.Name] {
			return fmt.Errorf("%s: duplicate token name %q", where, t.Name)
		}
		tokenNames[t.Name] = true
		if !tokenHashRe.MatchString(t.Hash) {
			return fmt.Errorf("%s (%s): hash must be \"sha256:<64 lowercase hex>\"", where, t.Name)
		}
		for _, g := range t.Groups {
			if g == "" {
				return fmt.Errorf("%s (%s): empty group name", where, t.Name)
			}
		}
	}

	// The OIDC login flow is not implemented yet. Accepting a provider
	// block now would validate credentials for a capability that does
	// nothing — the exact silently-dead-config failure this project
	// refuses to ship. Rejected until the flow lands.
	if len(a.IdentityProviders) > 0 {
		return fmt.Errorf("access.identity_providers: OIDC login is not implemented yet; remove the block (it ships in a later release)")
	}

	if a.EmailOTP.Enabled {
		if err := a.EmailOTP.validate(); err != nil {
			return err
		}
	}

	ruleNames := make(map[string]bool, len(a.Rules))
	for i, r := range a.Rules {
		where := fmt.Sprintf("access.rules[%d]", i)
		if r.Name == "" {
			return fmt.Errorf("%s: name required (labels metrics and logs)", where)
		}
		if ruleNames[r.Name] {
			return fmt.Errorf("%s: duplicate rule name %q", where, r.Name)
		}
		ruleNames[r.Name] = true
		if r.Action != "allow" && r.Action != "deny" {
			return fmt.Errorf("%s (%s): action must be allow|deny, got %q", where, r.Name, r.Action)
		}
		for _, h := range r.When.Hosts {
			if h == "" {
				return fmt.Errorf("%s (%s): empty host pattern", where, r.Name)
			}
		}
		for _, p := range r.When.Paths {
			if p == "" {
				return fmt.Errorf("%s (%s): empty path pattern", where, r.Name)
			}
		}
		if r.Require != nil {
			if r.Action == "deny" {
				return fmt.Errorf("%s (%s): require is meaningless on a deny rule", where, r.Name)
			}
			// An empty require block (or one whose only keys were
			// misspelled and rejected by strict parsing elsewhere) would
			// evaluate as "no requirement" — fail-open. Refuse it.
			if !r.Require.Authenticated && len(r.Require.Groups) == 0 && len(r.Require.Emails) == 0 &&
				len(r.Require.EmailsDomain) == 0 && r.Require.IdentityProvider == "" && len(r.Require.SourceCIDRs) == 0 {
				return fmt.Errorf("%s (%s): require must specify at least one clause (authenticated, groups, emails, emails_domain, identity_provider, source_cidrs) — an empty require would allow everyone", where, r.Name)
			}
			if r.Require.IdentityProvider != "" {
				return fmt.Errorf("%s (%s): require.identity_provider needs OIDC login, which is not implemented yet", where, r.Name)
			}
			// emails / emails_domain need a login flow that populates
			// Identity.Email. Email OTP provides one; without it (and
			// with OIDC still unimplemented) the clauses would be
			// permanently unsatisfiable — dead config, rejected.
			if (len(r.Require.Emails) > 0 || len(r.Require.EmailsDomain) > 0) && !a.EmailOTP.Enabled {
				return fmt.Errorf("%s (%s): require.emails / require.emails_domain need a login flow — enable access.email_otp (or wait for OIDC)", where, r.Name)
			}
			for _, g := range r.Require.Groups {
				if g == "" {
					return fmt.Errorf("%s (%s): empty group in require.groups", where, r.Name)
				}
			}
			for _, e := range r.Require.Emails {
				if e == "" || !strings.Contains(e, "@") {
					return fmt.Errorf("%s (%s): invalid email %q in require.emails", where, r.Name, e)
				}
			}
			for _, c := range r.Require.SourceCIDRs {
				if _, _, err := net.ParseCIDR(c); err != nil {
					return fmt.Errorf("%s (%s): invalid CIDR %q", where, r.Name, c)
				}
			}
			for _, d := range r.Require.EmailsDomain {
				if d == "" || strings.ContainsAny(d, "@ ") {
					return fmt.Errorf("%s (%s): invalid email domain %q", where, r.Name, d)
				}
			}
		}
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

	switch a.Identity.BindTo {
	case "", "none", "cn", "san":
	default:
		return fmt.Errorf("agents.identity.bind_to=%q: must be cn|san|none", a.Identity.BindTo)
	}

	seen := make(map[string]bool, len(a.ACL.Agents))
	for i, entry := range a.ACL.Agents {
		where := fmt.Sprintf("agents.acl.agents[%d]", i)
		if entry.ID == "" {
			return fmt.Errorf("%s: id required", where)
		}
		if seen[entry.ID] {
			return fmt.Errorf("%s: duplicate agent id %q", where, entry.ID)
		}
		seen[entry.ID] = true
		if len(entry.AllowedHosts) == 0 {
			return fmt.Errorf("%s (%s): allowed_hosts must list at least one pattern", where, entry.ID)
		}
		for _, pattern := range entry.AllowedHosts {
			if err := validateHostPattern(pattern); err != nil {
				return fmt.Errorf("%s (%s): %w", where, entry.ID, err)
			}
		}
	}
	// allow_unlisted:false with an empty agents list means no agent can
	// ever connect — deliberately NOT a validation error (it may be an
	// intentional lockdown); ztagents logs a warning at startup instead.

	for _, serial := range a.Revocation.DeniedSerials {
		if serial == "" || !isHex(serial) {
			return fmt.Errorf("agents.revocation.denied_serials: %q is not valid hex", serial)
		}
	}
	if a.Revocation.CRLFile != "" {
		if _, err := LoadCRLSerials(a.Revocation.CRLFile); err != nil {
			return fmt.Errorf("agents.revocation.crl_file: %w", err)
		}
	}
	return nil
}

// validate checks the email-OTP block (only called when enabled) and
// resolves env-referenced sender credentials.
func (e *EmailOTPConfig) validate() error {
	if e.From == "" || !strings.Contains(e.From, "@") || strings.ContainsAny(e.From, "\r\n") {
		// CR/LF would inject extra headers into every OTP mail
		// (buildMailMessage writes "From: %s\r\n" unencoded).
		return fmt.Errorf("access.email_otp.from: a valid sender address is required")
	}
	if e.CodeTTL < 0 {
		return fmt.Errorf("access.email_otp.code_ttl must be >= 0")
	}
	switch {
	case e.SMTP == nil && e.Brevo == nil:
		return fmt.Errorf("access.email_otp: configure exactly one sender (smtp or brevo)")
	case e.SMTP != nil && e.Brevo != nil:
		return fmt.Errorf("access.email_otp: smtp and brevo are mutually exclusive")
	case e.SMTP != nil:
		if e.SMTP.Host == "" {
			return fmt.Errorf("access.email_otp.smtp.host required")
		}
		if e.SMTP.Password != "" {
			pw, err := ExpandSecret(e.SMTP.Password)
			if err != nil {
				return fmt.Errorf("access.email_otp.smtp.password: %w", err)
			}
			e.SMTP.password = pw
		}
	default: // brevo
		if e.Brevo.APIKey == "" {
			return fmt.Errorf("access.email_otp.brevo.api_key required")
		}
		key, err := ExpandSecret(e.Brevo.APIKey)
		if err != nil {
			return fmt.Errorf("access.email_otp.brevo.api_key: %w", err)
		}
		e.Brevo.apiKey = key
	}
	return nil
}

// validateHostPattern checks a label-aware ACL glob: dot-separated
// labels, each either "*" or a plain DNS label.
func validateHostPattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("empty host pattern")
	}
	for _, label := range strings.Split(pattern, ".") {
		if label == "*" {
			continue
		}
		if label == "" {
			return fmt.Errorf("invalid host pattern %q: empty label", pattern)
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				return fmt.Errorf("invalid host pattern %q: label %q contains %q", pattern, label, string(r))
			}
		}
	}
	return nil
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// LoadCRLSerials reads a PEM- or DER-encoded CRL and returns the
// revoked serial numbers in lowercase hex. Used both by validation and
// by the ztagents revocation set (including on SIGHUP re-read).
func LoadCRLSerials(path string) ([]string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from operator config, not user input
	if err != nil {
		return nil, fmt.Errorf("read CRL: %w", err)
	}
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}
	serials := make([]string, 0, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		serials = append(serials, strings.ToLower(entry.SerialNumber.Text(16)))
	}
	return serials, nil
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
