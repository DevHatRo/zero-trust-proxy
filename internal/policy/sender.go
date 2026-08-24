package policy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// newCodeSender builds the configured sender. Validation guarantees
// exactly one of smtp/brevo is set.
func newCodeSender(cfg serverconfig.EmailOTPConfig) CodeSender {
	if cfg.SMTP != nil {
		return &smtpSender{
			host:          cfg.SMTP.Host,
			port:          cfg.SMTP.EffectivePort(),
			username:      cfg.SMTP.Username,
			password:      cfg.SMTP.ResolvedPassword(),
			from:          cfg.From,
			subject:       cfg.EffectiveSubject(),
			ttl:           cfg.EffectiveCodeTTL(),
			allowInsecure: cfg.SMTP.AllowInsecure,
		}
	}
	return &brevoSender{
		apiKey:   cfg.Brevo.ResolvedAPIKey(),
		from:     cfg.From,
		subject:  cfg.EffectiveSubject(),
		ttl:      cfg.EffectiveCodeTTL(),
		endpoint: brevoEndpoint,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// --- SMTP --------------------------------------------------------------

// smtpSender delivers over SMTP submission (STARTTLS when the server
// offers it — net/smtp upgrades automatically before AUTH).
type smtpSender struct {
	host, username, password, from, subject string
	port                                    int
	ttl                                     time.Duration
	// allowInsecure permits delivery to a server that does not offer
	// STARTTLS. Default false: the code would otherwise cross the network
	// in cleartext, and net/smtp's PlainAuth cleartext guard does not
	// apply when no username is configured.
	allowInsecure bool
}

func (s *smtpSender) SendCode(ctx context.Context, to, code string) error {
	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))

	// Dial through the context so a blackholed or dead mail server can no
	// longer pin the request goroutine for the OS connect timeout — the
	// caller's otpSendTimeout bounds the whole exchange. net/smtp's
	// SendMail offers no such control, so drive the client by hand.
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		// Bounds every subsequent read/write, not just the dial.
		_ = conn.SetDeadline(deadline)
	}

	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = c.Close() }()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	} else if !s.allowInsecure {
		// No STARTTLS and no opt-out: refuse rather than send the code
		// (and any credentials) in cleartext.
		return fmt.Errorf("smtp: server %s does not offer STARTTLS; set access.email_otp.smtp.allow_insecure to permit cleartext delivery", s.host)
	}
	if s.username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.username, s.password, s.host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(s.from); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := wc.Write(buildMailMessage(s.from, to, s.subject, otpMessageBody(code, s.ttl))); err != nil {
		_ = wc.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp data close: %w", err)
	}
	return c.Quit()
}

// buildMailMessage renders a minimal RFC 5322 message. The recipient
// address is validated upstream (single addr-spec, no CR/LF) so header
// injection via To is not possible; Subject is operator-configured and
// encoded defensively anyway.
func buildMailMessage(from, to, subject, body string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	// RFC 5322 §3.6 mandates a Date; a Message-ID is strongly advised.
	// Absent either, many MTAs and spam filters penalise or reject the
	// mail — silent OTP delivery failures in production.
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: %s\r\n", messageID(from))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return b.Bytes()
}

// messageID builds a unique RFC 5322 Message-ID scoped to the sender's
// domain.
func messageID(from string) string {
	domain := "localhost"
	if i := strings.LastIndexByte(from, '@'); i >= 0 && i+1 < len(from) {
		domain = from[i+1:]
	}
	var r [16]byte
	if _, err := rand.Read(r[:]); err != nil {
		// Uniqueness is best-effort; a coarse ID beats none.
		return fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), domain)
	}
	return fmt.Sprintf("<%s@%s>", hex.EncodeToString(r[:]), domain)
}

// --- Brevo -------------------------------------------------------------

const brevoEndpoint = "https://api.brevo.com/v3/smtp/email"

// brevoSender delivers through the Brevo (Sendinblue) transactional
// email API.
type brevoSender struct {
	apiKey, from, subject, endpoint string
	ttl                             time.Duration
	client                          *http.Client
}

type brevoPayload struct {
	Sender      brevoAddr   `json:"sender"`
	To          []brevoAddr `json:"to"`
	Subject     string      `json:"subject"`
	TextContent string      `json:"textContent"`
}

type brevoAddr struct {
	Email string `json:"email"`
}

func (b *brevoSender) SendCode(ctx context.Context, to, code string) error {
	payload, err := json.Marshal(brevoPayload{
		Sender:      brevoAddr{Email: b.from},
		To:          []brevoAddr{{Email: to}},
		Subject:     b.subject,
		TextContent: otpMessageBody(code, b.ttl),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("api-key", b.apiKey)

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("brevo send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read a bounded slice of the body for the log; never the key.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("brevo send: status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}
