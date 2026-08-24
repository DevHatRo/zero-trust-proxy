package policy

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

// Browser login flow for email OTP, under the proxy-owned /.ztp/
// namespace:
//
//	GET  /.ztp/login          email form (rd = sanitized return path)
//	POST /.ztp/otp/request    issue + deliver a code (if eligible)
//	POST /.ztp/otp/verify     exchange code for a session cookie
//
// The response to a request is identical whether or not the address is
// eligible or rate-limited — no account enumeration and no send-rate
// oracle. Only eligible addresses actually cause mail to be sent.
//
// GET /.ztp/login mints a per-browser transaction token, dropped as a
// SameSite=Strict cookie and echoed in a hidden form field; both POSTs
// require the two to match. A cross-site form cannot carry the Strict
// cookie, so it cannot verify a code into a victim's browser (login
// CSRF / session fixation).

const (
	loginTxnCookie = "ztp_login_txn"
	loginTxnTTL    = 15 * time.Minute
)

// newLoginToken returns a fresh random transaction token.
func newLoginToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// setLoginTxn drops the transaction cookie: Strict so it never rides a
// cross-site request, HttpOnly, scoped to the /.ztp/ namespace.
func setLoginTxn(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginTxnCookie,
		Value:    token,
		Path:     ZTPPrefix,
		MaxAge:   int(loginTxnTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// validLoginTxn reports whether the request carries a transaction cookie
// whose value matches the posted csrf field (constant-time).
func validLoginTxn(r *http.Request) bool {
	c, err := r.Cookie(loginTxnCookie)
	if err != nil || c.Value == "" {
		return false
	}
	posted := r.PostFormValue("csrf")
	if posted == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(posted)) == 1
}

// sanitizeReturnPath restricts the post-login redirect to a local
// path: no absolute URLs, no scheme-relative ("//host") forms, no
// backslash tricks — open-redirect prevention.
func sanitizeReturnPath(rd string) string {
	if rd == "" || !strings.HasPrefix(rd, "/") ||
		strings.HasPrefix(rd, "//") || strings.ContainsAny(rd, "\\\r\n") {
		return "/"
	}
	return rd
}

// validEmail parses a single addr-spec. Rejects anything net/mail
// cannot parse as one address (also excludes CR/LF, so the value is
// safe in mail headers).
func validEmail(s string) (string, bool) {
	if len(s) > 254 || strings.ContainsAny(s, "\r\n") {
		return "", false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s {
		return "", false
	}
	return strings.ToLower(s), true
}

// emailEligible reports whether mailing a code to this address could
// actually let the caller in — the gate on sending mail. It evaluates
// the real predicate (compiledRequire.satisfies) against the exact
// identity a successful login would mint (see handleOTPVerify) and the
// current request's source IP, so AND-ed clauses like source_cidrs or
// groups that this login can never satisfy correctly suppress the mail.
//
// Eligibility additionally requires an explicit email clause: a rule
// that merely says `authenticated: true` would otherwise turn the proxy
// into an open mail relay to any address. Only addresses an allow-list
// (emails) or allowed domain (emails_domain) names are ever mailed.
func (s *snapshot) emailEligible(email string, srcIP net.IP) bool {
	id := &Identity{Source: SourceSession, Subject: email, Email: email, Provider: "email_otp"}
	for i := range s.rules {
		r := &s.rules[i]
		if !r.allow || r.require == nil {
			continue
		}
		if len(r.require.emails) == 0 && len(r.require.emailDomains) == 0 {
			continue
		}
		if r.require.satisfies(id, srcIP) {
			return true
		}
	}
	return false
}

// handleLogin renders the email form and starts a transaction: a fresh
// token in a Strict cookie, mirrored into the form for double-submit.
// GET only — a forced cross-site POST must not be able to rotate (and
// so invalidate) an in-progress login's transaction cookie.
func (e *Engine) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeStatus(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}
	rd := sanitizeReturnPath(r.URL.Query().Get("rd"))
	token, err := newLoginToken()
	if err != nil {
		log.Error("access: login token: %v", err)
		writeStatus(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	setLoginTxn(w, token)
	renderLoginPage(w, loginView{Step: "email", Return: rd, CSRF: token})
}

// restartLogin bounces a POST whose transaction cookie is missing,
// expired, or forged back to a fresh /.ztp/login — no code is issued or
// verified without a browser-bound transaction. rd is preserved.
func restartLogin(w http.ResponseWriter, r *http.Request, rd string) {
	http.Redirect(w, r, "/.ztp/login?rd="+url.QueryEscape(rd), http.StatusSeeOther)
}

// handleOTPRequest issues and delivers a code.
func (e *Engine) handleOTPRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeStatus(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}
	rd := sanitizeReturnPath(r.PostFormValue("rd"))
	if !validLoginTxn(r) {
		restartLogin(w, r, rd)
		return
	}
	token := r.PostFormValue("csrf") // validated above; carried to the code form
	email, ok := validEmail(strings.TrimSpace(r.PostFormValue("email")))
	if !ok {
		renderLoginPage(w, loginView{Step: "email", Return: rd, CSRF: token, Error: "Enter a valid email address."})
		return
	}

	// Eligibility and rate limits are checked silently: the code-entry
	// page renders identically either way, and delivery is dispatched
	// off this goroutine so response time never depends on eligibility.
	if e.snap.Load().emailEligible(email, remoteIP(r)) {
		e.otp.issueAndDeliver(email, e.hooks.OTPSent)
	} else {
		log.Debug("access: otp requested for ineligible address %s", redactEmail(email))
	}
	renderLoginPage(w, loginView{Step: "code", Return: rd, Email: email, CSRF: token})
}

// handleOTPVerify exchanges a code for a session.
func (e *Engine) handleOTPVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeStatus(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}
	rd := sanitizeReturnPath(r.PostFormValue("rd"))
	if !validLoginTxn(r) {
		// Missing/forged transaction: never mint a session — this is the
		// cross-site verification path. Restart cleanly.
		restartLogin(w, r, rd)
		return
	}
	token := r.PostFormValue("csrf")
	email, okEmail := validEmail(strings.TrimSpace(r.PostFormValue("email")))
	code := strings.TrimSpace(r.PostFormValue("code"))

	// A malformed form (unparseable email, empty code) is not a
	// verification attempt: re-render without touching OTPFailed, which
	// tracks genuine wrong-code submissions for brute-force detection.
	if !okEmail || code == "" {
		renderLoginPage(w, loginView{Step: "code", Return: rd, Email: email, CSRF: token,
			Error: "Enter the code we emailed you."})
		return
	}
	if !e.otp.store.verify(email, code) {
		if e.hooks.OTPFailed != nil {
			e.hooks.OTPFailed()
		}
		renderLoginPage(w, loginView{Step: "code", Return: rd, Email: email, CSRF: token,
			Error: "That code is not valid or has expired. Request a new one if needed."})
		return
	}

	sessionToken, err := e.session.Mint(&Identity{
		Source:   SourceSession,
		Subject:  email,
		Email:    email,
		Provider: "email_otp",
	})
	if err != nil {
		log.Error("access: mint session: %v", err)
		writeStatus(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	e.session.SetCookie(w, sessionToken)
	// Retire the transaction so its token cannot be replayed.
	http.SetCookie(w, &http.Cookie{Name: loginTxnCookie, Value: "", Path: ZTPPrefix,
		MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	if e.hooks.OTPVerified != nil {
		e.hooks.OTPVerified()
	}
	log.Info("access: email_otp login for %s", email)
	// Not an open redirect: rd went through sanitizeReturnPath above —
	// local absolute paths only, no scheme/host, no "//", no CR/LF
	// (covered by TestSanitizeReturnPath).
	http.Redirect(w, r, rd, http.StatusSeeOther) // #nosec G710
}

// loginView feeds the two-step login template.
type loginView struct {
	Step   string // "email" | "code"
	Email  string
	Return string
	Error  string
	CSRF   string // transaction token, mirrored into the form
}

func renderLoginPage(w http.ResponseWriter, v loginView) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if v.Error != "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	if err := loginTmpl.Execute(w, v); err != nil {
		log.Error("access: render login page: %v", err)
	}
}

// loginTmpl is fully self-contained; html/template escapes all
// interpolated values (Email and Return are attacker-influenced).
var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Sign in</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #1d2430; background: #f5f6f8; }
  @media (prefers-color-scheme: dark) {
    body { background: #16181d; color: #e6e8eb; }
    .card { background: #1e2127; border-color: #2c313a; }
    input { background: #14171b; color: #e6e8eb; border-color: #2c313a; }
  }
  .card { background: #fff; border: 1px solid #e3e6ea; border-radius: 12px; padding: 32px; width: 22em; max-width: 90vw; }
  h1 { font-size: 20px; margin: 0 0 6px; }
  p { margin: 0 0 16px; color: #6b7280; font-size: 14px; }
  input { width: 100%; box-sizing: border-box; font-size: 16px; padding: 10px 12px; margin-bottom: 12px;
    border: 1px solid #d3d8de; border-radius: 8px; }
  button { width: 100%; padding: 10px; font-size: 15px; font-weight: 600; color: #fff;
    background: #2563eb; border: 0; border-radius: 8px; cursor: pointer; }
  .err { color: #dc2626; font-size: 14px; margin-bottom: 12px; }
</style>
</head>
<body>
  <div class="card">
  {{if eq .Step "email"}}
    <h1>Sign in</h1>
    <p>Enter your email address and we&#39;ll send you a one-time code.</p>
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
    <form method="post" action="/.ztp/otp/request">
      <input type="hidden" name="rd" value="{{.Return}}">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <input type="email" name="email" placeholder="you@example.com" required autofocus autocomplete="email">
      <button type="submit">Send code</button>
    </form>
  {{else}}
    <h1>Check your email</h1>
    <p>If <strong>{{.Email}}</strong> is authorized, a sign-in code is on its way. Enter it below.</p>
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
    <form method="post" action="/.ztp/otp/verify">
      <input type="hidden" name="rd" value="{{.Return}}">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <input type="hidden" name="email" value="{{.Email}}">
      <input type="text" name="code" placeholder="123456" required autofocus inputmode="numeric" autocomplete="one-time-code" maxlength="6">
      <button type="submit">Sign in</button>
    </form>
  {{end}}
  </div>
</body>
</html>`))

// loginRedirectURL builds the /.ztp/login URL preserving the original
// destination.
func loginRedirectURL(r *http.Request) string {
	return fmt.Sprintf("/.ztp/login?rd=%s", url.QueryEscape(r.URL.RequestURI()))
}
