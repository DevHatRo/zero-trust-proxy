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
	e.renderChooser(w, hostOnly(r.Host), sanitizeReturnPath(r.URL.Query().Get("rd")), "")
}

// renderChooser renders the login chooser (provider buttons and/or the
// email form). Whenever the email form is shown it provisions a fresh
// OTP transaction — cookie + mirrored csrf token — so the form is always
// submittable, including on the OIDC-failure fallback paths. An empty
// errMsg renders a 200; a non-empty one renders the same page as a 400.
func (e *Engine) renderChooser(w http.ResponseWriter, host, rd, errMsg string) {
	v := loginView{Step: "email", Return: rd, Host: host, OTP: e.otp != nil, Providers: e.providerLinks(rd), Error: errMsg}
	if e.otp != nil {
		token, err := newLoginToken()
		if err != nil {
			log.Error("access: login token: %v", err)
			writeStatus(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		setLoginTxn(w, token)
		v.CSRF = token
	}
	renderLoginPage(w, v)
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
		renderLoginPage(w, loginView{Step: "email", Return: rd, Host: hostOnly(r.Host), CSRF: token, Error: "Enter a valid email address."})
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
	renderLoginPage(w, loginView{Step: "code", Return: rd, Host: hostOnly(r.Host), Email: email, CSRF: token})
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
		renderLoginPage(w, loginView{Step: "code", Return: rd, Host: hostOnly(r.Host), Email: email, CSRF: token,
			Error: "Enter the code we emailed you."})
		return
	}
	if !e.otp.store.verify(email, code) {
		if e.hooks.OTPFailed != nil {
			e.hooks.OTPFailed()
		}
		renderLoginPage(w, loginView{Step: "code", Return: rd, Host: hostOnly(r.Host), Email: email, CSRF: token,
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
	Step      string // "email" | "code"
	Email     string
	Return    string
	Error     string
	Host      string         // the protected host, shown as context
	Brand     string         // footer label (set by renderLoginPage)
	CSRF      string         // transaction token, mirrored into the form
	OTP       bool           // show the email one-time-code form
	Providers []providerLink // OIDC sign-in buttons
}

// providerLink is one OIDC sign-in button.
type providerLink struct {
	Name  string // config name, used in the URL
	Label string // display label
	Icon  string // "google" | "sso"
	URL   string
}

func renderLoginPage(w http.ResponseWriter, v loginView) {
	v.Brand = loginBrand
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if v.Error != "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	if err := loginTmpl.Execute(w, v); err != nil {
		log.Error("access: render login page: %v", err)
	}
}

// loginBrand labels the footer; change it to your product/org name.
const loginBrand = "zero-trust-proxy"

// loginTmpl is fully self-contained (no external assets — CSP-safe and
// works while the backend is unreachable). html/template escapes every
// interpolated value; Email, Return, and Host are attacker-influenced.
var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#4f46e5">
<title>Sign in</title>
<style>
  :root{
    --bg:#eef1f6; --bg2:#f7f9fc; --card:#ffffff; --border:#e5e8ee;
    --shadow:0 18px 48px rgba(16,24,40,.12), 0 2px 6px rgba(16,24,40,.06);
    --fg:#101828; --muted:#667085; --field:#ffffff; --field-border:#d3d8e0;
    --accent:#4f46e5; --accent-fg:#ffffff; --accent-hover:#4338ca;
    --ring:rgba(79,70,229,.30);
    --err:#b42318; --err-bg:#fef3f2; --err-border:#fecdca;
  }
  @media (prefers-color-scheme: dark){
    :root{
      --bg:#0b0d11; --bg2:#12151b; --card:#161a21; --border:#252b35;
      --shadow:0 18px 48px rgba(0,0,0,.5);
      --fg:#e8eaef; --muted:#98a1b0; --field:#0f1216; --field-border:#2b323d;
      --accent:#6366f1; --accent-fg:#ffffff; --accent-hover:#7c7ff5;
      --ring:rgba(99,102,241,.40);
      --err:#f97066; --err-bg:#2a1512; --err-border:#5b241f;
    }
  }
  *{box-sizing:border-box}
  html,body{height:100%}
  body{margin:0; color:var(--fg); background:radial-gradient(1200px 600px at 50% -10%, var(--bg2), var(--bg));
    font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    display:flex; align-items:center; justify-content:center; padding:24px;}
  .card{width:100%; max-width:400px; background:var(--card); border:1px solid var(--border);
    border-radius:18px; box-shadow:var(--shadow); padding:32px 30px;}
  .mark{width:46px; height:46px; border-radius:13px; display:flex; align-items:center; justify-content:center;
    color:var(--accent-fg); background:linear-gradient(135deg,var(--accent),color-mix(in srgb,var(--accent) 65%, #000));
    margin:0 auto 16px;}
  h1{font-size:20px; font-weight:650; letter-spacing:-.01em; text-align:center; margin:0 0 4px;}
  .sub{text-align:center; color:var(--muted); font-size:14px; margin:0 0 22px;}
  .sub b{color:var(--fg); font-weight:600;}
  label{display:block; font-size:13px; font-weight:600; color:var(--fg); margin:0 0 6px;}
  input{width:100%; font:inherit; font-size:15px; padding:11px 13px; color:var(--fg);
    background:var(--field); border:1px solid var(--field-border); border-radius:10px; outline:none;
    transition:border-color .15s, box-shadow .15s;}
  input:focus{border-color:var(--accent); box-shadow:0 0 0 4px var(--ring);}
  .code{text-align:center; font-size:24px; letter-spacing:.5em; padding-left:.5em;
    font-variant-numeric:tabular-nums; font-weight:600;}
  button{width:100%; margin-top:14px; padding:11px 14px; font:inherit; font-size:15px; font-weight:650;
    color:var(--accent-fg); background:var(--accent); border:0; border-radius:10px; cursor:pointer;
    transition:background .15s;}
  button:hover{background:var(--accent-hover);}
  .provider{display:flex; align-items:center; justify-content:center; gap:10px; width:100%;
    padding:11px 14px; margin-bottom:10px; font-size:15px; font-weight:600; text-decoration:none;
    color:var(--fg); background:var(--field); border:1px solid var(--field-border); border-radius:10px;
    transition:border-color .15s, background .15s;}
  .provider:hover{border-color:var(--accent);}
  .provider svg{flex:0 0 auto;}
  .divider{display:flex; align-items:center; gap:12px; color:var(--muted); font-size:12px;
    text-transform:uppercase; letter-spacing:.08em; margin:18px 0;}
  .divider::before,.divider::after{content:""; height:1px; flex:1; background:var(--border);}
  .err{display:flex; gap:8px; align-items:flex-start; color:var(--err); background:var(--err-bg);
    border:1px solid var(--err-border); border-radius:10px; padding:10px 12px; font-size:13.5px; margin:0 0 16px;}
  .foot{text-align:center; color:var(--muted); font-size:12px; margin:20px 0 0;}
  .alt{text-align:center; margin:14px 0 0; font-size:13px;}
  a.link{color:var(--accent); text-decoration:none;}
  a.link:hover{text-decoration:underline;}
</style>
</head>
<body>
  <main class="card">
    <div class="mark" aria-hidden="true">
      <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
    </div>
  {{if eq .Step "email"}}
    <h1>Sign in</h1>
    <p class="sub">{{if .Host}}to continue to <b>{{.Host}}</b>{{else}}to continue{{end}}</p>
    {{if .Error}}<div class="err"><span aria-hidden="true">&#9888;</span><span>{{.Error}}</span></div>{{end}}
    {{range .Providers}}
      <a class="provider" href="{{.URL}}">
        {{if eq .Icon "google"}}<svg viewBox="0 0 18 18" width="18" height="18" aria-hidden="true"><path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.92c1.71-1.57 2.68-3.89 2.68-6.62z"/><path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.81.54-1.85.86-3.04.86-2.34 0-4.32-1.58-5.03-3.7H.96v2.33A9 9 0 0 0 9 18z"/><path fill="#FBBC05" d="M3.97 10.72a5.4 5.4 0 0 1 0-3.44V4.95H.96a9 9 0 0 0 0 8.1l3.01-2.33z"/><path fill="#EA4335" d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.58C13.47.9 11.43 0 9 0A9 9 0 0 0 .96 4.95L3.97 7.28C4.68 5.16 6.66 3.58 9 3.58z"/></svg>{{else}}<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>{{end}}
        <span>Continue with {{.Label}}</span>
      </a>
    {{end}}
    {{if and .Providers .OTP}}<div class="divider">or</div>{{end}}
    {{if .OTP}}
    <form method="post" action="/.ztp/otp/request">
      <input type="hidden" name="rd" value="{{.Return}}">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <label for="email">Email address</label>
      <input id="email" type="email" name="email" placeholder="you@example.com" required autofocus autocomplete="email" spellcheck="false">
      <button type="submit">Email me a code</button>
    </form>
    {{end}}
  {{else}}
    <h1>Check your email</h1>
    <p class="sub">Enter the code we sent to <b>{{.Email}}</b>.</p>
    {{if .Error}}<div class="err"><span aria-hidden="true">&#9888;</span><span>{{.Error}}</span></div>{{end}}
    <form method="post" action="/.ztp/otp/verify">
      <input type="hidden" name="rd" value="{{.Return}}">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <input type="hidden" name="email" value="{{.Email}}">
      <label for="code">Verification code</label>
      <input id="code" class="code" type="text" name="code" placeholder="000000" required autofocus inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxlength="6">
      <button type="submit">Sign in</button>
    </form>
    <p class="alt"><a class="link" href="/.ztp/login?rd={{.Return}}">Use a different email</a></p>
  {{end}}
    <p class="foot">Secured by {{.Brand}}</p>
  </main>
</body>
</html>`))

// loginRedirectURL builds the /.ztp/login URL preserving the original
// destination.
func loginRedirectURL(r *http.Request) string {
	return fmt.Sprintf("/.ztp/login?rd=%s", url.QueryEscape(r.URL.RequestURI()))
}
