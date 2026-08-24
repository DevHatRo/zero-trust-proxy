package policy

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/security"
)

// ZTPPrefix is the proxy-owned path namespace. Requests under it are
// handled by this middleware (login callback, logout) and must never
// be dispatched to an agent — the router carries a defence-in-depth
// guard for the disabled case.
const ZTPPrefix = "/.ztp/"

// Wrap returns the access-policy middleware. It owns /.ztp/*, resolves
// the caller's identity, evaluates the rule set, and either forwards,
// denies, or demands authentication.
func (e *Engine) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One normalized path for everything: the /.ztp/ ownership check
		// and rule matching must see the same dot-segment-collapsed form
		// that upstreams would resolve — "/foo/../.ztp/logout" IS the
		// reserved namespace, and "/x/../admin" IS /admin.
		path := security.CleanPath(r.URL.Path)

		if path == "/.ztp" || strings.HasPrefix(path, ZTPPrefix) {
			e.serveZTP(w, r, path)
			return
		}

		snap := e.snap.Load()
		id, cred := e.resolveIdentity(r, snap)

		host := hostOnly(r.Host)
		// Method uppercased: rule keys are normalized at compile time and
		// Go's request parser accepts any-token, any-case methods — a
		// lowercase "post" must not slip past a methods-scoped rule.
		verdict := snap.evaluate(host, path, strings.ToUpper(r.Method), remoteIP(r), id)

		switch verdict.Decision {
		case Allow:
			if e.hooks.Allowed != nil {
				e.hooks.Allowed(verdict.Rule)
			}
			if ri := common.RequestInfoFrom(r.Context()); ri != nil && id != nil {
				ri.Identity = id.Subject
				ri.IdentitySource = id.Source
			}
			// The credential that authenticated to the PROXY must not be
			// forwarded to the backend, where it could be captured and
			// replayed against the proxy. Only the consumed credential is
			// stripped — an unrecognized Authorization header may be the
			// backend's own auth and passes through untouched.
			stripConsumedCredential(r, cred, e.session.CookieName())
			next.ServeHTTP(w, r)

		case RequireAuth:
			if e.hooks.AuthRequired != nil {
				e.hooks.AuthRequired()
			}
			e.requireAuth(w, r)

		default: // Deny
			if e.hooks.Denied != nil {
				e.hooks.Denied(verdict.Rule)
			}
			log.Warn("access: deny host=%s path=%s rule=%q subject=%q src=%s",
				host, path, verdict.Rule, subjectOf(id), r.RemoteAddr)
			writeStatus(w, http.StatusForbidden, "Forbidden")
		}
	})
}

// serveZTP handles the reserved namespace (path is pre-normalized by
// the caller). The OIDC callback lands here in a later increment;
// unknown subpaths are 404 so nothing under /.ztp/ can ever fall
// through to a backend.
func (e *Engine) serveZTP(w http.ResponseWriter, r *http.Request, path string) {
	switch path {
	case ZTPPrefix + "logout":
		e.session.ClearCookie(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	case ZTPPrefix + "login":
		if e.otp == nil {
			writeStatus(w, http.StatusNotFound, "Not Found")
			return
		}
		e.handleLogin(w, r)
	case ZTPPrefix + "otp/request":
		if e.otp == nil {
			writeStatus(w, http.StatusNotFound, "Not Found")
			return
		}
		e.handleOTPRequest(w, r)
	case ZTPPrefix + "otp/verify":
		if e.otp == nil {
			writeStatus(w, http.StatusNotFound, "Not Found")
			return
		}
		e.handleOTPVerify(w, r)
	default:
		writeStatus(w, http.StatusNotFound, "Not Found")
	}
}

// credential records which request credential resolved the identity,
// so exactly that one can be stripped before proxying.
type credential int

const (
	credNone credential = iota
	credSessionCookie
	credAuthorization
	credXZTPToken
)

// resolveIdentity resolves the caller, first hit wins: valid session
// cookie, then bearer/service token, else anonymous. An invalid cookie
// or unknown token silently resolves to anonymous — the policy
// decision, not the resolution step, produces the client-visible
// outcome.
func (e *Engine) resolveIdentity(r *http.Request, snap *snapshot) (*Identity, credential) {
	if c, err := r.Cookie(e.session.CookieName()); err == nil && c.Value != "" {
		if id, err := e.session.Verify(c.Value); err == nil {
			return id, credSessionCookie
		}
		log.Debug("access: invalid session cookie from %s", r.RemoteAddr)
	}
	if token, ok := bearerToken(r.Header.Get("Authorization"), r.Header.Get("X-ZTP-Token")); ok {
		if id, ok := snap.tokens.lookup(token); ok {
			// Attribute the credential to the header it actually came from.
			if _, fromAuth := bearerToken(r.Header.Get("Authorization"), ""); fromAuth {
				return id, credAuthorization
			}
			return id, credXZTPToken
		}
		log.Debug("access: unknown service token from %s", r.RemoteAddr)
	}
	return &Identity{Source: SourceNone}, credNone
}

// stripConsumedCredential removes the proxy credential from the
// outbound request while leaving unrelated auth material (backend
// cookies, a backend's own Authorization header) intact.
func stripConsumedCredential(r *http.Request, cred credential, sessionCookie string) {
	switch cred {
	case credAuthorization:
		r.Header.Del("Authorization")
	case credXZTPToken:
		r.Header.Del("X-ZTP-Token")
	case credSessionCookie:
		cookies := r.Cookies()
		r.Header.Del("Cookie")
		for _, c := range cookies {
			if c.Name != sessionCookie {
				r.AddCookie(c)
			}
		}
	}
}

// requireAuth answers an anonymous caller that hit an identity-based
// rule. Browsers would be redirected into the login flow; until an
// identity provider ships, they get an explanatory 401. Non-browser
// clients always get a plain 401 — APIs want a status code, not a
// login page.
func (e *Engine) requireAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !wantsHTML(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="zero-trust-proxy"`)
		writeStatus(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	// Browser with email OTP configured: into the login flow, carrying
	// the original destination as a sanitized relative path.
	if e.otp != nil {
		http.Redirect(w, r, loginRedirectURL(r), http.StatusFound)
		return
	}
	// No login flow configured (OIDC lands in a later increment):
	// nowhere to send the user, so say that instead of looping.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>401 · Authentication Required</title></head><body style="font:16px/1.5 -apple-system,sans-serif;max-width:40em;margin:4em auto;padding:0 1em"><h1>Authentication required</h1><p>This service requires you to sign in, but no identity provider is configured on the proxy yet. Contact the operator, or use a service token.</p></body></html>`))
}

func writeStatus(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body + "\n"))
}

func subjectOf(id *Identity) string {
	if id == nil {
		return ""
	}
	return id.Subject
}

// hostOnly strips an optional port from a Host header value.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(hostport)
}

// remoteIP parses the client IP from RemoteAddr — never from
// forwarding headers, which are client-controlled.
func remoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

// wantsHTML reports whether the client accepts text/html with positive
// quality (same content negotiation as the router's error pages): only
// an explicit, non-zero-q text/html selects the HTML branch, so API
// clients get status codes rather than markup.
func wantsHTML(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		fields := strings.Split(part, ";")
		if strings.ToLower(strings.TrimSpace(fields[0])) != "text/html" {
			continue
		}
		q := 1.0
		for _, p := range fields[1:] {
			p = strings.ToLower(strings.TrimSpace(p))
			if strings.HasPrefix(p, "q=") {
				if f, err := strconv.ParseFloat(strings.TrimSpace(p[2:]), 64); err == nil {
					q = f
				}
			}
		}
		if q > 0 {
			return true
		}
	}
	return false
}
