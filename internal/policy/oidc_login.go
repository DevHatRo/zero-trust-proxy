package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// OIDC browser endpoints under /.ztp/:
//
//	GET /.ztp/oauth/login?provider=<name>&rd=<path>   → 302 to the IdP
//	GET /.ztp/oauth/callback                          ← IdP redirect back
//
// The per-attempt flow state (provider, state, nonce, PKCE verifier,
// return path) lives in a signed, SameSite=Strict cookie — the proxy
// keeps no server-side login state. state guards CSRF, nonce guards
// token replay, PKCE guards code interception.

const (
	oidcFlowCookie = "ztp_oidc_txn"
	oidcFlowTTL    = 10 * time.Minute
)

// oidcFlow is the signed cookie payload for one login attempt.
type oidcFlow struct {
	Provider string `json:"p"`
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Exp      int64  `json:"e"`
}

// handleOIDCLogin starts an auth-code flow for the named provider.
func (e *Engine) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeStatus(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}
	rd := sanitizeReturnPath(r.URL.Query().Get("rd"))
	p, ok := e.oidc.provider(r.URL.Query().Get("provider"))
	if !ok {
		writeStatus(w, http.StatusNotFound, "Unknown identity provider")
		return
	}

	state, err1 := newLoginToken()
	nonce, err2 := newLoginToken()
	verifier, err3 := newLoginToken()
	if err1 != nil || err2 != nil || err3 != nil {
		log.Error("access: oidc token gen failed")
		writeStatus(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	redirectURI := oidcRedirectURI(r)
	authURL, err := p.authCodeURL(r.Context(), redirectURI, state, nonce, pkceChallenge(verifier))
	if err != nil {
		log.Error("access: oidc discovery for %q failed: %v", p.name, err)
		if e.hooks.OIDCError != nil {
			e.hooks.OIDCError()
		}
		renderLoginPage(w, loginView{Step: "email", Return: rd, OTP: e.otp != nil,
			Providers: e.providerLinks(rd), Error: "Sign-in is temporarily unavailable. Try again shortly."})
		return
	}

	setFlowCookie(w, e.session.secret, oidcFlow{
		Provider: p.name, State: state, Nonce: nonce, Verifier: verifier,
		Return: rd, Exp: time.Now().Add(oidcFlowTTL).Unix(),
	})
	if e.hooks.AuthRedirect != nil {
		e.hooks.AuthRedirect()
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback completes the flow: verify state, exchange the code,
// validate the ID token, mint a session.
func (e *Engine) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	flow, err := readFlowCookie(r, e.session.secret)
	// The flow cookie is single-use regardless of outcome.
	clearFlowCookie(w)
	if err != nil {
		// No / expired / forged transaction: restart cleanly.
		http.Redirect(w, r, "/.ztp/login", http.StatusSeeOther)
		return
	}
	rd := sanitizeReturnPath(flow.Return)

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		log.Warn("access: oidc provider %q returned error=%q", flow.Provider, errParam)
		e.oidcFail(w, rd, "Sign-in was cancelled or refused.")
		return
	}
	state := r.URL.Query().Get("state")
	if state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(flow.State)) != 1 {
		log.Warn("access: oidc state mismatch")
		e.oidcFail(w, rd, "Your sign-in session expired. Please try again.")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		e.oidcFail(w, rd, "Your sign-in session expired. Please try again.")
		return
	}
	p, ok := e.oidc.provider(flow.Provider)
	if !ok {
		e.oidcFail(w, rd, "Your sign-in session expired. Please try again.")
		return
	}

	ctx := ctxWithVerifier(r.Context(), flow.Verifier)
	id, err := p.exchange(ctx, code, oidcRedirectURI(r), flow.Nonce)
	if err != nil {
		log.Error("access: oidc exchange for %q failed: %v", p.name, err)
		if e.hooks.OIDCError != nil {
			e.hooks.OIDCError()
		}
		e.oidcFail(w, rd, "Sign-in failed. Please try again.")
		return
	}

	token, err := e.session.Mint(id)
	if err != nil {
		log.Error("access: mint session: %v", err)
		writeStatus(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	e.session.SetCookie(w, token)
	if e.hooks.OIDCLogin != nil {
		e.hooks.OIDCLogin()
	}
	log.Info("access: oidc login provider=%s sub=%s", p.name, id.Subject)
	// rd is sanitized to a local path above.
	http.Redirect(w, r, rd, http.StatusSeeOther) // #nosec G710
}

// oidcFail renders the login chooser with an error message.
func (e *Engine) oidcFail(w http.ResponseWriter, rd, msg string) {
	renderLoginPage(w, loginView{Step: "email", Return: rd, OTP: e.otp != nil,
		Providers: e.providerLinks(rd), Error: msg})
}

// providerLinks builds the chooser buttons for every configured IdP.
func (e *Engine) providerLinks(rd string) []providerLink {
	if e.oidc == nil {
		return nil
	}
	links := make([]providerLink, 0, len(e.oidc.order))
	for _, name := range e.oidc.order {
		links = append(links, providerLink{
			Name: name,
			URL:  "/.ztp/oauth/login?provider=" + url.QueryEscape(name) + "&rd=" + url.QueryEscape(rd),
		})
	}
	return links
}

// oidcRedirectURI is the callback URL for this request's host. It must
// match between the authorize request and the token exchange, and be
// registered with the IdP.
func oidcRedirectURI(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		// The access layer runs on the TLS listener in production; only
		// tests reach it over plain HTTP.
		scheme = "http"
	}
	return scheme + "://" + r.Host + ZTPPrefix + "oauth/callback"
}

// --- signed flow cookie ------------------------------------------------

func setFlowCookie(w http.ResponseWriter, secret []byte, f oidcFlow) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcFlowCookie,
		Value:    signFlow(secret, f),
		Path:     ZTPPrefix,
		MaxAge:   int(oidcFlowTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Lax: must survive the top-level redirect back from the IdP
	})
}

func clearFlowCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: oidcFlowCookie, Value: "", Path: ZTPPrefix, MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func readFlowCookie(r *http.Request, secret []byte) (*oidcFlow, error) {
	c, err := r.Cookie(oidcFlowCookie)
	if err != nil || c.Value == "" {
		return nil, fmt.Errorf("no flow cookie")
	}
	return parseFlow(secret, c.Value)
}

// signFlow serializes and MACs the flow: base64url(json).base64url(hmac).
func signFlow(secret []byte, f oidcFlow) string {
	payload, _ := json.Marshal(f)
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	return b64 + "." + flowMAC(secret, b64)
}

func parseFlow(secret []byte, value string) (*oidcFlow, error) {
	dot := -1
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 {
		return nil, fmt.Errorf("malformed flow cookie")
	}
	b64, mac := value[:dot], value[dot+1:]
	if subtle.ConstantTimeCompare([]byte(mac), []byte(flowMAC(secret, b64))) != 1 {
		return nil, fmt.Errorf("bad flow signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	var f oidcFlow
	if err := json.Unmarshal(payload, &f); err != nil {
		return nil, err
	}
	if f.Exp <= time.Now().Unix() {
		return nil, fmt.Errorf("flow expired")
	}
	return &f, nil
}

func flowMAC(secret []byte, data string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
