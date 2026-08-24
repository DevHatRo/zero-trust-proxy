package policy

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// --- mock OpenID provider ------------------------------------------------

type mockIdP struct {
	server   *httptest.Server
	url      string
	priv     *rsa.PrivateKey
	kid      string
	clientID string
	now      time.Time

	mu     sync.Mutex
	nonce  string
	claims map[string]any
}

func newMockIdP(t *testing.T, clientID string, now time.Time) *mockIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockIdP{priv: priv, kid: "test-kid", clientID: clientID, now: now}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                 m.url,
			"authorization_endpoint": m.url + "/authorize",
			"token_endpoint":         m.url + "/token",
			"jwks_uri":               m.url + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": m.kid,
			"n": base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"token_type": "Bearer", "id_token": m.sign(nil)})
	})

	m.server = httptest.NewServer(mux)
	m.url = m.server.URL
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockIdP) client() *http.Client { return m.server.Client() }

func (m *mockIdP) set(nonce string, claims map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonce = nonce
	m.claims = claims
}

// sign builds and RS256-signs an ID token; extra overrides the defaults.
func (m *mockIdP) sign(extra map[string]any) string {
	m.mu.Lock()
	claims := map[string]any{
		"iss":            m.url,
		"aud":            m.clientID,
		"sub":            "user-123",
		"exp":            m.now.Add(time.Hour).Unix(),
		"iat":            m.now.Unix(),
		"nonce":          m.nonce,
		"email":          "ceo@example.com",
		"email_verified": true,
		"groups":         []string{"exec"},
	}
	for k, v := range m.claims {
		claims[k] = v
	}
	m.mu.Unlock()
	for k, v := range extra {
		claims[k] = v
	}
	return signRS256(m.priv, m.kid, claims)
}

func signRS256(priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	hdr, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	pl, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl)
	sum := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// oidcTestEngine builds an engine wired to the mock provider, with a rule
// requiring that provider + an example.com email domain.
func oidcTestEngine(t *testing.T, idp *mockIdP, now time.Time) *Engine {
	t.Helper()
	prov := &oidcProvider{
		name: "mock", issuer: idp.url, clientID: idp.clientID, clientSecret: "sec",
		scopes: []string{"openid", "email", "profile"}, groupsClaim: "groups",
		client: idp.client(), now: func() time.Time { return now },
	}
	mgr := &oidcManager{providers: map[string]*oidcProvider{"mock": prov}, order: []string{"mock"}}

	rules, err := compileRules([]serverconfig.AccessRule{{
		Name: "corp", When: serverconfig.AccessMatch{Hosts: []string{"app.example.com"}}, Action: "allow",
		Require: &serverconfig.AccessRequire{IdentityProvider: "mock", EmailsDomain: []string{"example.com"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := compileTokens(nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{
		session: NewSessionManager([]byte("0123456789abcdef0123456789abcdef"), "ztp_session", time.Hour),
		oidc:    mgr,
	}
	e.snap.Store(&snapshot{rules: rules, tokens: tokens})
	return e
}

// --- full flow -----------------------------------------------------------

func TestOIDCFullLoginFlow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	idp := newMockIdP(t, "cid", now)
	e := oidcTestEngine(t, idp, now)
	h := e.Wrap(okHandler(nil))

	// 1. Anonymous browser on a protected host → login redirect.
	rr := send(t, h, "GET", "http://app.example.com/dash", "9.9.9.9", func(r *http.Request) {
		r.Header.Set("Accept", "text/html")
	})
	if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), "/.ztp/login?rd=") {
		t.Fatalf("expected login redirect, got %d %q", rr.Code, rr.Header().Get("Location"))
	}

	// 2. The chooser offers the provider button.
	rr = send(t, h, "GET", "http://app.example.com/.ztp/login?rd=/dash", "9.9.9.9", nil)
	if !strings.Contains(rr.Body.String(), "/.ztp/oauth/login?provider=mock") {
		t.Fatalf("chooser missing provider button:\n%s", rr.Body.String())
	}

	// 3. Start the flow → 302 to the IdP; capture the signed flow cookie.
	rr = send(t, h, "GET", "http://app.example.com/.ztp/oauth/login?provider=mock&rd=/dash", "9.9.9.9", nil)
	if rr.Code != http.StatusFound {
		t.Fatalf("oauth/login: %d", rr.Code)
	}
	auth, err := url.Parse(rr.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(rr.Header().Get("Location"), idp.url+"/authorize") {
		t.Fatalf("authorize URL wrong: %q", rr.Header().Get("Location"))
	}
	if auth.Query().Get("code_challenge_method") != "S256" || auth.Query().Get("client_id") != "cid" ||
		auth.Query().Get("redirect_uri") != "http://app.example.com/.ztp/oauth/callback" {
		t.Fatalf("authorize params: %v", auth.Query())
	}
	var flowCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == oidcFlowCookie {
			flowCookie = c
		}
	}
	if flowCookie == nil {
		t.Fatal("no flow cookie set")
	}
	flow, err := parseFlow(e.session.secret, flowCookie.Value)
	if err != nil {
		t.Fatalf("flow cookie parse: %v", err)
	}
	if auth.Query().Get("state") != flow.State {
		t.Fatal("authorize state does not match the flow cookie")
	}
	if auth.Query().Get("code_challenge") != pkceChallenge(flow.Verifier) {
		t.Fatal("code_challenge does not match the flow verifier")
	}

	// 4. The IdP mints an ID token carrying this flow's nonce.
	idp.set(flow.Nonce, nil)

	// 5. Callback → session minted, redirect to the original path.
	rr = send(t, h, "GET", "http://app.example.com/.ztp/oauth/callback?code=xyz&state="+flow.State, "9.9.9.9",
		func(r *http.Request) { r.AddCookie(flowCookie) })
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/dash" {
		t.Fatalf("callback: %d loc=%q body=%s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	var session string
	for _, c := range rr.Result().Cookies() {
		if c.Name == "ztp_session" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("no session cookie minted")
	}

	// 6. The session satisfies the provider + email-domain rule.
	hit := false
	h2 := e.Wrap(okHandler(&hit))
	rr = send(t, h2, "GET", "http://app.example.com/dash", "9.9.9.9", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "ztp_session", Value: session})
	})
	if rr.Code != 200 || !hit {
		t.Fatalf("authenticated request: %d hit=%v", rr.Code, hit)
	}
}

// A CSRF/replay-mangled callback must not mint a session.
func TestOIDCCallbackRejectsBadState(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	idp := newMockIdP(t, "cid", now)
	e := oidcTestEngine(t, idp, now)
	h := e.Wrap(okHandler(nil))

	rr := send(t, h, "GET", "http://app.example.com/.ztp/oauth/login?provider=mock&rd=/dash", "9.9.9.9", nil)
	var flowCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == oidcFlowCookie {
			flowCookie = c
		}
	}
	// Wrong state param vs the cookie.
	rr = send(t, h, "GET", "http://app.example.com/.ztp/oauth/callback?code=xyz&state=forged", "9.9.9.9",
		func(r *http.Request) { r.AddCookie(flowCookie) })
	for _, c := range rr.Result().Cookies() {
		if c.Name == "ztp_session" && c.Value != "" {
			t.Fatal("bad state minted a session")
		}
	}
	if rr.Code == http.StatusSeeOther && rr.Header().Get("Location") == "/dash" {
		t.Fatal("bad state must not complete login")
	}

	// No flow cookie at all → restart redirect, no session.
	rr = send(t, h, "GET", "http://app.example.com/.ztp/oauth/callback?code=xyz&state=whatever", "9.9.9.9", nil)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/.ztp/login" {
		t.Fatalf("missing flow cookie: %d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
}

// --- ID-token verification -----------------------------------------------

func TestVerifyIDTokenChecks(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	idp := newMockIdP(t, "cid", now)
	p := &oidcProvider{
		name: "mock", issuer: idp.url, clientID: "cid",
		client: idp.client(), now: func() time.Time { return now }, groupsClaim: "groups",
	}
	ctx := context.Background()

	// Happy path.
	tok := idp.sign(map[string]any{"nonce": "N1"})
	id, err := p.verifyIDToken(ctx, tok, "N1")
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if id.Subject != "user-123" || id.Email != "ceo@example.com" || id.Provider != "mock" {
		t.Fatalf("claims not mapped: %+v", id)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "exec" {
		t.Fatalf("groups not mapped: %v", id.Groups)
	}

	cases := []struct {
		name  string
		tok   string
		nonce string
	}{
		{"nonce mismatch", idp.sign(map[string]any{"nonce": "OTHER"}), "N1"},
		{"expired", idp.sign(map[string]any{"nonce": "N1", "exp": now.Add(-time.Minute).Unix()}), "N1"},
		{"wrong audience", idp.sign(map[string]any{"nonce": "N1", "aud": "someone-else"}), "N1"},
		{"wrong issuer", idp.sign(map[string]any{"nonce": "N1", "iss": "https://evil.example"}), "N1"},
	}
	for _, tc := range cases {
		if _, err := p.verifyIDToken(ctx, tc.tok, tc.nonce); err == nil {
			t.Errorf("%s: expected rejection", tc.name)
		}
	}

	// Signature from a different key must fail.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := signRS256(other, idp.kid, map[string]any{
		"iss": idp.url, "aud": "cid", "sub": "x", "nonce": "N1",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
	})
	if _, err := p.verifyIDToken(ctx, forged, "N1"); err == nil {
		t.Error("token signed by an unknown key must be rejected")
	}
}

// Unverified email must not carry into the identity (can't satisfy an
// emails/emails_domain rule).
func TestVerifyIDTokenDropsUnverifiedEmail(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	idp := newMockIdP(t, "cid", now)
	p := &oidcProvider{name: "mock", issuer: idp.url, clientID: "cid",
		client: idp.client(), now: func() time.Time { return now }, groupsClaim: "groups"}

	tok := idp.sign(map[string]any{"nonce": "N1", "email_verified": false})
	id, err := p.verifyIDToken(context.Background(), tok, "N1")
	if err != nil {
		t.Fatal(err)
	}
	if id.Email != "" {
		t.Fatalf("unverified email must be dropped, got %q", id.Email)
	}
}
