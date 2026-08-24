package policy

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// Hand-rolled OIDC auth-code login (no external deps): discovery + JWKS
// are fetched and cached per provider, the browser is bounced to the
// IdP with PKCE (S256) + state + nonce, and the returned ID token is
// verified (RS256 signature via JWKS, iss/aud/exp/nonce) before a
// session is minted. Only the confidential auth-code flow is supported.

const (
	oidcMetaTTL   = time.Hour       // discovery document cache lifetime
	oidcJWKSTTL   = time.Hour       // JWKS cache lifetime
	oidcHTTPLimit = 1 << 20         // 1 MiB cap on IdP response bodies
	oidcHTTPTO    = 10 * time.Second // per-call timeout for IdP requests
)

// oidcMeta is the subset of the discovery document we use.
type oidcMeta struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURL  string `json:"jwks_uri"`
}

// oidcProvider is one configured IdP with cached discovery + keys.
type oidcProvider struct {
	name         string
	issuer       string
	clientID     string
	clientSecret string
	scopes       []string
	groupsClaim  string

	client *http.Client

	mu      sync.Mutex
	meta    *oidcMeta
	metaExp time.Time
	keys    map[string]*rsa.PublicKey
	keysExp time.Time

	now func() time.Time // stubbed in tests
}

// oidcManager holds every configured provider in config order.
type oidcManager struct {
	providers map[string]*oidcProvider
	order     []string
}

func newOIDCManager(providers []serverconfig.IdentityProvider) *oidcManager {
	m := &oidcManager{providers: make(map[string]*oidcProvider, len(providers))}
	for i := range providers {
		p := &providers[i]
		m.providers[p.Name] = &oidcProvider{
			name:         p.Name,
			issuer:       strings.TrimRight(p.Issuer, "/"),
			clientID:     p.ResolvedClientID(),
			clientSecret: p.ResolvedClientSecret(),
			scopes:       p.EffectiveScopes(),
			groupsClaim:  p.EffectiveGroupsClaim(),
			client:       &http.Client{Timeout: oidcHTTPTO},
			now:          time.Now,
		}
		m.order = append(m.order, p.Name)
	}
	return m
}

func (m *oidcManager) provider(name string) (*oidcProvider, bool) {
	p, ok := m.providers[name]
	return p, ok
}

// discover returns the cached discovery document, refetching when stale.
func (p *oidcProvider) discover(ctx context.Context) (*oidcMeta, error) {
	p.mu.Lock()
	if p.meta != nil && p.now().Before(p.metaExp) {
		meta := p.meta
		p.mu.Unlock()
		return meta, nil
	}
	p.mu.Unlock()

	var meta oidcMeta
	if err := p.getJSON(ctx, p.issuer+"/.well-known/openid-configuration", &meta); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	// The issuer in the document must match the configured issuer —
	// otherwise a rogue discovery URL could point tokens at anyone.
	if strings.TrimRight(meta.Issuer, "/") != p.issuer {
		return nil, fmt.Errorf("discovery: issuer mismatch (%q != %q)", meta.Issuer, p.issuer)
	}
	if meta.AuthURL == "" || meta.TokenURL == "" || meta.JWKSURL == "" {
		return nil, fmt.Errorf("discovery: incomplete document")
	}

	p.mu.Lock()
	p.meta = &meta
	p.metaExp = p.now().Add(oidcMetaTTL)
	p.mu.Unlock()
	return &meta, nil
}

// signingKey returns the RSA public key for kid, refreshing the JWKS
// once on a miss (rotation) before giving up.
func (p *oidcProvider) signingKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	p.mu.Lock()
	if p.keys != nil && p.now().Before(p.keysExp) {
		if k, ok := p.keys[kid]; ok {
			p.mu.Unlock()
			return k, nil
		}
	}
	p.mu.Unlock()

	if err := p.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if k, ok := p.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no JWKS key for kid %q", kid)
}

func (p *oidcProvider) refreshJWKS(ctx context.Context) error {
	meta, err := p.discover(ctx)
	if err != nil {
		return err
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := p.getJSON(ctx, meta.JWKSURL, &doc); err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		pub, err := rsaKeyFromJWK(k.N, k.E)
		if err != nil {
			continue // skip malformed keys, keep the rest
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("jwks: no usable RSA signing keys")
	}
	p.mu.Lock()
	p.keys = keys
	p.keysExp = p.now().Add(oidcJWKSTTL)
	p.mu.Unlock()
	return nil
}

// rsaKeyFromJWK builds an RSA public key from base64url modulus/exponent.
func rsaKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	if len(nb) == 0 || len(eb) == 0 {
		return nil, fmt.Errorf("empty modulus/exponent")
	}
	if len(eb) > 4 {
		return nil, fmt.Errorf("exponent too large")
	}
	// Left-pad the exponent to 8 bytes for BigEndian decoding.
	ePad := make([]byte, 8)
	copy(ePad[8-len(eb):], eb)
	e := binary.BigEndian.Uint64(ePad)
	// A real RSA public exponent is small and odd; bound it well within
	// int range so the conversion is safe on every platform.
	if e < 3 || e > math.MaxInt32 || e%2 == 0 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e)}, nil
}

// authCodeURL builds the IdP authorize URL for a login attempt.
func (p *oidcProvider) authCodeURL(ctx context.Context, redirectURI, state, nonce, challenge string) (string, error) {
	meta, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(p.scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(meta.AuthURL, "?") {
		sep = "&"
	}
	return meta.AuthURL + sep + q.Encode(), nil
}

// oidcClaims are the ID-token claims we consume.
type oidcClaims struct {
	Iss           string          `json:"iss"`
	Sub           string          `json:"sub"`
	Aud           json.RawMessage `json:"aud"`
	Exp           int64           `json:"exp"`
	Iat           int64           `json:"iat"`
	Nonce         string          `json:"nonce"`
	Email         string          `json:"email"`
	EmailVerified *bool           `json:"email_verified"`
}

// exchange swaps an auth code for a verified Identity. redirectURI must
// equal the one sent to authorize; nonce must equal the one issued.
func (p *oidcProvider) exchange(ctx context.Context, code, redirectURI, nonce string) (*Identity, error) {
	meta, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"code_verifier": {oidcVerifierFromChallengeCtx(ctx)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, oidcHTTPLimit))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token exchange: status %d", resp.StatusCode)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("token exchange: decode: %w", err)
	}
	if tok.IDToken == "" {
		return nil, fmt.Errorf("token exchange: no id_token in response")
	}
	return p.verifyIDToken(ctx, tok.IDToken, nonce)
}

// verifyIDToken validates a compact JWS RS256 ID token end to end.
func (p *oidcProvider) verifyIDToken(ctx context.Context, raw, nonce string) (*Identity, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("id_token: malformed")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("id_token: header: %w", err)
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("id_token: header: %w", err)
	}
	hashAlg, ok := oidcRSAHashes[hdr.Alg]
	if !ok {
		return nil, fmt.Errorf("id_token: unsupported alg %q (RS256/384/512 only)", hdr.Alg)
	}
	key, err := p.signingKey(ctx, hdr.Kid)
	if err != nil {
		return nil, fmt.Errorf("id_token: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("id_token: signature: %w", err)
	}
	h := hashAlg.New()
	h.Write([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, hashAlg, h.Sum(nil), sig); err != nil {
		return nil, fmt.Errorf("id_token: bad signature")
	}

	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("id_token: payload: %w", err)
	}
	var c oidcClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, fmt.Errorf("id_token: claims: %w", err)
	}
	if strings.TrimRight(c.Iss, "/") != p.issuer {
		return nil, fmt.Errorf("id_token: issuer mismatch")
	}
	if !audienceContains(c.Aud, p.clientID) {
		return nil, fmt.Errorf("id_token: audience mismatch")
	}
	now := p.now().Unix()
	if c.Exp <= now {
		return nil, fmt.Errorf("id_token: expired")
	}
	if c.Iat > now+60 {
		return nil, fmt.Errorf("id_token: issued in the future")
	}
	if nonce == "" || c.Nonce != nonce {
		return nil, fmt.Errorf("id_token: nonce mismatch")
	}
	if c.Sub == "" {
		return nil, fmt.Errorf("id_token: missing sub")
	}

	email := c.Email
	if c.EmailVerified != nil && !*c.EmailVerified {
		// Unverified email cannot satisfy an emails/emails_domain rule.
		email = ""
	}
	return &Identity{
		Source:   SourceSession,
		Subject:  c.Sub,
		Email:    strings.ToLower(email),
		Groups:   extractGroups(pb, p.groupsClaim),
		Provider: p.name,
	}, nil
}

// oidcRSAHashes maps the accepted JWS algs to their hash.
var oidcRSAHashes = map[string]crypto.Hash{
	"RS256": crypto.SHA256,
	"RS384": crypto.SHA384,
	"RS512": crypto.SHA512,
}

// audienceContains reports whether the aud claim (string or array)
// includes the client ID.
func audienceContains(raw json.RawMessage, clientID string) bool {
	if len(raw) == 0 {
		return false
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == clientID
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == clientID {
				return true
			}
		}
	}
	return false
}

// extractGroups pulls a string-array groups claim from the raw payload.
func extractGroups(payload []byte, claim string) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal(payload, &m) != nil {
		return nil
	}
	raw, ok := m[claim]
	if !ok {
		return nil
	}
	var groups []string
	if json.Unmarshal(raw, &groups) != nil {
		return nil
	}
	return groups
}

// getJSON fetches url and decodes a bounded JSON body into v.
func (p *oidcProvider) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d from %s", resp.StatusCode, u)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, oidcHTTPLimit))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// pkceChallenge returns the S256 code_challenge for a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// --- PKCE verifier plumbing --------------------------------------------
//
// The verifier is carried in the signed flow cookie, not on the wire, so
// exchange() reads it from the request context to keep the provider API
// free of flow-state parameters.

type oidcVerifierKey struct{}

func ctxWithVerifier(ctx context.Context, verifier string) context.Context {
	return context.WithValue(ctx, oidcVerifierKey{}, verifier)
}

func oidcVerifierFromChallengeCtx(ctx context.Context) string {
	if v, ok := ctx.Value(oidcVerifierKey{}).(string); ok {
		return v
	}
	return ""
}
