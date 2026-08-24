package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SessionManager mints and verifies the browser session cookie: a
// compact HS256 JWT. Self-contained — no server-side session store, so
// sessions survive a restart and need no shared state. Rotating the
// secret invalidates every live session (documented, acceptable).
type SessionManager struct {
	secret     []byte
	cookieName string
	ttl        time.Duration
	now        func() time.Time // stubbed in tests
}

func NewSessionManager(secret []byte, cookieName string, ttl time.Duration) *SessionManager {
	return &SessionManager{secret: secret, cookieName: cookieName, ttl: ttl, now: time.Now}
}

// sessionClaims is the JWT payload.
type sessionClaims struct {
	Sub      string   `json:"sub"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Provider string   `json:"provider,omitempty"`
	Iat      int64    `json:"iat"`
	Exp      int64    `json:"exp"`
}

var jwtHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

// Mint issues a signed session token for the identity.
func (m *SessionManager) Mint(id *Identity) (string, error) {
	now := m.now()
	payload, err := json.Marshal(sessionClaims{
		Sub:      id.Subject,
		Email:    id.Email,
		Groups:   id.Groups,
		Provider: id.Provider,
		Iat:      now.Unix(),
		Exp:      now.Add(m.ttl).Unix(),
	})
	if err != nil {
		return "", err
	}
	signing := jwtHeader + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signing + "." + m.sign(signing), nil
}

// Verify checks the signature and validity window and returns the
// session identity. Every failure is opaque to the caller on purpose —
// an invalid cookie simply resolves to anonymous.
func (m *SessionManager) Verify(token string) (*Identity, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	signing := parts[0] + "." + parts[1]
	// Constant-time MAC check before anything is parsed.
	if !hmac.Equal([]byte(m.sign(signing)), []byte(parts[2])) {
		return nil, errors.New("bad signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims sessionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}
	now := m.now().Unix()
	if claims.Exp <= now {
		return nil, errors.New("expired")
	}
	// A token "issued" in the future is forged or clock-skewed beyond
	// tolerance either way — reject.
	if claims.Iat > now+60 {
		return nil, errors.New("issued in the future")
	}
	return &Identity{
		Source:   SourceSession,
		Subject:  claims.Sub,
		Email:    claims.Email,
		Groups:   claims.Groups,
		Provider: claims.Provider,
	}, nil
}

func (m *SessionManager) sign(data string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// SetCookie writes the session cookie. Secure+HttpOnly always;
// SameSite=Lax lets the post-login top-level redirect carry the cookie
// while still blocking CSRF on cross-site POSTs.
func (m *SessionManager) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(m.ttl.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie expires the session cookie.
func (m *SessionManager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// CookieName exposes the configured cookie name (middleware lookup).
func (m *SessionManager) CookieName() string { return m.cookieName }
