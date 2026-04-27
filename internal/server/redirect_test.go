package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirect_PermanentToHTTPS(t *testing.T) {
	h := newRedirectHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo?bar=1", nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "https://example.com/foo?bar=1" {
		t.Fatalf("Location = %q", loc)
	}
}

func TestRedirect_ACMEChallengeBypass(t *testing.T) {
	called := false
	acme := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = w.Write([]byte("token-payload"))
	})
	h := newRedirectHandler(acme)

	req := httptest.NewRequest(http.MethodGet,
		"http://example.com/.well-known/acme-challenge/abc123", nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if !called {
		t.Fatal("acme handler not invoked")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 from acme handler", rec.Code)
	}
	if got := rec.Body.String(); got != "token-payload" {
		t.Fatalf("body = %q", got)
	}
}

func TestRedirect_MissingHost(t *testing.T) {
	h := newRedirectHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	req.Host = ""
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
