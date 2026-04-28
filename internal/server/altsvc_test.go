package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildAltSvcHeader(t *testing.T) {
	cases := map[string]string{
		":443":           `h3=":443"; ma=2592000`,
		":8443":          `h3=":8443"; ma=2592000`,
		"127.0.0.1:8443": `h3=":8443"; ma=2592000`, // strip host, keep port
	}
	for addr, want := range cases {
		if got := buildAltSvcHeader(addr); got != want {
			t.Errorf("buildAltSvcHeader(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestAltSvcMiddleware_AddsHeader(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h := altSvcMiddleware(":443", next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if !called {
		t.Fatal("next handler not invoked")
	}
	if got := rec.Header().Get("Alt-Svc"); got != `h3=":443"; ma=2592000` {
		t.Fatalf("Alt-Svc = %q", got)
	}
}
