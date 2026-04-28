package server

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

func TestClientIP(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:54321":   "127.0.0.1",
		"[::1]:8080":        "::1",
		"[fe80::1%lo0]:443": "fe80::1%lo0",
		"":                  "",
		"no-port":           "no-port",
	}
	for in, want := range cases {
		if got := clientIP(in); got != want {
			t.Errorf("clientIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAccessLogRecorder_CapturesStatusAndBytes(t *testing.T) {
	rec := httptest.NewRecorder()
	a := &accessLogRecorder{ResponseWriter: rec, status: http.StatusOK}
	a.WriteHeader(http.StatusTeapot)
	if _, err := a.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write([]byte(" world")); err != nil {
		t.Fatal(err)
	}
	if a.status != http.StatusTeapot {
		t.Errorf("status = %d, want 418", a.status)
	}
	if a.bytes != int64(len("hello world")) {
		t.Errorf("bytes = %d, want %d", a.bytes, len("hello world"))
	}
}

func TestAccessLogRecorder_HijackForwarded(t *testing.T) {
	hr := &fakeHijackRW{ResponseWriter: httptest.NewRecorder()}
	a := &accessLogRecorder{ResponseWriter: hr}
	if _, _, err := a.Hijack(); err != nil {
		t.Fatalf("Hijack: %v", err)
	}
	if !hr.hijacked {
		t.Fatal("underlying Hijack not invoked")
	}

	// And errors out cleanly when the underlying writer is not a Hijacker.
	a2 := &accessLogRecorder{ResponseWriter: httptest.NewRecorder()}
	if _, _, err := a2.Hijack(); err == nil {
		t.Fatal("expected error when underlying is not a Hijacker")
	}
}

func TestAccessLogMiddleware_RequestInfoFlowsToHandler(t *testing.T) {
	var seenAgentID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ri := common.RequestInfoFrom(r.Context())
		if ri == nil {
			t.Fatal("inner handler missing RequestInfo in context")
		}
		ri.AgentID = "agent-z"
		seenAgentID = ri.AgentID
		w.WriteHeader(http.StatusOK)
	})

	h := accessLogMiddleware(inner)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://x.test/path", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	h.ServeHTTP(rec, req)

	if seenAgentID != "agent-z" {
		t.Fatalf("inner handler agent_id = %q, want agent-z", seenAgentID)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

type fakeHijackRW struct {
	http.ResponseWriter
	hijacked bool
}

func (f *fakeHijackRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	f.hijacked = true
	c1, _ := net.Pipe()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}
