package ztrouter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

func newErrReq(accept string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://shop.example.com/checkout", nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return req
}

func TestWriteProxyError_HTMLForBrowsers(t *testing.T) {
	rr := httptest.NewRecorder()
	req := newErrReq("text/html,application/xhtml+xml")
	writeProxyError(rr, req, proxyError{
		Status:  http.StatusServiceUnavailable,
		Title:   "Agent Unreachable",
		Summary: "No agent is connected.",
		Failed:  nodeAgent,
	})

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type=%q, want text/html", ct)
	}
	body := rr.Body.String()
	for _, want := range []string{"<!doctype html>", "Agent Unreachable", "shop.example.com", "Zero Trust Proxy"} {
		if !strings.Contains(body, want) {
			t.Fatalf("html body missing %q\n%s", want, body)
		}
	}
}

func TestWriteProxyError_PlainTextForAPIClients(t *testing.T) {
	rr := httptest.NewRecorder()
	req := newErrReq("*/*") // curl default
	writeProxyError(rr, req, proxyError{
		Status:  http.StatusBadGateway,
		Title:   "Agent Connection Lost",
		Summary: "The connection dropped.",
		Detail:  "write tcp 10.0.0.5:8443->10.0.0.9:51234: write: broken pipe",
		Failed:  nodeAgent,
	})

	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type=%q, want text/plain", ct)
	}
	body := rr.Body.String()
	if strings.Contains(body, "<html") {
		t.Fatalf("plain client got HTML: %s", body)
	}
	for _, want := range []string{"Agent Connection Lost", "Request ID:"} {
		if !strings.Contains(body, want) {
			t.Fatalf("plain body missing %q\n%s", want, body)
		}
	}
	// Detail is log-only: a raw error containing internal addresses must never
	// reach the client.
	if strings.Contains(body, "broken pipe") || strings.Contains(body, "10.0.0.5") {
		t.Fatalf("plain body leaked Detail to client: %s", body)
	}
}

func TestWriteProxyError_SetsRequestIDHeaderAndReusesContextID(t *testing.T) {
	rr := httptest.NewRecorder()
	ri := &common.RequestInfo{RequestID: "abc123def456"}
	req := newErrReq("text/html")
	req = req.WithContext(common.WithRequestInfo(req.Context(), ri))

	writeProxyError(rr, req, proxyError{
		Status:  http.StatusGatewayTimeout,
		Title:   "Agent Timeout",
		Summary: "Timed out.",
		Failed:  nodeAgent,
	})

	if got := rr.Header().Get("X-Request-Id"); got != "abc123def456" {
		t.Fatalf("X-Request-Id=%q, want abc123def456", got)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", cc)
	}
	if !strings.Contains(rr.Body.String(), "abc123def456") {
		t.Fatal("page should display the request ID")
	}
}

func TestNodeStatuses_AgentFailure(t *testing.T) {
	nodes := nodeStatuses(nodeAgent)
	if len(nodes) != 3 {
		t.Fatalf("want 3 nodes, got %d", len(nodes))
	}
	if nodes[0].State != "ok" || nodes[1].State != "ok" || nodes[2].State != "error" {
		t.Fatalf("agent-failure states = %q/%q/%q, want ok/ok/error",
			nodes[0].State, nodes[1].State, nodes[2].State)
	}
}

func TestNodeStatuses_ClientFailureMarksLaterUnknown(t *testing.T) {
	nodes := nodeStatuses(nodeClient)
	if nodes[0].State != "error" || nodes[1].State != "unknown" || nodes[2].State != "unknown" {
		t.Fatalf("client-failure states = %q/%q/%q, want error/unknown/unknown",
			nodes[0].State, nodes[1].State, nodes[2].State)
	}
}

func TestWantsHTML(t *testing.T) {
	cases := map[string]bool{
		"text/html,application/xhtml+xml,application/xml;q=0.9": true,
		"*/*":              false,
		"application/json": false,
		"":                 false,
	}
	for accept, want := range cases {
		if got := wantsHTML(newErrReq(accept)); got != want {
			t.Errorf("wantsHTML(%q)=%v, want %v", accept, got, want)
		}
	}
}
