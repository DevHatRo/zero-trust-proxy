package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/types"
)

func newTestAgent() *Agent {
	return NewAgent("test-id", "localhost:8443", nil, nil)
}

// --- min ---

func TestMin(t *testing.T) {
	cases := [][3]int{{3, 5, 3}, {5, 3, 3}, {0, 0, 0}, {-1, 1, -1}}
	for _, c := range cases {
		if got := min(c[0], c[1]); got != c[2] {
			t.Fatalf("min(%d,%d)=%d, want %d", c[0], c[1], got, c[2])
		}
	}
}

// --- parseAddress ---

func TestParseAddress(t *testing.T) {
	tests := []struct {
		addr, host, port, proto string
	}{
		{"https://localhost:9443", "localhost", "9443", "https"},
		{"http://backend:8080", "backend", "8080", "http"},
		{"wss://ws.host:443", "ws.host", "443", "wss"},
		{"ws://ws.host:80", "ws.host", "80", "ws"},
		{"127.0.0.1:9000", "127.0.0.1", "9000", ""},
		{"justhost", "justhost", "", ""},
	}
	for _, tt := range tests {
		h, p, proto := parseAddress(tt.addr)
		if h != tt.host || p != tt.port || proto != tt.proto {
			t.Fatalf("parseAddress(%q)=(%q,%q,%q), want (%q,%q,%q)",
				tt.addr, h, p, proto, tt.host, tt.port, tt.proto)
		}
	}
}

// --- needsTLS ---

func TestNeedsTLS(t *testing.T) {
	svcHTTPS := &common.ServiceConfig{ServiceConfig: types.ServiceConfig{Protocol: "https"}}
	svcWSS := &common.ServiceConfig{ServiceConfig: types.ServiceConfig{Protocol: "wss"}}
	svcHTTP := &common.ServiceConfig{ServiceConfig: types.ServiceConfig{Protocol: "http"}}
	svcEmpty := &common.ServiceConfig{}

	if !needsTLS(svcHTTPS, "127.0.0.1:9443") {
		t.Error("needsTLS should be true for https protocol")
	}
	if !needsTLS(svcWSS, "127.0.0.1:9443") {
		t.Error("needsTLS should be true for wss protocol")
	}
	if needsTLS(svcHTTP, "127.0.0.1:8080") {
		t.Error("needsTLS should be false for http protocol")
	}
	if !needsTLS(svcEmpty, "https://backend:443") {
		t.Error("needsTLS should be true when backend addr has https:// prefix")
	}
	if needsTLS(svcEmpty, "127.0.0.1:8080") {
		t.Error("needsTLS should be false for plain addr with no protocol")
	}
}

// --- getHealthCheckScheme ---

func TestGetHealthCheckScheme(t *testing.T) {
	if s := getHealthCheckScheme(&ServiceConfig{Protocol: "https"}, "127.0.0.1:9443"); s != "https" {
		t.Fatalf("scheme=%s, want https", s)
	}
	if s := getHealthCheckScheme(&ServiceConfig{Protocol: "http"}, "127.0.0.1:8080"); s != "http" {
		t.Fatalf("scheme=%s, want http", s)
	}
	if s := getHealthCheckScheme(&ServiceConfig{}, "https://backend:443"); s != "https" {
		t.Fatalf("scheme=%s, want https for https:// prefix", s)
	}
	if s := getHealthCheckScheme(&ServiceConfig{}, "127.0.0.1:8080"); s != "http" {
		t.Fatalf("scheme=%s, want http default", s)
	}
}

// --- selectWeightedUpstream / selectLeastConnUpstream / selectHealthyUpstream ---

func TestSelectUpstreams(t *testing.T) {
	a := newTestAgent()
	upstreams := []UpstreamConfig{
		{Address: "a:8080", Weight: 1},
		{Address: "b:8080", Weight: 5},
		{Address: "c:8080", Weight: 2},
	}

	// Weighted — should pick highest weight.
	if got := a.selectWeightedUpstream(upstreams); got != "b:8080" {
		t.Fatalf("selectWeightedUpstream=%s, want b:8080", got)
	}

	// Least-conn — returns first upstream (simplified).
	if got := a.selectLeastConnUpstream(upstreams); got != "a:8080" {
		t.Fatalf("selectLeastConnUpstream=%s, want a:8080", got)
	}

	// Healthy — returns first upstream.
	if got := a.selectHealthyUpstream(upstreams); got != "a:8080" {
		t.Fatalf("selectHealthyUpstream=%s, want a:8080", got)
	}
}

// --- getPrimaryUpstream ---

func TestGetPrimaryUpstream(t *testing.T) {
	a := newTestAgent()

	// No upstreams → empty string.
	if got := a.getPrimaryUpstream(&ServiceConfig{}); got != "" {
		t.Fatalf("empty upstreams=%q, want empty", got)
	}

	// Default (no LB policy) → first upstream.
	svc := &ServiceConfig{Upstreams: []UpstreamConfig{{Address: "x:9000"}}}
	if got := a.getPrimaryUpstream(svc); got != "x:9000" {
		t.Fatalf("getPrimaryUpstream=%s, want x:9000", got)
	}

	// Weighted policy.
	svc2 := &ServiceConfig{
		Upstreams:     []UpstreamConfig{{Address: "lo:8080", Weight: 1}, {Address: "hi:8080", Weight: 10}},
		LoadBalancing: &LoadBalancingConfig{Policy: "weighted_round_robin"},
	}
	if got := a.getPrimaryUpstream(svc2); got != "hi:8080" {
		t.Fatalf("weighted=%s, want hi:8080", got)
	}

	// Least-conn policy.
	svc3 := &ServiceConfig{
		Upstreams:     []UpstreamConfig{{Address: "first:8080"}, {Address: "second:8080"}},
		LoadBalancing: &LoadBalancingConfig{Policy: "least_conn"},
	}
	if got := a.getPrimaryUpstream(svc3); got != "first:8080" {
		t.Fatalf("least_conn=%s, want first:8080", got)
	}
}

// --- servicesEqual ---

func TestServicesEqual(t *testing.T) {
	a := newTestAgent()
	base := &common.ServiceConfig{ServiceConfig: types.ServiceConfig{
		Hostname: "h", Backend: "b", Protocol: "https", WebSocket: true,
	}}
	same := &common.ServiceConfig{ServiceConfig: types.ServiceConfig{
		Hostname: "h", Backend: "b", Protocol: "https", WebSocket: true,
	}}
	diff := &common.ServiceConfig{ServiceConfig: types.ServiceConfig{
		Hostname: "h", Backend: "other", Protocol: "https",
	}}

	if !a.servicesEqual(base, same) {
		t.Fatal("identical configs should be equal")
	}
	if a.servicesEqual(base, diff) {
		t.Fatal("different backend should not be equal")
	}
}

// --- mapsEqual / interfaceEqual ---

func TestMapsEqual(t *testing.T) {
	if !mapsEqual(nil, nil) {
		t.Fatal("nil maps should be equal")
	}
	m1 := map[string]interface{}{"k": "v", "n": 1}
	m2 := map[string]interface{}{"k": "v", "n": 1}
	if !mapsEqual(m1, m2) {
		t.Fatal("equal maps should return true")
	}
	m3 := map[string]interface{}{"k": "other"}
	if mapsEqual(m1, m3) {
		t.Fatal("different maps should return false")
	}
	if mapsEqual(m1, map[string]interface{}{"k": "v"}) {
		t.Fatal("different length maps should return false")
	}
}

func TestInterfaceEqual(t *testing.T) {
	if !interfaceEqual("a", "a") {
		t.Fatal("equal strings should be equal")
	}
	if interfaceEqual("a", "b") {
		t.Fatal("different strings should not be equal")
	}
	if !interfaceEqual(42, 42) {
		t.Fatal("equal ints should be equal")
	}
}

// --- shouldUpdateApplicationLogging ---

func TestShouldUpdateApplicationLogging(t *testing.T) {
	a := newTestAgent()
	old := LoggingConfig{Level: "info", Format: "console", Output: "stdout"}

	if a.shouldUpdateApplicationLogging(old, old) {
		t.Fatal("identical logging config should not need update")
	}
	if !a.shouldUpdateApplicationLogging(old, LoggingConfig{Level: "debug", Format: "console", Output: "stdout"}) {
		t.Fatal("changed level should need update")
	}
	if !a.shouldUpdateApplicationLogging(old, LoggingConfig{Level: "info", Format: "json", Output: "stdout"}) {
		t.Fatal("changed format should need update")
	}
	if !a.shouldUpdateApplicationLogging(old, LoggingConfig{Level: "info", Format: "console", Output: "stderr"}) {
		t.Fatal("changed output should need update")
	}
}

// --- convertCommonToTypes / convertTypesToCommon ---

func TestConvertTypes(t *testing.T) {
	orig := &common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{
			Hostname: "h.example.com", Backend: "b:8080",
			Protocol: "https", WebSocket: true,
		},
	}
	tc := convertCommonToTypes(orig)
	if tc.Hostname != orig.Hostname || tc.Backend != orig.Backend || !tc.WebSocket {
		t.Fatalf("convertCommonToTypes: %+v", tc)
	}

	back := convertTypesToCommon(tc)
	if back.Hostname != orig.Hostname {
		t.Fatalf("convertTypesToCommon: %+v", back)
	}
}

// --- applyLoggingConfig ---

func TestApplyLoggingConfig(t *testing.T) {
	// Should not panic with valid configs.
	applyLoggingConfig(LoggingConfig{Level: "debug", Format: "json", Output: "stdout"})
	applyLoggingConfig(LoggingConfig{Level: "info", Format: "console", Output: "stderr"})
	applyLoggingConfig(LoggingConfig{Level: "", Format: "", Output: "file:/tmp/log.txt"})
	// Restore default.
	applyLoggingConfig(LoggingConfig{Level: "info", Format: "console", Output: "stdout"})
}

// --- convertToCommonServiceConfig ---

func TestConvertToCommonServiceConfig(t *testing.T) {
	a := newTestAgent()
	svc := &ServiceConfig{
		Protocol:  "https",
		WebSocket: true,
		Upstreams: []UpstreamConfig{{Address: "up:9000", Weight: 1}},
	}
	result := a.convertToCommonServiceConfig(svc, "host.example.com")
	if result.Hostname != "host.example.com" {
		t.Fatalf("hostname=%s, want host.example.com", result.Hostname)
	}
	if result.Backend != "up:9000" {
		t.Fatalf("backend=%s, want up:9000", result.Backend)
	}
	if !result.WebSocket {
		t.Fatal("WebSocket should be true")
	}
}

// --- convertToCommonEnhancedServiceConfig ---

func TestConvertToCommonEnhancedServiceConfig(t *testing.T) {
	a := newTestAgent()
	svc := &ServiceConfig{
		ID:        "svc-1",
		Name:      "test-svc",
		Protocol:  "http",
		WebSocket: false,
		Upstreams: []UpstreamConfig{
			{Address: "backend:8080", Weight: 5},
		},
	}
	result := a.convertToCommonEnhancedServiceConfig(svc, "enhanced.example.com")
	if result.Hostname != "enhanced.example.com" {
		t.Fatalf("hostname=%s", result.Hostname)
	}
	if result.ID != "svc-1" {
		t.Fatalf("id=%s, want svc-1", result.ID)
	}
	if len(result.Upstreams) != 1 || result.Upstreams[0].Address != "backend:8080" {
		t.Fatalf("upstreams=%+v", result.Upstreams)
	}
}

// --- startHealthChecks (no health checks — should be a no-op) ---

func TestStartHealthChecks_NoHealthChecks(t *testing.T) {
	a := newTestAgent()
	svc := &ServiceConfig{
		Upstreams: []UpstreamConfig{{Address: "up:9000"}}, // no HealthCheck
	}
	if err := a.startHealthChecks(svc); err != nil {
		t.Fatalf("startHealthChecks: %v", err)
	}
}

// TestCheckUpstreamHealth_302NotFollowed ensures the health client does not follow
// redirects (a 302 to a 200 /ok could otherwise look “healthy”).
func TestCheckUpstreamHealth_302NotFollowed(t *testing.T) {
	var sawOK bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hc":
			w.Header().Set("Location", "/ok")
			w.WriteHeader(http.StatusFound)
		case "/ok":
			sawOK = true
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()

	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}

	a := newTestAgent()
	svc := &ServiceConfig{ID: "s1", Protocol: "http"}
	up := UpstreamConfig{
		Address:     u.Host,
		HealthCheck: &HealthCheckConfig{Path: "/hc"},
	}
	if a.checkUpstreamHealth(svc, up) {
		t.Fatal("expected unhealthy when health endpoint returns 302")
	}
	if sawOK {
		t.Fatal("health check client must not follow redirect to /ok")
	}
}

// newConnectedAgent creates an Agent with conn and encoder wired up to a net.Pipe
// so that SendMessage / sendErrorResponse / sendBackendResponse work in tests.
func newConnectedAgent(t *testing.T) (*Agent, net.Conn) {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() {
		_ = serverSide.Close()
		_ = clientSide.Close()
	})
	a := newTestAgent()
	a.conn = serverSide
	a.encoder = json.NewEncoder(serverSide)
	a.decoder = json.NewDecoder(serverSide)
	return a, clientSide
}

// --- sendErrorResponse ---

func TestSendErrorResponse(t *testing.T) {
	a, client := newConnectedAgent(t)

	go func() { a.sendErrorResponse("req-1", "something went wrong") }()

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg common.Message
	if err := json.NewDecoder(client).Decode(&msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.Error != "something went wrong" {
		t.Fatalf("error=%q, want 'something went wrong'", msg.Error)
	}
	if msg.ID != "req-1" {
		t.Fatalf("id=%s, want req-1", msg.ID)
	}
}

// --- sendBackendResponse (small body — no streaming) ---

func TestSendBackendResponse_SmallBody(t *testing.T) {
	a, client := newConnectedAgent(t)

	resp := &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewBufferString("hello")),
		ContentLength: 5,
	}

	go func() { a.sendBackendResponse("req-2", resp) }()

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg common.Message
	if err := json.NewDecoder(client).Decode(&msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.HTTP == nil || msg.HTTP.StatusCode != 200 {
		t.Fatalf("unexpected msg: %+v", msg)
	}
	if string(msg.HTTP.Body) != "hello" {
		t.Fatalf("body=%q, want hello", msg.HTTP.Body)
	}
}

// --- buildWebSocketUpgradeRequest ---

func TestBuildWebSocketUpgradeRequest(t *testing.T) {
	a := newTestAgent()
	msg := &common.Message{
		HTTP: &common.HTTPData{
			Method: "GET",
			URL:    "/chat",
			Headers: map[string][]string{
				"Host":                  {"ws.example.com"},
				"Upgrade":               {"websocket"},
				"Connection":            {"Upgrade"},
				"Sec-WebSocket-Key":     {"dGhlIHNhbXBsZSBub25jZQ=="},
				"Sec-WebSocket-Version": {"13"},
			},
		},
	}
	result := a.buildWebSocketUpgradeRequest(msg)
	if !strings.Contains(result, "GET /chat HTTP/1.1\r\n") {
		t.Fatalf("request line missing: %q", result[:min(len(result), 80)])
	}
	if !strings.Contains(result, "X-Forwarded-Host: ws.example.com") {
		t.Fatalf("missing X-Forwarded-Host: %q", result)
	}
}

// --- handleHTTPRequest (proxy to local backend) ---

func TestHandleHTTPRequest_ProxyToBackend(t *testing.T) {
	// Spin up a local HTTP backend.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()

	a, clientConn := newConnectedAgent(t)

	// Register a service.
	a.mu.Lock()
	a.services[backend.Listener.Addr().String()] = &common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{
			Hostname: backend.Listener.Addr().String(),
			Backend:  backend.Listener.Addr().String(),
			Protocol: "http",
		},
	}
	a.mu.Unlock()

	msg := &common.Message{
		Type: "http_request",
		ID:   "proxy-test",
		HTTP: &common.HTTPData{
			Method: "GET",
			URL:    "/",
			Headers: map[string][]string{
				"Host": {backend.Listener.Addr().String()},
			},
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleHTTPRequest(msg)
	}()

	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var resp common.Message
	if err := json.NewDecoder(clientConn).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	<-done

	if resp.HTTP == nil || resp.HTTP.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %+v", resp.HTTP)
	}
}

// TestHandleHTTPRequest_PreservesRedirect ensures the agent does not let
// http.Client follow 3xx (regression: OAuth 302 was replaced by the followed 200 + HTML).
func TestHandleHTTPRequest_PreservesRedirect(t *testing.T) {
	redirectFollowed := make(chan struct{}, 1)
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectFollowed <- struct{}{}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("must-not-receive"))
	}))
	defer redirectTarget.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cb" {
			w.Header().Set("Location", redirectTarget.URL+"/sub")
			w.WriteHeader(http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer backend.Close()

	host := backend.Listener.Addr().String()
	a, clientConn := newConnectedAgent(t)
	a.mu.Lock()
	a.services[host] = &common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{
			Hostname: host,
			Backend:  host,
			Protocol: "http",
		},
	}
	a.mu.Unlock()

	msg := &common.Message{
		Type: "http_request",
		ID:   "redirect-preserve",
		HTTP: &common.HTTPData{
			Method: "GET",
			URL:    "/api/cb",
			Headers: map[string][]string{
				"Host": {host},
			},
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleHTTPRequest(msg)
	}()

	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var resp common.Message
	if err := json.NewDecoder(clientConn).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	<-done

	select {
	case <-redirectFollowed:
		t.Fatal("agent followed redirect; redirect target should not be called")
	default:
	}

	if resp.HTTP == nil || resp.HTTP.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %+v", resp.HTTP)
	}
	loc := resp.HTTP.Headers["Location"]
	if len(loc) == 0 || !strings.HasPrefix(loc[0], redirectTarget.URL) {
		t.Fatalf("Location header: %v", loc)
	}
}

func TestHandleHTTPRequest_NilHTTPData(t *testing.T) {
	a, _ := newConnectedAgent(t)
	// nil HTTP data should log and return without panic.
	a.handleHTTPRequest(&common.Message{Type: "http_request"})
}

func TestBuildWebSocketUpgradeRequest_WithClientIP(t *testing.T) {
	a := newTestAgent()
	msg := &common.Message{
		HTTP: &common.HTTPData{
			Method: "GET",
			URL:    "/ws",
			Headers: map[string][]string{
				"Host":                  {"ws2.example.com"},
				"Upgrade":               {"websocket"},
				"Connection":            {"Upgrade"},
				"Sec-WebSocket-Key":     {"key=="},
				"Sec-WebSocket-Version": {"13"},
				"X-Forwarded-For":       {"10.0.0.1, 10.0.0.2"},
			},
		},
	}
	result := a.buildWebSocketUpgradeRequest(msg)
	if !strings.Contains(result, "X-Real-IP: 10.0.0.1") {
		t.Fatalf("missing X-Real-IP header in: %q", result)
	}
}

// --- sendBackendResponse (streaming path for large response) ---

func TestSendBackendResponse_StreamingResponse(t *testing.T) {
	a, client := newConnectedAgent(t)

	// Create a response with Content-Length > 1MB to trigger streaming.
	// The streaming path calls HandleDownloadStream which will read the body
	// and send http_response messages.
	const size = 2 * 1024 * 1024
	body := bytes.Repeat([]byte("x"), size)
	resp := &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(size),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.sendBackendResponse("stream-resp", resp)
	}()

	// Drain all messages from the client pipe until the stream completes.
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	dec := json.NewDecoder(client)
	var gotLast bool
	for !gotLast {
		var msg common.Message
		if err := dec.Decode(&msg); err != nil {
			break
		}
		if msg.HTTP != nil && msg.HTTP.IsLastChunk {
			gotLast = true
		}
		if msg.Type == "http_response" && !msg.HTTP.IsStream {
			// Non-streaming response (fallback).
			gotLast = true
		}
	}

	<-done
}
