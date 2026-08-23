package agent

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

// mkReq builds a policyRequest for match/handler tests.
func mkReq(method, path, clientIP string) *policyRequest {
	return &policyRequest{Method: method, Path: path, ClientIP: clientIP}
}

func TestCompileMiddlewareUnknownType(t *testing.T) {
	_, err := compileMiddleware(MiddlewareConfig{Type: "basic_auth"})
	if err == nil || !strings.Contains(err.Error(), "unknown handler type") {
		t.Fatalf("expected unknown handler type error, got %v", err)
	}
	if _, err := compileMiddleware(MiddlewareConfig{}); err == nil {
		t.Fatal("expected error for handler with no type")
	}
}

func TestIPWhitelistCompileErrors(t *testing.T) {
	cases := []map[string]interface{}{
		nil, // missing allowed_ips
		{"allowed_ips": []interface{}{}},
		{"allowed_ips": []interface{}{"not-an-ip"}},
		{"allowed_ips": []interface{}{"10.0.0.0/99"}},
		{"allowed_ips": "86.126.81.150/32"}, // not a list
	}
	for i, cfg := range cases {
		if _, err := newIPWhitelistHandler(cfg); err == nil {
			t.Errorf("case %d: expected compile error for %v", i, cfg)
		}
	}
}

func TestIPWhitelistCheck(t *testing.T) {
	h, err := newIPWhitelistHandler(map[string]interface{}{
		"allowed_ips": []interface{}{"86.126.81.150/32", "10.0.0.0/8", "192.168.1.7", "2001:db8::/32"},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	allow := []string{"86.126.81.150", "10.20.30.40", "192.168.1.7", "2001:db8::1"}
	for _, ip := range allow {
		if dec := h.check(mkReq("GET", "/", ip)); dec != nil {
			t.Errorf("ip %s: expected allow, got %+v", ip, dec)
		}
	}

	deny := []string{"86.126.81.151", "11.0.0.1", "192.168.1.8", "2001:db9::1", "", "garbage"}
	for _, ip := range deny {
		dec := h.check(mkReq("GET", "/", ip))
		if dec == nil {
			t.Errorf("ip %q: expected deny", ip)
			continue
		}
		if dec.Status != http.StatusForbidden || dec.BlockedBy != blockedByIPWhitelist {
			t.Errorf("ip %q: got %+v", ip, dec)
		}
	}
}

func TestRateLimitCompileErrors(t *testing.T) {
	cases := []map[string]interface{}{
		nil, // missing rate
		{"rate": "fast"},
		{"rate": "10/fortnight"},
		{"rate": "0/minute"},
		{"rate": "-5/minute"},
		{"rate": 10}, // wrong type
		{"rate": "10/minute", "burst": "five"},
	}
	for i, cfg := range cases {
		if _, err := newRateLimitHandler(cfg); err == nil {
			t.Errorf("case %d: expected compile error for %v", i, cfg)
		}
	}
}

func TestRateLimitBucket(t *testing.T) {
	h, err := newRateLimitHandler(map[string]interface{}{"rate": "60/minute", "burst": 2})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	now := time.Unix(1000, 0)
	h.now = func() time.Time { return now }

	req := mkReq("GET", "/", "1.2.3.4")
	// Burst of 2 admits two immediate requests, the third is limited.
	if dec := h.check(req); dec != nil {
		t.Fatalf("request 1: expected allow, got %+v", dec)
	}
	if dec := h.check(req); dec != nil {
		t.Fatalf("request 2: expected allow, got %+v", dec)
	}
	dec := h.check(req)
	if dec == nil {
		t.Fatal("request 3: expected rate limit")
	}
	if dec.Status != http.StatusTooManyRequests || dec.BlockedBy != blockedByRateLimit {
		t.Fatalf("request 3: got %+v", dec)
	}
	if dec.RetryAfter < 1 {
		t.Fatalf("request 3: expected RetryAfter >= 1, got %d", dec.RetryAfter)
	}

	// A different client has its own bucket.
	if dec := h.check(mkReq("GET", "/", "5.6.7.8")); dec != nil {
		t.Fatalf("other client: expected allow, got %+v", dec)
	}

	// 60/minute = 1 token/second: one second later the client gets one more.
	now = now.Add(time.Second)
	if dec := h.check(req); dec != nil {
		t.Fatalf("after refill: expected allow, got %+v", dec)
	}
	if dec := h.check(req); dec == nil {
		t.Fatal("after refill: second request should be limited")
	}
}

func TestRateLimitDefaultBurst(t *testing.T) {
	h, err := newRateLimitHandler(map[string]interface{}{"rate": "3/hour"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	now := time.Unix(1000, 0)
	h.now = func() time.Time { return now }
	req := mkReq("GET", "/", "1.2.3.4")
	for i := 0; i < 3; i++ {
		if dec := h.check(req); dec != nil {
			t.Fatalf("request %d: expected allow (default burst = count), got %+v", i+1, dec)
		}
	}
	if dec := h.check(req); dec == nil {
		t.Fatal("request 4: expected rate limit")
	}
}

func TestCompiledMatch(t *testing.T) {
	tests := []struct {
		name  string
		match MatchConfig
		req   *policyRequest
		want  bool
	}{
		{"empty matches all", MatchConfig{}, mkReq("GET", "/anything", ""), true},
		{"star matches all", MatchConfig{Path: "/*"}, mkReq("POST", "/x/y", ""), true},
		{"exact hit", MatchConfig{Path: "/health"}, mkReq("GET", "/health", ""), true},
		{"exact miss", MatchConfig{Path: "/health"}, mkReq("GET", "/healthz", ""), false},
		{"slash-star matches base", MatchConfig{Path: "/api/*"}, mkReq("GET", "/api", ""), true},
		{"slash-star matches nested", MatchConfig{Path: "/api/*"}, mkReq("GET", "/api/v1/x", ""), true},
		{"slash-star respects boundary", MatchConfig{Path: "/api/*"}, mkReq("GET", "/apix", ""), false},
		{"bare-star prefix", MatchConfig{Path: "/api*"}, mkReq("GET", "/apix", ""), true},
		{"method hit", MatchConfig{Method: "post"}, mkReq("POST", "/", ""), true},
		{"method miss", MatchConfig{Method: "POST"}, mkReq("GET", "/", ""), false},
		{"auth subtree", MatchConfig{Path: "/api/v1/auth/*"}, mkReq("POST", "/api/v1/auth/local", ""), true},
	}
	for _, tt := range tests {
		cm := compileMatch(tt.match)
		if got := cm.matches(tt.req); got != tt.want {
			t.Errorf("%s: matches=%v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCompiledMatchHeadersAndQuery(t *testing.T) {
	cm := compileMatch(MatchConfig{
		Headers: map[string][]string{"x-api-key": {"secret1", "secret2"}},
		Query:   map[string]string{"mode": "admin"},
	})
	req := &policyRequest{
		Method:  "GET",
		Path:    "/",
		Headers: map[string][]string{"X-Api-Key": {"secret2"}},
		Query:   map[string][]string{"mode": {"admin"}},
	}
	if !cm.matches(req) {
		t.Fatal("expected header+query match")
	}
	req.Headers["X-Api-Key"] = []string{"wrong"}
	if cm.matches(req) {
		t.Fatal("expected header mismatch to fail")
	}
}

// TestEvaluateFirstMatchWins mirrors the seerr config: a tight limit on the
// auth endpoint, a loose one everywhere else.
func TestEvaluateFirstMatchWins(t *testing.T) {
	policy, err := compileRoutes([]RouteConfig{
		{
			Match: MatchConfig{Path: "/api/v1/auth/*"},
			Handle: []MiddlewareConfig{
				{Type: "rate_limit", Config: map[string]interface{}{"rate": "60/minute", "burst": 1}},
				{Type: "reverse_proxy"},
			},
		},
		{
			Match:  MatchConfig{Path: "/*"},
			Handle: []MiddlewareConfig{{Type: "reverse_proxy"}},
		},
	}, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	authReq := mkReq("POST", "/api/v1/auth/local", "1.2.3.4")
	if dec := policy.evaluate(authReq); !dec.Allowed {
		t.Fatalf("first auth request: expected allow, got %+v", dec)
	}
	if dec := policy.evaluate(authReq); dec.Allowed || dec.BlockedBy != blockedByRateLimit {
		t.Fatalf("second auth request: expected rate limit, got %+v", dec)
	}
	// The catch-all route is unlimited even for the same client.
	if dec := policy.evaluate(mkReq("GET", "/web/index.html", "1.2.3.4")); !dec.Allowed {
		t.Fatalf("catch-all: expected allow, got %+v", dec)
	}
}

func TestEvaluateNoRouteDenies(t *testing.T) {
	policy, err := compileRoutes([]RouteConfig{
		{Match: MatchConfig{Path: "/api/*"}, Handle: []MiddlewareConfig{{Type: "reverse_proxy"}}},
	}, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	dec := policy.evaluate(mkReq("GET", "/other", ""))
	if dec.Allowed || dec.BlockedBy != blockedByNoRoute || dec.Status != http.StatusNotFound {
		t.Fatalf("expected 404 no_route, got %+v", dec)
	}
}

func TestEmptyRoutesGetDefaultAllow(t *testing.T) {
	policy, err := compileRoutes(nil, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if dec := policy.evaluate(mkReq("GET", "/anything", "")); !dec.Allowed {
		t.Fatalf("default route: expected allow, got %+v", dec)
	}
}

func TestGlobalMiddlewareRunsBeforeRouteChain(t *testing.T) {
	cfg := &AgentConfig{
		GlobalMiddleware: []MiddlewareConfig{
			{Type: "ip_whitelist", Config: map[string]interface{}{"allowed_ips": []interface{}{"10.0.0.1"}}},
		},
		Services: []ServiceConfig{{
			ID:        "svc",
			Hosts:     []string{"a.example.com", "b.example.com"},
			Upstreams: []UpstreamConfig{{Address: "backend:80"}},
			Routes:    []RouteConfig{{Match: MatchConfig{Path: "/*"}, Handle: []MiddlewareConfig{{Type: "reverse_proxy"}}}},
		}},
	}
	policies, err := buildRoutePolicies(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if policies["a.example.com"] == nil || policies["a.example.com"] != policies["b.example.com"] {
		t.Fatal("hosts of one service should share a policy instance")
	}
	if dec := policies["a.example.com"].evaluate(mkReq("GET", "/", "10.0.0.1")); !dec.Allowed {
		t.Fatalf("whitelisted IP: expected allow, got %+v", dec)
	}
	if dec := policies["a.example.com"].evaluate(mkReq("GET", "/", "9.9.9.9")); dec.Allowed {
		t.Fatal("global whitelist should block non-listed IP")
	}
}

func TestValidateRejectsUnknownHandler(t *testing.T) {
	cfg := &AgentConfig{
		Agent: AgentSettings{ID: "a"},
		Services: []ServiceConfig{{
			ID:        "svc",
			Hosts:     []string{"a.example.com"},
			Upstreams: []UpstreamConfig{{Address: "backend:80"}},
			Routes: []RouteConfig{{
				Match:  MatchConfig{Path: "/*"},
				Handle: []MiddlewareConfig{{Type: "ip_whitlist"}}, // typo'd type
			}},
		}},
	}
	err := validateAndApplyDefaults(cfg)
	if err == nil || !strings.Contains(err.Error(), "unknown handler type") {
		t.Fatalf("expected unknown handler type error, got %v", err)
	}
}

func TestCheckRoutePolicy(t *testing.T) {
	a := NewAgent("test", "localhost:0", nil, nil)
	policy, err := compileRoutes([]RouteConfig{{
		Match: MatchConfig{Path: "/*"},
		Handle: []MiddlewareConfig{
			{Type: "ip_whitelist", Config: map[string]interface{}{"allowed_ips": []interface{}{"86.126.81.150/32"}}},
			{Type: "reverse_proxy"},
		},
	}}, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	a.routePolicies["sonarr.home.example.com"] = policy

	blocked := &common.HTTPData{
		Method:  "GET",
		URL:     "/series?page=1",
		Headers: map[string][]string{"X-Forwarded-For": {"100.64.1.2"}},
	}
	dec := a.checkRoutePolicy("sonarr.home.example.com", blocked)
	if dec.Allowed || dec.BlockedBy != blockedByIPWhitelist || dec.Status != http.StatusForbidden {
		t.Fatalf("mobile IP: expected ip_whitelist 403, got %+v", dec)
	}

	allowed := &common.HTTPData{
		Method:  "GET",
		URL:     "/series",
		Headers: map[string][]string{"X-Forwarded-For": {"86.126.81.150"}},
	}
	if dec := a.checkRoutePolicy("sonarr.home.example.com", allowed); !dec.Allowed {
		t.Fatalf("home IP: expected allow, got %+v", dec)
	}

	// A host without a policy (runtime-registered service) is allowed.
	if dec := a.checkRoutePolicy("other.example.com", blocked); !dec.Allowed {
		t.Fatalf("host without policy: expected allow, got %+v", dec)
	}
}

// Percent-encoded paths must not dodge a path matcher.
func TestCheckRoutePolicyDecodesPath(t *testing.T) {
	a := NewAgent("test", "localhost:0", nil, nil)
	policy, err := compileRoutes([]RouteConfig{
		{
			Match: MatchConfig{Path: "/admin/*"},
			Handle: []MiddlewareConfig{
				{Type: "ip_whitelist", Config: map[string]interface{}{"allowed_ips": []interface{}{"10.0.0.1"}}},
				{Type: "reverse_proxy"},
			},
		},
		{Match: MatchConfig{Path: "/*"}, Handle: []MiddlewareConfig{{Type: "reverse_proxy"}}},
	}, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	a.routePolicies["h.example.com"] = policy

	dec := a.checkRoutePolicy("h.example.com", &common.HTTPData{
		Method:  "GET",
		URL:     "/%61dmin/panel", // "/admin/panel"
		Headers: map[string][]string{"X-Forwarded-For": {"9.9.9.9"}},
	})
	if dec.Allowed {
		t.Fatal("percent-encoded /admin path should still hit the whitelist route")
	}
}

func TestClientIPFromHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		want    string
	}{
		{"xff single", map[string][]string{"X-Forwarded-For": {"1.2.3.4"}}, "1.2.3.4"},
		{"xff chain takes first", map[string][]string{"X-Forwarded-For": {"1.2.3.4, 10.0.0.1"}}, "1.2.3.4"},
		{"real ip fallback", map[string][]string{"X-Real-IP": {"5.6.7.8"}}, "5.6.7.8"},
		{"placeholder real ip ignored", map[string][]string{"X-Real-IP": {"{client_ip}"}}, ""},
		{"nothing", map[string][]string{}, ""},
	}
	for _, tt := range tests {
		if got := clientIPFromHeaders(tt.headers); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}
