package security

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

func TestParseRate(t *testing.T) {
	good := map[string]float64{
		"100/s":     100,
		"60/minute": 1,
		"2/m":       2.0 / 60,
		"3600/hour": 1,
	}
	for spec, want := range good {
		got, err := ParseRate(spec)
		if err != nil {
			t.Errorf("%s: unexpected error %v", spec, err)
			continue
		}
		if diff := got - want; diff > 1e-9 || diff < -1e-9 {
			t.Errorf("%s: got %v tokens/s, want %v", spec, got, want)
		}
	}
	for _, bad := range []string{"", "fast", "10", "0/s", "-1/m", "10/fortnight", "x/s"} {
		if _, err := ParseRate(bad); err == nil {
			t.Errorf("%q: expected parse error", bad)
		}
	}
}

func TestLimiterBurstAndRefill(t *testing.T) {
	l, err := NewLimiter("60/minute", 2) // 1 token/sec, burst 2
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }

	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("request 1 should pass")
	}
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("request 2 should pass (burst)")
	}
	ok, retry := l.Allow("k")
	if ok {
		t.Fatal("request 3 should be limited")
	}
	if retry < 1 {
		t.Fatalf("retryAfter=%d, want >= 1", retry)
	}
	// Independent key unaffected.
	if ok, _ := l.Allow("other"); !ok {
		t.Fatal("other key should pass")
	}
	// After exactly one second, exactly one token refills.
	now = now.Add(time.Second)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("post-refill request should pass")
	}
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("second post-refill request should be limited")
	}
}

func TestLimiterDefaultBurstIsRateCount(t *testing.T) {
	l, err := NewLimiter("3/hour", 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("k"); !ok {
			t.Fatalf("request %d should pass (default burst = count)", i+1)
		}
	}
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("request 4 should be limited")
	}
}

func TestLimiterEviction(t *testing.T) {
	l, err := NewLimiter("100/s", 100)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	for i := 0; i < 500; i++ {
		l.Allow(fmt.Sprintf("key-%d", i))
	}
	if got := l.Buckets(); got != 500 {
		t.Fatalf("buckets=%d, want 500", got)
	}
	now = now.Add(idleTTL + time.Minute)
	l.Allow("fresh")
	l.sweep(idleTTL)
	if got := l.Buckets(); got != 1 {
		t.Fatalf("after sweep buckets=%d, want 1 (only the fresh key)", got)
	}
}

func TestLimiterConcurrentAllowAndSweep(t *testing.T) {
	l, err := NewLimiter("1000/s", 1000)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				l.Allow(fmt.Sprintf("g%d-i%d", g, i%20))
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			l.sweep(0) // aggressive sweep while Allow hammers
		}
	}()
	wg.Wait()
}

func fwConfig() serverconfig.FirewallConfig {
	return serverconfig.FirewallConfig{
		Enabled: true,
		Rules: []serverconfig.FirewallRule{
			{Name: "block-secret-probes", Action: "deny",
				When: serverconfig.FirewallRuleMatch{Paths: []string{"/.env", "/.git/*", "/wp-admin/*"}}},
			{Name: "office-only-admin", Action: "allow",
				When: serverconfig.FirewallRuleMatch{Hosts: []string{"admin.example.com"}, SourceCIDRs: []string{"203.0.113.0/24"}}},
			{Name: "deny-other-admin", Action: "deny",
				When: serverconfig.FirewallRuleMatch{Hosts: []string{"admin.example.com"}}},
		},
	}
}

func TestFirewallPrecedence(t *testing.T) {
	fs, err := compileFirewall(fwConfig())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host, path, method, ip string
		wantDeny               bool
		wantRule               string
	}{
		{"any.example.com", "/.env", "GET", "1.2.3.4", true, "block-secret-probes"},
		{"any.example.com", "/.git/config", "GET", "1.2.3.4", true, "block-secret-probes"},
		{"any.example.com", "/wp-admin/setup.php", "POST", "1.2.3.4", true, "block-secret-probes"},
		{"admin.example.com", "/", "GET", "203.0.113.5", false, "office-only-admin"},
		{"admin.example.com", "/", "GET", "198.51.100.5", true, "deny-other-admin"},
		{"public.example.com", "/index.html", "GET", "198.51.100.5", false, ""}, // no match = allow
	}
	for _, c := range cases {
		denied, rule := fs.decision(c.host, c.path, c.method, parseIP(c.ip))
		if denied != c.wantDeny || rule != c.wantRule {
			t.Errorf("%s %s from %s: denied=%v rule=%q, want denied=%v rule=%q",
				c.host, c.path, c.ip, denied, rule, c.wantDeny, c.wantRule)
		}
	}
}

func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

func newEngine(t *testing.T, cfg serverconfig.SecurityConfig) *Engine {
	t.Helper()
	e, err := NewEngine(cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestWAFMiddleware(t *testing.T) {
	e := newEngine(t, serverconfig.SecurityConfig{Firewall: fwConfig()})
	h := e.WrapWAF(okHandler())

	req := httptest.NewRequest("GET", "http://any.example.com/.env", nil)
	req.RemoteAddr = "1.2.3.4:555"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("probe path: status=%d, want 403", rr.Code)
	}

	// Dot segments cannot dodge a path rule.
	req = httptest.NewRequest("GET", "http://any.example.com/public/../.git/config", nil)
	req.RemoteAddr = "1.2.3.4:555"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("dot-segment probe: status=%d, want 403", rr.Code)
	}

	// Office CIDR reaches admin; outsiders don't.
	req = httptest.NewRequest("GET", "http://admin.example.com:443/", nil)
	req.RemoteAddr = "203.0.113.5:1000"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("office admin: status=%d, want 200", rr.Code)
	}
	req = httptest.NewRequest("GET", "http://admin.example.com/", nil)
	req.RemoteAddr = "198.51.100.5:1000"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("outside admin: status=%d, want 403", rr.Code)
	}
}

func TestWAFSizeCap(t *testing.T) {
	cfg := serverconfig.SecurityConfig{Firewall: serverconfig.FirewallConfig{
		Enabled:         true,
		MaxRequestBytes: 10,
	}}
	e := newEngine(t, cfg)
	h := e.WrapWAF(okHandler())

	req := httptest.NewRequest("POST", "http://x.example.com/upload", strings.NewReader(strings.Repeat("a", 100)))
	req.RemoteAddr = "1.2.3.4:555"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: status=%d, want 413", rr.Code)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	cfg := serverconfig.SecurityConfig{RateLimit: serverconfig.RateLimitConfig{
		Enabled: true,
		Default: serverconfig.RateLimitRule{Key: "ip", Rate: "60/minute", Burst: 2},
		Overrides: []serverconfig.RateLimitOverride{
			{Hosts: []string{"api.example.com"}, RateLimitRule: serverconfig.RateLimitRule{Key: "ip", Rate: "60/minute", Burst: 1}},
		},
	}}
	e := newEngine(t, cfg)
	h := e.WrapRateLimit(okHandler())

	send := func(host, ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://"+host+"/", nil)
		req.RemoteAddr = ip + ":1234"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// Default limiter: burst 2 per IP.
	if rr := send("web.example.com", "1.1.1.1"); rr.Code != 200 {
		t.Fatalf("request 1: %d", rr.Code)
	}
	if rr := send("web.example.com", "1.1.1.1"); rr.Code != 200 {
		t.Fatalf("request 2: %d", rr.Code)
	}
	rr := send("web.example.com", "1.1.1.1")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("request 3: status=%d, want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
	// Different client IP has its own bucket.
	if rr := send("web.example.com", "2.2.2.2"); rr.Code != 200 {
		t.Fatalf("other ip: %d", rr.Code)
	}
	// Override host: burst 1.
	if rr := send("api.example.com", "3.3.3.3"); rr.Code != 200 {
		t.Fatalf("api request 1: %d", rr.Code)
	}
	if rr := send("api.example.com", "3.3.3.3"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("api request 2: status=%d, want 429", rr.Code)
	}
}

func TestEngineHotReloadSwapsRules(t *testing.T) {
	e := newEngine(t, serverconfig.SecurityConfig{Firewall: fwConfig()})
	h := e.WrapWAF(okHandler())

	req := httptest.NewRequest("GET", "http://any.example.com/.env", nil)
	req.RemoteAddr = "1.2.3.4:555"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("pre-reload: %d, want 403", rr.Code)
	}

	// Reload with an empty rule list: everything allowed now.
	if err := e.Reload(serverconfig.SecurityConfig{Firewall: serverconfig.FirewallConfig{Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("post-reload: %d, want 200", rr.Code)
	}
}

func TestHostGlob(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*", "anything.example.com", true},
		{"admin.example.com", "admin.example.com", true},
		{"admin.example.com", "admin.example.org", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "notexample.com", false},
	}
	for _, c := range cases {
		if got := compileHostGlob(c.pattern).matches(c.host); got != c.want {
			t.Errorf("glob %q vs %q: got %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}
