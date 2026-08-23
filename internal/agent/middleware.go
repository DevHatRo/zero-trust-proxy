package agent

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

// Route middleware engine. Compiles the `routes:` section of a service
// config into an executable policy and evaluates it on every HTTP request
// before the request is proxied to an upstream. Unknown handler types and
// malformed handler configs are compile errors, so a policy that cannot be
// enforced fails at config load instead of being silently ignored.

// Handler type names accepted in a route's `handle:` list.
const (
	handlerReverseProxy = "reverse_proxy"
	handlerIPWhitelist  = "ip_whitelist"
	handlerRateLimit    = "rate_limit"
)

// BlockedBy values carried back to the server on denied requests.
const (
	blockedByIPWhitelist = "ip_whitelist"
	blockedByRateLimit   = "rate_limit"
	blockedByNoRoute     = "no_route"
)

// policyRequest is the request view given to policy evaluation.
type policyRequest struct {
	Method   string
	Path     string // decoded path, so percent-encoding cannot bypass a match
	Query    url.Values
	Headers  map[string][]string
	ClientIP string
}

// policyDecision is the outcome of evaluating a request against a policy.
type policyDecision struct {
	Allowed    bool
	Status     int
	BlockedBy  string // blockedBy* constant; empty when allowed
	RetryAfter int    // seconds until a rate-limited client may retry; 0 otherwise
}

var policyAllow = policyDecision{Allowed: true}

// routeHandler is one compiled middleware in a route's handle chain.
// check returns nil to pass the request to the next handler.
type routeHandler interface {
	check(req *policyRequest) *policyDecision
}

// --- reverse_proxy -----------------------------------------------------------

// reverseProxyHandler is the terminal handler: reaching it means the request
// is allowed to be proxied. It never denies.
type reverseProxyHandler struct{}

func (reverseProxyHandler) check(*policyRequest) *policyDecision { return nil }

// --- ip_whitelist ------------------------------------------------------------

type ipWhitelistHandler struct {
	nets []*net.IPNet
}

func newIPWhitelistHandler(config map[string]interface{}) (*ipWhitelistHandler, error) {
	entries, err := stringList(config, "allowed_ips")
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("ip_whitelist: allowed_ips must list at least one IP or CIDR")
	}
	h := &ipWhitelistHandler{}
	for _, entry := range entries {
		ipNet, err := parseIPOrCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("ip_whitelist: %w", err)
		}
		h.nets = append(h.nets, ipNet)
	}
	return h, nil
}

// parseIPOrCIDR accepts "1.2.3.4/32" style CIDRs and bare IPs (which get a
// full-length mask).
func parseIPOrCIDR(entry string) (*net.IPNet, error) {
	if strings.Contains(entry, "/") {
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", entry)
		}
		return ipNet, nil
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP %q", entry)
	}
	bits := 128
	if v4 := ip.To4(); v4 != nil {
		ip = v4
		bits = 32
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// check fails closed: a request whose client IP cannot be determined is
// denied, since letting it through would defeat the whitelist.
func (h *ipWhitelistHandler) check(req *policyRequest) *policyDecision {
	ip := net.ParseIP(req.ClientIP)
	if ip != nil {
		for _, n := range h.nets {
			if n.Contains(ip) {
				return nil
			}
		}
	}
	return &policyDecision{Status: http.StatusForbidden, BlockedBy: blockedByIPWhitelist}
}

// --- rate_limit --------------------------------------------------------------

// rateLimitHandler is a per-client-IP token bucket. State lives on the
// compiled handler, which persists across requests for the lifetime of the
// loaded config (a hot reload rebuilds policies and resets the buckets).
type rateLimitHandler struct {
	rate  float64 // tokens per second
	burst float64

	mu        sync.Mutex
	buckets   map[string]*tokenBucket
	lastSweep time.Time
	now       func() time.Time // stubbed in tests
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// sweep parameters: once the bucket map grows past sweepThreshold entries,
// idle (fully refilled) buckets are dropped at most once per sweepInterval.
const (
	sweepThreshold = 4096
	sweepInterval  = time.Minute
)

func newRateLimitHandler(config map[string]interface{}) (*rateLimitHandler, error) {
	rateSpec, err := stringValue(config, "rate")
	if err != nil {
		return nil, err
	}
	if rateSpec == "" {
		return nil, fmt.Errorf("rate_limit: rate is required (e.g. \"10/minute\")")
	}
	count, per, err := parseRate(rateSpec)
	if err != nil {
		return nil, err
	}
	burst, err := intValue(config, "burst")
	if err != nil {
		return nil, err
	}
	// Default burst to the full per-window count; clamp to at least 1 so a
	// bucket can ever admit a request.
	if burst <= 0 {
		burst = count
	}
	if burst < 1 {
		burst = 1
	}
	return &rateLimitHandler{
		rate:    float64(count) / per.Seconds(),
		burst:   float64(burst),
		buckets: make(map[string]*tokenBucket),
		now:     time.Now,
	}, nil
}

// parseRate parses "N/second", "N/minute", "N/hour".
func parseRate(spec string) (count int, per time.Duration, err error) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("rate_limit: invalid rate %q, expected \"<count>/<second|minute|hour>\"", spec)
	}
	count, err = strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || count <= 0 {
		return 0, 0, fmt.Errorf("rate_limit: invalid rate count in %q", spec)
	}
	switch strings.ToLower(strings.TrimSpace(parts[1])) {
	case "second":
		per = time.Second
	case "minute":
		per = time.Minute
	case "hour":
		per = time.Hour
	default:
		return 0, 0, fmt.Errorf("rate_limit: invalid rate unit in %q, expected second, minute, or hour", spec)
	}
	return count, per, nil
}

func (h *rateLimitHandler) check(req *policyRequest) *policyDecision {
	// Requests with no determinable client IP share one bucket rather than
	// bypassing the limit.
	key := req.ClientIP
	if key == "" {
		key = "unknown"
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	now := h.now()
	b, ok := h.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: h.burst, last: now}
		h.buckets[key] = b
	}

	b.tokens = math.Min(h.burst, b.tokens+now.Sub(b.last).Seconds()*h.rate)
	b.last = now
	// Sweep on every check, not just insertions — once all active clients
	// have buckets no new keys are inserted, and idle entries would otherwise
	// accumulate forever. Runs after b.last is refreshed so the sweep can
	// never evict the bucket we are about to debit.
	h.maybeSweep(now)
	if b.tokens >= 1 {
		b.tokens--
		return nil
	}
	retry := int(math.Ceil((1 - b.tokens) / h.rate))
	if retry < 1 {
		retry = 1
	}
	return &policyDecision{
		Status:     http.StatusTooManyRequests,
		BlockedBy:  blockedByRateLimit,
		RetryAfter: retry,
	}
}

// maybeSweep drops buckets idle long enough to have fully refilled — they are
// indistinguishable from fresh ones, so removing them cannot change behavior.
// Called with h.mu held.
func (h *rateLimitHandler) maybeSweep(now time.Time) {
	if len(h.buckets) < sweepThreshold || now.Sub(h.lastSweep) < sweepInterval {
		return
	}
	h.lastSweep = now
	fullAfter := time.Duration(h.burst / h.rate * float64(time.Second))
	for key, b := range h.buckets {
		if now.Sub(b.last) >= fullAfter {
			delete(h.buckets, key)
		}
	}
}

// --- handler config helpers --------------------------------------------------
// Handler configs arrive as map[string]interface{} straight from YAML, so
// these coerce the loosely-typed values and reject wrong types loudly.

func stringList(config map[string]interface{}, key string) ([]string, error) {
	raw, ok := config[key]
	if !ok || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be a list of strings", key)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s must be a list of strings (got %T)", key, item)
		}
		out = append(out, s)
	}
	return out, nil
}

func stringValue(config map[string]interface{}, key string) (string, error) {
	raw, ok := config[key]
	if !ok || raw == nil {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string (got %T)", key, raw)
	}
	return s, nil
}

func intValue(config map[string]interface{}, key string) (int, error) {
	raw, ok := config[key]
	if !ok || raw == nil {
		return 0, nil
	}
	switch v := raw.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("%s must be an integer (got %T)", key, raw)
	}
}

// --- route matching ----------------------------------------------------------

type compiledMatch struct {
	matchAll  bool
	exactPath string              // set when the pattern has no wildcard
	prefix    string              // set for "…/*" and "…*" patterns
	method    string              // uppercase; "" matches any method
	headers   map[string][]string // canonical keys; request needs one of the listed values per key
	query     map[string]string
}

func compileMatch(m MatchConfig) compiledMatch {
	cm := compiledMatch{method: strings.ToUpper(m.Method), query: m.Query}
	switch {
	case m.Path == "" || m.Path == "*" || m.Path == "/*":
		cm.matchAll = true
	case strings.HasSuffix(m.Path, "/*"):
		// "/api/*" matches "/api" and everything under "/api/".
		cm.prefix = m.Path[:len(m.Path)-1] // keep the trailing slash
	case strings.HasSuffix(m.Path, "*"):
		cm.prefix = m.Path[:len(m.Path)-1]
	default:
		cm.exactPath = m.Path
	}
	if len(m.Headers) > 0 {
		cm.headers = make(map[string][]string, len(m.Headers))
		for k, v := range m.Headers {
			cm.headers[http.CanonicalHeaderKey(k)] = v
		}
	}
	return cm
}

func (cm *compiledMatch) matches(req *policyRequest) bool {
	if cm.method != "" && cm.method != strings.ToUpper(req.Method) {
		return false
	}
	switch {
	case cm.matchAll:
	case cm.exactPath != "":
		if req.Path != cm.exactPath {
			return false
		}
	case strings.HasSuffix(cm.prefix, "/"):
		if req.Path != strings.TrimSuffix(cm.prefix, "/") && !strings.HasPrefix(req.Path, cm.prefix) {
			return false
		}
	default:
		if !strings.HasPrefix(req.Path, cm.prefix) {
			return false
		}
	}
	for key, allowed := range cm.headers {
		if !headerHasAny(req.Headers[key], allowed) {
			return false
		}
	}
	for key, want := range cm.query {
		if req.Query.Get(key) != want {
			return false
		}
	}
	return true
}

func headerHasAny(have, allowed []string) bool {
	for _, h := range have {
		for _, a := range allowed {
			if h == a {
				return true
			}
		}
	}
	return false
}

// --- policy ------------------------------------------------------------------

type compiledRoute struct {
	match    compiledMatch
	handlers []routeHandler
}

// routePolicy is the compiled policy for one service. All hosts of a service
// share one instance, so rate-limit buckets are per service, not per host.
type routePolicy struct {
	global []routeHandler // from global_middleware; runs before every route chain
	routes []compiledRoute
}

// evaluate finds the first matching route (first-match wins) and runs the
// global chain then the route's handle chain. A request matching no route is
// denied: defined routes are an explicit policy, and proxying around them
// would reopen the silent-bypass hole this engine exists to close.
func (p *routePolicy) evaluate(req *policyRequest) policyDecision {
	for i := range p.routes {
		if !p.routes[i].match.matches(req) {
			continue
		}
		for _, h := range p.global {
			if dec := h.check(req); dec != nil {
				return *dec
			}
		}
		for _, h := range p.routes[i].handlers {
			if dec := h.check(req); dec != nil {
				return *dec
			}
		}
		return policyAllow
	}
	return policyDecision{Status: http.StatusNotFound, BlockedBy: blockedByNoRoute}
}

// compileMiddleware compiles one `handle:` entry. Unknown types are errors so
// a config that names a handler this agent cannot enforce refuses to load.
func compileMiddleware(mw MiddlewareConfig) (routeHandler, error) {
	switch mw.Type {
	case handlerReverseProxy:
		return reverseProxyHandler{}, nil
	case handlerIPWhitelist:
		return newIPWhitelistHandler(mw.Config)
	case handlerRateLimit:
		return newRateLimitHandler(mw.Config)
	case "":
		return nil, fmt.Errorf("handler is missing a type")
	default:
		return nil, fmt.Errorf("unknown handler type %q (supported: %s, %s, %s)",
			mw.Type, handlerReverseProxy, handlerIPWhitelist, handlerRateLimit)
	}
}

func compileMiddlewareChain(mws []MiddlewareConfig) ([]routeHandler, error) {
	handlers := make([]routeHandler, 0, len(mws))
	for i, mw := range mws {
		h, err := compileMiddleware(mw)
		if err != nil {
			return nil, fmt.Errorf("handle[%d]: %w", i, err)
		}
		handlers = append(handlers, h)
	}
	return handlers, nil
}

// compileRoutes builds a routePolicy from a service's routes. The global
// handler chain is shared: pass the same slice for every service so global
// rate limits count across services (see buildRoutePolicies).
func compileRoutes(routes []RouteConfig, global []routeHandler) (*routePolicy, error) {
	if len(routes) == 0 {
		routes = []RouteConfig{createDefaultRoute()}
	}
	p := &routePolicy{global: global}
	for i, route := range routes {
		handlers, err := compileMiddlewareChain(route.Handle)
		if err != nil {
			return nil, fmt.Errorf("routes[%d]: %w", i, err)
		}
		if len(handlers) == 0 {
			return nil, fmt.Errorf("routes[%d]: handle must list at least one handler", i)
		}
		p.routes = append(p.routes, compiledRoute{match: compileMatch(route.Match), handlers: handlers})
	}
	return p, nil
}

// buildRoutePolicies compiles every service's routes, keyed by host. Hosts of
// one service share a policy instance (shared rate-limit buckets); the global
// middleware chain is compiled once and shared by all services.
func buildRoutePolicies(config *AgentConfig) (map[string]*routePolicy, error) {
	global, err := compileMiddlewareChain(config.GlobalMiddleware)
	if err != nil {
		return nil, fmt.Errorf("global_middleware: %w", err)
	}
	policies := make(map[string]*routePolicy)
	for i := range config.Services {
		svc := &config.Services[i]
		policy, err := compileRoutes(svc.Routes, global)
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", svc.ID, err)
		}
		for _, host := range svc.GetAllHosts() {
			policies[host] = policy
		}
	}
	return policies, nil
}

// --- request-side helpers ----------------------------------------------------

// clientIPFromHeaders extracts the client IP the proxy stamped on the request.
// The router overwrites X-Forwarded-For / X-Real-IP with the values from the
// real client connection, so these are trustworthy here.
func clientIPFromHeaders(headers map[string][]string) string {
	if xff := headerFirst(headers, "X-Forwarded-For"); xff != "" {
		if first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); first != "" {
			return first
		}
	}
	if realIP := headerFirst(headers, "X-Real-IP"); realIP != "" && !strings.Contains(realIP, "{") {
		return realIP
	}
	return ""
}

func headerFirst(headers map[string][]string, key string) string {
	if v := headers[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// checkRoutePolicy evaluates the request against the host's compiled route
// policy. Hosts with no policy (e.g. services added at runtime without local
// route config) are allowed, matching the pre-policy behavior.
func (a *Agent) checkRoutePolicy(host string, httpData *common.HTTPData) policyDecision {
	a.mu.RLock()
	policy := a.routePolicies[host]
	a.mu.RUnlock()
	if policy == nil {
		return policyAllow
	}

	path := httpData.URL
	var query url.Values
	if u, err := url.Parse(httpData.URL); err == nil {
		path = u.Path // decoded, so %-encoding can't dodge a path match
		query = u.Query()
	}
	return policy.evaluate(&policyRequest{
		Method:   httpData.Method,
		Path:     path,
		Query:    query,
		Headers:  httpData.Headers,
		ClientIP: clientIPFromHeaders(httpData.Headers),
	})
}

// sendBlockedResponse reports a policy denial to the server. BlockedBy makes
// the router render its branded error page; older servers ignore the field
// and pass the plain-text status body through unchanged.
func (a *Agent) sendBlockedResponse(msgID string, dec policyDecision) {
	headers := map[string][]string{
		"Content-Type":  {"text/plain; charset=utf-8"},
		"Cache-Control": {"no-store"},
	}
	if dec.RetryAfter > 0 {
		headers["Retry-After"] = []string{strconv.Itoa(dec.RetryAfter)}
	}
	msg := &common.Message{
		Type: "http_response",
		ID:   msgID,
		HTTP: &common.HTTPData{
			StatusCode:    dec.Status,
			StatusMessage: fmt.Sprintf("%d %s", dec.Status, http.StatusText(dec.Status)),
			Headers:       headers,
			Body:          []byte(http.StatusText(dec.Status)),
			BlockedBy:     dec.BlockedBy,
			RetryAfter:    dec.RetryAfter,
		},
	}
	if err := a.SendMessage(msg); err != nil {
		log.Error("❌ Failed to send blocked response id=%s: %v", msgID, err)
	}
}
