package security

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/logger"
	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

var log = logger.WithComponent("security")

// Hooks are optional metric callbacks; nil funcs are skipped. The
// security package stays free of the prometheus dependency.
type Hooks struct {
	RateLimited  func(keyStrategy string)
	FirewallDeny func(rule string)
	Oversize     func()
}

// rlOverride is one compiled rate-limit override: first hostname match
// wins, its own Limiter applies.
type rlOverride struct {
	hosts []hostGlob
	key   string
	lim   *Limiter
}

// rateLimitSet is the compiled limiter configuration. Immutable;
// swapped atomically on hot reload (which resets bucket state —
// acceptable on an explicit reload).
type rateLimitSet struct {
	defKey    string
	def       *Limiter
	overrides []rlOverride
}

func compileRateLimit(cfg serverconfig.RateLimitConfig) (*rateLimitSet, error) {
	def, err := NewLimiter(cfg.Default.Rate, cfg.Default.Burst)
	if err != nil {
		return nil, err
	}
	set := &rateLimitSet{defKey: keyOrDefault(cfg.Default.Key), def: def}
	for _, o := range cfg.Overrides {
		lim, err := NewLimiter(o.Rate, o.Burst)
		if err != nil {
			return nil, err
		}
		ov := rlOverride{key: keyOrDefault(o.Key), lim: lim}
		for _, h := range o.Hosts {
			ov.hosts = append(ov.hosts, compileHostGlob(h))
		}
		set.overrides = append(set.overrides, ov)
	}
	return set, nil
}

func keyOrDefault(k string) string {
	if k == "" {
		return "ip"
	}
	return k
}

// forHost returns the limiter and key strategy for a request host.
func (s *rateLimitSet) forHost(host string) (*Limiter, string) {
	for i := range s.overrides {
		if anyHost(s.overrides[i].hosts, host) {
			return s.overrides[i].lim, s.overrides[i].key
		}
	}
	return s.def, s.defKey
}

func (s *rateLimitSet) buckets() int {
	n := s.def.Buckets()
	for i := range s.overrides {
		n += s.overrides[i].lim.Buckets()
	}
	return n
}

func (s *rateLimitSet) sweep(ttl time.Duration) {
	s.def.sweep(ttl)
	for i := range s.overrides {
		s.overrides[i].lim.sweep(ttl)
	}
}

// Engine owns the compiled firewall and rate-limit sets behind atomic
// pointers (lock-free hot path, SIGHUP swaps) plus the eviction
// sweeper goroutine.
type Engine struct {
	hooks Hooks
	fw    atomic.Pointer[firewallSet]
	rl    atomic.Pointer[rateLimitSet]
	stop  chan struct{}
}

// NewEngine compiles cfg. Disabled sections leave the corresponding
// pointer nil and their middleware becomes a pass-through.
func NewEngine(cfg serverconfig.SecurityConfig, hooks Hooks) (*Engine, error) {
	e := &Engine{hooks: hooks, stop: make(chan struct{})}
	if err := e.install(cfg); err != nil {
		return nil, err
	}
	if cfg.RateLimit.Enabled {
		go e.sweeper()
	}
	return e, nil
}

// Reload recompiles cfg and swaps it in. In-flight requests keep the
// old sets; rate-limit bucket state resets.
func (e *Engine) Reload(cfg serverconfig.SecurityConfig) error {
	return e.install(cfg)
}

func (e *Engine) install(cfg serverconfig.SecurityConfig) error {
	var fw *firewallSet
	var rl *rateLimitSet
	if cfg.Firewall.Enabled {
		var err error
		if fw, err = compileFirewall(cfg.Firewall); err != nil {
			return err
		}
	}
	if cfg.RateLimit.Enabled {
		var err error
		if rl, err = compileRateLimit(cfg.RateLimit); err != nil {
			return err
		}
	}
	e.fw.Store(fw)
	e.rl.Store(rl)
	return nil
}

// Close stops the eviction sweeper.
func (e *Engine) Close() {
	select {
	case <-e.stop:
	default:
		close(e.stop)
	}
}

func (e *Engine) sweeper() {
	tkr := time.NewTicker(evictInterval)
	defer tkr.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-tkr.C:
			if rl := e.rl.Load(); rl != nil {
				rl.sweep(idleTTL)
			}
		}
	}
}

// Buckets reports the live rate-limit bucket count for the gauge.
func (e *Engine) Buckets() int {
	if rl := e.rl.Load(); rl != nil {
		return rl.buckets()
	}
	return 0
}

// remoteIP extracts the client IP from r.RemoteAddr. NEVER derived
// from X-Forwarded-For — the proxy is the TLS termination point and
// client-supplied forwarding headers are attacker-controlled.
func remoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

// hostOnly strips an optional port from a Host header value.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(hostport)
}

// WrapWAF applies the request-size cap and the firewall rule list.
// Cheapest rejects first: a firewall-denied request never consumes a
// rate-limit token (WAF wraps outside WrapRateLimit in the chain).
func (e *Engine) WrapWAF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fw := e.fw.Load()
		if fw == nil {
			next.ServeHTTP(w, r)
			return
		}
		if fw.maxRequestBytes > 0 {
			if r.ContentLength > fw.maxRequestBytes {
				if e.hooks.Oversize != nil {
					e.hooks.Oversize()
				}
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			// Chunked bodies with no Content-Length: cap while reading.
			// Downstream ReadAll surfaces *http.MaxBytesError, which the
			// router maps to 413.
			r.Body = http.MaxBytesReader(w, r.Body, fw.maxRequestBytes)
		}
		host := hostOnly(r.Host)
		path := CleanPath(r.URL.Path)
		if denied, rule := fw.decision(host, path, r.Method, remoteIP(r)); denied {
			if e.hooks.FirewallDeny != nil {
				e.hooks.FirewallDeny(rule)
			}
			log.Warn("firewall deny rule=%s host=%s method=%s src=%s", rule, host, r.Method, r.RemoteAddr)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// WrapRateLimit applies the token-bucket limiter for the request's
// host, keyed by the configured strategy.
func (e *Engine) WrapRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rl := e.rl.Load()
		if rl == nil {
			next.ServeHTTP(w, r)
			return
		}
		host := hostOnly(r.Host)
		lim, strategy := rl.forHost(host)
		key := bucketKey(strategy, r, host)
		if ok, retry := lim.Allow(key); !ok {
			if e.hooks.RateLimited != nil {
				e.hooks.RateLimited(strategy)
			}
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bucketKey(strategy string, r *http.Request, host string) string {
	switch strategy {
	case "host":
		return host
	case "ip+host":
		return ipString(r) + "\x00" + host
	default: // "ip"
		return ipString(r)
	}
}

func ipString(r *http.Request) string {
	if ip := remoteIP(r); ip != nil {
		return ip.String()
	}
	// Unparseable RemoteAddr (shouldn't happen with net/http) shares
	// one bucket rather than bypassing the limit.
	return "unknown"
}

// IsBodyTooLarge reports whether err came from the MaxBytesReader cap,
// so callers reading the body can answer 413 instead of a generic 400.
func IsBodyTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}
