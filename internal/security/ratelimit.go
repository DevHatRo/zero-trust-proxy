// Package security implements the server's pre-dispatch edge
// protections: a sharded per-key token-bucket rate limiter and an
// ordered allow/deny firewall with a request-size cap. Both run before
// a request reaches agent dispatch, so floods and obvious junk are
// rejected without consuming agent bandwidth. They complement — not
// replace — the per-service route policies the agent enforces.
package security

import (
	"fmt"
	"hash/fnv"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	shardCount = 256 // power of two; shard index = fnv32a(key) & (shardCount-1)

	// Idle buckets are dropped by the background sweeper so IP churn
	// cannot grow memory without bound.
	evictInterval = time.Minute
	idleTTL       = 10 * time.Minute
)

// ParseRate parses "<n>/<unit>" where unit is s|m|h or
// second|minute|hour, returning tokens per second.
func ParseRate(spec string) (perSecond float64, err error) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid rate %q, expected \"<n>/<s|m|h>\"", spec)
	}
	n, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid rate count in %q", spec)
	}
	var per time.Duration
	switch strings.ToLower(strings.TrimSpace(parts[1])) {
	case "s", "second":
		per = time.Second
	case "m", "minute":
		per = time.Minute
	case "h", "hour":
		per = time.Hour
	default:
		return 0, fmt.Errorf("invalid rate unit in %q, expected s|m|h", spec)
	}
	return float64(n) / per.Seconds(), nil
}

// rateCount returns the "<n>" part of a validated rate spec; used as
// the default burst.
func rateCount(spec string) int {
	n, _ := strconv.Atoi(strings.SplitN(spec, "/", 2)[0])
	return n
}

type bucket struct {
	tokens float64
	last   time.Time
}

type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

// Limiter is a sharded token-bucket limiter. One instance per
// configured rule (default + each override); buckets are keyed by the
// configured key strategy (client IP, host, or both).
type Limiter struct {
	rate   float64 // tokens per second
	burst  float64
	now    func() time.Time // stubbed in tests
	shards [shardCount]*shard
}

// NewLimiter builds a limiter from a validated rate spec. burst <= 0
// defaults to the rate count (allow one full window in a burst).
func NewLimiter(rateSpec string, burst int) (*Limiter, error) {
	perSecond, err := ParseRate(rateSpec)
	if err != nil {
		return nil, err
	}
	if burst <= 0 {
		burst = rateCount(rateSpec)
	}
	if burst < 1 {
		burst = 1
	}
	l := &Limiter{rate: perSecond, burst: float64(burst), now: time.Now}
	for i := range l.shards {
		l.shards[i] = &shard{buckets: make(map[string]*bucket)}
	}
	return l, nil
}

func (l *Limiter) shardFor(key string) *shard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return l.shards[h.Sum32()&(shardCount-1)]
}

// Allow consumes one token from key's bucket. When denied, retryAfter
// is the whole seconds until one token refills (>= 1).
func (l *Limiter) Allow(key string) (ok bool, retryAfter int) {
	s := l.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	now := l.now()
	b, exists := s.buckets[key]
	if !exists {
		b = &bucket{tokens: l.burst, last: now}
		s.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	retry := int(math.Ceil((1 - b.tokens) / l.rate))
	if retry < 1 {
		retry = 1
	}
	return false, retry
}

// sweep drops buckets idle longer than ttl. Per-shard locking keeps
// the hot path from stalling behind a full-map scan.
func (l *Limiter) sweep(ttl time.Duration) {
	cutoff := l.now().Add(-ttl)
	for _, s := range l.shards {
		s.mu.Lock()
		for key, b := range s.buckets {
			if b.last.Before(cutoff) {
				delete(s.buckets, key)
			}
		}
		s.mu.Unlock()
	}
}

// Buckets returns the live bucket count (for the metrics gauge).
func (l *Limiter) Buckets() int {
	n := 0
	for _, s := range l.shards {
		s.mu.Lock()
		n += len(s.buckets)
		s.mu.Unlock()
	}
	return n
}
