package server

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// metrics is the project's tiny stdlib-only Prometheus exporter. It
// avoids pulling in the official `prometheus/client_golang` (and the
// Caddy-era 100+ transitive deps that came with it) by emitting the
// text format directly. If the project later needs richer metrics
// (histograms with custom buckets, native exemplars), swap this out.
type metrics struct {
	requestsTotal struct {
		mu     sync.RWMutex
		counts map[metricKey]uint64 // status_class → count
	}
	requestDuration struct {
		mu      sync.RWMutex
		buckets [10]uint64 // bounds defined by durationBuckets
		count   uint64
		sum     float64 // seconds
	}
	wsSessions     int64 // atomic — current count
	agentsRegistered int64 // atomic — current count
}

type metricKey struct {
	method string
	status string // "2xx", "3xx", "4xx", "5xx", "other"
}

// durationBuckets are the upper bounds in seconds, matching common
// reverse-proxy SLOs.
var durationBuckets = [...]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 10}

func newMetrics() *metrics {
	m := &metrics{}
	m.requestsTotal.counts = make(map[metricKey]uint64, 32)
	return m
}

// observeRequest records a finished HTTP request.
func (m *metrics) observeRequest(method string, status int, d time.Duration) {
	if m == nil {
		return
	}
	key := metricKey{method: method, status: statusClass(status)}

	m.requestsTotal.mu.Lock()
	m.requestsTotal.counts[key]++
	m.requestsTotal.mu.Unlock()

	secs := d.Seconds()
	m.requestDuration.mu.Lock()
	m.requestDuration.count++
	m.requestDuration.sum += secs
	for i, bound := range durationBuckets {
		if secs <= bound {
			m.requestDuration.buckets[i]++
		}
	}
	m.requestDuration.mu.Unlock()
}

func (m *metrics) setWebSocketSessions(n int)   { atomic.StoreInt64(&m.wsSessions, int64(n)) }
func (m *metrics) setAgentsRegistered(n int)    { atomic.StoreInt64(&m.agentsRegistered, int64(n)) }

func statusClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	default:
		return "other"
	}
}

// ServeHTTP emits the Prometheus text exposition format.
func (m *metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// requests_total
	_, _ = w.Write([]byte("# HELP ztp_requests_total Number of HTTP requests handled by the proxy.\n"))
	_, _ = w.Write([]byte("# TYPE ztp_requests_total counter\n"))
	m.requestsTotal.mu.RLock()
	for k, v := range m.requestsTotal.counts {
		_, _ = w.Write([]byte("ztp_requests_total{method=\"" + k.method + "\",status=\"" + k.status + "\"} " + strconv.FormatUint(v, 10) + "\n"))
	}
	m.requestsTotal.mu.RUnlock()

	// request_duration_seconds histogram
	_, _ = w.Write([]byte("# HELP ztp_request_duration_seconds Request duration in seconds.\n"))
	_, _ = w.Write([]byte("# TYPE ztp_request_duration_seconds histogram\n"))
	m.requestDuration.mu.RLock()
	for i, bound := range durationBuckets {
		_, _ = w.Write([]byte("ztp_request_duration_seconds_bucket{le=\"" + strconv.FormatFloat(bound, 'f', -1, 64) + "\"} " + strconv.FormatUint(m.requestDuration.buckets[i], 10) + "\n"))
	}
	_, _ = w.Write([]byte("ztp_request_duration_seconds_bucket{le=\"+Inf\"} " + strconv.FormatUint(m.requestDuration.count, 10) + "\n"))
	_, _ = w.Write([]byte("ztp_request_duration_seconds_sum " + strconv.FormatFloat(m.requestDuration.sum, 'f', -1, 64) + "\n"))
	_, _ = w.Write([]byte("ztp_request_duration_seconds_count " + strconv.FormatUint(m.requestDuration.count, 10) + "\n"))
	m.requestDuration.mu.RUnlock()

	// agents_registered gauge
	_, _ = w.Write([]byte("# HELP ztp_agents_registered Currently registered agents.\n"))
	_, _ = w.Write([]byte("# TYPE ztp_agents_registered gauge\n"))
	_, _ = w.Write([]byte("ztp_agents_registered " + strconv.FormatInt(atomic.LoadInt64(&m.agentsRegistered), 10) + "\n"))

	// websocket_sessions gauge
	_, _ = w.Write([]byte("# HELP ztp_websocket_sessions Active WebSocket sessions.\n"))
	_, _ = w.Write([]byte("# TYPE ztp_websocket_sessions gauge\n"))
	_, _ = w.Write([]byte("ztp_websocket_sessions " + strconv.FormatInt(atomic.LoadInt64(&m.wsSessions), 10) + "\n"))
}

// metricsMiddleware wraps an http.Handler so request counts and
// durations land in m. The wrapper also captures the response status
// via a thin ResponseWriter shim.
func metricsMiddleware(m *metrics, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		m.observeRequest(r.Method, rw.status, time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	s.status = code
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		// Implicit 200 like net/http does.
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

// Hijack and Flush are forwarded so middleware layering does not
// silently disable the WebSocket / streaming-download paths in
// ztrouter, which type-assert these interfaces on the ResponseWriter.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("metrics: underlying ResponseWriter is not a Hijacker")
	}
	return h.Hijack()
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
