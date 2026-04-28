package server

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// BuildVersion is set by main before the first Server is created so that
// the ztp_build_info metric carries the real binary version. Defaults to
// "dev" when running tests or outside the normal build pipeline.
var BuildVersion = "dev"

type metrics struct {
	requestsTotal   *prometheus.CounterVec
	requestDuration prometheus.Histogram
	agentsRegistered prometheus.Gauge
	wsSessions      prometheus.Gauge
	agentServices   *prometheus.GaugeVec
	reg             *prometheus.Registry
	handler         http.Handler
}

func newMetrics() *metrics {
	reg := prometheus.NewRegistry()

	requestsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ztp_requests_total",
			Help: "Number of HTTP requests handled by the proxy.",
		},
		[]string{"method", "status"},
	)
	requestDuration := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ztp_request_duration_seconds",
		Help:    "Request duration in seconds.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 10},
	})
	agentsRegistered := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ztp_agents_registered",
		Help: "Currently registered agents.",
	})
	wsSessions := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ztp_websocket_sessions",
		Help: "Active WebSocket sessions.",
	})
	agentServices := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ztp_agent_services",
		Help: "Number of services registered per agent.",
	}, []string{"agent_id"})

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ztp_build_info",
		Help: "Build metadata. Always 1.",
	}, []string{"version", "go_version"})
	buildInfo.With(prometheus.Labels{
		"version":    BuildVersion,
		"go_version": runtime.Version(),
	}).Set(1)

	reg.MustRegister(requestsTotal, requestDuration, agentsRegistered, wsSessions, agentServices, buildInfo)

	m := &metrics{
		requestsTotal:    requestsTotal,
		requestDuration:  requestDuration,
		agentsRegistered: agentsRegistered,
		wsSessions:       wsSessions,
		agentServices:    agentServices,
		reg:              reg,
	}
	m.handler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	return m
}

// observeRequest records a finished HTTP request.
func (m *metrics) observeRequest(method string, status int, d time.Duration) {
	if m == nil {
		return
	}
	m.requestsTotal.With(prometheus.Labels{
		"method": method,
		"status": statusClass(status),
	}).Inc()
	m.requestDuration.Observe(d.Seconds())
}

func (m *metrics) setWebSocketSessions(n int)  { m.wsSessions.Set(float64(n)) }
func (m *metrics) setAgentsRegistered(n int)   { m.agentsRegistered.Set(float64(n)) }
func (m *metrics) setAgentServices(counts map[string]int) {
	m.agentServices.Reset()
	for id, n := range counts {
		m.agentServices.With(prometheus.Labels{"agent_id": id}).Set(float64(n))
	}
}

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

// ServeHTTP serves the Prometheus text exposition format.
func (m *metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.handler.ServeHTTP(w, r)
}

// metricsMiddleware wraps an http.Handler so request counts and durations
// land in m. The statusRecorder shim captures the response status code while
// transparently forwarding http.Hijacker and http.Flusher so WebSocket and
// streaming-download paths in ztrouter still work.
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
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

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
