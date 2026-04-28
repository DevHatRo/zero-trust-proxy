package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetrics_TextFormat(t *testing.T) {
	m := newMetrics()
	m.observeRequest(http.MethodGet, http.StatusOK, 12*time.Millisecond)
	m.observeRequest(http.MethodGet, http.StatusInternalServerError, 800*time.Millisecond)
	m.observeRequest(http.MethodPost, http.StatusCreated, 50*time.Millisecond)
	m.setAgentsRegistered(3)
	m.setWebSocketSessions(2)
	m.setAgentServices(map[string]int{"agent-a": 2, "agent-b": 5})

	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("Content-Type = %q", got)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`ztp_requests_total{method="GET",status="2xx"} 1`,
		`ztp_requests_total{method="GET",status="5xx"} 1`,
		`ztp_requests_total{method="POST",status="2xx"} 1`,
		`ztp_request_duration_seconds_bucket{le="0.05"} 2`,
		`ztp_request_duration_seconds_bucket{le="+Inf"} 3`,
		`ztp_request_duration_seconds_count 3`,
		`ztp_agents_registered 3`,
		`ztp_websocket_sessions 2`,
		`ztp_agent_services{agent_id="agent-a"} 2`,
		`ztp_agent_services{agent_id="agent-b"} 5`,
		`ztp_build_info{`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("output missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestMetricsMiddleware_RecordsStatus(t *testing.T) {
	m := newMetrics()
	h := metricsMiddleware(m, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	rec2 := httptest.NewRecorder()
	m.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec2.Body.String()

	if !strings.Contains(body, `ztp_requests_total{method="GET",status="4xx"} 1`) {
		t.Fatalf("expected 4xx counter incremented:\n%s", body)
	}
}

func TestStatusClass(t *testing.T) {
	cases := map[int]string{
		200: "2xx",
		201: "2xx",
		301: "3xx",
		418: "4xx",
		500: "5xx",
		0:   "other",
		999: "other",
	}
	for code, want := range cases {
		if got := statusClass(code); got != want {
			t.Errorf("statusClass(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestMetrics_AgentServicesReset(t *testing.T) {
	m := newMetrics()
	m.setAgentServices(map[string]int{"agent-x": 3})

	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `ztp_agent_services{agent_id="agent-x"} 3`) {
		t.Fatal("expected agent-x with 3 services")
	}

	// Agent disconnects — next refresh has no agents.
	m.setAgentServices(map[string]int{})
	rec2 := httptest.NewRecorder()
	m.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(rec2.Body.String(), "agent-x") {
		t.Fatal("agent-x should be gone after reset")
	}
}
