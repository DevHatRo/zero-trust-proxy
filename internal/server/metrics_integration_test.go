package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
	"github.com/devhatro/zero-trust-proxy/internal/types"
)

// TestServer_MetricsIntegration brings up a Server with metrics
// enabled, drives one HTTP request through the public listener, and
// asserts /metrics reflects:
//   - ztp_requests_total{method,status} incremented
//   - ztp_request_duration_seconds_count incremented
//   - ztp_agents_registered gauge updated by the refresh ticker
//
// Builds on the helpers from integration_test.go.
func TestServer_MetricsIntegration(t *testing.T) {
	caCert, caKey := generateCA(t, "TestCA")
	serverCertPath, serverKeyPath, caCertPath := writeServerCerts(t, caCert, caKey)
	publicCertPath, publicKeyPath := writeServerCerts2(t, "smoke.local")
	agentCertPath, agentKeyPath := writeSignedAgentCerts(t, caCert, caKey, "agent-m")

	httpsAddr := freePort(t)
	agentsAddr := freePort(t)
	metricsAddr := freePort(t)

	cfg := &serverconfig.Config{
		Listen: serverconfig.ListenConfig{HTTPS: httpsAddr},
		TLS: serverconfig.TLSConfig{
			Mode:   serverconfig.TLSModeManual,
			Manual: &serverconfig.ManualCert{CertFile: publicCertPath, KeyFile: publicKeyPath},
		},
		Agents: serverconfig.AgentsConfig{
			Listen:    agentsAddr,
			CertFile:  serverCertPath,
			KeyFile:   serverKeyPath,
			CAFile:    caCertPath,
			CheckAddr: freePort(t),
		},
		Router:  serverconfig.RouterConfig{RequestTimeout: 5 * time.Second},
		Metrics: serverconfig.MetricsConfig{Addr: metricsAddr},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// Connect a fake agent so the request resolves to a real agent
	// (otherwise the router returns 503, which still counts but the
	// test reads better with a 2xx round-trip).
	conn, err := tls.Dial("tcp", agentsAddr, &tls.Config{
		Certificates: []tls.Certificate{loadCert(t, agentCertPath, agentKeyPath)},
		RootCAs:      poolFromCert(caCert),
		ServerName:   "test-server",
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Dial agents: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	// register + service_add
	_ = enc.Encode(&common.Message{Type: "register", ID: "agent-m"})
	var ack common.Message
	_ = dec.Decode(&ack)

	_ = enc.Encode(&common.Message{
		Type: "service_add",
		ID:   "add",
		Service: &common.ServiceConfig{
			ServiceConfig: types.ServiceConfig{
				Hostname: "metrics.example",
				Backend:  "127.0.0.1:9999",
				Protocol: "http",
			},
		},
	})
	var addAck common.Message
	_ = dec.Decode(&addAck)

	if !waitForHost(t, srv, "metrics.example", 2*time.Second) {
		t.Fatal("registry never saw metrics.example")
	}

	// Spawn agent responder.
	go func() {
		var msg common.Message
		if err := dec.Decode(&msg); err != nil {
			return
		}
		_ = enc.Encode(&common.Message{
			Type: "http_response",
			ID:   msg.ID,
			HTTP: &common.HTTPData{
				StatusCode: http.StatusOK,
				Body:       []byte("ok"),
			},
		})
	}()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed in test
		},
		Timeout: 5 * time.Second,
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+httpsAddr+"/probe", nil)
	req.Host = "metrics.example"
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}

	// Force gauge refresh — the ticker fires every 5s in production
	// but we shouldn't wait that long here. Push the values directly
	// via the same setters refreshGauges uses.
	srv.metrics.setAgentsRegistered(srv.agents.AgentCount())
	srv.metrics.setWebSocketSessions(srv.agents.WebSocketCount())

	// Scrape /metrics.
	mResp, err := http.Get("http://" + metricsAddr + "/metrics") //nolint:noctx // test
	if err != nil {
		t.Fatalf("scrape /metrics: %v", err)
	}
	body, _ := io.ReadAll(mResp.Body)
	_ = mResp.Body.Close()

	out := string(body)
	for _, want := range []string{
		`ztp_requests_total{method="GET",status="2xx"} 1`,
		`ztp_request_duration_seconds_count 1`,
		`ztp_agents_registered 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n--- /metrics ---\n%s", want, out)
		}
	}
}
