package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// TestServer_HTTP3Listener boots a Server with listen.http3 set and
// confirms the QUIC listener comes up alongside HTTPS. We don't run a
// real QUIC client here — that would require the full http3 client
// stack and a UDP capture. We just verify Start succeeds without
// error and Shutdown closes everything.
func TestServer_HTTP3Listener(t *testing.T) {
	cert, key := writeKeyPair(t, "h3.example")
	agentCert, agentKey := writeKeyPair(t, "agent.example")
	caCert, _ := writeKeyPair(t, "ca.example")

	httpsAddr := freePort(t)
	http3Addr := httpsAddr // same port; UDP for QUIC, TCP for HTTPS — doesn't conflict
	agentsAddr := freePort(t)

	cfg := &serverconfig.Config{
		Listen: serverconfig.ListenConfig{
			HTTPS: httpsAddr,
			HTTP3: http3Addr,
		},
		TLS: serverconfig.TLSConfig{
			Mode:   serverconfig.TLSModeManual,
			Manual: &serverconfig.ManualCert{CertFile: cert, KeyFile: key},
		},
		Agents: serverconfig.AgentsConfig{
			Listen:   agentsAddr,
			CertFile: agentCert, KeyFile: agentKey, CAFile: caCert,
			CheckAddr: freePort(t),
		},
		Router: serverconfig.RouterConfig{RequestTimeout: 5 * time.Second},
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

	if srv.http3Sr == nil {
		t.Fatal("http3 server expected to be set when listen.http3 is non-empty")
	}
}

func TestStartHTTP3_NilTLSConfig(t *testing.T) {
	_, err := startHTTP3(":0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil)
	if err == nil || !strings.Contains(err.Error(), "tls config required") {
		t.Fatalf("expected nil-tls error, got %v", err)
	}
}

func TestValidateHTTP3RequiresHTTPS(t *testing.T) {
	cfg := &serverconfig.Config{
		// HTTP set so we don't trip "at least one of http/https";
		// HTTPS empty so the http3 check triggers.
		Listen: serverconfig.ListenConfig{HTTP: ":80", HTTP3: ":443"},
		TLS:    serverconfig.TLSConfig{Mode: serverconfig.TLSModeNone},
		Agents: serverconfig.AgentsConfig{
			Listen: ":8443", CertFile: "a", KeyFile: "b", CAFile: "c",
		},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "http3") {
		t.Fatalf("expected http3-without-https error, got %v", err)
	}
}

// quiet a compile-time unused import when running without integration tests
var _ = tls.VersionTLS12
