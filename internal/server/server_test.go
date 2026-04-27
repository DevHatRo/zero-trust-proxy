package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// freePort grabs an OS-allocated TCP port and returns it as a ":N"
// listen address. The port is released before returning so callers can
// re-bind it; on busy CI hosts there is a small race window we accept
// in exchange for not requiring fixed ports.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestServer_StartAndShutdown_Manual(t *testing.T) {
	cert, key := writeKeyPair(t, "smoke.example")
	agentCert, agentKey := writeKeyPair(t, "agent.example")
	caCert, _ := writeKeyPair(t, "ca.example")

	httpsAddr := freePort(t)
	agentsAddr := freePort(t)

	cfg := &serverconfig.Config{
		Listen: serverconfig.ListenConfig{
			HTTP:         "",
			HTTPS:        httpsAddr,
			HTTPRedirect: false,
		},
		TLS: serverconfig.TLSConfig{
			Mode:   serverconfig.TLSModeManual,
			Manual: &serverconfig.ManualCert{CertFile: cert, KeyFile: key},
		},
		Agents: serverconfig.AgentsConfig{
			Listen:    agentsAddr,
			CertFile:  agentCert,
			KeyFile:   agentKey,
			CAFile:    caCert, // self-signed for the test; not used for client validation here
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

	// Hit the public HTTPS listener — no agent registered for this
	// host, so we expect a 503 from ztrouter.
	dialer := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // self-signed cert in test
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	for {
		conn, derr := dialer.DialContext(context.Background(), "tcp", httpsAddr)
		if derr == nil {
			tlsConn := conn.(*tls.Conn)
			req, _ := http.NewRequest(http.MethodGet, "https://nobody.example/", nil)
			req.Host = "nobody.example"
			if werr := req.Write(tlsConn); werr != nil {
				_ = tlsConn.Close()
				t.Fatalf("write request: %v", werr)
			}
			r, rerr := http.ReadResponse(bufio.NewReader(tlsConn), req)
			if rerr != nil {
				_ = tlsConn.Close()
				t.Fatalf("read response: %v", rerr)
			}
			resp = r
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
			_ = tlsConn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial https %s: %v", httpsAddr, derr)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (no agent)", resp.StatusCode)
	}
}

func TestServer_Reload_RestartOnlyRejected(t *testing.T) {
	cert, key := writeKeyPair(t, "reload.example")
	agentCert, agentKey := writeKeyPair(t, "agent.example")
	caCert, _ := writeKeyPair(t, "ca.example")

	httpsAddr := freePort(t)
	agentsAddr := freePort(t)

	cfg := &serverconfig.Config{
		Listen: serverconfig.ListenConfig{HTTPS: httpsAddr},
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
		_ = srv.Shutdown(context.Background())
	})

	// Identical config minus a listen address change → must reject.
	newCfg := *cfg
	newCfg.Listen.HTTPS = freePort(t)
	if err := srv.Reload(&newCfg); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("Reload should reject listen.https change, got %v", err)
	}

	// Pure router timeout change → must succeed.
	newCfg2 := *cfg
	newCfg2.Router.RequestTimeout = 30 * time.Second
	if err := srv.Reload(&newCfg2); err != nil {
		t.Fatalf("Reload(timeout-only): %v", err)
	}
}

func TestServer_StartTwiceFails(t *testing.T) {
	srv := &Server{cfg: &serverconfig.Config{}, started: true}
	err := srv.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("expected already-started error, got %v", err)
	}
}
