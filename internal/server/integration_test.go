package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
	"github.com/devhatro/zero-trust-proxy/internal/types"
)

// TestServer_EndToEnd_HTTPThroughAgent boots the full server, dials
// a fake agent over mTLS, registers a service for `app.example`, and
// drives an HTTP request through the public listener — asserting the
// agent received `http_request` and the client got our crafted
// response.
func TestServer_EndToEnd_HTTPThroughAgent(t *testing.T) {
	caCert, caKey := generateCA(t, "TestCA")
	serverCertPath, serverKeyPath, caCertPath := writeServerCerts(t, caCert, caKey)
	publicCertPath, publicKeyPath := writeServerCerts2(t, "smoke.local")
	agentCertPath, agentKeyPath := writeSignedAgentCerts(t, caCert, caKey, "agent-1")

	httpsAddr := freePort(t)
	agentsAddr := freePort(t)
	checkAddr := freePort(t)

	cfg := &serverconfig.Config{
		Listen: serverconfig.ListenConfig{
			HTTPS:        httpsAddr,
			HTTPRedirect: false,
		},
		TLS: serverconfig.TLSConfig{
			Mode:   serverconfig.TLSModeManual,
			Manual: &serverconfig.ManualCert{CertFile: publicCertPath, KeyFile: publicKeyPath},
		},
		Agents: serverconfig.AgentsConfig{
			Listen:    agentsAddr,
			CertFile:  serverCertPath,
			KeyFile:   serverKeyPath,
			CAFile:    caCertPath,
			CheckAddr: checkAddr,
		},
		Router: serverconfig.RouterConfig{RequestTimeout: 10 * time.Second},
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

	// Connect a fake agent over mTLS to :agentsAddr.
	agentTLS := tls.Config{
		Certificates: []tls.Certificate{loadCert(t, agentCertPath, agentKeyPath)},
		RootCAs:      poolFromCert(caCert),
		ServerName:   "test-server",
		MinVersion:   tls.VersionTLS12,
	}
	conn, err := tls.Dial("tcp", agentsAddr, &agentTLS)
	if err != nil {
		t.Fatalf("tls.Dial agents: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	// 1) register
	if err := enc.Encode(&common.Message{Type: "register", ID: "agent-1"}); err != nil {
		t.Fatalf("send register: %v", err)
	}
	var ack common.Message
	if err := dec.Decode(&ack); err != nil {
		t.Fatalf("read register_response: %v", err)
	}
	if ack.Type != "register_response" {
		t.Fatalf("expected register_response, got %q", ack.Type)
	}

	// 2) service_add for app.example
	addID := "add-1"
	if err := enc.Encode(&common.Message{
		Type: "service_add",
		ID:   addID,
		Service: &common.ServiceConfig{
			ServiceConfig: types.ServiceConfig{
				Hostname: "app.example",
				Backend:  "127.0.0.1:9999",
				Protocol: "http",
			},
		},
	}); err != nil {
		t.Fatalf("send service_add: %v", err)
	}
	var addAck common.Message
	if err := dec.Decode(&addAck); err != nil {
		t.Fatalf("read service_add_response: %v", err)
	}
	if addAck.Type != "service_add_response" {
		t.Fatalf("expected service_add_response, got %q", addAck.Type)
	}

	// Wait until the registry has the host, then start a goroutine
	// that responds to incoming http_request with a canned response.
	if !waitForHost(t, srv, "app.example", 2*time.Second) {
		t.Fatal("registry never saw app.example")
	}

	// Agent goroutine: read messages, respond to http_request with
	// a 201 + body.
	wantMethod := http.MethodGet
	wantPath := "/hi?x=1"
	wantBody := "hello-from-agent"

	agentDone := make(chan struct{})
	var agentErr error
	go func() {
		defer close(agentDone)
		var msg common.Message
		if err := dec.Decode(&msg); err != nil {
			agentErr = err
			return
		}
		if msg.Type != "http_request" {
			agentErr = &mismatchErr{want: "http_request", got: msg.Type}
			return
		}
		if msg.HTTP == nil || msg.HTTP.Method != wantMethod || msg.HTTP.URL != wantPath {
			agentErr = &mismatchErr{want: wantMethod + " " + wantPath, got: msg.HTTP.Method + " " + msg.HTTP.URL}
			return
		}
		// Reply.
		_ = enc.Encode(&common.Message{
			Type: "http_response",
			ID:   msg.ID,
			HTTP: &common.HTTPData{
				StatusCode: http.StatusCreated,
				Headers:    map[string][]string{"Content-Type": {"text/plain"}},
				Body:       []byte(wantBody),
			},
		})
	}()

	// 3) Make the HTTP request via the public listener.
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed in test
		},
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+httpsAddr+"/hi?x=1", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = "app.example"
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d, want 201", resp.StatusCode)
	}
	if string(body) != wantBody {
		t.Fatalf("body=%q, want %q", body, wantBody)
	}

	select {
	case <-agentDone:
		if agentErr != nil {
			t.Fatalf("agent goroutine: %v", agentErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent goroutine did not finish")
	}
}

// waitForHost polls Server.lookupHost until ok or deadline.
func waitForHost(t *testing.T, s *Server, host string, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if s.lookupHost(host) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

type mismatchErr struct{ want, got string }

func (e *mismatchErr) Error() string { return "want=" + e.want + " got=" + e.got }

// --- cert helpers ---

// generateCA returns an in-memory CA cert + key.
func generateCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, priv
}

// writeServerCerts writes the agent-mTLS server cert/key signed by ca,
// plus the CA cert, to a temp dir. Returns paths.
func writeServerCerts(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (certPath, keyPath, caPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	caPath = filepath.Join(dir, "ca.crt")

	signedCertToFile(t, ca, caKey, certPath, keyPath, "test-server",
		[]net.IP{net.ParseIP("127.0.0.1")}, []string{"test-server", "localhost"})
	pemWrite(t, caPath, "CERTIFICATE", ca.Raw)
	return
}

// writeServerCerts2 writes a self-signed cert/key for the public
// HTTPS listener (separate from the mTLS hierarchy — public listener
// just needs *something* the test client can ignore via
// InsecureSkipVerify).
func writeServerCerts2(t *testing.T, cn string) (certPath, keyPath string) {
	t.Helper()
	c, k := writeKeyPair(t, cn)
	return c, k
}

// writeSignedAgentCerts writes an agent client cert signed by ca.
func writeSignedAgentCerts(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath = filepath.Join(dir, "agent.crt")
	keyPath = filepath.Join(dir, "agent.key")
	signedCertToFile(t, ca, caKey, certPath, keyPath, cn, nil, []string{cn})
	return
}

func signedCertToFile(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, certPath, keyPath, cn string, ips []net.IP, dns []string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("priv: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  ips,
		DNSNames:     dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	pemWrite(t, certPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemWrite(t, keyPath, "EC PRIVATE KEY", keyDER)
}

func pemWrite(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func loadCert(t *testing.T, certPath, keyPath string) tls.Certificate {
	t.Helper()
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	return c
}

func poolFromCert(c *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}

// silence unused-import warnings if any helper above is removed
var _ = sync.Mutex{}
var _ = strings.Compare
