package ztagents

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestCerts creates a self-signed CA and a server cert signed by it,
// writes them to a temp dir, and returns the file paths.
func generateTestCerts(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	caFile = filepath.Join(dir, "ca.crt")
	f, _ := os.Create(caFile)
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	f.Close()

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	certFile = filepath.Join(dir, "server.crt")
	f, _ = os.Create(certFile)
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	f.Close()

	keyFile = filepath.Join(dir, "server.key")
	srvKeyDER, _ := x509.MarshalECPrivateKey(srvKey)
	f, _ = os.Create(keyFile)
	_ = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})
	f.Close()

	return certFile, keyFile, caFile
}

// --- App.Validate ---

func TestApp_Validate_MissingFields(t *testing.T) {
	cases := []struct {
		name    string
		app     App
		wantErr bool
	}{
		{"missing all", App{}, true},
		{"missing key and ca", App{CertFile: "/tmp/cert.crt"}, true},
		{"missing ca", App{CertFile: "/tmp/c.crt", KeyFile: "/tmp/k.key"}, true},
		{"all present", App{CertFile: "/c.crt", KeyFile: "/k.key", CAFile: "/ca.crt"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.app.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// --- App.Provision (no cert files → sets up runtime but returns nil) ---

func TestApp_Provision_NoCerts(t *testing.T) {
	app := &App{ListenAddr: ":0"}
	// No cert files: provision should initialize runtime and return nil.
	if err := app.provision(); err != nil {
		t.Fatalf("provision with no certs: %v", err)
	}
	if app.rt == nil {
		t.Fatal("runtime should be initialized after provision")
	}
}

func TestApp_Provision_BadCerts(t *testing.T) {
	app := &App{
		ListenAddr: ":0",
		CertFile:   "/nonexistent/cert.crt",
		KeyFile:    "/nonexistent/key.key",
		CAFile:     "/nonexistent/ca.crt",
	}
	// loadTLSConfig fails on missing files.
	if err := app.provision(); err == nil {
		t.Fatal("expected error from provision with missing cert files")
	}
}

// --- categorizeAcceptError ---

func TestCategorizeAcceptError(t *testing.T) {
	// Exercise the three error-categorization branches plus the default.
	categorizeAcceptError(errors.New("accept: too many open files"))
	categorizeAcceptError(errors.New("tls: certificate verify failed"))
	categorizeAcceptError(errors.New("tls: remote error: bad certificate"))
	categorizeAcceptError(errors.New("some unrecognized error"))
}

// --- startCheckServer / stopCheckServer ---

func newRuntimeApp() *App {
	return &App{rt: &runtime{
		registry: newRegistry(),
	}}
}

func TestStartStopCheckServer(t *testing.T) {
	app := newRuntimeApp()
	app.CheckAddr = "127.0.0.1:0"

	if err := app.startCheckServer(); err != nil {
		t.Fatalf("startCheckServer: %v", err)
	}
	if app.rt.checkServer == nil {
		t.Fatal("checkServer is nil after startCheckServer")
	}

	time.Sleep(20 * time.Millisecond)
	app.stopCheckServer()
}

func TestStopCheckServer_NilRuntime(t *testing.T) {
	app := &App{rt: nil}
	app.stopCheckServer() // must not panic
}

func TestStopCheckServer_NilCheckServer(t *testing.T) {
	app := newRuntimeApp()
	app.stopCheckServer() // rt.checkServer is nil, must not panic
}

func TestStartCheckServer_DefaultAddr(t *testing.T) {
	app := newRuntimeApp()
	// Leave CheckAddr empty → uses defaultCheckAddr (127.0.0.1:2020).
	// Bind may fail if the port is taken; either outcome is acceptable.
	err := app.startCheckServer()
	if err == nil {
		app.stopCheckServer()
	}
}

// --- loadTLSConfig success path ---

func TestLoadTLSConfig_Success(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	cfg, err := loadTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("loadTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth=%v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion=%v, want TLS 1.2", cfg.MinVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates len=%d, want 1", len(cfg.Certificates))
	}
	if cfg.ClientCAs == nil {
		t.Fatal("ClientCAs pool should not be nil")
	}
}

func TestLoadTLSConfig_EmptyCAPEM(t *testing.T) {
	dir := t.TempDir()
	// Write an empty CA file — AppendCertsFromPEM returns false.
	caFile := filepath.Join(dir, "empty_ca.crt")
	_ = os.WriteFile(caFile, []byte("not-a-cert"), 0o600)

	certFile, keyFile, _ := generateTestCerts(t)
	_, err := loadTLSConfig(certFile, keyFile, caFile)
	if err == nil {
		t.Fatal("expected error for invalid CA PEM")
	}
}

func TestApp_Provision_WithCerts(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	app := &App{
		ListenAddr: ":0",
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     caFile,
	}
	if err := app.provision(); err != nil {
		t.Fatalf("provision with valid certs: %v", err)
	}
	if app.rt == nil || app.rt.tlsConfig == nil {
		t.Fatal("runtime.tlsConfig should be set after provision with valid certs")
	}
}
