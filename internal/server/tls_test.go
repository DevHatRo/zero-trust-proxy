package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

func TestBuildTLS_None(t *testing.T) {
	b, err := buildTLSConfig(serverconfig.TLSConfig{Mode: serverconfig.TLSModeNone}, nil)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if b.tlsConfig != nil {
		t.Fatal("none mode must yield no tls config")
	}
}

func TestBuildTLS_Manual(t *testing.T) {
	cert, key := writeKeyPair(t, "manual.example")
	b, err := buildTLSConfig(serverconfig.TLSConfig{
		Mode:   serverconfig.TLSModeManual,
		Manual: &serverconfig.ManualCert{CertFile: cert, KeyFile: key},
	}, nil)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if b.tlsConfig == nil || b.tlsConfig.GetCertificate == nil {
		t.Fatal("manual: missing tlsConfig/GetCertificate")
	}
	got, err := b.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "manual.example"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got == nil || len(got.Certificate) == 0 {
		t.Fatal("nil cert returned")
	}
}

func TestBuildTLS_SNI(t *testing.T) {
	certA, keyA := writeKeyPair(t, "a.example")
	certB, keyB := writeKeyPair(t, "b.example")

	b, err := buildTLSConfig(serverconfig.TLSConfig{
		Mode: serverconfig.TLSModeSNI,
		SNI: map[string]serverconfig.ManualCert{
			"a.example": {CertFile: certA, KeyFile: keyA},
			"b.example": {CertFile: certB, KeyFile: keyB},
		},
	}, nil)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}

	for _, host := range []string{"a.example", "B.EXAMPLE"} {
		got, err := b.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
		if err != nil {
			t.Fatalf("GetCertificate(%q): %v", host, err)
		}
		if got == nil {
			t.Fatalf("nil cert for %q", host)
		}
	}

	if _, err := b.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example"}); err == nil {
		t.Fatal("expected error for unknown SNI")
	}
}

func TestBuildTLS_ACME_HostPolicyConsultsLookup(t *testing.T) {
	dir := t.TempDir()
	allowed := map[string]bool{"ok.example": true}
	b, err := buildTLSConfig(serverconfig.TLSConfig{
		Mode: serverconfig.TLSModeACME,
		ACME: &serverconfig.ACMEConfig{StorageDir: dir, Email: "ops@example.com"},
	}, func(host string) bool { return allowed[host] })
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if b.acme == nil {
		t.Fatal("acme manager nil")
	}
	if err := b.acme.HostPolicy(t.Context(), "ok.example"); err != nil {
		t.Fatalf("HostPolicy(ok.example) = %v, want nil", err)
	}
	if err := b.acme.HostPolicy(t.Context(), "blocked.example"); err == nil {
		t.Fatal("HostPolicy(blocked.example) = nil, want error")
	}
	if b.acmeHandler == nil {
		t.Fatal("acmeHandler nil — :80 mount would have nothing to forward")
	}
}

// writeKeyPair generates a short-lived self-signed cert/key and writes
// them as PEM files in a temp directory. Returns paths.
func writeKeyPair(t *testing.T, cn string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}
