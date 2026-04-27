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

// TestReloadCerts_Manual writes initial certs, builds the bundle,
// overwrites the files with a fresh pair, and asserts that
// reloadCerts swaps the atomic pointer so GetCertificate returns the
// new cert.
func TestReloadCerts_Manual(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	writeCertPair(t, certPath, keyPath, "first.example", big.NewInt(1))

	b, err := buildTLSConfig(serverconfig.TLSConfig{
		Mode:   serverconfig.TLSModeManual,
		Manual: &serverconfig.ManualCert{CertFile: certPath, KeyFile: keyPath},
	}, nil)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}

	first, err := b.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "first.example"})
	if err != nil || first == nil {
		t.Fatalf("first GetCertificate: %v", err)
	}
	firstSerial := mustParseSerial(t, first)

	// Overwrite with a new key pair (different serial, different key).
	writeCertPair(t, certPath, keyPath, "second.example", big.NewInt(2))

	if err := b.reloadCerts(); err != nil {
		t.Fatalf("reloadCerts: %v", err)
	}

	second, err := b.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "second.example"})
	if err != nil || second == nil {
		t.Fatalf("second GetCertificate: %v", err)
	}
	if mustParseSerial(t, second) == firstSerial {
		t.Fatalf("serial unchanged after reload: %d", firstSerial)
	}
}

// TestReloadCerts_SNI rewrites only one of two SNI entries and
// confirms the swap is per-host.
func TestReloadCerts_SNI(t *testing.T) {
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

	beforeA, _ := b.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example"})
	beforeB, _ := b.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "b.example"})
	if beforeA == nil || beforeB == nil {
		t.Fatal("initial certs missing")
	}
	beforeASerial := mustParseSerial(t, beforeA)
	beforeBSerial := mustParseSerial(t, beforeB)

	// Overwrite only host A.
	writeCertPair(t, certA, keyA, "a.example", big.NewInt(99))

	if err := b.reloadCerts(); err != nil {
		t.Fatalf("reloadCerts: %v", err)
	}

	afterA, _ := b.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example"})
	afterB, _ := b.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "b.example"})
	if mustParseSerial(t, afterA) == beforeASerial {
		t.Fatal("a.example serial unchanged after reload")
	}
	if mustParseSerial(t, afterB) != beforeBSerial {
		t.Fatal("b.example serial changed unexpectedly")
	}
}

// TestReloadCerts_BadFile leaves the cert pointer untouched if disk
// read fails (e.g. operator typo). The previous cert continues to
// serve.
func TestReloadCerts_BadFile(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	writeCertPair(t, certPath, keyPath, "good.example", big.NewInt(1))

	b, err := buildTLSConfig(serverconfig.TLSConfig{
		Mode:   serverconfig.TLSModeManual,
		Manual: &serverconfig.ManualCert{CertFile: certPath, KeyFile: keyPath},
	}, nil)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}

	first, _ := b.tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
	firstSerial := mustParseSerial(t, first)

	// Truncate the cert file — reload must surface an error and
	// leave the previous cert in place.
	if err := os.WriteFile(certPath, []byte("garbage"), 0o600); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := b.reloadCerts(); err == nil {
		t.Fatal("expected reloadCerts error for invalid cert file")
	}

	stillFirst, _ := b.tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
	if mustParseSerial(t, stillFirst) != firstSerial {
		t.Fatal("cert pointer was overwritten despite read failure")
	}
}

// writeCertPair writes a self-signed key pair to certPath/keyPath
// with the given CN and serial. Caller controls the serial so tests
// can distinguish before/after pointers via certificate parsing.
func writeCertPair(t *testing.T, certPath, keyPath, cn string, serial *big.Int) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
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
}

func mustParseSerial(t *testing.T, cert *tls.Certificate) int64 {
	t.Helper()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return parsed.SerialNumber.Int64()
}
