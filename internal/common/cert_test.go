package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// createTestCertificates creates test certificates for testing
func createTestCertificates(t *testing.T) (string, string, string) {
	t.Helper()

	// Create temporary directory
	tempDir := t.TempDir()

	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	// Create CA certificate template
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	// Save CA certificate
	caCertPath := filepath.Join(tempDir, "ca.crt")
	caCertFile, err := os.Create(caCertPath)
	if err != nil {
		t.Fatalf("failed to create CA cert file: %v", err)
	}
	defer caCertFile.Close()

	err = pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err != nil {
		t.Fatalf("failed to write CA certificate: %v", err)
	}

	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	// Create server certificate template
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  []string{"Test Server"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost", "127.0.0.1"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	// Create server certificate signed by CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create server certificate: %v", err)
	}

	// Save server certificate
	serverCertPath := filepath.Join(tempDir, "server.crt")
	serverCertFile, err := os.Create(serverCertPath)
	if err != nil {
		t.Fatalf("failed to create server cert file: %v", err)
	}
	defer serverCertFile.Close()

	err = pem.Encode(serverCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	if err != nil {
		t.Fatalf("failed to write server certificate: %v", err)
	}

	// Save server private key
	serverKeyPath := filepath.Join(tempDir, "server.key")
	serverKeyFile, err := os.Create(serverKeyPath)
	if err != nil {
		t.Fatalf("failed to create server key file: %v", err)
	}
	defer serverKeyFile.Close()

	serverKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatalf("failed to marshal server key: %v", err)
	}

	err = pem.Encode(serverKeyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyPKCS8})
	if err != nil {
		t.Fatalf("failed to write server key: %v", err)
	}

	return serverCertPath, serverKeyPath, caCertPath
}

// TestLoadCertificate tests loading certificate and key pairs
func TestLoadCertificate(t *testing.T) {
	certPath, keyPath, _ := createTestCertificates(t)

	// Test successful loading
	t.Run("valid certificate", func(t *testing.T) {
		cert, err := LoadCertificate(certPath, keyPath)
		if err != nil {
			t.Fatalf("failed to load certificate: %v", err)
		}

		if len(cert.Certificate) == 0 {
			t.Error("certificate chain is empty")
		}

		// Verify the certificate can be parsed
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse loaded certificate: %v", err)
		}

		if x509Cert.Subject.CommonName != "localhost" {
			t.Errorf("expected CN=localhost, got CN=%s", x509Cert.Subject.CommonName)
		}
	})

	// Test loading with non-existent files
	t.Run("non-existent cert file", func(t *testing.T) {
		_, err := LoadCertificate("/non/existent/cert.pem", keyPath)
		if err == nil {
			t.Error("expected error for non-existent cert file")
		}
	})

	t.Run("non-existent key file", func(t *testing.T) {
		_, err := LoadCertificate(certPath, "/non/existent/key.pem")
		if err == nil {
			t.Error("expected error for non-existent key file")
		}
	})

	// Test loading with mismatched cert/key
	t.Run("mismatched cert and key", func(t *testing.T) {
		// Create another certificate with different key
		otherCertPath, _, _ := createTestCertificates(t)

		_, err := LoadCertificate(otherCertPath, keyPath)
		if err == nil {
			t.Error("expected error for mismatched cert and key")
		}
	})
}

// TestLoadCA tests loading CA certificates
func TestLoadCA(t *testing.T) {
	_, _, caPath := createTestCertificates(t)

	// Test successful CA loading
	t.Run("valid CA certificate", func(t *testing.T) {
		caCertPool, err := LoadCA(caPath)
		if err != nil {
			t.Fatalf("failed to load CA certificate: %v", err)
		}

		if caCertPool == nil {
			t.Fatal("CA cert pool is nil")
		}

		// Test that we can get subjects from the pool
		subjects := caCertPool.Subjects()
		if len(subjects) == 0 {
			t.Error("CA cert pool has no subjects")
		}
	})

	// Test loading non-existent CA file
	t.Run("non-existent CA file", func(t *testing.T) {
		_, err := LoadCA("/non/existent/ca.pem")
		if err == nil {
			t.Error("expected error for non-existent CA file")
		}
	})

	// Test loading invalid CA file
	t.Run("invalid CA file", func(t *testing.T) {
		tempDir := t.TempDir()
		invalidCAPath := filepath.Join(tempDir, "invalid_ca.pem")

		// Create a file with invalid PEM content
		err := os.WriteFile(invalidCAPath, []byte("invalid pem content"), 0644)
		if err != nil {
			t.Fatalf("failed to create invalid CA file: %v", err)
		}

		_, err = LoadCA(invalidCAPath)
		if err == nil {
			t.Error("expected error for invalid CA file")
		}
	})
}

// TestLoadTLSConfig tests loading complete TLS configuration
func TestLoadTLSConfig(t *testing.T) {
	certPath, keyPath, caPath := createTestCertificates(t)

	// Test successful TLS config loading
	t.Run("valid TLS config", func(t *testing.T) {
		tlsConfig, err := LoadTLSConfig(certPath, keyPath, caPath)
		if err != nil {
			t.Fatalf("failed to load TLS config: %v", err)
		}

		if tlsConfig == nil {
			t.Fatal("TLS config is nil")
		}

		// Verify TLS version
		if tlsConfig.MinVersion != tls.VersionTLS12 {
			t.Errorf("expected MinVersion TLS 1.2, got %d", tlsConfig.MinVersion)
		}

		// Verify certificates
		if len(tlsConfig.Certificates) == 0 {
			t.Error("no certificates in TLS config")
		}

		// Verify CA pool
		if tlsConfig.RootCAs == nil {
			t.Error("RootCAs is nil in TLS config")
		}
	})

	// Test with invalid certificate file
	t.Run("invalid certificate", func(t *testing.T) {
		_, err := LoadTLSConfig("/non/existent/cert.pem", keyPath, caPath)
		if err == nil {
			t.Error("expected error for invalid certificate file")
		}
	})

	// Test with invalid CA file
	t.Run("invalid CA", func(t *testing.T) {
		_, err := LoadTLSConfig(certPath, keyPath, "/non/existent/ca.pem")
		if err == nil {
			t.Error("expected error for invalid CA file")
		}
	})
}

// TestLoadServerTLSConfig tests loading server-specific TLS configuration
func TestLoadServerTLSConfig(t *testing.T) {
	certPath, keyPath, caPath := createTestCertificates(t)

	// Test successful server TLS config loading
	t.Run("valid server TLS config", func(t *testing.T) {
		tlsConfig, err := LoadServerTLSConfig(certPath, keyPath, caPath)
		if err != nil {
			t.Fatalf("failed to load server TLS config: %v", err)
		}

		if tlsConfig == nil {
			t.Fatal("server TLS config is nil")
		}

		// Verify TLS version
		if tlsConfig.MinVersion != tls.VersionTLS12 {
			t.Errorf("expected MinVersion TLS 1.2, got %d", tlsConfig.MinVersion)
		}

		// Verify server certificates
		if len(tlsConfig.Certificates) == 0 {
			t.Error("no certificates in server TLS config")
		}

		// Verify CA pool
		if tlsConfig.RootCAs == nil {
			t.Error("RootCAs is nil in server TLS config")
		}
	})

	// Test with invalid server certificate
	t.Run("invalid server certificate", func(t *testing.T) {
		_, err := LoadServerTLSConfig("/non/existent/cert.pem", keyPath, caPath)
		if err == nil {
			t.Error("expected error for invalid server certificate file")
		}
	})

	// Test with invalid server key
	t.Run("invalid server key", func(t *testing.T) {
		_, err := LoadServerTLSConfig(certPath, "/non/existent/key.pem", caPath)
		if err == nil {
			t.Error("expected error for invalid server key file")
		}
	})
}

// TestCertificateDetails tests that certificate details are properly logged
func TestCertificateDetails(t *testing.T) {
	certPath, keyPath, _ := createTestCertificates(t)

	// Load certificate and verify details are accessible
	cert, err := LoadCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("failed to load certificate: %v", err)
	}

	// Parse the certificate to check details
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Verify certificate details
	if x509Cert.Subject.CommonName != "localhost" {
		t.Errorf("expected CN=localhost, got CN=%s", x509Cert.Subject.CommonName)
	}

	// Verify key usage
	expectedKeyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	if x509Cert.KeyUsage != expectedKeyUsage {
		t.Errorf("expected key usage %d, got %d", expectedKeyUsage, x509Cert.KeyUsage)
	}

	// Verify extended key usage
	expectedExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if len(x509Cert.ExtKeyUsage) != len(expectedExtKeyUsage) {
		t.Errorf("expected %d extended key usages, got %d", len(expectedExtKeyUsage), len(x509Cert.ExtKeyUsage))
	}
}

// TestTLSConfigDefaults tests that TLS configuration uses secure defaults
func TestTLSConfigDefaults(t *testing.T) {
	certPath, keyPath, caPath := createTestCertificates(t)

	tlsConfig, err := LoadTLSConfig(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("failed to load TLS config: %v", err)
	}

	// Test minimum TLS version
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("minimum TLS version should be at least TLS 1.2, got %d", tlsConfig.MinVersion)
	}

	// Test that certificates are present
	if len(tlsConfig.Certificates) == 0 {
		t.Error("TLS config should have at least one certificate")
	}

	// Test that RootCAs is configured
	if tlsConfig.RootCAs == nil {
		t.Error("TLS config should have RootCAs configured")
	}
}

// TestInvalidPEMFiles tests handling of invalid PEM files
func TestInvalidPEMFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Create invalid certificate file
	invalidCertPath := filepath.Join(tempDir, "invalid.crt")
	err := os.WriteFile(invalidCertPath, []byte("invalid certificate content"), 0644)
	if err != nil {
		t.Fatalf("failed to create invalid cert file: %v", err)
	}

	// Create invalid key file
	invalidKeyPath := filepath.Join(tempDir, "invalid.key")
	err = os.WriteFile(invalidKeyPath, []byte("invalid key content"), 0644)
	if err != nil {
		t.Fatalf("failed to create invalid key file: %v", err)
	}

	// Create invalid CA file
	invalidCAPath := filepath.Join(tempDir, "invalid_ca.crt")
	err = os.WriteFile(invalidCAPath, []byte("invalid CA content"), 0644)
	if err != nil {
		t.Fatalf("failed to create invalid CA file: %v", err)
	}

	// Test loading invalid certificate
	t.Run("invalid certificate content", func(t *testing.T) {
		_, err := LoadCertificate(invalidCertPath, invalidKeyPath)
		if err == nil {
			t.Error("expected error for invalid certificate content")
		}
	})

	// Test loading invalid CA
	t.Run("invalid CA content", func(t *testing.T) {
		_, err := LoadCA(invalidCAPath)
		if err == nil {
			t.Error("expected error for invalid CA content")
		}
	})
}

// TestEmptyFiles tests handling of empty certificate files
func TestEmptyFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Create empty certificate file
	emptyCertPath := filepath.Join(tempDir, "empty.crt")
	err := os.WriteFile(emptyCertPath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("failed to create empty cert file: %v", err)
	}

	// Create empty key file
	emptyKeyPath := filepath.Join(tempDir, "empty.key")
	err = os.WriteFile(emptyKeyPath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("failed to create empty key file: %v", err)
	}

	// Create empty CA file
	emptyCAPath := filepath.Join(tempDir, "empty_ca.crt")
	err = os.WriteFile(emptyCAPath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("failed to create empty CA file: %v", err)
	}

	// Test loading empty certificate
	t.Run("empty certificate file", func(t *testing.T) {
		_, err := LoadCertificate(emptyCertPath, emptyKeyPath)
		if err == nil {
			t.Error("expected error for empty certificate file")
		}
	})

	// Test loading empty CA
	t.Run("empty CA file", func(t *testing.T) {
		_, err := LoadCA(emptyCAPath)
		if err == nil {
			t.Error("expected error for empty CA file")
		}
	})
}

// BenchmarkLoadCertificate benchmarks certificate loading
func BenchmarkLoadCertificate(b *testing.B) {
	// Create test certificates once
	tempDir := b.TempDir()
	certPath := filepath.Join(tempDir, "bench.crt")
	keyPath := filepath.Join(tempDir, "bench.key")

	// Generate a simple certificate for benchmarking
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "benchmark"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)

	// Save certificate
	certFile, _ := os.Create(certPath)
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certFile.Close()

	// Save key
	keyFile, _ := os.Create(keyPath)
	keyPKCS8, _ := x509.MarshalPKCS8PrivateKey(key)
	pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyPKCS8})
	keyFile.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := LoadCertificate(certPath, keyPath)
		if err != nil {
			b.Fatalf("benchmark failed: %v", err)
		}
	}
}

// BenchmarkLoadCA benchmarks CA certificate loading
func BenchmarkLoadCA(b *testing.B) {
	// Create test CA once
	tempDir := b.TempDir()
	caPath := filepath.Join(tempDir, "bench_ca.crt")

	// Generate a simple CA certificate for benchmarking
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Benchmark CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}

	caCertDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)

	// Save CA certificate
	caFile, _ := os.Create(caPath)
	pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	caFile.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := LoadCA(caPath)
		if err != nil {
			b.Fatalf("benchmark failed: %v", err)
		}
	}
}
