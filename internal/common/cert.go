package common

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/devhatro/zero-trust-proxy/internal/logger"
)

// Component-specific logger for certificate operations
var certLog = logger.WithComponent("cert")

// LoadCertificate loads a certificate and key from files
func LoadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load certificate: %w", err)
	}

	// Parse certificate to get details
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	certLog.Info("🔐 Using certificate with CN: %s", x509Cert.Subject.CommonName)
	certLog.Info("🔧 Certificate key usage: %d", x509Cert.KeyUsage)
	certLog.Info("🎯 Certificate extended key usage: %v", x509Cert.ExtKeyUsage)

	return cert, nil
}

// LoadCA loads a CA certificate from a file
func LoadCA(caFile string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate")
	}

	return caCertPool, nil
}

// LoadTLSConfig loads TLS configuration from certificate files
func LoadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}

	// Parse the certificate to get details
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	certLog.Info("🔐 Using certificate with CN: %s", x509Cert.Subject.CommonName)
	certLog.Info("🔧 Certificate key usage: %d", x509Cert.KeyUsage)
	certLog.Info("🎯 Certificate extended key usage: %v", x509Cert.ExtKeyUsage)

	// Load CA certificate
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate")
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Log certificate details
	serverCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse server certificate: %w", err)
	}

	certLog.Info("🔐 Using certificate with CN: %s", serverCert.Subject.CommonName)
	certLog.Info("🔧 Certificate key usage: %d", serverCert.KeyUsage)
	certLog.Info("🎯 Certificate extended key usage: %v", serverCert.ExtKeyUsage)

	return tlsConfig, nil
}

// LoadServerTLSConfig loads TLS configuration from certificate files
func LoadServerTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %v", err)
	}

	// Parse the certificate to get details
	x509Cert, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse server certificate: %v", err)
	}

	certLog.Info("🔐 Using certificate with CN: %s", x509Cert.Subject.CommonName)
	certLog.Info("🔧 Certificate key usage: %d", x509Cert.KeyUsage)
	certLog.Info("🎯 Certificate extended key usage: %v", x509Cert.ExtKeyUsage)

	// Load CA certificate
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate")
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, nil
}
