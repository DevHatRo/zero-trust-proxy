package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/logger"
)

// Component-specific logger for certificate generation
var log = logger.WithComponent("certgen")

// Removed global flag definitions here
// var (
// 	outputDir = flag.String("output", "certs", "Output directory for certificates")
// 	validity  = flag.Int("validity", 365, "Certificate validity in days")
// 	genServer = flag.Bool("server", false, "Generate server certificate")
// 	serverIP  = flag.String("server-ip", "", "Server IP address")
// 	serverDNS = flag.String("server-dns", "", "Server DNS name")
// 	genClient = flag.Bool("client", false, "Generate client certificate")
// 	clientID  = flag.String("client-id", "", "Client identifier")
// )

// Add revocation support
type RevokedCert struct {
	SerialNumber *big.Int
	RevokedAt    time.Time
}

var revokedCerts []RevokedCert

func revokeCertificate(serialNumber *big.Int) {
	revokedCerts = append(revokedCerts, RevokedCert{
		SerialNumber: serialNumber,
		RevokedAt:    time.Now(),
	})
}

func isCertificateRevoked(serialNumber *big.Int) bool {
	for _, cert := range revokedCerts {
		if cert.SerialNumber.Cmp(serialNumber) == 0 {
			return true
		}
	}
	return false
}

var (
	rootCA         = flag.Bool("root-ca", false, "Generate Root CA certificate")
	intermediateCA = flag.Bool("intermediate-ca", false, "Generate Intermediate CA certificate")
	serverCA       = flag.Bool("server-ca", false, "Generate Server CA certificate")
	clientCA       = flag.Bool("client-ca", false, "Generate Client CA certificate")
	serverDNS      = flag.String("server-dns", "", "Server DNS name")
	serverIP       = flag.String("server-ip", "", "Server IP address")
	clientID       = flag.String("client-id", "", "Client identifier")
	outputDir      = flag.String("output", "certs", "Output directory for certificates")
	validity       = flag.Int("validity", 365, "Certificate validity in days")
	proxyCert      = flag.Bool("proxy-cert", false, "Generate proxy certificate for localhost")
	logLevel       = flag.String("log-level", "", "Log level (DEBUG, INFO, WARN, ERROR, FATAL) or set LOG_LEVEL env var")
)

func main() {
	flag.Parse()

	// Set log level from flag or environment variable
	level := *logLevel
	if level == "" {
		level = os.Getenv("LOG_LEVEL")
	}
	if level == "" {
		level = "INFO"
	}
	logger.SetLogLevel(level)

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatal("❌ Failed to create output directory: %v", err)
	}

	// Generate certificates based on flags
	if *rootCA {
		cert, key, err := generateRootCA()
		if err != nil {
			log.Fatal("❌ Failed to generate Root CA: %v", err)
		}
		saveCertificate(cert, key, *outputDir, "root")
	}

	if *intermediateCA {
		cert, key, err := generateIntermediateCA(nil, nil) // Root CA is self-signed
		if err != nil {
			log.Fatal("❌ Failed to generate Intermediate CA: %v", err)
		}
		saveCertificate(cert, key, *outputDir, "intermediate")
	}

	if *serverCA {
		err := generateServerCert(*validity, *outputDir, *serverIP, *serverDNS)
		if err != nil {
			log.Fatal("❌ Failed to generate Server CA: %v", err)
		}
	}

	if *clientCA {
		if *clientID == "" {
			log.Fatal("❌ Client ID is required for generating Client CA")
		}
		err := generateClientCert(*clientID, *validity, *outputDir)
		if err != nil {
			log.Fatal("❌ Failed to generate Client CA: %v", err)
		}
	}

	if *proxyCert {
		err := generateProxyCert()
		if err != nil {
			log.Fatal("❌ Failed to generate proxy certificate: %v", err)
		}
	}

	// Log success messages only for the certificates that were actually generated
	if *rootCA {
		log.Info("🔐 Root CA certificate generated successfully")
	}
	if *intermediateCA {
		log.Info("🔑 Intermediate CA certificate generated successfully")
	}
	if *serverCA {
		log.Info("🖥️  Server certificate generated successfully")
	}
	if *clientCA {
		log.Info("👤 Client certificate for %s generated successfully", *clientID)
	}
	if *proxyCert {
		log.Info("🔗 Proxy certificate generated successfully")
	}
}

func generateServerCert(validity int, outputDir, serverIP, serverDNS string) error {
	// Load the intermediate CA certificate and key
	intermediateCert, intermediateKey, err := loadCertAndKey("intermediate", outputDir)
	if err != nil {
		return fmt.Errorf("failed to load intermediate CA certificate: %w", err)
	}

	// Generate server key
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}

	// Create server certificate template
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"0Trust VPN"},
			CommonName:   "0Trust VPN Server",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 0, validity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Add IPs if provided (support comma-separated list)
	if serverIP != "" {
		for _, ipStr := range strings.Split(serverIP, ",") {
			ip := net.ParseIP(strings.TrimSpace(ipStr))
			if ip != nil {
				serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, ip)
			}
		}
	}
	if serverDNS != "" {
		serverTemplate.DNSNames = []string{serverDNS}
	}

	// Create server certificate signed by intermediate CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, intermediateCert, &serverKey.PublicKey, intermediateKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Save server certificate and key
	if err := saveCertAndKey("server", serverCertDER, serverKey, outputDir); err != nil {
		return err
	}

	return nil
}

func generateClientCert(clientID string, validity int, outputDir string) error {
	// Load the intermediate CA certificate and key
	intermediateCert, intermediateKey, err := loadCertAndKey("intermediate", outputDir)
	if err != nil {
		return fmt.Errorf("failed to load intermediate CA certificate: %w", err)
	}

	// Generate client key
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate client key: %w", err)
	}

	// Create client certificate template
	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"0Trust VPN"},
			CommonName:   clientID,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 0, validity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Create client certificate
	log.Info("🔨 Creating client certificate for %s:", clientID)
	log.Info("  📋 Subject: %s", clientTemplate.Subject.CommonName)
	log.Info("  🔧 Key Usage: %v", clientTemplate.KeyUsage)
	log.Info("  🎯 Extended Key Usage: %v", clientTemplate.ExtKeyUsage)
	log.Info("  📅 Valid from: %v to %v", clientTemplate.NotBefore, clientTemplate.NotAfter)

	// Create client certificate signed by intermediate CA
	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, intermediateCert, &clientKey.PublicKey, intermediateKey)
	if err != nil {
		return fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Save client certificate and key
	if err := saveCertAndKey(clientID, clientCertDER, clientKey, outputDir); err != nil {
		return err
	}

	return nil
}

func saveCertAndKey(name string, certDER []byte, key *ecdsa.PrivateKey, outputDir string) error {
	certFile := filepath.Join(outputDir, name+".crt")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}
	keyFile := filepath.Join(outputDir, name+".key")
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	return nil
}

func loadCertAndKey(name string, outputDir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certFile := filepath.Join(outputDir, name+".crt")
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	keyFile := filepath.Join(outputDir, name+".key")
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode private key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return cert, key, nil
}

// Update certificate generation to include revocation check
func generateCertificate(template *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if isCertificateRevoked(template.SerialNumber) {
		return nil, nil, fmt.Errorf("certificate with serial number %s is revoked", template.SerialNumber.String())
	}

	// Generate a new key pair
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// If this is a self-signed certificate (root CA)
	if parent == nil {
		parent = template
		parentKey = key
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate to get the x509.Certificate object
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, key, nil
}

func generateRootCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(100, 0, 0), // 100 years validity
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return generateCertificate(template, nil, nil)
}

func generateIntermediateCA(parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(20, 0, 0), // 20 years validity
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return generateCertificate(template, parent, parentKey)
}

func generateServerCA(parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "Server CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years validity
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return generateCertificate(template, parent, parentKey)
}

func generateClientCA(parent *x509.Certificate, parentKey *ecdsa.PrivateKey, validityYears int) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if validityYears > 20 {
		return nil, nil, fmt.Errorf("client certificate validity cannot exceed 20 years")
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject: pkix.Name{
			CommonName: "Client CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(validityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return generateCertificate(template, parent, parentKey)
}

func saveCertificate(cert *x509.Certificate, key *ecdsa.PrivateKey, outputDir string, name string) {
	// Save certificate
	certFile := filepath.Join(outputDir, name+".crt")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		log.Fatal("❌ Failed to save certificate: %v", err)
	}

	// Save private key
	keyFile := filepath.Join(outputDir, name+".key")
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatal("❌ Failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		log.Fatal("❌ Failed to save private key: %v", err)
	}

	log.Info("✅ %s certificate generated successfully", name)
}

func generateProxyCert() error {
	// Load the intermediate CA certificate and key
	intermediateCert, intermediateKey, err := loadCertAndKey("intermediate", *outputDir)
	if err != nil {
		return fmt.Errorf("failed to load intermediate CA certificate: %w", err)
	}

	// Generate proxy key
	proxyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate proxy key: %w", err)
	}

	// Support multiple IPs for proxy cert as well
	var proxyIPs []net.IP
	if *serverIP != "" {
		for _, ipStr := range strings.Split(*serverIP, ",") {
			ip := net.ParseIP(strings.TrimSpace(ipStr))
			if ip != nil {
				proxyIPs = append(proxyIPs, ip)
			}
		}
	} else {
		proxyIPs = []net.IP{net.ParseIP("127.0.0.1")}
	}

	// Create proxy certificate template
	proxyTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"0Trust VPN"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 0, *validity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: proxyIPs,
	}

	// Create proxy certificate signed by intermediate CA
	proxyCertDER, err := x509.CreateCertificate(rand.Reader, &proxyTemplate, intermediateCert, &proxyKey.PublicKey, intermediateKey)
	if err != nil {
		return fmt.Errorf("failed to create proxy certificate: %w", err)
	}

	// Save proxy certificate and key
	if err := saveCertAndKey("proxy", proxyCertDER, proxyKey, *outputDir); err != nil {
		return err
	}

	return nil
}
