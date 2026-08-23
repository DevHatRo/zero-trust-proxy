package ztagents

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
	"github.com/devhatro/zero-trust-proxy/internal/types"
	"github.com/devhatro/zero-trust-proxy/modules/zttcp"
)

// --- glob matcher --------------------------------------------------------

func TestHostGlobLabelSemantics(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*.eu.example.com", "a.eu.example.com", true},
		{"*.eu.example.com", "eu.example.com", false},     // * needs exactly one label
		{"*.eu.example.com", "a.b.eu.example.com", false}, // * never spans labels
		{"status.example.com", "status.example.com", true},
		{"status.example.com", "STATUS.Example.COM", true}, // case-insensitive
		{"status.example.com", "status.example.org", false},
		{"*.local.example.com", "nas.local.example.com", true},
		{"*", "anything", true}, // single-label wildcard
		{"*", "a.b", false},     // still one label only
	}
	for _, c := range cases {
		if got := compileHostGlob(c.pattern).matches(c.host); got != c.want {
			t.Errorf("%q vs %q: got %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestHostAllowedEmptyMeansUnrestricted(t *testing.T) {
	if !hostAllowed(nil, "any.example.com") {
		t.Fatal("empty glob list must allow all hosts (legacy behavior)")
	}
	globs := compileHostGlobs([]string{"*.a.example.com", "b.example.com"})
	if !hostAllowed(globs, "x.a.example.com") || !hostAllowed(globs, "b.example.com") {
		t.Fatal("listed hosts should match")
	}
	if hostAllowed(globs, "c.example.com") {
		t.Fatal("unlisted host must not match")
	}
}

// --- peerIdentity --------------------------------------------------------

func makeCert(t *testing.T, cn string, sans []string, serial int64) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
	}
}

func TestPeerIdentity(t *testing.T) {
	cert := makeCert(t, "synology", []string{"edge-eu", "alt"}, 7)

	if id, ok := peerIdentity(cert, "cn"); !ok || id != "synology" {
		t.Fatalf("cn: got (%q,%v)", id, ok)
	}
	if id, ok := peerIdentity(cert, "san"); !ok || id != "edge-eu" {
		t.Fatalf("san: got (%q,%v)", id, ok)
	}
	if _, ok := peerIdentity(cert, "none"); ok {
		t.Fatal("none: must not enforce")
	}
	if _, ok := peerIdentity(cert, ""); ok {
		t.Fatal("empty: must not enforce")
	}
	// SAN mode with no SANs: enforced, matches nothing.
	noSAN := makeCert(t, "x", nil, 8)
	if id, ok := peerIdentity(noSAN, "san"); !ok || id != "" {
		t.Fatalf("san-no-SAN: got (%q,%v), want (\"\",true)", id, ok)
	}
}

// --- checkRegister -------------------------------------------------------

func appWithIdentity(bindTo string, unlisted bool, acl map[string][]string) *App {
	rt := &runtime{
		registry:    newRegistry(),
		tcpManager:  zttcp.NewManager(),
		bindTo:      bindTo,
		aclUnlisted: unlisted,
		acl:         make(map[string][]hostGlob),
	}
	for id, patterns := range acl {
		rt.acl[id] = compileHostGlobs(patterns)
	}
	return &App{rt: rt}
}

func svcFor(hostname string) *common.ServiceConfig {
	return &common.ServiceConfig{ServiceConfig: types.ServiceConfig{Hostname: hostname, Backend: "127.0.0.1:1", Protocol: "http"}}
}

func TestCheckRegisterVersion(t *testing.T) {
	app := appWithIdentity("none", true, nil)

	for _, v := range []int{0, 1, common.ProtocolVersion} {
		if _, err := app.checkRegister("a", v, nil); err != nil {
			t.Fatalf("version %d should be accepted: %v", v, err)
		}
	}
	if _, err := app.checkRegister("a", common.ProtocolVersion+1, nil); err == nil || err.reason != "version" {
		t.Fatalf("future version: got %v, want version rejection", err)
	}
	if _, err := app.checkRegister("a", -1, nil); err == nil || err.reason != "version" {
		t.Fatalf("negative version: got %v, want version rejection", err)
	}
}

func TestCheckRegisterIdentityBinding(t *testing.T) {
	app := appWithIdentity("cn", true, nil)
	cert := makeCert(t, "synology", nil, 9)

	if _, err := app.checkRegister("synology", 1, cert); err != nil {
		t.Fatalf("matching CN should pass: %v", err)
	}
	_, err := app.checkRegister("impostor", 1, cert)
	if err == nil || err.reason != "identity" {
		t.Fatalf("mismatched CN: got %v, want identity rejection", err)
	}
}

// A missing peer certificate must fail closed when identity binding is
// configured — never silently skip the check (the real listener always
// provides a cert, but the gate must not depend on that).
func TestCheckRegisterNoCertFailsClosed(t *testing.T) {
	for _, mode := range []string{"cn", "san"} {
		app := appWithIdentity(mode, true, nil)
		_, err := app.checkRegister("any-agent", 1, nil)
		if err == nil || err.reason != "identity" {
			t.Fatalf("bind_to=%s with nil cert: got %v, want identity rejection", mode, err)
		}
	}
	// none/"" mode keeps accepting cert-less callers (legacy behavior).
	for _, mode := range []string{"none", ""} {
		app := appWithIdentity(mode, true, nil)
		if _, err := app.checkRegister("any-agent", 1, nil); err != nil {
			t.Fatalf("bind_to=%q with nil cert should pass: %v", mode, err)
		}
	}
}

// End-to-end over a non-TLS pipe: the register path itself must reject
// a cert-less connection under bind_to=cn, keeping the registry empty.
func TestRegisterWithoutCertRejectedUnderBinding(t *testing.T) {
	app := appWithIdentity("cn", true, nil)
	resp := driveRegister(t, app, &common.Message{Type: "register", ID: "ghost"})
	if resp.Error == "" || !strings.Contains(resp.Error, "no client certificate") {
		t.Fatalf("expected cert-less rejection, got %+v", resp)
	}
	if n := app.AgentCount(); n != 0 {
		t.Fatalf("registry has %d agents, want 0", n)
	}
}

func TestCheckRegisterObserveModeCountsMismatch(t *testing.T) {
	app := appWithIdentity("none", true, nil)
	var mismatches int
	app.SetIdentityHooks(IdentityHooks{IdentityMismatch: func() { mismatches++ }})
	cert := makeCert(t, "synology", nil, 10)

	if _, err := app.checkRegister("impostor", 1, cert); err != nil {
		t.Fatalf("observe mode must not reject: %v", err)
	}
	if mismatches != 1 {
		t.Fatalf("mismatch metric = %d, want 1", mismatches)
	}
}

func TestCheckRegisterACL(t *testing.T) {
	app := appWithIdentity("none", false, map[string][]string{
		"synology": {"*.local.example.com"},
	})

	globs, err := app.checkRegister("synology", 1, nil)
	if err != nil {
		t.Fatalf("listed agent should pass: %v", err)
	}
	if len(globs) != 1 {
		t.Fatalf("expected compiled globs, got %d", len(globs))
	}
	if _, err := app.checkRegister("unknown", 1, nil); err == nil || err.reason != "acl" {
		t.Fatalf("unlisted agent with allow_unlisted=false: got %v, want acl rejection", err)
	}

	// allow_unlisted=true admits unknown agents with no restrictions.
	open := appWithIdentity("none", true, nil)
	globs, err2 := open.checkRegister("unknown", 1, nil)
	if err2 != nil || len(globs) != 0 {
		t.Fatalf("unlisted agent with allow_unlisted=true: got globs=%d err=%v", len(globs), err2)
	}
}

// --- register flow over a pipe ------------------------------------------

// driveRegister writes a register message and returns the response.
func driveRegister(t *testing.T, app *App, msg *common.Message) *common.Message {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.handleAgentConnection(server)
	}()

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if err := json.NewEncoder(client).Encode(msg); err != nil {
		t.Fatalf("send register: %v", err)
	}
	var resp common.Message
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	return &resp
}

func TestRegisterRejectedAgentNeverEntersRegistry(t *testing.T) {
	app := appWithIdentity("none", false, nil) // empty ACL, unlisted forbidden
	var rejected []string
	app.SetIdentityHooks(IdentityHooks{RegisterRejected: func(reason string) { rejected = append(rejected, reason) }})

	resp := driveRegister(t, app, &common.Message{Type: "register", ID: "ghost"})
	if resp.Error == "" {
		t.Fatal("expected rejection error in register_response")
	}
	// The ordering assertion: a rejected agent must never be routable.
	if n := app.AgentCount(); n != 0 {
		t.Fatalf("registry has %d agents after rejection, want 0", n)
	}
	if len(rejected) != 1 || rejected[0] != "acl" {
		t.Fatalf("rejection hook = %v, want [acl]", rejected)
	}
}

func TestRegisterAcceptedStoresMetaAndVersion(t *testing.T) {
	app := appWithIdentity("none", true, nil)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	go app.handleAgentConnection(server)

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	err := json.NewEncoder(client).Encode(&common.Message{
		Type:    "register",
		ID:      "synology",
		Version: common.ProtocolVersion,
		Meta:    &common.AgentMeta{Name: "NAS", Region: "home", Tags: []string{"prod"}},
	})
	if err != nil {
		t.Fatalf("send register: %v", err)
	}
	var resp common.Message
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("unexpected rejection: %s", resp.Error)
	}
	agent, ok := app.rt.registry.get("synology")
	if !ok {
		t.Fatal("agent missing from registry")
	}
	if agent.Meta.Name != "NAS" || agent.Meta.Region != "home" || agent.Version != common.ProtocolVersion {
		t.Fatalf("agent identity fields not stored: %+v version=%d", agent.Meta, agent.Version)
	}
}

// --- service_add ACL enforcement ----------------------------------------

// dispatchAndRead runs one agent message through the handler (in a
// goroutine — net.Pipe writes block until read) and returns the response.
func dispatchAndRead(t *testing.T, app *App, agent *Agent, client net.Conn, msg *common.Message) *common.Message {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- app.DispatchAgentMessageForTest(agent, msg) }()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var resp common.Message
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	return &resp
}

func TestServiceAddOutsideACLRejectedConnectionSurvives(t *testing.T) {
	app, agent, client := newAppWithPipe(t)
	agent.allowedHosts = compileHostGlobs([]string{"*.local.example.com"})

	// Disallowed host: error response, service not stored, dispatch
	// returns nil (the connection is NOT torn down).
	resp := dispatchAndRead(t, app, agent, client, &common.Message{
		Type: "service_add", ID: "m1", Service: svcFor("bank.example.com"),
	})
	if resp.Error == "" || !strings.Contains(resp.Error, "not permitted") {
		t.Fatalf("expected ACL rejection, got %+v", resp)
	}
	if _, ok := app.LookupAgent("bank.example.com"); ok {
		t.Fatal("denied service must not be routable")
	}

	// The same connection still accepts an allowed host.
	resp = dispatchAndRead(t, app, agent, client, &common.Message{
		Type: "service_add", ID: "m2", Service: svcFor("nas.local.example.com"),
	})
	if resp.Error != "" {
		t.Fatalf("allowed host rejected: %s", resp.Error)
	}
	if _, ok := app.LookupAgent("nas.local.example.com"); !ok {
		t.Fatal("allowed service should be routable")
	}

	// service_update follows the same ACL.
	resp = dispatchAndRead(t, app, agent, client, &common.Message{
		Type: "service_update", ID: "m3", Service: svcFor("bank.example.com"),
	})
	if resp.Error == "" {
		t.Fatal("service_update outside ACL must be rejected")
	}
}

// --- revocation ----------------------------------------------------------

func TestRevocationSet(t *testing.T) {
	set, err := buildRevocationSet(serverconfig.RevocationConfig{DeniedSerials: []string{"0A1B", "ff"}})
	if err != nil {
		t.Fatal(err)
	}
	if !set.has("0a1b") || !set.has("FF") {
		t.Fatal("serials should match case-insensitively")
	}
	if set.has("dead") {
		t.Fatal("unlisted serial must not match")
	}
	var nilSet *revocationSet
	if nilSet.has("0a1b") || !nilSet.empty() {
		t.Fatal("nil set must be empty and match nothing")
	}
}

func TestBuildRevocationSetFromCRL(t *testing.T) {
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CRL CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(0xBEEF), RevocationTime: time.Now()},
		},
	}, caCert, caKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	crlFile := filepath.Join(dir, "revoked.crl")
	if err := os.WriteFile(crlFile, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	set, err := buildRevocationSet(serverconfig.RevocationConfig{CRLFile: crlFile, DeniedSerials: []string{"AA"}})
	if err != nil {
		t.Fatalf("build from CRL: %v", err)
	}
	if !set.has("beef") || !set.has("aa") {
		t.Fatal("CRL serial and inline serial should both be present")
	}
	// Broken CRL keeps the error path.
	_ = os.WriteFile(crlFile, []byte("garbage"), 0o600)
	if _, err := buildRevocationSet(serverconfig.RevocationConfig{CRLFile: crlFile}); err == nil {
		t.Fatal("broken CRL must error (reload keeps previous set)")
	}
}

// --- full TLS handshake: revoked cert + cn binding ----------------------

// testPKI builds a CA plus server and client certs; returns the file
// paths for the server side and a tls.Certificate for the client.
func testPKI(t *testing.T, clientCN string, clientSerial int64) (certFile, keyFile, caFile string, clientCert tls.Certificate) {
	t.Helper()
	dir := t.TempDir()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	caFile = filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600)

	writeKeyPair := func(name string, tmpl *x509.Certificate) (string, string) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		cf := filepath.Join(dir, name+".crt")
		kf := filepath.Join(dir, name+".key")
		_ = os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
		keyDER, _ := x509.MarshalECPrivateKey(key)
		_ = os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
		return cf, kf
	}

	certFile, keyFile = writeKeyPair("server", &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	})
	clientCertFile, clientKeyFile := writeKeyPair("client", &x509.Certificate{
		SerialNumber: big.NewInt(clientSerial),
		Subject:      pkix.Name{CommonName: clientCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	cc, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		t.Fatalf("load client pair: %v", err)
	}
	return certFile, keyFile, caFile, cc
}

func startIdentityApp(t *testing.T, cfg serverconfig.AgentsConfig) *App {
	t.Helper()
	app, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = app.Stop() })
	return app
}

func dialAgent(t *testing.T, addr string, clientCert tls.Certificate, caFile string) *tls.Conn {
	t.Helper()
	caPEM, _ := os.ReadFile(caFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestTLSRevokedSerialFailsHandshake(t *testing.T) {
	certFile, keyFile, caFile, clientCert := testPKI(t, "revoked-agent", 0xBAD)
	app := startIdentityApp(t, serverconfig.AgentsConfig{
		Listen: "127.0.0.1:0", CertFile: certFile, KeyFile: keyFile, CAFile: caFile,
		Revocation: serverconfig.RevocationConfig{DeniedSerials: []string{"bad"}},
	})
	addr := app.rt.listener.Addr().String()

	conn := dialAgent(t, addr, clientCert, caFile)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	// The server aborts the handshake; the failure surfaces on first use.
	_ = json.NewEncoder(conn).Encode(&common.Message{Type: "register", ID: "revoked-agent"})
	var resp common.Message
	if err := json.NewDecoder(conn).Decode(&resp); err == nil {
		t.Fatalf("expected handshake failure, got response %+v", resp)
	}
	if n := app.AgentCount(); n != 0 {
		t.Fatalf("registry has %d agents, want 0", n)
	}
}

func TestTLSIdentityBindingCN(t *testing.T) {
	certFile, keyFile, caFile, clientCert := testPKI(t, "synology", 0x77)
	app := startIdentityApp(t, serverconfig.AgentsConfig{
		Listen: "127.0.0.1:0", CertFile: certFile, KeyFile: keyFile, CAFile: caFile,
		Identity: serverconfig.IdentityConfig{BindTo: "cn"},
	})
	addr := app.rt.listener.Addr().String()

	// Wrong ID under bind_to=cn → rejected, registry stays empty.
	conn := dialAgent(t, addr, clientCert, caFile)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_ = json.NewEncoder(conn).Encode(&common.Message{Type: "register", ID: "impostor"})
	var resp common.Message
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("read rejection: %v", err)
	}
	if resp.Error == "" || !strings.Contains(resp.Error, "does not match") {
		t.Fatalf("expected identity rejection, got %+v", resp)
	}
	if n := app.AgentCount(); n != 0 {
		t.Fatalf("registry has %d agents after rejection, want 0", n)
	}

	// Matching ID registers fine over the same PKI.
	conn2 := dialAgent(t, addr, clientCert, caFile)
	_ = conn2.SetDeadline(time.Now().Add(2 * time.Second))
	_ = json.NewEncoder(conn2).Encode(&common.Message{Type: "register", ID: "synology"})
	var ok common.Message
	if err := json.NewDecoder(conn2).Decode(&ok); err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if ok.Error != "" {
		t.Fatalf("matching CN rejected: %s", ok.Error)
	}
	if agent, found := app.rt.registry.get("synology"); !found || agent.CertSerial != "77" {
		t.Fatalf("agent not registered with cert serial: found=%v", found)
	}
}
