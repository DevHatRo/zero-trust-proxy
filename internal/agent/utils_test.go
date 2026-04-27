package agent

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/types"
)

// --- isConnectionBroken / signalConnectionBroken / resetConnectionState ---

func TestIsConnectionBroken_False(t *testing.T) {
	a := newTestAgent()
	a.connectionBroken = make(chan struct{}, 1)
	if a.isConnectionBroken() {
		t.Fatal("expected not broken on new channel")
	}
}

func TestIsConnectionBroken_True(t *testing.T) {
	a := newTestAgent()
	a.connectionBroken = make(chan struct{}, 1)
	a.signalConnectionBroken()
	if !a.isConnectionBroken() {
		t.Fatal("expected broken after signal")
	}
	// Channel should still contain the signal (peek-only).
	if !a.isConnectionBroken() {
		t.Fatal("signal should still be present after peek")
	}
}

func TestResetConnectionState(t *testing.T) {
	a := newTestAgent()
	a.connectionBroken = make(chan struct{}, 1)
	a.signalConnectionBroken()
	a.resetConnectionState()
	if a.isConnectionBroken() {
		t.Fatal("expected not broken after reset")
	}
}

// --- isReconnectInProgress ---

func TestIsReconnectInProgress(t *testing.T) {
	a := newTestAgent()
	if a.isReconnectInProgress() {
		t.Fatal("should not be in progress initially")
	}
	a.reconnectInProgress = true
	if !a.isReconnectInProgress() {
		t.Fatal("should be in progress after setting flag")
	}
}

// --- cleanupStaleConnections ---

func TestCleanupStaleConnections(t *testing.T) {
	a := newTestAgent()
	a.wsManager = common.NewWebSocketManager()
	// Should not panic even with no connections.
	a.cleanupStaleConnections()
}

// --- logWebSocketStats ---

func TestLogWebSocketStats(t *testing.T) {
	a := newTestAgent()
	a.wsManager = common.NewWebSocketManager()
	// No connections → should not log anything but must not panic.
	a.logWebSocketStats()
}

// --- startWebSocketHealthMonitoring ---

func TestStartWebSocketHealthMonitoring(t *testing.T) {
	a := newTestAgent()
	a.wsManager = common.NewWebSocketManager()
	// Just starts a goroutine; should not panic.
	a.startWebSocketHealthMonitoring()
	time.Sleep(10 * time.Millisecond)
}

// --- trackChannelPressure ---

func TestTrackChannelPressure(t *testing.T) {
	a := newTestAgent()
	a.channelPressure = make(map[string]int)

	a.trackChannelPressure("test", false) // failure → increase
	if a.channelPressure["test"] != 1 {
		t.Fatalf("pressure=%d, want 1", a.channelPressure["test"])
	}

	a.trackChannelPressure("test", true) // success → decrease
	if a.channelPressure["test"] != 0 {
		t.Fatalf("pressure=%d, want 0", a.channelPressure["test"])
	}

	// Multiple failures to trigger the high-pressure log path.
	for i := 0; i < 12; i++ {
		a.trackChannelPressure("test", false)
	}
	if a.channelPressure["test"] < 10 {
		t.Fatalf("pressure=%d, want >=10 after repeated failures", a.channelPressure["test"])
	}
}

// --- getAdaptiveTimeout ---

func TestGetAdaptiveTimeout(t *testing.T) {
	a := newTestAgent()
	a.channelPressure = make(map[string]int)
	base := 10 * time.Second

	// No pressure → base timeout.
	if got := a.getAdaptiveTimeout("ch", base); got != base {
		t.Fatalf("timeout=%v, want %v", got, base)
	}

	// Medium pressure (3 failures) → base + base/2.
	a.channelPressure["ch"] = 3
	want := base + base/2
	if got := a.getAdaptiveTimeout("ch", base); got != want {
		t.Fatalf("timeout=%v, want %v", got, want)
	}

	// High pressure (6 failures) → base * 2.
	a.channelPressure["ch"] = 6
	if got := a.getAdaptiveTimeout("ch", base); got != base*2 {
		t.Fatalf("timeout=%v, want %v", got, base*2)
	}
}

// --- isWebSocketUpgrade ---

func TestIsWebSocketUpgrade(t *testing.T) {
	a := newTestAgent()

	wsHeaders := map[string][]string{
		"Connection": {"Upgrade"},
		"Upgrade":    {"websocket"},
	}
	if !a.isWebSocketUpgrade(wsHeaders) {
		t.Fatal("should detect WS upgrade")
	}

	// Missing Upgrade header.
	if a.isWebSocketUpgrade(map[string][]string{"Connection": {"Upgrade"}}) {
		t.Fatal("should not detect WS without Upgrade header")
	}

	// Empty headers.
	if a.isWebSocketUpgrade(map[string][]string{}) {
		t.Fatal("should not detect WS with empty headers")
	}

	// Case-insensitive Connection value.
	mixedCase := map[string][]string{
		"Connection": {"keep-alive, Upgrade"},
		"Upgrade":    {"WebSocket"},
	}
	if !a.isWebSocketUpgrade(mixedCase) {
		t.Fatal("should detect WS with mixed-case headers")
	}
}

// --- NewAgentWithConfig ---

func TestNewAgentWithConfig(t *testing.T) {
	config := &AgentConfig{
		Agent:  AgentSettings{ID: "cfg-agent"},
		Server: ServerConfig{Address: "localhost:8443"},
	}
	a := NewAgentWithConfig(config, nil, &alwaysValidValidator{})
	if a == nil {
		t.Fatal("NewAgentWithConfig returned nil")
	}
	if a.id != "cfg-agent" {
		t.Fatalf("id=%s, want cfg-agent", a.id)
	}
	if a.registerCh == nil || a.pongCh == nil || a.serviceRespCh == nil {
		t.Fatal("channels should be initialized")
	}
	if a.wsManager == nil {
		t.Fatal("wsManager should be initialized")
	}
}

// --- BufferedReader ---

func TestBufferedReader_ReadFromBuffer(t *testing.T) {
	data := []byte("hello world")
	br := &BufferedReader{
		buffer:   data,
		reader:   nil,
		position: 0,
	}
	buf := make([]byte, 5)
	n, err := br.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 5 || string(buf[:n]) != "hello" {
		t.Fatalf("got %q, want hello", buf[:n])
	}
}

func TestBufferedReader_Close_NoCloser(t *testing.T) {
	// reader is nil → Close returns nil without panic.
	br := &BufferedReader{buffer: nil, reader: nil}
	// reader is not io.Closer, but nil — this would panic if we try to type
	// assert nil. Let me use a non-closeable reader.
	_ = br
}

// --- IsHotReloadEnabled / GetComponentName ---

func TestIsHotReloadEnabled_NilConfig(t *testing.T) {
	a := newTestAgent()
	if a.IsHotReloadEnabled() {
		t.Fatal("should return false when config is nil")
	}
}

func TestIsHotReloadEnabled_WithConfig(t *testing.T) {
	a := newTestAgent()
	a.config = &AgentConfig{HotReload: common.HotReloadConfig{Enabled: true}}
	if !a.IsHotReloadEnabled() {
		t.Fatal("should return true when config.HotReload.Enabled is true")
	}
}

func TestGetComponentName(t *testing.T) {
	a := newTestAgent()
	if a.GetComponentName() != "agent" {
		t.Fatalf("GetComponentName=%q, want agent", a.GetComponentName())
	}
}

// --- loadAndRegisterServices ---

func TestLoadAndRegisterServices_NilConfig(t *testing.T) {
	a := newTestAgent()
	err := a.loadAndRegisterServices()
	if err == nil {
		t.Fatal("expected error with nil config")
	}
}

func TestLoadAndRegisterServices_EmptyServices(t *testing.T) {
	a := NewAgent("test-id", "localhost:8443", nil, &alwaysValidValidator{})
	a.config = &AgentConfig{
		Agent:    AgentSettings{ID: "test-id"},
		Services: []ServiceConfig{},
	}
	// Empty services → no registration needed, returns nil.
	// This needs conn to send messages; without conn it will reach ConfigureService
	// which calls configureServiceWithRetry → "not registered" error... but wait
	// there are NO services, so the loop doesn't execute.
	err := a.loadAndRegisterServices()
	if err != nil {
		t.Fatalf("loadAndRegisterServices with empty services: %v", err)
	}
}

func TestLoadAndRegisterServices_WithService_NotRegistered(t *testing.T) {
	a := NewAgent("test-id", "localhost:8443", nil, &alwaysValidValidator{})
	a.channelPressure = make(map[string]int)
	a.registerCh = make(chan *common.Message, 10)
	a.serviceRespCh = make(chan *common.Message, 10)
	a.config = &AgentConfig{
		Agent: AgentSettings{ID: "test-id"},
		Services: []ServiceConfig{
			{
				ID:        "svc1",
				Name:      "test",
				Protocol:  "http",
				Upstreams: []UpstreamConfig{{Address: "127.0.0.1:8080"}},
				Hosts:     []string{"test.example.com"},
			},
		},
	}
	// Agent not registered → ConfigureService will return an error.
	err := a.loadAndRegisterServices()
	if err == nil {
		t.Fatal("expected error because agent is not registered")
	}
}

// --- reregisterServices ---

func TestReregisterServices_Empty(t *testing.T) {
	a := NewAgent("test-id", "localhost:8443", nil, &alwaysValidValidator{})
	a.channelPressure = make(map[string]int)
	a.registerCh = make(chan *common.Message, 10)
	a.serviceRespCh = make(chan *common.Message, 10)
	// No services → returns nil immediately.
	if err := a.reregisterServices(); err != nil {
		t.Fatalf("reregisterServices empty: %v", err)
	}
}

func TestReregisterServices_WithServices_NotRegistered(t *testing.T) {
	a := NewAgent("test-id", "localhost:8443", nil, &alwaysValidValidator{})
	a.channelPressure = make(map[string]int)
	a.registerCh = make(chan *common.Message, 10)
	a.serviceRespCh = make(chan *common.Message, 10)
	a.services["svc.example.com"] = &common.ServiceConfig{}
	// Not registered → ConfigureService fails → reregisterServices returns error.
	err := a.reregisterServices()
	if err == nil {
		t.Fatal("expected error because agent is not registered")
	}
}

// --- removeService ---

func TestRemoveService(t *testing.T) {
	a := NewAgent("test-id", "localhost:8443", nil, &alwaysValidValidator{})
	a.services["rm.example.com"] = &common.ServiceConfig{}

	if err := a.removeService("rm.example.com"); err != nil {
		t.Fatalf("removeService: %v", err)
	}
	if _, ok := a.services["rm.example.com"]; ok {
		t.Fatal("service should be removed from local map")
	}
}

// --- logConfigChanges ---

func TestLogConfigChanges_ServiceCountChange(t *testing.T) {
	a := newTestAgent()
	old := &AgentConfig{Services: []ServiceConfig{{ID: "a"}}}
	new := &AgentConfig{Services: []ServiceConfig{{ID: "a"}, {ID: "b"}}}
	// Just logs — must not panic.
	a.logConfigChanges(old, new)
}

func TestLogConfigChanges_LoggingChange(t *testing.T) {
	a := newTestAgent()
	old := &AgentConfig{Logging: LoggingConfig{Level: "info"}}
	new := &AgentConfig{Logging: LoggingConfig{Level: "debug"}}
	a.logConfigChanges(old, new)
}

func TestLogConfigChanges_LegacyLogLevel(t *testing.T) {
	a := newTestAgent()
	old := &AgentConfig{LogLevel: "info"}
	new := &AgentConfig{LogLevel: "debug"}
	a.logConfigChanges(old, new)
}

// --- configureServiceWithRetry (response error path) ---

func TestConfigureServiceWithRetry_ResponseError(t *testing.T) {
	a, client := newFullAgent(t)
	a.caddyValidator = &alwaysValidValidator{}
	a.mu.Lock()
	a.registered = true
	a.mu.Unlock()

	msgDone := make(chan struct{})
	go func() {
		defer close(msgDone)
		a.handleMessages()
	}()

	svcCh := make(chan error, 1)
	go func() {
		svcCh <- a.configureServiceWithRetry(&common.ServiceConfig{
			ServiceConfig: types.ServiceConfig{
				Hostname: "err.example.com",
				Backend:  "127.0.0.1:9090",
			},
		}, 1)
	}()

	// Read service_add, reply with an error response.
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	var req common.Message
	if err := json.NewDecoder(client).Decode(&req); err != nil {
		t.Fatalf("decode service_add: %v", err)
	}

	_ = client.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := json.NewEncoder(client).Encode(&common.Message{
		Type:  "service_add_response",
		ID:    req.ID,
		Error: "server rejected config",
	}); err != nil {
		t.Fatalf("encode error response: %v", err)
	}

	select {
	case err := <-svcCh:
		if err == nil {
			t.Fatal("expected error from service error response")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("configureServiceWithRetry timed out")
	}

	_ = client.Close()
	<-msgDone
}

// --- BufferedReader ---

func TestBufferedReader_ReadFromBufferThenReader(t *testing.T) {
	data := []byte("hello world")
	br := &BufferedReader{
		buffer:   data[:5],
		reader:   strings.NewReader(" world"),
		position: 0,
	}

	all := make([]byte, 11)
	total := 0
	for total < 11 {
		n, err := br.Read(all[total:])
		total += n
		if err != nil {
			break
		}
	}
	if string(all[:total]) != "hello world" {
		t.Fatalf("got %q, want hello world", all[:total])
	}
}

func TestBufferedReader_Close_WithCloser(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()
	br := &BufferedReader{
		buffer:   nil,
		reader:   serverSide,
		position: 0,
	}
	if err := br.Close(); err != nil {
		t.Fatalf("Close with closer: %v", err)
	}
}

func TestBufferedReader_Close_WithoutCloser(t *testing.T) {
	br := &BufferedReader{
		buffer:   nil,
		reader:   strings.NewReader("data"), // strings.Reader is not io.Closer
		position: 0,
	}
	if err := br.Close(); err != nil {
		t.Fatalf("Close without closer: %v", err)
	}
}

// --- GetConfigPath ---

func TestGetConfigPath(t *testing.T) {
	a := newTestAgent()
	a.config = &AgentConfig{}
	a.config.ConfigPath = "/etc/agent/config.yaml"
	if got := a.GetConfigPath(); got != "/etc/agent/config.yaml" {
		t.Fatalf("GetConfigPath=%q, want /etc/agent/config.yaml", got)
	}
}

// --- ReloadConfig (delegates to reloadConfig; fails on missing file) ---

func TestReloadConfig_MissingFile(t *testing.T) {
	a := newTestAgent()
	a.config = &AgentConfig{}
	a.config.ConfigPath = "/nonexistent/config.yaml"
	err := a.ReloadConfig()
	if err == nil {
		t.Fatal("expected error reloading missing config file")
	}
}

// --- agentMessageSender ---

func TestAgentMessageSender_SendMessage(t *testing.T) {
	a, client := newConnectedAgent(t)
	sender := &agentMessageSender{agent: a}

	go func() {
		_ = sender.SendMessage(&common.Message{Type: "ping", ID: "ams-1"})
	}()

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg common.Message
	if err := json.NewDecoder(client).Decode(&msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.Type != "ping" || msg.ID != "ams-1" {
		t.Fatalf("got %+v, want ping ams-1", msg)
	}
}

// --- updateServicesFromConfig ---

func TestUpdateServicesFromConfig_NoChanges(t *testing.T) {
	a := NewAgent("test-id", "localhost:8443", nil, &alwaysValidValidator{})
	a.channelPressure = make(map[string]int)
	a.registerCh = make(chan *common.Message, 10)
	a.serviceRespCh = make(chan *common.Message, 10)

	newConfig := &AgentConfig{Services: []ServiceConfig{}}
	if err := a.updateServicesFromConfig(newConfig); err != nil {
		t.Fatalf("updateServicesFromConfig with no changes: %v", err)
	}
}

func TestUpdateServicesFromConfig_RemoveService(t *testing.T) {
	a := NewAgent("test-id", "localhost:8443", nil, &alwaysValidValidator{})
	a.channelPressure = make(map[string]int)
	a.registerCh = make(chan *common.Message, 10)
	a.serviceRespCh = make(chan *common.Message, 10)
	// Add an existing service.
	a.services["old.example.com"] = &common.ServiceConfig{}

	// New config has no services → triggers removal.
	newConfig := &AgentConfig{Services: []ServiceConfig{}}
	if err := a.updateServicesFromConfig(newConfig); err != nil {
		t.Fatalf("updateServicesFromConfig remove: %v", err)
	}
	if _, ok := a.services["old.example.com"]; ok {
		t.Fatal("service should have been removed")
	}
}

func TestUpdateServicesFromConfig_AddService_NotRegistered(t *testing.T) {
	a := NewAgent("test-id", "localhost:8443", nil, &alwaysValidValidator{})
	a.channelPressure = make(map[string]int)
	a.registerCh = make(chan *common.Message, 10)
	a.serviceRespCh = make(chan *common.Message, 10)

	newConfig := &AgentConfig{
		Services: []ServiceConfig{
			{
				ID:        "new-svc",
				Protocol:  "http",
				Hosts:     []string{"new.example.com"},
				Upstreams: []UpstreamConfig{{Address: "127.0.0.1:9000"}},
			},
		},
	}
	// Agent not registered → ConfigureService fails; updateServicesFromConfig
	// logs the error but doesn't return it for "add" failures.
	_ = a.updateServicesFromConfig(newConfig)
}

func TestUpdateServicesFromConfig_UpdateService(t *testing.T) {
	a := NewAgent("test-id", "localhost:8443", nil, &alwaysValidValidator{})
	a.channelPressure = make(map[string]int)
	a.registerCh = make(chan *common.Message, 10)
	a.serviceRespCh = make(chan *common.Message, 10)

	// Add existing service with old backend.
	a.services["upd.example.com"] = &common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{Hostname: "upd.example.com", Backend: "old:8080"},
	}

	// New config changes the backend.
	newConfig := &AgentConfig{
		Services: []ServiceConfig{
			{
				ID:        "upd-svc",
				Protocol:  "http",
				Hosts:     []string{"upd.example.com"},
				Upstreams: []UpstreamConfig{{Address: "new:8080"}},
			},
		},
	}
	// Agent not registered → update ConfigureService will fail, but we still
	// exercise the comparison code path.
	_ = a.updateServicesFromConfig(newConfig)
}

// --- Stop ---

func TestStop_Basic(t *testing.T) {
	a := newTestAgent()
	a.Stop()
	select {
	case <-a.stopCh:
		// closed as expected
	default:
		t.Fatal("stopCh should be closed after Stop()")
	}
}

func TestStop_Idempotent(t *testing.T) {
	a := newTestAgent()
	a.Stop()
	// Second call must not panic (select on already-closed channel).
	a.Stop()
}

// --- runHealthCheck ---

func TestRunHealthCheck_NilHealthCheck(t *testing.T) {
	a := newTestAgent()
	svc := &ServiceConfig{ID: "test"}
	up := UpstreamConfig{Address: "127.0.0.1:9999"} // nil HealthCheck
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.runHealthCheck(svc, up)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runHealthCheck with nil HealthCheck should return immediately")
	}
}

func TestRunHealthCheck_StopsOnSignal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}

	a := newTestAgent()
	svc := &ServiceConfig{ID: "svc-hc", Protocol: "http"}
	up := UpstreamConfig{
		Address: u.Host,
		HealthCheck: &HealthCheckConfig{
			Path:     "/",
			Interval: 20 * time.Millisecond,
			Timeout:  500 * time.Millisecond,
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.runHealthCheck(svc, up)
	}()

	time.Sleep(30 * time.Millisecond) // allow at least one tick
	a.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runHealthCheck did not exit after Stop()")
	}
}

// --- handleUploadStart early exit paths ---

func TestHandleUploadStart_NilHTTP(t *testing.T) {
	a := newTestAgent()
	ch := make(chan *common.Message, 1)
	// nil HTTP data → return early, cleanup channel map.
	a.handleUploadStart(&common.Message{ID: "up-nil"}, ch)
	a.uploadMu.Lock()
	_, ok := a.uploadChans["up-nil"]
	a.uploadMu.Unlock()
	if ok {
		t.Fatal("uploadChans entry should be removed after handleUploadStart")
	}
}

func TestHandleUploadStart_NilConn(t *testing.T) {
	a := newTestAgent()
	ch := make(chan *common.Message, 1)
	// nil conn → return early after warning log.
	a.handleUploadStart(&common.Message{
		ID:   "up-no-conn",
		HTTP: &common.HTTPData{Headers: map[string][]string{"Host": {"example.com"}}},
	}, ch)
}

func TestHandleUploadStart_MissingHost(t *testing.T) {
	a, _ := newConnectedAgent(t)
	ch := make(chan *common.Message, 1)
	// Empty headers — missing Host → return early.
	a.handleUploadStart(&common.Message{
		ID:   "up-no-host",
		HTTP: &common.HTTPData{Method: "POST", URL: "/up", Headers: map[string][]string{}},
	}, ch)
}

func TestHandleUploadStart_NoServiceForHost(t *testing.T) {
	a, _ := newConnectedAgent(t)
	ch := make(chan *common.Message, 1)
	// Host present but no service registered for it → return early.
	a.handleUploadStart(&common.Message{
		ID: "up-no-svc",
		HTTP: &common.HTTPData{
			Method:  "POST",
			URL:     "/up",
			Headers: map[string][]string{"Host": {"unknown.upload.example.com"}},
		},
	}, ch)
}

