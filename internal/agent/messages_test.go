package agent

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/types"
)

// alwaysValidValidator is a no-op ServiceValidator that accepts everything.
type alwaysValidValidator struct{}

func (v *alwaysValidValidator) ValidateServiceConfig(_ *types.ServiceConfig) *types.ValidationResult {
	return &types.ValidationResult{Valid: true}
}
func (v *alwaysValidValidator) AddExistingService(_ string, _ *types.ServiceConfig) {}
func (v *alwaysValidValidator) RemoveExistingService(_ string)                       {}
func (v *alwaysValidValidator) GetExistingServices() map[string]*types.ServiceConfig {
	return nil
}

// newFullAgent creates an Agent with all channels and state required by
// handleMessages, sendRawHTTPResponse, handleWebSocketFrame, etc.
func newFullAgent(t *testing.T) (*Agent, net.Conn) {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() {
		_ = serverSide.Close()
		_ = clientSide.Close()
	})
	a := NewAgent("test-id", "localhost:8443", nil, &alwaysValidValidator{})
	a.conn = serverSide
	a.encoder = json.NewEncoder(serverSide)
	a.decoder = json.NewDecoder(serverSide)
	a.registerCh = make(chan *common.Message, 10)
	a.pongCh = make(chan *common.Message, 10)
	a.serviceRespCh = make(chan *common.Message, 10)
	a.channelPressure = make(map[string]int)
	a.wsManager = common.NewWebSocketManager()
	a.connectionBroken = make(chan struct{}, 1)
	// Pre-set reconnectInProgress so attemptReconnection returns immediately on
	// connection close without trying to dial the (non-existent) server.
	a.reconnectInProgress = true
	return a, clientSide
}

// sendToAgent encodes a message and writes it to clientConn.
func sendToAgent(t *testing.T, clientConn net.Conn, msg *common.Message) {
	t.Helper()
	_ = clientConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := json.NewEncoder(clientConn).Encode(msg); err != nil {
		t.Fatalf("sendToAgent: %v", err)
	}
}

// recvFromAgent decodes a message written by the agent to clientConn.
func recvFromAgent(t *testing.T, clientConn net.Conn) *common.Message {
	t.Helper()
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg common.Message
	if err := json.NewDecoder(clientConn).Decode(&msg); err != nil {
		t.Fatalf("recvFromAgent: %v", err)
	}
	return &msg
}

// --- handleMessages ---

func TestHandleMessages_PingRespondsWithPong(t *testing.T) {
	a, client := newFullAgent(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleMessages()
	}()

	sendToAgent(t, client, &common.Message{Type: "ping", ID: "ping-1"})
	resp := recvFromAgent(t, client)
	if resp.Type != "pong" || resp.ID != "ping-1" {
		t.Fatalf("got %+v, want pong ping-1", resp)
	}

	// Close to terminate handleMessages.
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleMessages did not exit after connection close")
	}
}

func TestHandleMessages_RegisterResponse(t *testing.T) {
	a, client := newFullAgent(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleMessages()
	}()

	sendToAgent(t, client, &common.Message{Type: "register_response", ID: "r1"})

	select {
	case msg := <-a.registerCh:
		if msg.ID != "r1" {
			t.Fatalf("registerCh: id=%s, want r1", msg.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for register_response on channel")
	}

	a.mu.RLock()
	registered := a.registered
	a.mu.RUnlock()
	if !registered {
		t.Fatal("agent.registered should be true after register_response")
	}

	_ = client.Close()
	<-done
}

func TestHandleMessages_PongResponse(t *testing.T) {
	a, client := newFullAgent(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleMessages()
	}()

	sendToAgent(t, client, &common.Message{Type: "pong", ID: "p1"})

	select {
	case msg := <-a.pongCh:
		if msg.ID != "p1" {
			t.Fatalf("pongCh: id=%s, want p1", msg.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for pong on channel")
	}

	_ = client.Close()
	<-done
}

func TestHandleMessages_ServiceAddResponse(t *testing.T) {
	a, client := newFullAgent(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleMessages()
	}()

	sendToAgent(t, client, &common.Message{Type: "service_add_response", ID: "s1"})

	select {
	case msg := <-a.serviceRespCh:
		if msg.ID != "s1" {
			t.Fatalf("serviceRespCh: id=%s, want s1", msg.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for service_add_response on channel")
	}

	_ = client.Close()
	<-done
}

func TestHandleMessages_ServiceUpdateResponse(t *testing.T) {
	a, client := newFullAgent(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleMessages()
	}()

	sendToAgent(t, client, &common.Message{Type: "service_update_response", ID: "u1"})

	select {
	case msg := <-a.serviceRespCh:
		if msg.ID != "u1" {
			t.Fatalf("serviceRespCh: id=%s, want u1", msg.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for service_update_response on channel")
	}

	_ = client.Close()
	<-done
}

func TestHandleMessages_ServiceRemoveResponse(t *testing.T) {
	a, client := newFullAgent(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleMessages()
	}()

	sendToAgent(t, client, &common.Message{Type: "service_remove_response", ID: "sr1"})

	select {
	case msg := <-a.serviceRespCh:
		if msg.ID != "sr1" {
			t.Fatalf("serviceRespCh: id=%s, want sr1", msg.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for service_remove_response on channel")
	}

	_ = client.Close()
	<-done
}

func TestHandleMessages_UploadStartAndChunk(t *testing.T) {
	a, client := newFullAgent(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleMessages()
	}()

	// Send upload_start; handleMessages creates the uploadChans entry and
	// launches handleUploadStart in a goroutine. The goroutine will exit
	// quickly (no backend service registered) and clean up the channel — we
	// just verify handleMessages dispatches the message without crashing.
	sendToAgent(t, client, &common.Message{
		Type: "http_upload_start",
		ID:   "up-1",
		HTTP: &common.HTTPData{
			Method:    "POST",
			URL:       "/up",
			TotalSize: 5,
			Headers:   map[string][]string{"Host": {"upload.example.com"}},
		},
	})
	time.Sleep(30 * time.Millisecond)

	// Also verify that upload_chunk for an unknown ID is handled without crash.
	sendToAgent(t, client, &common.Message{
		Type: "http_upload_chunk",
		ID:   "unknown-up",
		HTTP: &common.HTTPData{Body: []byte("hello"), IsLastChunk: true},
	})
	time.Sleep(30 * time.Millisecond)

	_ = client.Close()
	<-done
}

func TestHandleMessages_WebSocketFrameDroppedWhenNoConn(t *testing.T) {
	a, client := newFullAgent(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleMessages()
	}()

	// No WS connection registered → frame is silently dropped (just logging).
	sendToAgent(t, client, &common.Message{
		Type: "websocket_frame",
		ID:   "xxxxxxxxxxxxxxxx",
		HTTP: &common.HTTPData{Body: []byte("data"), IsWebSocket: true},
	})

	time.Sleep(30 * time.Millisecond)

	_ = client.Close()
	<-done
}

func TestHandleMessages_WebSocketDisconnect(t *testing.T) {
	a, client := newFullAgent(t)

	// Register a WS connection.
	wsClient, wsServer := net.Pipe()
	t.Cleanup(func() { _ = wsClient.Close(); _ = wsServer.Close() })
	a.wsManager.AddConnection("ws-disc-01234567", wsServer)

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleMessages()
	}()

	sendToAgent(t, client, &common.Message{
		Type: "websocket_disconnect",
		ID:   "ws-disc-01234567",
	})
	time.Sleep(50 * time.Millisecond)

	if a.wsManager.GetConnectionCount() != 0 {
		t.Fatal("wsManager should have no connections after websocket_disconnect")
	}

	_ = client.Close()
	<-done
}

func TestHandleMessages_UnknownTypeIgnored(t *testing.T) {
	a, client := newFullAgent(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleMessages()
	}()

	// Unknown type just logs an error; should not crash.
	sendToAgent(t, client, &common.Message{Type: "totally_unknown", ID: "x"})
	time.Sleep(30 * time.Millisecond)

	_ = client.Close()
	<-done
}

func TestHandleMessages_EOFExits(t *testing.T) {
	a, client := newFullAgent(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleMessages()
	}()

	_ = client.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleMessages did not exit on EOF")
	}
}

// --- sendRawHTTPResponse ---

func TestSendRawHTTPResponse_Normal(t *testing.T) {
	a, client := newConnectedAgent(t)

	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"
	go func() { a.sendRawHTTPResponse("req-raw", raw) }()

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg common.Message
	if err := json.NewDecoder(client).Decode(&msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.HTTP == nil || msg.HTTP.StatusCode != 200 {
		t.Fatalf("expected 200 got %+v", msg.HTTP)
	}
	if string(msg.HTTP.Body) != "hello" {
		t.Fatalf("body=%q, want hello", msg.HTTP.Body)
	}
	if msg.HTTP.Headers["Content-Type"][0] != "text/plain" {
		t.Fatalf("Content-Type=%v", msg.HTTP.Headers["Content-Type"])
	}
}

func TestSendRawHTTPResponse_WebSocketUpgrade(t *testing.T) {
	a, client := newConnectedAgent(t)

	raw := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
	go func() { a.sendRawHTTPResponse("req-ws", raw) }()

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg common.Message
	if err := json.NewDecoder(client).Decode(&msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.HTTP == nil || msg.HTTP.StatusCode != 101 {
		t.Fatalf("status=%d, want 101", msg.HTTP.StatusCode)
	}
	if !msg.HTTP.IsWebSocket {
		t.Fatal("IsWebSocket should be true for 101")
	}
}

func TestSendRawHTTPResponse_EmptyLine(t *testing.T) {
	a := newTestAgent()
	// Empty string splits to one empty element — len(parts) < 2, returns early.
	a.sendRawHTTPResponse("req-empty", "")
}

func TestSendRawHTTPResponse_StatusOnly(t *testing.T) {
	a, client := newConnectedAgent(t)

	raw := "HTTP/1.1 404 Not Found\r\n\r\n"
	go func() { a.sendRawHTTPResponse("req-404", raw) }()

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg common.Message
	if err := json.NewDecoder(client).Decode(&msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.HTTP.StatusCode != 404 {
		t.Fatalf("status=%d, want 404", msg.HTTP.StatusCode)
	}
	if msg.HTTP.StatusMessage != "Not Found" {
		t.Fatalf("statusMsg=%q, want Not Found", msg.HTTP.StatusMessage)
	}
}

// --- handleWebSocketFrame ---

func TestHandleWebSocketFrame_NilHTTP(t *testing.T) {
	a := newTestAgent()
	a.wsManager = common.NewWebSocketManager()
	// nil HTTP → returns early, no panic.
	a.handleWebSocketFrame(&common.Message{ID: "00000000000000000000000000000001"})
}

func TestHandleWebSocketFrame_EmptyBody(t *testing.T) {
	a := newTestAgent()
	a.wsManager = common.NewWebSocketManager()
	a.handleWebSocketFrame(&common.Message{
		ID:   "00000000000000000000000000000002",
		HTTP: &common.HTTPData{Body: []byte{}},
	})
}

func TestHandleWebSocketFrame_ConnNotFound(t *testing.T) {
	a := newTestAgent()
	a.wsManager = common.NewWebSocketManager()
	// ID not registered → silently dropped (logging only).
	a.handleWebSocketFrame(&common.Message{
		ID:   "00000000000000000000000000000003",
		HTTP: &common.HTTPData{Body: []byte("frame"), IsWebSocket: true},
	})
}

func TestHandleWebSocketFrame_ForwardsToBackend(t *testing.T) {
	a := newTestAgent()
	a.wsManager = common.NewWebSocketManager()

	wsClient, wsServer := net.Pipe()
	t.Cleanup(func() { _ = wsClient.Close(); _ = wsServer.Close() })
	a.wsManager.AddConnection("ws-fwd-0000000000000001", wsServer)

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleWebSocketFrame(&common.Message{
			ID: "ws-fwd-0000000000000001",
			HTTP: &common.HTTPData{
				Body:        []byte("hello-ws"),
				IsWebSocket: true,
			},
		})
	}()

	_ = wsClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := wsClient.Read(buf)
	if err != nil {
		t.Fatalf("read from backend: %v", err)
	}
	if string(buf[:n]) != "hello-ws" {
		t.Fatalf("got %q, want hello-ws", buf[:n])
	}
	<-done
}

// --- handleWebSocketDisconnect ---

func TestHandleWebSocketDisconnect(t *testing.T) {
	a := newTestAgent()
	a.wsManager = common.NewWebSocketManager()

	wsClient, wsServer := net.Pipe()
	t.Cleanup(func() { _ = wsClient.Close(); _ = wsServer.Close() })
	a.wsManager.AddConnection("disc-00000000000000001", wsServer)

	if a.wsManager.GetConnectionCount() != 1 {
		t.Fatal("expected 1 ws connection before disconnect")
	}

	a.handleWebSocketDisconnect(&common.Message{ID: "disc-00000000000000001"})

	if a.wsManager.GetConnectionCount() != 0 {
		t.Fatal("expected 0 ws connections after disconnect")
	}
}

// --- checkUpstreamHealth ---

func TestCheckUpstreamHealth_NilHealthCheck(t *testing.T) {
	a := newTestAgent()
	svc := &ServiceConfig{ID: "test"}
	up := UpstreamConfig{Address: "127.0.0.1:9999"}
	if !a.checkUpstreamHealth(svc, up) {
		t.Fatal("nil health check should return healthy=true")
	}
}

func TestCheckUpstreamHealth_EmptyPath(t *testing.T) {
	a := newTestAgent()
	svc := &ServiceConfig{ID: "test"}
	up := UpstreamConfig{
		Address:     "127.0.0.1:9999",
		HealthCheck: &HealthCheckConfig{Path: ""},
	}
	if !a.checkUpstreamHealth(svc, up) {
		t.Fatal("empty path should return healthy=true")
	}
}

func TestCheckUpstreamHealth_RealServerHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := newTestAgent()
	svc := &ServiceConfig{ID: "test", Protocol: "http"}
	up := UpstreamConfig{
		Address: srv.Listener.Addr().String(),
		HealthCheck: &HealthCheckConfig{
			Path:    "/healthz",
			Method:  "GET",
			Timeout: 2 * time.Second,
		},
	}
	if !a.checkUpstreamHealth(svc, up) {
		t.Fatal("expected healthy=true from real server returning 200")
	}
}

func TestCheckUpstreamHealth_RealServerUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := newTestAgent()
	svc := &ServiceConfig{ID: "test", Protocol: "http"}
	up := UpstreamConfig{
		Address: srv.Listener.Addr().String(),
		HealthCheck: &HealthCheckConfig{
			Path:    "/healthz",
			Timeout: 2 * time.Second,
		},
	}
	if a.checkUpstreamHealth(svc, up) {
		t.Fatal("expected healthy=false from server returning 500")
	}
}

func TestCheckUpstreamHealth_ServerUnreachable(t *testing.T) {
	a := newTestAgent()
	svc := &ServiceConfig{ID: "test", Protocol: "http"}
	up := UpstreamConfig{
		Address: "127.0.0.1:1", // unreachable
		HealthCheck: &HealthCheckConfig{
			Path:    "/healthz",
			Timeout: 200 * time.Millisecond,
		},
	}
	if a.checkUpstreamHealth(svc, up) {
		t.Fatal("expected healthy=false from unreachable server")
	}
}

func TestCheckUpstreamHealth_WithCustomHeaders(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := newTestAgent()
	svc := &ServiceConfig{ID: "test", Protocol: "http"}
	up := UpstreamConfig{
		Address: srv.Listener.Addr().String(),
		HealthCheck: &HealthCheckConfig{
			Path:    "/healthz",
			Timeout: 2 * time.Second,
			Headers: map[string]string{"Authorization": "Bearer token123"},
		},
	}
	if !a.checkUpstreamHealth(svc, up) {
		t.Fatal("expected healthy=true")
	}
	if gotAuth != "Bearer token123" {
		t.Fatalf("Authorization header=%q, want Bearer token123", gotAuth)
	}
}

// --- startGlobalHealthChecks ---

func TestStartGlobalHealthChecks_NoEndpoints(t *testing.T) {
	a := newTestAgent()
	config := &AgentConfig{
		HealthChecks: HealthCheckSettings{Endpoints: nil},
	}
	if err := a.startGlobalHealthChecks(config); err != nil {
		t.Fatalf("startGlobalHealthChecks with no endpoints: %v", err)
	}
}

func TestStartGlobalHealthChecks_WithEndpoints(t *testing.T) {
	a := newTestAgent()
	config := &AgentConfig{
		HealthChecks: HealthCheckSettings{
			Endpoints: []HealthCheckEndpoint{{Path: "/ready", Response: "ok"}},
		},
	}
	if err := a.startGlobalHealthChecks(config); err != nil {
		t.Fatalf("startGlobalHealthChecks with endpoints: %v", err)
	}
	// Give the goroutine a moment to start; it will fail to bind :0 quietly.
	time.Sleep(20 * time.Millisecond)
}

// --- ConfigureService ---

func newConnectedAgentWithValidator(t *testing.T) (*Agent, net.Conn) {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() {
		_ = serverSide.Close()
		_ = clientSide.Close()
	})
	a := NewAgent("test-id", "localhost:8443", nil, &alwaysValidValidator{})
	a.conn = serverSide
	a.encoder = json.NewEncoder(serverSide)
	a.decoder = json.NewDecoder(serverSide)
	a.registerCh = make(chan *common.Message, 10)
	a.serviceRespCh = make(chan *common.Message, 10)
	a.channelPressure = make(map[string]int)
	return a, clientSide
}

func TestConfigureService_NotRegistered(t *testing.T) {
	a, _ := newConnectedAgentWithValidator(t)
	// registered=false → configureServiceWithRetry returns "agent not registered"
	// after maxAttempts. Use maxAttempts=1 to avoid sleep delays.
	err := a.configureServiceWithRetry(&common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{
			Hostname: "unregistered.example.com",
			Backend:  "127.0.0.1:8080",
		},
	}, 1)
	if err == nil {
		t.Fatal("expected error when agent is not registered")
	}
}

func TestConfigureService_ValidationFails(t *testing.T) {
	a, _ := newConnectedAgentWithValidator(t)
	// Agent is not registered, so ConfigureService should return an error.
	err := a.ConfigureService(&common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{
			Hostname: "cfg.example.com",
			Backend:  "127.0.0.1:8080",
		},
	})
	if err == nil {
		t.Fatal("expected error for unregistered agent in ConfigureService")
	}
}

func TestConfigureService_RegisteredSendsMessage(t *testing.T) {
	a, client := newFullAgent(t)
	a.caddyValidator = &alwaysValidValidator{}
	a.mu.Lock()
	a.registered = true
	a.mu.Unlock()

	// handleMessages reads the service_add_response and puts it on serviceRespCh.
	msgDone := make(chan struct{})
	go func() {
		defer close(msgDone)
		a.handleMessages()
	}()

	svcCh := make(chan error, 1)
	go func() {
		svcCh <- a.ConfigureService(&common.ServiceConfig{
			ServiceConfig: types.ServiceConfig{
				Hostname: "live.example.com",
				Backend:  "127.0.0.1:9090",
			},
		})
	}()

	// Read the service_add message from the pipe.
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	var req common.Message
	if err := json.NewDecoder(client).Decode(&req); err != nil {
		t.Fatalf("decode service_add: %v", err)
	}
	if req.Type != "service_add" {
		t.Fatalf("expected service_add, got %s", req.Type)
	}

	// Reply with service_add_response.
	_ = client.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := json.NewEncoder(client).Encode(&common.Message{
		Type: "service_add_response",
		ID:   req.ID,
	}); err != nil {
		t.Fatalf("encode service_add_response: %v", err)
	}

	select {
	case err := <-svcCh:
		if err != nil {
			t.Fatalf("ConfigureService returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ConfigureService timed out")
	}

	_ = client.Close()
	<-msgDone
}
