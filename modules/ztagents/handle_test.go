package ztagents

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/types"
)

// newAppWithWS creates an App with both a registry and a WebSocket manager.
func newAppWithWS(t *testing.T) (*App, *Agent, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	app := &App{rt: &runtime{
		registry:  newRegistry(),
		wsManager: common.NewWebSocketManager(),
	}}
	agent := NewAgent("test-agent", server)
	app.rt.registry.add(agent)
	return app, agent, client
}

func newAppWithPipe(t *testing.T) (*App, *Agent, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	app := &App{rt: &runtime{registry: newRegistry()}}
	agent := NewAgent("test-agent", server)
	app.rt.registry.add(agent)
	return app, agent, client
}

func readMessage(t *testing.T, c net.Conn) *common.Message {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg common.Message
	if err := json.NewDecoder(c).Decode(&msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return &msg
}

func TestHandleMessagePing(t *testing.T) {
	app, agent, client := newAppWithPipe(t)

	go func() {
		_ = app.handleAgentMessage(agent, &common.Message{Type: "ping", ID: "p1"})
	}()

	resp := readMessage(t, client)
	if resp.Type != "pong" || resp.ID != "p1" {
		t.Fatalf("got %+v, want pong p1", resp)
	}
}

func TestHandleMessageServiceAddRegistersHost(t *testing.T) {
	app, agent, client := newAppWithPipe(t)

	msg := &common.Message{
		Type: "service_add",
		ID:   "s1",
		Service: &common.ServiceConfig{
			ServiceConfig: types.ServiceConfig{Hostname: "app.example.com"},
		},
	}
	go func() { _ = app.handleAgentMessage(agent, msg) }()

	resp := readMessage(t, client)
	if resp.Type != "service_add_response" {
		t.Fatalf("got %s, want service_add_response", resp.Type)
	}

	if found, ok := app.LookupAgent("app.example.com"); !ok || found != agent {
		t.Fatalf("LookupAgent: ok=%v agent=%v", ok, found)
	}
}

func TestHandleMessageServiceRemoveUnregistersHost(t *testing.T) {
	app, agent, client := newAppWithPipe(t)
	agent.Services["app.example.com"] = &common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{Hostname: "app.example.com"},
	}

	msg := &common.Message{
		Type: "service_remove",
		ID:   "s1",
		Service: &common.ServiceConfig{
			ServiceConfig: types.ServiceConfig{Hostname: "app.example.com"},
		},
	}
	go func() { _ = app.handleAgentMessage(agent, msg) }()

	resp := readMessage(t, client)
	if resp.Type != "service_remove_response" {
		t.Fatalf("got %s, want service_remove_response", resp.Type)
	}

	if _, ok := app.LookupAgent("app.example.com"); ok {
		t.Fatal("host should be unregistered")
	}
}

func TestHandleMessageHttpResponseRoutesToHandler(t *testing.T) {
	app, agent, _ := newAppWithPipe(t)

	got := make(chan *common.Message, 4)
	agent.SetResponseHandler("req-42", func(m *common.Message) { got <- m })

	// Dispatch twice — the same handler must be reachable for both, since
	// download streaming delivers the initial response plus subsequent chunks
	// through the same registration. The router's defer is responsible for
	// removing the handler when the request finishes.
	for i := 0; i < 2; i++ {
		err := app.handleAgentMessage(agent, &common.Message{
			Type: "http_response",
			ID:   "req-42",
			HTTP: &common.HTTPData{StatusCode: 200},
		})
		if err != nil {
			t.Fatalf("handleAgentMessage #%d: %v", i, err)
		}
	}

	for i := 0; i < 2; i++ {
		select {
		case m := <-got:
			if m.HTTP.StatusCode != 200 {
				t.Fatalf("status=%d, want 200", m.HTTP.StatusCode)
			}
		case <-time.After(1 * time.Second):
			t.Fatalf("handler not invoked for dispatch #%d", i)
		}
	}

	if _, ok := agent.GetResponseHandler("req-42"); !ok {
		t.Fatal("handler should still be registered; removal is the caller's job")
	}
}

func TestHandleMessageRejectsMissingService(t *testing.T) {
	app, agent, _ := newAppWithPipe(t)
	err := app.handleAgentMessage(agent, &common.Message{Type: "service_add", ID: "x"})
	if err == nil {
		t.Fatal("expected error for service_add without config")
	}
}

func TestHandleMessageServiceUpdate(t *testing.T) {
	app, agent, client := newAppWithPipe(t)
	agent.Services["svc.example.com"] = &common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{Hostname: "svc.example.com"},
	}

	go func() {
		_ = app.handleAgentMessage(agent, &common.Message{
			Type: "service_update",
			ID:   "u1",
			Service: &common.ServiceConfig{
				ServiceConfig: types.ServiceConfig{Hostname: "svc.example.com", Backend: "127.0.0.1:9000"},
			},
		})
	}()

	resp := readMessage(t, client)
	if resp.Type != "service_update_response" {
		t.Fatalf("got %s, want service_update_response", resp.Type)
	}
	agent.mu.RLock()
	svc := agent.Services["svc.example.com"]
	agent.mu.RUnlock()
	if svc.Backend != "127.0.0.1:9000" {
		t.Fatalf("backend=%s, want 127.0.0.1:9000", svc.Backend)
	}
}

func TestHandleMessageServiceUpdateMissingConfig(t *testing.T) {
	app, agent, _ := newAppWithPipe(t)
	err := app.handleAgentMessage(agent, &common.Message{Type: "service_update", ID: "u2"})
	if err == nil {
		t.Fatal("expected error for service_update without config")
	}
}

func TestHandleMessageServiceAddEnhanced(t *testing.T) {
	app, agent, client := newAppWithPipe(t)

	go func() {
		_ = app.handleAgentMessage(agent, &common.Message{
			Type: "service_add",
			ID:   "e1",
			EnhancedService: &common.EnhancedServiceConfig{
				Hostname: "enhanced.example.com",
				Protocol: "https",
			},
		})
	}()

	resp := readMessage(t, client)
	if resp.Type != "service_add_response" {
		t.Fatalf("got %s, want service_add_response", resp.Type)
	}
	agent.mu.RLock()
	_, exists := agent.Services["enhanced.example.com"]
	agent.mu.RUnlock()
	if !exists {
		t.Fatal("enhanced service not registered in agent.Services")
	}
}

func TestHandleMessageWebSocketFrame(t *testing.T) {
	app, agent, _ := newAppWithWS(t)

	// Register a WebSocket connection.
	wsClient, wsServer := net.Pipe()
	t.Cleanup(func() { _ = wsClient.Close(); _ = wsServer.Close() })
	app.rt.wsManager.AddConnection("ws-1", wsServer)

	// Run in goroutine: writeAll(wsServer) blocks until wsClient reads.
	errCh := make(chan error, 1)
	go func() {
		errCh <- app.handleAgentMessage(agent, &common.Message{
			Type: "websocket_frame",
			ID:   "ws-1",
			HTTP: &common.HTTPData{Body: []byte("frame-data"), IsWebSocket: true},
		})
	}()

	// The frame should arrive on the client side of the WebSocket pipe.
	_ = wsClient.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, err := wsClient.Read(buf)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if string(buf[:n]) != "frame-data" {
		t.Fatalf("got %q, want frame-data", buf[:n])
	}

	if err := <-errCh; err != nil {
		t.Fatalf("handleAgentMessage: %v", err)
	}
}

func TestHandleMessageWebSocketDisconnect(t *testing.T) {
	app, agent, _ := newAppWithWS(t)

	wsClient, wsServer := net.Pipe()
	t.Cleanup(func() { _ = wsClient.Close(); _ = wsServer.Close() })
	app.rt.wsManager.AddConnection("ws-2", wsServer)

	if app.rt.wsManager.GetConnectionCount() != 1 {
		t.Fatalf("expected 1 ws connection before disconnect")
	}

	err := app.handleAgentMessage(agent, &common.Message{
		Type: "websocket_disconnect",
		ID:   "ws-2",
	})
	if err != nil {
		t.Fatalf("handleAgentMessage: %v", err)
	}

	if app.rt.wsManager.GetConnectionCount() != 0 {
		t.Fatalf("expected 0 ws connections after disconnect")
	}
}

func TestHandleMessageRegisterDuplicate(t *testing.T) {
	app, agent, client := newAppWithPipe(t)

	// First register — sets Registered=true and sends response.
	go func() {
		_ = app.handleAgentMessage(agent, &common.Message{Type: "register", ID: "r1"})
	}()
	resp := readMessage(t, client)
	if resp.Type != "register_response" {
		t.Fatalf("got %s, want register_response", resp.Type)
	}

	// Second register — already registered, should be a no-op (no response sent).
	err := app.handleAgentMessage(agent, &common.Message{Type: "register", ID: "r2"})
	if err != nil {
		t.Fatalf("second register: %v", err)
	}
	// No message should arrive within a short timeout.
	_ = client.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	var msg common.Message
	if decErr := json.NewDecoder(client).Decode(&msg); decErr == nil {
		t.Fatalf("unexpected message on second register: %+v", msg)
	}
}

func TestHandleMessageUnknownType(t *testing.T) {
	app, agent, _ := newAppWithPipe(t)
	// Unknown types are silently ignored — no error, no response.
	if err := app.handleAgentMessage(agent, &common.Message{Type: "unknown_op", ID: "x"}); err != nil {
		t.Fatalf("unexpected error for unknown type: %v", err)
	}
}

func TestHandleMessageNilAgent(t *testing.T) {
	app := &App{rt: &runtime{registry: newRegistry(), wsManager: common.NewWebSocketManager()}}
	if err := app.handleAgentMessage(nil, &common.Message{Type: "ping"}); err == nil {
		t.Fatal("expected error for nil agent")
	}
}

func TestHandleMessageNilMessage(t *testing.T) {
	app, agent, _ := newAppWithPipe(t)
	if err := app.handleAgentMessage(agent, nil); err == nil {
		t.Fatal("expected error for nil message")
	}
}

func TestHandleAgentConnection_RegisterAndDisconnect(t *testing.T) {
	app := &App{rt: &runtime{
		registry:  newRegistry(),
		wsManager: common.NewWebSocketManager(),
	}}

	client, server := net.Pipe()

	connDone := make(chan struct{})
	go func() {
		defer close(connDone)
		app.handleAgentConnection(server)
	}()

	// Send register message.
	enc := json.NewEncoder(client)
	if err := enc.Encode(&common.Message{Type: "register", ID: "conn-agent-1"}); err != nil {
		t.Fatalf("encode register: %v", err)
	}

	// Read register_response.
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var resp common.Message
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("decode register_response: %v", err)
	}
	if resp.Type != "register_response" {
		t.Fatalf("got %s, want register_response", resp.Type)
	}

	// Close client side — handleAgentConnection should return.
	_ = client.Close()

	select {
	case <-connDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handleAgentConnection did not return after connection close")
	}
}

func TestApp_WebSocketHelpers(t *testing.T) {
	app := &App{rt: &runtime{
		registry:  newRegistry(),
		wsManager: common.NewWebSocketManager(),
	}}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	if app.WebSocketCount() != 0 {
		t.Fatalf("expected 0 before register, got %d", app.WebSocketCount())
	}

	app.RegisterWebSocket("ws-test", server)
	if app.WebSocketCount() != 1 {
		t.Fatalf("expected 1 after register, got %d", app.WebSocketCount())
	}

	app.UnregisterWebSocket("ws-test")
	if app.WebSocketCount() != 0 {
		t.Fatalf("expected 0 after unregister, got %d", app.WebSocketCount())
	}
}

func TestApp_LookupAgentByHost(t *testing.T) {
	app := &App{rt: &runtime{registry: newRegistry(), wsManager: common.NewWebSocketManager()}}

	_, server := net.Pipe()
	defer server.Close()
	agent := NewAgent("lookup-agent", server)
	agent.Services["lookup.example.com"] = &common.ServiceConfig{}
	app.rt.registry.add(agent)

	found, ok := app.LookupAgent("lookup.example.com")
	if !ok || found != agent {
		t.Fatalf("LookupAgent: ok=%v agent=%v", ok, found)
	}

	if _, ok := app.LookupAgent("missing.example.com"); ok {
		t.Fatal("expected miss for unknown host")
	}
}

// TestHandleAgentConnection_DecodeError verifies early exit when the connection
// closes before any message is received.
func TestHandleAgentConnection_DecodeError(t *testing.T) {
	app := &App{rt: &runtime{
		registry:  newRegistry(),
		wsManager: common.NewWebSocketManager(),
	}}

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		app.handleAgentConnection(server)
	}()

	// Close immediately — decoder gets EOF.
	_ = client.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleAgentConnection did not return after connection close")
	}
}

// TestHandleAgentConnection_WrongFirstMessage verifies early exit when the first
// message is not "register".
func TestHandleAgentConnection_WrongFirstMessage(t *testing.T) {
	app := &App{rt: &runtime{
		registry:  newRegistry(),
		wsManager: common.NewWebSocketManager(),
	}}

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		app.handleAgentConnection(server)
	}()

	_ = json.NewEncoder(client).Encode(&common.Message{Type: "ping", ID: "x"})
	_ = client.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleAgentConnection did not return after wrong first message")
	}
}

// TestHandleAgentConnection_MissingID verifies early exit when "register" has no ID.
func TestHandleAgentConnection_MissingID(t *testing.T) {
	app := &App{rt: &runtime{
		registry:  newRegistry(),
		wsManager: common.NewWebSocketManager(),
	}}

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		app.handleAgentConnection(server)
	}()

	_ = json.NewEncoder(client).Encode(&common.Message{Type: "register", ID: ""})
	_ = client.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleAgentConnection did not return after missing ID")
	}
}

// TestAgent_SendMessage_NilConn verifies error when Conn is nil.
func TestAgent_SendMessage_NilConn(t *testing.T) {
	a := NewAgent("nil-conn-agent", nil)
	err := a.SendMessage(&common.Message{Type: "ping"})
	if err == nil {
		t.Fatal("expected error sending with nil conn")
	}
}
