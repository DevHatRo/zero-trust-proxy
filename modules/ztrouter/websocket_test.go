package ztrouter

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/types"
	"github.com/devhatro/zero-trust-proxy/modules/ztagents"
)

type hijackRecorder struct {
	mu        sync.Mutex
	header    http.Header
	code      int
	body      bytes.Buffer
	conn      net.Conn // server side of hijacked conn — returned by Hijack()
	hijacked  bool
}

func (r *hijackRecorder) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}

func (r *hijackRecorder) WriteHeader(code int) {
	r.mu.Lock()
	r.code = code
	r.mu.Unlock()
}

func (r *hijackRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.body.Write(p)
}

func (r *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hijacked = true
	bufrw := bufio.NewReadWriter(
		bufio.NewReader(r.conn),
		bufio.NewWriter(r.conn),
	)
	return r.conn, bufrw, nil
}

func TestHandler_WebSocketUpgradeAndFrames(t *testing.T) {
	const host = "ws.example.com"
	h := newHarness(t, host)

	// Client pipe — test side holds clientSide; handler's hijack returns serverSide.
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() {
		_ = serverSide.Close()
		_ = clientSide.Close()
	})

	rr := &hijackRecorder{conn: serverSide}

	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/chat", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	serveDone := make(chan error, 1)
	go func() { serveDone <- h.handler.ServeHTTP(rr, req, nil) }()

	// Read http_request from the agent side — confirm IsWebSocket=true.
	fwd := h.readForwardedRequest()
	if fwd.HTTP == nil || !fwd.HTTP.IsWebSocket {
		t.Fatalf("expected IsWebSocket=true, got %+v", fwd.HTTP)
	}

	// Dispatch the 101 Switching Protocols response via agent callback.
	cb, ok := h.agent.TakeResponseHandler(fwd.ID)
	if !ok {
		t.Fatalf("no response handler registered")
	}
	cb(&common.Message{
		Type: "http_response",
		ID:   fwd.ID,
		HTTP: &common.HTTPData{
			StatusCode:    http.StatusSwitchingProtocols,
			StatusMessage: "Switching Protocols",
			Headers: map[string][]string{
				"Upgrade":              {"websocket"},
				"Connection":           {"Upgrade"},
				"Sec-WebSocket-Accept": {"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
			},
			IsWebSocket: true,
		},
	})

	// Read the 101 upgrade response off the client side.
	_ = clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(clientSide), nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status=%d want 101", resp.StatusCode)
	}
	if resp.Header.Get("Sec-WebSocket-Accept") == "" {
		t.Fatalf("missing Sec-WebSocket-Accept header")
	}

	// Verify handler registered the ws session.
	if got := h.app.WebSocketCount(); got != 1 {
		t.Fatalf("WebSocketCount=%d want 1", got)
	}

	// Client → agent: write a frame, expect agent pipe to receive websocket_frame.
	wantFrame := []byte("hello-ws")
	if _, err := clientSide.Write(wantFrame); err != nil {
		t.Fatalf("client write: %v", err)
	}
	frameMsg := drainForMessageType(t, h.client, "websocket_frame")
	if frameMsg.HTTP == nil || !bytes.Equal(frameMsg.HTTP.Body, wantFrame) {
		t.Fatalf("got body=%q, want %q", frameMsg.HTTP.Body, wantFrame)
	}

	// Client closes → handler should send websocket_disconnect + unregister.
	_ = clientSide.Close()
	discMsg := drainForMessageType(t, h.client, "websocket_disconnect")
	if discMsg.ID != fwd.ID {
		t.Fatalf("disconnect id=%s want %s", discMsg.ID, fwd.ID)
	}

	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeHTTP did not return after client close")
	}

	if got := h.app.WebSocketCount(); got != 0 {
		t.Fatalf("WebSocketCount=%d want 0 after close", got)
	}
}

func TestHandler_WebSocketAgentFrameRelaysToClient(t *testing.T) {
	const host = "ws.example.com"
	app := ztagents.NewTestApp()

	agentSide, _ := net.Pipe() // not used for reads in this test
	defer agentSide.Close()
	agent := ztagents.NewAgent("a1", agentSide)
	agent.Services[host] = &common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{Hostname: host},
	}
	app.AddAgent(agent)

	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	msgID := "ws-session-1"
	app.RegisterWebSocket(msgID, serverSide)

	// Read from client side in parallel with the dispatch.
	readCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		_ = clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := clientSide.Read(buf)
		readCh <- buf[:n]
	}()

	// Agent → client frame delivery.
	err := app.DispatchAgentMessageForTest(agent, &common.Message{
		Type: "websocket_frame",
		ID:   msgID,
		HTTP: &common.HTTPData{Body: []byte("from-agent"), IsWebSocket: true},
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	select {
	case got := <-readCh:
		if string(got) != "from-agent" {
			t.Fatalf("got %q, want from-agent", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for frame delivery")
	}
}

// drainForMessageType reads messages off the agent-side pipe until one of the
// requested type appears (skipping the initial http_request if encountered).
func drainForMessageType(t *testing.T, c net.Conn, msgType string) *common.Message {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	dec := json.NewDecoder(c)
	for {
		var msg common.Message
		if err := dec.Decode(&msg); err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "use of closed") {
				t.Fatalf("pipe closed while waiting for %s", msgType)
			}
			t.Fatalf("decode: %v", err)
		}
		if msg.Type == msgType {
			return &msg
		}
	}
}

// TestHandleWebSocketUpgrade_NoHijacker verifies the 500 path when the
// ResponseWriter doesn't implement http.Hijacker.
func TestHandleWebSocketUpgrade_NoHijacker(t *testing.T) {
	const host = "ws-nohijack.example.com"
	app := ztagents.NewTestApp()
	_, agentConn := net.Pipe()
	defer agentConn.Close()
	agent := ztagents.NewAgent("nh1", agentConn)
	agent.Services[host] = &common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{Hostname: host},
	}
	app.AddAgent(agent)

	h := &Handler{app: app}

	rr := httptest.NewRecorder() // does NOT implement http.Hijacker
	resp := &common.Message{
		HTTP: &common.HTTPData{
			StatusCode:    http.StatusSwitchingProtocols,
			StatusMessage: "Switching Protocols",
			Headers:       map[string][]string{},
			IsWebSocket:   true,
		},
	}

	if err := h.handleWebSocketUpgrade(rr, agent, "msg-nh", resp); err != nil {
		t.Fatalf("handleWebSocketUpgrade returned error: %v", err)
	}
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500", rr.Code)
	}
}

// TestIsWebSocketUpgrade covers the false-path where Connection header is absent.
func TestIsWebSocketUpgrade_MissingConnectionHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	// No Connection: Upgrade header → should return false.
	if isWebSocketUpgrade(req) {
		t.Fatal("expected isWebSocketUpgrade to return false without Connection header")
	}
}

// Test helper we need — expose one more hook. See testhelper.go update below.
var _ = caddy.Duration(0) // keep import used
