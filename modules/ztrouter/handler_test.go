package ztrouter

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/types"
	"github.com/devhatro/zero-trust-proxy/modules/ztagents"
)

type testHarness struct {
	t       *testing.T
	app     *ztagents.App
	agent   *ztagents.Agent
	client  net.Conn // reads what handler sends
	handler *Handler
}

func newHarness(t *testing.T, host string) *testHarness {
	t.Helper()
	app := ztagents.NewTestApp()

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	agent := ztagents.NewAgent("a1", server)
	agent.Services[host] = &common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{Hostname: host},
	}
	app.AddAgent(agent)

	h := &Handler{RequestTimeout: caddy.Duration(2 * time.Second)}
	h.SetApp(app)

	return &testHarness{t: t, app: app, agent: agent, client: client, handler: h}
}

// readForwardedRequest drains the pipe to capture the agent-bound message.
func (h *testHarness) readForwardedRequest() *common.Message {
	h.t.Helper()
	_ = h.client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg common.Message
	if err := json.NewDecoder(h.client).Decode(&msg); err != nil {
		h.t.Fatalf("decode forwarded request: %v", err)
	}
	return &msg
}

func TestHandler_HappyPath(t *testing.T) {
	h := newHarness(t, "app.example.com")

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/hello?x=1", nil)
	rr := httptest.NewRecorder()

	done := make(chan error, 1)
	go func() { done <- h.handler.ServeHTTP(rr, req, nil) }()

	fwd := h.readForwardedRequest()
	if fwd.Type != "http_request" {
		t.Fatalf("got type %s, want http_request", fwd.Type)
	}
	if fwd.HTTP == nil || fwd.HTTP.URL != "/hello?x=1" {
		t.Fatalf("got URL %+v, want /hello?x=1", fwd.HTTP)
	}

	// Dispatch synthetic agent response via the registered handler.
	cb, ok := h.agent.TakeResponseHandler(fwd.ID)
	if !ok {
		t.Fatalf("no response handler registered for id %s", fwd.ID)
	}
	cb(&common.Message{
		Type: "http_response",
		ID:   fwd.ID,
		HTTP: &common.HTTPData{
			StatusCode: 201,
			Headers:    map[string][]string{"X-Foo": {"bar"}},
			Body:       []byte("hi"),
		},
	})

	if err := <-done; err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if rr.Code != 201 {
		t.Fatalf("status=%d, want 201", rr.Code)
	}
	if got := rr.Header().Get("X-Foo"); got != "bar" {
		t.Fatalf("X-Foo=%q, want bar", got)
	}
	if body, _ := io.ReadAll(rr.Body); string(body) != "hi" {
		t.Fatalf("body=%q, want hi", body)
	}
}

func TestHandler_NoAgentReturns503(t *testing.T) {
	h := newHarness(t, "other.example.com")

	req := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/", nil)
	rr := httptest.NewRecorder()

	if err := h.handler.ServeHTTP(rr, req, nil); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rr.Code)
	}
}

func TestHandler_TimeoutReturns504(t *testing.T) {
	h := newHarness(t, "slow.example.com")
	h.handler.RequestTimeout = caddy.Duration(100 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "http://slow.example.com/", nil)
	rr := httptest.NewRecorder()

	done := make(chan error, 1)
	go func() { done <- h.handler.ServeHTTP(rr, req, nil) }()

	// Drain the forwarded request so the write to the pipe doesn't block forever.
	_ = h.readForwardedRequest()

	if err := <-done; err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if rr.Code != http.StatusGatewayTimeout {
		t.Fatalf("status=%d, want 504", rr.Code)
	}
}

func TestHandler_UploadStreaming(t *testing.T) {
	h := newHarness(t, "upload.example.com")

	const totalSize = 2 * 1024 * 1024 // 2 MiB — exceeds 1 MiB threshold
	bodyBytes := bytes.Repeat([]byte("x"), totalSize)

	req := httptest.NewRequest(http.MethodPost, "http://upload.example.com/up", bytes.NewReader(bodyBytes))
	req.ContentLength = int64(totalSize)
	rr := httptest.NewRecorder()

	done := make(chan error, 1)
	go func() { done <- h.handler.ServeHTTP(rr, req, nil) }()

	// Drain chunks until we've reassembled the full upload. The first message
	// must be http_upload_start; subsequent messages are http_upload_chunk.
	_ = h.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	dec := json.NewDecoder(h.client)

	var firstID string
	var received bytes.Buffer
	var gotStart bool
	for received.Len() < totalSize {
		var msg common.Message
		if err := dec.Decode(&msg); err != nil {
			t.Fatalf("decode upload message: %v", err)
		}
		switch msg.Type {
		case "http_upload_start":
			if gotStart {
				t.Fatalf("duplicate http_upload_start")
			}
			gotStart = true
			firstID = msg.ID
			if msg.HTTP == nil || msg.HTTP.Method != http.MethodPost || msg.HTTP.URL != "/up" {
				t.Fatalf("bad start metadata: %+v", msg.HTTP)
			}
			if msg.HTTP.TotalSize != int64(totalSize) {
				t.Fatalf("TotalSize=%d want %d", msg.HTTP.TotalSize, totalSize)
			}
		case "http_upload_chunk":
			if !gotStart {
				t.Fatalf("chunk before http_upload_start")
			}
			if msg.ID != firstID {
				t.Fatalf("chunk ID=%s want %s", msg.ID, firstID)
			}
			if msg.HTTP == nil {
				t.Fatalf("chunk missing HTTP data")
			}
			received.Write(msg.HTTP.Body)
		default:
			t.Fatalf("unexpected message type during upload: %s", msg.Type)
		}
	}

	if !bytes.Equal(received.Bytes(), bodyBytes) {
		t.Fatalf("reassembled upload mismatch (len=%d want %d)", received.Len(), totalSize)
	}

	cb, ok := h.agent.TakeResponseHandler(firstID)
	if !ok {
		t.Fatalf("no response handler registered for id %s", firstID)
	}
	cb(&common.Message{
		Type: "http_response",
		ID:   firstID,
		HTTP: &common.HTTPData{
			StatusCode: http.StatusCreated,
			Body:       []byte("ok"),
		},
	})

	if err := <-done; err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d want 201", rr.Code)
	}
	if body, _ := io.ReadAll(rr.Body); string(body) != "ok" {
		t.Fatalf("body=%q want ok", body)
	}
}

func TestHandler_MissingHost(t *testing.T) {
	h := newHarness(t, "app.example.com")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = ""
	rr := httptest.NewRecorder()

	if err := h.handler.ServeHTTP(rr, req, nil); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Host") {
		t.Fatalf("body=%q, want message about Host", rr.Body.String())
	}
}
