package ztrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

	h := &Handler{RequestTimeout: 2 * time.Second}
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

// runServeHTTP runs ServeHTTP on a goroutine, returning a channel that
// closes when it returns.
func runServeHTTP(handler *Handler, w http.ResponseWriter, r *http.Request) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(w, r)
	}()
	return done
}

func TestHandler_HappyPath(t *testing.T) {
	h := newHarness(t, "app.example.com")

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/hello?x=1", nil)
	rr := httptest.NewRecorder()

	done := runServeHTTP(h.handler, rr, req)

	fwd := h.readForwardedRequest()
	if fwd.Type != "http_request" {
		t.Fatalf("got type %s, want http_request", fwd.Type)
	}
	if fwd.HTTP == nil || fwd.HTTP.URL != "/hello?x=1" {
		t.Fatalf("got URL %+v, want /hello?x=1", fwd.HTTP)
	}

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

	<-done
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

	h.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rr.Code)
	}
}

func TestHandler_TimeoutReturns504(t *testing.T) {
	h := newHarness(t, "slow.example.com")
	h.handler.RequestTimeout = 100 * time.Millisecond

	req := httptest.NewRequest(http.MethodGet, "http://slow.example.com/", nil)
	rr := httptest.NewRecorder()

	done := runServeHTTP(h.handler, rr, req)

	_ = h.readForwardedRequest()

	<-done
	if rr.Code != http.StatusGatewayTimeout {
		t.Fatalf("status=%d, want 504", rr.Code)
	}
}

// TestHandler_PerServiceTimeout_Overrides verifies that a non-zero
// services[].timeout shortens the per-request deadline below the
// global router default.
func TestHandler_PerServiceTimeout_Overrides(t *testing.T) {
	h := newHarness(t, "fast.example.com")
	h.handler.RequestTimeout = 10 * time.Second
	h.agent.Services["fast.example.com"].Timeout = 80 * time.Millisecond

	req := httptest.NewRequest(http.MethodGet, "http://fast.example.com/", nil)
	rr := httptest.NewRecorder()

	start := time.Now()
	done := runServeHTTP(h.handler, rr, req)
	_ = h.readForwardedRequest()
	<-done
	elapsed := time.Since(start)

	if rr.Code != http.StatusGatewayTimeout {
		t.Fatalf("status=%d, want 504", rr.Code)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("elapsed=%v exceeds per-service timeout — fell back to router default", elapsed)
	}
}

// TestHandler_PerServiceTimeout_ZeroFallsBack verifies that an unset
// (zero) per-service timeout uses the router default.
func TestHandler_PerServiceTimeout_ZeroFallsBack(t *testing.T) {
	h := newHarness(t, "default.example.com")
	h.handler.RequestTimeout = 80 * time.Millisecond
	// Service has no Timeout set (zero value).

	req := httptest.NewRequest(http.MethodGet, "http://default.example.com/", nil)
	rr := httptest.NewRecorder()

	done := runServeHTTP(h.handler, rr, req)
	_ = h.readForwardedRequest()
	<-done

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

	done := runServeHTTP(h.handler, rr, req)

	_ = h.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	dec := json.NewDecoder(h.client)

	var firstID string
	var received bytes.Buffer
	var gotStart, gotLast bool
	for !gotLast {
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
			if msg.HTTP.IsLastChunk {
				gotLast = true
			}
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

	<-done
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

	h.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Host") {
		t.Fatalf("body=%q, want message about Host", rr.Body.String())
	}
}

func TestHandler_ContextCancelled(t *testing.T) {
	h := newHarness(t, "ctx.example.com")
	h.handler.RequestTimeout = 5 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://ctx.example.com/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	done := runServeHTTP(h.handler, rr, req)

	_ = h.readForwardedRequest()
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeHTTP did not return after context cancel")
	}
}

func TestWriteAgentResponse_ErrorField(t *testing.T) {
	rr := httptest.NewRecorder()
	writeAgentResponse(rr, &common.Message{Error: "backend unavailable"})
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "backend unavailable") {
		t.Fatalf("body=%q, want error message", rr.Body.String())
	}
}

func TestWriteAgentResponse_NilHTTP(t *testing.T) {
	rr := httptest.NewRecorder()
	writeAgentResponse(rr, &common.Message{})
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", rr.Code)
	}
}

func TestWriteAgentResponse_ZeroStatusDefaultsTo200(t *testing.T) {
	rr := httptest.NewRecorder()
	writeAgentResponse(rr, &common.Message{
		HTTP: &common.HTTPData{
			StatusCode: 0,
			Headers:    map[string][]string{"X-Test": {"yes"}},
			Body:       []byte("ok"),
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	if rr.Header().Get("X-Test") != "yes" {
		t.Fatalf("X-Test=%q, want yes", rr.Header().Get("X-Test"))
	}
	if body, _ := io.ReadAll(rr.Body); string(body) != "ok" {
		t.Fatalf("body=%q, want ok", body)
	}
}

func TestHandler_AgentErrorResponse(t *testing.T) {
	h := newHarness(t, "err.example.com")

	req := httptest.NewRequest(http.MethodGet, "http://err.example.com/", nil)
	rr := httptest.NewRecorder()

	done := runServeHTTP(h.handler, rr, req)

	fwd := h.readForwardedRequest()
	cb, ok := h.agent.TakeResponseHandler(fwd.ID)
	if !ok {
		t.Fatalf("no response handler registered")
	}
	cb(&common.Message{ID: fwd.ID, Error: "upstream down"})

	<-done
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", rr.Code)
	}
}

func TestHandler_Timeout(t *testing.T) {
	const host = "timeout.example.com"
	h := newHarness(t, host)
	h.handler.RequestTimeout = 50 * time.Millisecond

	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/slow", nil)
	rr := httptest.NewRecorder()

	done := runServeHTTP(h.handler, rr, req)

	_ = h.readForwardedRequest()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeHTTP did not return after timeout")
	}

	if rr.Code != http.StatusGatewayTimeout {
		t.Fatalf("status=%d, want 504", rr.Code)
	}
}

func TestHandler_BodyReadError(t *testing.T) {
	const host = "bodyerr.example.com"
	h := newHarness(t, host)

	errReader := &alwaysErrReader{}
	req := httptest.NewRequest(http.MethodPost, "http://"+host+"/upload", errReader)
	req.ContentLength = 10
	rr := httptest.NewRecorder()

	done := runServeHTTP(h.handler, rr, req)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeHTTP did not return")
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
}

type alwaysErrReader struct{}

func (r *alwaysErrReader) Read(p []byte) (int, error) { return 0, io.ErrUnexpectedEOF }
