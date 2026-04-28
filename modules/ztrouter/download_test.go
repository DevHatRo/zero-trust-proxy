package ztrouter

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/modules/ztagents"
)

func TestHandler_DownloadStreaming(t *testing.T) {
	const host = "dl.example.com"
	h := newHarness(t, host)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/file.bin", nil)

	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		h.handler.ServeHTTP(rr, req)
	}()

	// Consume the http_request forwarded to the agent.
	fwd := h.readForwardedRequest()
	cb, ok := h.agent.TakeResponseHandler(fwd.ID)
	if !ok {
		t.Fatalf("no response handler registered")
	}
	// Put it back so subsequent chunks reach the same channel.
	h.agent.SetResponseHandler(fwd.ID, cb)

	payload := bytes.Repeat([]byte("d"), 4096)

	// Dispatch initial IsStream response (headers only).
	cb(&common.Message{
		Type: "http_response",
		ID:   fwd.ID,
		HTTP: &common.HTTPData{
			StatusCode:    http.StatusOK,
			StatusMessage: "OK",
			Headers:       map[string][]string{"Content-Type": {"application/octet-stream"}},
			IsStream:      true,
			TotalSize:     int64(len(payload)),
			ChunkIndex:    0,
		},
	})

	// Send two chunks — first half, then final half.
	half := len(payload) / 2
	cb(&common.Message{
		Type: "http_response",
		ID:   fwd.ID,
		HTTP: &common.HTTPData{
			Body:        payload[:half],
			IsStream:    true,
			ChunkSize:   half,
			TotalSize:   int64(len(payload)),
			ChunkIndex:  1,
			IsLastChunk: false,
		},
	})
	cb(&common.Message{
		Type: "http_response",
		ID:   fwd.ID,
		HTTP: &common.HTTPData{
			Body:        payload[half:],
			IsStream:    true,
			ChunkSize:   len(payload) - half,
			TotalSize:   int64(len(payload)),
			ChunkIndex:  2,
			IsLastChunk: true,
		},
	})

	select {
	case <-serveDone:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeHTTP did not return after last chunk")
	}

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rr.Code)
	}
	if !bytes.Equal(rr.Body.Bytes(), payload) {
		t.Fatalf("body len=%d want %d", rr.Body.Len(), len(payload))
	}
}

// newTestAgent returns a lightweight Agent backed by a throwaway net.Pipe.
func newTestAgent(t *testing.T, id string) *ztagents.Agent {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return ztagents.NewAgent(id, s)
}

// TestStreamDownloadFlush_Regular exercises the HTTP/2 flusher path with a
// two-chunk download that ends with IsLastChunk=true.
func TestStreamDownloadFlush_Regular(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/file", nil)
	agent := newTestAgent(t, "a1")

	payload := bytes.Repeat([]byte("r"), 512)
	half := len(payload) / 2

	respCh := make(chan *common.Message, 4)
	initial := &common.Message{
		HTTP: &common.HTTPData{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{"Content-Type": {"application/octet-stream"}},
		},
	}

	// Send chunks before calling so they're buffered.
	respCh <- &common.Message{HTTP: &common.HTTPData{Body: payload[:half], IsStream: true}}
	respCh <- &common.Message{HTTP: &common.HTTPData{Body: payload[half:], IsStream: true, IsLastChunk: true}}

	if err := h.streamDownloadFlush(rr, req, rr, agent, "msg-1", initial, respCh); err != nil {
		t.Fatalf("streamDownloadFlush: %v", err)
	}

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	if !bytes.Equal(rr.Body.Bytes(), payload) {
		t.Fatalf("body len=%d, want %d", rr.Body.Len(), len(payload))
	}
}

// TestStreamDownloadFlush_SSEClientDisconnect verifies that an SSE stream
// terminates cleanly when the client context is cancelled.
func TestStreamDownloadFlush_SSEClientDisconnect(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(ctx)
	agent := newTestAgent(t, "sse-agent")

	respCh := make(chan *common.Message, 4)
	initial := &common.Message{
		HTTP: &common.HTTPData{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{"Content-Type": {"text/event-stream"}},
		},
	}

	// Buffer one event before starting.
	respCh <- &common.Message{HTTP: &common.HTTPData{Body: []byte("data: ping\n\n"), IsStream: true}}

	done := make(chan error, 1)
	go func() {
		done <- h.streamDownloadFlush(rr, req, rr, agent, "msg-sse", initial, respCh)
	}()

	// Let the goroutine process the buffered event then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("streamDownloadFlush returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SSE stream did not terminate after context cancel")
	}

	if !bytes.Contains(rr.Body.Bytes(), []byte("data: ping")) {
		t.Fatalf("body=%q, want SSE event", rr.Body.Bytes())
	}
}

// TestStreamDownloadFlush_ChannelClosed verifies that a closed channel
// causes the flush loop to exit cleanly.
func TestStreamDownloadFlush_ChannelClosed(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/data", nil)
	agent := newTestAgent(t, "a-closed")

	respCh := make(chan *common.Message, 1)
	close(respCh)

	initial := &common.Message{
		HTTP: &common.HTTPData{StatusCode: http.StatusOK, Headers: map[string][]string{}},
	}

	if err := h.streamDownloadFlush(rr, req, rr, agent, "msg-closed", initial, respCh); err != nil {
		t.Fatalf("streamDownloadFlush: %v", err)
	}
}

// TestStreamDownloadFlush_NilChunk verifies that a nil chunk terminates the loop.
func TestStreamDownloadFlush_NilChunk(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/data", nil)
	agent := newTestAgent(t, "a-nil")

	respCh := make(chan *common.Message, 1)
	respCh <- nil

	initial := &common.Message{
		HTTP: &common.HTTPData{StatusCode: http.StatusOK, Headers: map[string][]string{}},
	}

	if err := h.streamDownloadFlush(rr, req, rr, agent, "msg-nil", initial, respCh); err != nil {
		t.Fatalf("streamDownloadFlush: %v", err)
	}
}

// TestHandleDownloadStream_Flusher exercises the Flusher branch of
// handleDownloadStream (ResponseWriter is http.Flusher but not http.Hijacker).
func TestHandleDownloadStream_Flusher(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder() // implements Flusher, not Hijacker
	agent := newTestAgent(t, "a-flusher")

	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	respCh := make(chan *common.Message, 2)
	initial := &common.Message{
		HTTP: &common.HTTPData{StatusCode: http.StatusOK, Headers: map[string][]string{}},
	}
	respCh <- &common.Message{HTTP: &common.HTTPData{Body: []byte("hello"), IsStream: true, IsLastChunk: true}}

	if err := h.handleDownloadStream(rr, req, agent, "msg-fl", initial, respCh); err != nil {
		t.Fatalf("handleDownloadStream: %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	if rr.Body.String() != "hello" {
		t.Fatalf("body=%q, want 'hello'", rr.Body.String())
	}
}

// TestStreamDownloadFlush_StatusZero verifies that a zero StatusCode defaults to 200.
func TestStreamDownloadFlush_StatusZero(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/data", nil)
	agent := newTestAgent(t, "a-zero-status")

	respCh := make(chan *common.Message, 1)
	initial := &common.Message{
		HTTP: &common.HTTPData{StatusCode: 0, Headers: map[string][]string{}},
	}
	respCh <- &common.Message{HTTP: &common.HTTPData{Body: []byte("ok"), IsStream: true, IsLastChunk: true}}

	if err := h.streamDownloadFlush(rr, req, rr, agent, "msg-zero", initial, respCh); err != nil {
		t.Fatalf("streamDownloadFlush: %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
}

// TestStreamDownloadFlush_SSEChannelClosed verifies that a closed channel
// terminates an SSE stream cleanly.
func TestStreamDownloadFlush_SSEChannelClosed(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	agent := newTestAgent(t, "a-sse-closed")

	respCh := make(chan *common.Message)
	close(respCh)

	initial := &common.Message{
		HTTP: &common.HTTPData{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{"Content-Type": {"text/event-stream"}},
		},
	}

	if err := h.streamDownloadFlush(rr, req, rr, agent, "msg-sse-closed", initial, respCh); err != nil {
		t.Fatalf("streamDownloadFlush: %v", err)
	}
}

// TestStreamDownloadFlush_SSELastChunk verifies that IsLastChunk=true in an SSE
// stream causes the flush loop to exit cleanly.
func TestStreamDownloadFlush_SSELastChunk(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	agent := newTestAgent(t, "a-sse-last")

	respCh := make(chan *common.Message, 1)
	initial := &common.Message{
		HTTP: &common.HTTPData{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{"Content-Type": {"text/event-stream"}},
		},
	}
	respCh <- &common.Message{HTTP: &common.HTTPData{Body: []byte("data: done\n\n"), IsStream: true, IsLastChunk: true}}

	if err := h.streamDownloadFlush(rr, req, rr, agent, "msg-sse-last", initial, respCh); err != nil {
		t.Fatalf("streamDownloadFlush: %v", err)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("data: done")) {
		t.Fatalf("body=%q, want SSE event", rr.Body.Bytes())
	}
}

// TestStreamDownloadFlush_Timeout verifies that a non-SSE stream returns an
// error when no chunk arrives before the inter-chunk deadline.
func TestStreamDownloadFlush_Timeout(t *testing.T) {
	h := &Handler{
		timeoutCfg: &common.TimeoutConfig{
			StreamingTimeout: 50 * time.Millisecond,
			LargeFileTimeout: 50 * time.Millisecond,
		},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/data", nil)
	agent := newTestAgent(t, "a-timeout")

	// Empty channel — no chunks will ever arrive.
	respCh := make(chan *common.Message)

	initial := &common.Message{
		HTTP: &common.HTTPData{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{},
			TotalSize:  1,
		},
	}

	done := make(chan error, 1)
	go func() { done <- h.streamDownloadFlush(rr, req, rr, agent, "msg-to", initial, respCh) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("streamDownloadFlush did not time out")
	}
}

// TestStreamDownloadFlush_NonSSEContextCancel verifies that cancelling the
// request context terminates a non-SSE download cleanly.
func TestStreamDownloadFlush_NonSSEContextCancel(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/data", nil).WithContext(ctx)
	agent := newTestAgent(t, "a-ctx-cancel")

	respCh := make(chan *common.Message)
	initial := &common.Message{
		HTTP: &common.HTTPData{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{},
			TotalSize:  1024 * 1024, // large size → long timeout so context fires first
		},
	}

	done := make(chan error, 1)
	go func() { done <- h.streamDownloadFlush(rr, req, rr, agent, "msg-ctx", initial, respCh) }()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil after context cancel, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("streamDownloadFlush did not return after context cancel")
	}
}

// plainResponseWriter implements only http.ResponseWriter — no Flusher, no Hijacker.
type plainResponseWriter struct {
	code   int
	header http.Header
	body   bytes.Buffer
}

func newPlainRW() *plainResponseWriter { return &plainResponseWriter{header: make(http.Header)} }
func (p *plainResponseWriter) Header() http.Header        { return p.header }
func (p *plainResponseWriter) WriteHeader(code int)        { p.code = code }
func (p *plainResponseWriter) Write(b []byte) (int, error) {
	if p.code == 0 {
		p.code = http.StatusOK
	}
	return p.body.Write(b)
}


// TestHandleDownloadStream_NoSupport covers the fallback when the
// ResponseWriter supports neither Hijacker nor Flusher.
func TestHandleDownloadStream_NoSupport(t *testing.T) {
	h := &Handler{}
	agent := newTestAgent(t, "a2")
	rw := newPlainRW()

	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	respCh := make(chan *common.Message, 1)
	initial := &common.Message{HTTP: &common.HTTPData{StatusCode: 200, Headers: map[string][]string{}}}

	if err := h.handleDownloadStream(rw, req, agent, "msg-ns", initial, respCh); err != nil {
		t.Fatalf("handleDownloadStream: %v", err)
	}
	if rw.code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", rw.code)
	}
}
