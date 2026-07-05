package ztrouter

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
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

// slowFlushRW is a ResponseWriter+Flusher whose Write is slow (and optionally
// gated on a channel), simulating a client that reads slower than the agent
// sends — the condition that made the old buffered-channel dispatch drop
// streaming chunks.
type slowFlushRW struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	code   int
	header http.Header
	delay  time.Duration
	gate   chan struct{} // if non-nil, the first Write blocks until closed
	gated  bool
}

func newSlowFlushRW(delay time.Duration, gate chan struct{}) *slowFlushRW {
	return &slowFlushRW{header: make(http.Header), delay: delay, gate: gate}
}

func (s *slowFlushRW) Header() http.Header { return s.header }
func (s *slowFlushRW) WriteHeader(c int)   { s.code = c }
func (s *slowFlushRW) Flush()              {}
func (s *slowFlushRW) Write(b []byte) (int, error) {
	if s.gate != nil && !s.gated {
		<-s.gate
		s.gated = true
	}
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(b)
}

func (s *slowFlushRW) bodyLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Len()
}

// runServeHTTPCatch runs ServeHTTP on a goroutine and reports the recovered
// panic value (nil if it returned normally).
func runServeHTTPCatch(handler *Handler, w http.ResponseWriter, r *http.Request) <-chan any {
	out := make(chan any, 1)
	go func() {
		defer func() { out <- recover() }()
		handler.ServeHTTP(w, r)
	}()
	return out
}

// startDownloadStream drives the harness up to the point where the agent
// starts a streaming response: it issues the request, captures the response
// callback, and dispatches the initial IsStream header message.
func startDownloadStream(t *testing.T, h *testHarness, w http.ResponseWriter, total int64) (func(*common.Message), <-chan any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://"+h.agentHost()+"/big.js", nil)
	done := runServeHTTPCatch(h.handler, w, req)

	fwd := h.readForwardedRequest()
	cb, ok := h.agent.TakeResponseHandler(fwd.ID)
	if !ok {
		t.Fatalf("no response handler registered")
	}
	h.agent.SetResponseHandler(fwd.ID, cb)

	cb(&common.Message{
		Type: "http_response",
		ID:   fwd.ID,
		HTTP: &common.HTTPData{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{"Content-Type": {"application/javascript"}},
			IsStream:   true,
			TotalSize:  total,
		},
	})
	return cb, done
}

// TestHandler_DownloadStreaming_BurstNoDrop is the regression test for the
// silent chunk-drop bug: an agent bursts far more chunks than the old
// 16-message channel buffer while the client writes slowly. Every chunk must
// still reach the client, in order, ending with IsLastChunk. With the old
// select/default dispatch this test fails with a truncated body (and, when
// the IsLastChunk message was dropped, a hang until timeout). Observed in the
// wild as Synology DSM's UIString i18n script arriving truncated, which broke
// the login page.
func TestHandler_DownloadStreaming_BurstNoDrop(t *testing.T) {
	const (
		numChunks = 200
		chunkSize = 4096
	)
	h := newHarness(t, "dl.example.com")

	var expected bytes.Buffer
	chunks := make([][]byte, numChunks)
	for i := range chunks {
		c := bytes.Repeat([]byte{0}, chunkSize)
		copy(c, fmt.Sprintf("%06d|", i)) // ordering marker
		chunks[i] = c
		expected.Write(c)
	}

	w := newSlowFlushRW(200*time.Microsecond, nil)
	cb, done := startDownloadStream(t, h, w, int64(expected.Len()))

	// Burst all chunks synchronously, like the agent read loop does.
	for i, c := range chunks {
		cb(&common.Message{
			Type: "http_response",
			HTTP: &common.HTTPData{
				Body:        c,
				IsStream:    true,
				ChunkIndex:  i + 1,
				IsLastChunk: i == len(chunks)-1,
			},
		})
	}

	select {
	case p := <-done:
		if p != nil {
			t.Fatalf("ServeHTTP panicked: %v", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("stream did not complete: IsLastChunk was likely dropped (received %d of %d bytes)",
			w.bodyLen(), expected.Len())
	}

	if w.code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.code)
	}
	if !bytes.Equal(w.buf.Bytes(), expected.Bytes()) {
		t.Fatalf("body truncated or reordered: got %d bytes, want %d", w.buf.Len(), expected.Len())
	}
}

// TestHandler_DownloadStreaming_OverflowAborts verifies that when the byte
// cap is genuinely exceeded the response is aborted (http.ErrAbortHandler)
// rather than ended cleanly — a clean end would let clients cache the
// truncated body as complete.
func TestHandler_DownloadStreaming_OverflowAborts(t *testing.T) {
	h := newHarness(t, "dl.example.com")
	h.handler.maxStreamBuffer = 16 * 1024 // tiny cap to force overflow

	gate := make(chan struct{})
	w := newSlowFlushRW(0, gate)
	cb, done := startDownloadStream(t, h, w, 1<<20)

	// Flood while the writer is gated shut: respCh (16) fills, then the
	// queue exceeds its 16 KiB cap.
	chunk := bytes.Repeat([]byte("x"), 4096)
	for i := 0; i < 60; i++ {
		cb(&common.Message{
			Type: "http_response",
			HTTP: &common.HTTPData{Body: chunk, IsStream: true, ChunkIndex: i + 1},
		})
	}
	close(gate) // let queued writes drain so the overflow sentinel is reached

	select {
	case p := <-done:
		if p != http.ErrAbortHandler {
			t.Fatalf("recovered %v, want http.ErrAbortHandler", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ServeHTTP did not return after overflow")
	}
	if w.bodyLen() >= 60*len(chunk) {
		t.Fatal("full body written despite overflow — abort came too late")
	}
}

// TestHandler_DownloadStreaming_TimeoutAborts verifies that an inter-chunk
// timeout aborts the response instead of ending the truncated body cleanly.
func TestHandler_DownloadStreaming_TimeoutAborts(t *testing.T) {
	h := newHarness(t, "dl.example.com")
	h.handler.timeoutCfg = &common.TimeoutConfig{
		StreamingTimeout: 50 * time.Millisecond,
		LargeFileTimeout: 50 * time.Millisecond,
	}

	w := newSlowFlushRW(0, nil)
	cb, done := startDownloadStream(t, h, w, 1)

	// One data chunk, never the last one — the agent side went silent.
	cb(&common.Message{
		Type: "http_response",
		HTTP: &common.HTTPData{Body: []byte("partial"), IsStream: true, ChunkIndex: 1},
	})

	select {
	case p := <-done:
		if p != http.ErrAbortHandler {
			t.Fatalf("recovered %v, want http.ErrAbortHandler", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ServeHTTP did not return after inter-chunk timeout")
	}
}

// TestStreamDownloadFlush_ErrorChunkAborts verifies that an Error-carrying
// message mid-stream surfaces as an error from the flush loop.
func TestStreamDownloadFlush_ErrorChunkAborts(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/data", nil)
	agent := newTestAgent(t, "a-errchunk")

	respCh := make(chan *common.Message, 2)
	respCh <- &common.Message{HTTP: &common.HTTPData{Body: []byte("data"), IsStream: true}}
	respCh <- &common.Message{Error: "boom"}

	initial := &common.Message{
		HTTP: &common.HTTPData{StatusCode: http.StatusOK, Headers: map[string][]string{}},
	}
	err := h.streamDownloadFlush(rr, req, rr, agent, "msg-err", initial, respCh)
	if err == nil {
		t.Fatal("expected error from Error-carrying chunk, got nil")
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
