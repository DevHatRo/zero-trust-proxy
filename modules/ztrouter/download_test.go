package ztrouter

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

func TestHandler_DownloadStreaming(t *testing.T) {
	const host = "dl.example.com"
	h := newHarness(t, host)

	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() {
		_ = serverSide.Close()
		_ = clientSide.Close()
	})
	rr := &hijackRecorder{conn: serverSide}

	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/file.bin", nil)

	serveDone := make(chan error, 1)
	go func() { serveDone <- h.handler.ServeHTTP(rr, req, nil) }()

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

	// Read the response status line and headers off the client side in a
	// goroutine so the handler's writes to the pipe don't deadlock.
	type readResult struct {
		resp *http.Response
		body []byte
		err  error
	}
	readCh := make(chan readResult, 1)
	var once sync.Once
	go func() {
		_ = clientSide.SetReadDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(clientSide)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			once.Do(func() { readCh <- readResult{err: err} })
			return
		}
		body, err := io.ReadAll(resp.Body)
		once.Do(func() { readCh <- readResult{resp: resp, body: body, err: err} })
	}()

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
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeHTTP did not return after last chunk")
	}

	// Close serverSide so ReadAll on the client returns.
	_ = serverSide.Close()

	res := <-readCh
	if res.err != nil && res.err != io.EOF {
		t.Fatalf("read response: %v", res.err)
	}
	if res.resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", res.resp.StatusCode)
	}
	if !bytes.Equal(res.body, payload) {
		t.Fatalf("body len=%d want %d", len(res.body), len(payload))
	}
}
