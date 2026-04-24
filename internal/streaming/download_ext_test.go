package streaming

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

func TestDownloadStreamer_StreamToConnection(t *testing.T) {
	clientSide, serverSide := net.Pipe()

	sender := &MockMessageSender{}
	streamer := NewDownloadStreamer("test-conn", 11, sender)

	responseChan := make(chan *common.Message, 4)
	initial := &common.Message{
		HTTP: &common.HTTPData{
			StatusCode:    200,
			StatusMessage: "OK",
			Headers:       map[string][]string{"Content-Type": {"text/plain"}},
			TotalSize:     11,
		},
	}

	type readResult struct {
		body []byte
		err  error
	}
	readCh := make(chan readResult, 1)
	go func() {
		defer clientSide.Close()
		_ = clientSide.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(clientSide), nil)
		if err != nil {
			readCh <- readResult{err: err}
			return
		}
		body, err := io.ReadAll(resp.Body)
		readCh <- readResult{body: body, err: err}
	}()

	done := make(chan error, 1)
	go func() {
		err := streamer.StreamToConnection(serverSide, responseChan, initial)
		_ = serverSide.Close()
		done <- err
	}()

	responseChan <- &common.Message{HTTP: &common.HTTPData{Body: []byte("hello"), IsStream: true}}
	responseChan <- &common.Message{HTTP: &common.HTTPData{Body: []byte(" world"), IsStream: true, IsLastChunk: true}}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("StreamToConnection: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("StreamToConnection did not return")
	}

	select {
	case res := <-readCh:
		if res.err != nil && res.err != io.EOF {
			t.Fatalf("client read: %v", res.err)
		}
		if !strings.Contains(string(res.body), "hello") {
			t.Fatalf("body=%q, want to contain 'hello world'", res.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client read did not complete")
	}
}

func TestDownloadStreamer_StreamToConnection_ChannelClosed(t *testing.T) {
	clientSide, serverSide := net.Pipe()

	// Drain client so header writes don't block.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := clientSide.Read(buf); err != nil {
				return
			}
		}
	}()

	sender := &MockMessageSender{}
	streamer := NewDownloadStreamer("test-closed-chan", 100, sender)

	responseChan := make(chan *common.Message)
	close(responseChan)

	initial := &common.Message{
		HTTP: &common.HTTPData{
			StatusCode:    200,
			StatusMessage: "OK",
			Headers:       map[string][]string{},
			TotalSize:     100,
		},
	}

	done := make(chan error, 1)
	go func() { done <- streamer.StreamToConnection(serverSide, responseChan, initial) }()

	select {
	case err := <-done:
		_ = clientSide.Close()
		_ = serverSide.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StreamToConnection blocked on closed channel")
	}
}

func TestDownloadStreamer_StreamToConnection_NilChunk(t *testing.T) {
	clientSide, serverSide := net.Pipe()

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := clientSide.Read(buf); err != nil {
				return
			}
		}
	}()

	sender := &MockMessageSender{}
	streamer := NewDownloadStreamer("test-nil-chunk", 100, sender)

	responseChan := make(chan *common.Message, 1)
	responseChan <- nil

	initial := &common.Message{
		HTTP: &common.HTTPData{
			StatusCode:    200,
			StatusMessage: "OK",
			Headers:       map[string][]string{},
			TotalSize:     100,
		},
	}

	done := make(chan error, 1)
	go func() { done <- streamer.StreamToConnection(serverSide, responseChan, initial) }()

	select {
	case err := <-done:
		_ = clientSide.Close()
		_ = serverSide.Close()
		if err != nil {
			t.Fatalf("nil chunk should terminate cleanly: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StreamToConnection blocked on nil chunk")
	}
}

func TestStreamingHandler_HandleDownloadStream(t *testing.T) {
	handler := NewStreamingHandler()
	defer handler.Close()

	sender := &MockMessageSender{}
	data := strings.NewReader("streamed body")
	resp := &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		Header:        make(http.Header),
		Body:          io.NopCloser(data),
		ContentLength: int64(data.Len()),
	}

	if err := handler.HandleDownloadStream("dl-1", resp, "msg-dl", sender); err != nil {
		t.Fatalf("HandleDownloadStream: %v", err)
	}

	msgs := sender.GetMessages()
	if len(msgs) == 0 {
		t.Fatal("no messages sent")
	}
	if msgs[0].Type != "http_response" {
		t.Fatalf("first msg type=%s, want http_response", msgs[0].Type)
	}
}

func TestStreamingHandler_GetStreamStats(t *testing.T) {
	handler := NewStreamingHandler()
	defer handler.Close()

	sender := &MockMessageSender{}
	handler.manager.CreateDownloadStream("stat-1", 1024, sender)

	stats := handler.GetStreamStats()
	if _, ok := stats["stat-1"]; !ok {
		t.Fatal("expected stat-1 in stats")
	}
}

func TestStreamingHandler_GetStream(t *testing.T) {
	handler := NewStreamingHandler()
	defer handler.Close()

	sender := &MockMessageSender{}
	handler.manager.CreateDownloadStream("gs-1", 512, sender)

	stream, ok := handler.GetStream("gs-1")
	if !ok || stream == nil {
		t.Fatal("expected stream gs-1 to exist")
	}
	if _, ok := handler.GetStream("nonexistent"); ok {
		t.Fatal("expected nonexistent stream to not exist")
	}
}

func TestStreamAdapter_GetHandler(t *testing.T) {
	adapter := NewStreamAdapter()
	if adapter.GetHandler() == nil {
		t.Fatal("GetHandler returned nil")
	}
}

func TestStreamingHandler_HandleDownloadToConnection(t *testing.T) {
	handler := NewStreamingHandler()
	defer handler.Close()

	clientSide, serverSide := net.Pipe()

	// Drain client so writes don't block.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := clientSide.Read(buf); err != nil {
				return
			}
		}
	}()

	sender := &MockMessageSender{}
	responseChan := make(chan *common.Message, 4)
	initial := &common.Message{
		HTTP: &common.HTTPData{
			StatusCode:    200,
			StatusMessage: "OK",
			Headers:       map[string][]string{},
			TotalSize:     5,
		},
	}

	done := make(chan error, 1)
	go func() {
		err := handler.HandleDownloadToConnection("dl-conn", serverSide, responseChan, initial, sender)
		_ = serverSide.Close()
		done <- err
	}()

	responseChan <- &common.Message{HTTP: &common.HTTPData{Body: []byte("hello"), IsStream: true, IsLastChunk: true}}

	select {
	case err := <-done:
		_ = clientSide.Close()
		if err != nil {
			t.Fatalf("HandleDownloadToConnection: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("HandleDownloadToConnection timed out")
	}
}

func TestStreamingHandler_StartCleanupRoutine(t *testing.T) {
	handler := NewStreamingHandler()
	defer handler.Close()

	sender := &MockMessageSender{}
	handler.manager.CreateDownloadStream("to-clean", 1024, sender)

	// Mark the stream as expired.
	stream, _ := handler.manager.GetStream("to-clean")
	stream.LastActivity = time.Now().Add(-2 * time.Hour)

	// Start cleanup with short interval and age so it fires quickly.
	handler.StartCleanupRoutine(50*time.Millisecond, time.Hour)

	time.Sleep(150 * time.Millisecond)

	if _, ok := handler.GetStream("to-clean"); ok {
		t.Fatal("stream should have been cleaned up")
	}
}
