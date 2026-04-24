package streaming

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

func TestUploadStreamer_StreamFromReader(t *testing.T) {
	sender := &MockMessageSender{}
	data := bytes.Repeat([]byte("x"), 1024)

	streamer := NewUploadStreamer("test-reader", int64(len(data)), sender)
	if err := streamer.StreamFromReader(bytes.NewReader(data), "msg-r1"); err != nil {
		t.Fatalf("StreamFromReader: %v", err)
	}

	msgs := sender.GetMessages()
	if len(msgs) < 2 {
		t.Fatalf("expected ≥2 messages, got %d", len(msgs))
	}
	if msgs[0].Type != "http_upload_start" {
		t.Fatalf("first msg type=%s, want http_upload_start", msgs[0].Type)
	}

	var totalBytes int
	var hasLast bool
	for _, m := range msgs[1:] {
		if m.Type != "http_upload_chunk" {
			t.Fatalf("expected http_upload_chunk, got %s", m.Type)
		}
		totalBytes += len(m.HTTP.Body)
		if m.HTTP.IsLastChunk {
			hasLast = true
		}
	}
	if !hasLast {
		t.Fatal("no IsLastChunk=true message")
	}
	if totalBytes != len(data) {
		t.Fatalf("total bytes=%d, want %d", totalBytes, len(data))
	}
}

func TestUploadStreamer_StreamFromReader_SenderError(t *testing.T) {
	sender := &MockMessageSender{sendErr: io.ErrUnexpectedEOF}
	streamer := NewUploadStreamer("test-err", 4, sender)
	if err := streamer.StreamFromReader(bytes.NewReader([]byte("data")), "msg"); err == nil {
		t.Fatal("expected error when sender fails")
	}
}

func TestUploadStreamer_StreamFromReaderWithContext(t *testing.T) {
	sender := &MockMessageSender{}
	data := bytes.Repeat([]byte("y"), 512)
	headers := map[string][]string{"Content-Type": {"application/octet-stream"}}

	streamer := NewUploadStreamer("test-ctx", int64(len(data)), sender)
	if err := streamer.StreamFromReaderWithContext(
		bytes.NewReader(data), "msg-ctx", "POST", "/upload", headers,
	); err != nil {
		t.Fatalf("StreamFromReaderWithContext: %v", err)
	}

	msgs := sender.GetMessages()
	if len(msgs) == 0 {
		t.Fatal("no messages sent")
	}
	start := msgs[0]
	if start.Type != "http_upload_start" {
		t.Fatalf("first msg type=%s, want http_upload_start", start.Type)
	}
	if start.HTTP.Method != "POST" {
		t.Fatalf("method=%s, want POST", start.HTTP.Method)
	}
	if start.HTTP.URL != "/upload" {
		t.Fatalf("url=%s, want /upload", start.HTTP.URL)
	}

	var hasLast bool
	for _, m := range msgs {
		if m.HTTP != nil && m.HTTP.IsLastChunk {
			hasLast = true
		}
	}
	if !hasLast {
		t.Fatal("no IsLastChunk=true message")
	}
}

func TestUploadStreamer_StreamFromReaderWithContext_SenderError(t *testing.T) {
	sender := &MockMessageSender{sendErr: io.ErrUnexpectedEOF}
	streamer := NewUploadStreamer("test-ctx-err", 4, sender)
	err := streamer.StreamFromReaderWithContext(
		bytes.NewReader([]byte("data")), "msg", "POST", "/up", nil,
	)
	if err == nil {
		t.Fatal("expected error when sender fails")
	}
}

func TestUploadStreamer_StreamToRequest(t *testing.T) {
	sender := &MockMessageSender{}
	streamer := NewUploadStreamer("test-to-req", -1, sender)

	req, _ := http.NewRequest("POST", "http://backend/upload", nil)

	uploadChan := make(chan *common.Message, 4)
	if err := streamer.StreamToRequest(uploadChan, req); err != nil {
		t.Fatalf("StreamToRequest: %v", err)
	}
	if req.Body == nil {
		t.Fatal("expected request body to be set to pipe reader")
	}

	// Send chunks.
	uploadChan <- &common.Message{
		HTTP: &common.HTTPData{Body: []byte("hello "), IsStream: true},
	}
	uploadChan <- &common.Message{
		HTTP: &common.HTTPData{Body: []byte("world"), IsStream: true, IsLastChunk: true},
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll body: %v", err)
	}
	if string(body) != "hello world" {
		t.Fatalf("body=%q, want 'hello world'", body)
	}
}

func TestUploadStreamer_StreamToRequest_ChannelClosed(t *testing.T) {
	sender := &MockMessageSender{}
	streamer := NewUploadStreamer("test-chan-close", -1, sender)

	req, _ := http.NewRequest("POST", "http://backend/upload", nil)
	uploadChan := make(chan *common.Message)
	close(uploadChan)

	if err := streamer.StreamToRequest(uploadChan, req); err != nil {
		t.Fatalf("StreamToRequest: %v", err)
	}

	// Channel was closed immediately — body should be readable (returns empty or EOF).
	body, _ := io.ReadAll(req.Body)
	if len(body) != 0 {
		t.Fatalf("expected empty body, got %q", body)
	}
}

func TestStreamingHandler_HandleUploadFromReader(t *testing.T) {
	handler := NewStreamingHandler()
	defer handler.Close()

	sender := &MockMessageSender{}
	data := bytes.Repeat([]byte("z"), 256)

	if err := handler.HandleUploadFromReader("up-1", bytes.NewReader(data), "msg-up", int64(len(data)), sender); err != nil {
		t.Fatalf("HandleUploadFromReader: %v", err)
	}

	msgs := sender.GetMessages()
	if len(msgs) < 2 {
		t.Fatalf("expected ≥2 messages, got %d", len(msgs))
	}
	if msgs[0].Type != "http_upload_start" {
		t.Fatalf("first msg=%s, want http_upload_start", msgs[0].Type)
	}
}

func TestStreamingHandler_HandleUploadFromReaderWithContext(t *testing.T) {
	handler := NewStreamingHandler()
	defer handler.Close()

	sender := &MockMessageSender{}
	data := bytes.Repeat([]byte("w"), 256)
	headers := map[string][]string{"Content-Type": {"application/octet-stream"}}

	if err := handler.HandleUploadFromReaderWithContext(
		"up-ctx", bytes.NewReader(data), "msg-ctx", int64(len(data)),
		"POST", "/api/upload", headers, sender,
	); err != nil {
		t.Fatalf("HandleUploadFromReaderWithContext: %v", err)
	}

	msgs := sender.GetMessages()
	if len(msgs) == 0 {
		t.Fatal("no messages")
	}
	if msgs[0].HTTP.Method != "POST" {
		t.Fatalf("method=%s, want POST", msgs[0].HTTP.Method)
	}
}
