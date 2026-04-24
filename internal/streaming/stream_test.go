package streaming

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

// MockMessageSender implements MessageSender for testing
type MockMessageSender struct {
	messages []*common.Message
	sendErr  error
}

func (m *MockMessageSender) SendMessage(msg *common.Message) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.messages = append(m.messages, msg)
	return nil
}

func (m *MockMessageSender) GetMessages() []*common.Message {
	return m.messages
}

func (m *MockMessageSender) GetLastMessage() *common.Message {
	if len(m.messages) == 0 {
		return nil
	}
	return m.messages[len(m.messages)-1]
}

func (m *MockMessageSender) Reset() {
	m.messages = nil
}

// MockConnection implements net.Conn for testing
type MockConnection struct {
	readBuffer  *bytes.Buffer
	writeBuffer *bytes.Buffer
	closed      bool
}

func NewMockConnection(data []byte) *MockConnection {
	return &MockConnection{
		readBuffer:  bytes.NewBuffer(data),
		writeBuffer: &bytes.Buffer{},
	}
}

func (m *MockConnection) Read(b []byte) (n int, err error) {
	if m.closed {
		return 0, io.EOF
	}
	return m.readBuffer.Read(b)
}

func (m *MockConnection) Write(b []byte) (n int, err error) {
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return m.writeBuffer.Write(b)
}

func (m *MockConnection) Close() error {
	m.closed = true
	return nil
}

func (m *MockConnection) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *MockConnection) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *MockConnection) SetDeadline(t time.Time) error      { return nil }
func (m *MockConnection) SetReadDeadline(t time.Time) error  { return nil }
func (m *MockConnection) SetWriteDeadline(t time.Time) error { return nil }

func (m *MockConnection) GetWrittenData() []byte {
	return m.writeBuffer.Bytes()
}

// Test Stream creation and basic operations
func TestNewStream(t *testing.T) {
	config := DefaultConfig()
	stream := NewStream("test-stream", 1024, config)

	if stream.ID != "test-stream" {
		t.Errorf("expected stream ID 'test-stream', got '%s'", stream.ID)
	}

	if stream.TotalSize != 1024 {
		t.Errorf("expected total size 1024, got %d", stream.TotalSize)
	}

	if stream.Direction != DirectionDownload {
		t.Errorf("expected direction Download, got %s", stream.Direction)
	}

	if stream.IsComplete() {
		t.Error("expected stream not to be complete initially")
	}

	// Test progress update
	stream.UpdateProgress(512)
	if stream.Transferred != 512 {
		t.Errorf("expected transferred 512, got %d", stream.Transferred)
	}

	stream.UpdateProgress(1024)
	if !stream.IsComplete() {
		t.Error("expected stream to be complete after transferring all data")
	}

	stream.Close()
}

// Test StreamManager
func TestStreamManager(t *testing.T) {
	manager := NewStreamManager()
	sender := &MockMessageSender{}

	// Create download stream
	downloader := manager.CreateDownloadStream("download-1", 2048, sender)
	if downloader == nil {
		t.Fatal("expected download streamer to be created")
	}

	// Create upload stream
	uploader := manager.CreateUploadStream("upload-1", 1024, sender)
	if uploader == nil {
		t.Fatal("expected upload streamer to be created")
	}

	// Check streams exist
	stream, exists := manager.GetStream("download-1")
	if !exists || stream == nil {
		t.Error("expected download stream to exist")
	}

	stream, exists = manager.GetStream("upload-1")
	if !exists || stream == nil {
		t.Error("expected upload stream to exist")
	}

	// Get active streams
	active := manager.GetActiveStreams()
	if len(active) != 2 {
		t.Errorf("expected 2 active streams, got %d", len(active))
	}

	// Test stream stats
	stats := manager.GetStreamStats()
	if len(stats) != 2 {
		t.Errorf("expected 2 stream stats, got %d", len(stats))
	}

	// Remove streams
	manager.RemoveStream("download-1")
	manager.RemoveStream("upload-1")

	active = manager.GetActiveStreams()
	if len(active) != 0 {
		t.Errorf("expected 0 active streams after removal, got %d", len(active))
	}
}

// Test DownloadStreamer
func TestDownloadStreamer(t *testing.T) {
	sender := &MockMessageSender{}

	// Create a mock HTTP response
	responseBody := strings.NewReader("This is test data for download streaming")
	resp := &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		Header:        make(http.Header),
		Body:          io.NopCloser(responseBody),
		ContentLength: int64(responseBody.Len()),
	}
	resp.Header.Set("Content-Type", "application/octet-stream")

	streamer := NewDownloadStreamer("test-download", resp.ContentLength, sender)

	// Test streaming
	err := streamer.StreamResponse(resp, "msg-123")
	if err != nil {
		t.Fatalf("unexpected error during streaming: %v", err)
	}

	// Check messages were sent
	messages := sender.GetMessages()
	if len(messages) < 2 {
		t.Errorf("expected at least 2 messages (initial + chunk), got %d", len(messages))
	}

	// Check initial message
	initialMsg := messages[0]
	if initialMsg.Type != "http_response" {
		t.Errorf("expected initial message type 'http_response', got '%s'", initialMsg.Type)
	}
	if !initialMsg.HTTP.IsStream {
		t.Error("expected initial message to be marked as stream")
	}

	// Check if any message is marked as last chunk
	hasLastChunk := false
	for _, msg := range messages {
		if msg.HTTP != nil && msg.HTTP.IsLastChunk {
			hasLastChunk = true
			break
		}
	}
	if !hasLastChunk {
		t.Error("expected at least one message to be marked as last chunk")
	}
}

// Test UploadStreamer
func TestUploadStreamer(t *testing.T) {
	sender := &MockMessageSender{}
	testData := []byte("This is test upload data")

	conn := NewMockConnection(testData)
	streamer := NewUploadStreamer("test-upload", int64(len(testData)), sender)

	// Test streaming from connection
	err := streamer.StreamFromConnection(conn, "msg-456", int64(len(testData)))
	if err != nil {
		t.Fatalf("unexpected error during upload streaming: %v", err)
	}

	// Check messages were sent
	messages := sender.GetMessages()
	if len(messages) < 2 {
		t.Errorf("expected at least 2 messages (initial + chunk), got %d", len(messages))
	}

	// Check initial message
	initialMsg := messages[0]
	if initialMsg.Type != "http_upload_start" {
		t.Errorf("expected initial message type 'http_upload_start', got '%s'", initialMsg.Type)
	}

	// Check chunk message
	chunkMsg := messages[1]
	if chunkMsg.Type != "http_upload_chunk" {
		t.Errorf("expected chunk message type 'http_upload_chunk', got '%s'", chunkMsg.Type)
	}
}

// Test StreamingHandler
func TestStreamingHandler(t *testing.T) {
	handler := NewStreamingHandler()
	defer handler.Close()

	// Test detection functions
	req := &http.Request{
		Method:        "GET",
		Header:        make(http.Header),
		ContentLength: 2048000, // 2MB
	}
	req.Header.Set("Range", "bytes=0-1023")

	shouldStream, direction := handler.DetectStreamingRequest(req)
	if !shouldStream {
		t.Error("expected request to be detected as streaming")
	}
	if direction != DirectionDownload {
		t.Errorf("expected direction Download, got %s", direction)
	}

	// Test upload detection
	uploadReq := &http.Request{
		Method:        "POST",
		Header:        make(http.Header),
		ContentLength: 5242880, // 5MB
	}

	shouldStream, direction = handler.DetectStreamingRequest(uploadReq)
	if !shouldStream {
		t.Error("expected upload request to be detected as streaming")
	}
	if direction != DirectionUpload {
		t.Errorf("expected direction Upload, got %s", direction)
	}

	// Test ShouldStream functions
	if !handler.ShouldStreamDownload(2048000, "application/octet-stream") {
		t.Error("expected large file to require streaming")
	}

	if handler.ShouldStreamDownload(1024, "text/plain") {
		t.Error("expected small file not to require streaming")
	}

	if !handler.ShouldStreamUpload(5242880) {
		t.Error("expected large upload to require streaming")
	}

	if handler.ShouldStreamUpload(512) {
		t.Error("expected small upload not to require streaming")
	}
}

// Test StreamAdapter
func TestStreamAdapter(t *testing.T) {
	adapter := NewStreamAdapter()

	// Test small response (should not stream)
	smallResp := &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("small")),
		ContentLength: 5,
	}

	err := adapter.AdaptDownloadStreaming("test", smallResp, "msg", &MockMessageSender{})
	if err == nil {
		t.Error("expected error for small response that doesn't require streaming")
	}

	// Test small upload (should not stream)
	conn := NewMockConnection([]byte("small"))
	err = adapter.AdaptUploadStreaming("test", conn, "msg", 5, &MockMessageSender{})
	if err == nil {
		t.Error("expected error for small upload that doesn't require streaming")
	}
}

// Test Configuration
func TestConfigurations(t *testing.T) {
	// Test default config
	defaultConfig := DefaultConfig()
	if defaultConfig.ChunkSize != 32768 {
		t.Errorf("expected default chunk size 32768, got %d", defaultConfig.ChunkSize)
	}
	if defaultConfig.Direction != DirectionDownload {
		t.Errorf("expected default direction Download, got %s", defaultConfig.Direction)
	}

	// Test download config
	downloadConfig := DownloadConfig()
	if downloadConfig.Direction != DirectionDownload {
		t.Errorf("expected download direction Download, got %s", downloadConfig.Direction)
	}
	if downloadConfig.ChunkSize != 32768 {
		t.Errorf("expected download chunk size 32768, got %d", downloadConfig.ChunkSize)
	}

	// Test upload config
	uploadConfig := UploadConfig()
	if uploadConfig.Direction != DirectionUpload {
		t.Errorf("expected upload direction Upload, got %s", uploadConfig.Direction)
	}
	if uploadConfig.ChunkSize != 65536 {
		t.Errorf("expected upload chunk size 65536, got %d", uploadConfig.ChunkSize)
	}
}

// Test Direction String method
func TestDirectionString(t *testing.T) {
	if DirectionDownload.String() != "download" {
		t.Errorf("expected 'download', got '%s'", DirectionDownload.String())
	}

	if DirectionUpload.String() != "upload" {
		t.Errorf("expected 'upload', got '%s'", DirectionUpload.String())
	}

	// Test unknown direction
	var unknown Direction = 999
	if unknown.String() != "unknown" {
		t.Errorf("expected 'unknown', got '%s'", unknown.String())
	}
}

// Test ProgressInfo calculation
func TestProgressInfo(t *testing.T) {
	config := DefaultConfig()
	stream := NewStream("test-progress", 1000, config)

	// Give the stream a slight delay to initialize
	time.Sleep(1 * time.Millisecond)

	// Initial progress - drain any existing progress info first
	stream.UpdateProgress(0)
	if stream.Transferred != 0 {
		t.Errorf("expected initial transferred to be 0, got %d", stream.Transferred)
	}

	// Drain any progress info from initial update
	select {
	case <-stream.ProgressChan:
		// Drain initial progress if any
	default:
		// No initial progress, that's fine
	}

	// Partial progress (UpdateProgress sets the total transferred, not adds to it)
	stream.UpdateProgress(250)
	if stream.Transferred != 250 {
		t.Errorf("expected transferred to be 250, got %d", stream.Transferred)
	}

	// Check progress info is sent to channel
	select {
	case progress := <-stream.ProgressChan:
		if progress.Progress != 25.0 {
			t.Errorf("expected progress 25%%, got %.1f%% (TotalSize=%d, Transferred=%d)",
				progress.Progress, progress.TotalSize, progress.Transferred)
		}
		if progress.StreamID != "test-progress" {
			t.Errorf("expected stream ID 'test-progress', got '%s'", progress.StreamID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected progress info to be sent to channel")
	}

	stream.Close()
}

// Test cleanup functionality
func TestCleanupExpiredStreams(t *testing.T) {
	manager := NewStreamManager()
	sender := &MockMessageSender{}

	// Create a stream
	streamer := manager.CreateDownloadStream("test-cleanup", 1024, sender)
	if streamer == nil {
		t.Fatal("expected streamer to be created")
	}

	// Simulate old activity
	stream, _ := manager.GetStream("test-cleanup")
	stream.LastActivity = time.Now().Add(-2 * time.Hour)

	// Cleanup with 1 hour max age
	manager.CleanupExpiredStreams(1 * time.Hour)

	// Stream should be removed
	_, exists := manager.GetStream("test-cleanup")
	if exists {
		t.Error("expected expired stream to be cleaned up")
	}
}

// Test error handling
func TestErrorHandling(t *testing.T) {
	// Test with sender that returns errors
	errorSender := &MockMessageSender{sendErr: io.ErrUnexpectedEOF}

	streamer := NewDownloadStreamer("error-test", 1024, errorSender)

	responseBody := strings.NewReader("test data")
	resp := &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		Header:        make(http.Header),
		Body:          io.NopCloser(responseBody),
		ContentLength: int64(responseBody.Len()),
	}

	err := streamer.StreamResponse(resp, "error-msg")
	if err == nil {
		t.Error("expected error when sender fails")
	}
}

// Test context cancellation
func TestContextCancellation(t *testing.T) {
	config := DefaultConfig()
	config.MaxTimeout = 100 * time.Millisecond // Short timeout for test

	stream := NewStream("cancel-test", 1024, config)

	// Wait for context to timeout
	select {
	case <-stream.Context.Done():
		if stream.Context.Err() != context.DeadlineExceeded {
			t.Errorf("expected deadline exceeded error, got %v", stream.Context.Err())
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("expected context to be cancelled due to timeout")
	}

	stream.Close()
}

// Benchmark streaming operations
func BenchmarkDownloadStreaming(b *testing.B) {
	sender := &MockMessageSender{}
	data := make([]byte, 1024*1024) // 1MB of data

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		responseBody := bytes.NewReader(data)
		resp := &http.Response{
			StatusCode:    200,
			Status:        "200 OK",
			Header:        make(http.Header),
			Body:          io.NopCloser(responseBody),
			ContentLength: int64(len(data)),
		}

		streamer := NewDownloadStreamer("bench-download", resp.ContentLength, sender)
		streamer.StreamResponse(resp, "bench-msg")
		sender.Reset()
	}
}

func TestUploadStreamingDetection(t *testing.T) {
	tests := []struct {
		name          string
		contentLength int64
		shouldStream  bool
		description   string
	}{
		{
			name:          "unknown_content_length",
			contentLength: -1,
			shouldStream:  false,
			description:   "Unknown content length (-1) should not trigger streaming",
		},
		{
			name:          "small_known_size",
			contentLength: 1024,
			shouldStream:  false,
			description:   "Small known size should not trigger streaming",
		},
		{
			name:          "medium_known_size",
			contentLength: 512 * 1024, // 512KB
			shouldStream:  false,
			description:   "Medium size below 1MB should not trigger streaming",
		},
		{
			name:          "large_known_size",
			contentLength: 2 * 1024 * 1024, // 2MB
			shouldStream:  true,
			description:   "Large known size above 1MB should trigger streaming",
		},
		{
			name:          "exactly_1mb",
			contentLength: 1024 * 1024, // Exactly 1MB
			shouldStream:  false,
			description:   "Exactly 1MB should not trigger streaming (boundary case)",
		},
		{
			name:          "just_over_1mb",
			contentLength: 1024*1024 + 1, // Just over 1MB
			shouldStream:  true,
			description:   "Just over 1MB should trigger streaming",
		},
		{
			name:          "zero_content_length",
			contentLength: 0,
			shouldStream:  false,
			description:   "Zero content length should not trigger streaming",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldStreamUpload(tt.contentLength)
			if result != tt.shouldStream {
				t.Errorf("ShouldStreamUpload(%d) = %v, want %v - %s",
					tt.contentLength, result, tt.shouldStream, tt.description)
			}
		})
	}
}

func TestStreamWriter_Write(t *testing.T) {
	config := DefaultConfig()
	stream := NewStream("sw-test", 100, config)
	defer stream.Close()

	var buf bytes.Buffer
	sw := NewStreamWriter(&buf, stream)
	n, err := sw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Fatalf("n=%d, want 5", n)
	}
	if buf.String() != "hello" {
		t.Fatalf("buf=%q, want hello", buf.String())
	}
	if stream.Transferred != 5 {
		t.Fatalf("transferred=%d, want 5", stream.Transferred)
	}
}

func TestStream_IsComplete_UnknownSize(t *testing.T) {
	config := DefaultConfig()
	stream := NewStream("unk-size", 0, config)
	defer stream.Close()
	if stream.IsComplete() {
		t.Fatal("stream with 0 total size should not be complete")
	}
}

func TestAdaptDownloadStreaming_Success(t *testing.T) {
	adapter := NewStreamAdapter()
	sender := &MockMessageSender{}

	data := bytes.Repeat([]byte("x"), 2*1024*1024) // 2 MB — above streaming threshold
	resp := &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
	}
	resp.Header.Set("Content-Type", "application/octet-stream")

	if err := adapter.AdaptDownloadStreaming("adapt-dl", resp, "msg-dl", sender); err != nil {
		t.Fatalf("AdaptDownloadStreaming: %v", err)
	}
	if len(sender.GetMessages()) == 0 {
		t.Fatal("expected messages to be sent")
	}
}

func TestStreamReader_Read(t *testing.T) {
	config := DefaultConfig()
	stream := NewStream("sr-test", 100, config)
	defer stream.Close()

	src := bytes.NewBufferString("hello world")
	sr := NewStreamReader(src, stream)
	buf := make([]byte, 5)
	n, err := sr.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 5 {
		t.Fatalf("n=%d, want 5", n)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("data=%q, want hello", buf[:n])
	}
	if stream.Transferred != 5 {
		t.Fatalf("transferred=%d, want 5", stream.Transferred)
	}
}

func TestAdaptUploadStreaming_Success(t *testing.T) {
	adapter := NewStreamAdapter()
	sender := &MockMessageSender{}

	data := bytes.Repeat([]byte("y"), 2*1024*1024) // 2 MB — above upload threshold
	conn := NewMockConnection(data)

	if err := adapter.AdaptUploadStreaming("adapt-up", conn, "msg-up", int64(len(data)), sender); err != nil {
		t.Fatalf("AdaptUploadStreaming: %v", err)
	}
	if len(sender.GetMessages()) == 0 {
		t.Fatal("expected messages to be sent")
	}
}

// TestHandleUploadToRequest exercises HandleUploadToRequest by providing a
// channel of upload messages and an HTTP request to write to.
func TestHandleUploadToRequest_Success(t *testing.T) {
	handler := NewStreamingHandler()
	defer handler.Close()

	sender := &MockMessageSender{}

	// Set up an HTTP test server to receive the upload.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/upload", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	uploadChan := make(chan *common.Message, 4)
	uploadChan <- &common.Message{
		HTTP: &common.HTTPData{Body: []byte("chunk1"), IsStream: true},
	}
	uploadChan <- &common.Message{
		HTTP: &common.HTTPData{Body: []byte("chunk2"), IsStream: true, IsLastChunk: true},
	}

	done := make(chan error, 1)
	go func() {
		done <- handler.HandleUploadToRequest("ul-1", uploadChan, req, sender)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandleUploadToRequest: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HandleUploadToRequest timed out")
	}
}
