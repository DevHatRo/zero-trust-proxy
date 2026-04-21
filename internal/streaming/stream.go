package streaming

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

// StreamManager manages active streaming operations
type StreamManager struct {
	streams map[string]*Stream
	mu      sync.RWMutex
}

// NewStreamManager creates a new stream manager
func NewStreamManager() *StreamManager {
	return &StreamManager{
		streams: make(map[string]*Stream),
	}
}

// CreateDownloadStream creates a new download stream
func (sm *StreamManager) CreateDownloadStream(streamID string, totalSize int64, sender MessageSender) *DownloadStreamer {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	streamer := NewDownloadStreamer(streamID, totalSize, sender)
	sm.streams[streamID] = streamer.stream

	return streamer
}

// CreateUploadStream creates a new upload stream
func (sm *StreamManager) CreateUploadStream(streamID string, totalSize int64, sender MessageSender) *UploadStreamer {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	streamer := NewUploadStreamer(streamID, totalSize, sender)
	sm.streams[streamID] = streamer.stream

	return streamer
}

// GetStream returns a stream by ID
func (sm *StreamManager) GetStream(streamID string) (*Stream, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stream, exists := sm.streams[streamID]
	return stream, exists
}

// RemoveStream removes a stream from the manager
func (sm *StreamManager) RemoveStream(streamID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if stream, exists := sm.streams[streamID]; exists {
		// Only close if not already closed
		if !stream.IsClosed() {
			stream.Close()
		}
		delete(sm.streams, streamID)
	}
}

// GetActiveStreams returns all active streams
func (sm *StreamManager) GetActiveStreams() map[string]*Stream {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := make(map[string]*Stream)
	for id, stream := range sm.streams {
		result[id] = stream
	}
	return result
}

// CleanupExpiredStreams removes streams that have been inactive for too long
func (sm *StreamManager) CleanupExpiredStreams(maxAge time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	for id, stream := range sm.streams {
		if now.Sub(stream.LastActivity) > maxAge {
			log.Info("🧹 Cleaning up expired stream: ID=%s, age=%v", id, now.Sub(stream.LastActivity))
			// Only close if not already closed
			if !stream.IsClosed() {
				stream.Close()
			}
			delete(sm.streams, id)
		}
	}
}

// GetStreamStats returns statistics about all streams
func (sm *StreamManager) GetStreamStats() map[string]*ProgressInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats := make(map[string]*ProgressInfo)
	for id, stream := range sm.streams {
		// Calculate current progress
		var progress float64
		if stream.TotalSize > 0 {
			progress = float64(stream.Transferred) / float64(stream.TotalSize) * 100
		}

		// Calculate transfer rate
		elapsed := time.Since(stream.StartTime)
		var transferRate float64
		if elapsed.Seconds() > 0 {
			transferRate = float64(stream.Transferred) / elapsed.Seconds()
		}

		// Calculate ETA
		var eta time.Duration
		if transferRate > 0 && stream.TotalSize > stream.Transferred {
			remainingBytes := float64(stream.TotalSize - stream.Transferred)
			eta = time.Duration(remainingBytes/transferRate) * time.Second
		}

		stats[id] = &ProgressInfo{
			StreamID:     id,
			Direction:    stream.Direction,
			TotalSize:    stream.TotalSize,
			Transferred:  stream.Transferred,
			ChunkIndex:   stream.ChunkIndex,
			Progress:     progress,
			TransferRate: transferRate,
			ETA:          eta,
			Elapsed:      elapsed,
		}
	}
	return stats
}

// StreamingHandler provides high-level streaming operations
type StreamingHandler struct {
	manager *StreamManager
}

// NewStreamingHandler creates a new streaming handler
func NewStreamingHandler() *StreamingHandler {
	return &StreamingHandler{
		manager: NewStreamManager(),
	}
}

// HandleDownloadStream handles a download streaming operation
func (sh *StreamingHandler) HandleDownloadStream(streamID string, resp *http.Response, msgID string, sender MessageSender) error {
	contentLength := resp.ContentLength

	// Handle unknown content length
	if contentLength <= 0 {
		contentLength = -1 // Unknown size
	}

	// Create download streamer
	streamer := sh.manager.CreateDownloadStream(streamID, contentLength, sender)
	defer func() {
		// Recover from any panic during cleanup
		if r := recover(); r != nil {
			log.Error("❌ Panic during stream cleanup: %v", r)
		}
		sh.manager.RemoveStream(streamID)
	}()

	// Stream the response
	return streamer.StreamResponse(resp, msgID)
}

// HandleDownloadToConnection handles streaming download data to a connection
func (sh *StreamingHandler) HandleDownloadToConnection(streamID string, conn net.Conn, responseChan <-chan *common.Message, initialResponse *common.Message, sender MessageSender) error {
	totalSize := initialResponse.HTTP.TotalSize

	// Create download streamer
	streamer := sh.manager.CreateDownloadStream(streamID, totalSize, sender)
	defer func() {
		// Recover from any panic during cleanup
		if r := recover(); r != nil {
			log.Error("❌ Panic during stream cleanup: %v", r)
		}
		sh.manager.RemoveStream(streamID)
	}()

	// Stream to connection
	return streamer.StreamToConnection(conn, responseChan, initialResponse)
}

// HandleUploadStream handles an upload streaming operation from a connection
func (sh *StreamingHandler) HandleUploadStream(streamID string, conn net.Conn, msgID string, expectedSize int64, sender MessageSender) error {
	// Create upload streamer
	streamer := sh.manager.CreateUploadStream(streamID, expectedSize, sender)
	defer func() {
		// Recover from any panic during cleanup
		if r := recover(); r != nil {
			log.Error("❌ Panic during stream cleanup: %v", r)
		}
		sh.manager.RemoveStream(streamID)
	}()

	// Stream from connection
	return streamer.StreamFromConnection(conn, msgID, expectedSize)
}

// HandleUploadToRequest handles streaming upload data to an HTTP request
func (sh *StreamingHandler) HandleUploadToRequest(streamID string, uploadChan <-chan *common.Message, req *http.Request, sender MessageSender) error {
	var totalSize int64 = -1

	streamer := sh.manager.CreateUploadStream(streamID, totalSize, sender)
	// Do NOT defer RemoveStream here. StreamToRequest returns immediately after
	// launching its goroutine; a defer here would fire before the goroutine
	// finishes, cancelling the stream context and aborting the in-flight upload.
	// The caller (handleUploadStart) defers StreamingHandler.Close() which
	// removes the stream after client.Do returns.
	return streamer.StreamToRequest(uploadChan, req)
}

// HandleUploadFromReader handles streaming upload data from an io.Reader
func (sh *StreamingHandler) HandleUploadFromReader(streamID string, reader io.Reader, msgID string, totalSize int64, sender MessageSender) error {
	// Create upload streamer
	streamer := sh.manager.CreateUploadStream(streamID, totalSize, sender)
	defer func() {
		// Recover from any panic during cleanup
		if r := recover(); r != nil {
			log.Error("❌ Panic during stream cleanup: %v", r)
		}
		sh.manager.RemoveStream(streamID)
	}()

	// Stream from reader
	return streamer.StreamFromReader(reader, msgID)
}

// HandleUploadFromReaderWithContext handles streaming upload data from an io.Reader with HTTP context
func (sh *StreamingHandler) HandleUploadFromReaderWithContext(streamID string, reader io.Reader, msgID string, totalSize int64, method string, url string, headers map[string][]string, sender MessageSender) error {
	// Create upload streamer
	streamer := sh.manager.CreateUploadStream(streamID, totalSize, sender)
	defer func() {
		// Recover from any panic during cleanup
		if r := recover(); r != nil {
			log.Error("❌ Panic during stream cleanup: %v", r)
		}
		sh.manager.RemoveStream(streamID)
	}()

	// Stream from reader with context
	return streamer.StreamFromReaderWithContext(reader, msgID, method, url, headers)
}

// ShouldStreamDownload determines if a response should be streamed for download
func (sh *StreamingHandler) ShouldStreamDownload(contentLength int64, contentType string) bool {
	return ShouldStream(contentLength, contentType)
}

// ShouldStreamUpload determines if a request should be streamed for upload
func (sh *StreamingHandler) ShouldStreamUpload(contentLength int64) bool {
	return ShouldStreamUpload(contentLength)
}

// DetectStreamingRequest analyzes a request to determine if it might involve streaming
func (sh *StreamingHandler) DetectStreamingRequest(req *http.Request) (bool, Direction) {
	// Check for download streaming (Range requests)
	if DetectStreamingFromRequest(req) {
		return true, DirectionDownload
	}

	// Check for upload streaming (large POST/PUT requests)
	if DetectUploadFromRequest(req) {
		return true, DirectionUpload
	}

	return false, DirectionDownload
}

// GetStreamStats returns statistics for all active streams
func (sh *StreamingHandler) GetStreamStats() map[string]*ProgressInfo {
	return sh.manager.GetStreamStats()
}

// GetStream returns a stream by ID
func (sh *StreamingHandler) GetStream(streamID string) (*Stream, bool) {
	return sh.manager.GetStream(streamID)
}

// StartCleanupRoutine starts a goroutine to periodically clean up expired streams
func (sh *StreamingHandler) StartCleanupRoutine(interval, maxAge time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			sh.manager.CleanupExpiredStreams(maxAge)
		}
	}()
}

// Close closes all streams and cleans up resources
func (sh *StreamingHandler) Close() {
	// Get a snapshot of stream IDs to avoid modifying map while iterating
	sh.manager.mu.RLock()
	streamIDs := make([]string, 0, len(sh.manager.streams))
	for id := range sh.manager.streams {
		streamIDs = append(streamIDs, id)
	}
	sh.manager.mu.RUnlock()

	// Remove each stream safely
	for _, id := range streamIDs {
		sh.manager.RemoveStream(id)
	}
}

// StreamAdapter provides adapter functions for legacy code
type StreamAdapter struct {
	handler *StreamingHandler
}

// NewStreamAdapter creates a new stream adapter
func NewStreamAdapter() *StreamAdapter {
	return &StreamAdapter{
		handler: NewStreamingHandler(),
	}
}

// AdaptDownloadStreaming adapts existing download streaming code to use the new library
func (sa *StreamAdapter) AdaptDownloadStreaming(streamID string, resp *http.Response, msgID string, sender MessageSender) error {
	// Check if streaming is needed
	if !sa.handler.ShouldStreamDownload(resp.ContentLength, resp.Header.Get("Content-Type")) {
		return fmt.Errorf("response does not require streaming")
	}

	// Use the streaming handler
	return sa.handler.HandleDownloadStream(streamID, resp, msgID, sender)
}

// AdaptUploadStreaming adapts existing upload streaming code to use the new library
func (sa *StreamAdapter) AdaptUploadStreaming(streamID string, conn net.Conn, msgID string, expectedSize int64, sender MessageSender) error {
	// Check if streaming is needed
	if !sa.handler.ShouldStreamUpload(expectedSize) {
		return fmt.Errorf("upload does not require streaming")
	}

	// Use the streaming handler
	return sa.handler.HandleUploadStream(streamID, conn, msgID, expectedSize, sender)
}

// GetHandler returns the underlying streaming handler
func (sa *StreamAdapter) GetHandler() *StreamingHandler {
	return sa.handler
}
