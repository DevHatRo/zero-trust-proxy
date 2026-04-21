package streaming

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/logger"
)

// Component-specific logger for streaming
var log = logger.WithComponent("streaming")

// DownloadStreamer handles file download streaming operations
type DownloadStreamer struct {
	stream *Stream
	sender MessageSender
}

// NewDownloadStreamer creates a new download streamer
func NewDownloadStreamer(streamID string, totalSize int64, sender MessageSender) *DownloadStreamer {
	config := DownloadConfig()
	stream := NewStream(streamID, totalSize, config)

	return &DownloadStreamer{
		stream: stream,
		sender: sender,
	}
}

// StreamResponse streams an HTTP response body in chunks
func (ds *DownloadStreamer) StreamResponse(resp *http.Response, msgID string) error {
	defer ds.stream.Close()

	log.Info("📡 Starting download stream: ID=%s, Size=%d bytes", ds.stream.ID, ds.stream.TotalSize)

	// Send initial streaming response with metadata
	initialMsg := &common.Message{
		Type: "http_response",
		ID:   msgID,
		HTTP: &common.HTTPData{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.Status,
			Headers:       resp.Header,
			IsStream:      true,
			ChunkSize:     ds.stream.Config.ChunkSize,
			TotalSize:     ds.stream.TotalSize,
			ChunkIndex:    0,
			IsLastChunk:   false,
		},
	}

	if err := ds.sender.SendMessage(initialMsg); err != nil {
		return fmt.Errorf("failed to send initial streaming response: %v", err)
	}

	// Create timeout configuration for streaming operations
	timeoutConfig := common.DefaultTimeouts()

	// Stream the response body in chunks
	buffer := make([]byte, ds.stream.Config.ChunkSize)
	lastProgressTime := time.Now()

	for {
		// Calculate dynamic timeout based on progress
		dynamicTimeout := common.CalculateStreamingTimeout(ds.stream.TotalSize, ds.stream.Transferred, timeoutConfig)

		// Read chunk with activity-based timeout detection
		n, err := resp.Body.Read(buffer)
		currentTime := time.Now()

		if n > 0 {
			// Update stream progress
			ds.stream.ChunkIndex++
			ds.stream.UpdateProgress(ds.stream.Transferred + int64(n))

			// Check if this is the last chunk (EOF detected or reached total size)
			isLastChunk := (err == io.EOF) || (ds.stream.TotalSize > 0 && ds.stream.Transferred >= ds.stream.TotalSize)

			// Create chunk message
			chunkMsg := &common.Message{
				Type: "http_response",
				ID:   msgID,
				HTTP: &common.HTTPData{
					Body:        buffer[:n],
					IsStream:    true,
					ChunkSize:   n,
					TotalSize:   ds.stream.TotalSize,
					ChunkIndex:  ds.stream.ChunkIndex,
					IsLastChunk: isLastChunk,
				},
			}

			// Send chunk
			if err := ds.sender.SendMessage(chunkMsg); err != nil {
				return fmt.Errorf("failed to send chunk %d: %v", ds.stream.ChunkIndex, err)
			}

			// Log progress periodically
			if time.Since(lastProgressTime) > ds.stream.Config.ProgressInterval || isLastChunk {
				elapsed := time.Since(ds.stream.StartTime)
				var progress float64
				if ds.stream.TotalSize > 0 {
					progress = float64(ds.stream.Transferred) / float64(ds.stream.TotalSize) * 100
				}
				log.Info("📊 Download progress: %.1f%% (%d/%d bytes), elapsed: %v, timeout: %v",
					progress, ds.stream.Transferred, ds.stream.TotalSize, elapsed.Round(time.Second),
					dynamicTimeout.Round(time.Second))
				lastProgressTime = time.Now()
			}

			if isLastChunk {
				elapsed := time.Since(ds.stream.StartTime)
				avgSpeed := float64(ds.stream.Transferred) / elapsed.Seconds() / (1024 * 1024) // MB/s
				log.Info("✅ Download stream completed: ID=%s, chunks=%d, size=%d bytes, time=%v, speed=%.2f MB/s",
					ds.stream.ID, ds.stream.ChunkIndex, ds.stream.Transferred, elapsed.Round(time.Second), avgSpeed)
				return nil
			}
		}

		if err == io.EOF {
			// Handle EOF without data read in this iteration
			if n == 0 {
				log.Debug("🔚 Reached EOF, download stream complete: ID=%s", ds.stream.ID)
				return nil
			}
		} else if err != nil {
			// Check for timeout based on activity
			timeSinceActivity := currentTime.Sub(ds.stream.LastActivity)
			if timeSinceActivity > dynamicTimeout {
				return fmt.Errorf("activity timeout exceeded (%.1fs since last data): %v",
					timeSinceActivity.Seconds(), err)
			} else {
				return fmt.Errorf("error reading response body: %v", err)
			}
		}

		// Activity-based timeout detection
		timeSinceActivity := currentTime.Sub(ds.stream.LastActivity)
		if timeSinceActivity > dynamicTimeout {
			return fmt.Errorf("no activity for %.1fs (timeout: %.1fs) - connection appears dead",
				timeSinceActivity.Seconds(), dynamicTimeout.Seconds())
		}
	}
}

// StreamToConnection streams chunked data to a network connection (server-side)
func (ds *DownloadStreamer) StreamToConnection(conn net.Conn, responseChan <-chan *common.Message, initialResponse *common.Message) error {
	defer ds.stream.Close()

	log.Info("📡 Starting download stream to connection: ID=%s, Size=%d bytes", ds.stream.ID, ds.stream.TotalSize)

	// Prepare proper HTTP headers for browser compatibility
	headers := make(http.Header)

	// Copy original headers
	for key, values := range initialResponse.HTTP.Headers {
		headers[key] = values
	}

	// Set essential headers for browser download progress
	headers.Set("Content-Length", fmt.Sprintf("%d", ds.stream.TotalSize))

	// Ensure proper content-type
	contentType := headers.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	headers.Set("Content-Type", contentType)

	// Support range requests for proper download behavior
	headers.Set("Accept-Ranges", "bytes")
	headers.Set("Cache-Control", "public, max-age=0")
	headers.Set("Connection", "keep-alive")

	// Remove headers that can interfere with streaming
	headers.Del("Transfer-Encoding")
	headers.Del("Content-Encoding")

	// Write HTTP status line
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n", initialResponse.HTTP.StatusCode, initialResponse.HTTP.StatusMessage)

	// Write headers
	for key, values := range headers {
		for _, value := range values {
			fmt.Fprintf(conn, "%s: %s\r\n", key, value)
		}
	}

	// End headers section
	fmt.Fprintf(conn, "\r\n")

	// Stream chunks with flow control
	lastProgressTime := time.Now()
	timeoutConfig := common.DefaultTimeouts()

	for {
		// Calculate dynamic timeout
		timeoutDur := common.CalculateStreamingTimeout(ds.stream.TotalSize, ds.stream.Transferred, timeoutConfig)

		// Wait for next chunk
		select {
		case chunk, ok := <-responseChan:
			if !ok {
				log.Info("📊 Download stream completed: channel closed after %d chunks, %d bytes",
					ds.stream.ChunkIndex, ds.stream.Transferred)
				return nil
			}

			if chunk == nil || chunk.HTTP == nil {
				log.Debug("📄 Received nil chunk, ending stream")
				return nil
			}

			ds.stream.ChunkIndex++
			chunkSize := int64(len(chunk.HTTP.Body))
			ds.stream.UpdateProgress(ds.stream.Transferred + chunkSize)

			// Write chunk data directly
			if _, err := conn.Write(chunk.HTTP.Body); err != nil {
				log.Debug("📞 Client disconnected during download streaming at chunk %d", ds.stream.ChunkIndex)
				return err
			}

			// Log progress with transfer rate
			now := time.Now()
			if now.Sub(lastProgressTime) > ds.stream.Config.ProgressInterval || chunk.HTTP.IsLastChunk {
				progress := float64(ds.stream.Transferred) / float64(ds.stream.TotalSize) * 100
				elapsed := now.Sub(lastProgressTime)
				var rate float64
				if elapsed > 0 {
					rate = float64(chunkSize) / elapsed.Seconds() / (1024 * 1024) // MB/s
				}

				var eta time.Duration
				if rate > 0 && ds.stream.TotalSize > ds.stream.Transferred {
					remainingBytes := float64(ds.stream.TotalSize - ds.stream.Transferred)
					eta = time.Duration(remainingBytes/rate/1024/1024) * time.Second
				}

				log.Info("📈 Download streaming progress: %.1f%% (%d chunks, %d MB, %.2f MB/s, ETA: %v)",
					progress, ds.stream.ChunkIndex, ds.stream.Transferred/(1024*1024), rate, eta.Round(time.Second))
				lastProgressTime = now
			}

			// Check if this was the last chunk
			if chunk.HTTP.IsLastChunk {
				elapsed := time.Since(ds.stream.StartTime)
				log.Info("✅ Download streaming completed successfully: %d chunks, %d bytes total, time: %v",
					ds.stream.ChunkIndex, ds.stream.Transferred, elapsed.Round(time.Second))

				// Verify size if known
				if ds.stream.Transferred != ds.stream.TotalSize && ds.stream.TotalSize > 0 {
					log.Warn("⚠️  Size mismatch: sent %d bytes, expected %d bytes",
						ds.stream.Transferred, ds.stream.TotalSize)
				}
				return nil
			}

		case <-time.After(timeoutDur):
			return fmt.Errorf("timeout waiting for chunk %d after %v (received %d bytes)",
				ds.stream.ChunkIndex+1, timeoutDur, ds.stream.Transferred)

		case <-ds.stream.Context.Done():
			return fmt.Errorf("download stream context cancelled")
		}
	}
}

// ShouldStream determines if a response should be streamed based on size.
// Chunked transfers (contentLength < 0) are always streamed so unbounded
// responses don't get fully buffered in memory. The chunking overhead for
// small chunked JSON responses is negligible compared to the memory risk.
func ShouldStream(contentLength int64, contentType string) bool {
	if contentLength > 1024*1024 {
		return true
	}
	if contentLength < 0 {
		return true
	}
	return false
}

// DetectStreamingFromRequest analyzes an HTTP request for streaming hints
func DetectStreamingFromRequest(req *http.Request) bool {
	// Only check for Range header - indicates partial content request
	rangeHeader := req.Header.Get("Range")
	return rangeHeader != ""
}
