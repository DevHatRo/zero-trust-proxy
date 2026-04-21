package streaming

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

// UploadStreamer handles file upload streaming operations
type UploadStreamer struct {
	stream *Stream
	sender MessageSender
}

// NewUploadStreamer creates a new upload streamer
func NewUploadStreamer(streamID string, totalSize int64, sender MessageSender) *UploadStreamer {
	config := UploadConfig()
	stream := NewStream(streamID, totalSize, config)

	return &UploadStreamer{
		stream: stream,
		sender: sender,
	}
}

// StreamFromConnection streams upload data from a network connection (server-side)
func (us *UploadStreamer) StreamFromConnection(conn net.Conn, msgID string, expectedSize int64) error {
	defer us.stream.Close()

	log.Info("📤 Starting upload stream from connection: ID=%s, Size=%d bytes", us.stream.ID, expectedSize)

	// Update stream with actual expected size if different
	if expectedSize > 0 && expectedSize != us.stream.TotalSize {
		us.stream.TotalSize = expectedSize
	}

	// Send initial upload stream message
	initialMsg := &common.Message{
		Type: "http_upload_start",
		ID:   msgID,
		HTTP: &common.HTTPData{
			IsStream:    true,
			ChunkSize:   us.stream.Config.ChunkSize,
			TotalSize:   us.stream.TotalSize,
			ChunkIndex:  0,
			IsLastChunk: false,
		},
	}

	if err := us.sender.SendMessage(initialMsg); err != nil {
		return fmt.Errorf("failed to send initial upload message: %v", err)
	}

	// Stream upload data in chunks
	buffer := make([]byte, us.stream.Config.ChunkSize)
	lastProgressTime := time.Now()
	timeoutConfig := common.DefaultTimeouts()

	for {
		// Calculate dynamic timeout
		dynamicTimeout := common.CalculateStreamingTimeout(us.stream.TotalSize, us.stream.Transferred, timeoutConfig)

		// Set read deadline
		if err := conn.SetReadDeadline(time.Now().Add(dynamicTimeout)); err != nil {
			return fmt.Errorf("failed to set read deadline: %v", err)
		}

		// Read chunk from connection
		n, err := conn.Read(buffer)
		currentTime := time.Now()

		if n > 0 {
			// Update stream progress
			us.stream.ChunkIndex++
			us.stream.UpdateProgress(us.stream.Transferred + int64(n))

			// Check if this might be the last chunk
			isLastChunk := (err == io.EOF) ||
				(us.stream.TotalSize > 0 && us.stream.Transferred >= us.stream.TotalSize)

			// Create chunk message
			chunkMsg := &common.Message{
				Type: "http_upload_chunk",
				ID:   msgID,
				HTTP: &common.HTTPData{
					Body:        buffer[:n],
					IsStream:    true,
					ChunkSize:   n,
					TotalSize:   us.stream.TotalSize,
					ChunkIndex:  us.stream.ChunkIndex,
					IsLastChunk: isLastChunk,
				},
			}

			// Send chunk
			if err := us.sender.SendMessage(chunkMsg); err != nil {
				return fmt.Errorf("failed to send upload chunk %d: %v", us.stream.ChunkIndex, err)
			}

			// Log progress periodically
			if time.Since(lastProgressTime) > us.stream.Config.ProgressInterval || isLastChunk {
				elapsed := time.Since(us.stream.StartTime)
				var progress float64
				if us.stream.TotalSize > 0 {
					progress = float64(us.stream.Transferred) / float64(us.stream.TotalSize) * 100
				}
				log.Info("📊 Upload progress: %.1f%% (%d/%d bytes), elapsed: %v, timeout: %v",
					progress, us.stream.Transferred, us.stream.TotalSize, elapsed.Round(time.Second),
					dynamicTimeout.Round(time.Second))
				lastProgressTime = time.Now()
			}

			if isLastChunk {
				elapsed := time.Since(us.stream.StartTime)
				avgSpeed := float64(us.stream.Transferred) / elapsed.Seconds() / (1024 * 1024) // MB/s
				log.Info("✅ Upload stream completed: ID=%s, chunks=%d, size=%d bytes, time=%v, speed=%.2f MB/s",
					us.stream.ID, us.stream.ChunkIndex, us.stream.Transferred, elapsed.Round(time.Second), avgSpeed)
				return nil
			}
		}

		if err == io.EOF {
			// Handle EOF without data read in this iteration. The body ended
			// cleanly on a prior Read and this one returns (0, EOF). Send a
			// final IsLastChunk=true marker so the receiver closes its pipe
			// instead of waiting forever for the next chunk.
			if n == 0 {
				if sendErr := us.sendFinalUploadMarker(msgID); sendErr != nil {
					return fmt.Errorf("failed to send final upload marker: %v", sendErr)
				}
				log.Debug("🔚 Reached EOF, upload stream complete: ID=%s", us.stream.ID)
				return nil
			}
		} else if err != nil {
			// Check for timeout based on activity
			timeSinceActivity := currentTime.Sub(us.stream.LastActivity)
			if timeSinceActivity > dynamicTimeout {
				return fmt.Errorf("upload activity timeout exceeded (%.1fs since last data): %v",
					timeSinceActivity.Seconds(), err)
			} else {
				return fmt.Errorf("error reading upload data: %v", err)
			}
		}

		// Activity-based timeout detection
		timeSinceActivity := currentTime.Sub(us.stream.LastActivity)
		if timeSinceActivity > dynamicTimeout {
			return fmt.Errorf("no upload activity for %.1fs (timeout: %.1fs) - connection appears dead",
				timeSinceActivity.Seconds(), dynamicTimeout.Seconds())
		}
	}
}

// StreamToRequest streams upload chunks to an HTTP request body (agent-side)
func (us *UploadStreamer) StreamToRequest(uploadChan <-chan *common.Message, req *http.Request) error {
	log.Info("📤 Starting upload stream to request: ID=%s", us.stream.ID)

	// Create a pipe for streaming the request body
	pipeReader, pipeWriter := io.Pipe()
	req.Body = pipeReader

	// Start a goroutine to write chunks to the pipe
	go func() {
		// Close the stream (and its context) only when the goroutine exits, not
		// when StreamToRequest returns. Moving the close here prevents a race
		// where the context was cancelled immediately on function return, causing
		// ctx.Done() to fire in the select below when uploadChan was briefly empty.
		defer us.stream.Close()
		defer pipeWriter.Close()

		lastProgressTime := time.Now()
		timeoutConfig := common.DefaultTimeouts()

		for {
			// Calculate dynamic timeout
			timeoutDur := common.CalculateStreamingTimeout(us.stream.TotalSize, us.stream.Transferred, timeoutConfig)

			// Wait for next chunk
			select {
			case chunk, ok := <-uploadChan:
				if !ok {
					log.Info("📊 Upload stream completed: channel closed after %d chunks, %d bytes",
						us.stream.ChunkIndex, us.stream.Transferred)
					return
				}

				if chunk == nil || chunk.HTTP == nil {
					log.Debug("📄 Received nil upload chunk, ending stream")
					return
				}

				us.stream.ChunkIndex++
				chunkSize := int64(len(chunk.HTTP.Body))
				us.stream.UpdateProgress(us.stream.Transferred + chunkSize)

				// Write chunk data to pipe
				if _, err := pipeWriter.Write(chunk.HTTP.Body); err != nil {
					log.Error("❌ Failed to write upload chunk to pipe: %v", err)
					pipeWriter.CloseWithError(err)
					return
				}

				// Log progress
				now := time.Now()
				if now.Sub(lastProgressTime) > us.stream.Config.ProgressInterval || chunk.HTTP.IsLastChunk {
					progress := float64(us.stream.Transferred) / float64(us.stream.TotalSize) * 100
					elapsed := now.Sub(lastProgressTime)
					var rate float64
					if elapsed > 0 {
						rate = float64(chunkSize) / elapsed.Seconds() / (1024 * 1024) // MB/s
					}

					log.Info("📈 Upload streaming progress: %.1f%% (%d chunks, %d MB, %.2f MB/s)",
						progress, us.stream.ChunkIndex, us.stream.Transferred/(1024*1024), rate)
					lastProgressTime = now
				}

				// Check if this was the last chunk
				if chunk.HTTP.IsLastChunk {
					elapsed := time.Since(us.stream.StartTime)
					log.Info("✅ Upload streaming completed successfully: %d chunks, %d bytes total, time: %v",
						us.stream.ChunkIndex, us.stream.Transferred, elapsed.Round(time.Second))
					return
				}

			case <-time.After(timeoutDur):
				err := fmt.Errorf("timeout waiting for upload chunk %d after %v (received %d bytes)",
					us.stream.ChunkIndex+1, timeoutDur, us.stream.Transferred)
				log.Error("⏰ Upload timeout: %v", err)
				pipeWriter.CloseWithError(err)
				return

			case <-us.stream.Context.Done():
				err := fmt.Errorf("upload stream context cancelled")
				log.Info("🚫 Upload stream cancelled")
				pipeWriter.CloseWithError(err)
				return
			}
		}
	}()

	return nil
}

// StreamFromReader streams data from an io.Reader (utility function)
func (us *UploadStreamer) StreamFromReader(reader io.Reader, msgID string) error {
	defer us.stream.Close()

	log.Info("📤 Starting upload stream from reader: ID=%s", us.stream.ID)

	// Send initial upload stream message
	initialMsg := &common.Message{
		Type: "http_upload_start",
		ID:   msgID,
		HTTP: &common.HTTPData{
			IsStream:    true,
			ChunkSize:   us.stream.Config.ChunkSize,
			TotalSize:   us.stream.TotalSize,
			ChunkIndex:  0,
			IsLastChunk: false,
		},
	}

	if err := us.sender.SendMessage(initialMsg); err != nil {
		return fmt.Errorf("failed to send initial upload message: %v", err)
	}

	// Stream data in chunks
	buffer := make([]byte, us.stream.Config.ChunkSize)
	lastProgressTime := time.Now()

	for {
		// Read chunk from reader
		n, err := reader.Read(buffer)

		if n > 0 {
			// Update stream progress
			us.stream.ChunkIndex++
			us.stream.UpdateProgress(us.stream.Transferred + int64(n))

			// Check if this is the last chunk
			isLastChunk := (err == io.EOF)

			// Create chunk message
			chunkMsg := &common.Message{
				Type: "http_upload_chunk",
				ID:   msgID,
				HTTP: &common.HTTPData{
					Body:        buffer[:n],
					IsStream:    true,
					ChunkSize:   n,
					TotalSize:   us.stream.TotalSize,
					ChunkIndex:  us.stream.ChunkIndex,
					IsLastChunk: isLastChunk,
				},
			}

			// Send chunk
			if err := us.sender.SendMessage(chunkMsg); err != nil {
				return fmt.Errorf("failed to send upload chunk %d: %v", us.stream.ChunkIndex, err)
			}

			// Log progress periodically
			if time.Since(lastProgressTime) > us.stream.Config.ProgressInterval || isLastChunk {
				elapsed := time.Since(us.stream.StartTime)
				var progress float64
				if us.stream.TotalSize > 0 {
					progress = float64(us.stream.Transferred) / float64(us.stream.TotalSize) * 100
				}
				log.Info("📊 Upload progress: %.1f%% (%d/%d bytes), elapsed: %v",
					progress, us.stream.Transferred, us.stream.TotalSize, elapsed.Round(time.Second))
				lastProgressTime = time.Now()
			}

			if isLastChunk {
				elapsed := time.Since(us.stream.StartTime)
				avgSpeed := float64(us.stream.Transferred) / elapsed.Seconds() / (1024 * 1024) // MB/s
				log.Info("✅ Upload stream completed: ID=%s, chunks=%d, size=%d bytes, time=%v, speed=%.2f MB/s",
					us.stream.ID, us.stream.ChunkIndex, us.stream.Transferred, elapsed.Round(time.Second), avgSpeed)
				return nil
			}
		}

		if err == io.EOF {
			// Handle EOF without data read in this iteration. Send a final
			// IsLastChunk=true marker so the receiver closes its pipe.
			if n == 0 {
				if sendErr := us.sendFinalUploadMarker(msgID); sendErr != nil {
					return fmt.Errorf("failed to send final upload marker: %v", sendErr)
				}
				log.Debug("🔚 Reached EOF, upload stream complete: ID=%s", us.stream.ID)
				return nil
			}
		} else if err != nil {
			return fmt.Errorf("error reading upload data: %v", err)
		}
	}
}

// StreamFromReaderWithContext streams data from an io.Reader with HTTP context (server-side)
func (us *UploadStreamer) StreamFromReaderWithContext(reader io.Reader, msgID string, method string, url string, headers map[string][]string) error {
	defer us.stream.Close()

	log.Info("📤 Starting upload stream from reader with context: ID=%s, method=%s, url=%s", us.stream.ID, method, url)

	// Send initial upload stream message with HTTP context
	initialMsg := &common.Message{
		Type: "http_upload_start",
		ID:   msgID,
		HTTP: &common.HTTPData{
			Method:      method,
			URL:         url,
			Headers:     headers,
			IsStream:    true,
			ChunkSize:   us.stream.Config.ChunkSize,
			TotalSize:   us.stream.TotalSize,
			ChunkIndex:  0,
			IsLastChunk: false,
		},
	}

	if err := us.sender.SendMessage(initialMsg); err != nil {
		return fmt.Errorf("failed to send initial upload message: %v", err)
	}

	// Stream data in chunks
	buffer := make([]byte, us.stream.Config.ChunkSize)
	lastProgressTime := time.Now()

	for {
		// Read chunk from reader
		n, err := reader.Read(buffer)

		if n > 0 {
			// Update stream progress
			us.stream.ChunkIndex++
			us.stream.UpdateProgress(us.stream.Transferred + int64(n))

			// Check if this is the last chunk
			isLastChunk := (err == io.EOF)

			// Create chunk message
			chunkMsg := &common.Message{
				Type: "http_upload_chunk",
				ID:   msgID,
				HTTP: &common.HTTPData{
					Body:        buffer[:n],
					IsStream:    true,
					ChunkSize:   n,
					TotalSize:   us.stream.TotalSize,
					ChunkIndex:  us.stream.ChunkIndex,
					IsLastChunk: isLastChunk,
				},
			}

			// Send chunk
			if err := us.sender.SendMessage(chunkMsg); err != nil {
				return fmt.Errorf("failed to send upload chunk %d: %v", us.stream.ChunkIndex, err)
			}

			// Log progress periodically
			if time.Since(lastProgressTime) > us.stream.Config.ProgressInterval || isLastChunk {
				elapsed := time.Since(us.stream.StartTime)
				var progress float64
				if us.stream.TotalSize > 0 {
					progress = float64(us.stream.Transferred) / float64(us.stream.TotalSize) * 100
				}
				log.Info("📊 Upload progress: %.1f%% (%d/%d bytes), elapsed: %v",
					progress, us.stream.Transferred, us.stream.TotalSize, elapsed.Round(time.Second))
				lastProgressTime = time.Now()
			}

			if isLastChunk {
				elapsed := time.Since(us.stream.StartTime)
				avgSpeed := float64(us.stream.Transferred) / elapsed.Seconds() / (1024 * 1024) // MB/s
				log.Info("✅ Upload stream completed: ID=%s, chunks=%d, size=%d bytes, time=%v, speed=%.2f MB/s",
					us.stream.ID, us.stream.ChunkIndex, us.stream.Transferred, elapsed.Round(time.Second), avgSpeed)
				return nil
			}
		}

		if err == io.EOF {
			// Handle EOF without data read in this iteration. Send a final
			// IsLastChunk=true marker so the agent's pipe writer closes and
			// the upstream POST completes; otherwise the agent hangs waiting
			// for the next chunk and the client times out.
			if n == 0 {
				if sendErr := us.sendFinalUploadMarker(msgID); sendErr != nil {
					return fmt.Errorf("failed to send final upload marker: %v", sendErr)
				}
				log.Debug("🔚 Reached EOF, upload stream complete: ID=%s", us.stream.ID)
				return nil
			}
		} else if err != nil {
			return fmt.Errorf("error reading upload data: %v", err)
		}
	}
}

// sendFinalUploadMarker sends an empty http_upload_chunk with IsLastChunk=true
// so the receiver knows the upload is complete. Required when the source
// reader returns (0, io.EOF) without coalescing EOF with the final data read.
func (us *UploadStreamer) sendFinalUploadMarker(msgID string) error {
	us.stream.ChunkIndex++
	return us.sender.SendMessage(&common.Message{
		Type: "http_upload_chunk",
		ID:   msgID,
		HTTP: &common.HTTPData{
			IsStream:    true,
			ChunkSize:   0,
			TotalSize:   us.stream.TotalSize,
			ChunkIndex:  us.stream.ChunkIndex,
			IsLastChunk: true,
		},
	})
}

// ShouldStreamUpload determines if an upload should be streamed based on content length
func ShouldStreamUpload(contentLength int64) bool {
	// Only stream uploads if content length is known AND large (>1MB)
	// Don't stream if content length is unknown (-1) - handle normally
	return contentLength > 0 && contentLength > 1024*1024
}

// DetectUploadFromRequest analyzes an HTTP request to determine if it's a large upload
func DetectUploadFromRequest(req *http.Request) bool {
	// Check for large content length or chunked transfer encoding
	contentLength := req.ContentLength
	transferEncoding := req.Header.Get("Transfer-Encoding")

	// Only treat as upload if we know it's large or explicitly chunked
	// Don't assume unknown sizes are large uploads
	return (contentLength > 0 && contentLength > 1024*1024) || transferEncoding == "chunked"
}
