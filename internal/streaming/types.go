package streaming

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

// Direction represents the streaming direction
type Direction int

const (
	DirectionDownload Direction = iota
	DirectionUpload
)

// String returns string representation of Direction
func (d Direction) String() string {
	switch d {
	case DirectionDownload:
		return "download"
	case DirectionUpload:
		return "upload"
	default:
		return "unknown"
	}
}

// Config holds streaming configuration
type Config struct {
	ChunkSize        int           `json:"chunk_size"`        // Size of each chunk in bytes
	BufferSize       int           `json:"buffer_size"`       // Internal buffer size
	MaxTimeout       time.Duration `json:"max_timeout"`       // Maximum timeout for operations
	ProgressInterval time.Duration `json:"progress_interval"` // How often to log progress
	Direction        Direction     `json:"direction"`         // Streaming direction
}

// DefaultConfig returns default streaming configuration
func DefaultConfig() *Config {
	return &Config{
		ChunkSize:        32768,             // 32KB chunks
		BufferSize:       65536,             // 64KB buffer
		MaxTimeout:       10 * time.Minute,  // 10 minute max timeout
		ProgressInterval: 5 * time.Second,   // Progress every 5 seconds
		Direction:        DirectionDownload, // Default to download
	}
}

// DownloadConfig returns configuration optimized for downloads
func DownloadConfig() *Config {
	config := DefaultConfig()
	config.Direction = DirectionDownload
	config.ChunkSize = 32768 // 32KB for good throughput
	return config
}

// UploadConfig returns configuration optimized for uploads
func UploadConfig() *Config {
	config := DefaultConfig()
	config.Direction = DirectionUpload
	config.ChunkSize = 65536                  // 64KB for better upload throughput (increased from 16KB)
	config.ProgressInterval = 3 * time.Second // Balanced progress updates for uploads (reduced frequency)
	return config
}

// Stream represents a streaming operation
type Stream struct {
	ID           string               `json:"id"`
	Direction    Direction            `json:"direction"`
	TotalSize    int64                `json:"total_size"`
	Transferred  int64                `json:"transferred"`
	ChunkIndex   int                  `json:"chunk_index"`
	StartTime    time.Time            `json:"start_time"`
	LastActivity time.Time            `json:"last_activity"`
	Config       *Config              `json:"config"`
	Context      context.Context      `json:"-"`
	Cancel       context.CancelFunc   `json:"-"`
	MessageChan  chan *common.Message `json:"-"`
	ErrorChan    chan error           `json:"-"`
	ProgressChan chan *ProgressInfo   `json:"-"`

	// Thread-safe closing
	closeOnce sync.Once  `json:"-"`
	closed    bool       `json:"-"`
	closeMu   sync.Mutex `json:"-"`
}

// ProgressInfo contains progress information for a stream
type ProgressInfo struct {
	StreamID     string        `json:"stream_id"`
	Direction    Direction     `json:"direction"`
	TotalSize    int64         `json:"total_size"`
	Transferred  int64         `json:"transferred"`
	ChunkIndex   int           `json:"chunk_index"`
	Progress     float64       `json:"progress"`      // Percentage (0-100)
	TransferRate float64       `json:"transfer_rate"` // Bytes per second
	ETA          time.Duration `json:"eta"`           // Estimated time to completion
	Elapsed      time.Duration `json:"elapsed"`       // Time elapsed since start
}

// NewStream creates a new stream with the given configuration
func NewStream(id string, totalSize int64, config *Config) *Stream {
	if config == nil {
		config = DefaultConfig()
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.MaxTimeout)

	return &Stream{
		ID:           id,
		Direction:    config.Direction,
		TotalSize:    totalSize,
		Transferred:  0,
		ChunkIndex:   0,
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		Config:       config,
		Context:      ctx,
		Cancel:       cancel,
		MessageChan:  make(chan *common.Message, 100),
		ErrorChan:    make(chan error, 10),
		ProgressChan: make(chan *ProgressInfo, 50),
	}
}

// IsComplete returns true if the stream has transferred all data
func (s *Stream) IsComplete() bool {
	if s.TotalSize <= 0 {
		return false
	}
	return s.Transferred >= s.TotalSize
}

// UpdateProgress updates the stream's progress and sends progress info
func (s *Stream) UpdateProgress(transferred int64) {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return // Don't update progress on closed stream
	}
	s.closeMu.Unlock()

	s.Transferred = transferred
	s.LastActivity = time.Now()

	// Calculate progress percentage
	var progress float64
	if s.TotalSize > 0 {
		progress = float64(s.Transferred) / float64(s.TotalSize) * 100
	}

	// Calculate transfer rate
	elapsed := time.Since(s.StartTime)
	var transferRate float64
	if elapsed.Seconds() > 0 {
		transferRate = float64(s.Transferred) / elapsed.Seconds()
	}

	// Calculate ETA
	var eta time.Duration
	if transferRate > 0 && s.TotalSize > s.Transferred {
		remainingBytes := float64(s.TotalSize - s.Transferred)
		eta = time.Duration(remainingBytes/transferRate) * time.Second
	}

	progressInfo := &ProgressInfo{
		StreamID:     s.ID,
		Direction:    s.Direction,
		TotalSize:    s.TotalSize,
		Transferred:  s.Transferred,
		ChunkIndex:   s.ChunkIndex,
		Progress:     progress,
		TransferRate: transferRate,
		ETA:          eta,
		Elapsed:      elapsed,
	}

	// Send progress info non-blocking, with closed channel protection
	select {
	case s.ProgressChan <- progressInfo:
	default:
		// Channel full or closed, skip this progress update
	}
}

// Close closes the stream and cleans up resources
func (s *Stream) Close() {
	s.closeOnce.Do(func() {
		s.closeMu.Lock()
		defer s.closeMu.Unlock()

		if s.closed {
			return // Already closed
		}

		// Cancel context first
		if s.Cancel != nil {
			s.Cancel()
		}

		// Close channels safely
		if s.MessageChan != nil {
			close(s.MessageChan)
		}
		if s.ErrorChan != nil {
			close(s.ErrorChan)
		}
		if s.ProgressChan != nil {
			close(s.ProgressChan)
		}

		s.closed = true
	})
}

// IsClosed returns whether the stream has been closed
func (s *Stream) IsClosed() bool {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closed
}

// StreamReader wraps an io.Reader for streaming operations
type StreamReader struct {
	reader io.Reader
	stream *Stream
}

// NewStreamReader creates a new StreamReader
func NewStreamReader(reader io.Reader, stream *Stream) *StreamReader {
	return &StreamReader{
		reader: reader,
		stream: stream,
	}
}

// Read implements io.Reader interface with progress tracking
func (sr *StreamReader) Read(p []byte) (n int, err error) {
	n, err = sr.reader.Read(p)
	if n > 0 {
		sr.stream.UpdateProgress(sr.stream.Transferred + int64(n))
	}
	return n, err
}

// StreamWriter wraps an io.Writer for streaming operations
type StreamWriter struct {
	writer io.Writer
	stream *Stream
}

// NewStreamWriter creates a new StreamWriter
func NewStreamWriter(writer io.Writer, stream *Stream) *StreamWriter {
	return &StreamWriter{
		writer: writer,
		stream: stream,
	}
}

// Write implements io.Writer interface with progress tracking
func (sw *StreamWriter) Write(p []byte) (n int, err error) {
	n, err = sw.writer.Write(p)
	if n > 0 {
		sw.stream.UpdateProgress(sw.stream.Transferred + int64(n))
	}
	return n, err
}

// MessageSender defines interface for sending messages
type MessageSender interface {
	SendMessage(msg *common.Message) error
}

// ConnectionManager defines interface for managing network connections
type ConnectionManager interface {
	GetConnection() net.Conn
	IsConnected() bool
}
