package common

import (
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/devhatro/zero-trust-proxy/internal/types"
)

// ServiceConfig represents a service configuration over the wire.
// Wraps types.ServiceConfig so the protocol struct lives next to the
// other JSON-encoded message types.
type ServiceConfig struct {
	types.ServiceConfig
}

// NewServiceConfig wraps a types.ServiceConfig.
func NewServiceConfig(typesConfig *types.ServiceConfig) *ServiceConfig {
	return &ServiceConfig{ServiceConfig: *typesConfig}
}

// ToTypes returns the underlying types.ServiceConfig.
func (sc *ServiceConfig) ToTypes() *types.ServiceConfig {
	return &sc.ServiceConfig
}

// Message is the on-wire envelope for every agent ⟷ server message.
// Each message carries a UUID `id` that multiplexes concurrent
// requests over the single agent connection.
type Message struct {
	Type    string         `json:"type"`
	ID      string         `json:"id,omitempty"`
	Service *ServiceConfig `json:"service,omitempty"`
	Error   string         `json:"error,omitempty"`
	HTTP    *HTTPData      `json:"http,omitempty"`
}

// HTTPData represents HTTP request/response data.
type HTTPData struct {
	Method        string              `json:"method"`
	URL           string              `json:"url"`
	Headers       map[string][]string `json:"headers"`
	Body          []byte              `json:"body"`
	StatusCode    int                 `json:"status_code,omitempty"`
	StatusMessage string              `json:"status_message,omitempty"`
	IsStream      bool                `json:"is_stream,omitempty"`
	IsWebSocket   bool                `json:"is_websocket,omitempty"`
	ChunkSize     int                 `json:"chunk_size,omitempty"`
	TotalSize     int64               `json:"total_size,omitempty"`
	ChunkIndex    int                 `json:"chunk_index,omitempty"`
	IsLastChunk   bool                `json:"is_last_chunk,omitempty"`
}

// StreamConfig represents configuration for streaming data.
type StreamConfig struct {
	ChunkSize   int   `json:"chunk_size"`
	TotalSize   int64 `json:"total_size"`
	ChunkIndex  int   `json:"chunk_index"`
	IsLastChunk bool  `json:"is_last_chunk"`
}

// ReadMessage reads a message from a connection.
func ReadMessage(conn net.Conn, msg *Message) error {
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(msg); err != nil {
		if err == io.EOF {
			return fmt.Errorf("connection closed")
		}
		return fmt.Errorf("failed to decode message: %w", err)
	}
	return nil
}

// WriteMessage writes a message to a connection.
func WriteMessage(conn net.Conn, msg *Message) error {
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(msg); err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}
	return nil
}
