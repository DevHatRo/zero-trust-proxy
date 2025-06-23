package common

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// mockConnection implements net.Conn for testing
type mockConnection struct {
	*bytes.Buffer
	closed bool
}

func (m *mockConnection) Close() error {
	m.closed = true
	return nil
}

func (m *mockConnection) LocalAddr() net.Addr                { return nil }
func (m *mockConnection) RemoteAddr() net.Addr               { return nil }
func (m *mockConnection) SetDeadline(t time.Time) error      { return nil }
func (m *mockConnection) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConnection) SetWriteDeadline(t time.Time) error { return nil }

func newMockConnection(data string) *mockConnection {
	return &mockConnection{
		Buffer: bytes.NewBufferString(data),
		closed: false,
	}
}

// TestMessageSerialization tests basic message serialization
func TestMessageSerialization(t *testing.T) {
	tests := []struct {
		name string
		msg  *Message
	}{
		{
			name: "simple message",
			msg: &Message{
				Type: "test",
				ID:   "123",
			},
		},
		{
			name: "service config message",
			msg: &Message{
				Type: "service_add",
				ID:   "service1",
				Service: &ServiceConfig{
					Hostname:     "example.com",
					Backend:      "127.0.0.1:8080",
					Protocol:     "http",
					WebSocket:    true,
					HTTPRedirect: false,
					ListenOn:     "both",
				},
			},
		},
		{
			name: "enhanced service config message",
			msg: &Message{
				Type: "enhanced_service_add",
				ID:   "enhanced1",
				EnhancedService: &EnhancedServiceConfig{
					ID:           "svc1",
					Name:         "Test Service",
					Hostname:     "test.example.com",
					Protocol:     "https",
					WebSocket:    true,
					HTTPRedirect: true,
					ListenOn:     "https",
					Upstreams: []UpstreamConfig{
						{
							Address: "192.168.1.100:8080",
							Weight:  100,
							HealthCheck: &HealthCheckConfig{
								Path:     "/health",
								Interval: "30s",
								Timeout:  "5s",
								Method:   "GET",
								Headers:  map[string]string{"X-Health": "check"},
							},
						},
					},
					LoadBalancing: &LoadBalancingConfig{
						Policy:              "round_robin",
						HealthCheckRequired: true,
						SessionAffinity:     false,
					},
					Routes: []RouteConfig{
						{
							Match: MatchConfig{
								Path:   "/api/*",
								Method: "GET",
								Headers: map[string][]string{
									"Accept": {"application/json"},
								},
								Query: map[string]string{
									"version": "v1",
								},
							},
							Handle: []MiddlewareConfig{
								{
									Type: "headers",
									Config: map[string]interface{}{
										"set": map[string]string{
											"X-API-Version": "v1",
										},
									},
								},
							},
						},
					},
					TLS: &TLSConfig{
						MinVersion: "1.2",
						Ciphers:    []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
						ClientAuth: "require",
					},
					Security: &SecurityConfig{
						CORS: &CORSConfig{
							Origins: []string{"https://example.com"},
							Methods: []string{"GET", "POST"},
							Headers: []string{"Content-Type", "Authorization"},
						},
						Auth: &AuthConfig{
							Type: "jwt",
							Config: map[string]interface{}{
								"secret": "test-secret",
								"issuer": "test-issuer",
							},
						},
					},
					Monitoring: &MonitoringConfig{
						MetricsEnabled: true,
						Logging: &LoggingConfig{
							Level:  "info",
							Format: "json",
							Fields: []string{"timestamp", "level", "message"},
						},
					},
					TrafficShaping: &TrafficShapingConfig{
						UploadLimit:   "10MB/s",
						DownloadLimit: "100MB/s",
						PerIPLimit:    "1MB/s",
					},
				},
			},
		},
		{
			name: "http request message",
			msg: &Message{
				Type: "http_request",
				ID:   "req1",
				HTTP: &HTTPData{
					Method: "POST",
					URL:    "https://api.example.com/users",
					Headers: map[string][]string{
						"Content-Type":  {"application/json"},
						"Authorization": {"Bearer token123"},
					},
					Body: []byte(`{"name":"John","email":"john@example.com"}`),
				},
			},
		},
		{
			name: "http response message",
			msg: &Message{
				Type: "http_response",
				ID:   "resp1",
				HTTP: &HTTPData{
					StatusCode:    200,
					StatusMessage: "OK",
					Headers: map[string][]string{
						"Content-Type": {"application/json"},
						"X-Rate-Limit": {"100"},
					},
					Body: []byte(`{"id":123,"name":"John","email":"john@example.com"}`),
				},
			},
		},
		{
			name: "streaming http message",
			msg: &Message{
				Type: "http_response",
				ID:   "stream1",
				HTTP: &HTTPData{
					StatusCode:    200,
					StatusMessage: "OK",
					Headers: map[string][]string{
						"Content-Type":      {"text/plain"},
						"Transfer-Encoding": {"chunked"},
					},
					Body:        []byte("chunk data here"),
					IsStream:    true,
					ChunkSize:   1024,
					TotalSize:   10240,
					ChunkIndex:  5,
					IsLastChunk: false,
				},
			},
		},
		{
			name: "websocket message",
			msg: &Message{
				Type: "http_request",
				ID:   "ws1",
				HTTP: &HTTPData{
					Method: "GET",
					URL:    "wss://websocket.example.com/chat",
					Headers: map[string][]string{
						"Upgrade":           {"websocket"},
						"Connection":        {"Upgrade"},
						"Sec-WebSocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="},
					},
					IsWebSocket: true,
				},
			},
		},
		{
			name: "error message",
			msg: &Message{
				Type:  "error",
				ID:    "err1",
				Error: "Failed to connect to upstream server",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize to JSON
			data, err := json.Marshal(tt.msg)
			if err != nil {
				t.Fatalf("failed to marshal message: %v", err)
			}

			// Deserialize back
			var decoded Message
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal message: %v", err)
			}

			// Basic comparisons
			if decoded.Type != tt.msg.Type {
				t.Errorf("expected type %s, got %s", tt.msg.Type, decoded.Type)
			}
			if decoded.ID != tt.msg.ID {
				t.Errorf("expected ID %s, got %s", tt.msg.ID, decoded.ID)
			}
			if decoded.Error != tt.msg.Error {
				t.Errorf("expected error %s, got %s", tt.msg.Error, decoded.Error)
			}

			// Verify service config if present
			if tt.msg.Service != nil {
				if decoded.Service == nil {
					t.Fatal("service config was lost during serialization")
				}
				if decoded.Service.Hostname != tt.msg.Service.Hostname {
					t.Errorf("expected hostname %s, got %s", tt.msg.Service.Hostname, decoded.Service.Hostname)
				}
			}

			// Verify HTTP data if present
			if tt.msg.HTTP != nil {
				if decoded.HTTP == nil {
					t.Fatal("HTTP data was lost during serialization")
				}
				if decoded.HTTP.Method != tt.msg.HTTP.Method {
					t.Errorf("expected method %s, got %s", tt.msg.HTTP.Method, decoded.HTTP.Method)
				}
				if decoded.HTTP.StatusCode != tt.msg.HTTP.StatusCode {
					t.Errorf("expected status code %d, got %d", tt.msg.HTTP.StatusCode, decoded.HTTP.StatusCode)
				}
				if !bytes.Equal(decoded.HTTP.Body, tt.msg.HTTP.Body) {
					t.Errorf("HTTP body mismatch")
				}
			}
		})
	}
}

// TestReadMessage tests reading messages from connections
func TestReadMessage(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		expectedMsg *Message
	}{
		{
			name:        "valid simple message",
			input:       `{"type":"test","id":"123"}`,
			expectError: false,
			expectedMsg: &Message{Type: "test", ID: "123"},
		},
		{
			name:        "valid service message",
			input:       `{"type":"service_add","service":{"hostname":"example.com","backend":"127.0.0.1:8080","protocol":"http"}}`,
			expectError: false,
			expectedMsg: &Message{
				Type: "service_add",
				Service: &ServiceConfig{
					Hostname: "example.com",
					Backend:  "127.0.0.1:8080",
					Protocol: "http",
				},
			},
		},
		{
			name:        "empty input",
			input:       "",
			expectError: true,
		},
		{
			name:        "invalid json",
			input:       `{"type":"test","id":}`,
			expectError: true,
		},
		{
			name:        "malformed json",
			input:       `not json at all`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newMockConnection(tt.input)
			var msg Message

			err := ReadMessage(conn, &msg)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if msg.Type != tt.expectedMsg.Type {
				t.Errorf("expected type %s, got %s", tt.expectedMsg.Type, msg.Type)
			}
			if msg.ID != tt.expectedMsg.ID {
				t.Errorf("expected ID %s, got %s", tt.expectedMsg.ID, msg.ID)
			}

			if tt.expectedMsg.Service != nil {
				if msg.Service == nil {
					t.Fatal("expected service config but got nil")
				}
				if msg.Service.Hostname != tt.expectedMsg.Service.Hostname {
					t.Errorf("expected hostname %s, got %s", tt.expectedMsg.Service.Hostname, msg.Service.Hostname)
				}
			}
		})
	}
}

// TestWriteMessage tests writing messages to connections
func TestWriteMessage(t *testing.T) {
	tests := []struct {
		name string
		msg  *Message
	}{
		{
			name: "simple message",
			msg:  &Message{Type: "test", ID: "123"},
		},
		{
			name: "service message",
			msg: &Message{
				Type: "service_add",
				Service: &ServiceConfig{
					Hostname: "example.com",
					Backend:  "127.0.0.1:8080",
					Protocol: "http",
				},
			},
		},
		{
			name: "http message",
			msg: &Message{
				Type: "http_request",
				HTTP: &HTTPData{
					Method: "GET",
					URL:    "https://api.example.com/test",
					Headers: map[string][]string{
						"User-Agent": {"zero-trust-proxy/1.0"},
					},
					Body: []byte("test body"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newMockConnection("")

			err := WriteMessage(conn, tt.msg)
			if err != nil {
				t.Fatalf("failed to write message: %v", err)
			}

			// Read back the written data
			var readBack Message
			err = ReadMessage(conn, &readBack)
			if err != nil {
				t.Fatalf("failed to read back message: %v", err)
			}

			if readBack.Type != tt.msg.Type {
				t.Errorf("expected type %s, got %s", tt.msg.Type, readBack.Type)
			}
			if readBack.ID != tt.msg.ID {
				t.Errorf("expected ID %s, got %s", tt.msg.ID, readBack.ID)
			}
		})
	}
}

// TestMessageRoundTrip tests complete message round trip
func TestMessageRoundTrip(t *testing.T) {
	originalMsg := &Message{
		Type: "service_update",
		ID:   "update-123",
		Service: &ServiceConfig{
			Hostname:     "api.example.com",
			Backend:      "192.168.1.100:8080",
			Protocol:     "https",
			WebSocket:    true,
			HTTPRedirect: true,
			ListenOn:     "both",
		},
		HTTP: &HTTPData{
			Method: "PUT",
			URL:    "https://api.example.com/services/update",
			Headers: map[string][]string{
				"Content-Type":  {"application/json"},
				"Authorization": {"Bearer xyz789"},
			},
			Body:        []byte(`{"enabled":true,"version":"2.0"}`),
			StatusCode:  200,
			IsStream:    false,
			IsWebSocket: false,
		},
	}

	// Write message
	conn := newMockConnection("")
	err := WriteMessage(conn, originalMsg)
	if err != nil {
		t.Fatalf("failed to write message: %v", err)
	}

	// Read message back
	var receivedMsg Message
	err = ReadMessage(conn, &receivedMsg)
	if err != nil {
		t.Fatalf("failed to read message: %v", err)
	}

	// Verify all fields
	if receivedMsg.Type != originalMsg.Type {
		t.Errorf("type mismatch: expected %s, got %s", originalMsg.Type, receivedMsg.Type)
	}
	if receivedMsg.ID != originalMsg.ID {
		t.Errorf("ID mismatch: expected %s, got %s", originalMsg.ID, receivedMsg.ID)
	}

	// Verify service config
	if receivedMsg.Service.Hostname != originalMsg.Service.Hostname {
		t.Errorf("hostname mismatch: expected %s, got %s", originalMsg.Service.Hostname, receivedMsg.Service.Hostname)
	}
	if receivedMsg.Service.WebSocket != originalMsg.Service.WebSocket {
		t.Errorf("websocket mismatch: expected %v, got %v", originalMsg.Service.WebSocket, receivedMsg.Service.WebSocket)
	}

	// Verify HTTP data
	if receivedMsg.HTTP.Method != originalMsg.HTTP.Method {
		t.Errorf("method mismatch: expected %s, got %s", originalMsg.HTTP.Method, receivedMsg.HTTP.Method)
	}
	if !bytes.Equal(receivedMsg.HTTP.Body, originalMsg.HTTP.Body) {
		t.Errorf("body mismatch: expected %s, got %s", string(originalMsg.HTTP.Body), string(receivedMsg.HTTP.Body))
	}
}

// TestStreamConfig tests streaming configuration
func TestStreamConfig(t *testing.T) {
	config := StreamConfig{
		ChunkSize:   1024,
		TotalSize:   10240,
		ChunkIndex:  5,
		IsLastChunk: false,
	}

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal stream config: %v", err)
	}

	var decoded StreamConfig
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal stream config: %v", err)
	}

	if decoded.ChunkSize != config.ChunkSize {
		t.Errorf("chunk size mismatch: expected %d, got %d", config.ChunkSize, decoded.ChunkSize)
	}
	if decoded.TotalSize != config.TotalSize {
		t.Errorf("total size mismatch: expected %d, got %d", config.TotalSize, decoded.TotalSize)
	}
	if decoded.ChunkIndex != config.ChunkIndex {
		t.Errorf("chunk index mismatch: expected %d, got %d", config.ChunkIndex, decoded.ChunkIndex)
	}
	if decoded.IsLastChunk != config.IsLastChunk {
		t.Errorf("is last chunk mismatch: expected %v, got %v", config.IsLastChunk, decoded.IsLastChunk)
	}
}

// TestMessageTypes tests various message type scenarios
func TestMessageTypes(t *testing.T) {
	messageTypes := []string{
		"service_add",
		"service_remove",
		"service_update",
		"enhanced_service_add",
		"enhanced_service_remove",
		"enhanced_service_update",
		"http_request",
		"http_response",
		"websocket_upgrade",
		"heartbeat",
		"error",
		"status",
	}

	for _, msgType := range messageTypes {
		t.Run(msgType, func(t *testing.T) {
			msg := &Message{
				Type: msgType,
				ID:   "test-" + msgType,
			}

			// Add appropriate data based on message type
			switch msgType {
			case "service_add", "service_remove", "service_update":
				msg.Service = &ServiceConfig{
					Hostname: "test.example.com",
					Backend:  "127.0.0.1:8080",
					Protocol: "http",
				}
			case "enhanced_service_add", "enhanced_service_remove", "enhanced_service_update":
				msg.EnhancedService = &EnhancedServiceConfig{
					ID:       "test-service",
					Hostname: "enhanced.example.com",
					Protocol: "https",
					Upstreams: []UpstreamConfig{
						{Address: "192.168.1.100:8080", Weight: 100},
					},
				}
			case "http_request", "http_response":
				msg.HTTP = &HTTPData{
					Method: "GET",
					URL:    "https://test.example.com/api",
					Headers: map[string][]string{
						"User-Agent": {"test"},
					},
				}
				if msgType == "http_response" {
					msg.HTTP.StatusCode = 200
					msg.HTTP.StatusMessage = "OK"
				}
			case "error":
				msg.Error = "Test error message"
			}

			// Test serialization round trip
			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("failed to marshal %s message: %v", msgType, err)
			}

			var decoded Message
			err = json.Unmarshal(data, &decoded)
			if err != nil {
				t.Fatalf("failed to unmarshal %s message: %v", msgType, err)
			}

			if decoded.Type != msg.Type {
				t.Errorf("type mismatch for %s: expected %s, got %s", msgType, msg.Type, decoded.Type)
			}
		})
	}
}

// BenchmarkMessageSerialization benchmarks message serialization
func BenchmarkMessageSerialization(b *testing.B) {
	msg := &Message{
		Type: "http_request",
		ID:   "benchmark-test",
		HTTP: &HTTPData{
			Method: "POST",
			URL:    "https://api.example.com/data",
			Headers: map[string][]string{
				"Content-Type":  {"application/json"},
				"Authorization": {"Bearer token123"},
			},
			Body: []byte(`{"data":"benchmark test data for performance testing"}`),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(msg)
		if err != nil {
			b.Fatalf("marshal failed: %v", err)
		}
	}
}

// BenchmarkMessageDeserialization benchmarks message deserialization
func BenchmarkMessageDeserialization(b *testing.B) {
	msg := &Message{
		Type: "http_request",
		ID:   "benchmark-test",
		HTTP: &HTTPData{
			Method: "POST",
			URL:    "https://api.example.com/data",
			Headers: map[string][]string{
				"Content-Type":  {"application/json"},
				"Authorization": {"Bearer token123"},
			},
			Body: []byte(`{"data":"benchmark test data for performance testing"}`),
		},
	}

	data, _ := json.Marshal(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var decoded Message
		err := json.Unmarshal(data, &decoded)
		if err != nil {
			b.Fatalf("unmarshal failed: %v", err)
		}
	}
}
