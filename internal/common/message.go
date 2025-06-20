package common

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
)

// ServiceConfig represents the configuration for a service (simple format for backward compatibility)
type ServiceConfig struct {
	Hostname     string `json:"hostname"`
	Backend      string `json:"backend"`
	Protocol     string `json:"protocol"`
	WebSocket    bool   `json:"websocket,omitempty"`     // Enable WebSocket support
	HTTPRedirect bool   `json:"http_redirect,omitempty"` // Enable HTTP to HTTPS redirect
	ListenOn     string `json:"listen_on,omitempty"`     // Protocol binding: "http", "https", "both"
}

// EnhancedServiceConfig represents an enhanced service configuration
// This is a forward declaration to avoid circular imports
type EnhancedServiceConfig struct {
	ID             string                `json:"id"`
	Name           string                `json:"name,omitempty"`
	Hostname       string                `json:"hostname"`
	Protocol       string                `json:"protocol"`
	WebSocket      bool                  `json:"websocket,omitempty"`     // Enable WebSocket support
	HTTPRedirect   bool                  `json:"http_redirect,omitempty"` // Enable HTTP to HTTPS redirect
	ListenOn       string                `json:"listen_on,omitempty"`     // Protocol binding: "http", "https", "both"
	Upstreams      []UpstreamConfig      `json:"upstreams"`
	LoadBalancing  *LoadBalancingConfig  `json:"load_balancing,omitempty"`
	Routes         []RouteConfig         `json:"routes,omitempty"`
	TLS            *TLSConfig            `json:"tls,omitempty"`
	Security       *SecurityConfig       `json:"security,omitempty"`
	Monitoring     *MonitoringConfig     `json:"monitoring,omitempty"`
	TrafficShaping *TrafficShapingConfig `json:"traffic_shaping,omitempty"`
}

// Supporting structs for enhanced configuration
type UpstreamConfig struct {
	Address     string             `json:"address"`
	Weight      int                `json:"weight,omitempty"`
	HealthCheck *HealthCheckConfig `json:"health_check,omitempty"`
}

type HealthCheckConfig struct {
	Path     string            `json:"path,omitempty"`
	Interval string            `json:"interval,omitempty"`
	Timeout  string            `json:"timeout,omitempty"`
	Method   string            `json:"method,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

type LoadBalancingConfig struct {
	Policy              string `json:"policy"`
	HealthCheckRequired bool   `json:"health_check_required,omitempty"`
	SessionAffinity     bool   `json:"session_affinity,omitempty"`
	AffinityDuration    string `json:"affinity_duration,omitempty"`
}

type RouteConfig struct {
	Match  MatchConfig        `json:"match"`
	Handle []MiddlewareConfig `json:"handle"`
}

type MatchConfig struct {
	Path    string              `json:"path,omitempty"`
	Method  string              `json:"method,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Query   map[string]string   `json:"query,omitempty"`
}

type MiddlewareConfig struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config,omitempty"`
}

type TLSConfig struct {
	CertFile     string   `json:"cert_file,omitempty"`
	KeyFile      string   `json:"key_file,omitempty"`
	CAFile       string   `json:"ca_file,omitempty"`
	MinVersion   string   `json:"min_version,omitempty"`
	Ciphers      []string `json:"ciphers,omitempty"`
	ClientAuth   string   `json:"client_auth,omitempty"`
	ClientCAFile string   `json:"client_ca_file,omitempty"`
}

type SecurityConfig struct {
	CORS *CORSConfig `json:"cors,omitempty"`
	Auth *AuthConfig `json:"auth,omitempty"`
}

type CORSConfig struct {
	Origins []string `json:"origins,omitempty"`
	Methods []string `json:"methods,omitempty"`
	Headers []string `json:"headers,omitempty"`
}

type AuthConfig struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config,omitempty"`
}

type MonitoringConfig struct {
	MetricsEnabled bool           `json:"metrics_enabled,omitempty"`
	Logging        *LoggingConfig `json:"logging,omitempty"`
}

type LoggingConfig struct {
	Level  string   `json:"level,omitempty"`
	Format string   `json:"format,omitempty"`
	Fields []string `json:"fields,omitempty"`
}

type TrafficShapingConfig struct {
	UploadLimit   string `json:"upload_limit,omitempty"`
	DownloadLimit string `json:"download_limit,omitempty"`
	PerIPLimit    string `json:"per_ip_limit,omitempty"`
}

// Message represents a message sent between agent and server
type Message struct {
	Type            string                 `json:"type"`
	ID              string                 `json:"id,omitempty"`
	Service         *ServiceConfig         `json:"service,omitempty"`          // Simple service config (backward compatibility)
	EnhancedService *EnhancedServiceConfig `json:"enhanced_service,omitempty"` // Enhanced service config
	Error           string                 `json:"error,omitempty"`
	HTTP            *HTTPData              `json:"http,omitempty"`
}

// HTTPData represents HTTP request/response data
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

// StreamConfig represents configuration for streaming data
type StreamConfig struct {
	ChunkSize   int   `json:"chunk_size"`
	TotalSize   int64 `json:"total_size"`
	ChunkIndex  int   `json:"chunk_index"`
	IsLastChunk bool  `json:"is_last_chunk"`
}

// ReadMessage reads a message from a connection
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

// WriteMessage writes a message to a connection
func WriteMessage(conn net.Conn, msg *Message) error {
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(msg); err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}
	return nil
}
