package caddy

import (
	"sync"

	"github.com/devhatro/zero-trust-proxy/internal/agent"
)

// ServiceConfig represents a simple service configuration for Caddy
type ServiceConfig struct {
	Hostname     string `json:"hostname"`
	Backend      string `json:"backend"` // This is the server's internal API endpoint
	Protocol     string `json:"protocol"`
	WebSocket    bool   `json:"websocket,omitempty"`     // Enable WebSocket support with transparent passthrough
	HTTPRedirect bool   `json:"http_redirect,omitempty"` // Enable HTTP to HTTPS redirect
	ListenOn     string `json:"listen_on,omitempty"`     // Protocol binding: "http", "https", "both"
}

// Manager handles Caddy configuration with enhanced service support
type Manager struct {
	adminAPI         string
	mu               sync.RWMutex                    // Protects config and enhancedServices
	config           map[string]*ServiceConfig       // hostname -> simple service config
	enhancedServices map[string]*agent.ServiceConfig // hostname -> enhanced agent service config
	validator        *Validator                      // Server-side configuration validator
}

// ManagerConfig holds configuration for creating a new Manager
type ManagerConfig struct {
	AdminAPI string // Caddy admin API endpoint (e.g., "http://localhost:2019")
}

// ServiceStats represents statistics about configured services
type ServiceStats struct {
	TotalServices    int `json:"total_services"`
	HTTPSServices    int `json:"https_services"`
	HTTPServices     int `json:"http_services"`
	WebSocketEnabled int `json:"websocket_enabled"`
	RedirectEnabled  int `json:"redirect_enabled"`
}
