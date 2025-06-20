package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"gopkg.in/yaml.v3"
)

// Enhanced configuration structures supporting Caddy-style features

// AgentConfig represents the complete agent configuration
type AgentConfig struct {
	ConfigPath       string                 `yaml:"-"` // File path for hot reload (not serialized)
	Agent            AgentSettings          `yaml:"agent"`
	Server           ServerConfig           `yaml:"server"`
	Services         []ServiceConfig        `yaml:"services"`
	GlobalMiddleware []MiddlewareConfig     `yaml:"global_middleware,omitempty"`
	HealthChecks     HealthCheckSettings    `yaml:"health_checks,omitempty"`
	HotReload        common.HotReloadConfig `yaml:"hot_reload,omitempty"`
	LogLevel         string                 `yaml:"log_level,omitempty"`
}

// ServerConfig contains server connection configuration
type ServerConfig struct {
	Address string `yaml:"address"`
	CACert  string `yaml:"ca_cert"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

// AgentSettings contains global agent configuration
type AgentSettings struct {
	ID     string   `yaml:"id"`
	Name   string   `yaml:"name,omitempty"`
	Region string   `yaml:"region,omitempty"`
	Tags   []string `yaml:"tags,omitempty"`
}

// ServiceConfig represents an enhanced service configuration
type ServiceConfig struct {
	ID             string                `yaml:"id" json:"id"`
	Name           string                `yaml:"name" json:"name"`
	Hostname       string                `yaml:"hostname,omitempty" json:"hostname,omitempty"` // Backward compatibility - single hostname
	Hosts          []string              `yaml:"hosts,omitempty" json:"hosts,omitempty"`       // New: multiple hostnames support
	Protocol       string                `yaml:"protocol" json:"protocol"`
	WebSocket      bool                  `yaml:"websocket,omitempty" json:"websocket,omitempty"`         // Enable WebSocket support
	HTTPRedirect   bool                  `yaml:"http_redirect,omitempty" json:"http_redirect,omitempty"` // Enable HTTP to HTTPS redirect
	ListenOn       string                `yaml:"listen_on,omitempty" json:"listen_on,omitempty"`         // Protocol binding: "http", "https", "both" (default: "both")
	Upstreams      []UpstreamConfig      `yaml:"upstreams" json:"upstreams"`
	LoadBalancing  *LoadBalancingConfig  `yaml:"load_balancing,omitempty" json:"load_balancing,omitempty"`
	Routes         []RouteConfig         `yaml:"routes,omitempty" json:"routes,omitempty"`
	TLS            *TLSConfig            `yaml:"tls,omitempty" json:"tls,omitempty"`
	Security       *SecurityConfig       `yaml:"security,omitempty" json:"security,omitempty"`
	Monitoring     *MonitoringConfig     `yaml:"monitoring,omitempty" json:"monitoring,omitempty"`
	TrafficShaping *TrafficShapingConfig `yaml:"traffic_shaping,omitempty"`
}

// UpstreamConfig represents a backend server
type UpstreamConfig struct {
	Address     string             `yaml:"address"`
	Weight      int                `yaml:"weight,omitempty"`
	HealthCheck *HealthCheckConfig `yaml:"health_check,omitempty"`
}

// HealthCheckConfig represents health check settings for an upstream
type HealthCheckConfig struct {
	Path     string            `yaml:"path,omitempty"`
	Interval time.Duration     `yaml:"interval,omitempty"`
	Timeout  time.Duration     `yaml:"timeout,omitempty"`
	Method   string            `yaml:"method,omitempty"`
	Headers  map[string]string `yaml:"headers,omitempty"`
}

// LoadBalancingConfig represents load balancing settings
type LoadBalancingConfig struct {
	Policy              string        `yaml:"policy"` // round_robin, least_conn, ip_hash, weighted_round_robin
	HealthCheckRequired bool          `yaml:"health_check_required,omitempty"`
	SessionAffinity     bool          `yaml:"session_affinity,omitempty"`
	AffinityDuration    time.Duration `yaml:"affinity_duration,omitempty"`
}

// RouteConfig represents routing rules with match conditions and handlers
type RouteConfig struct {
	Match  MatchConfig        `yaml:"match"`
	Handle []MiddlewareConfig `yaml:"handle"`
}

// MatchConfig represents route matching conditions
type MatchConfig struct {
	Path    string              `yaml:"path,omitempty"`
	Method  string              `yaml:"method,omitempty"`
	Headers map[string][]string `yaml:"headers,omitempty"`
	Query   map[string]string   `yaml:"query,omitempty"`
}

// MiddlewareConfig represents middleware configuration
type MiddlewareConfig struct {
	Type   string                 `yaml:"type"`
	Config map[string]interface{} `yaml:"config,omitempty"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	CertFile     string   `yaml:"cert_file,omitempty"`
	KeyFile      string   `yaml:"key_file,omitempty"`
	CAFile       string   `yaml:"ca_file,omitempty"`
	MinVersion   string   `yaml:"min_version,omitempty"`
	Ciphers      []string `yaml:"ciphers,omitempty"`
	ClientAuth   string   `yaml:"client_auth,omitempty"`
	ClientCAFile string   `yaml:"client_ca_file,omitempty"`
}

// SecurityConfig represents security middleware settings
type SecurityConfig struct {
	CORS *CORSConfig `yaml:"cors,omitempty"`
	Auth *AuthConfig `yaml:"auth,omitempty"`
}

// CORSConfig represents CORS configuration
type CORSConfig struct {
	Origins []string `yaml:"origins,omitempty"`
	Methods []string `yaml:"methods,omitempty"`
	Headers []string `yaml:"headers,omitempty"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Type   string                 `yaml:"type"`
	Config map[string]interface{} `yaml:"config,omitempty"`
}

// MonitoringConfig represents monitoring and observability settings
type MonitoringConfig struct {
	MetricsEnabled bool     `yaml:"metrics_enabled,omitempty"`
	LoggingFormat  string   `yaml:"logging_format,omitempty"`
	LoggingFields  []string `yaml:"logging_fields,omitempty"`
}

// TrafficShapingConfig represents bandwidth limiting
type TrafficShapingConfig struct {
	UploadLimit   string `yaml:"upload_limit,omitempty"`
	DownloadLimit string `yaml:"download_limit,omitempty"`
	PerIPLimit    string `yaml:"per_ip_limit,omitempty"`
}

// HealthCheckSettings represents global health check configuration
type HealthCheckSettings struct {
	GlobalSettings HealthCheckGlobalSettings `yaml:"global_settings"`
	Endpoints      []HealthCheckEndpoint     `yaml:"endpoints,omitempty"`
}

// HealthCheckGlobalSettings represents global health check settings
type HealthCheckGlobalSettings struct {
	CheckInterval      time.Duration `yaml:"check_interval,omitempty"`
	Timeout            time.Duration `yaml:"timeout,omitempty"`
	UnhealthyThreshold int           `yaml:"unhealthy_threshold,omitempty"`
	HealthyThreshold   int           `yaml:"healthy_threshold,omitempty"`
}

// HealthCheckEndpoint represents a health check endpoint
type HealthCheckEndpoint struct {
	Path     string `yaml:"path"`
	Response string `yaml:"response"`
}

// LoadConfig loads the enhanced agent configuration from a file
func LoadConfig(configPath string) (*AgentConfig, error) {
	// Ensure the config directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Read the config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default config if it doesn't exist
			config := createDefaultConfig()
			config.ConfigPath = configPath // Set the config path
			if err := SaveConfig(configPath, config); err != nil {
				return nil, fmt.Errorf("failed to create default config: %w", err)
			}
			return config, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse the config
	var config AgentConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set the config path (not part of YAML)
	config.ConfigPath = configPath

	// Validate and apply defaults
	if err := validateAndApplyDefaults(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// SaveConfig saves the agent configuration to a file
func SaveConfig(configPath string, config *AgentConfig) error {
	// Marshal the config
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write the config file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// createDefaultConfig creates a minimal default configuration
// Environment variables supported:
// - ZERO_TRUST_SERVER: Full server address (e.g., "server.example.com:9443")
// - SERVER_ADDRESS: Alternative server address if ZERO_TRUST_SERVER not set
// - SERVER_PORT: Port number to use with localhost (default: 8443)
func createDefaultConfig() *AgentConfig {
	// Use environment variable for server address, with flexible defaults
	serverAddr := os.Getenv("ZERO_TRUST_SERVER")
	if serverAddr == "" {
		// Default to common server addresses (don't hardcode port 8443)
		serverAddr = os.Getenv("SERVER_ADDRESS")
		if serverAddr == "" {
			// Use localhost with a configurable port
			port := os.Getenv("SERVER_PORT")
			if port == "" {
				port = "8443" // Default port if nothing is configured
			}
			serverAddr = fmt.Sprintf("localhost:%s", port)
		}
	}

	return &AgentConfig{
		Agent: AgentSettings{
			ID:   "default-agent",
			Name: "Default Agent",
		},
		Server: ServerConfig{
			Address: serverAddr,
			CACert:  "/config/certs/ca.crt",
			Cert:    "/config/certs/agent.crt",
			Key:     "/config/certs/agent.key",
		},
		LogLevel: "INFO",
		Services: []ServiceConfig{}, // No default services - user should configure their own
	}
}

// validateAndApplyDefaults validates the configuration and applies default values
func validateAndApplyDefaults(config *AgentConfig) error {
	// Validate agent settings
	if config.Agent.ID == "" {
		return fmt.Errorf("agent.id is required")
	}

	// Validate services
	for i, service := range config.Services {
		if service.ID == "" {
			return fmt.Errorf("services[%d].id is required", i)
		}

		// Check that at least one host is defined (backward compatibility)
		allHosts := service.GetAllHosts()
		if len(allHosts) == 0 {
			return fmt.Errorf("services[%d] must have at least one host defined (use 'hostname' or 'hosts')", i)
		}

		if len(service.Upstreams) == 0 {
			return fmt.Errorf("services[%d] must have at least one upstream", i)
		}

		// Apply defaults
		if service.Protocol == "" {
			config.Services[i].Protocol = "http"
		}

		// Apply default for ListenOn first
		if service.ListenOn == "" {
			config.Services[i].ListenOn = "both" // Default to listening on both HTTP and HTTPS
		}

		// Apply default for HTTPRedirect (security-first: redirect HTTP to HTTPS by default)
		// Only enable redirect if the service listens on both protocols or HTTPS-only with fallback
		if config.Services[i].ListenOn == "both" {
			config.Services[i].HTTPRedirect = true // Default to redirecting HTTP to HTTPS for security
		}
		// Note: For "http" only services, HTTPRedirect stays false (no HTTPS to redirect to)
		// Note: For "https" only services, HTTPRedirect doesn't matter (no HTTP listener)

		// Validate ListenOn values
		validListenOn := map[string]bool{
			"http":  true,
			"https": true,
			"both":  true,
		}
		if !validListenOn[config.Services[i].ListenOn] {
			return fmt.Errorf("services[%d].listen_on must be 'http', 'https', or 'both' (got: %s)", i, config.Services[i].ListenOn)
		}

		// Validate HTTPRedirect configuration
		if config.Services[i].HTTPRedirect && config.Services[i].ListenOn == "http" {
			return fmt.Errorf("services[%d].http_redirect cannot be true when listen_on is 'http' (no HTTPS listener to redirect to)", i)
		}

		// Apply default weights if not set
		for j, upstream := range service.Upstreams {
			if upstream.Weight == 0 {
				config.Services[i].Upstreams[j].Weight = 100
			}
		}

		// Apply default route if none specified
		if len(service.Routes) == 0 {
			config.Services[i].Routes = []RouteConfig{createDefaultRoute()}
		}
	}

	return nil
}

// AddService adds a service to the configuration
func (c *AgentConfig) AddService(service ServiceConfig) error {
	// Check for duplicate service hosts
	newHosts := service.GetAllHosts()
	for _, newHost := range newHosts {
		for _, existingService := range c.Services {
			for _, existingHost := range existingService.GetAllHosts() {
				if existingHost == newHost {
					return fmt.Errorf("service with host %s already exists (service ID: %s)", newHost, existingService.ID)
				}
			}
		}
	}

	c.Services = append(c.Services, service)
	return nil
}

// RemoveService removes a service from the configuration
func (c *AgentConfig) RemoveService(hostname string) error {
	for i, s := range c.Services {
		// Check if the hostname matches any of the service's hosts
		for _, host := range s.GetAllHosts() {
			if host == hostname {
				c.Services = append(c.Services[:i], c.Services[i+1:]...)
				return nil
			}
		}
	}
	return fmt.Errorf("service with host %s not found", hostname)
}

// GetService returns a service by hostname
func (c *AgentConfig) GetService(hostname string) (*ServiceConfig, error) {
	for _, s := range c.Services {
		// Check if the hostname matches any of the service's hosts
		for _, host := range s.GetAllHosts() {
			if host == hostname {
				return &s, nil
			}
		}
	}
	return nil, fmt.Errorf("service with host %s not found", hostname)
}

// GetServiceByID returns a service by ID
func (c *AgentConfig) GetServiceByID(id string) (*ServiceConfig, error) {
	for _, s := range c.Services {
		if s.ID == id {
			return &s, nil
		}
	}
	return nil, fmt.Errorf("service with ID %s not found", id)
}

// UpdateService updates an existing service configuration
func (c *AgentConfig) UpdateService(hostname string, service ServiceConfig) error {
	for i, s := range c.Services {
		// Check if the hostname matches any of the service's hosts
		for _, host := range s.GetAllHosts() {
			if host == hostname {
				// Preserve the service ID when updating
				service.ID = s.ID
				c.Services[i] = service
				return nil
			}
		}
	}
	return fmt.Errorf("service with host %s not found", hostname)
}

// Validate performs comprehensive configuration validation
func (c *AgentConfig) Validate() error {
	return validateAndApplyDefaults(c)
}

// GetAllHosts returns all hosts for this service (combines hostname and hosts for backward compatibility)
func (s *ServiceConfig) GetAllHosts() []string {
	var allHosts []string

	// Add deprecated hostname field if present
	if s.Hostname != "" {
		allHosts = append(allHosts, s.Hostname)
	}

	// Add new hosts array
	allHosts = append(allHosts, s.Hosts...)

	// Remove duplicates
	seen := make(map[string]bool)
	var unique []string
	for _, host := range allHosts {
		if host != "" && !seen[host] {
			seen[host] = true
			unique = append(unique, host)
		}
	}

	return unique
}

// GetPrimaryHost returns the primary host for this service (for backward compatibility)
func (s *ServiceConfig) GetPrimaryHost() string {
	hosts := s.GetAllHosts()
	if len(hosts) > 0 {
		return hosts[0]
	}
	return ""
}

// createDefaultRoute creates a default reverse proxy route
func createDefaultRoute() RouteConfig {
	return RouteConfig{
		Match: MatchConfig{
			Path: "/*",
		},
		Handle: []MiddlewareConfig{
			{
				Type: "reverse_proxy",
			},
		},
	}
}
