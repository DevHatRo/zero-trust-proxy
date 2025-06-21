package caddy

import "time"

// Enhanced configuration types for advanced Caddy features
// These mirror the agent types but are defined here to avoid circular dependencies

// EnhancedServiceConfig represents an advanced service configuration
type EnhancedServiceConfig struct {
	ID             string                `json:"id"`
	Name           string                `json:"name"`
	Hostname       string                `json:"hostname,omitempty"`
	Hosts          []string              `json:"hosts,omitempty"`
	Protocol       string                `json:"protocol"`
	WebSocket      bool                  `json:"websocket,omitempty"`
	HTTPRedirect   bool                  `json:"http_redirect,omitempty"`
	ListenOn       string                `json:"listen_on,omitempty"`
	Upstreams      []UpstreamConfig      `json:"upstreams"`
	LoadBalancing  *LoadBalancingConfig  `json:"load_balancing,omitempty"`
	Routes         []RouteConfig         `json:"routes,omitempty"`
	TLS            *TLSConfig            `json:"tls,omitempty"`
	Security       *SecurityConfig       `json:"security,omitempty"`
	Monitoring     *MonitoringConfig     `json:"monitoring,omitempty"`
	TrafficShaping *TrafficShapingConfig `json:"traffic_shaping,omitempty"`
}

// UpstreamConfig represents a backend server
type UpstreamConfig struct {
	Address     string             `json:"address"`
	Weight      int                `json:"weight,omitempty"`
	HealthCheck *HealthCheckConfig `json:"health_check,omitempty"`
}

// HealthCheckConfig represents health check settings
type HealthCheckConfig struct {
	Path     string            `json:"path,omitempty"`
	Interval time.Duration     `json:"interval,omitempty"`
	Timeout  time.Duration     `json:"timeout,omitempty"`
	Method   string            `json:"method,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

// LoadBalancingConfig represents load balancing settings
type LoadBalancingConfig struct {
	Policy              string        `json:"policy"`
	HealthCheckRequired bool          `json:"health_check_required,omitempty"`
	SessionAffinity     bool          `json:"session_affinity,omitempty"`
	AffinityDuration    time.Duration `json:"affinity_duration,omitempty"`
}

// RouteConfig represents routing rules
type RouteConfig struct {
	Match  MatchConfig        `json:"match"`
	Handle []MiddlewareConfig `json:"handle"`
}

// MatchConfig represents route matching conditions
type MatchConfig struct {
	Path    string              `json:"path,omitempty"`
	Method  string              `json:"method,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Query   map[string]string   `json:"query,omitempty"`
}

// MiddlewareConfig represents middleware configuration
type MiddlewareConfig struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config,omitempty"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	CertFile     string   `json:"cert_file,omitempty"`
	KeyFile      string   `json:"key_file,omitempty"`
	CAFile       string   `json:"ca_file,omitempty"`
	MinVersion   string   `json:"min_version,omitempty"`
	Ciphers      []string `json:"ciphers,omitempty"`
	ClientAuth   string   `json:"client_auth,omitempty"`
	ClientCAFile string   `json:"client_ca_file,omitempty"`
}

// SecurityConfig represents security settings
type SecurityConfig struct {
	CORS *CORSConfig `json:"cors,omitempty"`
	Auth *AuthConfig `json:"auth,omitempty"`
}

// CORSConfig represents CORS configuration
type CORSConfig struct {
	Origins []string `json:"origins,omitempty"`
	Methods []string `json:"methods,omitempty"`
	Headers []string `json:"headers,omitempty"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config,omitempty"`
}

// MonitoringConfig represents monitoring settings
type MonitoringConfig struct {
	MetricsEnabled bool     `json:"metrics_enabled,omitempty"`
	LoggingFormat  string   `json:"logging_format,omitempty"`
	LoggingFields  []string `json:"logging_fields,omitempty"`
}

// TrafficShapingConfig represents bandwidth limiting
type TrafficShapingConfig struct {
	UploadLimit   string `json:"upload_limit,omitempty"`
	DownloadLimit string `json:"download_limit,omitempty"`
	PerIPLimit    string `json:"per_ip_limit,omitempty"`
}

// GetAllHosts returns all hosts for this service
func (s *EnhancedServiceConfig) GetAllHosts() []string {
	var allHosts []string

	if s.Hostname != "" {
		allHosts = append(allHosts, s.Hostname)
	}

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

// GetPrimaryHost returns the primary host for this service
func (s *EnhancedServiceConfig) GetPrimaryHost() string {
	hosts := s.GetAllHosts()
	if len(hosts) > 0 {
		return hosts[0]
	}
	return ""
}
