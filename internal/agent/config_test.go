package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() (string, func()) // Returns config path and cleanup function
		wantErr   bool
		validate  func(t *testing.T, config *AgentConfig)
	}{
		{
			name: "default config creation",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "agent.yaml")
				return configPath, func() {}
			},
			wantErr: false,
			validate: func(t *testing.T, config *AgentConfig) {
				if config.Agent.ID != "default-agent" {
					t.Errorf("Expected default agent ID 'default-agent', got %s", config.Agent.ID)
				}
				if config.LogLevel != "INFO" {
					t.Errorf("Expected default LogLevel INFO, got %s", config.LogLevel)
				}
				// Check new logging configuration defaults
				if config.Logging.Level != "INFO" {
					t.Errorf("Expected default logging level INFO, got %s", config.Logging.Level)
				}
				if config.Logging.Format != "console" {
					t.Errorf("Expected default logging format console, got %s", config.Logging.Format)
				}
				if config.Logging.Output != "stdout" {
					t.Errorf("Expected default logging output stdout, got %s", config.Logging.Output)
				}
				// Note: Component field removed - each module now sets its own component via WithComponent()
				if len(config.Services) != 0 {
					t.Errorf("Expected no default services, got %d", len(config.Services))
				}
			},
		},
		{
			name: "valid existing config with services",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "agent.yaml")

				configContent := `
agent:
  id: "test-agent"
  name: "Test Agent"
  region: "us-west-1"
  tags: ["production", "web"]
server:
  address: "server.example.com:8443"
  ca_cert: "/custom/ca.crt"
  cert: "/custom/agent.crt"
  key: "/custom/agent.key"
services:
  - id: "web-service"
    name: "Web Service"
    hosts: ["app.example.com", "www.example.com"]
    protocol: "http"
    websocket: true
    http_redirect: true
    listen_on: "both"
    upstreams:
      - address: "localhost:3000"
        weight: 100
        health_check:
          path: "/health"
          interval: 30s
          timeout: 5s
          method: "GET"
    load_balancing:
      policy: "round_robin"
      health_check_required: true
    routes:
      - match:
          path: "/api/*"
          method: "GET"
        handle:
          - type: "rate_limit"
            config:
              rate: "100/minute"
    security:
      cors:
        origins: ["https://example.com"]
        methods: ["GET", "POST"]
        headers: ["Content-Type"]
log_level: "DEBUG"
health_checks:
  global_settings:
    check_interval: 30s
    timeout: 5s
    unhealthy_threshold: 3
    healthy_threshold: 2
`
				if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
					t.Fatalf("Failed to create test config: %v", err)
				}

				return configPath, func() {}
			},
			wantErr: false,
			validate: func(t *testing.T, config *AgentConfig) {
				if config.Agent.ID != "test-agent" {
					t.Errorf("Expected agent ID 'test-agent', got %s", config.Agent.ID)
				}
				if config.Agent.Name != "Test Agent" {
					t.Errorf("Expected agent name 'Test Agent', got %s", config.Agent.Name)
				}
				if config.Agent.Region != "us-west-1" {
					t.Errorf("Expected region 'us-west-1', got %s", config.Agent.Region)
				}
				if len(config.Agent.Tags) != 2 {
					t.Errorf("Expected 2 tags, got %d", len(config.Agent.Tags))
				}
				if len(config.Services) != 1 {
					t.Errorf("Expected 1 service, got %d", len(config.Services))
				}

				service := config.Services[0]
				if service.ID != "web-service" {
					t.Errorf("Expected service ID 'web-service', got %s", service.ID)
				}
				if len(service.Hosts) != 2 {
					t.Errorf("Expected 2 hosts, got %d", len(service.Hosts))
				}
				if !service.WebSocket {
					t.Error("Expected WebSocket to be enabled")
				}
				if !service.HTTPRedirect {
					t.Error("Expected HTTPRedirect to be enabled")
				}
				if service.ListenOn != "both" {
					t.Errorf("Expected ListenOn 'both', got %s", service.ListenOn)
				}
			},
		},
		{
			name: "config with environment variables",
			setupFunc: func() (string, func()) {
				// Set environment variable
				originalAddr := os.Getenv("ZERO_TRUST_SERVER")
				os.Setenv("ZERO_TRUST_SERVER", "env-server.example.com:9443")

				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "agent.yaml")

				// The config will use the environment variable
				return configPath, func() {
					// Restore original environment
					if originalAddr == "" {
						os.Unsetenv("ZERO_TRUST_SERVER")
					} else {
						os.Setenv("ZERO_TRUST_SERVER", originalAddr)
					}
				}
			},
			wantErr: false,
			validate: func(t *testing.T, config *AgentConfig) {
				if config.Server.Address != "env-server.example.com:9443" {
					t.Errorf("Expected server address from env var, got %s", config.Server.Address)
				}
			},
		},
		{
			name: "invalid yaml",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "agent.yaml")

				configContent := `
agent:
  id: "test-agent"
  invalid_yaml: [unclosed array
`
				if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
					t.Fatalf("Failed to create test config: %v", err)
				}

				return configPath, func() {}
			},
			wantErr: true,
		},
		{
			name: "missing required agent ID",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "agent.yaml")

				configContent := `
agent:
  name: "Test Agent"
server:
  address: "localhost:8443"
`
				if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
					t.Fatalf("Failed to create test config: %v", err)
				}

				return configPath, func() {}
			},
			wantErr: true,
		},
		{
			name: "service without hosts",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "agent.yaml")

				configContent := `
agent:
  id: "test-agent"
server:
  address: "localhost:8443"
services:
  - id: "web-service"
    protocol: "http"
    upstreams:
      - address: "localhost:3000"
`
				if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
					t.Fatalf("Failed to create test config: %v", err)
				}

				return configPath, func() {}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath, cleanup := tt.setupFunc()
			defer cleanup()

			config, err := LoadConfig(configPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("LoadConfig() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("LoadConfig() unexpected error: %v", err)
				return
			}

			if config == nil {
				t.Fatal("LoadConfig() returned nil config")
			}

			if config.ConfigPath != configPath {
				t.Errorf("Expected ConfigPath %s, got %s", configPath, config.ConfigPath)
			}

			if tt.validate != nil {
				tt.validate(t, config)
			}
		})
	}
}

func TestSaveConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "agent.yaml")

	config := &AgentConfig{
		Agent: AgentSettings{
			ID:   "test-agent",
			Name: "Test Agent",
		},
		Server: ServerConfig{
			Address: "localhost:8443",
			CACert:  "/test/ca.crt",
			Cert:    "/test/agent.crt",
			Key:     "/test/agent.key",
		},
		Services: []ServiceConfig{
			{
				ID:       "web-service",
				Name:     "Web Service",
				Hosts:    []string{"app.example.com"},
				Protocol: "http",
				Upstreams: []UpstreamConfig{
					{
						Address: "localhost:3000",
						Weight:  100,
					},
				},
			},
		},
		LogLevel: "INFO",
	}

	// Save the config
	err := SaveConfig(configPath, config)
	if err != nil {
		t.Fatalf("SaveConfig() failed: %v", err)
	}

	// Verify the file was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Errorf("SaveConfig() did not create config file")
	}

	// Load it back to verify it's valid
	loadedConfig, err := LoadConfig(configPath)
	if err != nil {
		t.Errorf("Failed to load saved config: %v", err)
		return
	}

	if loadedConfig.Agent.ID != config.Agent.ID {
		t.Errorf("Saved config doesn't match original")
	}
}

func TestCreateDefaultConfig(t *testing.T) {
	// Test with different environment variables
	tests := []struct {
		name     string
		envVars  map[string]string
		expected string
	}{
		{
			name:     "no environment variables",
			envVars:  map[string]string{},
			expected: "localhost:8443",
		},
		{
			name: "ZERO_TRUST_SERVER set",
			envVars: map[string]string{
				"ZERO_TRUST_SERVER": "server.example.com:9443",
			},
			expected: "server.example.com:9443",
		},
		{
			name: "SERVER_ADDRESS set",
			envVars: map[string]string{
				"SERVER_ADDRESS": "custom.server.com:9000",
			},
			expected: "custom.server.com:9000",
		},
		{
			name: "SERVER_PORT set",
			envVars: map[string]string{
				"SERVER_PORT": "9999",
			},
			expected: "localhost:9999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all relevant env vars first
			origVars := make(map[string]string)
			for _, key := range []string{"ZERO_TRUST_SERVER", "SERVER_ADDRESS", "SERVER_PORT"} {
				origVars[key] = os.Getenv(key)
				os.Unsetenv(key)
			}

			// Set test env vars
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			config := createDefaultConfig()

			// Restore original env vars
			for key, value := range origVars {
				if value == "" {
					os.Unsetenv(key)
				} else {
					os.Setenv(key, value)
				}
			}

			if config.Server.Address != tt.expected {
				t.Errorf("Expected server address %s, got %s", tt.expected, config.Server.Address)
			}

			if config.Agent.ID != "default-agent" {
				t.Errorf("Expected default agent ID 'default-agent', got %s", config.Agent.ID)
			}
		})
	}
}

func TestValidateAndApplyDefaults(t *testing.T) {
	tests := []struct {
		name    string
		config  *AgentConfig
		wantErr bool
		errMsg  string
		check   func(t *testing.T, config *AgentConfig) // Optional validation after success
	}{
		{
			name: "valid minimal config",
			config: &AgentConfig{
				Agent: AgentSettings{ID: "test-agent"},
				Services: []ServiceConfig{
					{
						ID:    "web-service",
						Hosts: []string{"app.example.com"},
						Upstreams: []UpstreamConfig{
							{Address: "localhost:3000"},
						},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, config *AgentConfig) {
				service := config.Services[0]
				if service.Protocol != "http" {
					t.Errorf("Expected default protocol 'http', got %s", service.Protocol)
				}
				if service.ListenOn != "both" {
					t.Errorf("Expected default ListenOn 'both', got %s", service.ListenOn)
				}
				if !service.HTTPRedirect {
					t.Error("Expected HTTPRedirect to be true by default for 'both' listen mode")
				}
				if service.Upstreams[0].Weight != 100 {
					t.Errorf("Expected default upstream weight 100, got %d", service.Upstreams[0].Weight)
				}
			},
		},
		{
			name: "missing agent ID",
			config: &AgentConfig{
				Agent: AgentSettings{Name: "Test Agent"},
			},
			wantErr: true,
			errMsg:  "agent.id is required",
		},
		{
			name: "missing service ID",
			config: &AgentConfig{
				Agent: AgentSettings{ID: "test-agent"},
				Services: []ServiceConfig{
					{
						Hosts: []string{"app.example.com"},
						Upstreams: []UpstreamConfig{
							{Address: "localhost:3000"},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "services[0].id is required",
		},
		{
			name: "service without hosts",
			config: &AgentConfig{
				Agent: AgentSettings{ID: "test-agent"},
				Services: []ServiceConfig{
					{
						ID: "web-service",
						Upstreams: []UpstreamConfig{
							{Address: "localhost:3000"},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "must have at least one host defined",
		},
		{
			name: "service without upstreams",
			config: &AgentConfig{
				Agent: AgentSettings{ID: "test-agent"},
				Services: []ServiceConfig{
					{
						ID:    "web-service",
						Hosts: []string{"app.example.com"},
					},
				},
			},
			wantErr: true,
			errMsg:  "must have at least one upstream",
		},
		{
			name: "invalid listen_on value",
			config: &AgentConfig{
				Agent: AgentSettings{ID: "test-agent"},
				Services: []ServiceConfig{
					{
						ID:       "web-service",
						Hosts:    []string{"app.example.com"},
						ListenOn: "invalid",
						Upstreams: []UpstreamConfig{
							{Address: "localhost:3000"},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "listen_on must be 'http', 'https', or 'both'",
		},
		{
			name: "http_redirect with http-only service",
			config: &AgentConfig{
				Agent: AgentSettings{ID: "test-agent"},
				Services: []ServiceConfig{
					{
						ID:           "web-service",
						Hosts:        []string{"app.example.com"},
						ListenOn:     "http",
						HTTPRedirect: true,
						Upstreams: []UpstreamConfig{
							{Address: "localhost:3000"},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "http_redirect cannot be true when listen_on is 'http'",
		},
		{
			name: "backward compatibility with hostname field",
			config: &AgentConfig{
				Agent: AgentSettings{ID: "test-agent"},
				Services: []ServiceConfig{
					{
						ID:       "web-service",
						Hostname: "app.example.com", // Old field
						Upstreams: []UpstreamConfig{
							{Address: "localhost:3000"},
						},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, config *AgentConfig) {
				hosts := config.Services[0].GetAllHosts()
				if len(hosts) != 1 || hosts[0] != "app.example.com" {
					t.Errorf("Expected hostname to be included in hosts, got %v", hosts)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAndApplyDefaults(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateAndApplyDefaults() expected error, got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateAndApplyDefaults() error = %v, expected to contain %s", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("validateAndApplyDefaults() unexpected error: %v", err)
				return
			}

			if tt.check != nil {
				tt.check(t, tt.config)
			}
		})
	}
}

func TestAgentConfigServiceManagement(t *testing.T) {
	config := &AgentConfig{
		Agent: AgentSettings{ID: "test-agent"},
		Services: []ServiceConfig{
			{
				ID:    "existing-service",
				Hosts: []string{"existing.example.com"},
				Upstreams: []UpstreamConfig{
					{Address: "localhost:3000"},
				},
			},
		},
	}

	// Test AddService
	newService := ServiceConfig{
		ID:    "new-service",
		Hosts: []string{"new.example.com"},
		Upstreams: []UpstreamConfig{
			{Address: "localhost:4000"},
		},
	}

	err := config.AddService(newService)
	if err != nil {
		t.Errorf("AddService() failed: %v", err)
	}

	if len(config.Services) != 2 {
		t.Errorf("Expected 2 services after AddService, got %d", len(config.Services))
	}

	// Test adding duplicate service (should fail)
	duplicateService := ServiceConfig{
		ID:    "duplicate-service",
		Hosts: []string{"existing.example.com"}, // Same host
		Upstreams: []UpstreamConfig{
			{Address: "localhost:5000"},
		},
	}

	err = config.AddService(duplicateService)
	if err == nil {
		t.Error("AddService() should have failed for duplicate host")
	}

	// Test GetService
	service, err := config.GetService("existing.example.com")
	if err != nil {
		t.Errorf("GetService() failed: %v", err)
	}
	if service.ID != "existing-service" {
		t.Errorf("GetService() returned wrong service: %s", service.ID)
	}

	// Test GetServiceByID
	service, err = config.GetServiceByID("new-service")
	if err != nil {
		t.Errorf("GetServiceByID() failed: %v", err)
	}
	if service.ID != "new-service" {
		t.Errorf("GetServiceByID() returned wrong service: %s", service.ID)
	}

	// Test UpdateService
	updatedService := ServiceConfig{
		ID:       "existing-service", // ID will be preserved
		Hosts:    []string{"existing.example.com"},
		Protocol: "https", // Change protocol
		Upstreams: []UpstreamConfig{
			{Address: "localhost:3001"}, // Change upstream
		},
	}

	err = config.UpdateService("existing.example.com", updatedService)
	if err != nil {
		t.Errorf("UpdateService() failed: %v", err)
	}

	service, _ = config.GetService("existing.example.com")
	if service.Protocol != "https" {
		t.Errorf("UpdateService() didn't update protocol: %s", service.Protocol)
	}

	// Test RemoveService
	err = config.RemoveService("new.example.com")
	if err != nil {
		t.Errorf("RemoveService() failed: %v", err)
	}

	if len(config.Services) != 1 {
		t.Errorf("Expected 1 service after RemoveService, got %d", len(config.Services))
	}

	// Test removing non-existent service
	err = config.RemoveService("nonexistent.example.com")
	if err == nil {
		t.Error("RemoveService() should have failed for non-existent service")
	}
}

func TestServiceConfigGetAllHosts(t *testing.T) {
	tests := []struct {
		name     string
		service  ServiceConfig
		expected []string
	}{
		{
			name: "only hostname field",
			service: ServiceConfig{
				Hostname: "old.example.com",
			},
			expected: []string{"old.example.com"},
		},
		{
			name: "only hosts field",
			service: ServiceConfig{
				Hosts: []string{"new1.example.com", "new2.example.com"},
			},
			expected: []string{"new1.example.com", "new2.example.com"},
		},
		{
			name: "both hostname and hosts",
			service: ServiceConfig{
				Hostname: "old.example.com",
				Hosts:    []string{"new1.example.com", "new2.example.com"},
			},
			expected: []string{"old.example.com", "new1.example.com", "new2.example.com"},
		},
		{
			name: "duplicates removed",
			service: ServiceConfig{
				Hostname: "example.com",
				Hosts:    []string{"example.com", "other.example.com"},
			},
			expected: []string{"example.com", "other.example.com"},
		},
		{
			name:     "empty service",
			service:  ServiceConfig{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts := tt.service.GetAllHosts()

			if len(hosts) != len(tt.expected) {
				t.Errorf("Expected %d hosts, got %d", len(tt.expected), len(hosts))
				return
			}

			for i, expected := range tt.expected {
				if i >= len(hosts) || hosts[i] != expected {
					t.Errorf("Expected host[%d] = %s, got %s", i, expected, hosts[i])
				}
			}
		})
	}
}

func TestServiceConfigGetPrimaryHost(t *testing.T) {
	tests := []struct {
		name     string
		service  ServiceConfig
		expected string
	}{
		{
			name: "hostname field takes priority",
			service: ServiceConfig{
				Hostname: "primary.example.com",
				Hosts:    []string{"secondary.example.com"},
			},
			expected: "primary.example.com",
		},
		{
			name: "first host when no hostname",
			service: ServiceConfig{
				Hosts: []string{"first.example.com", "second.example.com"},
			},
			expected: "first.example.com",
		},
		{
			name:     "empty when no hosts",
			service:  ServiceConfig{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := tt.service.GetPrimaryHost()
			if primary != tt.expected {
				t.Errorf("Expected primary host %s, got %s", tt.expected, primary)
			}
		})
	}
}

func TestConfigRoundTrip(t *testing.T) {
	// Test that we can save and load a complex config without losing data
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "agent.yaml")

	originalConfig := &AgentConfig{
		Agent: AgentSettings{
			ID:     "test-agent",
			Name:   "Test Agent",
			Region: "us-west-1",
			Tags:   []string{"production", "web"},
		},
		Server: ServerConfig{
			Address: "server.example.com:8443",
			CACert:  "/test/ca.crt",
			Cert:    "/test/agent.crt",
			Key:     "/test/agent.key",
		},
		Services: []ServiceConfig{
			{
				ID:           "web-service",
				Name:         "Web Service",
				Hosts:        []string{"app.example.com", "www.example.com"},
				Protocol:     "http",
				WebSocket:    true,
				HTTPRedirect: true,
				ListenOn:     "both",
				Upstreams: []UpstreamConfig{
					{
						Address: "localhost:3000",
						Weight:  100,
						HealthCheck: &HealthCheckConfig{
							Path:     "/health",
							Interval: 30 * time.Second,
							Timeout:  5 * time.Second,
							Method:   "GET",
						},
					},
				},
				LoadBalancing: &LoadBalancingConfig{
					Policy:              "round_robin",
					HealthCheckRequired: true,
				},
				Security: &SecurityConfig{
					CORS: &CORSConfig{
						Origins: []string{"https://example.com"},
						Methods: []string{"GET", "POST"},
						Headers: []string{"Content-Type"},
					},
				},
			},
		},
		LogLevel: "DEBUG",
	}

	// Save the config
	if err := SaveConfig(configPath, originalConfig); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load it back
	loadedConfig, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Compare key fields
	if loadedConfig.Agent.ID != originalConfig.Agent.ID {
		t.Errorf("Agent ID mismatch: got %s, want %s", loadedConfig.Agent.ID, originalConfig.Agent.ID)
	}
	if loadedConfig.Agent.Region != originalConfig.Agent.Region {
		t.Errorf("Agent Region mismatch: got %s, want %s", loadedConfig.Agent.Region, originalConfig.Agent.Region)
	}
	if len(loadedConfig.Services) != len(originalConfig.Services) {
		t.Errorf("Services count mismatch: got %d, want %d", len(loadedConfig.Services), len(originalConfig.Services))
	}
	if len(loadedConfig.Services) > 0 {
		loadedService := loadedConfig.Services[0]
		originalService := originalConfig.Services[0]
		if loadedService.WebSocket != originalService.WebSocket {
			t.Errorf("WebSocket mismatch: got %v, want %v", loadedService.WebSocket, originalService.WebSocket)
		}
		if loadedService.LoadBalancing.Policy != originalService.LoadBalancing.Policy {
			t.Errorf("Load balancing policy mismatch: got %s, want %s",
				loadedService.LoadBalancing.Policy, originalService.LoadBalancing.Policy)
		}
	}
}

func TestLoggingConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		configYAML string
		wantErr    bool
		validate   func(t *testing.T, config *AgentConfig)
	}{
		{
			name: "complete logging configuration",
			configYAML: `
agent:
  id: "test-agent"
server:
  address: "localhost:8443"
logging:
  level: "DEBUG"
  format: "json"
  output: "stderr"
  component: "my-custom-agent"
services: []
`,
			wantErr: false,
			validate: func(t *testing.T, config *AgentConfig) {
				if config.Logging.Level != "DEBUG" {
					t.Errorf("Expected logging level DEBUG, got %s", config.Logging.Level)
				}
				if config.Logging.Format != "json" {
					t.Errorf("Expected logging format json, got %s", config.Logging.Format)
				}
				if config.Logging.Output != "stderr" {
					t.Errorf("Expected logging output stderr, got %s", config.Logging.Output)
				}
				// Note: Component field removed - each module now sets its own component via WithComponent()

			},
		},
		{
			name: "partial logging configuration with defaults",
			configYAML: `
agent:
  id: "test-agent"
server:
  address: "localhost:8443"
logging:
  level: "WARN"
services: []
`,
			wantErr: false,
			validate: func(t *testing.T, config *AgentConfig) {
				if config.Logging.Level != "WARN" {
					t.Errorf("Expected logging level WARN, got %s", config.Logging.Level)
				}
				// These should get defaults applied
				if config.Logging.Format != "console" {
					t.Errorf("Expected default logging format console, got %s", config.Logging.Format)
				}
				if config.Logging.Output != "stdout" {
					t.Errorf("Expected default logging output stdout, got %s", config.Logging.Output)
				}
				// Note: Component field removed - each module now sets its own component via WithComponent()
			},
		},
		{
			name: "legacy log_level with new logging config",
			configYAML: `
agent:
  id: "test-agent"
server:
  address: "localhost:8443"
log_level: "ERROR"
logging:
  level: "DEBUG"
  format: "json"
services: []
`,
			wantErr: false,
			validate: func(t *testing.T, config *AgentConfig) {
				// New logging.level should take precedence over legacy log_level
				if config.Logging.Level != "DEBUG" {
					t.Errorf("Expected logging level DEBUG (from new config), got %s", config.Logging.Level)
				}
				if config.LogLevel != "ERROR" {
					t.Errorf("Expected legacy log_level ERROR to be preserved, got %s", config.LogLevel)
				}
			},
		},
		{
			name: "legacy log_level only",
			configYAML: `
agent:
  id: "test-agent"
server:
  address: "localhost:8443"
log_level: "ERROR"
services: []
`,
			wantErr: false,
			validate: func(t *testing.T, config *AgentConfig) {
				// logging.level should inherit from legacy log_level
				if config.Logging.Level != "ERROR" {
					t.Errorf("Expected logging level ERROR (from legacy config), got %s", config.Logging.Level)
				}
				if config.LogLevel != "ERROR" {
					t.Errorf("Expected legacy log_level ERROR, got %s", config.LogLevel)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "agent.yaml")

			if err := os.WriteFile(configPath, []byte(tt.configYAML), 0644); err != nil {
				t.Fatalf("Failed to create test config: %v", err)
			}

			config, err := LoadConfig(configPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("LoadConfig() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("LoadConfig() unexpected error: %v", err)
				return
			}

			if config == nil {
				t.Fatal("LoadConfig() returned nil config")
			}

			if tt.validate != nil {
				tt.validate(t, config)
			}
		})
	}
}

func TestLoggingConfigRoundTrip(t *testing.T) {
	// Test that we can save and load a config with logging configuration
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "agent.yaml")

	originalConfig := &AgentConfig{
		Agent: AgentSettings{
			ID:   "test-agent",
			Name: "Test Agent",
		},
		Server: ServerConfig{
			Address: "localhost:8443",
			CACert:  "/test/ca.crt",
			Cert:    "/test/agent.crt",
			Key:     "/test/agent.key",
		},
		Logging: LoggingConfig{
			Level:  "DEBUG",
			Format: "json",
			Output: "/var/log/agent.log",
		},
		LogLevel: "INFO", // Legacy field
		Services: []ServiceConfig{},
	}

	// Save the config
	err := SaveConfig(configPath, originalConfig)
	if err != nil {
		t.Fatalf("SaveConfig() failed: %v", err)
	}

	// Load it back
	loadedConfig, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() failed: %v", err)
	}

	// Verify logging configuration was preserved
	if loadedConfig.Logging.Level != originalConfig.Logging.Level {
		t.Errorf("Logging level mismatch: expected %s, got %s", originalConfig.Logging.Level, loadedConfig.Logging.Level)
	}
	if loadedConfig.Logging.Format != originalConfig.Logging.Format {
		t.Errorf("Logging format mismatch: expected %s, got %s", originalConfig.Logging.Format, loadedConfig.Logging.Format)
	}
	if loadedConfig.Logging.Output != originalConfig.Logging.Output {
		t.Errorf("Logging output mismatch: expected %s, got %s", originalConfig.Logging.Output, loadedConfig.Logging.Output)
	}
	// Note: Component field removed - each module now sets its own component via WithComponent()
}

func BenchmarkLoadConfig(b *testing.B) {
	tmpDir := b.TempDir()
	configPath := filepath.Join(tmpDir, "agent.yaml")

	// Create a test config file
	config := createDefaultConfig()
	if err := SaveConfig(configPath, config); err != nil {
		b.Fatalf("Failed to create test config: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := LoadConfig(configPath)
		if err != nil {
			b.Fatalf("LoadConfig failed: %v", err)
		}
	}
}

func BenchmarkValidateAndApplyDefaults(b *testing.B) {
	config := &AgentConfig{
		Agent: AgentSettings{ID: "test-agent"},
		Services: []ServiceConfig{
			{
				ID:    "web-service",
				Hosts: []string{"app.example.com"},
				Upstreams: []UpstreamConfig{
					{Address: "localhost:3000"},
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create a copy for each iteration
		testConfig := *config
		testConfig.Services = make([]ServiceConfig, len(config.Services))
		copy(testConfig.Services, config.Services)

		err := validateAndApplyDefaults(&testConfig)
		if err != nil {
			b.Fatalf("validateAndApplyDefaults failed: %v", err)
		}
	}
}
