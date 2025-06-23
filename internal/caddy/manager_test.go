package caddy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devhatro/zero-trust-proxy/internal/agent"
)

// mockCaddyServer creates a mock Caddy admin API server for testing
func mockCaddyServer(t *testing.T, expectedConfig map[string]interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/load" {
			t.Errorf("expected /load path, got %s", r.URL.Path)
		}

		// Read and validate the request body
		var receivedConfig map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&receivedConfig); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		// Optional validation of specific config parts
		if expectedConfig != nil {
			// Validate that the config has the expected structure
			if _, hasApps := receivedConfig["apps"]; !hasApps {
				t.Error("config should have 'apps' section")
			}
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
}

// TestNewManager tests creating a new Caddy manager
func TestNewManager(t *testing.T) {
	adminAPI := "http://localhost:2019"
	manager := NewManager(adminAPI)

	if manager == nil {
		t.Fatal("NewManager returned nil")
	}

	if manager.adminAPI != adminAPI {
		t.Errorf("expected adminAPI %s, got %s", adminAPI, manager.adminAPI)
	}

	if manager.config == nil {
		t.Error("config map should be initialized")
	}

	if manager.enhancedServices == nil {
		t.Error("enhancedServices map should be initialized")
	}

	if len(manager.config) != 0 {
		t.Error("config map should be empty initially")
	}

	if len(manager.enhancedServices) != 0 {
		t.Error("enhancedServices map should be empty initially")
	}
}

// TestAddService tests adding simple services
func TestAddService(t *testing.T) {
	// Create mock server
	server := mockCaddyServer(t, nil)
	defer server.Close()

	manager := NewManager(server.URL)

	tests := []struct {
		name     string
		hostname string
		backend  string
		protocol string
	}{
		{"simple http service", "example.com", "192.168.1.100:8080", "http"},
		{"https service", "secure.example.com", "192.168.1.101:8443", "https"},
		{"api service", "api.example.com", "192.168.1.102:3000", "http"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.AddService(tt.hostname, tt.backend, tt.protocol)
			if err != nil {
				t.Fatalf("AddService failed: %v", err)
			}

			// Verify service was added to config
			service, exists := manager.config[tt.hostname]
			if !exists {
				t.Error("service should exist in config after adding")
			}

			if service.Hostname != tt.hostname {
				t.Errorf("expected hostname %s, got %s", tt.hostname, service.Hostname)
			}

			if service.Backend != "127.0.0.1:9443" { // Should always point to server internal API
				t.Errorf("expected backend 127.0.0.1:9443, got %s", service.Backend)
			}

			if service.Protocol != tt.protocol {
				t.Errorf("expected protocol %s, got %s", tt.protocol, service.Protocol)
			}
		})
	}
}

// TestAddServiceWithWebSocket tests adding services with WebSocket support
func TestAddServiceWithWebSocket(t *testing.T) {
	server := mockCaddyServer(t, nil)
	defer server.Close()

	manager := NewManager(server.URL)

	err := manager.AddServiceWithWebSocket("chat.example.com", "192.168.1.100:8080", "http", true)
	if err != nil {
		t.Fatalf("AddServiceWithWebSocket failed: %v", err)
	}

	// Verify WebSocket support was enabled
	service := manager.config["chat.example.com"]
	if !service.WebSocket {
		t.Error("WebSocket should be enabled")
	}
}

// TestAddFullServiceConfig tests adding services with full configuration options
func TestAddFullServiceConfig(t *testing.T) {
	server := mockCaddyServer(t, nil)
	defer server.Close()

	manager := NewManager(server.URL)

	tests := []struct {
		name         string
		hostname     string
		backend      string
		protocol     string
		webSocket    bool
		httpRedirect bool
		listenOn     string
	}{
		{"full https service", "app.example.com", "192.168.1.100:8080", "https", true, true, "both"},
		{"http only service", "dev.example.com", "192.168.1.101:3000", "http", false, false, "http"},
		{"https only service", "secure.example.com", "192.168.1.102:8443", "https", false, false, "https"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.AddFullServiceConfig(tt.hostname, tt.backend, tt.protocol, tt.webSocket, tt.httpRedirect, tt.listenOn)
			if err != nil {
				t.Fatalf("AddFullServiceConfig failed: %v", err)
			}

			service := manager.config[tt.hostname]
			if service.WebSocket != tt.webSocket {
				t.Errorf("expected WebSocket %v, got %v", tt.webSocket, service.WebSocket)
			}
			if service.HTTPRedirect != tt.httpRedirect {
				t.Errorf("expected HTTPRedirect %v, got %v", tt.httpRedirect, service.HTTPRedirect)
			}
			if service.ListenOn != tt.listenOn {
				t.Errorf("expected ListenOn %s, got %s", tt.listenOn, service.ListenOn)
			}
		})
	}
}

// TestAddEnhancedService tests adding enhanced service configurations
func TestAddEnhancedService(t *testing.T) {
	server := mockCaddyServer(t, nil)
	defer server.Close()

	manager := NewManager(server.URL)

	enhancedService := &agent.ServiceConfig{
		ID:           "enhanced-test",
		Name:         "Enhanced Test Service",
		Hostname:     "enhanced.example.com",
		Protocol:     "https",
		WebSocket:    true,
		HTTPRedirect: true,
		ListenOn:     "both",
		Upstreams: []agent.UpstreamConfig{
			{
				Address: "192.168.1.100:8080",
				Weight:  100,
			},
		},
		Routes: []agent.RouteConfig{
			{
				Match: agent.MatchConfig{
					Path: "/api/*",
				},
				Handle: []agent.MiddlewareConfig{
					{
						Type: "reverse_proxy",
					},
				},
			},
		},
	}

	err := manager.AddEnhancedService(enhancedService)
	if err != nil {
		t.Fatalf("AddEnhancedService failed: %v", err)
	}

	// Verify enhanced service was added
	enhanced := manager.enhancedServices[enhancedService.Hostname]
	if enhanced == nil {
		t.Fatal("enhanced service should exist")
	}

	if enhanced.ID != enhancedService.ID {
		t.Errorf("expected ID %s, got %s", enhancedService.ID, enhanced.ID)
	}

	// Verify simple config was also created
	simple := manager.config[enhancedService.Hostname]
	if simple == nil {
		t.Fatal("simple config should exist for enhanced service")
	}

	if simple.Hostname != enhancedService.Hostname {
		t.Errorf("expected hostname %s, got %s", enhancedService.Hostname, simple.Hostname)
	}
}

// TestRemoveService tests removing services
func TestRemoveService(t *testing.T) {
	server := mockCaddyServer(t, nil)
	defer server.Close()

	manager := NewManager(server.URL)

	// Add a service first
	hostname := "test.example.com"
	err := manager.AddService(hostname, "192.168.1.100:8080", "http")
	if err != nil {
		t.Fatalf("AddService failed: %v", err)
	}

	// Verify service exists
	if _, exists := manager.config[hostname]; !exists {
		t.Fatal("service should exist before removal")
	}

	// Remove the service
	err = manager.RemoveService(hostname)
	if err != nil {
		t.Fatalf("RemoveService failed: %v", err)
	}

	// Verify service was removed
	if _, exists := manager.config[hostname]; exists {
		t.Error("service should not exist after removal")
	}
}

// TestGetServiceStats tests retrieving service statistics
func TestGetServiceStats(t *testing.T) {
	server := mockCaddyServer(t, nil)
	defer server.Close()

	manager := NewManager(server.URL)

	// Add various types of services
	manager.AddFullServiceConfig("https1.example.com", "backend", "https", false, false, "https")
	manager.AddFullServiceConfig("https2.example.com", "backend", "https", true, true, "both")
	manager.AddFullServiceConfig("http1.example.com", "backend", "http", false, false, "http")
	manager.AddFullServiceConfig("both1.example.com", "backend", "http", true, true, "both")

	stats := manager.GetServiceStats()

	if stats.TotalServices != 4 {
		t.Errorf("expected 4 total services, got %d", stats.TotalServices)
	}

	// https1 and https2 and both1 support HTTPS
	if stats.HTTPSServices != 3 {
		t.Errorf("expected 3 HTTPS services, got %d", stats.HTTPSServices)
	}

	// http1, https2, and both1 support HTTP (listenOn="http" or "both")
	if stats.HTTPServices != 3 {
		t.Errorf("expected 3 HTTP services, got %d", stats.HTTPServices)
	}

	// https2 and both1 have WebSocket enabled
	if stats.WebSocketEnabled != 2 {
		t.Errorf("expected 2 WebSocket enabled services, got %d", stats.WebSocketEnabled)
	}

	// https2 and both1 have redirect enabled
	if stats.RedirectEnabled != 2 {
		t.Errorf("expected 2 redirect enabled services, got %d", stats.RedirectEnabled)
	}
}

// TestServiceSupportsHTTPS tests HTTPS support checking
func TestServiceSupportsHTTPS(t *testing.T) {
	manager := NewManager("http://localhost:2019")

	tests := []struct {
		name     string
		listenOn string
		expected bool
	}{
		{"https only", "https", true},
		{"both protocols", "both", true},
		{"empty (default)", "", true},
		{"http only", "http", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &ServiceConfig{
				Hostname: "test.example.com",
				ListenOn: tt.listenOn,
			}

			result := manager.serviceSupportsHTTPS(service)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for listenOn=%s", tt.expected, result, tt.listenOn)
			}
		})
	}
}

// TestServiceSupportsHTTP tests HTTP support checking
func TestServiceSupportsHTTP(t *testing.T) {
	manager := NewManager("http://localhost:2019")

	tests := []struct {
		name     string
		listenOn string
		expected bool
	}{
		{"http only", "http", true},
		{"both protocols", "both", true},
		{"empty (default)", "", true},
		{"https only", "https", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &ServiceConfig{
				Hostname: "test.example.com",
				ListenOn: tt.listenOn,
			}

			result := manager.serviceSupportsHTTP(service)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for listenOn=%s", tt.expected, result, tt.listenOn)
			}
		})
	}
}

// TestBuildSimpleServiceRoute tests building simple service routes
func TestBuildSimpleServiceRoute(t *testing.T) {
	manager := NewManager("http://localhost:2019")

	tests := []struct {
		name      string
		service   *ServiceConfig
		checkFunc func(*testing.T, map[string]interface{})
	}{
		{
			name: "simple HTTP service",
			service: &ServiceConfig{
				Hostname:  "api.example.com",
				Backend:   "127.0.0.1:9443",
				Protocol:  "http",
				WebSocket: false,
			},
			checkFunc: func(t *testing.T, route map[string]interface{}) {
				// Check match conditions
				match, ok := route["match"].([]map[string]interface{})
				if !ok || len(match) == 0 {
					t.Fatal("route should have match conditions")
				}

				host, ok := match[0]["host"].([]string)
				if !ok || len(host) == 0 || host[0] != "api.example.com" {
					t.Error("route should match the correct hostname")
				}

				// Check handlers
				handle, ok := route["handle"].([]map[string]interface{})
				if !ok || len(handle) == 0 {
					t.Fatal("route should have handlers")
				}

				handler := handle[0]
				if handler["handler"] != "reverse_proxy" {
					t.Error("should have reverse_proxy handler")
				}
			},
		},
		{
			name: "WebSocket enabled service",
			service: &ServiceConfig{
				Hostname:  "ws.example.com",
				Backend:   "127.0.0.1:9443",
				Protocol:  "http",
				WebSocket: true,
			},
			checkFunc: func(t *testing.T, route map[string]interface{}) {
				// Check that WebSocket header is set
				handle, ok := route["handle"].([]map[string]interface{})
				if !ok || len(handle) == 0 {
					t.Fatal("route should have handlers")
				}

				headers, ok := handle[0]["headers"].(map[string]interface{})
				if !ok {
					t.Fatal("handler should have headers")
				}

				request, ok := headers["request"].(map[string]interface{})
				if !ok {
					t.Fatal("headers should have request section")
				}

				set, ok := request["set"].(map[string][]string)
				if !ok {
					t.Fatal("request should have set headers")
				}

				if wsEnabled, exists := set["X-WebSocket-Enabled"]; !exists || len(wsEnabled) == 0 || wsEnabled[0] != "true" {
					t.Error("should have X-WebSocket-Enabled header set to true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := manager.buildSimpleServiceRoute(tt.service)
			tt.checkFunc(t, route)
		})
	}
}

// TestBuildMatchConditions tests building match conditions for routes
func TestBuildMatchConditions(t *testing.T) {
	manager := NewManager("http://localhost:2019")

	tests := []struct {
		name     string
		hostname string
		match    *agent.MatchConfig
		expected int // expected number of conditions
	}{
		{
			name:     "hostname only",
			hostname: "example.com",
			match:    &agent.MatchConfig{},
			expected: 1,
		},
		{
			name:     "hostname and path",
			hostname: "api.example.com",
			match: &agent.MatchConfig{
				Path: "/api/v1/*",
			},
			expected: 2,
		},
		{
			name:     "hostname, path, and method",
			hostname: "api.example.com",
			match: &agent.MatchConfig{
				Path:   "/users",
				Method: "POST",
			},
			expected: 3,
		},
		{
			name:     "wildcard path (should not add path matcher)",
			hostname: "api.example.com",
			match: &agent.MatchConfig{
				Path: "/*",
			},
			expected: 1, // Only hostname matcher
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conditions := manager.buildMatchConditions(tt.hostname, tt.match)

			if len(conditions) != tt.expected {
				t.Errorf("expected %d conditions, got %d", tt.expected, len(conditions))
			}

			// First condition should always be hostname
			if host, exists := conditions[0]["host"]; exists {
				hostSlice, ok := host.([]string)
				if !ok || len(hostSlice) == 0 || hostSlice[0] != tt.hostname {
					t.Error("first condition should match hostname")
				}
			} else {
				t.Error("first condition should be hostname matcher")
			}
		})
	}
}

// TestReloadConfigHTTPRedirect tests HTTP to HTTPS redirect configuration
func TestReloadConfigHTTPRedirect(t *testing.T) {
	// Create a more sophisticated mock server that captures the config
	var receivedConfig map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedConfig)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	manager := NewManager(server.URL)

	// Add a service with HTTP redirect enabled
	err := manager.AddFullServiceConfig("redirect.example.com", "backend", "http", false, true, "both")
	if err != nil {
		t.Fatalf("AddFullServiceConfig failed: %v", err)
	}

	// Check that the config includes redirect routes
	if receivedConfig == nil {
		t.Fatal("no config was sent to mock server")
	}

	apps, ok := receivedConfig["apps"].(map[string]interface{})
	if !ok {
		t.Fatal("config should have apps section")
	}

	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		t.Fatal("config should have http app")
	}

	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		t.Fatal("http app should have servers")
	}

	// Should have both HTTP and HTTPS servers for redirect service
	if len(servers) == 0 {
		t.Error("should have servers configured")
	}
}

// TestConcurrentOperations tests thread safety of manager operations
func TestConcurrentOperations(t *testing.T) {
	server := mockCaddyServer(t, nil)
	defer server.Close()

	manager := NewManager(server.URL)
	const numGoroutines = 10
	const numOperations = 50

	done := make(chan bool, numGoroutines)

	// Run concurrent operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				hostname := fmt.Sprintf("test%d-%d.example.com", id, j)

				// Add service
				manager.AddService(hostname, "backend", "http")

				// Get stats
				manager.GetServiceStats()

				// Remove service
				manager.RemoveService(hostname)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify final state
	stats := manager.GetServiceStats()
	if stats.TotalServices != 0 {
		t.Errorf("expected 0 services after concurrent test, got %d", stats.TotalServices)
	}
}

// BenchmarkAddService benchmarks adding services
func BenchmarkAddService(b *testing.B) {
	server := mockCaddyServer(nil, nil)
	defer server.Close()

	manager := NewManager(server.URL)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hostname := fmt.Sprintf("test%d.example.com", i%1000) // Reuse hostnames
		manager.AddService(hostname, "backend", "http")
	}
}

// BenchmarkGetServiceStats benchmarks getting service statistics
func BenchmarkGetServiceStats(b *testing.B) {
	server := mockCaddyServer(nil, nil)
	defer server.Close()

	manager := NewManager(server.URL)

	// Add some services for benchmarking
	for i := 0; i < 100; i++ {
		hostname := fmt.Sprintf("test%d.example.com", i)
		manager.AddService(hostname, "backend", "http")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.GetServiceStats()
	}
}
