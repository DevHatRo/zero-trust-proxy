package caddy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewManager(t *testing.T) {
	adminAPI := "http://localhost:2019"
	manager := NewManager(adminAPI)

	if manager == nil {
		t.Fatal("NewManager returned nil")
	}

	if manager.adminAPI != adminAPI {
		t.Errorf("Expected adminAPI %s, got %s", adminAPI, manager.adminAPI)
	}

	if manager.simpleServices == nil {
		t.Error("simpleServices map not initialized")
	}

	if manager.enhancedServices == nil {
		t.Error("enhancedServices map not initialized")
	}

	if manager.validator == nil {
		t.Error("validator not initialized")
	}

	// Test initial state
	if count := manager.GetServiceCount(); count != 0 {
		t.Errorf("Expected 0 services initially, got %d", count)
	}

	services := manager.GetServiceList()
	if len(services) != 0 {
		t.Errorf("Expected empty service list initially, got %v", services)
	}
}

func TestManager_AddSimpleService(t *testing.T) {
	// Create a mock HTTP server for Caddy admin API
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/load" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	manager := NewManager(mockServer.URL)

	tests := []struct {
		name         string
		hostname     string
		backend      string
		protocol     string
		websocket    bool
		httpRedirect bool
		listenOn     string
		wantErr      bool
	}{
		{
			name:         "valid HTTPS service",
			hostname:     "example.com",
			backend:      "localhost:8080",
			protocol:     "https",
			websocket:    false,
			httpRedirect: false,
			listenOn:     "",
			wantErr:      false,
		},
		{
			name:         "valid WebSocket service",
			hostname:     "ws.example.com",
			backend:      "localhost:8081",
			protocol:     "https",
			websocket:    true,
			httpRedirect: false,
			listenOn:     "",
			wantErr:      false,
		},
		{
			name:         "valid HTTP with redirect",
			hostname:     "redirect.example.com",
			backend:      "localhost:8082",
			protocol:     "https",
			websocket:    false,
			httpRedirect: true,
			listenOn:     "both",
			wantErr:      false,
		},
		{
			name:         "invalid empty hostname",
			hostname:     "",
			backend:      "localhost:8080",
			protocol:     "https",
			websocket:    false,
			httpRedirect: false,
			listenOn:     "",
			wantErr:      true,
		},
		{
			name:         "invalid empty backend",
			hostname:     "example.com",
			backend:      "",
			protocol:     "https",
			websocket:    false,
			httpRedirect: false,
			listenOn:     "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.AddSimpleService(tt.hostname, tt.backend, tt.protocol, tt.websocket, tt.httpRedirect, tt.listenOn)

			if (err != nil) != tt.wantErr {
				t.Errorf("AddSimpleService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify service was added
				if count := manager.GetServiceCount(); count == 0 {
					t.Error("Service was not added to manager")
				}

				services := manager.GetServiceList()
				found := false
				for _, service := range services {
					if service == tt.hostname {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Service %s not found in service list", tt.hostname)
				}

				// Verify service configuration
				manager.mu.RLock()
				service, exists := manager.simpleServices[tt.hostname]
				manager.mu.RUnlock()

				if !exists {
					t.Errorf("Service %s not found in simpleServices map", tt.hostname)
				} else {
					if service.Hostname != tt.hostname {
						t.Errorf("Expected hostname %s, got %s", tt.hostname, service.Hostname)
					}
					if service.Backend != tt.backend {
						t.Errorf("Expected backend %s, got %s", tt.backend, service.Backend)
					}
					if service.Protocol != tt.protocol {
						t.Errorf("Expected protocol %s, got %s", tt.protocol, service.Protocol)
					}
					if service.WebSocket != tt.websocket {
						t.Errorf("Expected websocket %t, got %t", tt.websocket, service.WebSocket)
					}
					if service.HTTPRedirect != tt.httpRedirect {
						t.Errorf("Expected httpRedirect %t, got %t", tt.httpRedirect, service.HTTPRedirect)
					}
					if service.ListenOn != tt.listenOn {
						t.Errorf("Expected listenOn %s, got %s", tt.listenOn, service.ListenOn)
					}
				}
			}
		})
	}
}

func TestManager_AddEnhancedService(t *testing.T) {
	// Create a mock HTTP server for Caddy admin API
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/load" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	manager := NewManager(mockServer.URL)

	tests := []struct {
		name    string
		service *EnhancedServiceConfig
		wantErr bool
	}{
		{
			name: "valid enhanced service",
			service: &EnhancedServiceConfig{
				ID:           "test-service",
				Hosts:        []string{"api.example.com"},
				Protocol:     "https",
				WebSocket:    false,
				HTTPRedirect: true,
				ListenOn:     "",
				Routes: []RouteConfig{
					{
						Match: MatchConfig{
							Path: "/api/*",
						},
						Handle: []MiddlewareConfig{
							{
								Type: "reverse_proxy",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid WebSocket enhanced service",
			service: &EnhancedServiceConfig{
				ID:           "ws-service",
				Hosts:        []string{"ws.example.com"},
				Protocol:     "https",
				WebSocket:    true,
				HTTPRedirect: false,
				ListenOn:     "",
				Routes: []RouteConfig{
					{
						Match: MatchConfig{
							Path: "/ws",
						},
						Handle: []MiddlewareConfig{
							{
								Type: "headers",
								Config: map[string]interface{}{
									"request": map[string]interface{}{
										"set": map[string]interface{}{
											"X-WebSocket": []string{"enabled"},
										},
									},
								},
							},
							{
								Type: "reverse_proxy",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid enhanced service - no hosts",
			service: &EnhancedServiceConfig{
				ID:           "invalid-service",
				Hosts:        []string{},
				Protocol:     "https",
				WebSocket:    false,
				HTTPRedirect: false,
				ListenOn:     "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.AddEnhancedService(tt.service)

			if (err != nil) != tt.wantErr {
				t.Errorf("AddEnhancedService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify service was added
				if count := manager.GetServiceCount(); count == 0 {
					t.Error("Enhanced service was not added to manager")
				}

				primaryHost := tt.service.GetPrimaryHost()
				services := manager.GetServiceList()
				found := false
				for _, service := range services {
					if service == primaryHost {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Enhanced service %s not found in service list", primaryHost)
				}

				// Verify service configuration
				manager.mu.RLock()
				service, exists := manager.enhancedServices[primaryHost]
				manager.mu.RUnlock()

				if !exists {
					t.Errorf("Enhanced service %s not found in enhancedServices map", primaryHost)
				} else {
					if service.ID != tt.service.ID {
						t.Errorf("Expected ID %s, got %s", tt.service.ID, service.ID)
					}
					if service.Protocol != tt.service.Protocol {
						t.Errorf("Expected protocol %s, got %s", tt.service.Protocol, service.Protocol)
					}
					if service.WebSocket != tt.service.WebSocket {
						t.Errorf("Expected websocket %t, got %t", tt.service.WebSocket, service.WebSocket)
					}
				}
			}
		})
	}
}

func TestManager_RemoveService(t *testing.T) {
	// Create a mock HTTP server for Caddy admin API
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/load" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	manager := NewManager(mockServer.URL)

	// Add a simple service first
	err := manager.AddSimpleService("example.com", "localhost:8080", "https", false, false, "")
	if err != nil {
		t.Fatalf("Failed to add simple service: %v", err)
	}

	// Add an enhanced service
	enhancedService := &EnhancedServiceConfig{
		ID:           "enhanced-test",
		Hosts:        []string{"enhanced.example.com"},
		Protocol:     "https",
		WebSocket:    false,
		HTTPRedirect: false,
		ListenOn:     "",
	}
	err = manager.AddEnhancedService(enhancedService)
	if err != nil {
		t.Fatalf("Failed to add enhanced service: %v", err)
	}

	// Verify services were added
	if count := manager.GetServiceCount(); count != 2 {
		t.Fatalf("Expected 2 services, got %d", count)
	}

	// Remove simple service
	err = manager.RemoveService("example.com")
	if err != nil {
		t.Errorf("Failed to remove simple service: %v", err)
	}

	// Verify simple service was removed
	if count := manager.GetServiceCount(); count != 1 {
		t.Errorf("Expected 1 service after removal, got %d", count)
	}

	manager.mu.RLock()
	_, exists := manager.simpleServices["example.com"]
	manager.mu.RUnlock()
	if exists {
		t.Error("Simple service still exists after removal")
	}

	// Remove enhanced service
	err = manager.RemoveService("enhanced.example.com")
	if err != nil {
		t.Errorf("Failed to remove enhanced service: %v", err)
	}

	// Verify enhanced service was removed
	if count := manager.GetServiceCount(); count != 0 {
		t.Errorf("Expected 0 services after removal, got %d", count)
	}

	manager.mu.RLock()
	_, exists = manager.enhancedServices["enhanced.example.com"]
	manager.mu.RUnlock()
	if exists {
		t.Error("Enhanced service still exists after removal")
	}
}

func TestManager_GenerateCompleteConfiguration(t *testing.T) {
	manager := NewManager("http://localhost:2019")

	// Test empty configuration
	config := manager.generateCompleteConfiguration()
	if config == nil {
		t.Fatal("generateCompleteConfiguration returned nil")
	}

	// Verify basic structure
	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		t.Error("Missing or invalid apps section")
	}

	http, ok := apps["http"].(map[string]interface{})
	if !ok {
		t.Error("Missing or invalid http app")
	}

	servers, ok := http["servers"].(map[string]interface{})
	if !ok {
		t.Error("Missing or invalid servers section")
	}

	// Should have no servers initially
	if len(servers) != 0 {
		t.Errorf("Expected 0 servers initially, got %d", len(servers))
	}

	// Add services and test configuration generation
	manager.simpleServices["example.com"] = &ServiceConfig{
		Name:         "example.com",
		Hostname:     "example.com",
		Backend:      "localhost:8080",
		Protocol:     "https",
		WebSocket:    false,
		HTTPRedirect: false,
		ListenOn:     "",
	}

	manager.simpleServices["ws.example.com"] = &ServiceConfig{
		Name:         "ws.example.com",
		Hostname:     "ws.example.com",
		Backend:      "localhost:8081",
		Protocol:     "https",
		WebSocket:    true,
		HTTPRedirect: false,
		ListenOn:     "",
	}

	config = manager.generateCompleteConfiguration()
	apps = config["apps"].(map[string]interface{})
	http = apps["http"].(map[string]interface{})
	servers = http["servers"].(map[string]interface{})

	// Should have HTTPS server
	httpsServer, ok := servers["https"].(map[string]interface{})
	if !ok {
		t.Error("Missing HTTPS server")
	}

	// Check protocols - should be HTTP/1.1 only due to WebSocket
	protocols, ok := httpsServer["protocols"].([]string)
	if !ok {
		t.Error("Missing protocols configuration")
	}
	if len(protocols) != 1 || protocols[0] != "h1" {
		t.Errorf("Expected [h1] protocols for WebSocket, got %v", protocols)
	}

	// Verify routes exist
	routes, ok := httpsServer["routes"].([]map[string]interface{})
	if !ok {
		t.Error("Missing routes in HTTPS server")
	}
	if len(routes) < 2 { // At least 2 service routes + default route
		t.Errorf("Expected at least 2 routes, got %d", len(routes))
	}
}

func TestManager_WebSocketDetection(t *testing.T) {
	manager := NewManager("http://localhost:2019")

	// Test no WebSocket services
	if manager.hasWebSocketServices() {
		t.Error("Expected no WebSocket services initially")
	}

	// Add non-WebSocket service
	manager.simpleServices["example.com"] = &ServiceConfig{
		WebSocket: false,
	}

	if manager.hasWebSocketServices() {
		t.Error("Expected no WebSocket services with non-WebSocket simple service")
	}

	// Add WebSocket simple service
	manager.simpleServices["ws.example.com"] = &ServiceConfig{
		WebSocket: true,
	}

	if !manager.hasWebSocketServices() {
		t.Error("Expected WebSocket services with WebSocket simple service")
	}

	// Clear simple services and test enhanced services
	manager.simpleServices = make(map[string]*ServiceConfig)

	if manager.hasWebSocketServices() {
		t.Error("Expected no WebSocket services after clearing simple services")
	}

	// Add non-WebSocket enhanced service
	manager.enhancedServices["api.example.com"] = &EnhancedServiceConfig{
		WebSocket: false,
	}

	if manager.hasWebSocketServices() {
		t.Error("Expected no WebSocket services with non-WebSocket enhanced service")
	}

	// Add WebSocket enhanced service
	manager.enhancedServices["ws-api.example.com"] = &EnhancedServiceConfig{
		WebSocket: true,
	}

	if !manager.hasWebSocketServices() {
		t.Error("Expected WebSocket services with WebSocket enhanced service")
	}
}

func TestManager_ProtocolSupport(t *testing.T) {
	manager := NewManager("http://localhost:2019")

	tests := []struct {
		listenOn    string
		expectHTTPS bool
		expectHTTP  bool
	}{
		{"", true, true},       // Default to HTTPS, but also supports HTTP in some contexts
		{"https", true, false}, // HTTPS only
		{"http", false, true},  // HTTP only
		{"both", true, true},   // Both protocols
		{":443", false, false}, // Custom port - not recognized as protocol indicator
		{":80", false, false},  // Custom port - not recognized as protocol indicator
	}

	for _, tt := range tests {
		t.Run("listenOn_"+tt.listenOn, func(t *testing.T) {
			if got := manager.serviceSupportsHTTPS(tt.listenOn); got != tt.expectHTTPS {
				t.Errorf("serviceSupportsHTTPS(%s) = %v, want %v", tt.listenOn, got, tt.expectHTTPS)
			}
			if got := manager.serviceSupportsHTTP(tt.listenOn); got != tt.expectHTTP {
				t.Errorf("serviceSupportsHTTP(%s) = %v, want %v", tt.listenOn, got, tt.expectHTTP)
			}
		})
	}
}

func TestManager_ConfigurationValidation(t *testing.T) {
	// Test with failing validation
	failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Configuration error"))
	}))
	defer failingServer.Close()

	manager := NewManager(failingServer.URL)

	// This should fail due to server error
	err := manager.AddSimpleService("example.com", "localhost:8080", "https", false, false, "")
	if err == nil {
		t.Error("Expected error when Caddy API returns error, got nil")
	}
	if !strings.Contains(err.Error(), "non-200 status") {
		t.Errorf("Expected non-200 status error, got: %v", err)
	}
}

func TestManager_ConcurrentAccess(t *testing.T) {
	// Create a mock HTTP server for Caddy admin API
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/load" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	manager := NewManager(mockServer.URL)

	// Test concurrent access to manager methods
	done := make(chan bool, 3)

	// Goroutine 1: Add services
	go func() {
		for i := 0; i < 5; i++ {
			hostname := fmt.Sprintf("test%d.example.com", i)
			manager.AddSimpleService(hostname, "localhost:8080", "https", false, false, "")
		}
		done <- true
	}()

	// Goroutine 2: Get service count
	go func() {
		for i := 0; i < 10; i++ {
			manager.GetServiceCount()
		}
		done <- true
	}()

	// Goroutine 3: Get service list
	go func() {
		for i := 0; i < 10; i++ {
			manager.GetServiceList()
		}
		done <- true
	}()

	// Wait for all goroutines to complete
	for i := 0; i < 3; i++ {
		<-done
	}

	// Verify final state
	if count := manager.GetServiceCount(); count < 0 {
		t.Errorf("Invalid service count after concurrent access: %d", count)
	}
}

func TestManager_JSONSerialization(t *testing.T) {
	manager := NewManager("http://localhost:2019")

	// Add services
	manager.simpleServices["example.com"] = &ServiceConfig{
		Name:         "example.com",
		Hostname:     "example.com",
		Backend:      "localhost:8080",
		Protocol:     "https",
		WebSocket:    false,
		HTTPRedirect: false,
		ListenOn:     "",
	}

	config := manager.generateCompleteConfiguration()

	// Test JSON serialization
	jsonBytes, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal configuration to JSON: %v", err)
	}

	// Test JSON deserialization
	var unmarshaled map[string]interface{}
	err = json.Unmarshal(jsonBytes, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal configuration from JSON: %v", err)
	}

	// Verify structure is preserved
	apps, ok := unmarshaled["apps"].(map[string]interface{})
	if !ok {
		t.Error("Apps section lost during JSON serialization")
	}

	http, ok := apps["http"].(map[string]interface{})
	if !ok {
		t.Error("HTTP app lost during JSON serialization")
	}

	servers, ok := http["servers"].(map[string]interface{})
	if !ok {
		t.Error("Servers section lost during JSON serialization")
	}

	if len(servers) == 0 {
		t.Error("No servers found after JSON serialization")
	}
}
