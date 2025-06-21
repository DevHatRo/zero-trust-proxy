package caddy

import (
	"testing"
)

func TestValidator_ValidateServiceConfig(t *testing.T) {
	validator := NewValidator("")

	tests := []struct {
		name         string
		serviceName  string
		hostname     string
		backend      string
		protocol     string
		websocket    bool
		httpRedirect bool
		listenOn     string
		wantErr      bool
	}{
		{
			name:         "valid https service",
			serviceName:  "test-service",
			hostname:     "example.com",
			backend:      "127.0.0.1:8080",
			protocol:     "https",
			websocket:    false,
			httpRedirect: false,
			listenOn:     "https",
			wantErr:      false,
		},
		{
			name:         "valid websocket service",
			serviceName:  "websocket-service",
			hostname:     "ws.example.com",
			backend:      "127.0.0.1:8080",
			protocol:     "https",
			websocket:    true,
			httpRedirect: false,
			listenOn:     "https",
			wantErr:      false,
		},
		{
			name:         "valid http with redirect",
			serviceName:  "redirect-service",
			hostname:     "redirect.example.com",
			backend:      "127.0.0.1:8080",
			protocol:     "https",
			websocket:    false,
			httpRedirect: true,
			listenOn:     "both",
			wantErr:      false,
		},
		{
			name:         "invalid empty hostname",
			serviceName:  "invalid-service",
			hostname:     "",
			backend:      "127.0.0.1:8080",
			protocol:     "https",
			websocket:    false,
			httpRedirect: false,
			listenOn:     "https",
			wantErr:      true,
		},
		{
			name:         "invalid empty backend",
			serviceName:  "invalid-backend",
			hostname:     "example.com",
			backend:      "",
			protocol:     "https",
			websocket:    false,
			httpRedirect: false,
			listenOn:     "https",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateServiceConfig(
				tt.serviceName,
				tt.hostname,
				tt.backend,
				tt.protocol,
				tt.websocket,
				tt.httpRedirect,
				tt.listenOn,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateServiceConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateAndValidateServiceConfig(t *testing.T) {
	tests := []struct {
		name         string
		serviceName  string
		hostname     string
		backend      string
		protocol     string
		websocket    bool
		httpRedirect bool
		listenOn     string
	}{
		{
			name:         "https only service",
			serviceName:  "https-service",
			hostname:     "secure.example.com",
			backend:      "127.0.0.1:8080",
			protocol:     "https",
			websocket:    false,
			httpRedirect: false,
			listenOn:     "https",
		},
		{
			name:         "websocket service",
			serviceName:  "ws-service",
			hostname:     "ws.example.com",
			backend:      "127.0.0.1:8080",
			protocol:     "https",
			websocket:    true,
			httpRedirect: false,
			listenOn:     "https",
		},
		{
			name:         "http with redirect",
			serviceName:  "redirect-service",
			hostname:     "redirect.example.com",
			backend:      "127.0.0.1:8080",
			protocol:     "https",
			websocket:    false,
			httpRedirect: true,
			listenOn:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GenerateServiceConfig(
				tt.serviceName,
				tt.hostname,
				tt.backend,
				tt.protocol,
				tt.websocket,
				tt.httpRedirect,
				tt.listenOn,
			)

			// Validate the generated config
			validator := NewValidator("")
			if err := validator.ValidateConfig(config); err != nil {
				t.Errorf("Generated config validation failed: %v", err)
			}

			// Check basic structure
			if config["apps"] == nil {
				t.Error("Generated config missing 'apps' section")
			}

			apps := config["apps"].(map[string]interface{})
			if apps["http"] == nil {
				t.Error("Generated config missing 'apps.http' section")
			}

			httpApp := apps["http"].(map[string]interface{})
			if httpApp["servers"] == nil {
				t.Error("Generated config missing 'apps.http.servers' section")
			}

			servers := httpApp["servers"].(map[string]interface{})

			// Check that the service server exists
			serviceServer, ok := servers[tt.serviceName].(map[string]interface{})
			if !ok {
				t.Errorf("Expected service server '%s' but not found", tt.serviceName)
				return
			}

			// Verify listen addresses
			listen, ok := serviceServer["listen"].([]string)
			if !ok {
				t.Error("Missing or invalid listen addresses")
				return
			}

			expectedListen := ":443" // Default for HTTPS
			if tt.protocol == "http" {
				expectedListen = ":80"
			} else if tt.listenOn != "" {
				expectedListen = tt.listenOn
			}

			if len(listen) != 1 || listen[0] != expectedListen {
				t.Errorf("Expected listen address %s, got %v", expectedListen, listen)
			}

			// Check WebSocket configuration in handlers
			if tt.websocket {
				routes, ok := serviceServer["routes"].([]map[string]interface{})
				if !ok || len(routes) == 0 {
					t.Error("Missing routes for WebSocket service")
					return
				}

				route := routes[0]
				handle, ok := route["handle"].([]map[string]interface{})
				if !ok || len(handle) < 2 {
					t.Error("Expected at least 2 handlers for WebSocket service")
					return
				}

				// Find the reverse_proxy handler
				var proxyHandler map[string]interface{}
				for _, handler := range handle {
					if handler["handler"] == "reverse_proxy" {
						proxyHandler = handler
						break
					}
				}

				if proxyHandler == nil {
					t.Error("Missing reverse_proxy handler for WebSocket service")
					return
				}

				// Check WebSocket-specific configuration
				transport, ok := proxyHandler["transport"].(map[string]interface{})
				if !ok {
					t.Error("Missing transport configuration for WebSocket")
					return
				}

				protocol, ok := transport["protocol"].(string)
				if !ok || protocol != "http" {
					t.Errorf("Expected http protocol in transport, got %v", protocol)
					return
				}

				versions, ok := transport["versions"].([]string)
				if !ok {
					t.Error("Missing versions configuration for WebSocket")
					return
				}
				if len(versions) != 1 || versions[0] != "1.1" {
					t.Errorf("Expected HTTP/1.1 only for WebSocket, got %v", versions)
				}
			}

			// Check redirect configuration
			if tt.httpRedirect && (tt.protocol == "https" || tt.protocol == "both") {
				routes, ok := serviceServer["routes"].([]map[string]interface{})
				if !ok || len(routes) == 0 {
					t.Error("Missing routes for redirect service")
					return
				}

				route := routes[0]
				handle, ok := route["handle"].([]map[string]interface{})
				if !ok || len(handle) == 0 {
					t.Error("Missing handlers for redirect service")
					return
				}

				handler := handle[0]
				if handler["handler"] != "static_response" {
					t.Error("Expected static_response handler for redirect")
				}
				if handler["status_code"] != 301 {
					t.Error("Expected 301 status code for redirect")
				}
			}

			// Check TLS configuration for HTTPS services
			if tt.protocol == "https" || tt.protocol == "both" {
				if !tt.httpRedirect { // Only check TLS for non-redirect services
					tlsPolicies, ok := serviceServer["tls_connection_policies"].([]map[string]interface{})
					if !ok {
						t.Error("Missing TLS connection policies for HTTPS service")
						return
					}

					if len(tlsPolicies) == 0 {
						t.Error("Expected at least one TLS connection policy")
						return
					}

					// Check TLS app configuration
					tlsApp, ok := apps["tls"].(map[string]interface{})
					if !ok {
						t.Error("Missing TLS app for HTTPS service")
						return
					}

					automation, ok := tlsApp["automation"].(map[string]interface{})
					if !ok {
						t.Error("Missing TLS automation")
						return
					}

					policies, ok := automation["policies"].([]map[string]interface{})
					if !ok {
						t.Error("Missing TLS automation policies")
						return
					}

					if len(policies) == 0 {
						t.Error("Expected at least one TLS automation policy")
					}
				}
			}
		})
	}
}

func TestValidator_ValidateConfig(t *testing.T) {
	validator := NewValidator("")

	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
	}{
		{
			name: "valid basic config",
			config: map[string]interface{}{
				"admin": map[string]interface{}{
					"disabled": false,
				},
				"apps": map[string]interface{}{
					"http": map[string]interface{}{
						"servers": map[string]interface{}{
							"srv0": map[string]interface{}{
								"listen": []string{":443"},
								"routes": []map[string]interface{}{
									{
										"match": []map[string]interface{}{
											{
												"host": []string{"example.com"},
											},
										},
										"handle": []map[string]interface{}{
											{
												"handler": "reverse_proxy",
												"upstreams": []map[string]interface{}{
													{
														"dial": "127.0.0.1:8080",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing apps section",
			config: map[string]interface{}{
				"admin": map[string]interface{}{
					"disabled": false,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid server config - missing listen",
			config: map[string]interface{}{
				"apps": map[string]interface{}{
					"http": map[string]interface{}{
						"servers": map[string]interface{}{
							"srv0": map[string]interface{}{
								"routes": []map[string]interface{}{},
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidator_IsCaddyAvailable(t *testing.T) {
	validator := NewValidator("")

	// The result depends on whether Caddy is installed in the test environment
	// We just test that the method returns a boolean
	available := validator.IsCaddyAvailable()

	if available {
		t.Log("Caddy CLI is available in test environment")
	} else {
		t.Log("Caddy CLI is not available in test environment")
	}

	// Test that the validator was properly initialized
	if validator.adminAPI != "" {
		t.Errorf("Expected empty admin API for test validator, got: %s", validator.adminAPI)
	}
}

func TestValidator_CaddyValidationBehavior(t *testing.T) {
	// Test with admin API configured
	validatorWithAPI := NewValidator("http://localhost:2019")

	// Test with no admin API
	validatorNoAPI := NewValidator("")

	// Both should have the same Caddy availability status
	if validatorWithAPI.IsCaddyAvailable() != validatorNoAPI.IsCaddyAvailable() {
		t.Error("Caddy availability should be consistent regardless of admin API configuration")
	}

	// Test validation of a simple valid config
	validConfig := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen": []string{":443"},
						"routes": []map[string]interface{}{
							{
								"match": []map[string]interface{}{
									{
										"host": []string{"example.com"},
									},
								},
								"handle": []map[string]interface{}{
									{
										"handler": "reverse_proxy",
										"upstreams": []map[string]interface{}{
											{
												"dial": "127.0.0.1:8080",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Both validators should accept valid configs
	if err := validatorWithAPI.ValidateConfig(validConfig); err != nil {
		t.Errorf("Validator with API failed on valid config: %v", err)
	}

	if err := validatorNoAPI.ValidateConfig(validConfig); err != nil {
		t.Errorf("Validator without API failed on valid config: %v", err)
	}
}
