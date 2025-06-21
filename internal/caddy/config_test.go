package caddy

import (
	"encoding/json"
	"testing"
)

func TestGenerateServiceConfig(t *testing.T) {
	tests := []struct {
		name         string
		serviceName  string
		hostname     string
		backend      string
		protocol     string
		websocket    bool
		httpRedirect bool
		listenOn     string
		expectError  bool
	}{
		{
			name:         "Simple HTTPS service",
			serviceName:  "test-service",
			hostname:     "example.com",
			backend:      "localhost:8080",
			protocol:     "https",
			websocket:    false,
			httpRedirect: false,
			listenOn:     "https",
			expectError:  false,
		},
		{
			name:         "WebSocket service",
			serviceName:  "ws-service",
			hostname:     "ws.example.com",
			backend:      "localhost:8081",
			protocol:     "https",
			websocket:    true,
			httpRedirect: false,
			listenOn:     "https",
			expectError:  false,
		},
		{
			name:         "HTTP with redirect",
			serviceName:  "redirect-service",
			hostname:     "redirect.example.com",
			backend:      "localhost:8082",
			protocol:     "https",
			websocket:    false,
			httpRedirect: true,
			listenOn:     "both",
			expectError:  false,
		},
		{
			name:         "Empty hostname",
			serviceName:  "invalid-service",
			hostname:     "",
			backend:      "localhost:8080",
			protocol:     "https",
			websocket:    false,
			httpRedirect: false,
			listenOn:     "https",
			expectError:  true,
		},
		{
			name:         "Empty backend",
			serviceName:  "invalid-service",
			hostname:     "example.com",
			backend:      "",
			protocol:     "https",
			websocket:    false,
			httpRedirect: false,
			listenOn:     "https",
			expectError:  true,
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

			// Check for error conditions
			if tt.expectError {
				if _, hasError := config["error"]; !hasError {
					t.Errorf("Expected error but got valid config")
				}
				return
			}

			// Verify the configuration structure
			if _, hasError := config["error"]; hasError {
				t.Errorf("Unexpected error in config: %v", config["error"])
				return
			}

			// Verify apps section
			apps, ok := config["apps"].(map[string]interface{})
			if !ok {
				t.Errorf("Missing or invalid apps section")
				return
			}

			http, ok := apps["http"].(map[string]interface{})
			if !ok {
				t.Errorf("Missing or invalid http app")
				return
			}

			servers, ok := http["servers"].(map[string]interface{})
			if !ok {
				t.Errorf("Missing or invalid servers section")
				return
			}

			// Check that the service server exists
			serviceServer, ok := servers[tt.serviceName].(map[string]interface{})
			if !ok {
				t.Errorf("Missing service server: %s", tt.serviceName)
				return
			}

			// Verify listen addresses
			listen, ok := serviceServer["listen"].([]string)
			if !ok {
				t.Errorf("Missing or invalid listen addresses")
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

			// Verify routes
			routes, ok := serviceServer["routes"].([]map[string]interface{})
			if !ok {
				t.Errorf("Missing or invalid routes")
				return
			}

			if len(routes) == 0 {
				t.Errorf("Expected at least one route")
				return
			}

			// Check the route structure
			route := routes[0]
			match, ok := route["match"].([]map[string]interface{})
			if !ok {
				t.Errorf("Missing or invalid match conditions")
				return
			}

			if len(match) == 0 {
				t.Errorf("Expected at least one match condition")
				return
			}

			// Verify host matching
			hostMatch := match[0]
			hosts, ok := hostMatch["host"].([]string)
			if !ok {
				t.Errorf("Missing or invalid host match")
				return
			}

			if len(hosts) != 1 || hosts[0] != tt.hostname {
				t.Errorf("Expected host %s, got %v", tt.hostname, hosts)
			}

			// Verify handlers
			handle, ok := route["handle"].([]map[string]interface{})
			if !ok {
				t.Errorf("Missing or invalid handlers")
				return
			}

			if tt.httpRedirect && (tt.protocol == "https" || tt.protocol == "both") {
				// Should have redirect handler
				if len(handle) == 0 {
					t.Errorf("Expected redirect handler")
					return
				}
				handler := handle[0]
				if handler["handler"] != "static_response" {
					t.Errorf("Expected static_response handler for redirect")
				}
				if handler["status_code"] != 301 {
					t.Errorf("Expected 301 status code for redirect")
				}
			} else {
				// Should have proxy handlers
				if len(handle) < 2 {
					t.Errorf("Expected at least 2 handlers (headers + reverse_proxy)")
					return
				}

				// Check for headers handler
				headersHandler := handle[0]
				if headersHandler["handler"] != "headers" {
					t.Errorf("Expected headers handler as first handler")
				}

				// Check for reverse_proxy handler
				proxyHandler := handle[1]
				if proxyHandler["handler"] != "reverse_proxy" {
					t.Errorf("Expected reverse_proxy handler as second handler")
				}

				// Verify upstream configuration
				upstreams, ok := proxyHandler["upstreams"].([]map[string]interface{})
				if !ok {
					t.Errorf("Missing or invalid upstreams")
					return
				}

				if len(upstreams) != 1 {
					t.Errorf("Expected exactly one upstream")
					return
				}

				upstream := upstreams[0]
				dial, ok := upstream["dial"].(string)
				if !ok {
					t.Errorf("Missing or invalid dial address")
					return
				}

				if dial != tt.backend {
					t.Errorf("Expected dial address %s, got %s", tt.backend, dial)
				}

				// Check WebSocket configuration
				if tt.websocket {
					versions, ok := proxyHandler["versions"].([]string)
					if !ok {
						t.Errorf("Missing versions configuration for WebSocket")
						return
					}
					if len(versions) != 1 || versions[0] != "1.1" {
						t.Errorf("Expected HTTP/1.1 only for WebSocket, got %v", versions)
					}
				}
			}

			// Verify TLS configuration for HTTPS
			if tt.protocol == "https" || tt.protocol == "both" {
				tlsPolicies, ok := serviceServer["tls_connection_policies"].([]map[string]interface{})
				if !ok {
					t.Errorf("Missing TLS connection policies for HTTPS service")
					return
				}

				if len(tlsPolicies) == 0 {
					t.Errorf("Expected at least one TLS connection policy")
					return
				}

				policy := tlsPolicies[0]
				match, ok := policy["match"].(map[string]interface{})
				if !ok {
					t.Errorf("Missing TLS policy match")
					return
				}

				sni, ok := match["sni"].([]string)
				if !ok {
					t.Errorf("Missing SNI in TLS policy")
					return
				}

				if len(sni) != 1 || sni[0] != tt.hostname {
					t.Errorf("Expected SNI %s, got %v", tt.hostname, sni)
				}

				// Check TLS app configuration
				tlsApp, ok := apps["tls"].(map[string]interface{})
				if !ok {
					t.Errorf("Missing TLS app for HTTPS service")
					return
				}

				automation, ok := tlsApp["automation"].(map[string]interface{})
				if !ok {
					t.Errorf("Missing TLS automation")
					return
				}

				policies, ok := automation["policies"].([]map[string]interface{})
				if !ok {
					t.Errorf("Missing TLS automation policies")
					return
				}

				if len(policies) == 0 {
					t.Errorf("Expected at least one TLS automation policy")
					return
				}

				automationPolicy := policies[0]
				subjects, ok := automationPolicy["subjects"].([]string)
				if !ok {
					t.Errorf("Missing subjects in TLS automation policy")
					return
				}

				if len(subjects) != 1 || subjects[0] != tt.hostname {
					t.Errorf("Expected subject %s, got %v", tt.hostname, subjects)
				}
			}

			// Verify the configuration can be marshaled to JSON
			_, err := json.Marshal(config)
			if err != nil {
				t.Errorf("Failed to marshal config to JSON: %v", err)
			}
		})
	}
}

func TestGenerateServiceConfigRedirect(t *testing.T) {
	config := GenerateServiceConfig(
		"redirect-test",
		"example.com",
		"localhost:8080",
		"https",
		false,
		true, // HTTP redirect enabled
		"",   // Default listen
	)

	// Verify the configuration structure
	if _, hasError := config["error"]; hasError {
		t.Errorf("Unexpected error in config: %v", config["error"])
		return
	}

	// For a redirect service, we should get a redirect handler
	apps := config["apps"].(map[string]interface{})
	http := apps["http"].(map[string]interface{})
	servers := http["servers"].(map[string]interface{})

	serviceServer := servers["redirect-test"].(map[string]interface{})
	routes := serviceServer["routes"].([]map[string]interface{})

	if len(routes) == 0 {
		t.Errorf("Expected redirect route")
		return
	}

	// Check if the route has a redirect handler
	redirectRoute := routes[0]
	handle := redirectRoute["handle"].([]map[string]interface{})
	if len(handle) == 0 {
		t.Errorf("Expected handler in redirect route")
		return
	}

	handler := handle[0]
	if handler["handler"] != "static_response" {
		t.Errorf("Expected static_response handler for redirect")
	}
	if handler["status_code"] != 301 {
		t.Errorf("Expected 301 status code for redirect")
	}

	// Verify redirect location header
	headers, ok := handler["headers"].(map[string]interface{})
	if !ok {
		t.Errorf("Missing headers in redirect handler")
		return
	}

	location, ok := headers["Location"].([]string)
	if !ok {
		t.Errorf("Missing Location header in redirect")
		return
	}

	if len(location) != 1 || location[0] != "https://{http.request.host}{http.request.uri}" {
		t.Errorf("Expected HTTPS redirect location, got %v", location)
	}
}
