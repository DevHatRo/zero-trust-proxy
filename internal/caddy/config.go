package caddy

import (
	"fmt"
	"strings"

	"github.com/devhatro/zero-trust-proxy/internal/logger"
)

// GenerateServiceConfig generates a Caddy configuration for a single service
func GenerateServiceConfig(serviceName string, hostname string, backend string, protocol string, websocket bool, httpRedirect bool, listenOn string) map[string]interface{} {
	logger.Debug("🔧 Generating Caddy config for service: %s", serviceName)
	logger.Debug("🔧 Parameters: hostname=%s, backend=%s, protocol=%s, websocket=%t, httpRedirect=%t, listenOn=%s",
		hostname, backend, protocol, websocket, httpRedirect, listenOn)

	// Input validation
	if hostname == "" {
		logger.Error("💥 Hostname cannot be empty")
		return map[string]interface{}{
			"error": "hostname cannot be empty",
		}
	}

	if backend == "" {
		logger.Error("💥 Backend cannot be empty")
		return map[string]interface{}{
			"error": "backend cannot be empty",
		}
	}

	// Determine listen addresses based on protocol and listenOn
	var listenAddresses []string
	if listenOn != "" {
		// Custom listen address specified
		if protocol == "http" {
			listenAddresses = []string{listenOn}
		} else if protocol == "https" {
			listenAddresses = []string{listenOn}
		} else if protocol == "both" {
			// For both protocols, we need separate servers
			// This is handled in the server logic - for single service, default to HTTPS
			listenAddresses = []string{listenOn}
		} else {
			listenAddresses = []string{listenOn}
		}
	} else {
		// Default listen addresses
		if protocol == "http" {
			listenAddresses = []string{":80"}
		} else if protocol == "https" {
			listenAddresses = []string{":443"}
		} else if protocol == "both" {
			// For both protocols with single service, default to HTTPS
			listenAddresses = []string{":443"}
		} else {
			// Default to HTTPS
			listenAddresses = []string{":443"}
		}
	}

	logger.Debug("🔌 Listen addresses: %v", listenAddresses)

	// Create the server configuration
	serverConfig := map[string]interface{}{
		"listen": listenAddresses,
		"routes": []map[string]interface{}{
			{
				"match": []map[string]interface{}{
					{
						"host": []string{hostname},
					},
				},
				"handle": createHandlers(backend, websocket, httpRedirect, protocol),
			},
		},
	}

	// Add TLS configuration for HTTPS
	if protocol == "https" || protocol == "both" {
		logger.Debug("🔐 Adding TLS configuration for HTTPS")
		serverConfig["tls_connection_policies"] = []map[string]interface{}{
			{
				"match": map[string]interface{}{
					"sni": []string{hostname},
				},
			},
		}
	}

	config := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					serviceName: serverConfig,
				},
			},
		},
	}

	// Add TLS app configuration for automatic HTTPS
	if protocol == "https" || protocol == "both" {
		logger.Debug("🔐 Adding TLS app configuration")
		config["apps"].(map[string]interface{})["tls"] = map[string]interface{}{
			"automation": map[string]interface{}{
				"policies": []map[string]interface{}{
					{
						"subjects": []string{hostname},
					},
				},
			},
		}
	}

	logger.Debug("✅ Caddy configuration generated successfully")
	return config
}

// createHandlers creates the appropriate handlers based on service configuration
func createHandlers(backend string, websocket bool, httpRedirect bool, protocol string) []map[string]interface{} {
	var handlers []map[string]interface{}

	// Handle HTTP to HTTPS redirect
	if httpRedirect && (protocol == "https" || protocol == "both") {
		logger.Debug("🔀 Adding HTTP to HTTPS redirect handler")
		handlers = append(handlers, map[string]interface{}{
			"handler": "static_response",
			"headers": map[string]interface{}{
				"Location": []string{"https://{http.request.host}{http.request.uri}"},
			},
			"status_code": 301,
		})
		return handlers
	}

	// Add headers handler for proxy headers
	logger.Debug("🌐 Adding headers handler for proxy headers")
	headers := map[string]interface{}{
		"handler": "headers",
		"request": map[string]interface{}{
			"set": map[string]interface{}{
				"Host":              []string{"{http.reverse_proxy.upstream.hostport}"},
				"X-Forwarded-For":   []string{"{http.request.remote}"},
				"X-Forwarded-Proto": []string{"{http.request.scheme}"},
				"X-Forwarded-Host":  []string{"{http.request.host}"},
				"X-Real-IP":         []string{"{http.request.remote.host}"},
			},
		},
	}
	handlers = append(handlers, headers)

	// Create reverse proxy handler
	logger.Debug("🔗 Adding reverse proxy handler for backend: %s", backend)
	proxyHandler := map[string]interface{}{
		"handler": "reverse_proxy",
		"upstreams": []map[string]interface{}{
			{
				"dial": backend,
			},
		},
	}

	// Configure for WebSocket if needed
	if websocket {
		logger.Debug("🔌 Configuring WebSocket support (HTTP/1.1 only)")
		// WebSocket requires HTTP/1.1, disable HTTP/2
		proxyHandler["versions"] = []string{"1.1"}

		// Add WebSocket-specific headers
		headers["request"].(map[string]interface{})["set"].(map[string]interface{})["Connection"] = []string{"{http.request.header.Connection}"}
		headers["request"].(map[string]interface{})["set"].(map[string]interface{})["Upgrade"] = []string{"{http.request.header.Upgrade}"}
		headers["request"].(map[string]interface{})["set"].(map[string]interface{})["Sec-WebSocket-Key"] = []string{"{http.request.header.Sec-WebSocket-Key}"}
		headers["request"].(map[string]interface{})["set"].(map[string]interface{})["Sec-WebSocket-Version"] = []string{"{http.request.header.Sec-WebSocket-Version}"}
		headers["request"].(map[string]interface{})["set"].(map[string]interface{})["Sec-WebSocket-Protocol"] = []string{"{http.request.header.Sec-WebSocket-Protocol}"}
		headers["request"].(map[string]interface{})["set"].(map[string]interface{})["Sec-WebSocket-Extensions"] = []string{"{http.request.header.Sec-WebSocket-Extensions}"}
	}

	handlers = append(handlers, proxyHandler)

	logger.Debug("✅ Created %d handlers for service", len(handlers))
	return handlers
}

// GenerateMultiServiceConfig generates a Caddy configuration for multiple services
// This is used by the server for complex multi-service configurations
func GenerateMultiServiceConfig(services []ServiceConfig) map[string]interface{} {
	logger.Debug("🔧 Generating multi-service Caddy configuration for %d services", len(services))

	if len(services) == 0 {
		logger.Error("💥 No services provided for multi-service configuration")
		return map[string]interface{}{
			"error": "no services provided",
		}
	}

	servers := make(map[string]interface{})
	tlsPolicies := []map[string]interface{}{}
	allHostnames := []string{}

	// Group services by listen address and protocol
	httpServices := []ServiceConfig{}
	httpsServices := []ServiceConfig{}

	for _, service := range services {
		if service.Protocol == "http" {
			httpServices = append(httpServices, service)
		} else {
			httpsServices = append(httpsServices, service)
			allHostnames = append(allHostnames, service.Hostname)
		}
	}

	// Create HTTP server if needed
	if len(httpServices) > 0 {
		logger.Debug("🌐 Creating HTTP server for %d services", len(httpServices))
		servers["http"] = createServerConfig(httpServices, ":80", false)
	}

	// Create HTTPS server if needed
	if len(httpsServices) > 0 {
		logger.Debug("🔐 Creating HTTPS server for %d services", len(httpsServices))
		servers["https"] = createServerConfig(httpsServices, ":443", true)

		// Add TLS policies for all HTTPS hostnames
		if len(allHostnames) > 0 {
			tlsPolicies = append(tlsPolicies, map[string]interface{}{
				"subjects": allHostnames,
			})
		}
	}

	config := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": servers,
			},
		},
	}

	// Add TLS app if we have HTTPS services
	if len(tlsPolicies) > 0 {
		logger.Debug("🔐 Adding TLS app configuration for %d policies", len(tlsPolicies))
		config["apps"].(map[string]interface{})["tls"] = map[string]interface{}{
			"automation": map[string]interface{}{
				"policies": tlsPolicies,
			},
		}
	}

	logger.Debug("✅ Multi-service Caddy configuration generated successfully")
	return config
}

// ServiceConfig represents a service configuration
type ServiceConfig struct {
	Name         string `json:"name"`
	Hostname     string `json:"hostname"`
	Backend      string `json:"backend"`
	Protocol     string `json:"protocol"`
	WebSocket    bool   `json:"websocket"`
	HTTPRedirect bool   `json:"http_redirect"`
	ListenOn     string `json:"listen_on"`
}

// createServerConfig creates a server configuration for a group of services
func createServerConfig(services []ServiceConfig, defaultListen string, tls bool) map[string]interface{} {
	routes := []map[string]interface{}{}

	for _, service := range services {
		logger.Debug("🔧 Adding route for service: %s (hostname: %s)", service.Name, service.Hostname)

		route := map[string]interface{}{
			"match": []map[string]interface{}{
				{
					"host": []string{service.Hostname},
				},
			},
			"handle": createHandlers(service.Backend, service.WebSocket, service.HTTPRedirect, service.Protocol),
		}
		routes = append(routes, route)
	}

	serverConfig := map[string]interface{}{
		"listen": []string{defaultListen},
		"routes": routes,
	}

	// Add TLS connection policies for HTTPS
	if tls {
		logger.Debug("🔐 Adding TLS connection policies")
		policies := []map[string]interface{}{}
		for _, service := range services {
			policies = append(policies, map[string]interface{}{
				"match": map[string]interface{}{
					"sni": []string{service.Hostname},
				},
			})
		}
		serverConfig["tls_connection_policies"] = policies
	}

	return serverConfig
}

// ValidateServiceInput validates service input parameters
func ValidateServiceInput(hostname, backend string) error {
	logger.Debug("🔧 Validating service input parameters")

	if hostname == "" {
		logger.Error("💥 Hostname validation failed: empty hostname")
		return fmt.Errorf("hostname cannot be empty")
	}

	if backend == "" {
		logger.Error("💥 Backend validation failed: empty backend")
		return fmt.Errorf("backend cannot be empty")
	}

	// Basic hostname validation
	if strings.Contains(hostname, " ") {
		logger.Error("💥 Hostname validation failed: contains spaces")
		return fmt.Errorf("hostname cannot contain spaces")
	}

	// Basic backend validation (should be host:port format)
	if !strings.Contains(backend, ":") {
		logger.Warn("⚠️ Backend format warning: missing port (recommended format: host:port)")
	}

	logger.Debug("✅ Service input validation passed")
	return nil
}
