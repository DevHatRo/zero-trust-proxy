package caddy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/devhatro/zero-trust-proxy/internal/agent"
	"github.com/devhatro/zero-trust-proxy/internal/logger"
)

// NewManager creates a new enhanced Caddy manager
func NewManager(adminAPI string) *Manager {
	return &Manager{
		adminAPI:         adminAPI,
		config:           make(map[string]*ServiceConfig),
		enhancedServices: make(map[string]*agent.ServiceConfig),
	}
}

// AddService adds or updates a simple service configuration (backward compatibility)
func (cm *Manager) AddService(hostname, backend, protocol string) error {
	return cm.AddServiceWithWebSocket(hostname, backend, protocol, false)
}

// AddServiceWithWebSocket adds or updates a service configuration with WebSocket support
func (cm *Manager) AddServiceWithWebSocket(hostname, backend, protocol string, webSocket bool) error {
	return cm.AddFullServiceConfig(hostname, backend, protocol, webSocket, false, "both")
}

// AddFullServiceConfig adds or updates a service configuration with full options
func (cm *Manager) AddFullServiceConfig(hostname, backend, protocol string, webSocket, httpRedirect bool, listenOn string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Apply default for listenOn if empty
	if listenOn == "" {
		listenOn = "both"
	}

	cm.config[hostname] = &ServiceConfig{
		Hostname:     hostname,
		Backend:      "127.0.0.1:9443", // Always proxy to server's internal API
		Protocol:     protocol,
		WebSocket:    webSocket,
		HTTPRedirect: httpRedirect,
		ListenOn:     listenOn,
	}

	return cm.reloadConfig()
}

// AddEnhancedService adds or updates an enhanced service configuration
func (cm *Manager) AddEnhancedService(serviceConfig *agent.ServiceConfig) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Store enhanced config for advanced Caddy features
	cm.enhancedServices[serviceConfig.Hostname] = serviceConfig

	// Also create simple config for the core proxy functionality
	cm.config[serviceConfig.Hostname] = &ServiceConfig{
		Hostname:     serviceConfig.Hostname,
		Backend:      "127.0.0.1:9443", // Always proxy to server's internal API
		Protocol:     serviceConfig.Protocol,
		WebSocket:    serviceConfig.WebSocket,    // Copy WebSocket flag for simple config compatibility
		HTTPRedirect: serviceConfig.HTTPRedirect, // Copy HTTP redirect setting
		ListenOn:     serviceConfig.ListenOn,     // Copy protocol binding setting
	}

	return cm.reloadConfig()
}

// RemoveService removes a service configuration
func (cm *Manager) RemoveService(hostname string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	delete(cm.config, hostname)
	delete(cm.enhancedServices, hostname)
	return cm.reloadConfig()
}

// GetServiceStats returns statistics about configured services
func (cm *Manager) GetServiceStats() ServiceStats {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	stats := ServiceStats{
		TotalServices: len(cm.config),
	}

	for _, service := range cm.config {
		if cm.serviceSupportsHTTPS(service) {
			stats.HTTPSServices++
		}
		if cm.serviceSupportsHTTP(service) {
			stats.HTTPServices++
		}
		if service.WebSocket {
			stats.WebSocketEnabled++
		}
		if service.HTTPRedirect {
			stats.RedirectEnabled++
		}
	}

	return stats
}

// hasWebSocketEnabledServicesLocked checks for WebSocket services without acquiring mutex (internal use)
func (cm *Manager) hasWebSocketEnabledServicesLocked() bool {
	// Check enhanced services
	for _, enhancedService := range cm.enhancedServices {
		if enhancedService.WebSocket {
			return true
		}
	}

	// Also check simple services for WebSocket support
	for _, service := range cm.config {
		if service.WebSocket {
			return true
		}
	}

	return false
}

// reloadConfig applies the current configuration to Caddy with enhanced features
func (cm *Manager) reloadConfig() error {
	// Check if any services have WebSocket enabled (caller already holds mutex)
	hasWebSocketServices := cm.hasWebSocketEnabledServicesLocked()

	// Build separate servers for HTTP and HTTPS to handle redirects properly
	servers := make(map[string]interface{})

	// Always create HTTPS server if we have any HTTPS services
	if cm.hasHTTPSServices() {
		httpsServer := map[string]interface{}{
			"listen": []string{":443"},
			"routes": cm.buildHTTPSRoutes(),
		}

		// Configure protocols based on WebSocket requirements
		if hasWebSocketServices {
			httpsServer["protocols"] = []string{"h1"}
			logger.Info("🔌 Configuring HTTPS server with HTTP/1.1 only due to WebSocket services")
		} else {
			httpsServer["protocols"] = []string{"h1", "h2"}
			logger.Debug("⚡ Configuring HTTPS server with HTTP/1.1 and HTTP/2 support")
		}

		servers["https"] = httpsServer
	}

	// Create HTTP server for redirects and HTTP-only services
	if cm.hasHTTPServices() {
		httpServer := map[string]interface{}{
			"listen": []string{":80"},
			"routes": cm.buildHTTPRoutes(),
		}

		// HTTP server always uses HTTP/1.1
		httpServer["protocols"] = []string{"h1"}
		servers["http"] = httpServer
	}

	// Create enhanced Caddy config
	caddyConfig := map[string]interface{}{
		"admin": map[string]interface{}{
			"disabled": false,
		},
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": servers,
			},
		},
	}

	// Add custom storage configuration to match server startup
	configDir := "/config/caddy"
	if _, err := os.Stat(configDir); err == nil {
		// Directory exists, use custom storage
		caddyConfig["storage"] = map[string]interface{}{
			"module": "file_system",
			"root":   configDir,
		}
		logger.Debug("📁 Using custom certificate storage for config reload: %s", configDir)
	}

	// Convert to JSON
	configJSON, err := json.Marshal(caddyConfig)
	if err != nil {
		return fmt.Errorf("❌ failed to marshal Caddy config: %w", err)
	}

	// POST to Caddy admin API
	resp, err := http.Post(cm.adminAPI+"/load", "application/json", bytes.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("❌ failed to POST to Caddy admin API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("❌ Caddy API returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
	}

	logger.Info("✅ Successfully reloaded enhanced Caddy configuration with %d services", len(cm.config))
	return nil
}

// hasHTTPSServices checks if any services need HTTPS
func (cm *Manager) hasHTTPSServices() bool {
	for _, service := range cm.config {
		if cm.serviceSupportsHTTPS(service) {
			return true
		}
	}
	return false
}

// hasHTTPServices checks if any services need HTTP
func (cm *Manager) hasHTTPServices() bool {
	for _, service := range cm.config {
		if cm.serviceSupportsHTTP(service) {
			return true
		}
	}
	return false
}

// serviceSupportsHTTPS checks if a service supports HTTPS connections
func (cm *Manager) serviceSupportsHTTPS(service *ServiceConfig) bool {
	return service.ListenOn == "https" || service.ListenOn == "both" || service.ListenOn == ""
}

// serviceSupportsHTTP checks if a service supports HTTP connections
func (cm *Manager) serviceSupportsHTTP(service *ServiceConfig) bool {
	return service.ListenOn == "http" || service.ListenOn == "both" || service.ListenOn == ""
}

// buildHTTPSRoutes builds routes for HTTPS server
func (cm *Manager) buildHTTPSRoutes() []map[string]interface{} {
	var routes []map[string]interface{}

	// Build routes for each service that supports HTTPS
	for hostname, service := range cm.config {
		enhancedService := cm.enhancedServices[hostname]

		if cm.serviceSupportsHTTPS(service) {
			if enhancedService != nil {
				// Use enhanced service configuration for advanced routing
				routes = append(routes, cm.buildEnhancedServiceRoutes(service, enhancedService)...)
			} else {
				// Use simple service configuration for backward compatibility
				routes = append(routes, cm.buildSimpleServiceRoute(service))
			}
		}
	}

	// Add default route for unmatched hosts
	routes = append(routes, map[string]interface{}{
		"match": []map[string]interface{}{
			{
				"host": []string{"*"},
			},
		},
		"handle": []map[string]interface{}{
			{
				"handler":     "static_response",
				"body":        "No HTTPS service configured for this hostname",
				"status_code": 404,
			},
		},
	})

	return routes
}

// buildHTTPRoutes builds routes for HTTP server (redirects and HTTP-only services)
func (cm *Manager) buildHTTPRoutes() []map[string]interface{} {
	var routes []map[string]interface{}

	// First, add HTTP to HTTPS redirect routes
	for hostname, service := range cm.config {
		if service.HTTPRedirect && cm.serviceSupportsHTTPS(service) {
			redirectRoute := map[string]interface{}{
				"match": []map[string]interface{}{
					{
						"host": []string{hostname},
					},
				},
				"handle": []map[string]interface{}{
					{
						"handler":     "static_response",
						"status_code": 301, // Permanent redirect
						"headers": map[string][]string{
							"Location": {"https://{http.request.host}{http.request.uri}"},
						},
					},
				},
			}
			routes = append(routes, redirectRoute)
			logger.Debug("🔀 Added HTTP to HTTPS redirect for: %s", hostname)
		}
	}

	// Add HTTP-only services (no redirect)
	for hostname, service := range cm.config {
		enhancedService := cm.enhancedServices[hostname]

		if cm.serviceSupportsHTTP(service) && !service.HTTPRedirect {
			if enhancedService != nil {
				routes = append(routes, cm.buildEnhancedServiceHTTPRoutes(service, enhancedService)...)
			} else {
				routes = append(routes, cm.buildSimpleServiceHTTPRoute(service))
			}
		}
	}

	// Add default route for unmatched hosts
	routes = append(routes, map[string]interface{}{
		"match": []map[string]interface{}{
			{
				"host": []string{"*"},
			},
		},
		"handle": []map[string]interface{}{
			{
				"handler":     "static_response",
				"body":        "No HTTP service configured for this hostname",
				"status_code": 404,
			},
		},
	})

	return routes
}

// buildEnhancedServiceRoutes builds routes for enhanced service configurations
func (cm *Manager) buildEnhancedServiceRoutes(service *ServiceConfig, enhancedService *agent.ServiceConfig) []map[string]interface{} {
	var routes []map[string]interface{}

	// Process each route configuration from the enhanced service
	for _, routeConfig := range enhancedService.Routes {
		route := map[string]interface{}{
			"match":  cm.buildMatchConditions(service.Hostname, &routeConfig.Match),
			"handle": cm.buildEnhancedHandlers(service, enhancedService, &routeConfig),
		}
		routes = append(routes, route)
	}

	// If no routes defined, create a default route
	if len(enhancedService.Routes) == 0 {
		routes = append(routes, cm.buildSimpleServiceRoute(service))
	}

	return routes
}

// buildSimpleServiceRoute builds a simple route for backward compatibility
func (cm *Manager) buildSimpleServiceRoute(service *ServiceConfig) map[string]interface{} {
	// Check if this is a WebSocket-enabled simple service
	requestHeaders := map[string][]string{
		// Only essential proxy headers
		"Host":              {service.Hostname},             // Preserve original host
		"X-Forwarded-Proto": {"https"},                      // Original protocol
		"X-Forwarded-Host":  {"{http.request.host}"},        // Original host
		"X-Real-IP":         {"{http.request.remote.host}"}, // Client IP (correct Caddy v2 placeholder)
		"X-Forwarded-For":   {"{http.request.remote.host}"}, // Client IP for proxy chain
		"X-Agent-Config":    {"simple"},                     // Config type
	}

	// Add WebSocket identification if enabled
	if service.WebSocket {
		requestHeaders["X-WebSocket-Enabled"] = []string{"true"}
		logger.Debug("🔌 Simple service %s: WebSocket support enabled", service.Hostname)
	}

	return map[string]interface{}{
		"match": []map[string]interface{}{
			{
				"host": []string{service.Hostname},
			},
		},
		"handle": []map[string]interface{}{
			// Single reverse proxy handler with transparent header passthrough
			{
				"handler": "reverse_proxy",
				"upstreams": []map[string]interface{}{
					{
						"dial": "127.0.0.1:9443", // Always proxy to server's internal API
					},
				},
				"transport": map[string]interface{}{
					"protocol": "http",
					"tls": map[string]interface{}{
						"server_name":          "127.0.0.1",
						"insecure_skip_verify": true, // Skip verification for localhost
					},
				},
				// transparent header passthrough for simple services too
				"headers": map[string]interface{}{
					"request": map[string]interface{}{
						"set": requestHeaders,
						// Let ALL other headers pass through transparently
					},
				},
				// No handle_response - let responses pass through transparently
			},
		},
	}
}

// buildEnhancedServiceHTTPRoutes builds HTTP-only routes for enhanced services
func (cm *Manager) buildEnhancedServiceHTTPRoutes(service *ServiceConfig, enhancedService *agent.ServiceConfig) []map[string]interface{} {
	var routes []map[string]interface{}

	// Process each route configuration from the enhanced service for HTTP
	for _, routeConfig := range enhancedService.Routes {
		route := map[string]interface{}{
			"match":  cm.buildHTTPMatchConditions(service.Hostname, &routeConfig.Match),
			"handle": cm.buildEnhancedHandlers(service, enhancedService, &routeConfig),
		}
		routes = append(routes, route)
	}

	// If no routes defined, create a default HTTP route
	if len(enhancedService.Routes) == 0 {
		routes = append(routes, cm.buildSimpleServiceHTTPRoute(service))
	}

	return routes
}

// buildSimpleServiceHTTPRoute builds an HTTP-only route for simple services
func (cm *Manager) buildSimpleServiceHTTPRoute(service *ServiceConfig) map[string]interface{} {
	requestHeaders := map[string][]string{
		"Host":              {service.Hostname},
		"X-Forwarded-Proto": {"http"}, // HTTP protocol for this route
		"X-Forwarded-Host":  {"{http.request.host}"},
		"X-Real-IP":         {"{http.request.remote.host}"},
		"X-Forwarded-For":   {"{http.request.remote.host}"},
		"X-Agent-Config":    {"simple"},
	}

	if service.WebSocket {
		requestHeaders["X-WebSocket-Enabled"] = []string{"true"}
	}

	return map[string]interface{}{
		"match": []map[string]interface{}{
			{
				"host": []string{service.Hostname},
				// No scheme matcher - this route is only in HTTP server
			},
		},
		"handle": []map[string]interface{}{
			{
				"handler": "reverse_proxy",
				"upstreams": []map[string]interface{}{
					{
						"dial": "127.0.0.1:9443",
					},
				},
				"transport": map[string]interface{}{
					"protocol": "http",
					"tls": map[string]interface{}{
						"server_name":          "127.0.0.1",
						"insecure_skip_verify": true,
					},
				},
				"headers": map[string]interface{}{
					"request": map[string]interface{}{
						"set": requestHeaders,
					},
				},
			},
		},
	}
}

// buildMatchConditions creates Caddy match conditions from agent route config
func (cm *Manager) buildMatchConditions(hostname string, match *agent.MatchConfig) []map[string]interface{} {
	conditions := []map[string]interface{}{
		{
			"host": []string{hostname},
		},
	}

	// Add path matching if specified, but handle wildcard patterns correctly
	if match.Path != "" {
		// For wildcard patterns like "/*" or "*", don't add path matcher (match all paths)
		// For specific paths, use Caddy's path_regexp for proper pattern matching
		if match.Path != "/*" && match.Path != "*" {
			// Use path_regexp for more flexible pattern matching
			if strings.Contains(match.Path, "*") {
				// Convert shell-style wildcards to regex
				regexPattern := strings.ReplaceAll(match.Path, "*", ".*")
				conditions = append(conditions, map[string]interface{}{
					"path_regexp": []string{regexPattern},
				})
			} else {
				// Exact path match
				conditions = append(conditions, map[string]interface{}{
					"path": []string{match.Path},
				})
			}
		}
		// If path is "/*" or "*", don't add any path matcher - this matches ALL paths
	}

	// Add method matching if specified
	if match.Method != "" {
		conditions = append(conditions, map[string]interface{}{
			"method": []string{match.Method},
		})
	}

	// Add header matching if specified
	if len(match.Headers) > 0 {
		headerMatch := make(map[string][]string)
		for key, values := range match.Headers {
			headerMatch[key] = values
		}
		conditions = append(conditions, map[string]interface{}{
			"header": headerMatch,
		})
	}

	return conditions
}

// buildHTTPMatchConditions creates HTTP-specific match conditions
func (cm *Manager) buildHTTPMatchConditions(hostname string, match *agent.MatchConfig) []map[string]interface{} {
	conditions := []map[string]interface{}{
		{
			"host": []string{hostname},
			// No scheme matcher - this route is only in HTTP server
		},
	}

	// Add path matching if specified
	if match.Path != "" && match.Path != "/*" && match.Path != "*" {
		if strings.Contains(match.Path, "*") {
			regexPattern := strings.ReplaceAll(match.Path, "*", ".*")
			conditions = append(conditions, map[string]interface{}{
				"path_regexp": []string{regexPattern},
			})
		} else {
			conditions = append(conditions, map[string]interface{}{
				"path": []string{match.Path},
			})
		}
	}

	// Add method matching if specified
	if match.Method != "" {
		conditions = append(conditions, map[string]interface{}{
			"method": []string{match.Method},
		})
	}

	// Add header matching if specified
	if len(match.Headers) > 0 {
		headerMatch := make(map[string][]string)
		for key, values := range match.Headers {
			headerMatch[key] = values
		}
		conditions = append(conditions, map[string]interface{}{
			"header": headerMatch,
		})
	}

	return conditions
}

// buildEnhancedHandlers creates Caddy handlers from agent middleware configs
func (cm *Manager) buildEnhancedHandlers(service *ServiceConfig, enhancedService *agent.ServiceConfig, routeConfig *agent.RouteConfig) []map[string]interface{} {
	var handlers []map[string]interface{}

	// Process middleware handlers
	for _, middleware := range routeConfig.Handle {
		switch middleware.Type {
		case "headers":
			if handler := cm.buildHeadersHandler(&middleware); handler != nil {
				handlers = append(handlers, handler)
			}
		case "rate_limit":
			if handler := cm.buildRateLimitHandler(&middleware); handler != nil {
				handlers = append(handlers, handler)
			}
		case "reverse_proxy":
			// Always add the reverse proxy handler that points to server's internal API
			handlers = append(handlers, cm.buildReverseProxyHandler(service, enhancedService))
		}
	}

	// Ensure we always have a reverse proxy handler
	hasReverseProxy := false
	for _, handler := range handlers {
		if handler["handler"] == "reverse_proxy" {
			hasReverseProxy = true
			break
		}
	}

	if !hasReverseProxy {
		// Add headers handler first, then reverse proxy handler
		handlers = append(handlers, cm.buildRequestHeadersHandler(service, enhancedService))
		handlers = append(handlers, cm.buildReverseProxyHandler(service, enhancedService))
	}

	return handlers
}

// buildHeadersHandler creates a Caddy headers handler
func (cm *Manager) buildHeadersHandler(middleware *agent.MiddlewareConfig) map[string]interface{} {
	if middleware.Config == nil {
		return nil
	}

	handler := map[string]interface{}{
		"handler": "headers",
	}

	// Add request headers if configured
	if requestConfig, ok := middleware.Config["request"].(map[string]interface{}); ok {
		if setHeaders, ok := requestConfig["set"].(map[string]interface{}); ok {
			if handler["request"] == nil {
				handler["request"] = make(map[string]interface{})
			}
			handler["request"].(map[string]interface{})["set"] = setHeaders
		}
		if addHeaders, ok := requestConfig["add"].(map[string]interface{}); ok {
			if handler["request"] == nil {
				handler["request"] = make(map[string]interface{})
			}
			handler["request"].(map[string]interface{})["add"] = addHeaders
		}
	}

	// Add response headers if configured
	if responseConfig, ok := middleware.Config["response"].(map[string]interface{}); ok {
		if setHeaders, ok := responseConfig["set"].(map[string]interface{}); ok {
			if handler["response"] == nil {
				handler["response"] = make(map[string]interface{})
			}
			handler["response"].(map[string]interface{})["set"] = setHeaders
		}
		if addHeaders, ok := responseConfig["add"].(map[string]interface{}); ok {
			if handler["response"] == nil {
				handler["response"] = make(map[string]interface{})
			}
			handler["response"].(map[string]interface{})["add"] = addHeaders
		}
	}

	return handler
}

// buildRateLimitHandler creates a Caddy rate limit handler (if supported)
func (cm *Manager) buildRateLimitHandler(middleware *agent.MiddlewareConfig) map[string]interface{} {
	// Rate limiting would require a Caddy plugin
	// For now, we'll log that it's configured but not implemented in Caddy
	logger.Info("⚠️  Rate limiting configured for service but requires Caddy plugin")
	return nil
}

// buildReverseProxyHandler creates the main reverse proxy handler
func (cm *Manager) buildReverseProxyHandler(service *ServiceConfig, enhancedService *agent.ServiceConfig) map[string]interface{} {
	// In zero-trust setup, ALL requests go through the server/agent at 127.0.0.1:9443
	backendAddress := "127.0.0.1:9443"

	handler := map[string]interface{}{
		"handler": "reverse_proxy",
		"upstreams": []map[string]interface{}{
			{
				"dial": backendAddress,
			},
		},
		"transport": map[string]interface{}{
			"protocol": "http",
			"tls": map[string]interface{}{
				"server_name":          "127.0.0.1",
				"insecure_skip_verify": true, // Skip verification for backends
			},
		},
		// transparent header passthrough
		"headers": map[string]interface{}{
			"request": map[string]interface{}{
				"set": map[string][]string{
					// Only set essential proxy headers, pass everything else through transparently
					"Host":               {service.Hostname},             // Preserve original host for server routing
					"X-Forwarded-Proto":  {"https"},                      // Original protocol
					"X-Forwarded-Host":   {"{http.request.host}"},        // Original host requested by client
					"X-Real-IP":          {"{http.request.remote.host}"}, // Client IP (correct Caddy v2 placeholder)
					"X-Forwarded-For":    {"{http.request.remote.host}"}, // Client IP for proxy chain
					"X-Forwarded-Server": {"zero-trust-caddy"},           // Identify proxy layer
				},
				// Don't modify any other headers - let WebSocket headers pass through transparently
			},
		},
		// No handle_response - let ALL responses pass through transparently by default
		// This allows WebSocket upgrades, streaming, and all other responses to work naturally
	}

	// Enhanced security features would be configured here
	logger.Debug("🌐 Service %s: configured for transparent header passthrough", service.Hostname)

	return handler
}

// buildRequestHeadersHandler creates a headers handler for setting request headers
func (cm *Manager) buildRequestHeadersHandler(service *ServiceConfig, enhancedService *agent.ServiceConfig) map[string]interface{} {
	requestHeaders := map[string][]string{
		"X-Forwarded-Proto": {"https"},
		"X-Forwarded-Host":  {"{http.request.host}"},
		"X-Real-IP":         {"{http.request.remote.host}"},
		"X-Forwarded-For":   {"{http.request.remote.host}"},
	}

	if enhancedService != nil {
		requestHeaders["X-Agent-Config"] = []string{"enhanced"}
		requestHeaders["X-Service-ID"] = []string{enhancedService.ID}

		if enhancedService.TLS != nil {
			requestHeaders["X-TLS-Configured"] = []string{"true"}
			requestHeaders["X-Service-Protocol"] = []string{enhancedService.Protocol}
		}
	} else {
		requestHeaders["X-Agent-Config"] = []string{"simple"}
	}

	return map[string]interface{}{
		"handler": "headers",
		"request": map[string]interface{}{
			"set": requestHeaders,
		},
		"response": map[string]interface{}{
			"delete": []string{"Server"},
		},
	}
}
