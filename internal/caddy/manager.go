package caddy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/devhatro/zero-trust-proxy/internal/logger"
)

// Manager handles all Caddy configuration and management
type Manager struct {
	adminAPI         string
	mu               sync.RWMutex
	simpleServices   map[string]*ServiceConfig         // hostname -> simple service config
	enhancedServices map[string]*EnhancedServiceConfig // hostname -> enhanced service config
	validator        *Validator
}

// NewManager creates a new comprehensive Caddy manager
func NewManager(adminAPI string) *Manager {
	return &Manager{
		adminAPI:         adminAPI,
		simpleServices:   make(map[string]*ServiceConfig),
		enhancedServices: make(map[string]*EnhancedServiceConfig),
		validator:        NewValidator(adminAPI),
	}
}

// AddSimpleService adds a simple service configuration
func (m *Manager) AddSimpleService(hostname, backend, protocol string, websocket, httpRedirect bool, listenOn string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logger.Info("🌐 Adding simple service: %s -> %s (protocol: %s, websocket: %t, redirect: %t, listen: %s)",
		hostname, backend, protocol, websocket, httpRedirect, listenOn)

	// Validate the service configuration
	testConfig := GenerateServiceConfig("test", hostname, backend, protocol, websocket, httpRedirect, listenOn)
	if err := m.validator.ValidateConfig(testConfig); err != nil {
		return fmt.Errorf("💥 Simple service configuration validation failed: %w", err)
	}

	m.simpleServices[hostname] = &ServiceConfig{
		Name:         hostname,
		Hostname:     hostname,
		Backend:      backend,
		Protocol:     protocol,
		WebSocket:    websocket,
		HTTPRedirect: httpRedirect,
		ListenOn:     listenOn,
	}

	return m.reloadConfiguration()
}

// AddEnhancedService adds an enhanced service configuration
func (m *Manager) AddEnhancedService(service *EnhancedServiceConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logger.Info("🚀 Adding enhanced service: %s (ID: %s, protocol: %s, websocket: %t)",
		service.GetPrimaryHost(), service.ID, service.Protocol, service.WebSocket)

	// Store the enhanced service
	primaryHost := service.GetPrimaryHost()
	if primaryHost == "" {
		return fmt.Errorf("💥 Enhanced service must have at least one host")
	}

	m.enhancedServices[primaryHost] = service

	// Generate and validate the complete configuration
	testConfig := m.generateCompleteConfiguration()
	if err := m.validator.ValidateConfig(testConfig); err != nil {
		// Rollback on validation failure
		delete(m.enhancedServices, primaryHost)
		return fmt.Errorf("💥 Enhanced service configuration validation failed: %w", err)
	}

	return m.reloadConfiguration()
}

// RemoveService removes a service configuration
func (m *Manager) RemoveService(hostname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logger.Info("🗑️ Removing service: %s", hostname)

	delete(m.simpleServices, hostname)
	delete(m.enhancedServices, hostname)

	return m.reloadConfiguration()
}

// reloadConfiguration applies the current configuration to Caddy
func (m *Manager) reloadConfiguration() error {
	config := m.generateCompleteConfiguration()

	// Validate before applying
	if err := m.validator.ValidateConfig(config); err != nil {
		return fmt.Errorf("💥 Configuration validation failed: %w", err)
	}

	logger.Debug("✅ Configuration validation passed")

	// Convert to JSON
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("💥 Failed to marshal Caddy config: %w", err)
	}

	// POST to Caddy admin API
	resp, err := http.Post(m.adminAPI+"/load", "application/json", bytes.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("💥 Failed to POST to Caddy admin API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("💥 Caddy API returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
	}

	totalServices := len(m.simpleServices) + len(m.enhancedServices)
	logger.Info("✅ Successfully reloaded Caddy configuration with %d services", totalServices)
	return nil
}

// generateCompleteConfiguration creates the full Caddy configuration
func (m *Manager) generateCompleteConfiguration() map[string]interface{} {
	logger.Debug("🔧 Generating complete Caddy configuration")

	// Check for WebSocket services to determine protocol configuration
	hasWebSocketServices := m.hasWebSocketServices()

	servers := make(map[string]interface{})

	// Create HTTPS server if needed
	if m.hasHTTPSServices() {
		httpsServer := map[string]interface{}{
			"listen": []string{":443"},
			"routes": m.buildHTTPSRoutes(),
		}

		// Configure protocols based on WebSocket requirements
		if hasWebSocketServices {
			httpsServer["protocols"] = []string{"h1"}
			logger.Debug("🔌 Configuring HTTPS server with HTTP/1.1 only due to WebSocket services")
		} else {
			httpsServer["protocols"] = []string{"h1", "h2"}
			logger.Debug("⚡ Configuring HTTPS server with HTTP/1.1 and HTTP/2 support")
		}

		servers["https"] = httpsServer
	}

	// Create HTTP server if needed
	if m.hasHTTPServices() {
		httpServer := map[string]interface{}{
			"listen":    []string{":80"},
			"routes":    m.buildHTTPRoutes(),
			"protocols": []string{"h1"},
		}
		servers["http"] = httpServer
	}

	// Create the complete configuration
	config := map[string]interface{}{
		"admin": map[string]interface{}{
			"disabled": false,
		},
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": servers,
			},
		},
	}

	// Add custom storage configuration
	configDir := "/config/caddy"
	if _, err := os.Stat(configDir); err == nil {
		config["storage"] = map[string]interface{}{
			"module": "file_system",
			"root":   configDir,
		}
		logger.Debug("📁 Using custom certificate storage: %s", configDir)
	}

	return config
}

// hasWebSocketServices checks if any services have WebSocket enabled
func (m *Manager) hasWebSocketServices() bool {
	for _, service := range m.simpleServices {
		if service.WebSocket {
			return true
		}
	}
	for _, service := range m.enhancedServices {
		if service.WebSocket {
			return true
		}
	}
	return false
}

// hasHTTPSServices checks if any services need HTTPS
func (m *Manager) hasHTTPSServices() bool {
	for _, service := range m.simpleServices {
		if m.serviceSupportsHTTPS(service.ListenOn) {
			return true
		}
	}
	for _, service := range m.enhancedServices {
		if m.serviceSupportsHTTPS(service.ListenOn) {
			return true
		}
	}
	return false
}

// hasHTTPServices checks if any services need HTTP
func (m *Manager) hasHTTPServices() bool {
	for _, service := range m.simpleServices {
		if m.serviceSupportsHTTP(service.ListenOn) {
			return true
		}
	}
	for _, service := range m.enhancedServices {
		if m.serviceSupportsHTTP(service.ListenOn) {
			return true
		}
	}
	return false
}

// serviceSupportsHTTPS checks if a service supports HTTPS
func (m *Manager) serviceSupportsHTTPS(listenOn string) bool {
	return listenOn == "https" || listenOn == "both" || listenOn == ""
}

// serviceSupportsHTTP checks if a service supports HTTP
func (m *Manager) serviceSupportsHTTP(listenOn string) bool {
	return listenOn == "http" || listenOn == "both" || listenOn == ""
}

// buildHTTPSRoutes builds routes for the HTTPS server
func (m *Manager) buildHTTPSRoutes() []map[string]interface{} {
	var routes []map[string]interface{}

	// Add simple service routes
	for hostname, service := range m.simpleServices {
		if m.serviceSupportsHTTPS(service.ListenOn) {
			routes = append(routes, m.buildSimpleServiceRoute(service))
			logger.Debug("🔧 Added simple HTTPS route for: %s", hostname)
		}
	}

	// Add enhanced service routes
	for hostname, service := range m.enhancedServices {
		if m.serviceSupportsHTTPS(service.ListenOn) {
			routes = append(routes, m.buildEnhancedServiceRoutes(service)...)
			logger.Debug("🚀 Added enhanced HTTPS routes for: %s", hostname)
		}
	}

	// Add default route for unmatched hosts
	routes = append(routes, map[string]interface{}{
		"match": []map[string]interface{}{
			{"host": []string{"*"}},
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

// buildHTTPRoutes builds routes for the HTTP server
func (m *Manager) buildHTTPRoutes() []map[string]interface{} {
	var routes []map[string]interface{}

	// Add HTTP to HTTPS redirects
	for hostname, service := range m.simpleServices {
		if service.HTTPRedirect && m.serviceSupportsHTTPS(service.ListenOn) {
			routes = append(routes, m.buildHTTPRedirectRoute(hostname))
			logger.Debug("🔀 Added HTTP to HTTPS redirect for: %s", hostname)
		}
	}

	for hostname, service := range m.enhancedServices {
		if service.HTTPRedirect && m.serviceSupportsHTTPS(service.ListenOn) {
			routes = append(routes, m.buildHTTPRedirectRoute(hostname))
			logger.Debug("🔀 Added HTTP to HTTPS redirect for: %s", hostname)
		}
	}

	// Add HTTP-only services
	for hostname, service := range m.simpleServices {
		if m.serviceSupportsHTTP(service.ListenOn) && !service.HTTPRedirect {
			routes = append(routes, m.buildSimpleServiceHTTPRoute(service))
			logger.Debug("🌐 Added HTTP-only route for: %s", hostname)
		}
	}

	for hostname, service := range m.enhancedServices {
		if m.serviceSupportsHTTP(service.ListenOn) && !service.HTTPRedirect {
			routes = append(routes, m.buildEnhancedServiceHTTPRoutes(service)...)
			logger.Debug("🌐 Added enhanced HTTP-only routes for: %s", hostname)
		}
	}

	// Add default route
	routes = append(routes, map[string]interface{}{
		"match": []map[string]interface{}{
			{"host": []string{"*"}},
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

// buildHTTPRedirectRoute builds an HTTP to HTTPS redirect route
func (m *Manager) buildHTTPRedirectRoute(hostname string) map[string]interface{} {
	return map[string]interface{}{
		"match": []map[string]interface{}{
			{"host": []string{hostname}},
		},
		"handle": []map[string]interface{}{
			{
				"handler":     "static_response",
				"status_code": 301,
				"headers": map[string][]string{
					"Location": {"https://{http.request.host}{http.request.uri}"},
				},
			},
		},
	}
}

// buildSimpleServiceRoute builds a route for a simple service
func (m *Manager) buildSimpleServiceRoute(service *ServiceConfig) map[string]interface{} {
	return map[string]interface{}{
		"match": []map[string]interface{}{
			{"host": []string{service.Hostname}},
		},
		"handle": m.buildSimpleServiceHandlers(service),
	}
}

// buildSimpleServiceHTTPRoute builds an HTTP-only route for a simple service
func (m *Manager) buildSimpleServiceHTTPRoute(service *ServiceConfig) map[string]interface{} {
	return map[string]interface{}{
		"match": []map[string]interface{}{
			{"host": []string{service.Hostname}},
		},
		"handle": m.buildSimpleServiceHandlers(service),
	}
}

// buildSimpleServiceHandlers builds handlers for a simple service
func (m *Manager) buildSimpleServiceHandlers(service *ServiceConfig) []map[string]interface{} {
	var handlers []map[string]interface{}

	// Add headers handler
	requestHeaders := map[string][]string{
		"Host":              {service.Hostname},
		"X-Forwarded-Proto": {"https"},
		"X-Forwarded-Host":  {"{http.request.host}"},
		"X-Real-IP":         {"{http.request.remote.host}"},
		"X-Forwarded-For":   {"{http.request.remote.host}"},
		"X-Agent-Config":    {"simple"},
	}

	if service.WebSocket {
		requestHeaders["X-WebSocket-Enabled"] = []string{"true"}
		// Add WebSocket headers for transparent passthrough
		requestHeaders["Connection"] = []string{"{http.request.header.Connection}"}
		requestHeaders["Upgrade"] = []string{"{http.request.header.Upgrade}"}
		requestHeaders["Sec-WebSocket-Key"] = []string{"{http.request.header.Sec-WebSocket-Key}"}
		requestHeaders["Sec-WebSocket-Version"] = []string{"{http.request.header.Sec-WebSocket-Version}"}
		requestHeaders["Sec-WebSocket-Protocol"] = []string{"{http.request.header.Sec-WebSocket-Protocol}"}
		requestHeaders["Sec-WebSocket-Extensions"] = []string{"{http.request.header.Sec-WebSocket-Extensions}"}
	}

	// Create reverse proxy handler
	proxyHandler := map[string]interface{}{
		"handler": "reverse_proxy",
		"upstreams": []map[string]interface{}{
			{"dial": service.Backend},
		},
		"headers": map[string]interface{}{
			"request": map[string]interface{}{
				"set": requestHeaders,
			},
		},
	}

	// Configure transport for zero-trust (if backend is internal)
	if strings.HasPrefix(service.Backend, "127.0.0.1:") || strings.HasPrefix(service.Backend, "localhost:") {
		proxyHandler["transport"] = map[string]interface{}{
			"protocol": "http",
			"tls": map[string]interface{}{
				"server_name":          "127.0.0.1",
				"insecure_skip_verify": true,
			},
		}
	}

	handlers = append(handlers, proxyHandler)
	return handlers
}

// buildEnhancedServiceRoutes builds routes for an enhanced service
func (m *Manager) buildEnhancedServiceRoutes(service *EnhancedServiceConfig) []map[string]interface{} {
	var routes []map[string]interface{}

	// Process each route configuration
	for _, routeConfig := range service.Routes {
		route := map[string]interface{}{
			"match":  m.buildMatchConditions(service.GetPrimaryHost(), &routeConfig.Match),
			"handle": m.buildEnhancedHandlers(service, &routeConfig),
		}
		routes = append(routes, route)
	}

	// If no routes defined, create a default route
	if len(service.Routes) == 0 {
		routes = append(routes, m.buildDefaultEnhancedRoute(service))
	}

	return routes
}

// buildEnhancedServiceHTTPRoutes builds HTTP routes for an enhanced service
func (m *Manager) buildEnhancedServiceHTTPRoutes(service *EnhancedServiceConfig) []map[string]interface{} {
	// For now, use the same logic as HTTPS routes
	// In the future, this could have HTTP-specific logic
	return m.buildEnhancedServiceRoutes(service)
}

// buildDefaultEnhancedRoute builds a default route for an enhanced service
func (m *Manager) buildDefaultEnhancedRoute(service *EnhancedServiceConfig) map[string]interface{} {
	return map[string]interface{}{
		"match": []map[string]interface{}{
			{"host": service.GetAllHosts()},
		},
		"handle": m.buildDefaultEnhancedHandlers(service),
	}
}

// buildMatchConditions builds Caddy match conditions from route config
func (m *Manager) buildMatchConditions(hostname string, match *MatchConfig) []map[string]interface{} {
	conditions := []map[string]interface{}{
		{"host": []string{hostname}},
	}

	// Add path matching
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

	// Add method matching
	if match.Method != "" {
		conditions = append(conditions, map[string]interface{}{
			"method": []string{match.Method},
		})
	}

	// Add header matching
	if len(match.Headers) > 0 {
		conditions = append(conditions, map[string]interface{}{
			"header": match.Headers,
		})
	}

	return conditions
}

// buildEnhancedHandlers builds handlers for enhanced service routes
func (m *Manager) buildEnhancedHandlers(service *EnhancedServiceConfig, routeConfig *RouteConfig) []map[string]interface{} {
	var handlers []map[string]interface{}

	// Process middleware handlers
	for _, middleware := range routeConfig.Handle {
		switch middleware.Type {
		case "headers":
			if handler := m.buildHeadersHandler(&middleware); handler != nil {
				handlers = append(handlers, handler)
			}
		case "rate_limit":
			if handler := m.buildRateLimitHandler(&middleware); handler != nil {
				handlers = append(handlers, handler)
			}
		case "reverse_proxy":
			handlers = append(handlers, m.buildEnhancedReverseProxyHandler(service))
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
		handlers = append(handlers, m.buildEnhancedReverseProxyHandler(service))
	}

	return handlers
}

// buildDefaultEnhancedHandlers builds default handlers for enhanced services
func (m *Manager) buildDefaultEnhancedHandlers(service *EnhancedServiceConfig) []map[string]interface{} {
	return []map[string]interface{}{
		m.buildEnhancedReverseProxyHandler(service),
	}
}

// buildHeadersHandler builds a headers handler from middleware config
func (m *Manager) buildHeadersHandler(middleware *MiddlewareConfig) map[string]interface{} {
	if middleware.Config == nil {
		return nil
	}

	handler := map[string]interface{}{
		"handler": "headers",
	}

	// Add request headers
	if requestConfig, ok := middleware.Config["request"].(map[string]interface{}); ok {
		if handler["request"] == nil {
			handler["request"] = make(map[string]interface{})
		}
		if setHeaders, ok := requestConfig["set"].(map[string]interface{}); ok {
			handler["request"].(map[string]interface{})["set"] = setHeaders
		}
		if addHeaders, ok := requestConfig["add"].(map[string]interface{}); ok {
			handler["request"].(map[string]interface{})["add"] = addHeaders
		}
	}

	// Add response headers
	if responseConfig, ok := middleware.Config["response"].(map[string]interface{}); ok {
		if handler["response"] == nil {
			handler["response"] = make(map[string]interface{})
		}
		if setHeaders, ok := responseConfig["set"].(map[string]interface{}); ok {
			handler["response"].(map[string]interface{})["set"] = setHeaders
		}
		if addHeaders, ok := responseConfig["add"].(map[string]interface{}); ok {
			handler["response"].(map[string]interface{})["add"] = addHeaders
		}
	}

	return handler
}

// buildRateLimitHandler builds a rate limit handler (placeholder)
func (m *Manager) buildRateLimitHandler(middleware *MiddlewareConfig) map[string]interface{} {
	logger.Info("⚠️ Rate limiting configured but requires Caddy plugin")
	return nil
}

// buildEnhancedReverseProxyHandler builds a reverse proxy handler for enhanced services
func (m *Manager) buildEnhancedReverseProxyHandler(service *EnhancedServiceConfig) map[string]interface{} {
	// For zero-trust architecture, always proxy to internal API
	backendAddress := "127.0.0.1:9443"

	requestHeaders := map[string][]string{
		"Host":               {service.GetPrimaryHost()},
		"X-Forwarded-Proto":  {"https"},
		"X-Forwarded-Host":   {"{http.request.host}"},
		"X-Real-IP":          {"{http.request.remote.host}"},
		"X-Forwarded-For":    {"{http.request.remote.host}"},
		"X-Forwarded-Server": {"zero-trust-caddy"},
		"X-Agent-Config":     {"enhanced"},
		"X-Service-ID":       {service.ID},
	}

	if service.WebSocket {
		requestHeaders["X-WebSocket-Enabled"] = []string{"true"}
		// Add WebSocket headers for transparent passthrough
		requestHeaders["Connection"] = []string{"{http.request.header.Connection}"}
		requestHeaders["Upgrade"] = []string{"{http.request.header.Upgrade}"}
		requestHeaders["Sec-WebSocket-Key"] = []string{"{http.request.header.Sec-WebSocket-Key}"}
		requestHeaders["Sec-WebSocket-Version"] = []string{"{http.request.header.Sec-WebSocket-Version}"}
		requestHeaders["Sec-WebSocket-Protocol"] = []string{"{http.request.header.Sec-WebSocket-Protocol}"}
		requestHeaders["Sec-WebSocket-Extensions"] = []string{"{http.request.header.Sec-WebSocket-Extensions}"}
	}

	handler := map[string]interface{}{
		"handler": "reverse_proxy",
		"upstreams": []map[string]interface{}{
			{"dial": backendAddress},
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
	}

	return handler
}

// GetServiceCount returns the total number of configured services
func (m *Manager) GetServiceCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.simpleServices) + len(m.enhancedServices)
}

// GetServiceList returns a list of all configured hostnames
func (m *Manager) GetServiceList() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var hostnames []string
	for hostname := range m.simpleServices {
		hostnames = append(hostnames, hostname)
	}
	for hostname := range m.enhancedServices {
		hostnames = append(hostnames, hostname)
	}
	return hostnames
}
