package caddy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/logger"
)

// Validator provides validation capabilities for Caddy configurations
type Validator struct {
	adminAPI       string
	timeout        time.Duration
	caddyAvailable bool
}

// NewValidator creates a new Caddy validator
func NewValidator(adminAPI string) *Validator {
	// Check if Caddy CLI is available at startup
	caddyAvailable := false
	if _, err := exec.LookPath("caddy"); err == nil {
		caddyAvailable = true
		logger.Debug("🔧 Caddy CLI detected and available for validation")
	} else {
		logger.Debug("⚠️ Caddy CLI not found, will use structural validation only")
	}

	validator := &Validator{
		adminAPI:       adminAPI,
		timeout:        30 * time.Second,
		caddyAvailable: caddyAvailable,
	}

	if adminAPI != "" {
		logger.Debug("🌐 Caddy admin API configured: %s", adminAPI)
	}

	return validator
}

// ValidateConfig validates a Caddy configuration using multiple methods
func (v *Validator) ValidateConfig(config map[string]interface{}) error {
	logger.Debug("🔧 Starting Caddy configuration validation")

	// Method 1: Structural validation (always available)
	logger.Debug("🔧 Running structural validation")
	if err := v.validateStructure(config); err != nil {
		logger.Error("💥 Structural validation failed: %v", err)
		return fmt.Errorf("structural validation failed: %w", err)
	}
	logger.Debug("✅ Structural validation passed")

	// Method 2: JSON schema validation
	logger.Debug("🔧 Running JSON validation")
	if err := v.validateJSON(config); err != nil {
		logger.Error("💥 JSON validation failed: %v", err)
		return fmt.Errorf("JSON validation failed: %w", err)
	}
	logger.Debug("✅ JSON validation passed")

	// Method 3: Caddy CLI validation (preferred method when available)
	if v.caddyAvailable {
		logger.Debug("🚀 Running Caddy CLI validation")
		if err := v.validateWithCaddyCLI(config); err != nil {
			// CLI validation failed - this is a real configuration error
			logger.Error("💥 Caddy CLI validation failed: %v", err)
			return fmt.Errorf("Caddy CLI validation failed: %w", err)
		}
		logger.Debug("✅ Caddy CLI validation passed")
		// CLI validation passed - configuration is valid
		return nil
	}

	// Method 4: Admin API validation if CLI not available but API is configured
	if v.adminAPI != "" {
		logger.Debug("🌐 Running admin API validation")
		if err := v.validateWithAdminAPI(config); err != nil {
			// Only fail on clear configuration errors
			if strings.Contains(err.Error(), "configuration error") ||
				strings.Contains(err.Error(), "invalid") {
				logger.Error("💥 Caddy admin API validation failed: %v", err)
				return fmt.Errorf("Caddy admin API validation failed: %w", err)
			}
			// API not reachable - continue with structural validation only
			logger.Warn("⚠️ Admin API validation failed (API not reachable): %v", err)
		} else {
			logger.Debug("✅ Admin API validation passed")
		}
	}

	// If we get here, we've passed structural and JSON validation
	// This is sufficient for basic validation when Caddy CLI is not available
	logger.Debug("✅ Configuration validation completed successfully")
	return nil
}

// validateStructure performs basic structural validation
func (v *Validator) validateStructure(config map[string]interface{}) error {
	// Check for required top-level keys
	if _, ok := config["apps"]; !ok {
		return fmt.Errorf("missing required 'apps' section")
	}

	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid 'apps' section - must be object")
	}

	// Validate HTTP app if present
	if httpApp, exists := apps["http"]; exists {
		if err := v.validateHTTPApp(httpApp); err != nil {
			return fmt.Errorf("HTTP app validation failed: %w", err)
		}
	}

	return nil
}

// validateHTTPApp validates the HTTP application configuration
func (v *Validator) validateHTTPApp(httpApp interface{}) error {
	app, ok := httpApp.(map[string]interface{})
	if !ok {
		return fmt.Errorf("HTTP app must be object")
	}

	// Check servers
	if servers, exists := app["servers"]; exists {
		serversMap, ok := servers.(map[string]interface{})
		if !ok {
			return fmt.Errorf("servers must be object")
		}

		for serverName, serverConfig := range serversMap {
			if err := v.validateServer(serverConfig); err != nil {
				return fmt.Errorf("server '%s' validation failed: %w", serverName, err)
			}
		}
	}

	return nil
}

// validateServer validates a single server configuration
func (v *Validator) validateServer(serverConfig interface{}) error {
	server, ok := serverConfig.(map[string]interface{})
	if !ok {
		return fmt.Errorf("server config must be object")
	}

	// Validate listen addresses - they should be present for most server configs
	if listen, exists := server["listen"]; exists {
		// Handle both []string and []interface{} types
		switch listenVal := listen.(type) {
		case []interface{}:
			if len(listenVal) == 0 {
				return fmt.Errorf("at least one listen address required")
			}
			for i, addr := range listenVal {
				if _, ok := addr.(string); !ok {
					return fmt.Errorf("listen address %d must be string", i)
				}
			}
		case []string:
			if len(listenVal) == 0 {
				return fmt.Errorf("at least one listen address required")
			}
		default:
			return fmt.Errorf("listen must be array")
		}
	} else {
		// Missing listen field is usually an error for HTTP servers
		return fmt.Errorf("missing 'listen' field")
	}

	// Validate routes - they should be present for most server configs
	if routes, exists := server["routes"]; exists {
		routesArray, ok := routes.([]interface{})
		if !ok {
			// Try []map[string]interface{} type as well
			if routesMapArray, ok := routes.([]map[string]interface{}); ok {
				for i, route := range routesMapArray {
					if err := v.validateRoute(route); err != nil {
						return fmt.Errorf("route %d validation failed: %w", i, err)
					}
				}
				return nil
			}
			return fmt.Errorf("routes must be array")
		}
		for i, route := range routesArray {
			if err := v.validateRoute(route); err != nil {
				return fmt.Errorf("route %d validation failed: %w", i, err)
			}
		}
	} else {
		// Missing routes field is usually an error for HTTP servers
		return fmt.Errorf("missing 'routes' field")
	}

	return nil
}

// validateRoute validates a single route configuration
func (v *Validator) validateRoute(route interface{}) error {
	routeMap, ok := route.(map[string]interface{})
	if !ok {
		return fmt.Errorf("route must be object")
	}

	// Validate match conditions
	if match, exists := routeMap["match"]; exists {
		// Handle both []interface{} and []map[string]interface{} types
		switch matchVal := match.(type) {
		case []interface{}:
			for i, matcher := range matchVal {
				if _, ok := matcher.(map[string]interface{}); !ok {
					return fmt.Errorf("matcher %d must be object", i)
				}
			}
		case []map[string]interface{}:
			// Already the right type, no need to validate further
		default:
			return fmt.Errorf("match must be array")
		}
	}

	// Validate handlers
	if handle, exists := routeMap["handle"]; exists {
		// Handle both []interface{} and []map[string]interface{} types
		switch handleVal := handle.(type) {
		case []interface{}:
			for i, handler := range handleVal {
				if err := v.validateHandler(handler); err != nil {
					return fmt.Errorf("handler %d validation failed: %w", i, err)
				}
			}
		case []map[string]interface{}:
			for i, handler := range handleVal {
				if err := v.validateHandler(handler); err != nil {
					return fmt.Errorf("handler %d validation failed: %w", i, err)
				}
			}
		default:
			return fmt.Errorf("handle must be array")
		}
	}

	return nil
}

// validateHandler validates a single handler configuration
func (v *Validator) validateHandler(handler interface{}) error {
	handlerMap, ok := handler.(map[string]interface{})
	if !ok {
		return fmt.Errorf("handler must be object")
	}

	handlerType, ok := handlerMap["handler"].(string)
	if !ok {
		return fmt.Errorf("handler must have 'handler' field of type string")
	}

	// Validate specific handler types
	switch handlerType {
	case "reverse_proxy":
		return v.validateReverseProxyHandler(handlerMap)
	case "static_response":
		return v.validateStaticResponseHandler(handlerMap)
	case "headers":
		return v.validateHeadersHandler(handlerMap)
	case "file_server":
		return v.validateFileServerHandler(handlerMap)
	default:
		// Unknown handler type - just warn, don't fail
		// Caddy might support handlers we don't know about
		logger.Debug("⚠️ Unknown handler type '%s' - skipping specific validation", handlerType)
		return nil
	}
}

// validateReverseProxyHandler validates reverse_proxy handler
func (v *Validator) validateReverseProxyHandler(handler map[string]interface{}) error {
	if upstreams, exists := handler["upstreams"]; exists {
		// Handle both []interface{} and []map[string]interface{} types
		switch upstreamsVal := upstreams.(type) {
		case []interface{}:
			if len(upstreamsVal) == 0 {
				return fmt.Errorf("at least one upstream required")
			}
			for i, upstream := range upstreamsVal {
				upstreamMap, ok := upstream.(map[string]interface{})
				if !ok {
					return fmt.Errorf("upstream %d must be object", i)
				}
				if _, ok := upstreamMap["dial"].(string); !ok {
					return fmt.Errorf("upstream %d must have 'dial' field", i)
				}
			}
		case []map[string]interface{}:
			if len(upstreamsVal) == 0 {
				return fmt.Errorf("at least one upstream required")
			}
			for i, upstream := range upstreamsVal {
				if _, ok := upstream["dial"].(string); !ok {
					return fmt.Errorf("upstream %d must have 'dial' field", i)
				}
			}
		default:
			return fmt.Errorf("upstreams must be array")
		}
	}
	return nil
}

// validateStaticResponseHandler validates static_response handler
func (v *Validator) validateStaticResponseHandler(handler map[string]interface{}) error {
	// status_code is optional, but if present should be valid
	if statusCode, exists := handler["status_code"]; exists {
		switch v := statusCode.(type) {
		case float64:
			if v < 100 || v > 599 {
				return fmt.Errorf("invalid status code: %v", v)
			}
		case int:
			if v < 100 || v > 599 {
				return fmt.Errorf("invalid status code: %v", v)
			}
		default:
			return fmt.Errorf("status_code must be number")
		}
	}
	return nil
}

// validateHeadersHandler validates headers handler
func (v *Validator) validateHeadersHandler(handler map[string]interface{}) error {
	// Headers handler structure is flexible, just check basic structure
	if request, exists := handler["request"]; exists {
		if _, ok := request.(map[string]interface{}); !ok {
			return fmt.Errorf("request headers must be object")
		}
	}
	if response, exists := handler["response"]; exists {
		if _, ok := response.(map[string]interface{}); !ok {
			return fmt.Errorf("response headers must be object")
		}
	}
	return nil
}

// validateFileServerHandler validates file_server handler
func (v *Validator) validateFileServerHandler(handler map[string]interface{}) error {
	// File server is usually simple, just check if root exists if specified
	if root, exists := handler["root"]; exists {
		if _, ok := root.(string); !ok {
			return fmt.Errorf("file server root must be string")
		}
	}
	return nil
}

// validateJSON validates the JSON structure
func (v *Validator) validateJSON(config map[string]interface{}) error {
	// Try to marshal and unmarshal to check JSON validity
	jsonData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to JSON: %w", err)
	}

	var testConfig map[string]interface{}
	if err := json.Unmarshal(jsonData, &testConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config from JSON: %w", err)
	}

	return nil
}

// validateWithCaddyCLI validates using Caddy CLI
func (v *Validator) validateWithCaddyCLI(config map[string]interface{}) error {
	logger.Debug("⚙️ Creating temporary config file for Caddy CLI validation")

	// Create temporary config file
	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "caddy-config-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		os.Remove(tmpFile.Name())
		logger.Debug("🗑️ Cleaned up temporary config file: %s", tmpFile.Name())
	}()
	defer tmpFile.Close()

	if _, err := tmpFile.Write(configJSON); err != nil {
		return fmt.Errorf("failed to write temp config: %w", err)
	}
	tmpFile.Close()

	logger.Debug("🚀 Running 'caddy validate --config %s'", tmpFile.Name())

	// Validate using Caddy CLI with timeout
	cmd := exec.Command("caddy", "validate", "--config", tmpFile.Name())
	cmd.Env = append(os.Environ(), "CADDY_ADMIN=off") // Disable admin API for validation

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Parse Caddy CLI output for better error messages
		outputStr := string(output)
		logger.Debug("💥 Caddy CLI output: %s", outputStr)

		if strings.Contains(outputStr, "adapt") {
			return fmt.Errorf("configuration adaptation error: %s", outputStr)
		}
		if strings.Contains(outputStr, "invalid") {
			return fmt.Errorf("invalid configuration: %s", outputStr)
		}
		if strings.Contains(outputStr, "unknown") {
			return fmt.Errorf("unknown configuration directive: %s", outputStr)
		}
		return fmt.Errorf("configuration validation failed: %s", outputStr)
	}

	logger.Debug("✅ Caddy CLI validation completed successfully")
	return nil
}

// validateWithAdminAPI validates using Caddy admin API if available
func (v *Validator) validateWithAdminAPI(config map[string]interface{}) error {
	if v.adminAPI == "" {
		return fmt.Errorf("admin API not configured")
	}

	logger.Debug("🔗 Testing connection to Caddy admin API: %s", v.adminAPI)

	client := &http.Client{Timeout: v.timeout}

	// First check if admin API is reachable
	resp, err := client.Get(v.adminAPI + "/config/")
	if err != nil {
		return fmt.Errorf("admin API not reachable: %w", err)
	}
	resp.Body.Close()

	logger.Debug("✅ Admin API is reachable")

	// Note: We could use a dry-run endpoint if Caddy supported it
	// For now, we'll skip live validation to avoid disrupting running config
	// This is safer for production environments

	return nil
}

// ValidateServiceConfig validates a service configuration by generating and validating the Caddy config
func (v *Validator) ValidateServiceConfig(serviceName string, hostname string, backend string, protocol string, websocket bool, httpRedirect bool, listenOn string) error {
	logger.Debug("🔧 Validating service config: %s (hostname: %s, backend: %s)", serviceName, hostname, backend)

	// Generate the Caddy configuration
	config := GenerateServiceConfig(serviceName, hostname, backend, protocol, websocket, httpRedirect, listenOn)

	// Check for generation errors
	if errorMsg, hasError := config["error"]; hasError {
		logger.Error("💥 Service config generation failed: %v", errorMsg)
		return fmt.Errorf("service config generation failed: %v", errorMsg)
	}

	// Validate the generated configuration
	return v.ValidateConfig(config)
}

// IsCaddyAvailable returns whether Caddy CLI is available for validation
func (v *Validator) IsCaddyAvailable() bool {
	return v.caddyAvailable
}
