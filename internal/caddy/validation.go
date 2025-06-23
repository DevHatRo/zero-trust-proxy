package caddy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/devhatro/zero-trust-proxy/internal/logger"
	"github.com/devhatro/zero-trust-proxy/internal/types"
)

// ValidationContext indicates where the validation is being performed
type ValidationContext string

const (
	AgentValidation  ValidationContext = "agent"
	ServerValidation ValidationContext = "server"
)

// Validator provides validation for Caddy configurations before applying them
type Validator struct {
	// Track existing configurations to detect conflicts
	existingServices map[string]*types.ServiceConfig
	// Validation context (agent or server)
	context ValidationContext
}

// NewValidator creates a new Caddy configuration validator
func NewValidator() *Validator {
	return &Validator{
		existingServices: make(map[string]*types.ServiceConfig),
		context:          ServerValidation, // Default to server validation for backward compatibility
	}
}

// NewValidatorWithContext creates a new Caddy configuration validator with specific context
func NewValidatorWithContext(context ValidationContext) *Validator {
	return &Validator{
		existingServices: make(map[string]*types.ServiceConfig),
		context:          context,
	}
}

// SetContext updates the validation context
func (v *Validator) SetContext(context ValidationContext) {
	v.context = context
}

// ValidateServiceConfig validates a service configuration for Caddy compatibility
func (v *Validator) ValidateServiceConfig(config *types.ServiceConfig) *types.ValidationResult {
	result := &types.ValidationResult{
		Valid:  true,
		Errors: []types.ValidationError{},
	}

	// Validate hostname
	if err := v.validateHostname(config.Hostname); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, *err)
	}

	// Validate backend address
	if err := v.validateBackend(config.Backend); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, *err)
	}

	// Validate protocol
	if err := v.validateProtocol(config.Protocol); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, *err)
	}

	// Validate listen_on value
	if err := v.validateListenOn(config.ListenOn); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, *err)
	}

	// Check for hostname conflicts
	if err := v.checkHostnameConflicts(config.Hostname, config); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, *err)
	}

	// Validate WebSocket configuration
	if err := v.validateWebSocketConfig(config); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, *err)
	}

	// Test Caddy configuration generation
	if result.Valid {
		if err := v.testCaddyConfigGeneration(config); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, types.ValidationError{
				Field:   "caddy_config",
				Message: fmt.Sprintf("failed to generate valid Caddy configuration: %v", err),
				Code:    "CADDY_CONFIG_GENERATION_FAILED",
			})
		}
	}

	return result
}

// validateHostname validates the hostname format
func (v *Validator) validateHostname(hostname string) *types.ValidationError {
	if hostname == "" {
		return &types.ValidationError{
			Field:   "hostname",
			Message: "hostname cannot be empty",
			Code:    "EMPTY_HOSTNAME",
		}
	}

	// Handle wildcard patterns first
	if strings.Contains(hostname, "*") {
		// Simple wildcard validation: *.domain.com format
		if strings.HasPrefix(hostname, "*.") {
			// Remove the wildcard and validate the rest as a normal hostname
			domainPart := hostname[2:] // Remove "*."
			if domainPart == "" {
				return &types.ValidationError{
					Field:   "hostname",
					Message: fmt.Sprintf("invalid wildcard hostname format: %s", hostname),
					Code:    "INVALID_HOSTNAME_FORMAT",
				}
			}
			// Validate the domain part
			hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
			if !hostnameRegex.MatchString(domainPart) {
				return &types.ValidationError{
					Field:   "hostname",
					Message: fmt.Sprintf("invalid wildcard hostname format: %s", hostname),
					Code:    "INVALID_HOSTNAME_FORMAT",
				}
			}
		} else {
			// Wildcard not at the beginning is invalid
			return &types.ValidationError{
				Field:   "hostname",
				Message: fmt.Sprintf("invalid wildcard hostname format: %s", hostname),
				Code:    "INVALID_HOSTNAME_FORMAT",
			}
		}
		return nil // Valid wildcard
	}

	// Validate regular hostname format (RFC 1123)
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !hostnameRegex.MatchString(hostname) {
		return &types.ValidationError{
			Field:   "hostname",
			Message: fmt.Sprintf("invalid hostname format: %s", hostname),
			Code:    "INVALID_HOSTNAME_FORMAT",
		}
	}

	return nil
}

// validateBackend validates the backend address format
func (v *Validator) validateBackend(backend string) *types.ValidationError {
	if backend == "" {
		return &types.ValidationError{
			Field:   "backend",
			Message: "backend address cannot be empty",
			Code:    "EMPTY_BACKEND",
		}
	}

	// Check if it's a URL format
	if strings.HasPrefix(backend, "http://") || strings.HasPrefix(backend, "https://") {
		if _, err := url.Parse(backend); err != nil {
			return &types.ValidationError{
				Field:   "backend",
				Message: fmt.Sprintf("invalid backend URL format: %s", backend),
				Code:    "INVALID_BACKEND_URL",
			}
		}
	} else {
		// Check if it's a valid host:port format
		hostPortRegex := regexp.MustCompile(`^[a-zA-Z0-9\.\-]+:[0-9]+$`)
		if !hostPortRegex.MatchString(backend) {
			return &types.ValidationError{
				Field:   "backend",
				Message: fmt.Sprintf("invalid backend host:port format: %s", backend),
				Code:    "INVALID_BACKEND_FORMAT",
			}
		}
	}

	// Only warn about backend address during server-side validation
	// Agent-side validation naturally has different backend addresses
	if v.context == ServerValidation {
		expectedBackend := "127.0.0.1:9443"
		if backend != expectedBackend {
			logger.Warn("⚠️  Backend %s does not match expected server API address %s", backend, expectedBackend)
		}
	}

	return nil
}

// validateProtocol validates the protocol value
func (v *Validator) validateProtocol(protocol string) *types.ValidationError {
	if protocol == "" {
		return &types.ValidationError{
			Field:   "protocol",
			Message: "protocol cannot be empty",
			Code:    "EMPTY_PROTOCOL",
		}
	}

	supportedProtocols := []string{"http", "https", "tcp", "udp"}
	for _, supported := range supportedProtocols {
		if protocol == supported {
			return nil
		}
	}

	return &types.ValidationError{
		Field:   "protocol",
		Message: fmt.Sprintf("unsupported protocol: %s (supported: %s)", protocol, strings.Join(supportedProtocols, ", ")),
		Code:    "UNSUPPORTED_PROTOCOL",
	}
}

// validateListenOn validates the listen_on value
func (v *Validator) validateListenOn(listenOn string) *types.ValidationError {
	// Empty or default values are valid
	if listenOn == "" || listenOn == "both" {
		return nil
	}

	validValues := []string{"http", "https", "both"}
	for _, valid := range validValues {
		if listenOn == valid {
			return nil
		}
	}

	return &types.ValidationError{
		Field:   "listen_on",
		Message: fmt.Sprintf("invalid listen_on value: %s (supported: %s)", listenOn, strings.Join(validValues, ", ")),
		Code:    "INVALID_LISTEN_ON",
	}
}

// checkHostnameConflicts checks for conflicts with existing services
func (v *Validator) checkHostnameConflicts(hostname string, newConfig *types.ServiceConfig) *types.ValidationError {
	if existingConfig, exists := v.existingServices[hostname]; exists {
		// Allow updating the same service
		if existingConfig.Protocol == newConfig.Protocol &&
			existingConfig.Backend == newConfig.Backend &&
			existingConfig.ListenOn == newConfig.ListenOn {
			return nil // Same configuration, not a conflict
		}

		return &types.ValidationError{
			Field:   "hostname",
			Message: fmt.Sprintf("hostname %s conflicts with existing service", hostname),
			Code:    "HOSTNAME_CONFLICT",
		}
	}

	return nil
}

// validateWebSocketConfig validates WebSocket-specific configuration
func (v *Validator) validateWebSocketConfig(config *types.ServiceConfig) *types.ValidationError {
	if !config.WebSocket {
		return nil // No WebSocket validation needed
	}

	// WebSocket requires HTTP/1.1, which is compatible with both http and https
	// No specific validation errors for WebSocket at this time
	return nil
}

// testCaddyConfigGeneration tests if we can generate a valid Caddy configuration
func (v *Validator) testCaddyConfigGeneration(config *types.ServiceConfig) error {
	// Create a simple test configuration
	testConfig := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"test": map[string]interface{}{
						"listen": []string{":443"},
						"routes": []map[string]interface{}{
							{
								"match": []map[string]interface{}{
									{
										"host": []string{config.Hostname},
									},
								},
								"handle": []map[string]interface{}{
									{
										"handler": "reverse_proxy",
										"upstreams": []map[string]interface{}{
											{
												"dial": config.Backend,
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

	// Try to marshal to JSON to test validity
	_, err := json.Marshal(testConfig)
	return err
}

// AddExistingService tracks a service for conflict detection
func (v *Validator) AddExistingService(hostname string, config *types.ServiceConfig) {
	v.existingServices[hostname] = config
}

// RemoveExistingService removes a service from conflict tracking
func (v *Validator) RemoveExistingService(hostname string) {
	delete(v.existingServices, hostname)
}

// GetExistingServices returns a copy of existing services map
func (v *Validator) GetExistingServices() map[string]*types.ServiceConfig {
	result := make(map[string]*types.ServiceConfig)
	for k, v := range v.existingServices {
		result[k] = v
	}
	return result
}
