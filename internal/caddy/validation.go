package caddy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

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
	// Path to caddy binary (defaults to "caddy" in PATH)
	caddyBinary string
	// Skip Caddy binary validation (useful for testing)
	skipBinaryValidation bool
}

// NewValidator creates a new Caddy configuration validator
func NewValidator() *Validator {
	return &Validator{
		existingServices:     make(map[string]*types.ServiceConfig),
		context:              ServerValidation, // Default to server validation for backward compatibility
		caddyBinary:          "caddy",          // Use caddy from PATH
		skipBinaryValidation: false,            // Enable binary validation by default
	}
}

// NewValidatorWithContext creates a new Caddy configuration validator with specific context
func NewValidatorWithContext(context ValidationContext) *Validator {
	return &Validator{
		existingServices:     make(map[string]*types.ServiceConfig),
		context:              context,
		caddyBinary:          "caddy",
		skipBinaryValidation: false,
	}
}

// SetContext updates the validation context
func (v *Validator) SetContext(context ValidationContext) {
	v.context = context
}

// SetCaddyBinary sets the path to the caddy binary (useful for testing or custom installations)
func (v *Validator) SetCaddyBinary(path string) {
	v.caddyBinary = path
}

// SetSkipBinaryValidation enables or disables Caddy binary validation
func (v *Validator) SetSkipBinaryValidation(skip bool) {
	v.skipBinaryValidation = skip
}

// ValidateServiceConfig validates a service configuration for Caddy compatibility
func (v *Validator) ValidateServiceConfig(config *types.ServiceConfig) *types.ValidationResult {
	result := &types.ValidationResult{
		Valid:  true,
		Errors: []types.ValidationError{},
	}

	// Basic validation (still useful for early error detection)
	if err := v.validateBasics(config); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, *err)
		return result // Don't proceed with Caddy validation if basics fail
	}

	// Check for hostname conflicts
	if err := v.checkHostnameConflicts(config.Hostname, config); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, *err)
	}

	// Only warn about backend address during server-side validation
	// Agent-side validation naturally has different backend addresses
	if v.context == ServerValidation {
		expectedBackend := "127.0.0.1:9443"
		if config.Backend != expectedBackend {
			logger.Warn("⚠️  Backend %s does not match expected server API address %s", config.Backend, expectedBackend)
		}
	}

	// **Use Caddy binary for comprehensive validation (if enabled and available)**
	if result.Valid && !v.skipBinaryValidation {
		// Check if Caddy binary is available
		if _, err := exec.LookPath(v.caddyBinary); err != nil {
			logger.Debug("⚠️  Caddy binary not found at '%s', skipping binary validation: %v", v.caddyBinary, err)
		} else {
			if err := v.validateWithCaddyBinary(config); err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, types.ValidationError{
					Field:   "caddy_config",
					Message: fmt.Sprintf("Caddy validation failed: %v", err),
					Code:    "CADDY_VALIDATION_FAILED",
				})
			}
		}
	}

	return result
}

// validateBasics performs basic validation that doesn't require Caddy
func (v *Validator) validateBasics(config *types.ServiceConfig) *types.ValidationError {
	if config.Hostname == "" {
		return &types.ValidationError{
			Field:   "hostname",
			Message: "hostname cannot be empty",
			Code:    "EMPTY_HOSTNAME",
		}
	}

	if config.Backend == "" {
		return &types.ValidationError{
			Field:   "backend",
			Message: "backend address cannot be empty",
			Code:    "EMPTY_BACKEND",
		}
	}

	// Validate backend address format
	if err := v.validateBackendAddress(config.Backend); err != nil {
		return &types.ValidationError{
			Field:   "backend",
			Message: fmt.Sprintf("invalid backend address format: %v", err),
			Code:    "INVALID_BACKEND_FORMAT",
		}
	}

	if config.Protocol == "" {
		return &types.ValidationError{
			Field:   "protocol",
			Message: "protocol cannot be empty",
			Code:    "EMPTY_PROTOCOL",
		}
	}

	// Basic protocol validation
	supportedProtocols := []string{"http", "https", "tcp", "udp"}
	protocolValid := false
	for _, supported := range supportedProtocols {
		if config.Protocol == supported {
			protocolValid = true
			break
		}
	}
	if !protocolValid {
		return &types.ValidationError{
			Field:   "protocol",
			Message: fmt.Sprintf("unsupported protocol: %s (supported: %s)", config.Protocol, strings.Join(supportedProtocols, ", ")),
			Code:    "UNSUPPORTED_PROTOCOL",
		}
	}

	return nil
}

// validateBackendAddress validates the backend address format
func (v *Validator) validateBackendAddress(backend string) error {
	// Check for obviously invalid patterns
	if strings.Contains(backend, " ") || strings.Contains(backend, "\t") || strings.Contains(backend, "\n") {
		return fmt.Errorf("backend address contains invalid whitespace characters")
	}

	// Handle IPv6 addresses in brackets like [::1]:8080
	if strings.HasPrefix(backend, "[") {
		closeBracket := strings.Index(backend, "]:")
		if closeBracket == -1 {
			return fmt.Errorf("IPv6 backend address missing closing bracket and port")
		}
		host := backend[1:closeBracket]
		port := backend[closeBracket+2:]

		if host == "" {
			return fmt.Errorf("IPv6 backend address has empty host")
		}
		if port == "" {
			return fmt.Errorf("IPv6 backend address has empty port")
		}
		if !isValidPort(port) {
			return fmt.Errorf("IPv6 backend address has invalid port: %s", port)
		}
		return nil
	}

	// Count colons for regular host:port format
	colonCount := strings.Count(backend, ":")
	if colonCount == 0 {
		return fmt.Errorf("backend address missing port (expected format: host:port)")
	}
	if colonCount > 1 {
		return fmt.Errorf("backend address has too many colons (found %d, expected 1 for host:port format)", colonCount)
	}

	// Split into exactly two parts: host and port
	parts := strings.SplitN(backend, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("backend address could not be split into host and port")
	}

	host := parts[0]
	port := parts[1]

	// Validate host part
	if host == "" {
		return fmt.Errorf("backend address has empty host")
	}

	// Validate port part
	if port == "" {
		return fmt.Errorf("backend address has empty port")
	}

	if !isValidPort(port) {
		return fmt.Errorf("backend address has invalid port: %s", port)
	}

	return nil
}

// isValidPort checks if a port string is valid (numeric or known service name)
func isValidPort(port string) bool {
	// Check if it's a number
	if len(port) == 0 {
		return false
	}

	// Check for obviously invalid characters that shouldn't be in ports
	if strings.Contains(port, ":") || strings.Contains(port, " ") ||
		strings.Contains(port, "\t") || strings.Contains(port, "\n") {
		return false
	}

	// Check if it's all numeric
	isNumeric := true
	for _, char := range port {
		if char < '0' || char > '9' {
			isNumeric = false
			break
		}
	}

	if isNumeric {
		// If it's all numeric, check the range
		num := 0
		for _, char := range port {
			num = num*10 + int(char-'0')
			if num > 65535 {
				return false // Port number too high
			}
		}
		return num > 0 // Port must be positive
	}

	// If it contains non-numeric characters, it might be a service name
	// Allow service names like "http", "https", etc. but catch obvious errors
	return len(port) > 0 && len(port) <= 15 // Reasonable length for service names
}

// validateWithCaddyBinary uses the actual Caddy binary to validate the configuration
func (v *Validator) validateWithCaddyBinary(config *types.ServiceConfig) error {
	// Generate a complete Caddy configuration for validation
	caddyConfig := v.generateTestCaddyConfig(config)

	// Create temporary file for validation
	tempFile, err := v.createTempCaddyConfig(caddyConfig)
	if err != nil {
		return fmt.Errorf("failed to create temp config file: %w", err)
	}
	defer os.Remove(tempFile)

	// Run caddy validate command
	return v.runCaddyValidate(tempFile)
}

// generateTestCaddyConfig generates a complete Caddy configuration for validation
func (v *Validator) generateTestCaddyConfig(config *types.ServiceConfig) map[string]interface{} {
	return map[string]interface{}{
		"admin": map[string]interface{}{
			"disabled": false,
		},
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"validation_server": map[string]interface{}{
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
										"headers": map[string]interface{}{
											"request": map[string]interface{}{
												"set": map[string][]string{
													"Host":              {config.Hostname},
													"X-Forwarded-Proto": {config.Protocol},
													"X-Forwarded-Host":  {"{http.request.host}"},
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
	}
}

// createTempCaddyConfig creates a temporary file with the Caddy configuration
func (v *Validator) createTempCaddyConfig(config map[string]interface{}) (string, error) {
	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal config to JSON: %w", err)
	}

	// Create temp file in system temp directory
	tempFile, err := os.CreateTemp("", "caddy-validate-*.json")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tempFile.Close()

	if _, err := tempFile.Write(configJSON); err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("failed to write config to temp file: %w", err)
	}

	return tempFile.Name(), nil
}

// runCaddyValidate executes the caddy validate command
func (v *Validator) runCaddyValidate(configFile string) error {
	// Set timeout for validation (should be fast)
	timeout := 10 * time.Second

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Prepare command with context: caddy validate --config <file>
	cmd := exec.CommandContext(ctx, v.caddyBinary, "validate", "--config", configFile)
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Parse Caddy's error output for meaningful error messages
		outputStr := string(output)
		if strings.Contains(outputStr, "validation") || strings.Contains(outputStr, "error") {
			return fmt.Errorf("caddy validation error: %s", outputStr)
		}
		return fmt.Errorf("caddy validate command failed: %w (output: %s)", err, outputStr)
	}

	logger.Debug("✅ Caddy binary validation passed for hostname: %s", configFile)
	return nil
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
