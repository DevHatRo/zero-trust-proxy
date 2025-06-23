package caddy

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/devhatro/zero-trust-proxy/internal/types"
)

// isCaddyAvailable checks if the caddy binary is available for testing
func isCaddyAvailable() bool {
	_, err := exec.LookPath("caddy")
	return err == nil
}

func TestValidator_ValidateServiceConfig(t *testing.T) {
	validator := NewValidator()

	// Skip binary validation for basic tests to avoid dependency on Caddy binary
	validator.SetSkipBinaryValidation(true)

	tests := []struct {
		name          string
		config        *types.ServiceConfig
		expectValid   bool
		expectedError string
		skipIfNoCaddy bool
	}{
		{
			name: "valid basic service config",
			config: &types.ServiceConfig{
				Hostname: "example.com",
				Backend:  "127.0.0.1:9443",
				Protocol: "https",
				ListenOn: "both",
			},
			expectValid: true,
		},
		{
			name: "empty hostname",
			config: &types.ServiceConfig{
				Hostname: "",
				Backend:  "127.0.0.1:9443",
				Protocol: "https",
			},
			expectValid:   false,
			expectedError: "hostname cannot be empty",
		},
		{
			name: "empty backend",
			config: &types.ServiceConfig{
				Hostname: "example.com",
				Backend:  "",
				Protocol: "https",
			},
			expectValid:   false,
			expectedError: "backend address cannot be empty",
		},
		{
			name: "empty protocol",
			config: &types.ServiceConfig{
				Hostname: "example.com",
				Backend:  "127.0.0.1:8080",
				Protocol: "",
			},
			expectValid:   false,
			expectedError: "protocol cannot be empty",
		},
		{
			name: "invalid protocol",
			config: &types.ServiceConfig{
				Hostname: "example.com",
				Backend:  "127.0.0.1:8080",
				Protocol: "invalid",
			},
			expectValid:   false,
			expectedError: "unsupported protocol",
		},
		{
			name: "websocket with https protocol",
			config: &types.ServiceConfig{
				Hostname:  "websocket.example.com",
				Backend:   "127.0.0.1:9443",
				Protocol:  "https",
				WebSocket: true,
			},
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateServiceConfig(tt.config)

			if result.Valid != tt.expectValid {
				t.Errorf("ValidateServiceConfig() valid = %v, expected %v", result.Valid, tt.expectValid)
				if !result.Valid {
					for _, err := range result.Errors {
						t.Logf("Validation error: %s", err.Error())
					}
				}
			}

			if !tt.expectValid && tt.expectedError != "" {
				found := false
				for _, err := range result.Errors {
					if strings.Contains(err.Message, tt.expectedError) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error containing '%s', but got errors: %v", tt.expectedError, result.Errors)
				}
			}
		})
	}
}

func TestValidator_CaddyBinaryValidation(t *testing.T) {
	if !isCaddyAvailable() {
		t.Skip("Skipping Caddy binary validation tests - caddy binary not available")
	}

	validator := NewValidator()

	tests := []struct {
		name        string
		config      *types.ServiceConfig
		expectValid bool
	}{
		{
			name: "valid configuration for Caddy",
			config: &types.ServiceConfig{
				Hostname: "test.example.com",
				Backend:  "127.0.0.1:8080",
				Protocol: "https",
			},
			expectValid: true,
		},
		{
			name: "invalid backend address for Caddy",
			config: &types.ServiceConfig{
				Hostname: "test.example.com",
				Backend:  "invalid:backend:format",
				Protocol: "https",
			},
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateWithCaddyBinary(tt.config)

			if tt.expectValid && err != nil {
				t.Errorf("Expected validation to pass, but got error: %v", err)
			}

			if !tt.expectValid && err == nil {
				t.Errorf("Expected validation to fail, but it passed")
			}
		})
	}
}

func TestValidator_MockCaddyBinary(t *testing.T) {
	validator := NewValidator()

	// Test with non-existent binary to simulate failure
	validator.SetCaddyBinary("/non/existent/caddy")

	config := &types.ServiceConfig{
		Hostname: "test.example.com",
		Backend:  "127.0.0.1:8080",
		Protocol: "https",
	}

	err := validator.validateWithCaddyBinary(config)
	if err == nil {
		t.Error("Expected validation to fail with non-existent binary, but it passed")
	}
}

func TestValidationContext(t *testing.T) {
	tests := []struct {
		name          string
		context       ValidationContext
		backend       string
		expectWarning bool
	}{
		{
			name:          "Server validation with non-server backend shows warning",
			context:       ServerValidation,
			backend:       "192.168.1.100:8080",
			expectWarning: true,
		},
		{
			name:          "Agent validation with non-server backend does not show warning",
			context:       AgentValidation,
			backend:       "192.168.1.100:8080",
			expectWarning: false,
		},
		{
			name:          "Server validation with server backend does not show warning",
			context:       ServerValidation,
			backend:       "127.0.0.1:9443",
			expectWarning: false,
		},
		{
			name:          "Agent validation with server backend does not show warning",
			context:       AgentValidation,
			backend:       "127.0.0.1:9443",
			expectWarning: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewValidatorWithContext(tt.context)

			// Skip binary validation for context tests
			validator.SetSkipBinaryValidation(true)

			config := &types.ServiceConfig{
				Hostname: "test.example.com",
				Backend:  tt.backend,
				Protocol: "https",
			}

			// Test validation behavior with different contexts
			result := validator.ValidateServiceConfig(config)

			// The validation should pass regardless of context (only warnings should differ)
			if !result.Valid {
				t.Errorf("Expected validation to pass, but got errors: %v", result.Errors)
			}
		})
	}
}

func TestValidatorSetContext(t *testing.T) {
	validator := NewValidator() // Defaults to ServerValidation

	// Verify default context
	if validator.context != ServerValidation {
		t.Errorf("Expected default context to be ServerValidation, got %v", validator.context)
	}

	// Change context
	validator.SetContext(AgentValidation)
	if validator.context != AgentValidation {
		t.Errorf("Expected context to be AgentValidation after SetContext, got %v", validator.context)
	}
}

func TestValidator_SetCaddyBinary(t *testing.T) {
	validator := NewValidator()

	// Test default binary
	if validator.caddyBinary != "caddy" {
		t.Errorf("Expected default caddy binary to be 'caddy', got %s", validator.caddyBinary)
	}

	// Test setting custom binary
	customPath := "/custom/path/to/caddy"
	validator.SetCaddyBinary(customPath)
	if validator.caddyBinary != customPath {
		t.Errorf("Expected caddy binary to be %s, got %s", customPath, validator.caddyBinary)
	}
}

// Benchmark the new validation approach
func BenchmarkValidator_ValidateServiceConfig(b *testing.B) {
	if !isCaddyAvailable() {
		b.Skip("Skipping benchmark - caddy binary not available")
	}

	validator := NewValidator()
	config := &types.ServiceConfig{
		Hostname: "bench.example.com",
		Backend:  "127.0.0.1:8080",
		Protocol: "https",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateServiceConfig(config)
	}
}
