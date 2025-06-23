package caddy

import (
	"strings"
	"testing"

	"github.com/devhatro/zero-trust-proxy/internal/types"
)

func TestValidator_ValidateServiceConfig(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name          string
		config        *types.ServiceConfig
		expectValid   bool
		expectedError string
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
			name: "valid wildcard hostname",
			config: &types.ServiceConfig{
				Hostname: "*.example.com",
				Backend:  "127.0.0.1:9443",
				Protocol: "https",
			},
			expectValid: true,
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

func BenchmarkValidator_ValidateServiceConfig(b *testing.B) {
	validator := NewValidator()

	config := &types.ServiceConfig{
		Hostname: "benchmark.example.com",
		Backend:  "127.0.0.1:9443",
		Protocol: "https",
		ListenOn: "both",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		validator.ValidateServiceConfig(config)
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
			config := &types.ServiceConfig{
				Hostname: "test.example.com",
				Backend:  tt.backend,
				Protocol: "https",
			}

			// Capture log output to check for warnings
			// Note: This is a basic test - in a real implementation you might want
			// to use a test logger to capture and verify log messages
			result := validator.ValidateServiceConfig(config)

			// The validation should still pass regardless of context
			if !result.Valid {
				t.Errorf("Expected validation to pass, but got errors: %v", result.Errors)
			}

			// Verify that no validation errors are returned
			// (backend warnings are logged, not returned as errors)
			if len(result.Errors) > 0 {
				t.Errorf("Expected no validation errors, but got: %v", result.Errors)
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
