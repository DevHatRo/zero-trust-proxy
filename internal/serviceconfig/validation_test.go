package serviceconfig

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
				for _, err := range result.Errors {
					t.Logf("Validation error: %s", err.Error())
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
					t.Errorf("Expected error containing %q, got: %v", tt.expectedError, result.Errors)
				}
			}
		})
	}
}

func TestValidationContext(t *testing.T) {
	for _, ctx := range []ValidationContext{ServerValidation, AgentValidation} {
		t.Run(string(ctx), func(t *testing.T) {
			validator := NewValidatorWithContext(ctx)
			result := validator.ValidateServiceConfig(&types.ServiceConfig{
				Hostname: "test.example.com",
				Backend:  "192.168.1.100:8080",
				Protocol: "https",
			})
			if !result.Valid {
				t.Errorf("Expected validation to pass, got errors: %v", result.Errors)
			}
		})
	}
}

func TestValidatorSetContext(t *testing.T) {
	validator := NewValidator()
	if validator.context != ServerValidation {
		t.Errorf("Expected default context ServerValidation, got %v", validator.context)
	}
	validator.SetContext(AgentValidation)
	if validator.context != AgentValidation {
		t.Errorf("Expected AgentValidation after SetContext, got %v", validator.context)
	}
}

func TestValidator_BackendValidation(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name          string
		backend       string
		expectValid   bool
		expectedError string
	}{
		{name: "valid IPv4 address with port", backend: "127.0.0.1:8080", expectValid: true},
		{name: "valid hostname with port", backend: "localhost:3000", expectValid: true},
		{name: "valid service name port", backend: "example.com:http", expectValid: true},
		{name: "invalid multiple colons", backend: "invalid:backend:format", expectValid: false, expectedError: "too many colons"},
		{name: "missing port", backend: "example.com", expectValid: false, expectedError: "missing port"},
		{name: "empty host", backend: ":8080", expectValid: false, expectedError: "empty host"},
		{name: "empty port", backend: "example.com:", expectValid: false, expectedError: "empty port"},
		{name: "port with spaces", backend: "example.com:80 80", expectValid: false, expectedError: "invalid whitespace characters"},
		{name: "backend with whitespace", backend: "example.com: 8080", expectValid: false, expectedError: "invalid whitespace characters"},
		{name: "valid IPv6 address", backend: "[::1]:8080", expectValid: true},
		{name: "invalid IPv6 missing bracket", backend: "::1:8080", expectValid: false, expectedError: "too many colons"},
		{name: "high port number", backend: "example.com:99999", expectValid: false, expectedError: "invalid port"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &types.ServiceConfig{
				Hostname: "test.example.com",
				Backend:  tt.backend,
				Protocol: "https",
			}
			result := validator.ValidateServiceConfig(config)
			if result.Valid != tt.expectValid {
				t.Errorf("Expected %v for backend %q, got %v", tt.expectValid, tt.backend, result.Valid)
				for _, err := range result.Errors {
					t.Logf("Error: %s", err.Message)
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
					t.Errorf("Expected error containing %q for backend %q, got: %v", tt.expectedError, tt.backend, result.Errors)
				}
			}
		})
	}
}

func TestValidator_ExistingServiceTracking(t *testing.T) {
	v := NewValidator()

	cfg := &types.ServiceConfig{
		Hostname: "tracked.example.com",
		Backend:  "127.0.0.1:8080",
		Protocol: "https",
	}

	if len(v.GetExistingServices()) != 0 {
		t.Fatal("expected empty existing services")
	}

	v.AddExistingService("tracked.example.com", cfg)
	if _, ok := v.GetExistingServices()["tracked.example.com"]; !ok {
		t.Fatal("expected tracked.example.com to be present")
	}

	v.RemoveExistingService("tracked.example.com")
	if len(v.GetExistingServices()) != 0 {
		t.Fatal("expected empty existing services after removal")
	}
}

func TestValidator_HostnameConflict(t *testing.T) {
	v := NewValidator()

	v.AddExistingService("conflict.example.com", &types.ServiceConfig{
		Hostname: "conflict.example.com",
		Backend:  "127.0.0.1:8080",
		Protocol: "https",
	})

	// Different backend — should be reported as a conflict.
	result := v.ValidateServiceConfig(&types.ServiceConfig{
		Hostname: "conflict.example.com",
		Backend:  "127.0.0.1:9090",
		Protocol: "https",
	})
	if result.Valid {
		t.Fatal("expected validation to fail on hostname conflict")
	}
	found := false
	for _, e := range result.Errors {
		if e.Code == "HOSTNAME_CONFLICT" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HOSTNAME_CONFLICT error, got: %v", result.Errors)
	}
}

func TestValidator_HostnameNoConflictSameConfig(t *testing.T) {
	v := NewValidator()

	cfg := &types.ServiceConfig{
		Hostname: "same.example.com",
		Backend:  "127.0.0.1:8080",
		Protocol: "https",
	}
	v.AddExistingService("same.example.com", cfg)

	// Same config — not a conflict.
	result := v.ValidateServiceConfig(cfg)
	if !result.Valid {
		t.Fatalf("expected no conflict for identical config, got: %v", result.Errors)
	}
}

func BenchmarkValidator_ValidateServiceConfig(b *testing.B) {
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

