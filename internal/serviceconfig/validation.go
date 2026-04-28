package serviceconfig

import (
	"fmt"
	"strings"

	"github.com/devhatro/zero-trust-proxy/internal/types"
)

// ValidationContext indicates where the validation is being performed.
// Currently it only tweaks one warning; kept for API compatibility
// with callers that constructed via NewValidatorWithContext.
type ValidationContext string

const (
	AgentValidation  ValidationContext = "agent"
	ServerValidation ValidationContext = "server"
)

// Validator checks per-service configurations for structural validity
// before the agent registers them with the server. The validator does
// **not** depend on Caddy in any way — historical shell-out to a
// `caddy validate` binary was removed once the project moved off
// Caddy.
type Validator struct {
	existingServices map[string]*types.ServiceConfig
	context          ValidationContext
}

// NewValidator returns a validator with the default ServerValidation
// context. Most callers want NewValidatorWithContext.
func NewValidator() *Validator {
	return &Validator{
		existingServices: make(map[string]*types.ServiceConfig),
		context:          ServerValidation,
	}
}

// NewValidatorWithContext constructs a validator scoped to either the
// agent side or the server side. The context only affects a couple of
// log warnings.
func NewValidatorWithContext(context ValidationContext) *Validator {
	return &Validator{
		existingServices: make(map[string]*types.ServiceConfig),
		context:          context,
	}
}

// SetContext updates the validation context.
func (v *Validator) SetContext(context ValidationContext) {
	v.context = context
}

// ValidateServiceConfig validates a service configuration.
func (v *Validator) ValidateServiceConfig(config *types.ServiceConfig) *types.ValidationResult {
	result := &types.ValidationResult{
		Valid:  true,
		Errors: []types.ValidationError{},
	}

	if err := v.validateBasics(config); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, *err)
		return result
	}

	if err := v.checkHostnameConflicts(config.Hostname, config); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, *err)
	}

	return result
}

// validateBasics enforces the structural rules: non-empty hostname,
// well-formed backend, and a supported protocol.
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

// validateBackendAddress validates the backend address format.
func (v *Validator) validateBackendAddress(backend string) error {
	if strings.Contains(backend, " ") || strings.Contains(backend, "\t") || strings.Contains(backend, "\n") {
		return fmt.Errorf("backend address contains invalid whitespace characters")
	}

	// IPv6 in brackets like [::1]:8080
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

	colonCount := strings.Count(backend, ":")
	if colonCount == 0 {
		return fmt.Errorf("backend address missing port (expected format: host:port)")
	}
	if colonCount > 1 {
		return fmt.Errorf("backend address has too many colons (found %d, expected 1 for host:port format)", colonCount)
	}

	parts := strings.SplitN(backend, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("backend address could not be split into host and port")
	}
	host := parts[0]
	port := parts[1]

	if host == "" {
		return fmt.Errorf("backend address has empty host")
	}
	if port == "" {
		return fmt.Errorf("backend address has empty port")
	}
	if !isValidPort(port) {
		return fmt.Errorf("backend address has invalid port: %s", port)
	}
	return nil
}

// isValidPort reports whether port is a numeric port in [1, 65535] or
// a short service name like "http".
func isValidPort(port string) bool {
	if len(port) == 0 {
		return false
	}
	if strings.ContainsAny(port, ": \t\n") {
		return false
	}

	isNumeric := true
	for _, char := range port {
		if char < '0' || char > '9' {
			isNumeric = false
			break
		}
	}

	if isNumeric {
		num := 0
		for _, char := range port {
			num = num*10 + int(char-'0')
			if num > 65535 {
				return false
			}
		}
		return num > 0
	}

	return len(port) <= 15
}

// checkHostnameConflicts reports a conflict when the same hostname is
// re-registered with a different backend or protocol.
func (v *Validator) checkHostnameConflicts(hostname string, newConfig *types.ServiceConfig) *types.ValidationError {
	if existingConfig, exists := v.existingServices[hostname]; exists {
		if existingConfig.Protocol == newConfig.Protocol &&
			existingConfig.Backend == newConfig.Backend {
			return nil
		}

		return &types.ValidationError{
			Field:   "hostname",
			Message: fmt.Sprintf("hostname %s conflicts with existing service", hostname),
			Code:    "HOSTNAME_CONFLICT",
		}
	}
	return nil
}

// AddExistingService tracks a service for conflict detection.
func (v *Validator) AddExistingService(hostname string, config *types.ServiceConfig) {
	v.existingServices[hostname] = config
}

// RemoveExistingService removes a service from conflict tracking.
func (v *Validator) RemoveExistingService(hostname string) {
	delete(v.existingServices, hostname)
}

// GetExistingServices returns a copy of existing services map.
func (v *Validator) GetExistingServices() map[string]*types.ServiceConfig {
	out := make(map[string]*types.ServiceConfig, len(v.existingServices))
	for k, vv := range v.existingServices {
		out[k] = vv
	}
	return out
}
