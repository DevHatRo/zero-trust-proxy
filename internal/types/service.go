package types

import (
	"fmt"
	"time"
)

// ServiceConfig is the on-wire shape of a service registration sent
// from the agent to the server.
//
// Timeout, when non-zero, overrides router.request_timeout for this
// service. Encoded as a Go duration string (e.g. "30s", "5m") on the
// wire and in YAML.
type ServiceConfig struct {
	Hostname  string        `json:"hostname" yaml:"hostname"`
	Backend   string        `json:"backend" yaml:"backend"`
	Protocol  string        `json:"protocol" yaml:"protocol"`
	WebSocket bool          `json:"websocket,omitempty" yaml:"websocket,omitempty"`
	Timeout   time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (ve ValidationError) Error() string {
	return fmt.Sprintf("validation error in %s: %s (%s)", ve.Field, ve.Message, ve.Code)
}

// ValidationResult contains the result of configuration validation
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors"`
}
