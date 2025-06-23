package types

import "fmt"

// ServiceConfig represents a service configuration that can be used by both agent and caddy
type ServiceConfig struct {
	Hostname     string `json:"hostname" yaml:"hostname"`
	Backend      string `json:"backend" yaml:"backend"`
	Protocol     string `json:"protocol" yaml:"protocol"`
	WebSocket    bool   `json:"websocket,omitempty" yaml:"websocket,omitempty"`
	HTTPRedirect bool   `json:"http_redirect,omitempty" yaml:"http_redirect,omitempty"`
	ListenOn     string `json:"listen_on,omitempty" yaml:"listen_on,omitempty"`
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
