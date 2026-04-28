package serverconfig

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads YAML from path, overlays it on Defaults(), and validates
// the result.
func Load(path string) (*Config, error) {
	cfg := Defaults()
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path is trusted input
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &cfg, nil
}

// Parse decodes YAML bytes (no defaults overlay; intended for tests).
func Parse(data []byte) (*Config, error) {
	cfg := Defaults()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}
