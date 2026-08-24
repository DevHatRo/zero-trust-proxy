package serverconfig

import (
	"bytes"
	"fmt"
	"io"
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
	if err := strictUnmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &cfg, nil
}

// strictUnmarshal decodes YAML rejecting unknown fields. A misspelled
// key in a security-relevant block (e.g. `group:` for `groups:` in an
// access rule) must fail the load, not silently produce a zero value
// that fails open. Exactly one document is allowed: a stray `---`
// would otherwise silently discard everything after it (including,
// say, the whole access policy).
func strictUnmarshal(data []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if err == io.EOF {
			return nil // empty input: caller keeps defaults
		}
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("config contains multiple YAML documents; only one is allowed")
		}
		return err
	}
	return nil
}

// Parse decodes YAML bytes (no defaults overlay; intended for tests).
func Parse(data []byte) (*Config, error) {
	cfg := Defaults()
	if err := strictUnmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}
