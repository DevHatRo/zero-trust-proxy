package server

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"gopkg.in/yaml.v3"
)

// ServerConfig represents the complete server configuration
type ServerConfig struct {
	ConfigPath string                 `yaml:"-"` // File path for hot reload (not serialized)
	Server     ServerSettings         `yaml:"server"`
	API        APISettings            `yaml:"api"`
	Logging    LoggingConfig          `yaml:"logging,omitempty"` // Zero Trust Proxy application logging
	Caddy      CaddySettings          `yaml:"caddy"`
	HotReload  common.HotReloadConfig `yaml:"hot_reload,omitempty"`
	LogLevel   string                 `yaml:"log_level,omitempty"` // Deprecated: use logging.level instead
}

// ServerSettings contains core server configuration
type ServerSettings struct {
	ListenAddr string `yaml:"listen_addr"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`
}

// APISettings contains API server configuration
type APISettings struct {
	ListenAddr string `yaml:"listen_addr"`
}

// LoggingConfig represents the application logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level"`  // Log level (DEBUG, INFO, WARN, ERROR, FATAL)
	Format string `yaml:"format"` // Output format (console, json)
	Output string `yaml:"output"` // Output destination (stdout, stderr, or file path)
}

// CaddySettings contains Caddy configuration
type CaddySettings struct {
	AdminAPI   string       `yaml:"admin_api"`
	ConfigDir  string       `yaml:"config_dir,omitempty"`
	StorageDir string       `yaml:"storage_dir,omitempty"`
	Logging    CaddyLogging `yaml:"logging,omitempty"`
}

// CaddyLogging contains Caddy logging configuration
type CaddyLogging struct {
	Enabled            bool                   `yaml:"enabled"`
	Level              string                 `yaml:"level,omitempty"`
	Format             string                 `yaml:"format,omitempty"`
	Output             string                 `yaml:"output,omitempty"`
	Include            []string               `yaml:"include,omitempty"`
	Exclude            []string               `yaml:"exclude,omitempty"`
	Fields             map[string]interface{} `yaml:"fields,omitempty"`
	SamplingFirst      int                    `yaml:"sampling_first,omitempty"`
	SamplingThereafter int                    `yaml:"sampling_thereafter,omitempty"`
}

// LoadServerConfig loads the server configuration from a file
func LoadServerConfig(configPath string) (*ServerConfig, error) {
	// Ensure the config directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Read the config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default config if it doesn't exist
			config := createDefaultServerConfig()
			config.ConfigPath = configPath // Set the config path
			if err := SaveServerConfig(configPath, config); err != nil {
				return nil, fmt.Errorf("failed to create default config: %w", err)
			}
			return config, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse the config
	var config ServerConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set the config path (not part of YAML)
	config.ConfigPath = configPath

	// Validate and apply defaults
	if err := validateServerConfig(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// SaveServerConfig saves the server configuration to a file
func SaveServerConfig(configPath string, config *ServerConfig) error {
	// Marshal the config
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write the config file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// createDefaultServerConfig creates a minimal default server configuration
func createDefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Server: ServerSettings{
			ListenAddr: ":8443",
			CertFile:   "/config/certs/server.crt",
			KeyFile:    "/config/certs/server.key",
			CAFile:     "/config/certs/ca.crt",
		},
		API: APISettings{
			ListenAddr: ":9443",
		},
		Logging: LoggingConfig{
			Level:  "INFO",
			Format: "console",
			Output: "stdout",
		},
		Caddy: CaddySettings{
			AdminAPI:   "http://localhost:2019",
			ConfigDir:  "/config/caddy",
			StorageDir: "/config/caddy/storage",
			Logging: CaddyLogging{
				Enabled: true,
				Level:   "INFO",
				Format:  "console",
				Output:  "stdout",
				Include: []string{"ts", "request>method", "request>uri", "status", "duration", "size"},
				Exclude: []string{"request>headers>Authorization", "request>headers>Cookie"},
			},
		},
		LogLevel: "INFO", // Deprecated: maintained for backward compatibility
	}
}

// validateServerConfig validates the server configuration
func validateServerConfig(config *ServerConfig) error {
	// Validate server settings
	if config.Server.ListenAddr == "" {
		return fmt.Errorf("server.listen_addr is required")
	}
	if config.Server.CertFile == "" {
		return fmt.Errorf("server.cert_file is required")
	}
	if config.Server.KeyFile == "" {
		return fmt.Errorf("server.key_file is required")
	}
	if config.Server.CAFile == "" {
		return fmt.Errorf("server.ca_file is required")
	}

	// Validate API settings
	if config.API.ListenAddr == "" {
		return fmt.Errorf("api.listen_addr is required")
	}

	// Apply defaults for logging configuration
	if config.Logging.Level == "" {
		// Use legacy log_level if new logging.level is not set
		if config.LogLevel != "" {
			config.Logging.Level = config.LogLevel
		} else {
			config.Logging.Level = "INFO"
		}
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "console"
	}
	if config.Logging.Output == "" {
		config.Logging.Output = "stdout"
	}

	// Apply defaults for Caddy
	if config.Caddy.AdminAPI == "" {
		config.Caddy.AdminAPI = "http://localhost:2019"
	}

	return nil
}
