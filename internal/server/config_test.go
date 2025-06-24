package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

func TestLoadServerConfig(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() (string, func()) // Returns config path and cleanup function
		wantErr   bool
		validate  func(t *testing.T, config *ServerConfig)
	}{
		{
			name: "default config creation",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "server.yaml")
				return configPath, func() {}
			},
			wantErr: false,
			validate: func(t *testing.T, config *ServerConfig) {
				if config.Server.ListenAddr != ":8443" {
					t.Errorf("Expected default ListenAddr :8443, got %s", config.Server.ListenAddr)
				}
				if config.LogLevel != "INFO" {
					t.Errorf("Expected default LogLevel INFO, got %s", config.LogLevel)
				}
			},
		},
		{
			name: "valid existing config",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "server.yaml")

				configContent := `
server:
  listen_addr: ":9443"
  cert_file: "/custom/server.crt"
  key_file: "/custom/server.key"
  ca_file: "/custom/ca.crt"
api:
  listen_addr: ":10443"
caddy:
  admin_api: "http://localhost:2020"
  config_dir: "/custom/caddy"
  storage_dir: "/custom/storage"
log_level: "DEBUG"
hot_reload:
  enabled: true
  watch_interval: 5s
`
				if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
					t.Fatalf("Failed to create test config: %v", err)
				}

				return configPath, func() {}
			},
			wantErr: false,
			validate: func(t *testing.T, config *ServerConfig) {
				if config.Server.ListenAddr != ":9443" {
					t.Errorf("Expected ListenAddr :9443, got %s", config.Server.ListenAddr)
				}
				if config.API.ListenAddr != ":10443" {
					t.Errorf("Expected API ListenAddr :10443, got %s", config.API.ListenAddr)
				}
				if config.Caddy.AdminAPI != "http://localhost:2020" {
					t.Errorf("Expected AdminAPI http://localhost:2020, got %s", config.Caddy.AdminAPI)
				}
				if config.LogLevel != "DEBUG" {
					t.Errorf("Expected LogLevel DEBUG, got %s", config.LogLevel)
				}
				if !config.HotReload.Enabled {
					t.Error("Expected HotReload to be enabled")
				}
			},
		},
		{
			name: "config with Caddy logging",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "server.yaml")

				configContent := `
server:
  listen_addr: ":8443"
  cert_file: "/config/certs/server.crt"
  key_file: "/config/certs/server.key"
  ca_file: "/config/certs/ca.crt"
api:
  listen_addr: ":9443"
caddy:
  admin_api: "http://localhost:2019"
  config_dir: "/config/caddy"
  storage_dir: "/config/storage"
  logging:
    enabled: true
    level: "DEBUG"
    format: "json"
    output: "/var/log/caddy.log"
    include:
      - "ts"
      - "request>method"
      - "request>uri"
      - "status"
    exclude:
      - "request>headers>Authorization"
      - "request>headers>Cookie"
    fields:
      component: "caddy-proxy"
      environment: "test"
    sampling_first: 100
    sampling_thereafter: 50
log_level: "INFO"
`
				if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
					t.Fatalf("Failed to create test config: %v", err)
				}

				return configPath, func() {}
			},
			wantErr: false,
			validate: func(t *testing.T, config *ServerConfig) {
				logging := config.Caddy.Logging
				if !logging.Enabled {
					t.Error("Expected Caddy logging to be enabled")
				}
				if logging.Level != "DEBUG" {
					t.Errorf("Expected logging level DEBUG, got %s", logging.Level)
				}
				if logging.Format != "json" {
					t.Errorf("Expected logging format json, got %s", logging.Format)
				}
				if logging.Output != "/var/log/caddy.log" {
					t.Errorf("Expected logging output /var/log/caddy.log, got %s", logging.Output)
				}
				if len(logging.Include) != 4 {
					t.Errorf("Expected 4 include fields, got %d", len(logging.Include))
				}
				if len(logging.Exclude) != 2 {
					t.Errorf("Expected 2 exclude fields, got %d", len(logging.Exclude))
				}

				if logging.SamplingFirst != 100 {
					t.Errorf("Expected sampling_first 100, got %d", logging.SamplingFirst)
				}
				if logging.SamplingThereafter != 50 {
					t.Errorf("Expected sampling_thereafter 50, got %d", logging.SamplingThereafter)
				}
			},
		},
		{
			name: "invalid yaml",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "server.yaml")

				configContent := `
server:
  listen_addr: ":9443"
  invalid_yaml: [unclosed array
`
				if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
					t.Fatalf("Failed to create test config: %v", err)
				}

				return configPath, func() {}
			},
			wantErr: true,
		},
		{
			name: "missing required fields",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "server.yaml")

				configContent := `
server:
  # Missing required fields
api:
  listen_addr: ":10443"
`
				if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
					t.Fatalf("Failed to create test config: %v", err)
				}

				return configPath, func() {}
			},
			wantErr: true,
		},
		{
			name: "unreadable directory",
			setupFunc: func() (string, func()) {
				if os.Getuid() == 0 {
					t.Skip("Cannot test permission denied as root")
				}

				tmpDir := t.TempDir()
				unreadableDir := filepath.Join(tmpDir, "unreadable")
				if err := os.Mkdir(unreadableDir, 0000); err != nil {
					t.Fatalf("Failed to create unreadable dir: %v", err)
				}

				configPath := filepath.Join(unreadableDir, "server.yaml")

				return configPath, func() {
					os.Chmod(unreadableDir, 0755) // Restore permissions for cleanup
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath, cleanup := tt.setupFunc()
			defer cleanup()

			config, err := LoadServerConfig(configPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("LoadServerConfig() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("LoadServerConfig() unexpected error: %v", err)
				return
			}

			if config == nil {
				t.Fatal("LoadServerConfig() returned nil config")
			}

			if config.ConfigPath != configPath {
				t.Errorf("Expected ConfigPath %s, got %s", configPath, config.ConfigPath)
			}

			if tt.validate != nil {
				tt.validate(t, config)
			}
		})
	}
}

func TestSaveServerConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    *ServerConfig
		setupFunc func() (string, func()) // Returns config path and cleanup function
		wantErr   bool
	}{
		{
			name: "valid config save",
			config: &ServerConfig{
				Server: ServerSettings{
					ListenAddr: ":8443",
					CertFile:   "/test/server.crt",
					KeyFile:    "/test/server.key",
					CAFile:     "/test/ca.crt",
				},
				API: APISettings{
					ListenAddr: ":9443",
				},
				Caddy: CaddySettings{
					AdminAPI: "http://localhost:2019",
				},
				LogLevel: "INFO",
			},
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "server.yaml")
				return configPath, func() {}
			},
			wantErr: false,
		},
		{
			name:   "unwritable directory",
			config: createDefaultServerConfig(),
			setupFunc: func() (string, func()) {
				if os.Getuid() == 0 {
					t.Skip("Cannot test permission denied as root")
				}

				tmpDir := t.TempDir()
				unwritableDir := filepath.Join(tmpDir, "unwritable")
				if err := os.Mkdir(unwritableDir, 0555); err != nil {
					t.Fatalf("Failed to create unwritable dir: %v", err)
				}

				configPath := filepath.Join(unwritableDir, "server.yaml")

				return configPath, func() {
					os.Chmod(unwritableDir, 0755) // Restore permissions for cleanup
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath, cleanup := tt.setupFunc()
			defer cleanup()

			err := SaveServerConfig(configPath, tt.config)

			if tt.wantErr {
				if err == nil {
					t.Errorf("SaveServerConfig() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("SaveServerConfig() unexpected error: %v", err)
				return
			}

			// Verify the file was created and is readable
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				t.Errorf("SaveServerConfig() did not create config file")
			}

			// Try to load it back to verify it's valid
			loadedConfig, err := LoadServerConfig(configPath)
			if err != nil {
				t.Errorf("Failed to load saved config: %v", err)
				return
			}

			if loadedConfig.Server.ListenAddr != tt.config.Server.ListenAddr {
				t.Errorf("Saved config doesn't match original")
			}
		})
	}
}

func TestCreateDefaultServerConfig(t *testing.T) {
	config := createDefaultServerConfig()

	if config == nil {
		t.Fatal("createDefaultServerConfig() returned nil")
	}

	// Test default values
	if config.Server.ListenAddr != ":8443" {
		t.Errorf("Expected listen addr :8443, got %s", config.Server.ListenAddr)
	}

	if config.API.ListenAddr != ":9443" {
		t.Errorf("Expected API listen addr :9443, got %s", config.API.ListenAddr)
	}

	// Test application logging defaults
	if config.Logging.Level != "INFO" {
		t.Errorf("Expected logging level INFO, got %s", config.Logging.Level)
	}

	if config.Logging.Format != "console" {
		t.Errorf("Expected logging format console, got %s", config.Logging.Format)
	}

	if config.Logging.Output != "stdout" {
		t.Errorf("Expected logging output stdout, got %s", config.Logging.Output)
	}

	// Test Caddy logging defaults
	if !config.Caddy.Logging.Enabled {
		t.Error("Expected Caddy logging to be enabled by default")
	}

	if config.Caddy.Logging.Level != "INFO" {
		t.Errorf("Expected Caddy logging level INFO, got %s", config.Caddy.Logging.Level)
	}

	// Test legacy log level (deprecated)
	if config.LogLevel != "INFO" {
		t.Errorf("Expected legacy log level INFO, got %s", config.LogLevel)
	}
}

func TestValidateServerConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *ServerConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid config",
			config:  createDefaultServerConfig(),
			wantErr: false,
		},
		{
			name: "missing server listen addr",
			config: &ServerConfig{
				Server: ServerSettings{
					CertFile: "/test/server.crt",
					KeyFile:  "/test/server.key",
					CAFile:   "/test/ca.crt",
				},
				API: APISettings{
					ListenAddr: ":9443",
				},
			},
			wantErr: true,
			errMsg:  "server.listen_addr is required",
		},
		{
			name: "missing cert file",
			config: &ServerConfig{
				Server: ServerSettings{
					ListenAddr: ":8443",
					KeyFile:    "/test/server.key",
					CAFile:     "/test/ca.crt",
				},
				API: APISettings{
					ListenAddr: ":9443",
				},
			},
			wantErr: true,
			errMsg:  "server.cert_file is required",
		},
		{
			name: "missing key file",
			config: &ServerConfig{
				Server: ServerSettings{
					ListenAddr: ":8443",
					CertFile:   "/test/server.crt",
					CAFile:     "/test/ca.crt",
				},
				API: APISettings{
					ListenAddr: ":9443",
				},
			},
			wantErr: true,
			errMsg:  "server.key_file is required",
		},
		{
			name: "missing ca file",
			config: &ServerConfig{
				Server: ServerSettings{
					ListenAddr: ":8443",
					CertFile:   "/test/server.crt",
					KeyFile:    "/test/server.key",
				},
				API: APISettings{
					ListenAddr: ":9443",
				},
			},
			wantErr: true,
			errMsg:  "server.ca_file is required",
		},
		{
			name: "missing api listen addr",
			config: &ServerConfig{
				Server: ServerSettings{
					ListenAddr: ":8443",
					CertFile:   "/test/server.crt",
					KeyFile:    "/test/server.key",
					CAFile:     "/test/ca.crt",
				},
				API: APISettings{},
			},
			wantErr: true,
			errMsg:  "api.listen_addr is required",
		},
		{
			name: "empty caddy admin api gets default",
			config: &ServerConfig{
				Server: ServerSettings{
					ListenAddr: ":8443",
					CertFile:   "/test/server.crt",
					KeyFile:    "/test/server.key",
					CAFile:     "/test/ca.crt",
				},
				API: APISettings{
					ListenAddr: ":9443",
				},
				Caddy: CaddySettings{
					AdminAPI: "", // Should get default
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with Caddy logging",
			config: &ServerConfig{
				Server: ServerSettings{
					ListenAddr: ":8443",
					CertFile:   "/test/server.crt",
					KeyFile:    "/test/server.key",
					CAFile:     "/test/ca.crt",
				},
				API: APISettings{
					ListenAddr: ":9443",
				},
				Caddy: CaddySettings{
					AdminAPI: "http://localhost:2019",
					Logging: CaddyLogging{
						Enabled: true,
						Level:   "INFO",
						Format:  "json",
						Output:  "stdout",
						Include: []string{"ts", "request>method", "status"},
						Exclude: []string{"request>headers>Authorization"},

						SamplingFirst:      100,
						SamplingThereafter: 50,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with disabled Caddy logging",
			config: &ServerConfig{
				Server: ServerSettings{
					ListenAddr: ":8443",
					CertFile:   "/test/server.crt",
					KeyFile:    "/test/server.key",
					CAFile:     "/test/ca.crt",
				},
				API: APISettings{
					ListenAddr: ":9443",
				},
				Caddy: CaddySettings{
					AdminAPI: "http://localhost:2019",
					Logging: CaddyLogging{
						Enabled: false,
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateServerConfig(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateServerConfig() expected error, got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateServerConfig() error = %v, expected to contain %s", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("validateServerConfig() unexpected error: %v", err)
			}

			// Check that default was applied for empty AdminAPI
			if tt.config.Caddy.AdminAPI == "" {
				t.Error("validateServerConfig() should have applied default AdminAPI")
			}
		})
	}
}

func TestServerConfigRoundTrip(t *testing.T) {
	// Test that we can save and load a config without losing data
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "server.yaml")

	originalConfig := &ServerConfig{
		Server: ServerSettings{
			ListenAddr: ":8443",
			CertFile:   "/test/server.crt",
			KeyFile:    "/test/server.key",
			CAFile:     "/test/ca.crt",
		},
		API: APISettings{
			ListenAddr: ":9443",
		},
		Caddy: CaddySettings{
			AdminAPI:   "http://localhost:2019",
			ConfigDir:  "/test/caddy",
			StorageDir: "/test/storage",
		},
		HotReload: common.HotReloadConfig{
			Enabled:         true,
			WatchConfig:     true,
			DebounceDelay:   100 * time.Millisecond,
			GracefulTimeout: 30 * time.Second,
		},
		LogLevel: "DEBUG",
	}

	// Save the config
	if err := SaveServerConfig(configPath, originalConfig); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load it back
	loadedConfig, err := LoadServerConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Compare the configs
	if loadedConfig.Server.ListenAddr != originalConfig.Server.ListenAddr {
		t.Errorf("ListenAddr mismatch: got %s, want %s", loadedConfig.Server.ListenAddr, originalConfig.Server.ListenAddr)
	}
	if loadedConfig.API.ListenAddr != originalConfig.API.ListenAddr {
		t.Errorf("API ListenAddr mismatch: got %s, want %s", loadedConfig.API.ListenAddr, originalConfig.API.ListenAddr)
	}
	if loadedConfig.Caddy.AdminAPI != originalConfig.Caddy.AdminAPI {
		t.Errorf("AdminAPI mismatch: got %s, want %s", loadedConfig.Caddy.AdminAPI, originalConfig.Caddy.AdminAPI)
	}
	if loadedConfig.LogLevel != originalConfig.LogLevel {
		t.Errorf("LogLevel mismatch: got %s, want %s", loadedConfig.LogLevel, originalConfig.LogLevel)
	}
	if loadedConfig.HotReload.Enabled != originalConfig.HotReload.Enabled {
		t.Errorf("HotReload.Enabled mismatch: got %v, want %v", loadedConfig.HotReload.Enabled, originalConfig.HotReload.Enabled)
	}
}

// TestCaddyLoggingConfigRoundTrip tests that Caddy logging configuration survives save/load cycles
func TestCaddyLoggingConfigRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "server.yaml")

	originalConfig := &ServerConfig{
		Server: ServerSettings{
			ListenAddr: ":8443",
			CertFile:   "/test/server.crt",
			KeyFile:    "/test/server.key",
			CAFile:     "/test/ca.crt",
		},
		API: APISettings{
			ListenAddr: ":9443",
		},
		Caddy: CaddySettings{
			AdminAPI:   "http://localhost:2019",
			ConfigDir:  "/test/caddy",
			StorageDir: "/test/storage",
			Logging: CaddyLogging{
				Enabled: true,
				Level:   "DEBUG",
				Format:  "json",
				Output:  "/var/log/caddy-access.log",
				Include: []string{
					"ts",
					"request>method",
					"request>uri",
					"request>host",
					"request>remote_ip",
					"status",
					"duration",
					"size",
				},
				Exclude: []string{
					"request>headers>Authorization",
					"request>headers>Cookie",
					"request>body",
				},
				SamplingFirst:      100,
				SamplingThereafter: 50,
			},
		},
		LogLevel: "DEBUG",
	}

	// Save the config
	if err := SaveServerConfig(configPath, originalConfig); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load it back
	loadedConfig, err := LoadServerConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Compare Caddy logging configuration
	originalLogging := originalConfig.Caddy.Logging
	loadedLogging := loadedConfig.Caddy.Logging

	if loadedLogging.Enabled != originalLogging.Enabled {
		t.Errorf("Logging.Enabled mismatch: got %v, want %v", loadedLogging.Enabled, originalLogging.Enabled)
	}
	if loadedLogging.Level != originalLogging.Level {
		t.Errorf("Logging.Level mismatch: got %s, want %s", loadedLogging.Level, originalLogging.Level)
	}
	if loadedLogging.Format != originalLogging.Format {
		t.Errorf("Logging.Format mismatch: got %s, want %s", loadedLogging.Format, originalLogging.Format)
	}
	if loadedLogging.Output != originalLogging.Output {
		t.Errorf("Logging.Output mismatch: got %s, want %s", loadedLogging.Output, originalLogging.Output)
	}

	// Compare include fields
	if len(loadedLogging.Include) != len(originalLogging.Include) {
		t.Errorf("Include fields length mismatch: got %d, want %d", len(loadedLogging.Include), len(originalLogging.Include))
	} else {
		for i, field := range originalLogging.Include {
			if loadedLogging.Include[i] != field {
				t.Errorf("Include field %d mismatch: got %s, want %s", i, loadedLogging.Include[i], field)
			}
		}
	}

	// Compare exclude fields
	if len(loadedLogging.Exclude) != len(originalLogging.Exclude) {
		t.Errorf("Exclude fields length mismatch: got %d, want %d", len(loadedLogging.Exclude), len(originalLogging.Exclude))
	} else {
		for i, field := range originalLogging.Exclude {
			if loadedLogging.Exclude[i] != field {
				t.Errorf("Exclude field %d mismatch: got %s, want %s", i, loadedLogging.Exclude[i], field)
			}
		}
	}

	// Compare sampling configuration
	if loadedLogging.SamplingFirst != originalLogging.SamplingFirst {
		t.Errorf("SamplingFirst mismatch: got %d, want %d", loadedLogging.SamplingFirst, originalLogging.SamplingFirst)
	}
	if loadedLogging.SamplingThereafter != originalLogging.SamplingThereafter {
		t.Errorf("SamplingThereafter mismatch: got %d, want %d", loadedLogging.SamplingThereafter, originalLogging.SamplingThereafter)
	}
}

func BenchmarkLoadServerConfig(b *testing.B) {
	tmpDir := b.TempDir()
	configPath := filepath.Join(tmpDir, "server.yaml")

	// Create a test config file
	config := createDefaultServerConfig()
	if err := SaveServerConfig(configPath, config); err != nil {
		b.Fatalf("Failed to create test config: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := LoadServerConfig(configPath)
		if err != nil {
			b.Fatalf("LoadServerConfig failed: %v", err)
		}
	}
}

func BenchmarkSaveServerConfig(b *testing.B) {
	tmpDir := b.TempDir()
	config := createDefaultServerConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		configPath := filepath.Join(tmpDir, "server_bench.yaml")
		err := SaveServerConfig(configPath, config)
		if err != nil {
			b.Fatalf("SaveServerConfig failed: %v", err)
		}
		os.Remove(configPath) // Clean up for next iteration
	}
}

// TestApplicationLoggingConfig tests the application logging configuration
func TestApplicationLoggingConfig(t *testing.T) {
	config := &ServerConfig{
		Server: ServerSettings{
			ListenAddr: ":8443",
			CertFile:   "/test/server.crt",
			KeyFile:    "/test/server.key",
			CAFile:     "/test/ca.crt",
		},
		API: APISettings{
			ListenAddr: ":9443",
		},
		Logging: LoggingConfig{
			Level:  "DEBUG",
			Format: "json",
			Output: "stderr",
		},
		Caddy: CaddySettings{
			AdminAPI: "http://localhost:2019",
		},
	}

	// Validate the configuration
	err := validateServerConfig(config)
	if err != nil {
		t.Fatalf("Configuration validation failed: %v", err)
	}

	// Test that values are preserved
	if config.Logging.Level != "DEBUG" {
		t.Errorf("Expected logging level DEBUG, got %s", config.Logging.Level)
	}

	if config.Logging.Format != "json" {
		t.Errorf("Expected logging format json, got %s", config.Logging.Format)
	}

	if config.Logging.Output != "stderr" {
		t.Errorf("Expected logging output stderr, got %s", config.Logging.Output)
	}
}

// TestLoggingConfigDefaults tests that defaults are applied correctly
func TestLoggingConfigDefaults(t *testing.T) {
	config := &ServerConfig{
		Server: ServerSettings{
			ListenAddr: ":8443",
			CertFile:   "/test/server.crt",
			KeyFile:    "/test/server.key",
			CAFile:     "/test/ca.crt",
		},
		API: APISettings{
			ListenAddr: ":9443",
		},
		// Logging config intentionally empty to test defaults
		Logging: LoggingConfig{},
		Caddy: CaddySettings{
			AdminAPI: "http://localhost:2019",
		},
	}

	// Validate the configuration (this should apply defaults)
	err := validateServerConfig(config)
	if err != nil {
		t.Fatalf("Configuration validation failed: %v", err)
	}

	// Test that defaults were applied
	if config.Logging.Level != "INFO" {
		t.Errorf("Expected default logging level INFO, got %s", config.Logging.Level)
	}

	if config.Logging.Format != "console" {
		t.Errorf("Expected default logging format console, got %s", config.Logging.Format)
	}

	if config.Logging.Output != "stdout" {
		t.Errorf("Expected default logging output stdout, got %s", config.Logging.Output)
	}
}

// TestLegacyLogLevelCompatibility tests backward compatibility with legacy log_level
func TestLegacyLogLevelCompatibility(t *testing.T) {
	config := &ServerConfig{
		Server: ServerSettings{
			ListenAddr: ":8443",
			CertFile:   "/test/server.crt",
			KeyFile:    "/test/server.key",
			CAFile:     "/test/ca.crt",
		},
		API: APISettings{
			ListenAddr: ":9443",
		},
		Logging: LoggingConfig{
			// Level intentionally empty to test legacy fallback
		},
		Caddy: CaddySettings{
			AdminAPI: "http://localhost:2019",
		},
		LogLevel: "WARN", // Legacy log level
	}

	// Validate the configuration
	err := validateServerConfig(config)
	if err != nil {
		t.Fatalf("Configuration validation failed: %v", err)
	}

	// Test that legacy log level is used when new logging.level is empty
	if config.Logging.Level != "WARN" {
		t.Errorf("Expected logging level from legacy config WARN, got %s", config.Logging.Level)
	}
}

// TestLoggingConfigRoundTrip tests saving and loading configuration with logging
func TestLoggingConfigRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test-logging-config.yaml")

	originalConfig := &ServerConfig{
		Server: ServerSettings{
			ListenAddr: ":8443",
			CertFile:   "/test/server.crt",
			KeyFile:    "/test/server.key",
			CAFile:     "/test/ca.crt",
		},
		API: APISettings{
			ListenAddr: ":9443",
		},
		Logging: LoggingConfig{
			Level:  "DEBUG",
			Format: "json",
			Output: "/var/log/app.log",
		},
		Caddy: CaddySettings{
			AdminAPI: "http://localhost:2019",
			Logging: CaddyLogging{
				Enabled: true,
				Level:   "WARN",
				Format:  "json",
			},
		},
	}

	// Save the configuration
	err := SaveServerConfig(configPath, originalConfig)
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load the configuration
	loadedConfig, err := LoadServerConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Compare application logging settings
	if loadedConfig.Logging.Level != originalConfig.Logging.Level {
		t.Errorf("Logging level mismatch: expected %s, got %s", originalConfig.Logging.Level, loadedConfig.Logging.Level)
	}

	if loadedConfig.Logging.Format != originalConfig.Logging.Format {
		t.Errorf("Logging format mismatch: expected %s, got %s", originalConfig.Logging.Format, loadedConfig.Logging.Format)
	}

	if loadedConfig.Logging.Output != originalConfig.Logging.Output {
		t.Errorf("Logging output mismatch: expected %s, got %s", originalConfig.Logging.Output, loadedConfig.Logging.Output)
	}

	// Note: Fields functionality has been removed
}
