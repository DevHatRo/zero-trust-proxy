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
		t.Errorf("Expected default ListenAddr :8443, got %s", config.Server.ListenAddr)
	}

	if config.API.ListenAddr != ":9443" {
		t.Errorf("Expected default API ListenAddr :9443, got %s", config.API.ListenAddr)
	}

	if config.Caddy.AdminAPI != "http://localhost:2019" {
		t.Errorf("Expected default AdminAPI http://localhost:2019, got %s", config.Caddy.AdminAPI)
	}

	if config.LogLevel != "INFO" {
		t.Errorf("Expected default LogLevel INFO, got %s", config.LogLevel)
	}

	// Test certificate paths are set
	if config.Server.CertFile == "" {
		t.Error("Expected CertFile to be set")
	}
	if config.Server.KeyFile == "" {
		t.Error("Expected KeyFile to be set")
	}
	if config.Server.CAFile == "" {
		t.Error("Expected CAFile to be set")
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
