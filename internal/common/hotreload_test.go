package common

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// MockConfigReloader implements ConfigReloader for testing
type MockConfigReloader struct {
	configPath       string
	componentName    string
	hotReloadEnabled bool
	reloadCount      int
	reloadError      error
	reloadDelay      time.Duration
	mu               sync.RWMutex
}

func NewMockConfigReloader(configPath, componentName string, enabled bool) *MockConfigReloader {
	return &MockConfigReloader{
		configPath:       configPath,
		componentName:    componentName,
		hotReloadEnabled: enabled,
	}
}

func (m *MockConfigReloader) ReloadConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.reloadDelay > 0 {
		time.Sleep(m.reloadDelay)
	}

	m.reloadCount++
	return m.reloadError
}

func (m *MockConfigReloader) GetConfigPath() string {
	return m.configPath
}

func (m *MockConfigReloader) IsHotReloadEnabled() bool {
	return m.hotReloadEnabled
}

func (m *MockConfigReloader) GetComponentName() string {
	return m.componentName
}

func (m *MockConfigReloader) GetReloadCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.reloadCount
}

func (m *MockConfigReloader) SetReloadError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloadError = err
}

func (m *MockConfigReloader) SetReloadDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloadDelay = delay
}

func TestNewFileWatcher(t *testing.T) {
	reloader := NewMockConfigReloader("/test/config.yaml", "test-component", true)
	watcher := NewFileWatcher(reloader)

	if watcher == nil {
		t.Fatal("NewFileWatcher returned nil")
	}
	if watcher.reloader != reloader {
		t.Error("FileWatcher reloader not set correctly")
	}
	if watcher.debounceDelay != 100*time.Millisecond {
		t.Errorf("Expected default debounce delay 100ms, got %v", watcher.debounceDelay)
	}
	if watcher.running {
		t.Error("FileWatcher should not be running initially")
	}
}

func TestFileWatcherStart(t *testing.T) {
	tests := []struct {
		name            string
		setupFunc       func() (*MockConfigReloader, string, func())
		wantErr         bool
		expectedRunning bool
	}{
		{
			name: "hot reload disabled",
			setupFunc: func() (*MockConfigReloader, string, func()) {
				tmpFile := createTempConfigFile(t, "test config")
				reloader := NewMockConfigReloader(tmpFile, "test-component", false)
				return reloader, tmpFile, func() { os.Remove(tmpFile) }
			},
			wantErr:         false,
			expectedRunning: false,
		},
		{
			name: "empty config path",
			setupFunc: func() (*MockConfigReloader, string, func()) {
				reloader := NewMockConfigReloader("", "test-component", true)
				return reloader, "", func() {}
			},
			wantErr:         false,
			expectedRunning: false,
		},
		{
			name: "valid config file",
			setupFunc: func() (*MockConfigReloader, string, func()) {
				tmpFile := createTempConfigFile(t, "test config")
				reloader := NewMockConfigReloader(tmpFile, "test-component", true)
				return reloader, tmpFile, func() { os.Remove(tmpFile) }
			},
			wantErr:         false,
			expectedRunning: true,
		},
		{
			name: "non-existent config file",
			setupFunc: func() (*MockConfigReloader, string, func()) {
				tmpFile := "/tmp/non-existent-config.yaml"
				reloader := NewMockConfigReloader(tmpFile, "test-component", true)
				return reloader, tmpFile, func() {}
			},
			wantErr:         true,
			expectedRunning: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reloader, _, cleanup := tt.setupFunc()
			defer cleanup()

			watcher := NewFileWatcher(reloader)
			err := watcher.Start()

			if tt.wantErr {
				if err == nil {
					t.Errorf("FileWatcher.Start() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("FileWatcher.Start() unexpected error: %v", err)
				}
			}

			if watcher.running != tt.expectedRunning {
				t.Errorf("Expected running state %v, got %v", tt.expectedRunning, watcher.running)
			}

			// Clean up
			if watcher.running {
				watcher.Stop()
				// Give the goroutine time to exit to avoid race conditions
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func TestFileWatcherStop(t *testing.T) {
	tmpFile := createTempConfigFile(t, "test config")
	defer os.Remove(tmpFile)

	reloader := NewMockConfigReloader(tmpFile, "test-component", true)
	watcher := NewFileWatcher(reloader)

	// Start the watcher
	err := watcher.Start()
	if err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}

	if !watcher.running {
		t.Error("Watcher should be running after Start()")
	}

	// Stop the watcher
	err = watcher.Stop()
	if err != nil {
		t.Errorf("FileWatcher.Stop() failed: %v", err)
	}

	if watcher.running {
		t.Error("Watcher should not be running after Stop()")
	}

	// Stopping again should not error
	err = watcher.Stop()
	if err != nil {
		t.Errorf("FileWatcher.Stop() should not error when already stopped: %v", err)
	}
}

func TestFileWatcherAlreadyRunning(t *testing.T) {
	tmpFile := createTempConfigFile(t, "test config")
	defer os.Remove(tmpFile)

	reloader := NewMockConfigReloader(tmpFile, "test-component", true)
	watcher := NewFileWatcher(reloader)

	// Start the watcher
	err := watcher.Start()
	if err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer watcher.Stop()

	// Try to start again
	err = watcher.Start()
	if err == nil {
		t.Error("FileWatcher.Start() should error when already running")
	}
}

func TestFileWatcherSetDebounceDelay(t *testing.T) {
	reloader := NewMockConfigReloader("/test/config.yaml", "test-component", true)
	watcher := NewFileWatcher(reloader)

	newDelay := 250 * time.Millisecond
	watcher.SetDebounceDelay(newDelay)

	if watcher.debounceDelay != newDelay {
		t.Errorf("Expected debounce delay %v, got %v", newDelay, watcher.debounceDelay)
	}
}

func TestFileWatcherReload(t *testing.T) {
	tmpFile := createTempConfigFile(t, "initial config")
	defer os.Remove(tmpFile)

	reloader := NewMockConfigReloader(tmpFile, "test-component", true)
	watcher := NewFileWatcher(reloader)

	// Set very short debounce delay for testing
	watcher.SetDebounceDelay(10 * time.Millisecond)

	err := watcher.Start()
	if err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer watcher.Stop()

	// Wait for the watch loop to be ready
	time.Sleep(50 * time.Millisecond)

	initialCount := reloader.GetReloadCount()

	// Write to the config file to trigger a reload
	err = os.WriteFile(tmpFile, []byte("updated config"), 0644)
	if err != nil {
		t.Fatalf("Failed to write to config file: %v", err)
	}

	// Wait for the debounced reload
	time.Sleep(100 * time.Millisecond)

	if reloader.GetReloadCount() <= initialCount {
		t.Error("Expected reload to be triggered after file change")
	}
}

func TestFileWatcherReloadError(t *testing.T) {
	tmpFile := createTempConfigFile(t, "initial config")
	defer os.Remove(tmpFile)

	reloader := NewMockConfigReloader(tmpFile, "test-component", true)
	reloader.SetReloadError(fmt.Errorf("reload failed"))

	watcher := NewFileWatcher(reloader)
	watcher.SetDebounceDelay(10 * time.Millisecond)

	err := watcher.Start()
	if err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer watcher.Stop()

	// Wait for the watch loop to be ready
	time.Sleep(50 * time.Millisecond)

	// Write to the config file to trigger a reload
	err = os.WriteFile(tmpFile, []byte("updated config"), 0644)
	if err != nil {
		t.Fatalf("Failed to write to config file: %v", err)
	}

	// Wait for the debounced reload
	time.Sleep(100 * time.Millisecond)

	// The reload should have been attempted despite the error
	if reloader.GetReloadCount() == 0 {
		t.Error("Expected reload attempt even when error occurs")
	}
}

func TestHotReloadManager(t *testing.T) {
	manager := NewHotReloadManager()

	if manager == nil {
		t.Fatal("NewHotReloadManager returned nil")
	}
	if manager.watchers == nil {
		t.Error("HotReloadManager watchers map not initialized")
	}
}

func TestHotReloadManagerRegisterReloader(t *testing.T) {
	tmpFile := createTempConfigFile(t, "test config")
	defer os.Remove(tmpFile)

	manager := NewHotReloadManager()
	defer manager.StopAll()

	reloader := NewMockConfigReloader(tmpFile, "test-component", true)

	err := manager.RegisterReloader(reloader)
	if err != nil {
		t.Errorf("RegisterReloader failed: %v", err)
	}

	// Check that the reloader was registered
	status := manager.GetStatus()
	if !status["test-component"] {
		t.Error("Expected component to be registered and running")
	}

	// Try to register the same component again
	err = manager.RegisterReloader(reloader)
	if err == nil {
		t.Error("RegisterReloader should fail when component already registered")
	}
}

func TestHotReloadManagerUnregisterReloader(t *testing.T) {
	tmpFile := createTempConfigFile(t, "test config")
	defer os.Remove(tmpFile)

	manager := NewHotReloadManager()
	defer manager.StopAll()

	reloader := NewMockConfigReloader(tmpFile, "test-component", true)

	// Register the reloader
	err := manager.RegisterReloader(reloader)
	if err != nil {
		t.Fatalf("RegisterReloader failed: %v", err)
	}

	// Unregister the reloader
	err = manager.UnregisterReloader("test-component")
	if err != nil {
		t.Errorf("UnregisterReloader failed: %v", err)
	}

	// Check that the reloader was unregistered
	status := manager.GetStatus()
	if status["test-component"] {
		t.Error("Expected component to be unregistered")
	}

	// Try to unregister a non-existent component
	err = manager.UnregisterReloader("non-existent")
	if err == nil {
		t.Error("UnregisterReloader should fail for non-existent component")
	}
}

func TestHotReloadManagerTriggerReload(t *testing.T) {
	tmpFile := createTempConfigFile(t, "test config")
	defer os.Remove(tmpFile)

	manager := NewHotReloadManager()
	defer manager.StopAll()

	reloader := NewMockConfigReloader(tmpFile, "test-component", true)

	// Register the reloader
	err := manager.RegisterReloader(reloader)
	if err != nil {
		t.Fatalf("RegisterReloader failed: %v", err)
	}

	initialCount := reloader.GetReloadCount()

	// Trigger manual reload
	err = manager.TriggerReload("test-component")
	if err != nil {
		t.Errorf("TriggerReload failed: %v", err)
	}

	if reloader.GetReloadCount() <= initialCount {
		t.Error("Expected reload count to increase after trigger")
	}

	// Try to trigger reload for non-existent component
	err = manager.TriggerReload("non-existent")
	if err == nil {
		t.Error("TriggerReload should fail for non-existent component")
	}
}

func TestHotReloadManagerStopAll(t *testing.T) {
	tmpFile1 := createTempConfigFile(t, "test config 1")
	tmpFile2 := createTempConfigFile(t, "test config 2")
	defer os.Remove(tmpFile1)
	defer os.Remove(tmpFile2)

	manager := NewHotReloadManager()

	reloader1 := NewMockConfigReloader(tmpFile1, "component-1", true)
	reloader2 := NewMockConfigReloader(tmpFile2, "component-2", true)

	// Register multiple reloaders
	err := manager.RegisterReloader(reloader1)
	if err != nil {
		t.Fatalf("RegisterReloader failed: %v", err)
	}
	err = manager.RegisterReloader(reloader2)
	if err != nil {
		t.Fatalf("RegisterReloader failed: %v", err)
	}

	// Verify they are running
	status := manager.GetStatus()
	if len(status) != 2 {
		t.Errorf("Expected 2 registered components, got %d", len(status))
	}

	// Stop all
	manager.StopAll()

	// Verify all are stopped
	status = manager.GetStatus()
	if len(status) != 0 {
		t.Errorf("Expected 0 registered components after StopAll, got %d", len(status))
	}
}

func TestHotReloadManagerGetStatus(t *testing.T) {
	tmpFile := createTempConfigFile(t, "test config")
	defer os.Remove(tmpFile)

	manager := NewHotReloadManager()
	defer manager.StopAll()

	// Test empty status
	status := manager.GetStatus()
	if len(status) != 0 {
		t.Errorf("Expected empty status, got %d components", len(status))
	}

	// Register a reloader
	reloader := NewMockConfigReloader(tmpFile, "test-component", true)
	err := manager.RegisterReloader(reloader)
	if err != nil {
		t.Fatalf("RegisterReloader failed: %v", err)
	}

	// Test status with one component
	status = manager.GetStatus()
	if len(status) != 1 {
		t.Errorf("Expected 1 component in status, got %d", len(status))
	}
	if !status["test-component"] {
		t.Error("Expected test-component to be running")
	}
}

func TestDefaultHotReloadConfig(t *testing.T) {
	config := DefaultHotReloadConfig()

	if !config.Enabled {
		t.Error("Expected default config to be enabled")
	}
	if !config.WatchConfig {
		t.Error("Expected default config to watch config")
	}
	if config.DebounceDelay != 100*time.Millisecond {
		t.Errorf("Expected default debounce delay 100ms, got %v", config.DebounceDelay)
	}
	if config.GracefulTimeout != 30*time.Second {
		t.Errorf("Expected default graceful timeout 30s, got %v", config.GracefulTimeout)
	}
}

func TestIsValidReloadSignal(t *testing.T) {
	tests := []struct {
		signal string
		valid  bool
	}{
		{"", true},
		{"SIGHUP", true},
		{"SIGUSR1", true},
		{"SIGUSR2", true},
		{"sighup", true},   // Case insensitive
		{"sigusr1", true},  // Case insensitive
		{"SIGTERM", false}, // Not in valid list
		{"INVALID", false}, // Invalid signal
	}

	for _, tt := range tests {
		t.Run(tt.signal, func(t *testing.T) {
			if IsValidReloadSignal(tt.signal) != tt.valid {
				t.Errorf("IsValidReloadSignal(%q) = %v, want %v", tt.signal, !tt.valid, tt.valid)
			}
		})
	}
}

func TestFileWatcherRateLimiting(t *testing.T) {
	tmpFile := createTempConfigFile(t, "test config")
	defer os.Remove(tmpFile)

	reloader := NewMockConfigReloader(tmpFile, "test-component", true)
	watcher := NewFileWatcher(reloader)

	// Test rate limiting by calling performReload multiple times quickly
	initialCount := reloader.GetReloadCount()

	// First reload should succeed
	err := watcher.performReload()
	if err != nil {
		t.Errorf("First performReload failed: %v", err)
	}

	// Immediate second reload should be rate limited
	err = watcher.performReload()
	if err != nil {
		t.Errorf("Second performReload failed: %v", err)
	}

	// Should only have one reload due to rate limiting
	finalCount := reloader.GetReloadCount()
	if finalCount != initialCount+1 {
		t.Errorf("Expected 1 reload due to rate limiting, got %d", finalCount-initialCount)
	}
}

func TestFileWatcherDebouncing(t *testing.T) {
	tmpFile := createTempConfigFile(t, "initial config")
	defer os.Remove(tmpFile)

	reloader := NewMockConfigReloader(tmpFile, "test-component", true)
	watcher := NewFileWatcher(reloader)
	watcher.SetDebounceDelay(50 * time.Millisecond)

	err := watcher.Start()
	if err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer watcher.Stop()

	// Wait for the watch loop to be ready
	time.Sleep(25 * time.Millisecond)

	initialCount := reloader.GetReloadCount()

	// Trigger multiple rapid file changes
	for i := 0; i < 5; i++ {
		err = os.WriteFile(tmpFile, []byte(fmt.Sprintf("config update %d", i)), 0644)
		if err != nil {
			t.Fatalf("Failed to write to config file: %v", err)
		}
		time.Sleep(10 * time.Millisecond) // Less than debounce delay
	}

	// Wait for debounce to complete
	time.Sleep(100 * time.Millisecond)

	// Should only have one reload due to debouncing
	finalCount := reloader.GetReloadCount()
	reloadCount := finalCount - initialCount
	if reloadCount != 1 {
		t.Errorf("Expected 1 reload due to debouncing, got %d", reloadCount)
	}
}

func TestHotReloadConfigStruct(t *testing.T) {
	config := HotReloadConfig{
		Enabled:         true,
		WatchConfig:     true,
		ReloadSignal:    "SIGHUP",
		GracefulTimeout: 30 * time.Second,
		DebounceDelay:   100 * time.Millisecond,
	}

	if !config.Enabled {
		t.Error("Expected Enabled to be true")
	}
	if !config.WatchConfig {
		t.Error("Expected WatchConfig to be true")
	}
	if config.ReloadSignal != "SIGHUP" {
		t.Errorf("Expected ReloadSignal SIGHUP, got %s", config.ReloadSignal)
	}
	if config.GracefulTimeout != 30*time.Second {
		t.Errorf("Expected GracefulTimeout 30s, got %v", config.GracefulTimeout)
	}
	if config.DebounceDelay != 100*time.Millisecond {
		t.Errorf("Expected DebounceDelay 100ms, got %v", config.DebounceDelay)
	}
}

// Helper function to create temporary config files for testing
func createTempConfigFile(t *testing.T, content string) string {
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	return tmpFile.Name()
}

// Helper function to create temporary config files for benchmarks
func createTempConfigFileForBench(b *testing.B, content string) string {
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		b.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := tmpFile.WriteString(content); err != nil {
		b.Fatalf("Failed to write to temp file: %v", err)
	}

	if err := tmpFile.Close(); err != nil {
		b.Fatalf("Failed to close temp file: %v", err)
	}

	return tmpFile.Name()
}

// Benchmark tests
func BenchmarkFileWatcherPerformReload(b *testing.B) {
	tmpFile := createTempConfigFileForBench(b, "test config")
	defer os.Remove(tmpFile)

	reloader := NewMockConfigReloader(tmpFile, "test-component", true)
	watcher := NewFileWatcher(reloader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset the last reload time to avoid rate limiting
		watcher.lastReloadTime = time.Time{}
		watcher.performReload()
	}
}

func BenchmarkHotReloadManagerRegisterUnregister(b *testing.B) {
	tmpFile := createTempConfigFileForBench(b, "test config")
	defer os.Remove(tmpFile)

	manager := NewHotReloadManager()
	defer manager.StopAll()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		componentName := fmt.Sprintf("component-%d", i)
		reloader := NewMockConfigReloader(tmpFile, componentName, false) // Disabled to avoid file watching overhead

		err := manager.RegisterReloader(reloader)
		if err != nil {
			b.Fatalf("RegisterReloader failed: %v", err)
		}

		err = manager.UnregisterReloader(componentName)
		if err != nil {
			b.Fatalf("UnregisterReloader failed: %v", err)
		}
	}
}
