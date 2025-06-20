package common

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/logger"
	"github.com/fsnotify/fsnotify"
)

// HotReloadConfig represents generic hot reload configuration
type HotReloadConfig struct {
	Enabled         bool          `yaml:"enabled,omitempty"`
	WatchConfig     bool          `yaml:"watch_config,omitempty"`
	ReloadSignal    string        `yaml:"reload_signal,omitempty"`
	GracefulTimeout time.Duration `yaml:"graceful_timeout,omitempty"`
	DebounceDelay   time.Duration `yaml:"debounce_delay,omitempty"`
}

// ConfigReloader defines the interface for configuration reloading
type ConfigReloader interface {
	// ReloadConfig is called when the configuration file changes
	ReloadConfig() error
	// GetConfigPath returns the path to the configuration file being watched
	GetConfigPath() string
	// IsHotReloadEnabled returns whether hot reload is enabled
	IsHotReloadEnabled() bool
	// GetComponentName returns the name of the component (for logging)
	GetComponentName() string
}

// FileWatcher manages file watching and reload coordination
type FileWatcher struct {
	reloader       ConfigReloader
	watcher        *fsnotify.Watcher
	mu             sync.RWMutex
	running        bool
	debounceTimer  *time.Timer
	debounceDelay  time.Duration
	lastReloadTime time.Time
}

// NewFileWatcher creates a new file watcher for the given reloader
func NewFileWatcher(reloader ConfigReloader) *FileWatcher {
	return &FileWatcher{
		reloader:      reloader,
		debounceDelay: 100 * time.Millisecond, // Default debounce delay
	}
}

// Start begins watching the configuration file for changes
func (fw *FileWatcher) Start() error {
	// Check if hot reload is enabled
	if !fw.reloader.IsHotReloadEnabled() {
		logger.Info("🔥 Hot reload disabled for %s", fw.reloader.GetComponentName())
		return nil
	}

	configPath := fw.reloader.GetConfigPath()
	if configPath == "" {
		logger.Debug("🔥 Hot reload disabled: no config path available for %s", fw.reloader.GetComponentName())
		return nil
	}

	fw.mu.Lock()
	defer fw.mu.Unlock()

	if fw.running {
		return fmt.Errorf("file watcher already running")
	}

	// Create fsnotify watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create config file watcher: %w", err)
	}
	fw.watcher = watcher

	// Watch the config file
	if err := fw.watcher.Add(configPath); err != nil {
		fw.watcher.Close()
		return fmt.Errorf("failed to watch config file %s: %w", configPath, err)
	}

	// Also watch the directory for atomic writes (editors often write to temp file then rename)
	configDir := filepath.Dir(configPath)
	if err := fw.watcher.Add(configDir); err != nil {
		logger.Warn("⚠️  Failed to watch config directory %s: %v", configDir, err)
	}

	fw.running = true
	fw.lastReloadTime = time.Now()

	// Start watching in background
	go fw.watchLoop()

	logger.Info("🔥 Hot reload enabled for %s: watching %s for changes",
		fw.reloader.GetComponentName(), configPath)

	return nil
}

// Stop stops the file watcher
func (fw *FileWatcher) Stop() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if !fw.running {
		return nil
	}

	// Stop debounce timer if running
	if fw.debounceTimer != nil {
		fw.debounceTimer.Stop()
		fw.debounceTimer = nil
	}

	// Close the watcher
	if fw.watcher != nil {
		if err := fw.watcher.Close(); err != nil {
			logger.Error("❌ Error closing file watcher: %v", err)
		}
		fw.watcher = nil
	}

	fw.running = false
	logger.Info("🔥 Hot reload stopped for %s", fw.reloader.GetComponentName())

	return nil
}

// watchLoop handles file system events and triggers reloads
func (fw *FileWatcher) watchLoop() {
	defer func() {
		logger.Debug("🔥 File watcher loop exiting for %s", fw.reloader.GetComponentName())
	}()

	configPath := fw.reloader.GetConfigPath()

	for {
		select {
		case event, ok := <-fw.watcher.Events:
			if !ok {
				logger.Error("🔥 Config watcher channel closed for %s", fw.reloader.GetComponentName())
				return
			}

			// Only react to write events on our config file
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				// Handle both direct writes and atomic writes (temp file renames)
				if event.Name == configPath || filepath.Base(event.Name) == filepath.Base(configPath) {
					logger.Info("🔥 Config file changed: %s (event: %s) for %s",
						event.Name, event.Op.String(), fw.reloader.GetComponentName())

					// Use debouncing to handle rapid successive writes
					fw.scheduleReload()
				}
			}

		case err, ok := <-fw.watcher.Errors:
			if !ok {
				logger.Error("🔥 Config watcher error channel closed for %s", fw.reloader.GetComponentName())
				return
			}
			logger.Error("🔥 Config watcher error for %s: %v", fw.reloader.GetComponentName(), err)
		}
	}
}

// scheduleReload schedules a configuration reload with debouncing
func (fw *FileWatcher) scheduleReload() {
	// Stop existing timer if running
	if fw.debounceTimer != nil {
		fw.debounceTimer.Stop()
	}

	// Start new timer
	fw.debounceTimer = time.AfterFunc(fw.debounceDelay, func() {
		if err := fw.performReload(); err != nil {
			logger.Error("❌ Failed to reload config for %s: %v", fw.reloader.GetComponentName(), err)
		}
	})
}

// performReload executes the actual configuration reload
func (fw *FileWatcher) performReload() error {
	// Prevent too frequent reloads
	if time.Since(fw.lastReloadTime) < 500*time.Millisecond {
		logger.Debug("🔥 Skipping reload due to rate limiting for %s", fw.reloader.GetComponentName())
		return nil
	}

	logger.Info("🔄 Reloading configuration for %s from %s",
		fw.reloader.GetComponentName(), fw.reloader.GetConfigPath())

	startTime := time.Now()
	if err := fw.reloader.ReloadConfig(); err != nil {
		logger.Error("❌ Configuration reload failed for %s: %v", fw.reloader.GetComponentName(), err)
		return err
	}

	fw.lastReloadTime = time.Now()
	reloadDuration := time.Since(startTime)

	logger.Info("✅ Configuration reloaded successfully for %s (took %v)",
		fw.reloader.GetComponentName(), reloadDuration.Round(time.Millisecond))
	return nil
}

// SetDebounceDelay sets the debounce delay for file change events
func (fw *FileWatcher) SetDebounceDelay(delay time.Duration) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.debounceDelay = delay
}

// HotReloadManager manages multiple file watchers for different components
type HotReloadManager struct {
	watchers map[string]*FileWatcher
	mu       sync.RWMutex
}

// NewHotReloadManager creates a new hot reload manager
func NewHotReloadManager() *HotReloadManager {
	return &HotReloadManager{
		watchers: make(map[string]*FileWatcher),
	}
}

// RegisterReloader registers a new configuration reloader
func (hrm *HotReloadManager) RegisterReloader(reloader ConfigReloader) error {
	hrm.mu.Lock()
	defer hrm.mu.Unlock()

	componentName := reloader.GetComponentName()
	if _, exists := hrm.watchers[componentName]; exists {
		return fmt.Errorf("reloader already registered for component: %s", componentName)
	}

	watcher := NewFileWatcher(reloader)
	hrm.watchers[componentName] = watcher

	// Start watching immediately if hot reload is enabled
	if err := watcher.Start(); err != nil {
		delete(hrm.watchers, componentName)
		return fmt.Errorf("failed to start watcher for %s: %w", componentName, err)
	}

	logger.Info("🔥 Registered hot reload for component: %s", componentName)
	return nil
}

// UnregisterReloader unregisters a configuration reloader
func (hrm *HotReloadManager) UnregisterReloader(componentName string) error {
	hrm.mu.Lock()
	defer hrm.mu.Unlock()

	watcher, exists := hrm.watchers[componentName]
	if !exists {
		return fmt.Errorf("no reloader registered for component: %s", componentName)
	}

	if err := watcher.Stop(); err != nil {
		logger.Error("❌ Error stopping watcher for %s: %v", componentName, err)
	}

	delete(hrm.watchers, componentName)
	logger.Info("🔥 Unregistered hot reload for component: %s", componentName)
	return nil
}

// StopAll stops all registered file watchers
func (hrm *HotReloadManager) StopAll() {
	hrm.mu.Lock()
	defer hrm.mu.Unlock()

	for componentName, watcher := range hrm.watchers {
		if err := watcher.Stop(); err != nil {
			logger.Error("❌ Error stopping watcher for %s: %v", componentName, err)
		}
	}

	hrm.watchers = make(map[string]*FileWatcher)
	logger.Info("🔥 Stopped all hot reload watchers")
}

// GetStatus returns the status of all registered watchers
func (hrm *HotReloadManager) GetStatus() map[string]bool {
	hrm.mu.RLock()
	defer hrm.mu.RUnlock()

	status := make(map[string]bool)
	for componentName, watcher := range hrm.watchers {
		watcher.mu.RLock()
		status[componentName] = watcher.running
		watcher.mu.RUnlock()
	}

	return status
}

// TriggerReload manually triggers a reload for a specific component
func (hrm *HotReloadManager) TriggerReload(componentName string) error {
	hrm.mu.RLock()
	watcher, exists := hrm.watchers[componentName]
	hrm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("no reloader registered for component: %s", componentName)
	}

	logger.Info("🔄 Manually triggering reload for %s", componentName)
	return watcher.performReload()
}

// DefaultHotReloadConfig returns default hot reload configuration
func DefaultHotReloadConfig() HotReloadConfig {
	return HotReloadConfig{
		Enabled:         true,
		WatchConfig:     true,
		DebounceDelay:   100 * time.Millisecond,
		GracefulTimeout: 30 * time.Second,
	}
}

// IsValidReloadSignal checks if a reload signal is valid
func IsValidReloadSignal(signal string) bool {
	validSignals := []string{"SIGHUP", "SIGUSR1", "SIGUSR2", ""}
	for _, valid := range validSignals {
		if strings.EqualFold(signal, valid) {
			return true
		}
	}
	return false
}
