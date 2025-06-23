package logger

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNewLogger tests creating a new logger with different configurations
func TestNewLogger(t *testing.T) {
	tests := []struct {
		name     string
		level    LogLevel
		module   string
		useColor bool
	}{
		{"debug logger", DEBUG, "test", true},
		{"info logger", INFO, "server", false},
		{"error logger", ERROR, "", true},
		{"fatal logger", FATAL, "agent", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewLogger(&buf, tt.level, tt.module, tt.useColor)

			if logger.level != tt.level {
				t.Errorf("expected level %v, got %v", tt.level, logger.level)
			}
			if logger.module != tt.module {
				t.Errorf("expected module %q, got %q", tt.module, logger.module)
			}
			if logger.useColor != tt.useColor {
				t.Errorf("expected useColor %v, got %v", tt.useColor, logger.useColor)
			}
		})
	}
}

// TestLogLevels tests that only appropriate log levels are output
func TestLogLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, WARN, "test", false)

	// These should not appear (below WARN level)
	logger.log(DEBUG, "debug message")
	logger.log(INFO, "info message")

	// These should appear (WARN level and above)
	logger.log(WARN, "warn message")
	logger.log(ERROR, "error message")
	logger.log(FATAL, "fatal message")

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Should have 3 lines (WARN, ERROR, FATAL)
	if len(lines) != 3 {
		t.Errorf("expected 3 log lines, got %d", len(lines))
	}

	// Check that correct levels appear
	if !strings.Contains(output, "WARN warn message") {
		t.Error("WARN message not found in output")
	}
	if !strings.Contains(output, "ERROR error message") {
		t.Error("ERROR message not found in output")
	}
	if !strings.Contains(output, "FATAL fatal message") {
		t.Error("FATAL message not found in output")
	}

	// Check that filtered levels don't appear
	if strings.Contains(output, "debug message") {
		t.Error("DEBUG message should not appear in output")
	}
	if strings.Contains(output, "info message") {
		t.Error("INFO message should not appear in output")
	}
}

// TestLogFormatting tests log message formatting
func TestLogFormatting(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, DEBUG, "test", false)

	logger.log(INFO, "formatted %s %d", "message", 42)

	output := buf.String()
	if !strings.Contains(output, "formatted message 42") {
		t.Error("message formatting failed")
	}
	if !strings.Contains(output, "INFO") {
		t.Error("log level not present in output")
	}
}

// TestColorOutput tests colored vs non-colored output
func TestColorOutput(t *testing.T) {
	tests := []struct {
		name     string
		useColor bool
		level    LogLevel
	}{
		{"colored output", true, INFO},
		{"non-colored output", false, ERROR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewLogger(&buf, DEBUG, "test", tt.useColor)

			logger.log(tt.level, "test message")
			output := buf.String()

			if tt.useColor {
				// Should contain ANSI color codes
				if !strings.Contains(output, "\033[") {
					t.Error("expected color codes in colored output")
				}
				if !strings.Contains(output, resetColor) {
					t.Error("expected reset color code in colored output")
				}
			} else {
				// Should not contain ANSI color codes
				if strings.Contains(output, "\033[") {
					t.Error("unexpected color codes in non-colored output")
				}
			}
		})
	}
}

// TestSetLogLevel tests setting the global log level
func TestSetLogLevel(t *testing.T) {
	// Save original logger to restore later
	origLogger := defaultLogger

	tests := []struct {
		levelStr string
		expected LogLevel
	}{
		{"DEBUG", DEBUG},
		{"INFO", INFO},
		{"WARN", WARN},
		{"ERROR", ERROR},
		{"FATAL", FATAL},
		{"debug", DEBUG}, // Test case insensitivity
		{"info", INFO},
		{"invalid", INFO}, // Should default to INFO for invalid levels
	}

	for _, tt := range tests {
		t.Run(tt.levelStr, func(t *testing.T) {
			// Reset default logger for each test
			defaultLogger = nil
			once = sync.Once{}

			SetLogLevel(tt.levelStr)

			if defaultLogger.level != tt.expected {
				t.Errorf("expected level %v, got %v", tt.expected, defaultLogger.level)
			}
		})
	}

	// Restore original logger
	defaultLogger = origLogger
}

// TestGlobalLogFunctions tests the global logging functions
func TestGlobalLogFunctions(t *testing.T) {
	// Save original defaults
	origLogger := defaultLogger
	origOnce := once

	defer func() {
		// Restore originals
		defaultLogger = origLogger
		once = origOnce
	}()

	// Create a test buffer and set up test logger
	var buf bytes.Buffer
	defaultLogger = NewLogger(&buf, DEBUG, "", false)

	// Make the once flag think it has already run by calling it with a dummy function
	once.Do(func() {})

	// Test each global function
	Debug("debug %s", "message")
	Info("info %s", "message")
	Warn("warn %s", "message")
	Error("error %s", "message")

	output := buf.String()

	// Verify all messages appear
	expectedMessages := []string{
		"DEBUG debug message",
		"INFO info message",
		"WARN warn message",
		"ERROR error message",
	}

	for _, expected := range expectedMessages {
		if !strings.Contains(output, expected) {
			t.Errorf("expected message %q not found in output", expected)
		}
	}
}

// TestTimestampFormat tests that timestamps are properly formatted
func TestTimestampFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, INFO, "test", false)

	logger.log(INFO, "test message")
	output := buf.String()

	// Check timestamp format: should start with YYYY/MM/DD HH:MM:SS.mmm
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		t.Fatal("no output generated")
	}

	line := lines[0]
	parts := strings.Fields(line)
	if len(parts) < 2 {
		t.Fatal("log line format incorrect")
	}

	// Parse timestamp
	timestamp := parts[0] + " " + parts[1]
	_, err := time.Parse("2006/01/02 15:04:05.000", timestamp)
	if err != nil {
		t.Errorf("timestamp format incorrect: %s, error: %v", timestamp, err)
	}
}

// TestConcurrentLogging tests thread safety of logging
func TestConcurrentLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, INFO, "test", false)

	// Run concurrent logging
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				logger.log(INFO, "goroutine %d message %d", id, j)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Should have 1000 lines (10 goroutines * 100 messages each)
	if len(lines) != 1000 {
		t.Errorf("expected 1000 log lines, got %d", len(lines))
	}
}

// TestFatalDoesNotExit tests Fatal function behavior (but avoids actual exit)
func TestFatalFunction(t *testing.T) {
	// We can't actually test os.Exit(), but we can test that Fatal logs properly
	var buf bytes.Buffer
	logger := NewLogger(&buf, FATAL, "test", false)

	// Test that fatal level messages are logged
	logger.log(FATAL, "fatal error occurred")

	output := buf.String()
	if !strings.Contains(output, "FATAL fatal error occurred") {
		t.Error("FATAL message not logged correctly")
	}
}

// BenchmarkLogging benchmarks logging performance
func BenchmarkLogging(b *testing.B) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, INFO, "benchmark", false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.log(INFO, "benchmark message %d", i)
	}
}

// BenchmarkColoredLogging benchmarks colored logging performance
func BenchmarkColoredLogging(b *testing.B) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, INFO, "benchmark", true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.log(INFO, "benchmark message %d", i)
	}
}

// BenchmarkFilteredLogging benchmarks logging when messages are filtered out
func BenchmarkFilteredLogging(b *testing.B) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, ERROR, "benchmark", false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.log(DEBUG, "filtered message %d", i) // This should be filtered out
	}
}
