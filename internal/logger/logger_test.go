package logger

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// TestNewLogger tests creating a new logger with different configurations
func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, INFO, ConsoleFormat, "test-component", false)

	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}

	if logger.level != INFO {
		t.Errorf("Expected level INFO, got %v", logger.level)
	}

	if logger.format != ConsoleFormat {
		t.Errorf("Expected format ConsoleFormat, got %v", logger.format)
	}

	if logger.component != "test-component" {
		t.Errorf("Expected component 'test-component', got %s", logger.component)
	}
}

// TestLogLevels tests that only appropriate log levels are output
func TestLogLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, WARN, ConsoleFormat, "test", false)

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
	logger := NewLogger(&buf, DEBUG, ConsoleFormat, "test", false)

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
			logger := NewLogger(&buf, DEBUG, ConsoleFormat, "test", tt.useColor)

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
	tests := []struct {
		input    string
		expected LogLevel
	}{
		{"DEBUG", DEBUG},
		{"INFO", INFO},
		{"WARN", WARN},
		{"ERROR", ERROR},
		{"FATAL", FATAL},
		{"debug", DEBUG},  // Test case insensitivity
		{"invalid", INFO}, // Invalid levels should default to INFO
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			// Reset default logger for each test
			defaultLogger = nil
			once = sync.Once{}

			SetLogLevel(tt.input)
			if defaultLogger.level != tt.expected {
				t.Errorf("SetLogLevel(%s): expected %v, got %v", tt.input, tt.expected, defaultLogger.level)
			}
		})
	}
}

// TestSetFormat tests setting the global log format
func TestSetFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected Format
	}{
		{"json", JSONFormat},
		{"console", ConsoleFormat},
		{"JSON", JSONFormat}, // Test case insensitivity
		{"CONSOLE", ConsoleFormat},
		{"invalid", ConsoleFormat}, // Invalid formats should default to console
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			// Reset default logger for each test
			defaultLogger = nil
			once = sync.Once{}

			SetFormat(tt.input)
			if defaultLogger.format != tt.expected {
				t.Errorf("SetFormat(%s): expected %v, got %v", tt.input, tt.expected, defaultLogger.format)
			}
		})
	}
}

// TestConsoleFormatOutput tests console format output
func TestConsoleFormatOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, DEBUG, ConsoleFormat, "test", false)

	logger.log(INFO, "Test message")

	output := buf.String()
	if !strings.Contains(output, "INFO") {
		t.Error("Console output should contain log level")
	}
	if !strings.Contains(output, "Test message") {
		t.Error("Console output should contain log message")
	}
	// Should contain timestamp
	if !strings.Contains(output, "/") {
		t.Error("Console output should contain timestamp")
	}
}

// TestJSONFormatOutput tests JSON format output
func TestJSONFormatOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, DEBUG, JSONFormat, "test-component", false)

	logger.log(INFO, "Test message")

	output := strings.TrimSpace(buf.String())

	// Parse JSON to validate structure
	var entry LogEntry
	if err := json.Unmarshal([]byte(output), &entry); err != nil {
		t.Fatalf("JSON output should be valid JSON: %v", err)
	}

	if entry.Level != "info" {
		t.Errorf("Expected level 'info', got %s", entry.Level)
	}
	if entry.Message != "Test message" {
		t.Errorf("Expected message 'Test message', got %s", entry.Message)
	}
	if entry.Component != "test-component" {
		t.Errorf("Expected component 'test-component', got %s", entry.Component)
	}
	if entry.Timestamp == "" {
		t.Error("JSON output should contain timestamp")
	}
}

// TestLogWithFields tests logging with fields
func TestLogWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, DEBUG, JSONFormat, "test", false)

	fields := map[string]interface{}{
		"user_id": "12345",
		"action":  "login",
		"ip":      "192.168.1.1",
	}

	logger.logWithFields(INFO, fields, "User action completed")

	output := strings.TrimSpace(buf.String())

	// Parse as a general map since fields are now merged into the main JSON object
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &entry); err != nil {
		t.Fatalf("JSON output should be valid JSON: %v", err)
	}

	if entry["user_id"] != "12345" {
		t.Errorf("Expected user_id '12345', got %v", entry["user_id"])
	}
	if entry["action"] != "login" {
		t.Errorf("Expected action 'login', got %v", entry["action"])
	}
	if entry["ip"] != "192.168.1.1" {
		t.Errorf("Expected ip '192.168.1.1', got %v", entry["ip"])
	}
}

// TestLogWithFieldsConsoleFormat tests console format with fields
func TestLogWithFieldsConsoleFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, DEBUG, ConsoleFormat, "test", false)

	fields := map[string]interface{}{
		"user_id": "12345",
		"action":  "login",
	}

	logger.logWithFields(INFO, fields, "User action completed")

	output := buf.String()

	// Console format should include fields as key=value pairs
	if !strings.Contains(output, "user_id=12345") {
		t.Error("Console output should contain user_id field")
	}
	if !strings.Contains(output, "action=login") {
		t.Error("Console output should contain action field")
	}
	if !strings.Contains(output, "User action completed") {
		t.Error("Console output should contain log message")
	}
}

// TestDebugWithFields tests logging with fields at the debug level
func TestDebugWithFields(t *testing.T) {
	// Reset default logger for this test
	savedLogger := defaultLogger
	savedOnce := once
	defer func() {
		defaultLogger = savedLogger
		once = savedOnce
	}()

	var buf bytes.Buffer
	defaultLogger = NewLogger(&buf, DEBUG, JSONFormat, "test", false)
	once = sync.Once{}
	once.Do(func() {}) // Mark as initialized

	fields := map[string]interface{}{
		"debug_field": "debug_value",
	}

	DebugWithFields(fields, "Debug message with fields")

	output := strings.TrimSpace(buf.String())

	// Parse as a general map since fields are now merged into the main JSON object
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &entry); err != nil {
		t.Fatalf("JSON output should be valid JSON: %v", err)
	}

	if entry["level"] != "debug" {
		t.Errorf("Expected level 'debug', got %s", entry["level"])
	}
	if entry["debug_field"] != "debug_value" {
		t.Errorf("Expected debug_field 'debug_value', got %v", entry["debug_field"])
	}
}

// TestLogLevelFiltering tests filtering logs based on log level
func TestLogLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, WARN, ConsoleFormat, "test", false)

	// These should not appear (below WARN level)
	logger.log(DEBUG, "Debug message")
	logger.log(INFO, "Info message")

	// These should appear (WARN level and above)
	logger.log(WARN, "Warning message")
	logger.log(ERROR, "Error message")

	output := buf.String()

	if strings.Contains(output, "Debug message") {
		t.Error("DEBUG message should be filtered out")
	}
	if strings.Contains(output, "Info message") {
		t.Error("INFO message should be filtered out")
	}
	if !strings.Contains(output, "Warning message") {
		t.Error("WARN message should appear")
	}
	if !strings.Contains(output, "Error message") {
		t.Error("ERROR message should appear")
	}
}

// TestSetComponent tests setting the component for logging
func TestSetComponent(t *testing.T) {
	// Reset default logger for this test
	savedLogger := defaultLogger
	savedOnce := once
	defer func() {
		defaultLogger = savedLogger
		once = savedOnce
	}()

	var buf bytes.Buffer
	defaultLogger = NewLogger(&buf, INFO, JSONFormat, "", false)
	once = sync.Once{}
	once.Do(func() {}) // Mark as initialized

	SetComponent("my-component")
	Info("Test message")

	output := strings.TrimSpace(buf.String())

	var entry LogEntry
	if err := json.Unmarshal([]byte(output), &entry); err != nil {
		t.Fatalf("JSON output should be valid JSON: %v", err)
	}

	if entry.Component != "my-component" {
		t.Errorf("Expected component 'my-component', got %s", entry.Component)
	}
}

// TestJSONMarshalError tests handling JSON marshaling errors
func TestJSONMarshalError(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, DEBUG, JSONFormat, "test", false)

	// Create a field that cannot be marshaled to JSON
	fields := map[string]interface{}{
		"invalid": make(chan int), // channels cannot be marshaled to JSON
	}

	logger.logWithFields(INFO, fields, "Test message")

	output := buf.String()

	// Should fall back to console format when JSON marshaling fails
	if !strings.Contains(output, "JSON marshal error") {
		t.Error("Should contain JSON marshal error message")
	}
	if !strings.Contains(output, "Test message") {
		t.Error("Should still contain original message")
	}
}

// Benchmark tests
func BenchmarkConsoleLogging(b *testing.B) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, INFO, ConsoleFormat, "benchmark", false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.log(INFO, "Benchmark message %d", i)
	}
}

func BenchmarkJSONLogging(b *testing.B) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, INFO, JSONFormat, "benchmark", false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.log(INFO, "Benchmark message %d", i)
	}
}

func BenchmarkJSONLoggingWithFields(b *testing.B) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, INFO, JSONFormat, "benchmark", false)

	fields := map[string]interface{}{
		"field1": "value1",
		"field2": 42,
		"field3": true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.logWithFields(INFO, fields, "Benchmark message %d", i)
	}
}

// TestWithComponent tests creating logger instances with specific component names
func TestWithComponent(t *testing.T) {
	// Reset default logger for this test
	savedLogger := defaultLogger
	savedOnce := once
	defer func() {
		defaultLogger = savedLogger
		once = savedOnce
	}()

	var buf bytes.Buffer
	defaultLogger = NewLogger(&buf, INFO, JSONFormat, "", false)
	once = sync.Once{}
	once.Do(func() {}) // Mark as initialized

	// Create component-specific loggers
	serverLogger := WithComponent("server")
	agentLogger := WithComponent("agent")
	caddyLogger := WithComponent("caddy.manager")

	// Test that each logger has the correct component
	if serverLogger.component != "server" {
		t.Errorf("Expected server logger component 'server', got %s", serverLogger.component)
	}
	if agentLogger.component != "agent" {
		t.Errorf("Expected agent logger component 'agent', got %s", agentLogger.component)
	}
	if caddyLogger.component != "caddy.manager" {
		t.Errorf("Expected caddy logger component 'caddy.manager', got %s", caddyLogger.component)
	}

	// Test that they inherit the default logger settings
	if serverLogger.level != INFO {
		t.Errorf("Expected server logger level INFO, got %v", serverLogger.level)
	}
	if serverLogger.format != JSONFormat {
		t.Errorf("Expected server logger format JSONFormat, got %v", serverLogger.format)
	}

	// Test actual logging with different components
	serverLogger.log(INFO, "Server message")
	agentLogger.log(INFO, "Agent message")
	caddyLogger.log(INFO, "Caddy manager message")

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) != 3 {
		t.Errorf("Expected 3 log lines, got %d", len(lines))
	}

	// Parse and verify each log entry
	var serverEntry, agentEntry, caddyEntry map[string]interface{}

	if err := json.Unmarshal([]byte(lines[0]), &serverEntry); err != nil {
		t.Fatalf("Failed to parse server log entry: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &agentEntry); err != nil {
		t.Fatalf("Failed to parse agent log entry: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[2]), &caddyEntry); err != nil {
		t.Fatalf("Failed to parse caddy log entry: %v", err)
	}

	// Verify components
	if serverEntry["component"] != "server" {
		t.Errorf("Expected server component 'server', got %v", serverEntry["component"])
	}
	if agentEntry["component"] != "agent" {
		t.Errorf("Expected agent component 'agent', got %v", agentEntry["component"])
	}
	if caddyEntry["component"] != "caddy.manager" {
		t.Errorf("Expected caddy component 'caddy.manager', got %v", caddyEntry["component"])
	}

	// Verify messages
	if serverEntry["msg"] != "Server message" {
		t.Errorf("Expected server message 'Server message', got %v", serverEntry["msg"])
	}
	if agentEntry["msg"] != "Agent message" {
		t.Errorf("Expected agent message 'Agent message', got %v", agentEntry["msg"])
	}
	if caddyEntry["msg"] != "Caddy manager message" {
		t.Errorf("Expected caddy message 'Caddy manager message', got %v", caddyEntry["msg"])
	}
}
