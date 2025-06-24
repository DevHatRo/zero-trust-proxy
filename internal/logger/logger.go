package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel int

// Format represents the output format for log messages
type Format int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

const (
	ConsoleFormat Format = iota
	JSONFormat
)

var (
	levelNames = map[LogLevel]string{
		DEBUG: "DEBUG",
		INFO:  "INFO",
		WARN:  "WARN",
		ERROR: "ERROR",
		FATAL: "FATAL",
	}

	levelColors = map[LogLevel]string{
		DEBUG: "\033[36m", // Cyan
		INFO:  "\033[32m", // Green
		WARN:  "\033[33m", // Yellow
		ERROR: "\033[31m", // Red
		FATAL: "\033[35m", // Magenta
	}

	resetColor = "\033[0m"
)

// LogEntry represents a structured log entry for JSON format
type LogEntry struct {
	Timestamp string `json:"ts"`
	Level     string `json:"level"`
	Message   string `json:"msg"`
	Component string `json:"component,omitempty"`
}

// Logger represents a structured logger instance
type Logger struct {
	mu        sync.Mutex
	level     LogLevel
	format    Format
	output    io.Writer
	component string
	useColor  bool
	// isComponentLogger indicates if this is a component logger that should reference default logger's config
	isComponentLogger bool
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// initDefaultLogger initializes the default logger
func initDefaultLogger() {
	defaultLogger = NewLogger(os.Stdout, INFO, ConsoleFormat, "", true)
}

// NewLogger creates a new logger instance
func NewLogger(output io.Writer, level LogLevel, format Format, component string, useColor bool) *Logger {
	return &Logger{
		level:     level,
		format:    format,
		output:    output,
		component: component,
		useColor:  useColor,
	}
}

// WithComponent creates a new logger instance with a specific component name
// This allows each module to have its own logger with hierarchical naming
// Component loggers dynamically reference the default logger's configuration
func WithComponent(component string) *Logger {
	once.Do(initDefaultLogger)
	return &Logger{
		component:         component,
		isComponentLogger: true, // Mark as component logger to use dynamic config
	}
}

// SetLogLevel sets the minimum log level to display
func SetLogLevel(level string) {
	once.Do(initDefaultLogger)
	level = strings.ToUpper(level)
	switch level {
	case "DEBUG":
		defaultLogger.level = DEBUG
	case "INFO":
		defaultLogger.level = INFO
	case "WARN":
		defaultLogger.level = WARN
	case "ERROR":
		defaultLogger.level = ERROR
	case "FATAL":
		defaultLogger.level = FATAL
	default:
		// Invalid log levels default to INFO for safety
		defaultLogger.level = INFO
	}
}

// SetFormat sets the output format for the default logger
func SetFormat(format string) {
	once.Do(initDefaultLogger)
	switch strings.ToLower(format) {
	case "json":
		defaultLogger.format = JSONFormat
		defaultLogger.useColor = false // Disable colors for JSON
	case "console":
		defaultLogger.format = ConsoleFormat
	default:
		// Invalid log formats default to console for safety
		defaultLogger.format = ConsoleFormat
	}
}

// SetComponent sets the component name for the default logger
// NOTE: This is deprecated - use WithComponent() instead for better module isolation
func SetComponent(component string) {
	once.Do(initDefaultLogger)
	defaultLogger.component = component
}

// formatConsole formats a log message for console output
func (l *Logger) formatConsole(level LogLevel, msg string) string {
	// Format timestamp like Caddy: "2025/06/16 12:05:17.420"
	now := time.Now().Format("2006/01/02 15:04:05.000")
	levelName := levelNames[level]

	// Format the log line with improved spacing and icon support
	if l.useColor {
		return fmt.Sprintf("%s %s%4s%s %s",
			now,
			levelColors[level],
			levelName,
			resetColor,
			msg)
	} else {
		return fmt.Sprintf("%s %4s %s", now, levelName, msg)
	}
}

// formatJSON formats a log message for JSON output
func (l *Logger) formatJSON(level LogLevel, msg string) string {
	entry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Level:     strings.ToLower(levelNames[level]),
		Message:   msg,
		Component: l.component,
	}

	// Marshal to JSON
	data, err := json.Marshal(entry)
	if err != nil {
		// Fallback to console format if JSON marshaling fails
		return l.formatConsole(level, fmt.Sprintf("JSON marshal error: %v, original message: %s", err, msg))
	}

	return string(data)
}

// getEffectiveConfig returns the effective configuration for this logger
// Component loggers use the default logger's configuration dynamically
func (l *Logger) getEffectiveConfig() (LogLevel, Format, io.Writer, bool) {
	if l.isComponentLogger {
		// Component loggers reference default logger's config dynamically
		once.Do(initDefaultLogger)
		return defaultLogger.level, defaultLogger.format, defaultLogger.output, defaultLogger.useColor
	}
	// Regular loggers use their own config
	return l.level, l.format, l.output, l.useColor
}

// log writes a log message with the given level and format
func (l *Logger) log(level LogLevel, format string, v ...interface{}) {
	// Get effective configuration (dynamic for component loggers)
	effectiveLevel, effectiveFormat, effectiveOutput, effectiveUseColor := l.getEffectiveConfig()

	if level < effectiveLevel {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Create the log message
	msg := fmt.Sprintf(format, v...)

	// Create a temporary logger with effective config for formatting
	tempLogger := &Logger{
		format:    effectiveFormat,
		component: l.component,
		useColor:  effectiveUseColor,
	}

	// Format based on the effective format
	var logLine string
	switch effectiveFormat {
	case JSONFormat:
		logLine = tempLogger.formatJSON(level, msg)
	case ConsoleFormat:
		logLine = tempLogger.formatConsole(level, msg)
	default:
		logLine = tempLogger.formatConsole(level, msg)
	}

	fmt.Fprintln(effectiveOutput, logLine)
}

// logWithFields writes a log message with additional structured fields (for JSON format)
func (l *Logger) logWithFields(level LogLevel, fields map[string]interface{}, format string, v ...interface{}) {
	// Get effective configuration (dynamic for component loggers)
	effectiveLevel, effectiveFormat, effectiveOutput, effectiveUseColor := l.getEffectiveConfig()

	if level < effectiveLevel {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Create the log message
	msg := fmt.Sprintf(format, v...)

	var logLine string
	switch effectiveFormat {
	case JSONFormat:
		entry := LogEntry{
			Timestamp: time.Now().Format(time.RFC3339Nano),
			Level:     strings.ToLower(levelNames[level]),
			Message:   msg,
			Component: l.component,
		}

		// Add message-specific fields to the entry
		if len(fields) > 0 {
			// We need to create a custom struct that includes the fields
			// Since we can't modify LogEntry structure dynamically, we'll use a map
			entryMap := map[string]interface{}{
				"ts":        entry.Timestamp,
				"level":     entry.Level,
				"msg":       entry.Message,
				"component": entry.Component,
			}

			// Add the additional fields
			for k, v := range fields {
				entryMap[k] = v
			}

			// Marshal the map instead of the struct
			data, err := json.Marshal(entryMap)
			if err != nil {
				tempLogger := &Logger{format: ConsoleFormat, component: l.component, useColor: effectiveUseColor}
				logLine = tempLogger.formatConsole(level, fmt.Sprintf("JSON marshal error: %v, original message: %s", err, msg))
			} else {
				logLine = string(data)
			}
		} else {
			// No additional fields, use the regular struct
			data, err := json.Marshal(entry)
			if err != nil {
				tempLogger := &Logger{format: ConsoleFormat, component: l.component, useColor: effectiveUseColor}
				logLine = tempLogger.formatConsole(level, fmt.Sprintf("JSON marshal error: %v, original message: %s", err, msg))
			} else {
				logLine = string(data)
			}
		}
	case ConsoleFormat:
		// For console format, append fields as key=value pairs
		if len(fields) > 0 {
			var fieldStrs []string
			for k, v := range fields {
				fieldStrs = append(fieldStrs, fmt.Sprintf("%s=%v", k, v))
			}
			msg = fmt.Sprintf("%s [%s]", msg, strings.Join(fieldStrs, " "))
		}
		tempLogger := &Logger{format: ConsoleFormat, component: l.component, useColor: effectiveUseColor}
		logLine = tempLogger.formatConsole(level, msg)
	default:
		tempLogger := &Logger{format: ConsoleFormat, component: l.component, useColor: effectiveUseColor}
		logLine = tempLogger.formatConsole(level, msg)
	}

	fmt.Fprintln(effectiveOutput, logLine)
}

// Debug logs a debug message
func Debug(format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.log(DEBUG, format, v...)
}

// DebugWithFields logs a debug message with structured fields
func DebugWithFields(fields map[string]interface{}, format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.logWithFields(DEBUG, fields, format, v...)
}

// Info logs an info message
func Info(format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.log(INFO, format, v...)
}

// InfoWithFields logs an info message with structured fields
func InfoWithFields(fields map[string]interface{}, format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.logWithFields(INFO, fields, format, v...)
}

// Warn logs a warning message
func Warn(format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.log(WARN, format, v...)
}

// WarnWithFields logs a warning message with structured fields
func WarnWithFields(fields map[string]interface{}, format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.logWithFields(WARN, fields, format, v...)
}

// Error logs an error message
func Error(format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.log(ERROR, format, v...)
}

// ErrorWithFields logs an error message with structured fields
func ErrorWithFields(fields map[string]interface{}, format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.logWithFields(ERROR, fields, format, v...)
}

// Fatal logs a fatal message and exits
func Fatal(format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.log(FATAL, format, v...)
	os.Exit(1)
}

// FatalWithFields logs a fatal message with structured fields and exits
func FatalWithFields(fields map[string]interface{}, format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.logWithFields(FATAL, fields, format, v...)
	os.Exit(1)
}

// Convenience methods for Logger instances to support component-specific logging

// Debug logs a debug message using this logger instance
func (l *Logger) Debug(format string, v ...interface{}) {
	l.log(DEBUG, format, v...)
}

// DebugWithFields logs a debug message with structured fields using this logger instance
func (l *Logger) DebugWithFields(fields map[string]interface{}, format string, v ...interface{}) {
	l.logWithFields(DEBUG, fields, format, v...)
}

// Info logs an info message using this logger instance
func (l *Logger) Info(format string, v ...interface{}) {
	l.log(INFO, format, v...)
}

// InfoWithFields logs an info message with structured fields using this logger instance
func (l *Logger) InfoWithFields(fields map[string]interface{}, format string, v ...interface{}) {
	l.logWithFields(INFO, fields, format, v...)
}

// Warn logs a warning message using this logger instance
func (l *Logger) Warn(format string, v ...interface{}) {
	l.log(WARN, format, v...)
}

// WarnWithFields logs a warning message with structured fields using this logger instance
func (l *Logger) WarnWithFields(fields map[string]interface{}, format string, v ...interface{}) {
	l.logWithFields(WARN, fields, format, v...)
}

// Error logs an error message using this logger instance
func (l *Logger) Error(format string, v ...interface{}) {
	l.log(ERROR, format, v...)
}

// ErrorWithFields logs an error message with structured fields using this logger instance
func (l *Logger) ErrorWithFields(fields map[string]interface{}, format string, v ...interface{}) {
	l.logWithFields(ERROR, fields, format, v...)
}

// Fatal logs a fatal message using this logger instance and exits
func (l *Logger) Fatal(format string, v ...interface{}) {
	l.log(FATAL, format, v...)
	os.Exit(1)
}

// FatalWithFields logs a fatal message with structured fields using this logger instance and exits
func (l *Logger) FatalWithFields(fields map[string]interface{}, format string, v ...interface{}) {
	l.logWithFields(FATAL, fields, format, v...)
	os.Exit(1)
}
