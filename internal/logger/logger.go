package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
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

// Logger represents a structured logger instance
type Logger struct {
	mu       sync.Mutex
	level    LogLevel
	output   io.Writer
	module   string
	useColor bool
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// initDefaultLogger initializes the default logger
func initDefaultLogger() {
	defaultLogger = NewLogger(os.Stdout, INFO, "", true)
}

// NewLogger creates a new logger instance
func NewLogger(output io.Writer, level LogLevel, module string, useColor bool) *Logger {
	return &Logger{
		level:    level,
		output:   output,
		module:   module,
		useColor: useColor,
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
		Error("Invalid log level: %s, using INFO", level)
		defaultLogger.level = INFO
	}
}

// log writes a log message with the given level and format
func (l *Logger) log(level LogLevel, format string, v ...interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Format timestamp like Caddy: "2025/06/16 12:05:17.420"
	now := time.Now().Format("2006/01/02 15:04:05.000")
	levelName := levelNames[level]

	// Create the log message
	msg := fmt.Sprintf(format, v...)

	// Format the log line with improved spacing and icon support
	var logLine string
	if l.useColor {
		logLine = fmt.Sprintf("%s %s%4s%s %s",
			now,
			levelColors[level],
			levelName,
			resetColor,
			msg)
	} else {
		logLine = fmt.Sprintf("%s %4s %s", now, levelName, msg)
	}

	fmt.Fprintln(l.output, logLine)
}

// Debug logs a debug message
func Debug(format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.log(DEBUG, format, v...)
}

// Info logs an info message
func Info(format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.log(INFO, format, v...)
}

// Warn logs a warning message
func Warn(format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.log(WARN, format, v...)
}

// Error logs an error message
func Error(format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.log(ERROR, format, v...)
}

// Fatal logs a fatal message and exits
func Fatal(format string, v ...interface{}) {
	once.Do(initDefaultLogger)
	defaultLogger.log(FATAL, format, v...)
	os.Exit(1)
}
