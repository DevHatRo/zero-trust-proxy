package common

import (
	"time"
)

// TimeoutConfig holds timeout configuration
type TimeoutConfig struct {
	DefaultTimeout   time.Duration
	StreamingTimeout time.Duration
	LargeFileTimeout time.Duration
	HeartbeatTimeout time.Duration
}

// DefaultTimeouts returns a default timeout configuration
func DefaultTimeouts() *TimeoutConfig {
	return &TimeoutConfig{
		DefaultTimeout:   30 * time.Second,
		StreamingTimeout: 1 * time.Minute,
		LargeFileTimeout: 10 * time.Minute,
		HeartbeatTimeout: 15 * time.Second,
	}
}

// CalculateWriteTimeout calculates appropriate write timeout based on message characteristics
func CalculateWriteTimeout(msg *Message, config *TimeoutConfig) time.Duration {
	if config == nil {
		config = DefaultTimeouts()
	}

	// Default timeout for regular messages
	defaultTimeout := config.DefaultTimeout

	// For HTTP responses, especially streaming chunks, use longer timeouts
	if msg.Type == "http_response" && msg.HTTP != nil {
		// For streaming chunks, calculate timeout based on chunk size
		if msg.HTTP.IsStream {
			chunkSize := len(msg.HTTP.Body)

			// Base timeout for streaming chunks
			streamTimeout := config.StreamingTimeout

			// Add extra time for large chunks (1 second per 32KB)
			if chunkSize > 0 {
				extraTime := time.Duration(chunkSize/32768) * time.Second
				streamTimeout += extraTime
			}

			// Cap at maximum large file timeout
			if streamTimeout > config.LargeFileTimeout {
				streamTimeout = config.LargeFileTimeout
			}

			// Minimum of streaming timeout
			if streamTimeout < config.StreamingTimeout {
				streamTimeout = config.StreamingTimeout
			}

			return streamTimeout
		}

		// For large non-streaming responses
		bodySize := len(msg.HTTP.Body)
		if bodySize > 1024*1024 { // >1MB
			return 2 * time.Minute
		}
	}

	// For HTTP requests being sent to agents
	if msg.Type == "http_request" && msg.HTTP != nil {
		bodySize := len(msg.HTTP.Body)

		// Base timeout for HTTP requests
		requestTimeout := config.StreamingTimeout

		// Add extra time for large request bodies
		if bodySize > 1024*1024 { // >1MB request body
			requestTimeout = 2 * time.Minute
		}

		return requestTimeout
	}

	return defaultTimeout
}

// CalculateStreamingTimeout calculates timeout for streaming operations
func CalculateStreamingTimeout(totalSize, received int64, config *TimeoutConfig) time.Duration {
	if config == nil {
		config = DefaultTimeouts()
	}

	// Base timeout
	baseTimeout := config.StreamingTimeout

	// For very large files, use progressive timeouts
	if totalSize > 0 {
		// Calculate progress
		progress := float64(received) / float64(totalSize)

		// If we're making good progress, use standard timeout
		if progress > 0.1 { // More than 10% received
			return baseTimeout
		}

		// For large files that are just starting, use longer timeout
		if totalSize > 100*1024*1024 { // >100MB
			return config.LargeFileTimeout
		}
	}

	return baseTimeout
}

// CalculateHeartbeatTimeout calculates timeout for heartbeat operations
func CalculateHeartbeatTimeout(config *TimeoutConfig) time.Duration {
	if config == nil {
		config = DefaultTimeouts()
	}
	return config.HeartbeatTimeout
}

// AdaptiveTimeout manages adaptive timeouts based on success/failure rates
type AdaptiveTimeout struct {
	baseTimeout      time.Duration
	maxTimeout       time.Duration
	failureCount     int
	successCount     int
	consecutiveFails int
}

// NewAdaptiveTimeout creates a new adaptive timeout manager
func NewAdaptiveTimeout(baseTimeout, maxTimeout time.Duration) *AdaptiveTimeout {
	return &AdaptiveTimeout{
		baseTimeout: baseTimeout,
		maxTimeout:  maxTimeout,
	}
}

// GetTimeout returns the current adaptive timeout
func (at *AdaptiveTimeout) GetTimeout() time.Duration {
	// Increase timeout based on consecutive failures
	if at.consecutiveFails > 5 {
		return at.maxTimeout
	} else if at.consecutiveFails > 2 {
		return at.baseTimeout + (at.baseTimeout / 2)
	}
	return at.baseTimeout
}

// RecordSuccess records a successful operation
func (at *AdaptiveTimeout) RecordSuccess() {
	at.successCount++
	at.consecutiveFails = 0
}

// RecordFailure records a failed operation
func (at *AdaptiveTimeout) RecordFailure() {
	at.failureCount++
	at.consecutiveFails++
}

// GetStats returns success/failure statistics
func (at *AdaptiveTimeout) GetStats() (successes, failures, consecutiveFailures int) {
	return at.successCount, at.failureCount, at.consecutiveFails
}
