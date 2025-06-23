package common

import (
	"testing"
	"time"
)

// TestDefaultTimeouts tests the default timeout configuration
func TestDefaultTimeouts(t *testing.T) {
	config := DefaultTimeouts()

	if config.DefaultTimeout != 30*time.Second {
		t.Errorf("expected DefaultTimeout 30s, got %v", config.DefaultTimeout)
	}
	if config.StreamingTimeout != 1*time.Minute {
		t.Errorf("expected StreamingTimeout 1m, got %v", config.StreamingTimeout)
	}
	if config.LargeFileTimeout != 10*time.Minute {
		t.Errorf("expected LargeFileTimeout 10m, got %v", config.LargeFileTimeout)
	}
	if config.HeartbeatTimeout != 15*time.Second {
		t.Errorf("expected HeartbeatTimeout 15s, got %v", config.HeartbeatTimeout)
	}
}

// TestCalculateWriteTimeout tests timeout calculation for different message types
func TestCalculateWriteTimeout(t *testing.T) {
	config := DefaultTimeouts()

	tests := []struct {
		name     string
		msg      *Message
		expected time.Duration
	}{
		{
			name: "simple message",
			msg: &Message{
				Type: "service_add",
			},
			expected: config.DefaultTimeout,
		},
		{
			name: "http response streaming",
			msg: &Message{
				Type: "http_response",
				HTTP: &HTTPData{
					IsStream: true,
					Body:     make([]byte, 32768), // 32KB
				},
			},
			expected: config.StreamingTimeout + time.Second, // Extra time for 32KB chunk
		},
		{
			name: "http response large body",
			msg: &Message{
				Type: "http_response",
				HTTP: &HTTPData{
					IsStream: false,
					Body:     make([]byte, 2*1024*1024), // 2MB
				},
			},
			expected: 2 * time.Minute,
		},
		{
			name: "http request with large body",
			msg: &Message{
				Type: "http_request",
				HTTP: &HTTPData{
					Body: make([]byte, 2*1024*1024), // 2MB
				},
			},
			expected: 2 * time.Minute,
		},
		{
			name: "http request normal size",
			msg: &Message{
				Type: "http_request",
				HTTP: &HTTPData{
					Body: make([]byte, 1024), // 1KB
				},
			},
			expected: config.StreamingTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeout := CalculateWriteTimeout(tt.msg, config)
			if timeout != tt.expected {
				t.Errorf("expected timeout %v, got %v", tt.expected, timeout)
			}
		})
	}
}

// TestCalculateWriteTimeoutWithNilConfig tests timeout calculation with nil config
func TestCalculateWriteTimeoutWithNilConfig(t *testing.T) {
	msg := &Message{Type: "test"}
	timeout := CalculateWriteTimeout(msg, nil)

	expected := DefaultTimeouts().DefaultTimeout
	if timeout != expected {
		t.Errorf("expected timeout %v, got %v", expected, timeout)
	}
}

// TestCalculateStreamingTimeout tests streaming timeout calculations
func TestCalculateStreamingTimeout(t *testing.T) {
	config := DefaultTimeouts()

	tests := []struct {
		name      string
		totalSize int64
		received  int64
		expected  time.Duration
	}{
		{
			name:      "good progress",
			totalSize: 1000,
			received:  150, // 15% progress
			expected:  config.StreamingTimeout,
		},
		{
			name:      "slow start",
			totalSize: 1000,
			received:  50, // 5% progress
			expected:  config.StreamingTimeout,
		},
		{
			name:      "large file slow start",
			totalSize: 200 * 1024 * 1024, // 200MB
			received:  1024 * 1024,       // 1MB (0.5% progress)
			expected:  config.LargeFileTimeout,
		},
		{
			name:      "unknown total size",
			totalSize: 0,
			received:  1024,
			expected:  config.StreamingTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeout := CalculateStreamingTimeout(tt.totalSize, tt.received, config)
			if timeout != tt.expected {
				t.Errorf("expected timeout %v, got %v", tt.expected, timeout)
			}
		})
	}
}

// TestCalculateStreamingTimeoutWithNilConfig tests streaming timeout with nil config
func TestCalculateStreamingTimeoutWithNilConfig(t *testing.T) {
	timeout := CalculateStreamingTimeout(1000, 100, nil)
	expected := DefaultTimeouts().StreamingTimeout
	if timeout != expected {
		t.Errorf("expected timeout %v, got %v", expected, timeout)
	}
}

// TestCalculateHeartbeatTimeout tests heartbeat timeout calculation
func TestCalculateHeartbeatTimeout(t *testing.T) {
	config := DefaultTimeouts()
	timeout := CalculateHeartbeatTimeout(config)

	if timeout != config.HeartbeatTimeout {
		t.Errorf("expected timeout %v, got %v", config.HeartbeatTimeout, timeout)
	}
}

// TestCalculateHeartbeatTimeoutWithNilConfig tests heartbeat timeout with nil config
func TestCalculateHeartbeatTimeoutWithNilConfig(t *testing.T) {
	timeout := CalculateHeartbeatTimeout(nil)
	expected := DefaultTimeouts().HeartbeatTimeout
	if timeout != expected {
		t.Errorf("expected timeout %v, got %v", expected, timeout)
	}
}

// TestNewAdaptiveTimeout tests creating a new adaptive timeout manager
func TestNewAdaptiveTimeout(t *testing.T) {
	baseTimeout := 30 * time.Second
	maxTimeout := 2 * time.Minute

	at := NewAdaptiveTimeout(baseTimeout, maxTimeout)

	if at.baseTimeout != baseTimeout {
		t.Errorf("expected baseTimeout %v, got %v", baseTimeout, at.baseTimeout)
	}
	if at.maxTimeout != maxTimeout {
		t.Errorf("expected maxTimeout %v, got %v", maxTimeout, at.maxTimeout)
	}
	if at.failureCount != 0 {
		t.Errorf("expected initial failureCount 0, got %d", at.failureCount)
	}
	if at.successCount != 0 {
		t.Errorf("expected initial successCount 0, got %d", at.successCount)
	}
	if at.consecutiveFails != 0 {
		t.Errorf("expected initial consecutiveFails 0, got %d", at.consecutiveFails)
	}
}

// TestAdaptiveTimeoutGetTimeout tests timeout calculation based on failure rates
func TestAdaptiveTimeoutGetTimeout(t *testing.T) {
	baseTimeout := 30 * time.Second
	maxTimeout := 2 * time.Minute
	at := NewAdaptiveTimeout(baseTimeout, maxTimeout)

	// Initial timeout should be base timeout
	timeout := at.GetTimeout()
	if timeout != baseTimeout {
		t.Errorf("expected initial timeout %v, got %v", baseTimeout, timeout)
	}

	// After 3 consecutive failures, timeout should increase
	at.consecutiveFails = 3
	timeout = at.GetTimeout()
	expected := baseTimeout + (baseTimeout / 2)
	if timeout != expected {
		t.Errorf("expected timeout %v after 3 failures, got %v", expected, timeout)
	}

	// After 6 consecutive failures, timeout should be max
	at.consecutiveFails = 6
	timeout = at.GetTimeout()
	if timeout != maxTimeout {
		t.Errorf("expected max timeout %v after 6 failures, got %v", maxTimeout, timeout)
	}
}

// TestAdaptiveTimeoutRecordSuccess tests recording successful operations
func TestAdaptiveTimeoutRecordSuccess(t *testing.T) {
	at := NewAdaptiveTimeout(30*time.Second, 2*time.Minute)

	// Set some failures first
	at.consecutiveFails = 5
	at.failureCount = 10

	// Record success
	at.RecordSuccess()

	if at.successCount != 1 {
		t.Errorf("expected successCount 1, got %d", at.successCount)
	}
	if at.consecutiveFails != 0 {
		t.Errorf("expected consecutiveFails to reset to 0, got %d", at.consecutiveFails)
	}
	if at.failureCount != 10 {
		t.Errorf("expected failureCount to remain 10, got %d", at.failureCount)
	}
}

// TestAdaptiveTimeoutRecordFailure tests recording failed operations
func TestAdaptiveTimeoutRecordFailure(t *testing.T) {
	at := NewAdaptiveTimeout(30*time.Second, 2*time.Minute)

	// Set some successes first
	at.successCount = 5

	// Record failure
	at.RecordFailure()

	if at.failureCount != 1 {
		t.Errorf("expected failureCount 1, got %d", at.failureCount)
	}
	if at.consecutiveFails != 1 {
		t.Errorf("expected consecutiveFails 1, got %d", at.consecutiveFails)
	}
	if at.successCount != 5 {
		t.Errorf("expected successCount to remain 5, got %d", at.successCount)
	}
}

// TestAdaptiveTimeoutGetStats tests retrieving statistics
func TestAdaptiveTimeoutGetStats(t *testing.T) {
	at := NewAdaptiveTimeout(30*time.Second, 2*time.Minute)

	// Record some operations
	at.RecordSuccess()
	at.RecordSuccess()
	at.RecordFailure()
	at.RecordFailure()
	at.RecordFailure()

	successes, failures, consecutive := at.GetStats()

	if successes != 2 {
		t.Errorf("expected 2 successes, got %d", successes)
	}
	if failures != 3 {
		t.Errorf("expected 3 failures, got %d", failures)
	}
	if consecutive != 3 {
		t.Errorf("expected 3 consecutive failures, got %d", consecutive)
	}
}

// TestAdaptiveTimeoutIntegration tests the complete adaptive timeout workflow
func TestAdaptiveTimeoutIntegration(t *testing.T) {
	baseTimeout := 10 * time.Second
	maxTimeout := 60 * time.Second
	at := NewAdaptiveTimeout(baseTimeout, maxTimeout)

	// Initially should use base timeout
	if at.GetTimeout() != baseTimeout {
		t.Error("should start with base timeout")
	}

	// Simulate some successful operations
	for i := 0; i < 5; i++ {
		at.RecordSuccess()
	}
	if at.GetTimeout() != baseTimeout {
		t.Error("should stay at base timeout after successes")
	}

	// Simulate some failures
	for i := 0; i < 3; i++ {
		at.RecordFailure()
	}
	timeout := at.GetTimeout()
	expected := baseTimeout + (baseTimeout / 2)
	if timeout != expected {
		t.Errorf("expected increased timeout %v, got %v", expected, timeout)
	}

	// More failures should max out timeout
	for i := 0; i < 5; i++ {
		at.RecordFailure()
	}
	if at.GetTimeout() != maxTimeout {
		t.Error("should use max timeout after many failures")
	}

	// Success should reset consecutive failures
	at.RecordSuccess()
	if at.GetTimeout() != baseTimeout {
		t.Error("should reset to base timeout after success")
	}
}

// BenchmarkCalculateWriteTimeout benchmarks timeout calculation
func BenchmarkCalculateWriteTimeout(b *testing.B) {
	config := DefaultTimeouts()
	msg := &Message{
		Type: "http_response",
		HTTP: &HTTPData{
			IsStream: true,
			Body:     make([]byte, 32768),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalculateWriteTimeout(msg, config)
	}
}

// BenchmarkAdaptiveTimeout benchmarks adaptive timeout operations
func BenchmarkAdaptiveTimeout(b *testing.B) {
	at := NewAdaptiveTimeout(30*time.Second, 2*time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		at.GetTimeout()
		if i%2 == 0 {
			at.RecordSuccess()
		} else {
			at.RecordFailure()
		}
	}
}
