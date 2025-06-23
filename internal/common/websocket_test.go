package common

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// mockConn implements net.Conn for WebSocket testing
type mockConn struct {
	closed     bool
	localAddr  net.Addr
	remoteAddr net.Addr
	mu         sync.Mutex
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, net.ErrClosed
	}
	// Simulate some data
	if len(b) > 0 {
		b[0] = 'x'
		return 1, nil
	}
	return 0, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, net.ErrClosed
	}
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return m.localAddr
}

func (m *mockConn) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func newMockConn() *mockConn {
	return &mockConn{
		closed:     false,
		localAddr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
		remoteAddr: &net.TCPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 54321},
	}
}

// TestNewWebSocketConnection tests creating a new WebSocket connection
func TestNewWebSocketConnection(t *testing.T) {
	conn := newMockConn()
	wsc := NewWebSocketConnection(conn)

	if wsc == nil {
		t.Fatal("NewWebSocketConnection returned nil")
	}

	if wsc.conn != conn {
		t.Error("WebSocket connection not properly set")
	}

	if wsc.lastActivity.IsZero() {
		t.Error("last activity should be initialized")
	}

	if wsc.done == nil {
		t.Error("done channel should be initialized")
	}

	if wsc.healthTicker == nil {
		t.Error("health ticker should be initialized")
	}

	// Clean up
	wsc.Close()
}

// TestWebSocketConnectionUpdateActivity tests activity updates
func TestWebSocketConnectionUpdateActivity(t *testing.T) {
	conn := newMockConn()
	wsc := NewWebSocketConnection(conn)
	defer wsc.Close()

	initialActivity := wsc.lastActivity

	// Sleep a bit to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Update activity
	wsc.UpdateActivity()

	// Check that activity was updated
	if !wsc.lastActivity.After(initialActivity) {
		t.Error("activity timestamp should be updated")
	}
}

// TestWebSocketConnectionIsHealthy tests health checking
func TestWebSocketConnectionIsHealthy(t *testing.T) {
	conn := newMockConn()
	wsc := NewWebSocketConnection(conn)
	defer wsc.Close()

	// Should be healthy initially
	if !wsc.IsHealthy() {
		t.Error("new connection should be healthy")
	}

	// Set activity to old timestamp to simulate stale connection
	oldTime := time.Now().Add(-6 * time.Minute)
	wsc.mu.Lock()
	wsc.lastActivity = oldTime
	wsc.mu.Unlock()

	// Should now be unhealthy
	if wsc.IsHealthy() {
		t.Error("connection with old activity should be unhealthy")
	}

	// Update activity to make it healthy again
	wsc.UpdateActivity()
	if !wsc.IsHealthy() {
		t.Error("connection with recent activity should be healthy")
	}
}

// TestWebSocketConnectionClose tests connection closing
func TestWebSocketConnectionClose(t *testing.T) {
	conn := newMockConn()
	wsc := NewWebSocketConnection(conn)

	// Verify connection is not closed initially
	if conn.IsClosed() {
		t.Error("connection should not be closed initially")
	}

	// Close the WebSocket connection
	wsc.Close()

	// Verify connection is closed
	if !conn.IsClosed() {
		t.Error("connection should be closed after Close()")
	}

	// Verify health ticker is stopped (we can't directly test this,
	// but calling Close() multiple times should not panic)
	wsc.Close() // Should not panic
}

// TestWebSocketConnectionGetLastActivity tests retrieving last activity
func TestWebSocketConnectionGetLastActivity(t *testing.T) {
	conn := newMockConn()
	wsc := NewWebSocketConnection(conn)
	defer wsc.Close()

	initialActivity := wsc.GetLastActivity()
	if initialActivity.IsZero() {
		t.Error("initial activity should not be zero")
	}

	// Update activity
	time.Sleep(10 * time.Millisecond)
	wsc.UpdateActivity()

	newActivity := wsc.GetLastActivity()
	if !newActivity.After(initialActivity) {
		t.Error("updated activity should be more recent")
	}
}

// TestWebSocketConnectionGetConn tests getting the underlying connection
func TestWebSocketConnectionGetConn(t *testing.T) {
	conn := newMockConn()
	wsc := NewWebSocketConnection(conn)
	defer wsc.Close()

	retrievedConn := wsc.GetConn()
	if retrievedConn != conn {
		t.Error("GetConn should return the original connection")
	}
}

// TestNewWebSocketManager tests creating a new WebSocket manager
func TestNewWebSocketManager(t *testing.T) {
	wsm := NewWebSocketManager()

	if wsm == nil {
		t.Fatal("NewWebSocketManager returned nil")
	}

	if wsm.connections == nil {
		t.Error("connections map should be initialized")
	}

	if len(wsm.connections) != 0 {
		t.Error("connections map should be empty initially")
	}
}

// TestWebSocketManagerAddConnection tests adding connections
func TestWebSocketManagerAddConnection(t *testing.T) {
	wsm := NewWebSocketManager()
	conn := newMockConn()
	id := "test-connection-1"

	// Add connection
	wsm.AddConnection(id, conn)

	// Verify connection was added
	if wsm.GetConnectionCount() != 1 {
		t.Error("connection count should be 1 after adding connection")
	}

	// Verify we can retrieve the connection
	wsc, exists := wsm.GetConnection(id)
	if !exists {
		t.Error("connection should exist after adding")
	}
	if wsc.GetConn() != conn {
		t.Error("retrieved connection should match original")
	}

	// Clean up
	wsm.CloseAll()
}

// TestWebSocketManagerRemoveConnection tests removing connections
func TestWebSocketManagerRemoveConnection(t *testing.T) {
	wsm := NewWebSocketManager()
	conn := newMockConn()
	id := "test-connection-1"

	// Add connection
	wsm.AddConnection(id, conn)

	// Verify connection exists
	if wsm.GetConnectionCount() != 1 {
		t.Error("connection count should be 1 after adding")
	}

	// Remove connection
	wsm.RemoveConnection(id)

	// Verify connection was removed
	if wsm.GetConnectionCount() != 0 {
		t.Error("connection count should be 0 after removing")
	}

	// Verify connection no longer exists
	_, exists := wsm.GetConnection(id)
	if exists {
		t.Error("connection should not exist after removing")
	}

	// Verify underlying connection was closed
	if !conn.IsClosed() {
		t.Error("underlying connection should be closed when removed")
	}
}

// TestWebSocketManagerUpdateActivity tests updating connection activity
func TestWebSocketManagerUpdateActivity(t *testing.T) {
	wsm := NewWebSocketManager()
	conn := newMockConn()
	id := "test-connection-1"

	// Add connection
	wsm.AddConnection(id, conn)

	// Get initial activity
	wsc, _ := wsm.GetConnection(id)
	initialActivity := wsc.GetLastActivity()

	// Sleep to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Update activity through manager
	wsm.UpdateActivity(id)

	// Verify activity was updated
	newActivity := wsc.GetLastActivity()
	if !newActivity.After(initialActivity) {
		t.Error("activity should be updated through manager")
	}

	// Test updating activity for non-existent connection (should not panic)
	wsm.UpdateActivity("non-existent")

	// Clean up
	wsm.CloseAll()
}

// TestWebSocketManagerGetConnection tests retrieving connections
func TestWebSocketManagerGetConnection(t *testing.T) {
	wsm := NewWebSocketManager()
	conn := newMockConn()
	id := "test-connection-1"

	// Test getting non-existent connection
	_, exists := wsm.GetConnection(id)
	if exists {
		t.Error("non-existent connection should not exist")
	}

	// Add connection
	wsm.AddConnection(id, conn)

	// Test getting existing connection
	wsc, exists := wsm.GetConnection(id)
	if !exists {
		t.Error("existing connection should be found")
	}
	if wsc == nil {
		t.Error("returned connection should not be nil")
	}
	if wsc.GetConn() != conn {
		t.Error("returned connection should match original")
	}

	// Clean up
	wsm.CloseAll()
}

// TestWebSocketManagerGetConnectionCount tests connection counting
func TestWebSocketManagerGetConnectionCount(t *testing.T) {
	wsm := NewWebSocketManager()

	// Initially should have 0 connections
	if wsm.GetConnectionCount() != 0 {
		t.Error("initial connection count should be 0")
	}

	// Add connections
	wsm.AddConnection("conn1", newMockConn())
	if wsm.GetConnectionCount() != 1 {
		t.Error("connection count should be 1 after adding one connection")
	}

	wsm.AddConnection("conn2", newMockConn())
	if wsm.GetConnectionCount() != 2 {
		t.Error("connection count should be 2 after adding two connections")
	}

	wsm.AddConnection("conn3", newMockConn())
	if wsm.GetConnectionCount() != 3 {
		t.Error("connection count should be 3 after adding three connections")
	}

	// Remove one connection
	wsm.RemoveConnection("conn2")
	if wsm.GetConnectionCount() != 2 {
		t.Error("connection count should be 2 after removing one connection")
	}

	// Clean up
	wsm.CloseAll()
}

// TestWebSocketManagerCleanupStaleConnections tests stale connection cleanup
func TestWebSocketManagerCleanupStaleConnections(t *testing.T) {
	wsm := NewWebSocketManager()

	// Add healthy connections
	wsm.AddConnection("healthy1", newMockConn())
	wsm.AddConnection("healthy2", newMockConn())

	// Add stale connections by manipulating their activity timestamps
	wsm.AddConnection("stale1", newMockConn())
	wsm.AddConnection("stale2", newMockConn())

	// Make some connections stale
	stale1, _ := wsm.GetConnection("stale1")
	stale2, _ := wsm.GetConnection("stale2")

	oldTime := time.Now().Add(-6 * time.Minute)
	stale1.mu.Lock()
	stale1.lastActivity = oldTime
	stale1.mu.Unlock()

	stale2.mu.Lock()
	stale2.lastActivity = oldTime
	stale2.mu.Unlock()

	// Verify initial state
	if wsm.GetConnectionCount() != 4 {
		t.Error("should have 4 connections before cleanup")
	}

	// Run cleanup
	removed := wsm.CleanupStaleConnections()

	// Verify cleanup results
	if removed != 2 {
		t.Errorf("expected 2 removed connections, got %d", removed)
	}

	if wsm.GetConnectionCount() != 2 {
		t.Errorf("expected 2 remaining connections, got %d", wsm.GetConnectionCount())
	}

	// Verify healthy connections remain
	_, exists1 := wsm.GetConnection("healthy1")
	_, exists2 := wsm.GetConnection("healthy2")
	if !exists1 || !exists2 {
		t.Error("healthy connections should remain after cleanup")
	}

	// Verify stale connections were removed
	_, exists3 := wsm.GetConnection("stale1")
	_, exists4 := wsm.GetConnection("stale2")
	if exists3 || exists4 {
		t.Error("stale connections should be removed after cleanup")
	}

	// Clean up
	wsm.CloseAll()
}

// TestWebSocketManagerGetStats tests getting connection statistics
func TestWebSocketManagerGetStats(t *testing.T) {
	wsm := NewWebSocketManager()

	// Initially should have no connections
	total, healthy, stale := wsm.GetStats()
	if total != 0 || healthy != 0 || stale != 0 {
		t.Error("initial stats should be all zeros")
	}

	// Add healthy connections
	wsm.AddConnection("healthy1", newMockConn())
	wsm.AddConnection("healthy2", newMockConn())

	// Add stale connection
	wsm.AddConnection("stale1", newMockConn())
	staleConn, _ := wsm.GetConnection("stale1")
	oldTime := time.Now().Add(-6 * time.Minute)
	staleConn.mu.Lock()
	staleConn.lastActivity = oldTime
	staleConn.mu.Unlock()

	// Check stats
	total, healthy, stale = wsm.GetStats()
	if total != 3 {
		t.Errorf("expected total 3, got %d", total)
	}
	if healthy != 2 {
		t.Errorf("expected healthy 2, got %d", healthy)
	}
	if stale != 1 {
		t.Errorf("expected stale 1, got %d", stale)
	}

	// Clean up
	wsm.CloseAll()
}

// TestWebSocketManagerCloseAll tests closing all connections
func TestWebSocketManagerCloseAll(t *testing.T) {
	wsm := NewWebSocketManager()

	// Create mock connections to track closure
	conn1 := newMockConn()
	conn2 := newMockConn()
	conn3 := newMockConn()

	// Add connections
	wsm.AddConnection("conn1", conn1)
	wsm.AddConnection("conn2", conn2)
	wsm.AddConnection("conn3", conn3)

	// Verify connections exist
	if wsm.GetConnectionCount() != 3 {
		t.Error("should have 3 connections before CloseAll")
	}

	// Close all connections
	wsm.CloseAll()

	// Verify all connections are closed
	if wsm.GetConnectionCount() != 0 {
		t.Error("should have 0 connections after CloseAll")
	}

	// Verify underlying connections are closed
	if !conn1.IsClosed() || !conn2.IsClosed() || !conn3.IsClosed() {
		t.Error("all underlying connections should be closed")
	}
}

// TestWebSocketManagerConcurrency tests concurrent operations
func TestWebSocketManagerConcurrency(t *testing.T) {
	wsm := NewWebSocketManager()
	const numGoroutines = 10
	const numOperations = 100

	var wg sync.WaitGroup

	// Start multiple goroutines performing operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			connID := fmt.Sprintf("conn-%d", id)

			for j := 0; j < numOperations; j++ {
				// Add connection
				wsm.AddConnection(connID, newMockConn())

				// Update activity
				wsm.UpdateActivity(connID)

				// Get connection
				_, _ = wsm.GetConnection(connID)

				// Get stats
				_, _, _ = wsm.GetStats()

				// Remove connection
				wsm.RemoveConnection(connID)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify final state
	if wsm.GetConnectionCount() != 0 {
		t.Error("all connections should be removed after concurrent test")
	}

	// Clean up any remaining connections
	wsm.CloseAll()
}

// TestWebSocketConnectionHealthMonitoring tests the health monitoring goroutine
func TestWebSocketConnectionHealthMonitoring(t *testing.T) {
	conn := newMockConn()
	wsc := NewWebSocketConnection(conn)

	// Set a very old activity time to trigger health monitoring
	veryOldTime := time.Now().Add(-10 * time.Minute)
	wsc.mu.Lock()
	wsc.lastActivity = veryOldTime
	wsc.mu.Unlock()

	// The health monitor should eventually close the connection
	// We'll give it some time to detect the unhealthy state
	time.Sleep(100 * time.Millisecond)

	// Check if connection was marked as unhealthy
	if wsc.IsHealthy() {
		t.Error("connection with very old activity should be unhealthy")
	}

	// Clean up
	wsc.Close()
}

// BenchmarkWebSocketManagerOperations benchmarks WebSocket manager operations
func BenchmarkWebSocketManagerOperations(b *testing.B) {
	wsm := NewWebSocketManager()
	defer wsm.CloseAll()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("conn-%d", i%1000) // Reuse IDs to avoid memory growth

		// Add connection
		wsm.AddConnection(id, newMockConn())

		// Update activity
		wsm.UpdateActivity(id)

		// Get connection
		_, _ = wsm.GetConnection(id)

		// Remove connection
		wsm.RemoveConnection(id)
	}
}

// BenchmarkWebSocketConnectionActivity benchmarks activity updates
func BenchmarkWebSocketConnectionActivity(b *testing.B) {
	conn := newMockConn()
	wsc := NewWebSocketConnection(conn)
	defer wsc.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wsc.UpdateActivity()
	}
}
