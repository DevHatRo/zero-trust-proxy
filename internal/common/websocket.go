package common

import (
	"net"
	"sync"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/logger"
)

// WebSocketConnection represents an active WebSocket connection with health monitoring
type WebSocketConnection struct {
	conn         net.Conn
	lastActivity time.Time
	healthTicker *time.Ticker
	done         chan bool
	mu           sync.RWMutex
}

// NewWebSocketConnection creates a new WebSocket connection with health monitoring
func NewWebSocketConnection(conn net.Conn) *WebSocketConnection {
	wsc := &WebSocketConnection{
		conn:         conn,
		lastActivity: time.Now(),
		done:         make(chan bool, 2),
	}

	// Start health monitoring (health check every 60 seconds)
	wsc.startHealthMonitoring()

	return wsc
}

// UpdateActivity updates the last activity timestamp
func (wsc *WebSocketConnection) UpdateActivity() {
	wsc.mu.Lock()
	wsc.lastActivity = time.Now()
	wsc.mu.Unlock()
}

// IsHealthy checks if connection is healthy (activity within last 5 minutes)
func (wsc *WebSocketConnection) IsHealthy() bool {
	wsc.mu.RLock()
	defer wsc.mu.RUnlock()
	return time.Since(wsc.lastActivity) < 5*time.Minute
}

// Close closes the WebSocket connection and stops health monitoring
func (wsc *WebSocketConnection) Close() {
	if wsc.healthTicker != nil {
		wsc.healthTicker.Stop()
	}

	// Signal goroutines to stop
	select {
	case wsc.done <- true:
	default:
	}

	if wsc.conn != nil {
		wsc.conn.Close()
	}
}

// GetLastActivity returns the last activity time (for external monitoring)
func (wsc *WebSocketConnection) GetLastActivity() time.Time {
	wsc.mu.RLock()
	defer wsc.mu.RUnlock()
	return wsc.lastActivity
}

// GetConn returns the underlying connection (for writing frames)
func (wsc *WebSocketConnection) GetConn() net.Conn {
	return wsc.conn
}

// startHealthMonitoring starts WebSocket health monitoring
func (wsc *WebSocketConnection) startHealthMonitoring() {
	// Health check every 60 seconds to detect truly stale connections
	wsc.healthTicker = time.NewTicker(60 * time.Second)

	go func() {
		for {
			select {
			case <-wsc.healthTicker.C:
				// Check connection health without sending ping frames
				wsc.mu.RLock()
				lastActivity := wsc.lastActivity
				wsc.mu.RUnlock()

				timeSinceActivity := time.Since(lastActivity)
				isHealthy := wsc.IsHealthy()

				if !isHealthy {
					logger.Info("💀 WebSocket connection unhealthy (last activity: %v), closing",
						timeSinceActivity.Round(time.Second))
					wsc.Close()
					return
				} else {
					logger.Debug("✅ WebSocket health check passed (last activity: %v)",
						timeSinceActivity.Round(time.Second))
				}

			case <-wsc.done:
				logger.Debug("🛑 WebSocket health monitoring stopped")
				return
			}
		}
	}()
}

// WebSocketManager manages multiple WebSocket connections
type WebSocketManager struct {
	connections map[string]*WebSocketConnection
	mu          sync.RWMutex
}

// NewWebSocketManager creates a new WebSocket connection manager
func NewWebSocketManager() *WebSocketManager {
	return &WebSocketManager{
		connections: make(map[string]*WebSocketConnection),
	}
}

// AddConnection adds a WebSocket connection
func (wsm *WebSocketManager) AddConnection(id string, conn net.Conn) {
	wsm.mu.Lock()
	defer wsm.mu.Unlock()
	wsm.connections[id] = NewWebSocketConnection(conn)
}

// RemoveConnection removes a WebSocket connection
func (wsm *WebSocketManager) RemoveConnection(id string) {
	wsm.mu.Lock()
	defer wsm.mu.Unlock()
	if wsc, exists := wsm.connections[id]; exists {
		wsc.Close()
		delete(wsm.connections, id)
	}
}

// UpdateActivity updates activity for a connection
func (wsm *WebSocketManager) UpdateActivity(id string) {
	wsm.mu.RLock()
	if wsc, exists := wsm.connections[id]; exists {
		wsc.UpdateActivity()
	}
	wsm.mu.RUnlock()
}

// GetConnection returns a WebSocket connection by ID
func (wsm *WebSocketManager) GetConnection(id string) (*WebSocketConnection, bool) {
	wsm.mu.RLock()
	defer wsm.mu.RUnlock()
	wsc, exists := wsm.connections[id]
	return wsc, exists
}

// GetConnectionCount returns the total number of connections
func (wsm *WebSocketManager) GetConnectionCount() int {
	wsm.mu.RLock()
	defer wsm.mu.RUnlock()
	return len(wsm.connections)
}

// CleanupStaleConnections removes unhealthy connections
func (wsm *WebSocketManager) CleanupStaleConnections() int {
	wsm.mu.Lock()
	defer wsm.mu.Unlock()

	staleConnections := make([]string, 0)
	healthyCount := 0

	for id, wsc := range wsm.connections {
		if wsc == nil || wsc.conn == nil {
			staleConnections = append(staleConnections, id)
			continue
		}

		if !wsc.IsHealthy() {
			lastActivity := time.Since(wsc.GetLastActivity())
			staleConnections = append(staleConnections, id)
			logger.Info("💀 Marking unhealthy connection for cleanup: ID=%s, LastActivity=%v",
				id[:min(8, len(id))]+"...", lastActivity.Round(time.Second))
			wsc.Close()
		} else {
			healthyCount++
		}
	}

	// Remove stale connections
	for _, id := range staleConnections {
		delete(wsm.connections, id)
	}

	if len(staleConnections) > 0 {
		totalBefore := len(wsm.connections) + len(staleConnections)
		logger.Info("🧹 WebSocket cleanup: Removed=%d, Healthy=%d, Total=%d→%d",
			len(staleConnections), healthyCount, totalBefore, len(wsm.connections))
	}

	return len(staleConnections)
}

// GetStats returns connection statistics
func (wsm *WebSocketManager) GetStats() (total, healthy, stale int) {
	wsm.mu.RLock()
	defer wsm.mu.RUnlock()

	total = len(wsm.connections)
	for _, wsc := range wsm.connections {
		if wsc.IsHealthy() {
			healthy++
		} else {
			stale++
		}
	}

	return total, healthy, stale
}

// CloseAll closes all WebSocket connections
func (wsm *WebSocketManager) CloseAll() {
	wsm.mu.Lock()
	defer wsm.mu.Unlock()

	logger.Info("🧹 Closing all %d WebSocket connections", len(wsm.connections))

	for id, wsc := range wsm.connections {
		if wsc != nil {
			wsc.Close()
			logger.Debug("🗑️  Closed WebSocket connection: ID=%s", id[:min(8, len(id))]+"...")
		}
	}

	wsm.connections = make(map[string]*WebSocketConnection)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
