package agent

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"bytes"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/logger"
	"github.com/devhatro/zero-trust-proxy/internal/types"
)

// Component-specific logger for agent
var log = logger.WithComponent("agent")

// Message types
const (
	MessageTypePing  = "ping"
	MessageTypePong  = "pong"
	MessageTypeProxy = "proxy"
)

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseAddress parses an address and returns host, port, and protocol information
func parseAddress(addr string) (host, port, protocol string) {
	// Remove protocol prefix if present
	if strings.HasPrefix(addr, "https://") {
		protocol = "https"
		addr = strings.TrimPrefix(addr, "https://")
	} else if strings.HasPrefix(addr, "http://") {
		protocol = "http"
		addr = strings.TrimPrefix(addr, "http://")
	} else if strings.HasPrefix(addr, "wss://") {
		protocol = "wss"
		addr = strings.TrimPrefix(addr, "wss://")
	} else if strings.HasPrefix(addr, "ws://") {
		protocol = "ws"
		addr = strings.TrimPrefix(addr, "ws://")
	}

	// Split host and port
	if strings.Contains(addr, ":") {
		parts := strings.Split(addr, ":")
		if len(parts) >= 2 {
			host = parts[0]
			port = parts[1]
		}
	} else {
		host = addr
		// Don't assume default ports - let the caller decide
	}

	return host, port, protocol
}

// needsTLS determines if TLS should be used based on service config and address
func needsTLS(service *common.ServiceConfig, backendAddr string) bool {
	// Priority 1: Service protocol setting (most reliable)
	if service.Protocol == "https" || service.Protocol == "wss" {
		return true
	}

	// Priority 2: Explicit protocol in backend address
	_, _, protocol := parseAddress(backendAddr)
	if protocol == "https" || protocol == "wss" {
		return true
	}

	// Priority 3: Service protocol is unset but backend has secure protocol prefix
	if service.Protocol == "" {
		if strings.HasPrefix(backendAddr, "https://") || strings.HasPrefix(backendAddr, "wss://") {
			return true
		}
	}

	return false
}

// getHealthCheckScheme determines the HTTP scheme for health checks
func getHealthCheckScheme(service *ServiceConfig, upstreamAddr string) string {
	// Priority 1: Service protocol setting
	if service.Protocol == "https" {
		return "https"
	}

	// Priority 2: Explicit protocol in upstream address
	_, _, protocol := parseAddress(upstreamAddr)
	if protocol == "https" || protocol == "wss" {
		return "https"
	}

	// Priority 3: Check if upstream has secure protocol prefix
	if strings.HasPrefix(upstreamAddr, "https://") || strings.HasPrefix(upstreamAddr, "wss://") {
		return "https"
	}

	// Default to HTTP
	return "http"
}

// Message represents a message between agent and server
type Message struct {
	Type    string `json:"type"`
	AgentID string `json:"agent_id"`
}

// Agent represents an agent instance
type Agent struct {
	id          string
	serverAddr  string
	certFile    string
	keyFile     string
	caFile      string
	serviceAddr string
	conn        net.Conn
	encoder     *json.Encoder
	decoder     *json.Decoder
	writeMu     sync.Mutex // Protects concurrent writes to connection
	readMu      sync.Mutex // Protects concurrent reads from connection
	registered  bool
	services    map[string]*common.ServiceConfig
	mu          sync.RWMutex
	lastPong    time.Time
	tlsConfig   *tls.Config
	// Message channels
	registerCh    chan *common.Message
	httpRespCh    chan *common.Message
	pongCh        chan *common.Message
	serviceRespCh chan *common.Message
	// Channel pressure tracking
	channelPressure map[string]int
	pressureMu      sync.RWMutex
	config          *AgentConfig
	// WebSocket connections tracking with health monitoring
	wsManager *common.WebSocketManager
	// Connection state management
	connectionBroken chan struct{} // Signals when main connection is broken
	connectionMu     sync.RWMutex
	// Global reconnection coordination
	reconnectInProgress bool
	reconnectMu         sync.Mutex
	// Hot reload management
	hotReloadManager *common.HotReloadManager
	// Caddy configuration validation
	caddyValidator types.ServiceValidator
}

// Config holds the agent configuration
type Config struct {
	ServerAddr  string
	CertFile    string
	KeyFile     string
	CAFile      string
	ID          string
	ServiceAddr string
}

// NewAgent creates a new agent instance
func NewAgent(id, serverAddress string, tlsConfig *tls.Config, validator types.ServiceValidator) *Agent {
	return &Agent{
		id:                  id,
		serverAddr:          serverAddress,
		tlsConfig:           tlsConfig,
		services:            make(map[string]*common.ServiceConfig),
		conn:                nil,
		registered:          false,
		reconnectInProgress: false,
		reconnectMu:         sync.Mutex{},
		hotReloadManager:    common.NewHotReloadManager(),
		caddyValidator:      validator,
	}
}

// NewAgentWithConfig creates a new agent instance using configuration struct
func NewAgentWithConfig(config *AgentConfig, tlsConfig *tls.Config, validator types.ServiceValidator) *Agent {
	agent := &Agent{
		id:                  config.Agent.ID,
		serverAddr:          config.Server.Address,
		certFile:            config.Server.Cert,
		keyFile:             config.Server.Key,
		caFile:              config.Server.CACert,
		tlsConfig:           tlsConfig,
		config:              config,
		services:            make(map[string]*common.ServiceConfig),
		lastPong:            time.Now(),
		registerCh:          make(chan *common.Message, 10),
		httpRespCh:          make(chan *common.Message, 1000),
		pongCh:              make(chan *common.Message, 500),
		serviceRespCh:       make(chan *common.Message, 500),
		channelPressure:     make(map[string]int),
		wsManager:           common.NewWebSocketManager(),
		pressureMu:          sync.RWMutex{},
		connectionBroken:    make(chan struct{}, 1),
		connectionMu:        sync.RWMutex{},
		reconnectInProgress: false,
		reconnectMu:         sync.Mutex{},
		hotReloadManager:    common.NewHotReloadManager(),
		caddyValidator:      validator,
	}

	// Apply logging configuration from config
	applyLoggingConfig(config.Logging)

	// Store config path in config object for hot reload
	config.ConfigPath = config.ConfigPath

	return agent
}

// applyLoggingConfig applies the logging configuration to the logger package
func applyLoggingConfig(config LoggingConfig) {
	// Set log level
	if config.Level != "" {
		logger.SetLogLevel(config.Level)
	}

	// Set format
	if config.Format != "" {
		logger.SetFormat(config.Format)
	}

	// Note: Output redirection to files would require more complex implementation
	// For now, we support stdout/stderr via the default logger output
	if config.Output != "" && config.Output != "stdout" && config.Output != "stderr" {
		log.Warn("File output for application logging not yet implemented, using stdout")
	}
}

// convertCommonToTypes converts common.ServiceConfig to types.ServiceConfig
func convertCommonToTypes(config *common.ServiceConfig) *types.ServiceConfig {
	return &types.ServiceConfig{
		Hostname:     config.Hostname,
		Backend:      config.Backend,
		Protocol:     config.Protocol,
		WebSocket:    config.WebSocket,
		HTTPRedirect: config.HTTPRedirect,
		ListenOn:     config.ListenOn,
	}
}

// convertTypesToCommon converts types.ServiceConfig to common.ServiceConfig
func convertTypesToCommon(config *types.ServiceConfig) *common.ServiceConfig {
	return &common.ServiceConfig{
		ServiceConfig: *config,
	}
}

// Connect establishes a connection to the server
func (a *Agent) Connect() error {
	log.Info("🔌 Connecting to server at %s", a.serverAddr)

	// Reset connection state for new connection
	a.resetConnectionState()

	// Connect to server
	conn, err := tls.Dial("tcp", a.serverAddr, a.tlsConfig)
	if err != nil {
		return fmt.Errorf("❌ failed to connect to server: %v", err)
	}

	a.conn = conn
	a.encoder = json.NewEncoder(conn)
	a.decoder = json.NewDecoder(conn)

	log.Info("🔌 Connected to server at %s", a.serverAddr)

	// Start message handling goroutine
	go a.handleMessages()

	// Register with server
	registerMsg := &common.Message{
		Type: "register",
		ID:   a.id,
	}

	log.Info("📋 Registering agent with server...")
	if err := a.SendMessage(registerMsg); err != nil {
		// Clean up connection on registration failure with proper locking
		a.writeMu.Lock()
		a.readMu.Lock()
		a.conn.Close()
		a.conn = nil
		a.encoder = nil
		a.decoder = nil
		a.readMu.Unlock()
		a.writeMu.Unlock()
		return fmt.Errorf("❌ failed to send registration message: %v", err)
	}

	// Wait for registration acknowledgment
	select {
	case <-a.registerCh:
		log.Info("✅ Successfully registered with server")
		// Initialize last successful heartbeat timestamp for successful connection
		a.mu.Lock()
		a.lastPong = time.Now()
		a.mu.Unlock()
	case <-time.After(10 * time.Second):
		// Clean up connection on timeout with proper locking
		a.writeMu.Lock()
		a.readMu.Lock()
		a.conn.Close()
		a.conn = nil
		a.encoder = nil
		a.decoder = nil
		a.readMu.Unlock()
		a.writeMu.Unlock()
		return fmt.Errorf("⏰ timeout waiting for registration acknowledgment")
	}

	return nil
}

// handleMessages handles incoming messages from the server
func (a *Agent) handleMessages() {
	defer func() {
		// Recover from any panics to prevent crashing the entire application
		if r := recover(); r != nil {
			log.Error("🚨 Panic in message handler: %v", r)
			// Trigger reconnection after panic
			a.signalConnectionBroken()
			a.cleanupAllWebSocketConnections()
			a.mu.Lock()
			a.registered = false
			a.mu.Unlock()
			a.attemptReconnection("message-handler-panic")
		}
		log.Debug("🛑 Message handler exiting")
	}()

	for {
		var msg common.Message

		// Lock to prevent concurrent reads from the TLS connection
		a.readMu.Lock()

		// Check if decoder is nil before attempting to use it
		if a.decoder == nil {
			a.readMu.Unlock()
			log.Debug("🔌 Decoder is nil, connection likely closed - exiting message handler")
			return
		}

		err := a.decoder.Decode(&msg)
		a.readMu.Unlock()

		if err != nil {
			if err == io.EOF {
				log.Error("💔 Connection closed by server")

				// Signal connection broken and clean up
				a.signalConnectionBroken()
				a.cleanupAllWebSocketConnections()

				// Mark as unregistered and clean up connection state
				a.mu.Lock()
				a.registered = false
				a.mu.Unlock()

				// Trigger coordinated reconnection
				a.attemptReconnection("connection-close")

				return
			}

			// Check for other connection-related errors
			if strings.Contains(err.Error(), "broken pipe") ||
				strings.Contains(err.Error(), "connection reset") ||
				strings.Contains(err.Error(), "connection refused") ||
				strings.Contains(err.Error(), "use of closed network connection") {
				log.Error("💔 Connection broken: %v", err)

				// Signal connection broken and clean up
				a.signalConnectionBroken()
				a.cleanupAllWebSocketConnections()

				// Mark as unregistered and clean up connection state
				a.mu.Lock()
				a.registered = false
				a.mu.Unlock()

				// Trigger coordinated reconnection
				a.attemptReconnection("connection-error")

				return
			}

			log.Error("❌ Failed to decode message: %v", err)
			continue
		}

		// Handle message based on type
		switch msg.Type {
		case "register_response":
			a.mu.Lock()
			a.registered = true
			a.mu.Unlock()
			// Use adaptive timeout based on channel pressure
			timeout := a.getAdaptiveTimeout("register", 5*time.Second)
			select {
			case a.registerCh <- &msg:
				log.Debug("📨 Register response sent to channel, buffer usage: %d/%d", len(a.registerCh), cap(a.registerCh))
				a.trackChannelPressure("register", true)
			case <-time.After(timeout):
				log.Error("⚠️  Timeout sending register response to channel, buffer full: %d/%d", len(a.registerCh), cap(a.registerCh))
				a.trackChannelPressure("register", false)
			}
		case "pong":
			a.mu.Lock()
			a.lastPong = time.Now()
			a.mu.Unlock()
			// Use adaptive timeout based on channel pressure
			timeout := a.getAdaptiveTimeout("pong", 5*time.Second)
			select {
			case a.pongCh <- &msg:
				if len(a.pongCh) > cap(a.pongCh)*3/4 { // Log when 75% full
					log.Debug("📈 Pong channel usage high: %d/%d", len(a.pongCh), cap(a.pongCh))
				}
				a.trackChannelPressure("pong", true)
			case <-time.After(timeout):
				log.Error("⚠️  Timeout sending pong to channel, buffer full: %d/%d", len(a.pongCh), cap(a.pongCh))
				a.trackChannelPressure("pong", false)
			}
		case "service_add_response", "service_update_response", "service_remove_response":
			// Use adaptive timeout based on channel pressure
			timeout := a.getAdaptiveTimeout("service", 10*time.Second)
			select {
			case a.serviceRespCh <- &msg:
				if len(a.serviceRespCh) > cap(a.serviceRespCh)*3/4 { // Log when 75% full
					log.Debug("📈 Service response channel usage high: %d/%d", len(a.serviceRespCh), cap(a.serviceRespCh))
				}
				a.trackChannelPressure("service", true)
			case <-time.After(timeout):
				log.Error("⚠️  Timeout sending service response to channel, buffer full: %d/%d", len(a.serviceRespCh), cap(a.serviceRespCh))
				a.trackChannelPressure("service", false)
			}
		case "http_response_ack":
			// Acknowledgments are no longer used - ignore
		case "http_request":
			go a.handleHTTPRequest(&msg)
		case "ping":
			// Send pong response
			pong := &common.Message{
				Type: "pong",
				ID:   msg.ID,
			}
			if err := a.SendMessage(pong); err != nil {
				log.Error("❌ Failed to send pong response: %v", err)
			}
		case "websocket_frame":
			// Handle WebSocket frame from client to backend
			go a.handleWebSocketFrame(&msg)
		case "websocket_disconnect":
			// Handle notification that client disconnected from server
			go a.handleWebSocketDisconnect(&msg)
		default:
			log.Error("❓ Unknown message type: %s", msg.Type)
		}
	}
}

// handleHTTPRequest handles an HTTP request from the server
func (a *Agent) handleHTTPRequest(msg *common.Message) {
	if msg.HTTP == nil {
		log.Error("❌ Received HTTP request without HTTP data")
		return
	}

	// Check if we have a connection to send responses
	if a.conn == nil {
		log.Warn("⚠️  Received HTTP request but no server connection - triggering reconnection")
		a.attemptReconnection("http-request-no-connection")
		return
	}

	// Extract host from headers
	host := msg.HTTP.Headers["Host"][0]
	log.Info("🌐 Handling HTTP request for host: [%s]", host)

	// Find service configuration
	a.mu.RLock()
	service, ok := a.services[host]
	a.mu.RUnlock()

	if !ok {
		log.Error("❌ No service configuration found for host: %s", host)
		return
	}

	// Check if this is a WebSocket upgrade request
	isWebSocketUpgrade := a.isWebSocketUpgrade(msg.HTTP.Headers)
	if isWebSocketUpgrade {
		log.Info("🔌 Detected WebSocket upgrade request for host: %s - using raw TCP relay approach", host)

		// Debug: Log all headers received from client
		log.Debug("🔍 Headers received from client for WebSocket upgrade:")
		for key, values := range msg.HTTP.Headers {
			for _, value := range values {
				log.Debug("  📋 %s: %s", key, value)
			}
		}

		a.handleWebSocketConnection(msg, service)
		return
	}

	// Create HTTP request to local service with proper protocol handling
	var url string
	backend := service.Backend

	// Check if backend already includes protocol
	hasProtocol := strings.HasPrefix(backend, "http://") ||
		strings.HasPrefix(backend, "https://") ||
		strings.HasPrefix(backend, "ws://") ||
		strings.HasPrefix(backend, "wss://")

	if hasProtocol {
		// Backend already has protocol, use as-is
		url = fmt.Sprintf("%s%s", backend, msg.HTTP.URL)
		log.Debug("🔗 Backend includes protocol, using as-is: %s", backend)
	} else {
		// Backend doesn't have protocol, determine from service config or default to http
		protocol := "http"
		if service.Protocol == "https" {
			protocol = "https"
		}
		url = fmt.Sprintf("%s://%s%s", protocol, backend, msg.HTTP.URL)
		log.Debug("🔗 Backend without protocol, using service protocol '%s': %s", protocol, backend)
	}

	log.Debug("📤 Forwarding request to local service: %s", url)
	log.Debug("🏠 Original Host header: %s, Backend: %s", host, service.Backend)

	// Create HTTP request to the backend service
	req, err := http.NewRequest(msg.HTTP.Method, url, bytes.NewReader(msg.HTTP.Body))
	if err != nil {
		log.Error("❌ Failed to create request: %v", err)
		return
	}

	// Copy headers
	for key, values := range msg.HTTP.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Add standard reverse proxy headers (like Caddy, Nginx, HAProxy, etc.)
	originalHost := req.Header.Get("Host")

	// CRITICAL FIX: Go's http.NewRequest sets req.Host to the URL host (traefik:80)
	// We MUST explicitly set req.Host to the original host for proper routing
	if originalHost != "" {
		req.Host = originalHost // This is the key fix!
		log.Info("✅ FIXED: Set req.Host to original host: %s (was: %s)", originalHost, req.URL.Host)
	} else {
		log.Warn("⚠️  No original Host header found - this might cause routing issues")
	}

	// Configure reverse proxy headers

	// Add X-Forwarded-Host (the original host the client requested)
	if originalHost != "" {
		req.Header.Set("X-Forwarded-Host", originalHost)
	}

	// Add X-Forwarded-Proto (the original protocol - HTTPS since it came through Caddy)
	req.Header.Set("X-Forwarded-Proto", "https")

	// Extract client IP from the headers that Caddy set
	clientIP := ""

	// Try to get the real client IP from X-Forwarded-For (set by Caddy)
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can be "ip1, ip2, ip3" - take the first (original client)
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			clientIP = strings.TrimSpace(parts[0])
		}
	}

	// If no X-Forwarded-For, try X-Real-IP (though this might have placeholder text)
	if clientIP == "" {
		if xRealIP := req.Header.Get("X-Real-IP"); xRealIP != "" && !strings.Contains(xRealIP, "{") {
			clientIP = xRealIP
		}
	}

	// Set the proper X-Real-IP and X-Forwarded-For headers for the backend
	if clientIP != "" {
		// Set X-Real-IP to the actual client IP
		req.Header.Set("X-Real-IP", clientIP)

		// Build X-Forwarded-For chain: client -> agent
		req.Header.Set("X-Forwarded-For", clientIP)
		log.Debug("🌍 Set client IP headers: X-Real-IP=%s, X-Forwarded-For=%s", clientIP, clientIP)
	} else {
		log.Warn("⚠️  Could not determine client IP from headers")
	}

	// Add X-Forwarded-Server (this agent's identifier)
	req.Header.Set("X-Forwarded-Server", fmt.Sprintf("zero-trust-agent-%s", a.id))

	// Log the routing information
	log.Info("🚀 Request routing: URL=%s, Host=%s, Backend=%s", url, originalHost, service.Backend)
	log.Info("🔧 Added reverse proxy headers: X-Forwarded-Host=%s, X-Forwarded-Proto=https", originalHost)

	// Debug: Show all headers being sent to backend
	log.Debug("📋 Headers being sent to backend:")
	for key, values := range req.Header {
		log.Debug("  📎 %s: %v", key, values)
	}

	// Determine if this might be a streaming operation based on request characteristics
	// Use a simple heuristic: if Range header is present, it's likely a large file
	rangeHeader := req.Header.Get("Range")
	mightBeStream := rangeHeader != ""

	// Create HTTP client with activity-based timeout (no total timeout limit)
	var client *http.Client

	// Check if this is an HTTPS request to determine if we need custom TLS config
	isHTTPS := strings.HasPrefix(url, "https://")

	// Create transport with optional TLS certificate verification skipping
	transport := &http.Transport{}
	if isHTTPS {
		// For HTTPS requests, create custom TLS config
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // Skip certificate verification for internal services
		}
		transport.TLSClientConfig = tlsConfig
		log.Debug("🔒 HTTPS request detected - configured to skip certificate verification for internal service")
	}

	// Always use unlimited timeout and let the actual response characteristics decide streaming
	client = &http.Client{
		Timeout:   0, // No timeout - handled dynamically by activity detection
		Transport: transport,
	}

	if mightBeStream {
		log.Debug("📡 Range request detected - likely large file transfer")
	} else {
		log.Debug("⏱️  Using unlimited timeout with activity-based detection")
	}

	// Make the request with appropriate timeout
	resp, err := client.Do(req)
	if err != nil {
		log.Error("❌ Failed to forward request: %v", err)
		return
	}

	// Log the agent's IP for trusted proxy configuration
	if req.URL.Host != "" {
		// Get the local IP that would be used to connect to this backend
		if conn, err := net.Dial("tcp", req.URL.Host); err == nil {
			agentIP := conn.LocalAddr().(*net.TCPAddr).IP.String()
			conn.Close()
			log.Info("🔧 AGENT IP: %s (connecting to %s) ", agentIP, req.URL.Host)
		}
	}
	defer resp.Body.Close()

	// Now check actual response characteristics for streaming decision
	contentLength := resp.ContentLength
	contentType := resp.Header.Get("Content-Type")

	// Debug logging for API responses
	log.Debug("📊 Response details: URL=%s, ContentLength=%d, ContentType=%s, Status=%d",
		req.URL.Path, contentLength, contentType, resp.StatusCode)

	// If we underestimated and this is actually a large file, log it
	if !mightBeStream && (contentLength > 1024*1024) {
		log.Debug("📈 Large response detected (%d bytes) - consider extending timeout for this URL pattern", contentLength)
	}

	// Stream if content is large (>1MB) - content type doesn't matter with robust timeout system
	shouldStream := contentLength > 1024*1024

	log.Debug("🎯 Streaming decision: shouldStream=%t, contentLength=%d, contentType=%s",
		shouldStream, contentLength, contentType)

	if shouldStream {
		log.Debug("📡 Streaming response for large file, reported size: %d bytes", contentLength)

		// Handle unknown content length
		if contentLength <= 0 {
			contentLength = -1 // Normalize unknown size
			log.Debug("❓ Content length unknown, will determine actual size during streaming")
		}

		// Detect WebSocket upgrade response for streaming
		isWebSocketUpgrade := resp.StatusCode == 101
		if isWebSocketUpgrade {
			log.Info("✅ WebSocket upgrade response detected (101) for streaming host: %s", host)
		}

		// Create timeout configuration for streaming operations
		timeoutConfig := common.DefaultTimeouts()

		// Send initial response with streaming info
		initialMsg := &common.Message{
			Type: "http_response",
			ID:   msg.ID,
			HTTP: &common.HTTPData{
				StatusCode:    resp.StatusCode,
				StatusMessage: resp.Status,
				Headers:       resp.Header,
				IsStream:      true,
				IsWebSocket:   isWebSocketUpgrade, // Mark WebSocket upgrade responses
				ChunkSize:     32768,              // 32KB chunks
				TotalSize:     contentLength,      // Will be updated if actual size differs
				ChunkIndex:    0,
				IsLastChunk:   false,
			},
		}

		if err := a.SendMessage(initialMsg); err != nil {
			log.Error("❌ Failed to send initial streaming response: %v", err)
			return
		}

		log.Info("🚀 Started streaming response for request ID: %s", msg.ID)

		// Stream the response body in chunks with dynamic timeouts
		buffer := make([]byte, 32768) // 32KB buffer
		chunkIndex := 0
		totalSent := int64(0)

		actualTotalSize := contentLength // Track actual size, may differ from Content-Length header
		lastProgressLog := time.Now()
		lastActivityTime := time.Now() // Track last activity for timeout detection
		startTime := time.Now()

		for {
			// Get dynamic timeout based on current transfer performance
			dynamicTimeout := common.CalculateStreamingTimeout(contentLength, totalSent, timeoutConfig)

			// Don't set read deadline during active streaming
			// Instead, detect activity timeout after the read attempt
			// This prevents "context deadline exceeded" errors during active transfers

			n, err := resp.Body.Read(buffer)
			currentTime := time.Now()

			if n > 0 {
				// Activity detected - reset activity timer
				lastActivityTime = currentTime
				chunkIndex++
				totalSent += int64(n)

				// Activity detected - used in timeout calculation

				// EOF is the primary indicator of completion, not byte count
				isLastChunk := (err == io.EOF)

				// Update actual total size if we've read more than expected
				if totalSent > actualTotalSize {
					actualTotalSize = totalSent
				}

				chunkMsg := &common.Message{
					Type: "http_response",
					ID:   msg.ID,
					HTTP: &common.HTTPData{
						Body:        buffer[:n],
						IsStream:    true,
						ChunkSize:   n,
						TotalSize:   actualTotalSize,
						ChunkIndex:  chunkIndex,
						IsLastChunk: isLastChunk,
					},
				}

				if err := a.SendMessage(chunkMsg); err != nil {
					log.Error("❌ Failed to send chunk %d: %v", chunkIndex, err)
					return
				}

				// Progress logging with transfer rate and ETA
				if time.Since(lastProgressLog) > 5*time.Second || isLastChunk {
					elapsed := time.Since(startTime)
					var progress float64
					if contentLength > 0 {
						progress = float64(totalSent) / float64(contentLength) * 100
					}
					log.Info("📊 Transfer progress: %.1f%% (%d/%d bytes), elapsed: %v, timeout: %v",
						progress, totalSent, actualTotalSize, elapsed.Round(time.Second),
						dynamicTimeout.Round(time.Second))
					lastProgressLog = time.Now()
				}

				if isLastChunk {
					// Log if actual size differs from reported size
					if totalSent != contentLength {
						log.Info("📏 Streaming complete - actual size (%d bytes) differs from reported size (%d bytes)", totalSent, contentLength)
					}
					log.Info("✅ Streaming complete for request ID: %s, total chunks: %d, actual size: %d bytes, transfer time: %v",
						msg.ID, chunkIndex, totalSent, time.Since(startTime).Round(time.Second))
					break
				}
			}

			if err == io.EOF {
				// Handle EOF without data read in this iteration
				if n == 0 {
					log.Debug("🔚 Reached EOF, streaming complete for request ID: %s", msg.ID)
					break
				}
			} else if err != nil {
				// Check for timeout based on activity, not read deadline

				timeSinceActivity := currentTime.Sub(lastActivityTime)
				if timeSinceActivity > dynamicTimeout {
					log.Error("⏰ Activity timeout exceeded (%.1fs since last data) during streaming: %v",
						timeSinceActivity.Seconds(), err)
				} else {
					log.Error("❌ Error reading response body: %v", err)
				}
				return
			}

			// Activity-based timeout detection
			// Only timeout if no activity for longer than dynamic timeout
			timeSinceActivity := currentTime.Sub(lastActivityTime)
			if timeSinceActivity > dynamicTimeout {
				log.Error("💀 No activity for %.1fs (timeout: %.1fs) - connection appears dead",
					timeSinceActivity.Seconds(), dynamicTimeout.Seconds())
				return
			}
		}

		// Final completion log with statistics
		elapsed := time.Since(startTime)
		avgSpeed := float64(totalSent) / elapsed.Seconds() / (1024 * 1024) // MB/s
		log.Info("🏁 Stream completed: %d bytes in %v (%.2f MB/s avg)", totalSent, elapsed.Round(time.Second), avgSpeed)
	} else {
		// For small files, read everything into memory (original behavior)
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error("❌ Failed to read response body: %v", err)
			return
		}

		// Note: WebSocket upgrade responses (101) should not occur here since
		// WebSocket connections are now handled by handleWebSocketConnection()
		// at the beginning of the request flow. This ensures proper TCP-level relay.

		// For regular HTTP responses, continue with normal handling
		// Create response message
		responseMsg := &common.Message{
			Type: "http_response",
			ID:   msg.ID,
			HTTP: &common.HTTPData{
				StatusCode:    resp.StatusCode,
				StatusMessage: resp.Status,
				Headers:       resp.Header,
				Body:          body,
				IsWebSocket:   false,
				IsStream:      false,
			},
		}

		// Send response to server
		if err := a.SendMessage(responseMsg); err != nil {
			log.Error("❌ Failed to send response: %v", err)
			return
		}

		log.Debug("✅ HTTP response sent successfully for request ID: %s", msg.ID)
	}
}

// handleWebSocketConnection handles WebSocket connections using raw TCP relay
func (a *Agent) handleWebSocketConnection(msg *common.Message, service *common.ServiceConfig) {
	host := msg.HTTP.Headers["Host"][0]
	log.Info("🔌 Starting WebSocket connection handler for %s", host)

	// Cleanup stale connections before creating new ones
	a.cleanupStaleConnections()

	// Debug: Log connection tracking info
	total, healthy, stale := a.wsManager.GetStats()
	activeConnections := total

	log.Debug("📊 WebSocket connection stats: Active=%d, Healthy=%d, Stale=%d, New ID=%s",
		activeConnections, healthy, stale, msg.ID[:8]+"...")

	// Add small delay for rapid reconnections (page refresh scenarios)
	// This helps prevent race conditions and allows proper cleanup
	if activeConnections > 0 {
		log.Debug("⏰ Multiple WebSocket connections detected, adding 500ms delay to prevent race conditions")
		time.Sleep(500 * time.Millisecond)

		// Cleanup again after delay to ensure proper state
		a.wsManager.CleanupStaleConnections()

		// Update connection count after cleanup
		activeConnections = a.wsManager.GetConnectionCount()
		log.Debug("📊 After cleanup delay: Active=%d connections", activeConnections)
	}

	// Extract backend address
	backend := service.Backend
	backendAddr := backend

	// Remove protocol prefix if present and determine the actual address
	if strings.HasPrefix(backend, "http://") {
		backendAddr = strings.TrimPrefix(backend, "http://")
	} else if strings.HasPrefix(backend, "https://") {
		backendAddr = strings.TrimPrefix(backend, "https://")
	} else if strings.HasPrefix(backend, "ws://") {
		backendAddr = strings.TrimPrefix(backend, "ws://")
	} else if strings.HasPrefix(backend, "wss://") {
		backendAddr = strings.TrimPrefix(backend, "wss://")
	}

	log.Info("🔗 Connecting to WebSocket backend: %s", backendAddr)

	// Determine if we need TLS based on the service protocol or backend address
	shouldUseTLS := needsTLS(service, backendAddr)

	var backendConn net.Conn
	var err error

	if shouldUseTLS {
		// Establish TLS connection for HTTPS/WSS backends
		log.Debug("🔒 Using TLS connection for HTTPS/WSS backend")
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,                               // Skip verification for backends (like curl -k)
			ServerName:         strings.Split(backendAddr, ":")[0], // Extract hostname
		}
		backendConn, err = tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", backendAddr, tlsConfig)
	} else {
		// Establish plain TCP connection for HTTP/WS backends
		log.Debug("🔓 Using plain TCP connection for HTTP/WS backend")
		backendConn, err = net.DialTimeout("tcp", backendAddr, 10*time.Second)
	}

	if err != nil {
		connType := "TCP"
		if shouldUseTLS {
			connType = "TLS"
		}
		log.Error("❌ Failed to connect to WebSocket backend %s using %s: %v", backendAddr, connType, err)
		// Send error response
		errorResponse := &common.Message{
			Type: "http_response",
			ID:   msg.ID,
			HTTP: &common.HTTPData{
				StatusCode:    502,
				StatusMessage: "Bad Gateway",
				Headers:       make(map[string][]string),
				Body:          []byte("Failed to connect to backend"),
				IsWebSocket:   false,
			},
		}
		a.SendMessage(errorResponse)
		return
	}
	defer backendConn.Close()

	log.Info("✅ Connected to WebSocket backend %s", backendAddr)

	// Build and send the HTTP upgrade request to backend
	upgradeRequest := a.buildWebSocketUpgradeRequest(msg)

	// Debug: Log the complete upgrade request being sent to backend
	log.Debug("📤 Sending WebSocket upgrade request to backend:")
	log.Debug("📄 --- Request Start ---")
	log.Debug("%s", upgradeRequest)
	log.Debug("📄 --- Request End ---")

	if _, err := backendConn.Write([]byte(upgradeRequest)); err != nil {
		log.Error("❌ Failed to send upgrade request to backend: %v", err)
		return
	}

	log.Debug("📤 Sent WebSocket upgrade request to backend")

	// Read the upgrade response from backend
	buffer := make([]byte, 4096)
	n, err := backendConn.Read(buffer)
	if err != nil {
		log.Error("❌ Failed to read upgrade response from backend: %v", err)
		return
	}

	response := string(buffer[:n])
	log.Info("📥 Backend WebSocket response: %s", strings.Split(response, "\r\n")[0])

	// Debug: Log the complete response for troubleshooting
	log.Debug("📥 Complete backend response:")
	log.Debug("📄 --- Response Start ---")
	log.Debug("%s", response)
	log.Debug("📄 --- Response End ---")

	// Check if upgrade was successful (101 status)
	if !strings.Contains(response, "101 Switching Protocols") {
		log.Error("❌ Backend rejected WebSocket upgrade: %s", strings.Split(response, "\r\n")[0])
		log.Error("🔍 This means the backend service doesn't support WebSockets or has an issue")
		// Forward the error response to client
		a.sendRawHTTPResponse(msg.ID, response)
		return
	}

	log.Info("🎉 WebSocket upgrade successful with backend %s", backendAddr)

	// Send the 101 response to client
	a.sendRawHTTPResponse(msg.ID, response)

	// Store the backend connection for frame relay
	a.wsManager.AddConnection(msg.ID, backendConn)
	totalConnections := a.wsManager.GetConnectionCount()

	log.Info("🔗 WebSocket connection established: ID=%s, Backend=%s, Total=%d",
		msg.ID[:8]+"...", backendAddr, totalConnections)

	// Start bidirectional relay between server and backend
	done := make(chan bool, 2)

	// Client to Backend relay is now handled by handleWebSocketFrame method
	// when the server sends us "websocket_frame" messages

	// Backend to Client relay - read from backend and send to client
	go func() {
		defer func() {
			// Clean up the stored connection
			a.wsManager.RemoveConnection(msg.ID)
			totalConnections := a.wsManager.GetConnectionCount()

			log.Info("🔌 WebSocket relay ended: ID=%s, Backend=%s, Remaining=%d",
				msg.ID[:8]+"...", backendAddr, totalConnections)
			done <- true
		}()
		log.Info("🔄 Starting backend→client relay: ID=%s, Backend=%s", msg.ID[:8]+"...", backendAddr)

		buffer := make([]byte, 16384) // 16KB buffer for better performance
		frameCount := 0

		for {
			// Check if main connection is broken before trying to read/send
			select {
			case <-a.connectionBroken:
				log.Info("🔌 Main connection broken, stopping WebSocket relay: ID=%s", msg.ID[:8]+"...")
				return
			default:
				// Continue with normal operation
			}

			// WebSocket connections should not have read timeouts, health is managed separately
			// This prevents "i/o timeout" errors that break legitimate long-lived connections

			n, err := backendConn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					// Check if this is due to main connection being broken
					if a.isConnectionBroken() {
						log.Debug("🔌 Backend read error due to main connection break: ID=%s", msg.ID[:8]+"...")
						return
					}

					// Log backend errors with reduced verbosity during network issues
					if strings.Contains(err.Error(), "use of closed network connection") {
						log.Debug("🔌 Backend connection closed: ID=%s", msg.ID[:8]+"...")
					} else if strings.Contains(err.Error(), "connection reset") {
						log.Debug("🔄 Backend reset connection: ID=%s (normal behavior)", msg.ID[:8]+"...")
					} else if strings.Contains(err.Error(), "broken pipe") {
						log.Debug("📞 Backend connection broken: ID=%s (client disconnected)", msg.ID[:8]+"...")
					} else {
						log.Error("❌ Backend read error for ID=%s: %v", msg.ID[:8]+"...", err)
					}
				} else {
					// Log more details for short-lived connections
					if frameCount < 10 {
						log.Warn("⚡ Backend closed WebSocket quickly: ID=%s, FrameCount=%d (may indicate auth/protocol issue)",
							msg.ID[:8]+"...", frameCount)
					} else {
						log.Debug("📡 Backend gracefully closed WebSocket: ID=%s, FrameCount=%d",
							msg.ID[:8]+"...", frameCount)
					}
				}
				break
			}

			if n > 0 {
				frameCount++

				// Update activity in our health monitoring system
				a.wsManager.UpdateActivity(msg.ID)

				// Log detailed frame info for debugging with protocol analysis
				if frameCount%10 == 1 || n > 1024 { // Log every 10th small frame or all large frames
					log.Debug("📦 Backend→Client frame #%d: %d bytes (ID=%s)", frameCount, n, msg.ID[:8]+"...")
				}

				// Check if main connection is broken before sending
				if a.isConnectionBroken() {
					log.Info("🔌 Main connection broken, stopping frame relay: ID=%s, Frame=%d",
						msg.ID[:8]+"...", frameCount)
					return
				}

				// Send WebSocket data to client through message system with exact buffer copy
				frameData := make([]byte, n)
				copy(frameData, buffer[:n])

				frameMsg := &common.Message{
					Type: "websocket_frame",
					ID:   msg.ID,
					HTTP: &common.HTTPData{
						Body:        frameData,
						IsWebSocket: true,
					},
				}

				if err := a.SendMessage(frameMsg); err != nil {
					// Check if the error is due to main connection being broken
					if strings.Contains(err.Error(), "broken pipe") ||
						strings.Contains(err.Error(), "connection reset") ||
						strings.Contains(err.Error(), "use of closed network connection") ||
						strings.Contains(err.Error(), "i/o timeout") ||
						a.isConnectionBroken() {
						log.Info("🔌 Failed to relay frame due to main connection break: ID=%s, Frame=%d, Error: %v",
							msg.ID[:8]+"...", frameCount, err)

						// Trigger reconnection for persistent connection issues
						if strings.Contains(err.Error(), "i/o timeout") {
							log.Warn("⚠️  Persistent I/O timeout detected on WebSocket relay")
							// Don't trigger reconnection from WebSocket relay - let heartbeat handle it
							// to prevent multiple simultaneous reconnection attempts
						}
						return
					}

					log.Error("❌ Failed to relay frame to client (ID=%s): %v", msg.ID[:8]+"...", err)
					break
				}
			}
		}

		log.Info("📊 WebSocket relay stats: ID=%s, Total frames=%d", msg.ID[:8]+"...", frameCount)
	}()

	// Wait for one direction to finish
	<-done
	log.Info("🔌 WebSocket connection relay ended for %s", host)
}

// buildWebSocketUpgradeRequest builds the raw HTTP upgrade request for the backend
func (a *Agent) buildWebSocketUpgradeRequest(msg *common.Message) string {
	var request strings.Builder

	// Start with request line
	request.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", msg.HTTP.Method, msg.HTTP.URL))
	log.Debug("🔧 WebSocket upgrade request line: %s %s HTTP/1.1", msg.HTTP.Method, msg.HTTP.URL)

	// Extract client IP for proxy headers
	clientIP := ""
	if xff := msg.HTTP.Headers["X-Forwarded-For"]; len(xff) > 0 && xff[0] != "" {
		// X-Forwarded-For can be "ip1, ip2, ip3" - take the first (original client)
		parts := strings.Split(xff[0], ",")
		if len(parts) > 0 {
			clientIP = strings.TrimSpace(parts[0])
		}
	}
	if clientIP == "" {
		if xRealIP := msg.HTTP.Headers["X-Real-IP"]; len(xRealIP) > 0 && xRealIP[0] != "" {
			clientIP = xRealIP[0]
		}
	}

	// Debug: Check for essential WebSocket headers
	hasConnection := false
	hasUpgrade := false
	hasSecWebSocketKey := false
	hasSecWebSocketVersion := false
	hasAuthorization := false

	// Add original client headers - keep WebSocket protocol headers and authentication
	for key, values := range msg.HTTP.Headers {
		for _, value := range values {
			keyLower := strings.ToLower(key)

			// Skip WebSocket extensions to prevent compression issues
			if keyLower == "sec-websocket-extensions" {
				log.Debug("🚫 Skipping WebSocket extensions header to prevent compression issues: %s", value)
				continue
			}

			// Skip server-added proxy headers that will be replaced with proper values
			switch keyLower {
			case "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-server", "x-real-ip":
				// These will be added back with proper values for Zero Trust
				log.Debug("🔄 Replacing proxy header %s with Zero Trust values", key)
				continue
			default:
				// Pass through all other original client headers (WebSocket protocol, auth, etc.)
				request.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
			}

			// Check for essential WebSocket headers
			switch keyLower {
			case "connection":
				hasConnection = true
				log.Debug("🔧 Found Connection header: %s", value)
			case "upgrade":
				hasUpgrade = true
				log.Debug("🔧 Found Upgrade header: %s", value)
			case "sec-websocket-key":
				hasSecWebSocketKey = true
				log.Debug("🔧 Found Sec-WebSocket-Key header: %s", value)
			case "sec-websocket-version":
				hasSecWebSocketVersion = true
				log.Debug("🔧 Found Sec-WebSocket-Version header: %s", value)
			case "authorization":
				hasAuthorization = true
				log.Info("🔑 Authorization header included in WebSocket upgrade: %s", value[:min(len(value), 30)]+"...")
			case "cookie":
				log.Debug("🍪 Cookie header found: %s", value[:min(len(value), 50)]+"...")
			}
		}
	}

	// Add Zero Trust proxy headers for identity-aware proxy functionality
	// These headers are needed by ALL backend services for proper authentication and routing
	originalHost := msg.HTTP.Headers["Host"][0]

	// Add X-Forwarded-Host (the original host the client requested)
	request.WriteString(fmt.Sprintf("X-Forwarded-Host: %s\r\n", originalHost))

	// Add X-Forwarded-Proto (the original protocol - HTTPS since it came through Caddy)
	request.WriteString("X-Forwarded-Proto: https\r\n")

	// Add client IP headers if available
	if clientIP != "" {
		request.WriteString(fmt.Sprintf("X-Real-IP: %s\r\n", clientIP))
		request.WriteString(fmt.Sprintf("X-Forwarded-For: %s\r\n", clientIP))
		log.Debug("🔧 Added Zero Trust client IP headers: X-Real-IP=%s, X-Forwarded-For=%s", clientIP, clientIP)
	}

	// Add X-Forwarded-Server (this agent's identifier)
	request.WriteString(fmt.Sprintf("X-Forwarded-Server: zero-trust-agent-%s\r\n", a.id))

	// Log missing essential WebSocket headers
	if !hasConnection {
		log.Error("❌ Missing Connection header in WebSocket upgrade request!")
	}
	if !hasUpgrade {
		log.Error("❌ Missing Upgrade header in WebSocket upgrade request!")
	}
	if !hasSecWebSocketKey {
		log.Error("❌ Missing Sec-WebSocket-Key header in WebSocket upgrade request!")
	}
	if !hasSecWebSocketVersion {
		log.Error("❌ Missing Sec-WebSocket-Version header in WebSocket upgrade request!")
	}

	// Generic WebSocket upgrade logging - works for all services
	log.Info("🔌 WebSocket upgrade for %s - including Zero Trust headers for identity-aware proxy", originalHost)
	if hasAuthorization {
		log.Info("✅ WebSocket upgrade includes Authorization header")
	} else {
		log.Debug("💡 WebSocket upgrade without Authorization header - this is normal for many services")
	}

	// Add end of headers
	request.WriteString("\r\n")

	// Add body if present (though WebSocket upgrade requests typically don't have bodies)
	if len(msg.HTTP.Body) > 0 {
		request.Write(msg.HTTP.Body)
	}

	log.Info("📋 WebSocket upgrade request built with Zero Trust headers: Host=%s, ClientIP=%s, Protocol=https",
		originalHost, clientIP)

	return request.String()
}

// sendRawHTTPResponse sends a raw HTTP response back to the client
func (a *Agent) sendRawHTTPResponse(messageID, response string) {
	// Parse the response to extract status and headers
	lines := strings.Split(response, "\r\n")
	if len(lines) == 0 {
		return
	}

	// Parse status line
	statusLine := lines[0]
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return
	}

	statusCode := 200
	statusMessage := "OK"
	if len(parts) >= 2 {
		if code, err := strconv.Atoi(parts[1]); err == nil {
			statusCode = code
		}
	}
	if len(parts) >= 3 {
		statusMessage = parts[2]
	}

	// Parse headers
	headers := make(map[string][]string)
	bodyStart := 1
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			bodyStart = i + 1
			break
		}

		if colon := strings.Index(line, ":"); colon > 0 {
			key := strings.TrimSpace(line[:colon])
			value := strings.TrimSpace(line[colon+1:])
			headers[key] = append(headers[key], value)
		}
	}

	// Extract body (if any)
	var body []byte
	if bodyStart < len(lines) {
		bodyText := strings.Join(lines[bodyStart:], "\r\n")
		body = []byte(bodyText)
	}

	// Send response message
	responseMsg := &common.Message{
		Type: "http_response",
		ID:   messageID,
		HTTP: &common.HTTPData{
			StatusCode:    statusCode,
			StatusMessage: statusMessage,
			Headers:       headers,
			Body:          body,
			IsWebSocket:   statusCode == 101,
		},
	}

	if err := a.SendMessage(responseMsg); err != nil {
		log.Error("❌ Failed to send WebSocket upgrade response: %v", err)
	}
}

// handleWebSocketFrame handles incoming WebSocket frames from the client and forwards them to the backend
func (a *Agent) handleWebSocketFrame(msg *common.Message) {
	if msg.HTTP == nil || len(msg.HTTP.Body) == 0 {
		return
	}

	// Find the backend connection for this WebSocket session
	wsConn, exists := a.wsManager.GetConnection(msg.ID)

	if !exists {
		log.Debug("🔍 WebSocket frame dropped - connection not found: ID=%s", msg.ID[:8]+"...")
		return
	}

	// Validate connection is still active
	if wsConn == nil || wsConn.GetConn() == nil {
		log.Warn("⚠️  WebSocket frame dropped - nil connection: ID=%s", msg.ID[:8]+"...")
		a.wsManager.RemoveConnection(msg.ID)
		return
	}

	// Update activity timestamp
	wsConn.UpdateActivity()

	// NO TIMEOUT - Use approach with health monitoring instead
	// Major providers don't set write timeouts on WebSocket connections

	// Forward the frame data to the backend atomically
	totalWritten := 0
	data := msg.HTTP.Body
	frameSize := len(data)

	for totalWritten < len(data) {
		n, err := wsConn.GetConn().Write(data[totalWritten:])
		if err != nil {
			log.Error("❌ Failed to write WebSocket frame to backend (ID=%s): %v", msg.ID[:8]+"...", err)
			// Connection is broken, clean it up
			a.wsManager.RemoveConnection(msg.ID)
			totalConnections := a.wsManager.GetConnectionCount()
			log.Info("🗑️  Removed broken WebSocket connection: ID=%s, Remaining=%d", msg.ID[:8]+"...", totalConnections)
			return
		}
		totalWritten += n
	}

	// Log frame forwarding with less verbosity for small frames
	if frameSize > 100 || frameSize == 2 { // Log large frames or likely ping/pong frames
		log.Debug("📤 Client→Backend frame: %d bytes (ID=%s)", frameSize, msg.ID[:8]+"...")
	}

	// Generic client authentication frame analysis - works for any service
	if frameSize > 50 && strings.Contains(string(data[:min(frameSize, 200)]), "access_token") {
		log.Info("🔑 Client sending authentication token")
	} else if frameSize > 20 && strings.Contains(string(data[:min(frameSize, 100)]), "type") {
		frameStr := string(data[:min(frameSize, 100)])
		if strings.Contains(frameStr, "auth") {
			log.Debug("🔐 Client authentication frame detected")
		} else if strings.Contains(frameStr, "subscribe") {
			log.Debug("📡 Client subscribing to events")
		}
	}
}

// handleWebSocketDisconnect handles notification from server that client disconnected
func (a *Agent) handleWebSocketDisconnect(msg *common.Message) {
	log.Info("📞 Server notified client disconnected: ID=%s", msg.ID[:8]+"...")

	// Find and cleanup the backend connection
	a.wsManager.RemoveConnection(msg.ID)
	totalConnections := a.wsManager.GetConnectionCount()

	log.Info("🧹 Cleaned up backend WebSocket connection: ID=%s, Remaining=%d",
		msg.ID[:8]+"...", totalConnections)
}

// loadAndRegisterServices loads services from config and registers them with the server
func (a *Agent) loadAndRegisterServices() error {
	// Use the config that was already loaded and passed to the agent
	a.mu.RLock()
	config := a.config
	a.mu.RUnlock()

	if config == nil {
		return fmt.Errorf("❌ no configuration available")
	}

	log.Info("📋 Loaded agent configuration: ID=%s, Name=%s, Services=%d",
		config.Agent.ID, config.Agent.Name, len(config.Services))

	// Register each service
	for _, serviceConfig := range config.Services {
		// Get all hosts for this service (handles both hostname and hosts fields)
		allHosts := serviceConfig.GetAllHosts()

		log.Info("🌐 Loaded service configuration: %s (%s) -> %s://%s with %d upstreams and %d hosts",
			serviceConfig.ID, serviceConfig.Name, serviceConfig.Protocol,
			a.getPrimaryUpstream(&serviceConfig), len(serviceConfig.Upstreams), len(allHosts))

		// Register each host separately with the server
		for _, hostname := range allHosts {
			// Validate service configuration BEFORE processing
			log.Debug("🔍 Validating service configuration for host: %s", hostname)

			// Convert enhanced config to common ServiceConfig for validation
			commonServiceForValidation := a.convertToCommonServiceConfig(&serviceConfig, hostname)
			typesServiceForValidation := convertCommonToTypes(commonServiceForValidation)
			validationResult := a.caddyValidator.ValidateServiceConfig(typesServiceForValidation)

			if !validationResult.Valid {
				var errorMessages []string
				for _, err := range validationResult.Errors {
					errorMessages = append(errorMessages, err.Error())
				}
				return fmt.Errorf("❌ Caddy configuration validation failed for service %s (host: %s): %s",
					serviceConfig.ID, hostname, strings.Join(errorMessages, "; "))
			}

			log.Info("✅ Caddy configuration validation passed for service %s (host: %s)", serviceConfig.ID, hostname)

			// Convert enhanced config to common ServiceConfig for server registration
			commonService := a.convertToCommonServiceConfig(&serviceConfig, hostname)

			// Store service config with primary upstream for request handling
			a.mu.Lock()
			a.services[hostname] = commonService
			a.mu.Unlock()

			log.Info("📌 Registering host: %s -> %s", hostname, a.getPrimaryUpstream(&serviceConfig))

			// Register with server (this will perform basic validation again but that's OK for safety)
			if err := a.ConfigureService(commonService); err != nil {
				return fmt.Errorf("❌ failed to register service %s for host %s: %w", serviceConfig.ID, hostname, err)
			}
		}

		// Start health checks if configured (once per service, not per host)
		if err := a.startHealthChecks(&serviceConfig); err != nil {
			log.Error("❌ Failed to start health checks for service %s: %v", serviceConfig.ID, err)
		}
	}

	// Start global health check endpoints if configured
	if err := a.startGlobalHealthChecks(config); err != nil {
		log.Error("❌ Failed to start global health checks: %v", err)
	}

	return nil
}

// convertToCommonServiceConfig converts enhanced ServiceConfig to common.ServiceConfig for server registration
func (a *Agent) convertToCommonServiceConfig(service *ServiceConfig, hostname string) *common.ServiceConfig {
	// Use primary upstream as the backend
	primaryUpstream := a.getPrimaryUpstream(service)

	return &common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{
			Hostname:     hostname,
			Backend:      primaryUpstream,
			Protocol:     service.Protocol,
			WebSocket:    service.WebSocket,    // CRITICAL: Copy WebSocket flag for server/Caddy configuration
			HTTPRedirect: service.HTTPRedirect, // Copy HTTP redirect setting
			ListenOn:     service.ListenOn,     // Copy protocol binding setting
		},
	}
}

// getPrimaryUpstream returns the primary upstream address for a service
func (a *Agent) getPrimaryUpstream(service *ServiceConfig) string {
	if len(service.Upstreams) == 0 {
		return ""
	}

	// If load balancing is configured, select based on policy
	if service.LoadBalancing != nil {
		switch service.LoadBalancing.Policy {
		case "weighted_round_robin":
			return a.selectWeightedUpstream(service.Upstreams)
		case "least_conn":
			return a.selectLeastConnUpstream(service.Upstreams)
		default:
			// Default to round robin - return first healthy upstream
			return a.selectHealthyUpstream(service.Upstreams)
		}
	}

	// Default: return first upstream
	return service.Upstreams[0].Address
}

// selectWeightedUpstream selects an upstream based on weights (simplified implementation)
func (a *Agent) selectWeightedUpstream(upstreams []UpstreamConfig) string {
	// Simplified: return highest weight upstream
	// In production, this would implement proper weighted round-robin
	maxWeight := 0
	selectedAddress := ""

	for _, upstream := range upstreams {
		if upstream.Weight > maxWeight {
			maxWeight = upstream.Weight
			selectedAddress = upstream.Address
		}
	}

	return selectedAddress
}

// selectLeastConnUpstream selects upstream with least connections (placeholder)
func (a *Agent) selectLeastConnUpstream(upstreams []UpstreamConfig) string {
	// Simplified: return first upstream
	// In production, this would track connection counts
	return upstreams[0].Address
}

// selectHealthyUpstream returns the first healthy upstream
func (a *Agent) selectHealthyUpstream(upstreams []UpstreamConfig) string {
	// For now, return first upstream
	// Health check status would be checked here in production
	return upstreams[0].Address
}

// startHealthChecks starts health checking for service upstreams
func (a *Agent) startHealthChecks(service *ServiceConfig) error {
	for _, upstream := range service.Upstreams {
		if upstream.HealthCheck != nil {
			go a.runHealthCheck(service, upstream)
		}
	}
	return nil
}

// runHealthCheck performs health checking for an upstream
func (a *Agent) runHealthCheck(service *ServiceConfig, upstream UpstreamConfig) {
	if upstream.HealthCheck == nil {
		return
	}

	hc := upstream.HealthCheck
	interval := hc.Interval
	if interval == 0 {
		interval = 30 * time.Second // Default interval
	}

	timeout := hc.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second // Default timeout
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			healthy := a.checkUpstreamHealth(service, upstream)
			if healthy {
				log.Debug("✅ Health check passed for %s upstream %s", service.ID, upstream.Address)
			} else {
				log.Error("❌ Health check failed for %s upstream %s", service.ID, upstream.Address)
			}
		}
	}
}

// checkUpstreamHealth performs a single health check
func (a *Agent) checkUpstreamHealth(service *ServiceConfig, upstream UpstreamConfig) bool {
	if upstream.HealthCheck == nil {
		return true // No health check configured, assume healthy
	}

	hc := upstream.HealthCheck
	if hc.Path == "" {
		return true // No path configured, assume healthy
	}

	// Build health check URL - use proper scheme detection instead of hardcoded port
	scheme := getHealthCheckScheme(service, upstream.Address)

	url := fmt.Sprintf("%s://%s%s", scheme, upstream.Address, hc.Path)

	// Create HTTP client with timeout
	timeout := hc.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
	}

	// Create request
	method := hc.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		log.Error("❌ Failed to create health check request for %s: %v", upstream.Address, err)
		return false
	}

	// Add custom headers if configured
	for key, value := range hc.Headers {
		req.Header.Set(key, value)
	}

	// Perform request
	resp, err := client.Do(req)
	if err != nil {
		log.Debug("⚠️  Health check request failed for %s: %v", upstream.Address, err)
		return false
	}
	defer resp.Body.Close()

	// Check status code (2xx is healthy)
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// startGlobalHealthChecks starts global health check endpoints
func (a *Agent) startGlobalHealthChecks(config *AgentConfig) error {
	if config.HealthChecks.Endpoints == nil || len(config.HealthChecks.Endpoints) == 0 {
		return nil
	}

	// Start HTTP server for health check endpoints
	go a.runHealthCheckServer(config.HealthChecks.Endpoints)

	return nil
}

// runHealthCheckServer runs a simple HTTP server for health check endpoints
func (a *Agent) runHealthCheckServer(endpoints []HealthCheckEndpoint) {
	mux := http.NewServeMux()

	// Register health check endpoints
	for _, endpoint := range endpoints {
		endpoint := endpoint // Capture for closure
		mux.HandleFunc(endpoint.Path, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(endpoint.Response))
		})
	}

	// Start server on a dynamic port
	server := &http.Server{
		Addr:    ":0", // Dynamic port
		Handler: mux,
	}

	log.Info("🏥 Starting health check server...")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("❌ Health check server error: %v", err)
	}
}

// ConfigureService configures a service on the server with enhanced configuration support
func (a *Agent) ConfigureService(config *common.ServiceConfig) error {
	return a.configureServiceWithRetry(config, 3) // Allow up to 3 attempts
}

// configureServiceWithRetry configures a service with retry logic
func (a *Agent) configureServiceWithRetry(config *common.ServiceConfig, maxAttempts int) error {
	var lastErr error

	// Validate configuration BEFORE attempting to send to server
	log.Debug("🔍 Validating Caddy configuration for service: %s", config.Hostname)
	typesConfig := convertCommonToTypes(config)
	validationResult := a.caddyValidator.ValidateServiceConfig(typesConfig)

	if !validationResult.Valid {
		var errorMessages []string
		for _, err := range validationResult.Errors {
			errorMessages = append(errorMessages, err.Error())
		}
		return fmt.Errorf("❌ Caddy configuration validation failed for service %s: %s",
			config.Hostname, strings.Join(errorMessages, "; "))
	}

	log.Info("✅ Caddy configuration validation passed for service: %s", config.Hostname)

	// Track this service for future conflict detection
	a.caddyValidator.AddExistingService(config.Hostname, typesConfig)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Check registration status before each attempt
		a.mu.RLock()
		registered := a.registered
		a.mu.RUnlock()

		if !registered {
			log.Warn("⚠️  Agent not registered, cannot configure service %s (attempt %d/%d)",
				config.Hostname, attempt, maxAttempts)
			if attempt < maxAttempts {
				time.Sleep(time.Duration(attempt) * time.Second) // Progressive delay
				continue
			}
			return fmt.Errorf("agent not registered with server after %d attempts", maxAttempts)
		}

		log.Info("⚙️  Configuring service: %s (attempt %d/%d)", config.Hostname, attempt, maxAttempts)

		// Check if we have enhanced configuration for this service
		var enhancedConfig *common.EnhancedServiceConfig
		if a.config != nil {
			for _, service := range a.config.Services {
				// Check if this hostname is handled by this service
				for _, serviceHost := range service.GetAllHosts() {
					if serviceHost == config.Hostname {
						// Convert agent ServiceConfig to common EnhancedServiceConfig
						enhancedConfig = a.convertToCommonEnhancedServiceConfig(&service, config.Hostname)
						break
					}
				}
				if enhancedConfig != nil {
					break
				}
			}
		}

		// Create message with both simple and enhanced configs for full compatibility
		msg := &common.Message{
			Type:            "service_add",
			ID:              a.id,
			Service:         config,         // Simple config for backward compatibility
			EnhancedService: enhancedConfig, // Enhanced config if available
		}

		if enhancedConfig != nil {
			log.Debug("📦 Sending enhanced service configuration for %s with %d upstreams",
				config.Hostname, len(enhancedConfig.Upstreams))
		} else {
			log.Debug("📄 Sending simple service configuration for %s", config.Hostname)
		}

		if err := a.SendMessage(msg); err != nil {
			lastErr = fmt.Errorf("failed to send service configuration: %w", err)
			log.Error("❌ Failed to send service config (attempt %d/%d): %v", attempt, maxAttempts, err)

			// Check if this is a connection error that might resolve with retry
			if strings.Contains(err.Error(), "no connection") ||
				strings.Contains(err.Error(), "i/o timeout") ||
				strings.Contains(err.Error(), "connection reset") {
				if attempt < maxAttempts {
					log.Info("🔄 Connection error, retrying service configuration in %ds", attempt)
					time.Sleep(time.Duration(attempt) * time.Second)
					continue
				}
			}
			return lastErr
		}

		// Wait for response with progressive timeout (longer for later attempts)
		timeout := time.Duration(15+10*attempt) * time.Second
		log.Debug("⏳ Waiting for service config response (timeout: %v)", timeout)

		select {
		case response := <-a.serviceRespCh:
			if response.Error != "" {
				lastErr = fmt.Errorf("service error: %s", response.Error)
				log.Error("❌ Service configuration error (attempt %d/%d): %s", attempt, maxAttempts, response.Error)
				if attempt < maxAttempts {
					time.Sleep(time.Duration(attempt) * time.Second)
					continue
				}
				return lastErr
			}
			if response.Type != "service_add_response" {
				lastErr = fmt.Errorf("unexpected response type: %s", response.Type)
				log.Error("❌ Unexpected response type (attempt %d/%d): %s", attempt, maxAttempts, response.Type)
				if attempt < maxAttempts {
					time.Sleep(time.Duration(attempt) * time.Second)
					continue
				}
				return lastErr
			}
			log.Info("✅ Service configuration successful: %s (attempt %d/%d)", config.Hostname, attempt, maxAttempts)
			return nil

		case <-time.After(timeout):
			lastErr = fmt.Errorf("timeout waiting for service configuration response")
			log.Error("⏰ Timeout waiting for service config response (attempt %d/%d, timeout: %v)",
				attempt, maxAttempts, timeout)

			if attempt < maxAttempts {
				log.Info("🔄 Retrying service configuration in %ds", attempt)
				time.Sleep(time.Duration(attempt) * time.Second)
				continue
			}
		}
	}

	return lastErr
}

// convertToCommonEnhancedServiceConfig converts agent ServiceConfig to common EnhancedServiceConfig
func (a *Agent) convertToCommonEnhancedServiceConfig(service *ServiceConfig, hostname string) *common.EnhancedServiceConfig {
	enhancedConfig := &common.EnhancedServiceConfig{
		ID:           service.ID,
		Name:         service.Name,
		Hostname:     hostname,
		Protocol:     service.Protocol,
		WebSocket:    service.WebSocket,    // Copy WebSocket configuration
		HTTPRedirect: service.HTTPRedirect, // Copy HTTP redirect setting
		ListenOn:     service.ListenOn,     // Copy protocol binding setting
	}

	// Convert upstreams
	for _, upstream := range service.Upstreams {
		commonUpstream := common.UpstreamConfig{
			Address: upstream.Address,
			Weight:  upstream.Weight,
		}

		// Convert health check if present
		if upstream.HealthCheck != nil {
			commonUpstream.HealthCheck = &common.HealthCheckConfig{
				Path:     upstream.HealthCheck.Path,
				Interval: upstream.HealthCheck.Interval.String(),
				Timeout:  upstream.HealthCheck.Timeout.String(),
				Method:   upstream.HealthCheck.Method,
				Headers:  upstream.HealthCheck.Headers,
			}
		}

		enhancedConfig.Upstreams = append(enhancedConfig.Upstreams, commonUpstream)
	}

	// Convert load balancing config if present
	if service.LoadBalancing != nil {
		enhancedConfig.LoadBalancing = &common.LoadBalancingConfig{
			Policy:              service.LoadBalancing.Policy,
			HealthCheckRequired: service.LoadBalancing.HealthCheckRequired,
			SessionAffinity:     service.LoadBalancing.SessionAffinity,
		}
		if service.LoadBalancing.AffinityDuration > 0 {
			enhancedConfig.LoadBalancing.AffinityDuration = service.LoadBalancing.AffinityDuration.String()
		}
	}

	// Convert routes
	for _, route := range service.Routes {
		commonRoute := common.RouteConfig{
			Match: common.MatchConfig{
				Path:    route.Match.Path,
				Method:  route.Match.Method,
				Headers: route.Match.Headers,
				Query:   route.Match.Query,
			},
		}

		// Convert middleware handlers
		for _, handler := range route.Handle {
			commonHandler := common.MiddlewareConfig{
				Type:   handler.Type,
				Config: handler.Config,
			}
			commonRoute.Handle = append(commonRoute.Handle, commonHandler)
		}

		enhancedConfig.Routes = append(enhancedConfig.Routes, commonRoute)
	}

	// Convert TLS config if present
	if service.TLS != nil {
		enhancedConfig.TLS = &common.TLSConfig{
			CertFile:     service.TLS.CertFile,
			KeyFile:      service.TLS.KeyFile,
			CAFile:       service.TLS.CAFile,
			MinVersion:   service.TLS.MinVersion,
			Ciphers:      service.TLS.Ciphers,
			ClientAuth:   service.TLS.ClientAuth,
			ClientCAFile: service.TLS.ClientCAFile,
		}
	}

	// Convert security config if present
	if service.Security != nil {
		enhancedConfig.Security = &common.SecurityConfig{}

		if service.Security.CORS != nil {
			enhancedConfig.Security.CORS = &common.CORSConfig{
				Origins: service.Security.CORS.Origins,
				Methods: service.Security.CORS.Methods,
				Headers: service.Security.CORS.Headers,
			}
		}

		if service.Security.Auth != nil {
			enhancedConfig.Security.Auth = &common.AuthConfig{
				Type:   service.Security.Auth.Type,
				Config: service.Security.Auth.Config,
			}
		}
	}

	// Convert monitoring config if present
	if service.Monitoring != nil {
		enhancedConfig.Monitoring = &common.MonitoringConfig{
			MetricsEnabled: service.Monitoring.MetricsEnabled,
		}

		// Use simplified logging configuration
		if service.Monitoring.LoggingFormat != "" || len(service.Monitoring.LoggingFields) > 0 {
			enhancedConfig.Monitoring.Logging = &common.LoggingConfig{
				Format: service.Monitoring.LoggingFormat,
				Fields: service.Monitoring.LoggingFields,
			}
		}
	}

	// Convert traffic shaping config if present
	if service.TrafficShaping != nil {
		enhancedConfig.TrafficShaping = &common.TrafficShapingConfig{
			UploadLimit:   service.TrafficShaping.UploadLimit,
			DownloadLimit: service.TrafficShaping.DownloadLimit,
			PerIPLimit:    service.TrafficShaping.PerIPLimit,
		}
	}

	return enhancedConfig
}

// sendHeartbeat sends a heartbeat to the server
func (a *Agent) sendHeartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	consecutiveFailures := 0
	maxFailures := 3
	lastSuccessfulHeartbeat := time.Now()
	maxTimeBetweenHeartbeats := 5 * time.Minute // Force reconnection if no successful heartbeat for 5 minutes

	log.Info("💓 Starting heartbeat monitoring (30s interval)")

	for {
		select {
		case <-ticker.C:
			// Check if too much time has passed without a successful heartbeat
			timeSinceLastSuccess := time.Since(lastSuccessfulHeartbeat)
			if timeSinceLastSuccess > maxTimeBetweenHeartbeats {
				log.Error("💀 No successful heartbeat for %v, forcing reconnection", timeSinceLastSuccess.Round(time.Second))
				a.attemptReconnection("heartbeat-timeout")
				lastSuccessfulHeartbeat = time.Now() // Reset timer
				consecutiveFailures = 0
				continue
			}

			// Check if connection is already broken FIRST (before registration check)
			if a.isConnectionBroken() {
				log.Debug("💔 Connection broken detected in heartbeat monitoring")
				// Use coordinated reconnection
				a.attemptReconnection("heartbeat-broken-connection")
				continue
			}

			// Check if connection is nil (no connection at all) - this handles failed reconnection scenarios
			if a.conn == nil {
				log.Debug("💀 No connection detected, triggering reconnection")
				a.attemptReconnection("heartbeat-no-connection")
				continue
			}

			// Check if encoder/decoder are nil (connection not properly initialized)
			if a.encoder == nil || a.decoder == nil {
				log.Warn("⚠️  Connection not properly initialized (encoder/decoder nil), triggering reconnection")
				a.attemptReconnection("heartbeat-invalid-connection")
				continue
			}

			// Check registration status for normal heartbeat operations
			a.mu.RLock()
			registered := a.registered
			a.mu.RUnlock()

			if !registered {
				log.Debug("⏸️  Skipping heartbeat - agent not registered (will check for broken connection next cycle)")
				continue
			}

			// Skip heartbeat during reconnection
			if a.isReconnectInProgress() {
				log.Debug("⏸️  Skipping heartbeat - reconnection in progress")
				continue
			}

			// Skip heartbeat if we've had too many consecutive failures
			if consecutiveFailures >= maxFailures {
				log.Error("💀 Too many heartbeat failures (%d), triggering reconnection", consecutiveFailures)
				// Use coordinated reconnection and reset failure count
				a.attemptReconnection("heartbeat-failures")
				consecutiveFailures = 0 // Reset after triggering reconnection
				continue
			}

			// Send ping message
			msg := &common.Message{
				Type: "ping",
				ID:   a.id,
			}

			// Use a timeout for sending heartbeat to avoid blocking
			heartbeatDone := make(chan error, 1)
			go func() {
				heartbeatDone <- a.SendMessage(msg)
			}()

			select {
			case err := <-heartbeatDone:
				if err != nil {
					consecutiveFailures++
					log.Error("💔 Failed to send heartbeat (failure %d/%d): %v", consecutiveFailures, maxFailures, err)

					// Check for connection-related errors and trigger immediate reconnection
					if strings.Contains(err.Error(), "broken pipe") ||
						strings.Contains(err.Error(), "connection reset") ||
						strings.Contains(err.Error(), "connection refused") ||
						strings.Contains(err.Error(), "use of closed network connection") ||
						strings.Contains(err.Error(), "i/o timeout") {
						log.Error("🔌 Connection error detected in heartbeat, triggering immediate reconnection")
						consecutiveFailures = maxFailures // Force immediate reconnection
					}
					continue
				} else {
					// Reset failure counter on successful send
					consecutiveFailures = 0
				}
			case <-time.After(15 * time.Second):
				consecutiveFailures++
				log.Error("⏰ Heartbeat send timeout (failure %d/%d)", consecutiveFailures, maxFailures)
				continue
			}

			// Wait for pong response with timeout
			select {
			case response := <-a.pongCh:
				if response.Type == "pong" && response.ID == a.id {
					log.Debug("💓 Received pong response")
					consecutiveFailures = 0              // Reset failure count on successful pong
					lastSuccessfulHeartbeat = time.Now() // Record successful heartbeat
					continue
				}
				log.Error("❓ Unexpected response type or ID while waiting for pong: %s (ID: %s)", response.Type, response.ID)
				consecutiveFailures++
			case <-time.After(5 * time.Second):
				consecutiveFailures++
				log.Error("⏰ Timeout waiting for heartbeat response (failure %d/%d)", consecutiveFailures, maxFailures)

				// If we've reached max failures, trigger immediate reconnection
				if consecutiveFailures >= maxFailures {
					log.Error("💀 Max heartbeat pong timeouts reached, triggering immediate reconnection")
					// Use coordinated reconnection and reset failure count
					a.attemptReconnection("heartbeat-pong-timeouts")
					consecutiveFailures = 0 // Reset after triggering reconnection
					continue
				}
			}
		}
	}
}

// monitorChannelHealth periodically reports channel health statistics
func (a *Agent) monitorChannelHealth() {
	ticker := time.NewTicker(60 * time.Second) // Report every minute
	defer ticker.Stop()

	log.Debug("📊 Starting channel health monitoring (60s interval)")

	for {
		select {
		case <-ticker.C:
			// Log channel usage statistics
			registerUsage := float64(len(a.registerCh)) / float64(cap(a.registerCh)) * 100
			httpRespUsage := float64(len(a.httpRespCh)) / float64(cap(a.httpRespCh)) * 100
			pongUsage := float64(len(a.pongCh)) / float64(cap(a.pongCh)) * 100
			serviceRespUsage := float64(len(a.serviceRespCh)) / float64(cap(a.serviceRespCh)) * 100

			// Only log if any channel is significantly used
			if registerUsage > 10 || httpRespUsage > 10 || pongUsage > 10 || serviceRespUsage > 10 {
				log.Info("📊 Channel usage - Register: %.1f%%, HTTP: %.1f%%, Pong: %.1f%%, Service: %.1f%%",
					registerUsage, httpRespUsage, pongUsage, serviceRespUsage)
			}

			// Log pressure statistics
			a.pressureMu.RLock()
			highPressureChannels := 0
			for channelName, pressure := range a.channelPressure {
				if pressure > 0 {
					log.Debug("⚠️  Channel pressure - %s: %d", channelName, pressure)
					if pressure > 5 {
						highPressureChannels++
					}
				}
			}
			a.pressureMu.RUnlock()

			// Alert if multiple channels have high pressure
			if highPressureChannels > 2 {
				log.Warn("🚨 High pressure detected on %d channels - performance may be impacted", highPressureChannels)
			}
		}
	}
}

// startWebSocketHealthMonitoring starts background WebSocket health monitoring for the agent
func (a *Agent) startWebSocketHealthMonitoring() {
	go func() {
		// Clean up stale connections every 2 minutes
		cleanupTicker := time.NewTicker(2 * time.Minute)
		defer cleanupTicker.Stop()

		// Report connection statistics every 5 minutes
		statsTicker := time.NewTicker(5 * time.Minute)
		defer statsTicker.Stop()

		for {
			select {
			case <-cleanupTicker.C:
				a.cleanupStaleConnections()
			case <-statsTicker.C:
				a.logWebSocketStats()
			}
		}
	}()
}

// logWebSocketStats logs WebSocket connection statistics
func (a *Agent) logWebSocketStats() {
	total, healthy, stale := a.wsManager.GetStats()
	if total > 0 {
		log.Info("📊 Agent WebSocket Stats: Total=%d, Healthy=%d, Stale=%d", total, healthy, stale)
	}
}

// Start starts the agent
func (a *Agent) Start() error {
	log.Info("🚀 Starting 0Trust agent: %s", a.id)

	// Connect to server
	if err := a.Connect(); err != nil {
		return fmt.Errorf("❌ failed to connect: %v", err)
	}

	// Start heartbeat loop
	log.Info("💓 Starting heartbeat monitoring")
	go a.sendHeartbeat()

	// Start WebSocket health monitoring
	log.Info("🔌 Starting WebSocket health monitoring")
	a.startWebSocketHealthMonitoring()

	// Start shared hot reload system
	log.Info("🔥 Starting shared hot reload system")
	if err := a.hotReloadManager.RegisterReloader(a); err != nil {
		log.Error("❌ Failed to register hot reload: %v", err)
	}

	// Load and register services
	log.Info("📋 Loading and registering services")
	if err := a.loadAndRegisterServices(); err != nil {
		return fmt.Errorf("❌ failed to load and register services: %v", err)
	}

	// Start channel health monitoring
	log.Info("📊 Starting channel health monitoring")
	go a.monitorChannelHealth()

	log.Info("✅ Agent %s started successfully and ready to handle requests", a.id)
	return nil
}

// reconnect attempts to reconnect to the server with exponential backoff
func (a *Agent) reconnect() error {
	log.Info("🔄 Attempting to reconnect to server...")

	// Close existing connection if any - use proper locking to prevent race conditions
	a.writeMu.Lock()
	a.readMu.Lock()
	if a.conn != nil {
		a.conn.Close()
		a.conn = nil
		a.encoder = nil
		a.decoder = nil
	}
	a.readMu.Unlock()
	a.writeMu.Unlock()

	// Reset registration state
	a.mu.Lock()
	a.registered = false
	a.mu.Unlock()

	// Signal connection broken to stop any ongoing operations
	a.signalConnectionBroken()

	// Clean up all WebSocket connections
	a.cleanupAllWebSocketConnections()

	// Connect to server with exponential backoff (never give up)
	attempt := 0
	var lastErr error
	for {
		attempt++

		// Reset connection state for each reconnection attempt
		a.resetConnectionState()

		conn, err := tls.Dial("tcp", a.serverAddr, a.tlsConfig)
		if err != nil {
			lastErr = err

			// Calculate exponential backoff delay (1s, 2s, 4s, 8s, 16s, 32s, 60s max)
			delay := time.Duration(1<<min(attempt-1, 5)) * time.Second
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}

			log.Error("❌ Failed to connect (attempt %d): %v - retrying in %v", attempt, err, delay)

			// Wait before next attempt
			time.Sleep(delay)
			continue
		}

		// Set new connection and reinitialize encoder/decoder with proper locking
		a.writeMu.Lock()
		a.readMu.Lock()
		a.conn = conn
		a.encoder = json.NewEncoder(conn)
		a.decoder = json.NewDecoder(conn)
		a.readMu.Unlock()
		a.writeMu.Unlock()

		// Reset connection state for the new connection
		a.resetConnectionState()

		log.Info("🔌 Reconnected to server, starting message handler...")

		// Restart message handling goroutine for the new connection
		go a.handleMessages()

		// Send registration message
		log.Info("📋 Sending registration message to server")
		if err := a.SendMessage(&common.Message{
			Type: "register",
			ID:   a.id,
		}); err != nil {
			lastErr = err
			log.Error("❌ Failed to send registration message (attempt %d): %v", attempt, err)
			// Close this connection and try again with delay
			conn.Close()
			a.writeMu.Lock()
			a.readMu.Lock()
			a.conn = nil
			a.encoder = nil
			a.decoder = nil
			a.readMu.Unlock()
			a.writeMu.Unlock()

			// Calculate delay for next attempt
			delay := time.Duration(1<<min(attempt-1, 5)) * time.Second
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}
			log.Debug("⏰ Retrying registration in %v", delay)
			time.Sleep(delay)
			continue
		}

		// Wait for registration response with timeout
		log.Info("⏳ Waiting for registration response...")
		select {
		case response := <-a.registerCh:
			if response.Type != "register_response" {
				lastErr = fmt.Errorf("unexpected response type during registration: %s", response.Type)
				log.Error("❌ Registration failed (attempt %d): %v", attempt, lastErr)
				// Close this connection and try again with delay
				conn.Close()
				a.writeMu.Lock()
				a.readMu.Lock()
				a.conn = nil
				a.encoder = nil
				a.decoder = nil
				a.readMu.Unlock()
				a.writeMu.Unlock()

				// Calculate delay for next attempt
				delay := time.Duration(1<<min(attempt-1, 5)) * time.Second
				if delay > 60*time.Second {
					delay = 60 * time.Second
				}
				log.Debug("⏰ Retrying registration in %v", delay)
				time.Sleep(delay)
				continue
			}

			log.Info("✅ Successfully re-registered with server")

			// Initialize last successful heartbeat timestamp for successful reconnection
			a.mu.Lock()
			a.lastPong = time.Now()
			a.mu.Unlock()

			// Re-register all services after reconnection
			if err := a.reregisterServices(); err != nil {
				log.Error("⚠️  Failed to re-register services after reconnection: %v", err)
				// Don't fail reconnection for this, services can be registered later
			}

			return nil
		case <-time.After(10 * time.Second):
			lastErr = fmt.Errorf("timeout waiting for registration confirmation")
			log.Error("⏰ Registration timeout (attempt %d)", attempt)
			// Close this connection and try again with delay
			conn.Close()
			a.writeMu.Lock()
			a.readMu.Lock()
			a.conn = nil
			a.encoder = nil
			a.decoder = nil
			a.readMu.Unlock()
			a.writeMu.Unlock()

			// Calculate delay for next attempt
			delay := time.Duration(1<<min(attempt-1, 5)) * time.Second
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}
			log.Debug("⏰ Retrying registration in %v", delay)
			time.Sleep(delay)
			continue
		}
	}
}

// reregisterServices re-registers all services after reconnection
func (a *Agent) reregisterServices() error {
	a.mu.RLock()
	services := make(map[string]*common.ServiceConfig)
	for k, v := range a.services {
		services[k] = v
	}
	a.mu.RUnlock()

	if len(services) == 0 {
		log.Debug("📝 No services to re-register")
		return nil
	}

	log.Info("🔄 Re-registering %d services after reconnection", len(services))

	for hostname, serviceConfig := range services {
		log.Debug("📋 Re-registering service: %s", hostname)
		if err := a.ConfigureService(serviceConfig); err != nil {
			log.Error("❌ Failed to re-register service %s: %v", hostname, err)
			return fmt.Errorf("failed to re-register service %s: %w", hostname, err)
		}
	}

	log.Info("✅ Successfully re-registered all services")
	return nil
}

// trackChannelPressure tracks pressure on named channels
func (a *Agent) trackChannelPressure(channelName string, success bool) {
	a.pressureMu.Lock()
	defer a.pressureMu.Unlock()

	if success {
		// Reduce pressure on success
		if a.channelPressure[channelName] > 0 {
			a.channelPressure[channelName]--
		}
	} else {
		// Increase pressure on failure
		a.channelPressure[channelName]++
		if a.channelPressure[channelName] > 10 {
			log.Error("🚨 High channel pressure detected for %s: %d failures", channelName, a.channelPressure[channelName])
		}
	}
}

// getAdaptiveTimeout returns timeout based on channel pressure
func (a *Agent) getAdaptiveTimeout(channelName string, baseTimeout time.Duration) time.Duration {
	a.pressureMu.RLock()
	pressure := a.channelPressure[channelName]
	a.pressureMu.RUnlock()

	// Increase timeout based on pressure
	if pressure > 5 {
		return baseTimeout * 2
	} else if pressure > 2 {
		return baseTimeout + (baseTimeout / 2)
	}
	return baseTimeout
}

// SendMessage sends a message to the server
func (a *Agent) SendMessage(msg *common.Message) error {
	// Lock to prevent concurrent writes to the TLS connection
	a.writeMu.Lock()
	defer a.writeMu.Unlock()

	// Check if connection or encoder is nil
	if a.conn == nil {
		return fmt.Errorf("no connection to server")
	}

	if a.encoder == nil {
		return fmt.Errorf("no encoder available - connection not properly initialized")
	}

	// Calculate adaptive write timeout using shared utilities
	timeoutConfig := &common.TimeoutConfig{
		DefaultTimeout:   30 * time.Second,
		StreamingTimeout: 1 * time.Minute,
		LargeFileTimeout: 10 * time.Minute,
		HeartbeatTimeout: 15 * time.Second,
	}
	writeTimeout := common.CalculateWriteTimeout(msg, timeoutConfig)

	// Set write deadline with adaptive timeout
	if err := a.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %v", err)
	}

	// Send message using JSON encoder (now protected by mutex)
	if err := a.encoder.Encode(msg); err != nil {
		// Check for connection-related errors that indicate broken connection
		if strings.Contains(err.Error(), "broken pipe") ||
			strings.Contains(err.Error(), "connection reset") ||
			strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "network is unreachable") ||
			strings.Contains(err.Error(), "use of closed network connection") ||
			strings.Contains(err.Error(), "i/o timeout") {
			log.Debug("🔗 Detected broken connection in SendMessage: %v", err)
		}
		return fmt.Errorf("failed to send message: %v", err)
	}

	return nil
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade (for logging purposes)
func (a *Agent) isWebSocketUpgrade(headers map[string][]string) bool {
	connection := ""
	upgrade := ""

	// Check Connection header
	if connHeaders, ok := headers["Connection"]; ok && len(connHeaders) > 0 {
		connection = strings.ToLower(connHeaders[0])
	}

	// Check Upgrade header
	if upgradeHeaders, ok := headers["Upgrade"]; ok && len(upgradeHeaders) > 0 {
		upgrade = strings.ToLower(upgradeHeaders[0])
	}

	return strings.Contains(connection, "upgrade") && upgrade == "websocket"
}

// cleanupStaleConnections removes stale WebSocket connections that are no longer active
func (a *Agent) cleanupStaleConnections() {
	a.wsManager.CleanupStaleConnections()
}

// signalConnectionBroken notifies all goroutines that the connection is broken
func (a *Agent) signalConnectionBroken() {
	a.connectionMu.Lock()
	defer a.connectionMu.Unlock()

	// Non-blocking send to avoid deadlock
	select {
	case a.connectionBroken <- struct{}{}:
		log.Debug("📡 Signaled connection broken to all goroutines")
	default:
		// Channel already has a signal, no need to send another
	}
}

// resetConnectionState resets the connection state for new connections
func (a *Agent) resetConnectionState() {
	a.connectionMu.Lock()
	defer a.connectionMu.Unlock()

	// Drain any existing signals
	select {
	case <-a.connectionBroken:
	default:
	}

	log.Debug("🔄 Reset connection state for new connection")
}

// isConnectionBroken checks if the connection is broken (non-blocking)
func (a *Agent) isConnectionBroken() bool {
	a.connectionMu.RLock()
	defer a.connectionMu.RUnlock()

	select {
	case <-a.connectionBroken:
		// Put the signal back since we only peeked
		a.connectionBroken <- struct{}{}
		return true
	default:
		return false
	}
}

// cleanupAllWebSocketConnections closes all active WebSocket connections
func (a *Agent) cleanupAllWebSocketConnections() {
	a.wsManager.CloseAll()
}

// setReconnectInProgress safely sets the reconnection in progress state
func (a *Agent) setReconnectInProgress(inProgress bool) bool {
	a.reconnectMu.Lock()
	defer a.reconnectMu.Unlock()

	if inProgress {
		// Try to set in progress - return false if already in progress
		if a.reconnectInProgress {
			return false // Already in progress
		}
		a.reconnectInProgress = true
		return true // Successfully set to in progress
	} else {
		// Clear in progress state
		a.reconnectInProgress = false
		return true
	}
}

// isReconnectInProgress safely checks if reconnection is in progress
func (a *Agent) isReconnectInProgress() bool {
	a.reconnectMu.Lock()
	defer a.reconnectMu.Unlock()
	return a.reconnectInProgress
}

// attemptReconnection attempts reconnection if not already in progress
func (a *Agent) attemptReconnection(source string) {
	// Try to set reconnection in progress
	if !a.setReconnectInProgress(true) {
		log.Debug("🔄 Reconnection already in progress, skipping %s trigger", source)
		return
	}

	log.Info("🔄 Starting reconnection process (triggered by %s)", source)

	// Run reconnection in background
	go func() {
		defer func() {
			// Clear reconnection in progress state
			a.setReconnectInProgress(false)
		}()

		// Add small delay for heartbeat-triggered reconnections to avoid hammering server
		if strings.Contains(source, "heartbeat") {
			log.Debug("⏰ Adding 2s delay for heartbeat-triggered reconnection")
			time.Sleep(2 * time.Second)
		}

		if err := a.reconnect(); err != nil {
			log.Error("🔄 Reconnection failed (%s trigger): %v", source, err)
		} else {
			log.Info("🎉 Reconnection successful (%s trigger)", source)
		}
	}()
}

// reloadConfig reloads the configuration and updates services
func (a *Agent) reloadConfig() error {
	log.Info("🔄 Reloading configuration from %s", a.config.ConfigPath)

	// Load new config
	newConfig, err := LoadConfig(a.config.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load new config: %w", err)
	}

	// Validate new config
	if err := newConfig.Validate(); err != nil {
		return fmt.Errorf("new config validation failed: %w", err)
	}

	// Compare with current config and update services
	if err := a.updateServicesFromConfig(newConfig); err != nil {
		return fmt.Errorf("failed to update services: %w", err)
	}

	// Update agent config
	a.mu.Lock()
	oldConfig := a.config
	a.config = newConfig
	a.mu.Unlock()

	log.Info("✅ Configuration reloaded successfully: %d services configured", len(newConfig.Services))

	// Log what changed
	a.logConfigChanges(oldConfig, newConfig)

	return nil
}

// updateServicesFromConfig compares old and new configs and updates services accordingly
func (a *Agent) updateServicesFromConfig(newConfig *AgentConfig) error {
	a.mu.RLock()
	currentServices := make(map[string]*common.ServiceConfig)
	for k, v := range a.services {
		currentServices[k] = v
	}
	a.mu.RUnlock()

	// Build map of new services for comparison
	newServices := make(map[string]*ServiceConfig)
	newServiceHosts := make(map[string]*ServiceConfig)

	for _, service := range newConfig.Services {
		newServices[service.ID] = &service
		for _, host := range service.GetAllHosts() {
			newServiceHosts[host] = &service
		}
	}

	// Track changes
	hostsToAdd := make(map[string]*ServiceConfig)
	hostsToUpdate := make(map[string]*ServiceConfig)
	hostsToRemove := make([]string, 0)

	// Find services to add or update
	for host, service := range newServiceHosts {
		if currentService, exists := currentServices[host]; exists {
			// Service exists, check if it needs updating
			newCommonService := a.convertToCommonServiceConfig(service, host)
			if !a.servicesEqual(currentService, newCommonService) {
				hostsToUpdate[host] = service
				log.Debug("🔄 Service %s needs update", host)
			}
		} else {
			// New service
			hostsToAdd[host] = service
			log.Debug("➕ New service: %s", host)
		}
	}

	// Find services to remove
	for host := range currentServices {
		if _, exists := newServiceHosts[host]; !exists {
			hostsToRemove = append(hostsToRemove, host)
			log.Debug("➖ Service to remove: %s", host)
		}
	}

	// Apply changes
	changeCount := 0

	// Remove services
	for _, host := range hostsToRemove {
		if err := a.removeService(host); err != nil {
			log.Error("❌ Failed to remove service %s: %v", host, err)
		} else {
			log.Info("➖ Removed service: %s", host)
			changeCount++
		}
	}

	// Add new services (with validation)
	for host, service := range hostsToAdd {
		// Validate service configuration for new services
		log.Debug("🔍 Validating new service configuration for host: %s", host)
		commonServiceToValidate := a.convertToCommonServiceConfig(service, host)
		typesServiceToValidate := convertCommonToTypes(commonServiceToValidate)
		validationResult := a.caddyValidator.ValidateServiceConfig(typesServiceToValidate)

		if !validationResult.Valid {
			var errorMessages []string
			for _, err := range validationResult.Errors {
				errorMessages = append(errorMessages, err.Error())
			}
			log.Error("❌ Validation failed for new service %s: %s", host, strings.Join(errorMessages, "; "))
			continue // Skip this service but continue with others
		}

		commonService := a.convertToCommonServiceConfig(service, host)
		if err := a.ConfigureService(commonService); err != nil {
			log.Error("❌ Failed to add service %s: %v", host, err)
		} else {
			// Store service config locally
			a.mu.Lock()
			a.services[host] = commonService
			a.mu.Unlock()
			log.Info("➕ Added service: %s -> %s", host, a.getPrimaryUpstream(service))
			changeCount++
		}
	}

	// Update existing services (with validation)
	for host, service := range hostsToUpdate {
		// IMPORTANT: Remove the old service from validator tracking temporarily
		// to avoid false hostname conflicts when validating the updated service
		a.caddyValidator.RemoveExistingService(host)

		// Validate service configuration for updated services
		log.Debug("🔍 Validating updated service configuration for host: %s", host)
		commonServiceToValidate := a.convertToCommonServiceConfig(service, host)
		typesServiceToValidate := convertCommonToTypes(commonServiceToValidate)
		validationResult := a.caddyValidator.ValidateServiceConfig(typesServiceToValidate)

		if !validationResult.Valid {
			var errorMessages []string
			for _, err := range validationResult.Errors {
				errorMessages = append(errorMessages, err.Error())
			}
			log.Error("❌ Validation failed for updated service %s: %s", host, strings.Join(errorMessages, "; "))

			// Re-add the old service back to validator tracking since validation failed
			if currentService, exists := currentServices[host]; exists {
				oldTypesService := convertCommonToTypes(currentService)
				a.caddyValidator.AddExistingService(host, oldTypesService)
			}
			continue // Skip this service but continue with others
		}

		commonService := a.convertToCommonServiceConfig(service, host)
		if err := a.ConfigureService(commonService); err != nil {
			log.Error("❌ Failed to update service %s: %v", host, err)

			// Re-add the old service back to validator tracking since update failed
			if currentService, exists := currentServices[host]; exists {
				oldTypesService := convertCommonToTypes(currentService)
				a.caddyValidator.AddExistingService(host, oldTypesService)
			}
		} else {
			// Store updated service config locally
			a.mu.Lock()
			a.services[host] = commonService
			a.mu.Unlock()

			// Add the new service to validator tracking (replaces the temporarily removed one)
			a.caddyValidator.AddExistingService(host, typesServiceToValidate)

			log.Info("🔄 Updated service: %s -> %s", host, a.getPrimaryUpstream(service))
			changeCount++
		}
	}

	if changeCount == 0 {
		log.Info("ℹ️  No service changes detected")
	} else {
		log.Info("✅ Applied %d service changes", changeCount)
	}

	return nil
}

// removeService removes a service from both local storage and server
func (a *Agent) removeService(hostname string) error {
	// Remove from local storage
	a.mu.Lock()
	delete(a.services, hostname)
	a.mu.Unlock()

	// Remove from validator tracking
	a.caddyValidator.RemoveExistingService(hostname)

	// Send remove message to server (if we have this functionality)
	// For now, we'll just log since the current protocol focuses on adding services
	log.Debug("🗑️  Service %s removed from local storage and validator tracking", hostname)

	return nil
}

// servicesEqual compares two service configurations for equality
func (a *Agent) servicesEqual(old, new *common.ServiceConfig) bool {
	return old.Hostname == new.Hostname &&
		old.Backend == new.Backend &&
		old.Protocol == new.Protocol &&
		old.WebSocket == new.WebSocket &&
		old.HTTPRedirect == new.HTTPRedirect &&
		old.ListenOn == new.ListenOn
}

// logConfigChanges logs what changed between configurations
func (a *Agent) logConfigChanges(oldConfig, newConfig *AgentConfig) {
	changes := make([]string, 0)

	// Check service count changes
	if len(oldConfig.Services) != len(newConfig.Services) {
		changes = append(changes, fmt.Sprintf("services: %d → %d", len(oldConfig.Services), len(newConfig.Services)))
	}

	// Check application logging configuration changes
	if a.shouldUpdateApplicationLogging(oldConfig.Logging, newConfig.Logging) {
		oldLoggingDesc := fmt.Sprintf("level=%s,format=%s,output=%s",
			oldConfig.Logging.Level, oldConfig.Logging.Format, oldConfig.Logging.Output)
		newLoggingDesc := fmt.Sprintf("level=%s,format=%s,output=%s",
			newConfig.Logging.Level, newConfig.Logging.Format, newConfig.Logging.Output)
		changes = append(changes, fmt.Sprintf("application_logging: %s → %s", oldLoggingDesc, newLoggingDesc))

		// Apply new logging configuration
		log.Info("🔧 Application logging configuration changed, updating logger...")
		applyLoggingConfig(newConfig.Logging)
		log.Info("✅ Application logging configuration updated successfully")
	}

	// Check legacy log level changes (deprecated but maintained for compatibility)
	if oldConfig.LogLevel != newConfig.LogLevel {
		changes = append(changes, fmt.Sprintf("legacy_log_level: %s → %s", oldConfig.LogLevel, newConfig.LogLevel))

		// Apply new log level only if new logging.level is not set
		if newConfig.LogLevel != "" && newConfig.Logging.Level == "" {
			logger.SetLogLevel(newConfig.LogLevel)
			log.Info("🔧 Legacy log level changed to: %s", newConfig.LogLevel)
		}
	}

	if len(changes) > 0 {
		log.Info("📝 Agent config changes: %s", strings.Join(changes, ", "))
	}
}

// shouldUpdateApplicationLogging checks if application logging configuration needs to be updated
func (a *Agent) shouldUpdateApplicationLogging(oldLogging, newLogging LoggingConfig) bool {
	// Check if logging level changed
	if oldLogging.Level != newLogging.Level {
		return true
	}

	// Check if logging format changed
	if oldLogging.Format != newLogging.Format {
		return true
	}

	// Check if logging output changed
	if oldLogging.Output != newLogging.Output {
		return true
	}

	return false
}

// mapsEqual compares two maps for equality
func mapsEqual(a, b map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}

	for k, v := range a {
		if bv, ok := b[k]; !ok || !interfaceEqual(v, bv) {
			return false
		}
	}

	return true
}

// interfaceEqual compares two interface{} values for equality
func interfaceEqual(a, b interface{}) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// Implement ConfigReloader interface for shared hot reload

// ReloadConfig implements the ConfigReloader interface
func (a *Agent) ReloadConfig() error {
	return a.reloadConfig()
}

// GetConfigPath implements the ConfigReloader interface
func (a *Agent) GetConfigPath() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config.ConfigPath
}

// IsHotReloadEnabled implements the ConfigReloader interface
func (a *Agent) IsHotReloadEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.config == nil {
		return false
	}
	return a.config.HotReload.Enabled
}

// GetComponentName implements the ConfigReloader interface
func (a *Agent) GetComponentName() string {
	return "agent"
}
