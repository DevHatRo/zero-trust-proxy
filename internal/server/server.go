package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/agent"
	"github.com/devhatro/zero-trust-proxy/internal/caddy"
	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/logger"
	"github.com/google/uuid"
)

// Server represents the main server
type Server struct {
	listenAddr       string
	apiAddr          string
	tlsConfig        *tls.Config
	agents           map[string]*Agent
	mu               sync.RWMutex
	caddyAdminAPI    string
	caddyManager     *caddy.Manager
	caddyProcess     *os.Process
	responseHandlers sync.Map
	certFile         string
	keyFile          string
	caFile           string
	cert             tls.Certificate
	caCertPool       *x509.CertPool
	// WebSocket connections tracking with health monitoring
	wsManager *common.WebSocketManager
	// Configuration management
	config   *ServerConfig
	configMu sync.RWMutex
	// Hot reload management
	hotReloadManager *common.HotReloadManager
}

// Config holds the server configuration
type Config struct {
	ListenAddr     string
	CertFile       string
	KeyFile        string
	CAFile         string
	AllowedDomains []string
}

// Agent represents a connected agent
type Agent struct {
	ID               string
	Conn             net.Conn
	writeMu          sync.Mutex // Protects concurrent writes to connection
	readMu           sync.Mutex // Protects concurrent reads from connection
	ResponseHandlers map[string]func(*common.Message)
	Services         map[string]*common.ServiceConfig
	Registered       bool
	mu               sync.RWMutex
}

// Message types
const (
	MessageTypePing  = "ping"
	MessageTypePong  = "pong"
	MessageTypeProxy = "proxy"
)

// Message represents a message between agent and server
type Message struct {
	Type    string `json:"type"`
	AgentID string `json:"agent_id"`
}

// NewServerWithConfig creates a new server using configuration struct
func NewServerWithConfig(config *ServerConfig) *Server {
	s := &Server{
		listenAddr:       config.Server.ListenAddr,
		apiAddr:          config.API.ListenAddr,
		certFile:         config.Server.CertFile,
		keyFile:          config.Server.KeyFile,
		caFile:           config.Server.CAFile,
		caddyAdminAPI:    config.Caddy.AdminAPI,
		agents:           make(map[string]*Agent),
		config:           config,
		hotReloadManager: common.NewHotReloadManager(),
	}
	return s
}

// Start starts the server
func (s *Server) Start() error {
	logger.Info("🚀 Starting 0Trust server...")

	// Load certificates
	cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		return fmt.Errorf("❌ failed to load certificate: %v", err)
	}

	// Load CA certificate
	caCert, err := os.ReadFile(s.caFile)
	if err != nil {
		return fmt.Errorf("❌ failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("❌ failed to append CA certificate")
	}

	// Store certificates
	s.cert = cert
	s.caCertPool = caCertPool

	logger.Info("🔐 SSL certificates loaded successfully")

	// Initialize WebSocket manager
	s.wsManager = common.NewWebSocketManager()

	// Initialize CaddyManager
	s.caddyManager = caddy.NewManager("http://localhost:2019")
	logger.Info("⚙️  Caddy manager initialized")

	// Start Caddy
	if err := s.startCaddy(); err != nil {
		return fmt.Errorf("❌ failed to start Caddy: %v", err)
	}

	// Start shared hot reload system
	logger.Info("🔥 Starting shared hot reload system")
	if err := s.hotReloadManager.RegisterReloader(s); err != nil {
		logger.Error("❌ Failed to register server hot reload: %v", err)
	}

	// Start WebSocket health monitoring
	logger.Info("🔌 Starting WebSocket health monitoring")
	s.startWebSocketHealthMonitoring()

	logger.Info("🌐 Server listening on %s (API on %s)", s.listenAddr, s.apiAddr)

	// Start both API servers (this will block and handle all connections)
	return s.startAPIServer()
}

// startCaddy starts the Caddy server
func (s *Server) startCaddy() error {
	logger.Info("🚀 Starting Caddy reverse proxy...")

	// Kill any existing Caddy processes
	exec.Command("pkill", "caddy").Run()

	// Create /config directory structure for certificates
	configDir := "/config/caddy"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		logger.Info("⚠️  Could not create %s directory (may not have permissions), using default storage: %v", configDir, err)
		configDir = "" // Use default storage
	} else {
		logger.Info("📁 Using custom certificate storage: %s", configDir)
	}

	// Create initial Caddy config with custom storage
	config := map[string]interface{}{
		"admin": map[string]interface{}{
			"disabled": false,
			"listen":   "localhost:2019",
		},
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen": []string{":80", ":443"},
						"routes": []map[string]interface{}{
							{
								"handle": []map[string]interface{}{
									{
										"handler": "static_response",
										"body":    "Caddy is running",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Add custom storage configuration if we have permissions
	if configDir != "" {
		config["storage"] = map[string]interface{}{
			"module": "file_system",
			"root":   configDir,
		}
	}

	// Write config to temporary file
	configFile := "/tmp/caddy.json"
	configData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("❌ failed to marshal Caddy config: %v", err)
	}
	if err := os.WriteFile(configFile, configData, 0644); err != nil {
		return fmt.Errorf("❌ failed to write Caddy config: %v", err)
	}

	logger.Debug("📄 Caddy configuration written to %s", configFile)

	// Start Caddy process
	cmd := exec.Command("caddy", "run", "--config", configFile)
	cmd.Stdout = os.Stdout // See Caddy's output
	cmd.Stderr = os.Stderr // See Caddy's errors

	// Detach Caddy process so it keeps running independently
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("❌ failed to start Caddy: %v", err)
	}

	logger.Info("🔄 Caddy process started, waiting for API to be ready...")

	// Wait for Caddy to start
	for i := 0; i < 10; i++ {
		logger.Debug("⏱️  Waiting for Caddy to start on %s (attempt %d/10): ", s.caddyAdminAPI, i+1)
		// Use the correct URL with trailing slash and follow redirects
		resp, err := http.Get(s.caddyAdminAPI + "/config/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				logger.Info("✅ Caddy started successfully")
				return nil
			}
		}
		time.Sleep(time.Second)
	}

	// If we get here, Caddy failed to start
	cmd.Process.Kill()
	return fmt.Errorf("⏰ timeout waiting for Caddy to start")
}

// handleAgentConnection handles a new agent connection
func (s *Server) handleAgentConnection(conn net.Conn) {
	defer conn.Close()

	// Read initial message to get agent ID
	var msg common.Message
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&msg); err != nil {
		logger.Error("❌ Failed to read initial message: %v", err)
		return
	}

	if msg.Type != "register" {
		logger.Error("❌ Invalid initial message type: %s", msg.Type)
		return
	}

	agentID := msg.ID
	if agentID == "" {
		logger.Error("❌ Missing agent ID in registration message")
		return
	}

	// Create new agent
	agent := NewAgent(agentID, conn)

	// Add agent to map
	s.mu.Lock()
	s.agents[agentID] = agent
	totalAgents := len(s.agents)
	s.mu.Unlock()

	// Send registration response
	response := &common.Message{
		Type: "register_response",
		ID:   agentID,
	}
	if err := agent.SendMessage(response); err != nil {
		logger.Error("❌ Failed to send registration response: %v", err)
		return
	}

	logger.Info("🔗 Agent %s connected (Total: %d)", agentID, totalAgents)

	// Handle messages from agent
	for {
		var msg common.Message

		// Lock to prevent concurrent reads from the TLS connection
		agent.readMu.Lock()
		err := decoder.Decode(&msg)
		agent.readMu.Unlock()

		if err != nil {
			logger.Error("❌ Failed to read message from agent %s: %v", agentID, err)
			break
		}

		// Use local agent variable instead of map lookup to avoid race condition
		if err := s.handleAgentMessage(agent, &msg); err != nil {
			logger.Error("❌ Failed to handle message from agent %s: %v", agentID, err)
			break
		}
	}

	// Remove agent when connection is closed
	s.mu.Lock()
	delete(s.agents, agentID)
	remainingAgents := len(s.agents)
	s.mu.Unlock()

	logger.Info("📤 Agent %s disconnected (Remaining: %d)", agentID, remainingAgents)
}

// GetAgent returns an agent by ID
func (s *Server) GetAgent(id string) *Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.agents[id]
}

// sendMessage sends a message to an agent
func (s *Server) sendMessage(agent *Agent, msg *common.Message) error {
	if agent.Conn == nil {
		return fmt.Errorf("agent not connected")
	}

	// Lock to prevent concurrent writes to the TLS connection
	agent.writeMu.Lock()
	defer agent.writeMu.Unlock()

	// Calculate adaptive write timeout using shared utilities
	timeoutConfig := common.DefaultTimeouts()
	writeTimeout := common.CalculateWriteTimeout(msg, timeoutConfig)

	// Set write deadline with adaptive timeout
	if err := agent.Conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %v", err)
	}

	// Send message (now protected by mutex)
	if err := json.NewEncoder(agent.Conn).Encode(msg); err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	return nil
}

// handleAPIRequest handles an incoming API request
func (s *Server) handleAPIRequest(conn net.Conn) {
	defer conn.Close()

	// Create a buffered reader for the connection
	reader := bufio.NewReader(conn)

	// Read the HTTP request
	req, err := http.ReadRequest(reader)
	if err != nil {
		logger.Error("❌ Failed to read API request: %v", err)
		return
	}

	// Extract the Host header
	host := req.Host
	if host == "" {
		logger.Error("❌ Missing Host header in API request")
		// Create a response writer
		resp := &http.Response{
			StatusCode: http.StatusBadRequest,
			Status:     "Missing Host header",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		resp.Write(conn)
		return
	}

	logger.Debug("🌐 Handling API request for host: %s, path: %s", host, req.URL.Path)

	// Find the agent responsible for this host
	s.mu.RLock()
	var targetAgent *Agent
	for _, agent := range s.agents {
		if _, ok := agent.Services[host]; ok {
			targetAgent = agent
			break
		}
	}
	s.mu.RUnlock()

	if targetAgent == nil {
		logger.Error("❌ No agent found for host: %s", host)
		// Create a response writer
		resp := &http.Response{
			StatusCode: http.StatusNotFound,
			Status:     "No agent found for this host",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		resp.Write(conn)
		return
	}

	logger.Debug("🔗 Found agent %s for host %s", targetAgent.ID, host)

	// Read request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		logger.Error("❌ Failed to read request body: %v", err)
		// Create a response writer
		resp := &http.Response{
			StatusCode: http.StatusInternalServerError,
			Status:     "Failed to read request body",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		resp.Write(conn)
		return
	}

	// Create HTTP request message
	msgID := uuid.New().String()
	httpMsg := &common.Message{
		Type: "http_request",
		ID:   msgID,
		HTTP: &common.HTTPData{
			Method:  req.Method,
			URL:     req.URL.Path + "?" + req.URL.RawQuery, // Include query parameters
			Headers: make(map[string][]string),
			Body:    body,
		},
	}

	// Copy headers from the original request
	for key, values := range req.Header {
		httpMsg.HTTP.Headers[key] = values
	}

	// Ensure Host header is set
	httpMsg.HTTP.Headers["Host"] = []string{host}

	logger.Debug("📨 Forwarding %s %s to agent %s (ID: %s)", req.Method, req.URL.Path, targetAgent.ID, msgID[:8]+"...")

	// Create a channel to receive the response - use larger buffer for streaming
	var responseChan chan *common.Message

	// Use larger channel for potential streaming, but implement proper backpressure
	responseChan = make(chan *common.Message, 50)

	// Set up response handler with proper backpressure (blocking sends)
	targetAgent.mu.Lock()
	targetAgent.ResponseHandlers[msgID] = func(msg *common.Message) {
		// Use blocking send with timeout to implement backpressure
		// This will naturally slow down the agent to match server consumption rate
		select {
		case responseChan <- msg:
			// Successfully queued
		case <-time.After(30 * time.Second):
			// If we can't send within 30 seconds, the connection is likely dead
			logger.Error("⏰ Timeout sending response for ID: %s, connection may be dead", msgID)
		}
	}
	targetAgent.mu.Unlock()

	// Clean up handler when done
	defer func() {
		targetAgent.mu.Lock()
		delete(targetAgent.ResponseHandlers, msgID)
		targetAgent.mu.Unlock()
		close(responseChan) // Close channel to prevent goroutine leaks
	}()

	// Send request to agent with connection check
	if err := targetAgent.SendMessage(httpMsg); err != nil {
		logger.Error("❌ Failed to send request to agent %s: %v", targetAgent.ID, err)

		// Remove the agent if send failed (likely disconnected)
		s.mu.Lock()
		delete(s.agents, targetAgent.ID)
		s.mu.Unlock()

		logger.Info("🗑️  Removed disconnected agent: %s", targetAgent.ID)

		// Create a response writer
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "Agent disconnected",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		resp.Write(conn)
		return
	}

	// Wait for response with timeout
	select {
	case response := <-responseChan:
		if response.Error != "" {
			logger.Error("❌ Agent returned error: %s", response.Error)
			// Create a response writer
			resp := &http.Response{
				StatusCode: http.StatusInternalServerError,
				Status:     response.Error,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
			}
			resp.Write(conn)
			return
		}

		// Write response back to client
		if response.HTTP == nil {
			logger.Error("❌ Invalid response from agent: missing HTTP data")
			// Create a response writer
			resp := &http.Response{
				StatusCode: http.StatusInternalServerError,
				Status:     "Invalid response from agent",
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
			}
			resp.Write(conn)
			return
		}

		// If this is a WebSocket upgrade response, handle specially
		if response.HTTP.IsWebSocket {
			logger.Debug("🔌 Handling WebSocket upgrade response for ID: %s", msgID)

			// Write WebSocket upgrade response headers
			resp := &http.Response{
				StatusCode: response.HTTP.StatusCode,
				Status:     response.HTTP.StatusMessage,
				Header:     response.HTTP.Headers,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
			}

			// Write response (this completes the WebSocket handshake)
			if err := resp.Write(conn); err != nil {
				logger.Error("❌ Failed to write WebSocket upgrade response: %v", err)
				return
			}

			logger.Info("🎉 WebSocket upgrade completed for ID: %s", msgID)

			// Store the client connection for WebSocket frame relay
			s.wsManager.AddConnection(msgID, conn)

			// Start client → agent relay (client frames to agent)
			go func() {
				defer func() {
					// Clean up the stored connection with proper cleanup
					s.wsManager.RemoveConnection(msgID)
					totalConnections := s.wsManager.GetConnectionCount()

					// Notify agent that client disconnected so it can cleanup its side
					disconnectMsg := &common.Message{
						Type: "websocket_disconnect",
						ID:   msgID,
					}
					if err := s.sendMessage(targetAgent, disconnectMsg); err != nil {
						logger.Debug("⚠️  Failed to notify agent of WebSocket disconnect: %v", err)
					}

					logger.Info("🔌 WebSocket client disconnected, notified agent: ID=%s, Remaining=%d",
						msgID[:8]+"...", totalConnections)
				}()

				logger.Debug("🔄 Starting client→agent relay for WebSocket ID: %s", msgID)

				buffer := make([]byte, 16384) // 16KB buffer for better performance

				for {
					// WebSocket connections should not have read timeouts, health is managed separately
					// This prevents "i/o timeout" errors that break legitimate long-lived connections

					n, err := conn.Read(buffer)
					if err != nil {
						if err != io.EOF {
							logger.Error("❌ Error reading from client: %v", err)
						} else {
							logger.Debug("📞 Client closed WebSocket connection")
						}
						return
					}

					if n > 0 {
						// Update activity in our health monitoring system
						s.wsManager.UpdateActivity(msgID)

						logger.Debug("📤 Relaying %d bytes from client to agent", n)

						// Send WebSocket frame to agent through message system with exact buffer copy
						frameData := make([]byte, n)
						copy(frameData, buffer[:n])

						frameMsg := &common.Message{
							Type: "websocket_frame",
							ID:   msgID,
							HTTP: &common.HTTPData{
								Body:        frameData,
								IsWebSocket: true,
							},
						}

						if err := s.sendMessage(targetAgent, frameMsg); err != nil {
							logger.Error("❌ Failed to send WebSocket frame to agent: %v", err)
							return
						}
					}
				}
			}()

			// Keep the main goroutine alive for this connection
			// The client→agent relay goroutine will handle cleanup when done
			select {}
		}

		// If this is a streaming response, handle with flow control
		if response.HTTP.IsStream {
			logger.Info("📡 Starting streaming response for large file: %d bytes", response.HTTP.TotalSize)

			// Prepare proper HTTP headers for browser compatibility
			headers := make(http.Header)

			// Copy original headers
			for key, values := range response.HTTP.Headers {
				headers[key] = values
			}

			// Set essential headers for browser download progress
			headers.Set("Content-Length", fmt.Sprintf("%d", response.HTTP.TotalSize))

			// Ensure proper content-type
			contentType := headers.Get("Content-Type")
			if contentType == "" {
				contentType = "application/octet-stream" // Default for downloads
			}
			headers.Set("Content-Type", contentType)

			// Support range requests for proper download behavior
			headers.Set("Accept-Ranges", "bytes")

			// Add headers that help browsers show proper download progress
			headers.Set("Cache-Control", "public, max-age=0")
			headers.Set("Connection", "keep-alive")

			// Don't set Content-Range for full downloads (only for 206 Partial Content)
			// Content-Range causes Chrome to show "Resuming..." for 200 OK responses

			// Remove headers that can interfere with streaming
			headers.Del("Transfer-Encoding")
			headers.Del("Content-Encoding") // Remove if present to avoid confusion

			// Write HTTP status line
			fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n", response.HTTP.StatusCode, response.HTTP.StatusMessage)

			// Write headers manually for better control
			for key, values := range headers {
				for _, value := range values {
					fmt.Fprintf(conn, "%s: %s\r\n", key, value)
				}
			}

			// End headers section
			fmt.Fprintf(conn, "\r\n")

			// Implement flow control for streaming - process chunks one at a time
			chunkCount := 0
			totalReceived := int64(0)
			lastProgressTime := time.Now()

			for {
				// Calculate dynamic timeout based on file size and progress using shared utilities
				timeoutConfig := common.DefaultTimeouts()
				timeoutDur := common.CalculateStreamingTimeout(response.HTTP.TotalSize, totalReceived, timeoutConfig)

				// Wait for next chunk with dynamic timeout
				select {
				case chunk, ok := <-responseChan:
					if !ok {
						// Channel was closed, we're done
						logger.Info("📊 Streaming completed: channel closed after %d chunks, %d bytes", chunkCount, totalReceived)
						return
					}

					if chunk == nil || chunk.HTTP == nil {
						logger.Debug("📄 Received nil chunk, ending stream")
						return
					}

					chunkCount++
					chunkSize := int64(len(chunk.HTTP.Body))
					totalReceived += chunkSize

					// Write chunk data directly (no HTTP framing)
					if _, err := conn.Write(chunk.HTTP.Body); err != nil {
						// Client disconnected, stop processing
						logger.Debug("📞 Client disconnected during streaming at chunk %d", chunkCount)
						return
					}

					// Log progress with transfer rate for better monitoring
					now := time.Now()
					if now.Sub(lastProgressTime) > 5*time.Second || chunk.HTTP.IsLastChunk {
						progress := float64(totalReceived) / float64(response.HTTP.TotalSize) * 100
						elapsed := now.Sub(lastProgressTime)
						if elapsed > 0 {
							rate := float64(chunkSize*int64(chunkCount%1000)) / elapsed.Seconds() / (1024 * 1024) // MB/s for recent chunks
							eta := time.Duration(0)
							if rate > 0 && response.HTTP.TotalSize > totalReceived {
								remainingBytes := float64(response.HTTP.TotalSize - totalReceived)
								eta = time.Duration(remainingBytes/rate/1024/1024) * time.Second
							}

							logger.Info("📈 Streaming progress: %.1f%% (%d chunks, %d MB, %.2f MB/s, ETA: %v)",
								progress, chunkCount, totalReceived/(1024*1024), rate, eta.Round(time.Second))
						} else {
							logger.Info("📊 Streaming progress: %.1f%% (%d chunks, %d MB)",
								progress, chunkCount, totalReceived/(1024*1024))
						}
						lastProgressTime = now
					}

					// If this was the last chunk, we're done
					if chunk.HTTP.IsLastChunk {
						logger.Info("✅ Streaming completed successfully: %d chunks, %d bytes total", chunkCount, totalReceived)

						// Verify we sent the expected amount
						if totalReceived != response.HTTP.TotalSize && response.HTTP.TotalSize > 0 {
							logger.Warn("⚠️  Size mismatch: sent %d bytes, expected %d bytes", totalReceived, response.HTTP.TotalSize)
						}

						return
					}

				case <-time.After(timeoutDur):
					// Timeout waiting for next chunk
					logger.Error("⏰ Timeout waiting for chunk %d after %v (received %d bytes)",
						chunkCount+1, timeoutDur, totalReceived)
					return
				}
			}
		} else {
			// Handle normal response
			resp := &http.Response{
				StatusCode:    response.HTTP.StatusCode,
				Status:        response.HTTP.StatusMessage,
				Header:        response.HTTP.Headers,
				Body:          io.NopCloser(bytes.NewReader(response.HTTP.Body)),
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				ContentLength: int64(len(response.HTTP.Body)),
			}

			// Ensure content-length is set correctly
			if resp.Header.Get("Content-Length") == "" {
				resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(response.HTTP.Body)))
			}

			// Write response
			if err := resp.Write(conn); err != nil {
				logger.Error("❌ Failed to write response: %v", err)
				return
			}
		}

	case <-time.After(2 * time.Minute):
		logger.Error("⏰ Timeout waiting for initial agent response")
		// Create a response writer
		resp := &http.Response{
			StatusCode: http.StatusGatewayTimeout,
			Status:     "Timeout waiting for agent response",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		resp.Write(conn)
		return
	}
}

// handleAgentMessage handles messages from agents
func (s *Server) handleAgentMessage(agent *Agent, msg *common.Message) error {
	// Defensive programming: check for nil agent
	if agent == nil {
		return fmt.Errorf("❌ agent is nil")
	}

	// Defensive programming: check for nil message
	if msg == nil {
		return fmt.Errorf("❌ message is nil")
	}

	logger.Debug("📨 Received message type: %s from agent %s", msg.Type, agent.ID)

	switch msg.Type {
	case "register":
		// Handle registration
		if agent.Registered {
			logger.Debug("✅ Agent %s already registered", agent.ID)
			return nil
		}

		// Register agent
		agent.Registered = true
		logger.Info("📋 Agent %s registered", agent.ID)

		// Send registration response
		response := &common.Message{
			Type: "register_response",
			ID:   msg.ID,
		}
		if err := s.sendMessage(agent, response); err != nil {
			return fmt.Errorf("❌ failed to send registration response: %v", err)
		}

	case "service_add":
		// Handle service add request
		if msg.Service == nil && msg.EnhancedService == nil {
			return fmt.Errorf("❌ service configuration missing")
		}

		var hostname string
		var isEnhanced bool

		// Determine which configuration to use
		if msg.EnhancedService != nil {
			hostname = msg.EnhancedService.Hostname
			isEnhanced = true
			logger.Info("🌐 Enhanced service add request received for host: %s with %d upstreams",
				hostname, len(msg.EnhancedService.Upstreams))
		} else {
			hostname = msg.Service.Hostname
			logger.Info("🌐 Simple service add request received for host: %s", hostname)
		}

		// Store service configuration (use simple format for agent Services map)
		if msg.Service != nil {
			agent.Services[hostname] = msg.Service
		} else {
			// Create simple service config from enhanced for backward compatibility
			simpleConfig := &common.ServiceConfig{
				Hostname:  msg.EnhancedService.Hostname,
				Backend:   "127.0.0.1:9443", // Always points to server's internal API
				Protocol:  msg.EnhancedService.Protocol,
				WebSocket: msg.EnhancedService.WebSocket, // Copy WebSocket flag
			}
			agent.Services[hostname] = simpleConfig
		}

		// Add service to Caddy using the appropriate method
		if isEnhanced {
			// Convert common.EnhancedServiceConfig to agent.ServiceConfig for Caddy manager
			agentServiceConfig := s.convertCommonToAgentServiceConfig(msg.EnhancedService)
			if err := s.caddyManager.AddEnhancedService(agentServiceConfig); err != nil {
				return fmt.Errorf("❌ failed to add enhanced service to Caddy: %v", err)
			}

			// Log the configuration details
			redirectStatus := "disabled"
			if msg.EnhancedService.HTTPRedirect {
				redirectStatus = "enabled"
			}
			listenOn := msg.EnhancedService.ListenOn
			if listenOn == "" {
				listenOn = "both"
			}
			logger.Info("✅ Enhanced service %s added to Caddy successfully with %d upstreams, HTTP redirect: %s, Listen on: %s",
				hostname, len(msg.EnhancedService.Upstreams), redirectStatus, listenOn)
		} else {
			// Use full service configuration for simple services too
			if err := s.caddyManager.AddFullServiceConfig(
				msg.Service.Hostname,
				msg.Service.Backend,
				msg.Service.Protocol,
				msg.Service.WebSocket,
				msg.Service.HTTPRedirect,
				msg.Service.ListenOn); err != nil {
				return fmt.Errorf("❌ failed to add service to Caddy: %v", err)
			}

			// Log the configuration details
			redirectStatus := "disabled"
			if msg.Service.HTTPRedirect {
				redirectStatus = "enabled"
			}
			listenOn := msg.Service.ListenOn
			if listenOn == "" {
				listenOn = "both"
			}
			logger.Info("✅ Simple service %s added to Caddy successfully, HTTP redirect: %s, Listen on: %s",
				hostname, redirectStatus, listenOn)
		}

		// Send service add response
		response := &common.Message{
			Type: "service_add_response",
			ID:   msg.ID,
		}
		if err := s.sendMessage(agent, response); err != nil {
			return fmt.Errorf("❌ failed to send service add response: %v", err)
		}

	case "service_update":
		// Handle service update
		if msg.Service == nil {
			return fmt.Errorf("❌ service configuration missing")
		}

		// Update service configuration
		agent.Services[msg.Service.Hostname] = msg.Service

		// Update service in Caddy with full configuration support
		if err := s.caddyManager.AddFullServiceConfig(
			msg.Service.Hostname,
			msg.Service.Backend,
			msg.Service.Protocol,
			msg.Service.WebSocket,
			msg.Service.HTTPRedirect,
			msg.Service.ListenOn); err != nil {
			return fmt.Errorf("❌ failed to update service in Caddy: %v", err)
		}

		logger.Info("🔄 Service %s updated in Caddy successfully", msg.Service.Hostname)

		// Send service update response
		response := &common.Message{
			Type: "service_update_response",
			ID:   msg.ID,
		}
		if err := s.sendMessage(agent, response); err != nil {
			return fmt.Errorf("❌ failed to send service update response: %v", err)
		}

	case "service_remove":
		// Handle service remove
		if msg.Service == nil {
			return fmt.Errorf("❌ service configuration missing")
		}

		// Remove service configuration
		delete(agent.Services, msg.Service.Hostname)

		// Remove service from Caddy
		if err := s.caddyManager.RemoveService(msg.Service.Hostname); err != nil {
			return fmt.Errorf("❌ failed to remove service from Caddy: %v", err)
		}

		logger.Info("🗑️  Service %s removed from Caddy successfully", msg.Service.Hostname)

		// Send service remove response
		response := &common.Message{
			Type: "service_remove_response",
			ID:   msg.ID,
		}
		if err := s.sendMessage(agent, response); err != nil {
			return fmt.Errorf("❌ failed to send service remove response: %v", err)
		}

	case "ping":
		// Handle ping
		response := &common.Message{
			Type: "pong",
			ID:   msg.ID,
		}
		if err := s.sendMessage(agent, response); err != nil {
			return fmt.Errorf("❌ failed to send pong response: %v", err)
		}
		logger.Debug("💓 Pong sent to agent %s", agent.ID)

	case "http_response":
		// Handle HTTP response
		if msg.HTTP == nil {
			return fmt.Errorf("❌ HTTP data missing")
		}

		// Get response handler from agent
		agent.mu.Lock()
		handler, ok := agent.ResponseHandlers[msg.ID]
		agent.mu.Unlock()
		if !ok {
			// Don't treat missing response handlers as fatal errors - they could be late responses
			// after timeouts or cleanup. Just log and continue to keep the agent connected.
			logger.Debug("🔍 No response handler found for message ID: %s (possibly timed out or cleaned up)", msg.ID)
			return nil
		}

		// Call handler - no acknowledgments needed since TCP provides reliability
		handler(msg)

	case "websocket_frame":
		// Handle WebSocket frame from agent (backend → client)
		if msg.HTTP == nil || len(msg.HTTP.Body) == 0 {
			return nil
		}

		// Find the client connection for this WebSocket session
		wsConn, exists := s.wsManager.GetConnection(msg.ID)

		if !exists {
			logger.Debug("🔍 WebSocket frame dropped - client connection not found: ID=%s", msg.ID[:8]+"...")
			return nil
		}

		// Validate connection is still active
		if wsConn == nil || wsConn.GetConn() == nil {
			logger.Warn("⚠️  WebSocket frame dropped - nil client connection: ID=%s", msg.ID[:8]+"...")
			s.wsManager.RemoveConnection(msg.ID)
			return nil
		}

		// Update activity timestamp
		wsConn.UpdateActivity()

		// Forward the frame data to the client atomically
		data := msg.HTTP.Body
		totalWritten := 0

		for totalWritten < len(data) {
			n, err := wsConn.GetConn().Write(data[totalWritten:])
			if err != nil {
				logger.Error("❌ Failed to write WebSocket frame to client (ID=%s): %v", msg.ID[:8]+"...", err)
				// Connection is broken, clean it up
				s.wsManager.RemoveConnection(msg.ID)
				totalConnections := s.wsManager.GetConnectionCount()

				// Notify agent that client connection is broken
				disconnectMsg := &common.Message{
					Type: "websocket_disconnect",
					ID:   msg.ID,
				}
				if err := s.sendMessage(agent, disconnectMsg); err != nil {
					logger.Debug("❌ Failed to notify agent of broken WebSocket connection: %v", err)
				}

				wsConn.Close()
				logger.Info("🗑️  Removed broken client WebSocket connection: ID=%s, Remaining=%d",
					msg.ID[:8]+"...", totalConnections)
				return nil
			}
			totalWritten += n
		}

		logger.Debug("📦 Forwarded %d bytes from agent to client for WebSocket ID: %s", len(data), msg.ID)

	default:
		return fmt.Errorf("❓ unknown message type: %s", msg.Type)
	}

	return nil
}

// NewAgent creates a new agent
func NewAgent(id string, conn net.Conn) *Agent {
	return &Agent{
		ID:               id,
		Conn:             conn,
		ResponseHandlers: make(map[string]func(*common.Message)),
		Services:         make(map[string]*common.ServiceConfig),
	}
}

// SetResponseHandler sets a response handler for a message ID
func (a *Agent) SetResponseHandler(msgID string, handler func(*common.Message)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ResponseHandlers[msgID] = handler
}

// SendMessage sends a message to the agent
func (a *Agent) SendMessage(msg *common.Message) error {
	if a.Conn == nil {
		return fmt.Errorf("agent not connected")
	}

	// Lock to prevent concurrent writes to the TLS connection
	a.writeMu.Lock()
	defer a.writeMu.Unlock()

	// Calculate adaptive write timeout using shared utilities
	timeoutConfig := common.DefaultTimeouts()
	writeTimeout := common.CalculateWriteTimeout(msg, timeoutConfig)

	// Set write deadline with adaptive timeout
	if err := a.Conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %v", err)
	}

	encoder := json.NewEncoder(a.Conn)
	return encoder.Encode(msg)
}

// Stop stops the server
func (s *Server) Stop() error {
	logger.Info("🛑 Stopping 0Trust server...")

	// Stop Caddy process if running
	if s.caddyProcess != nil {
		if err := s.caddyProcess.Kill(); err != nil {
			logger.Error("❌ Failed to kill Caddy process: %v", err)
		} else {
			logger.Info("✅ Caddy process stopped")
		}
	}

	// Close all agent connections
	s.mu.Lock()
	agentCount := len(s.agents)
	for agentID, agent := range s.agents {
		if err := agent.Conn.Close(); err != nil {
			logger.Error("❌ Failed to close agent connection %s: %v", agentID, err)
		}
	}
	s.mu.Unlock()

	logger.Info("📤 Closed %d agent connections", agentCount)
	logger.Info("✅ Server stopped successfully")
	return nil
}

// startAPIServer starts the API server
func (s *Server) startAPIServer() error {
	logger.Info("🚀 Starting API servers...")

	// Start both agent API (with client certs) and HTTP proxy API (without client certs)
	go s.startAgentAPIServer()
	go s.startHTTPProxyServer()

	// Keep the main goroutine alive
	select {}
}

// startAgentAPIServer starts the API server for agent connections (requires client certificates)
func (s *Server) startAgentAPIServer() error {
	// Create TLS configuration requiring client certificates for agents
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		ClientCAs:    s.caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	// Start agent API listener on port 8443
	listener, err := tls.Listen("tcp", s.listenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("❌ failed to start agent API listener: %v", err)
	}
	defer listener.Close()

	logger.Info("🔗 Agent API server listening on %s", s.listenAddr)

	// Accept agent connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("❌ Failed to accept agent connection: %v", err)
			continue
		}
		go s.handleAgentConnection(conn)
	}
}

// startHTTPProxyServer starts the HTTP proxy server for Caddy connections (no client certificates required)
func (s *Server) startHTTPProxyServer() error {
	// Create TLS configuration without requiring client certificates for HTTP proxy
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		ClientAuth:   tls.NoClientCert, // No client certificate required for HTTP proxy
		MinVersion:   tls.VersionTLS12,
	}

	// Start HTTP proxy listener on port 9443
	listener, err := tls.Listen("tcp", s.apiAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("❌ failed to start HTTP proxy listener: %v", err)
	}
	defer listener.Close()

	logger.Info("🌐 HTTP proxy server listening on %s", s.apiAddr)

	// Accept HTTP proxy connections from Caddy
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("❌ Failed to accept HTTP proxy connection: %v", err)
			continue
		}
		go s.handleAPIRequest(conn)
	}
}

// convertCommonToAgentServiceConfig converts common.EnhancedServiceConfig to agent.ServiceConfig
func (s *Server) convertCommonToAgentServiceConfig(commonConfig *common.EnhancedServiceConfig) *agent.ServiceConfig {
	agentConfig := &agent.ServiceConfig{
		ID:           commonConfig.ID,
		Name:         commonConfig.Name,
		Hostname:     commonConfig.Hostname,
		Protocol:     commonConfig.Protocol,
		WebSocket:    commonConfig.WebSocket,
		HTTPRedirect: commonConfig.HTTPRedirect, // Copy HTTP redirect setting
		ListenOn:     commonConfig.ListenOn,     // Copy protocol binding setting
	}

	// Convert upstreams
	for _, upstream := range commonConfig.Upstreams {
		agentUpstream := agent.UpstreamConfig{
			Address: upstream.Address,
			Weight:  upstream.Weight,
		}

		// Convert health check if present
		if upstream.HealthCheck != nil {
			agentUpstream.HealthCheck = &agent.HealthCheckConfig{
				Path:    upstream.HealthCheck.Path,
				Method:  upstream.HealthCheck.Method,
				Headers: upstream.HealthCheck.Headers,
			}

			// Parse duration strings
			if upstream.HealthCheck.Interval != "" {
				if interval, err := time.ParseDuration(upstream.HealthCheck.Interval); err == nil {
					agentUpstream.HealthCheck.Interval = interval
				}
			}
			if upstream.HealthCheck.Timeout != "" {
				if timeout, err := time.ParseDuration(upstream.HealthCheck.Timeout); err == nil {
					agentUpstream.HealthCheck.Timeout = timeout
				}
			}
		}

		agentConfig.Upstreams = append(agentConfig.Upstreams, agentUpstream)
	}

	// Convert load balancing config if present
	if commonConfig.LoadBalancing != nil {
		agentConfig.LoadBalancing = &agent.LoadBalancingConfig{
			Policy:              commonConfig.LoadBalancing.Policy,
			HealthCheckRequired: commonConfig.LoadBalancing.HealthCheckRequired,
			SessionAffinity:     commonConfig.LoadBalancing.SessionAffinity,
		}
		if commonConfig.LoadBalancing.AffinityDuration != "" {
			if duration, err := time.ParseDuration(commonConfig.LoadBalancing.AffinityDuration); err == nil {
				agentConfig.LoadBalancing.AffinityDuration = duration
			}
		}
	}

	// Convert routes
	for _, route := range commonConfig.Routes {
		agentRoute := agent.RouteConfig{
			Match: agent.MatchConfig{
				Path:    route.Match.Path,
				Method:  route.Match.Method,
				Headers: route.Match.Headers,
				Query:   route.Match.Query,
			},
		}

		// Convert middleware handlers
		for _, handler := range route.Handle {
			agentHandler := agent.MiddlewareConfig{
				Type:   handler.Type,
				Config: handler.Config,
			}
			agentRoute.Handle = append(agentRoute.Handle, agentHandler)
		}

		agentConfig.Routes = append(agentConfig.Routes, agentRoute)
	}

	// Convert TLS config if present
	if commonConfig.TLS != nil {
		agentConfig.TLS = &agent.TLSConfig{
			CertFile:     commonConfig.TLS.CertFile,
			KeyFile:      commonConfig.TLS.KeyFile,
			CAFile:       commonConfig.TLS.CAFile,
			MinVersion:   commonConfig.TLS.MinVersion,
			Ciphers:      commonConfig.TLS.Ciphers,
			ClientAuth:   commonConfig.TLS.ClientAuth,
			ClientCAFile: commonConfig.TLS.ClientCAFile,
		}
	}

	// Convert security config if present
	if commonConfig.Security != nil {
		agentConfig.Security = &agent.SecurityConfig{}

		if commonConfig.Security.CORS != nil {
			agentConfig.Security.CORS = &agent.CORSConfig{
				Origins: commonConfig.Security.CORS.Origins,
				Methods: commonConfig.Security.CORS.Methods,
				Headers: commonConfig.Security.CORS.Headers,
			}
		}

		if commonConfig.Security.Auth != nil {
			agentConfig.Security.Auth = &agent.AuthConfig{
				Type:   commonConfig.Security.Auth.Type,
				Config: commonConfig.Security.Auth.Config,
			}
		}
	}

	// Convert monitoring config if present
	if commonConfig.Monitoring != nil {
		agentConfig.Monitoring = &agent.MonitoringConfig{
			MetricsEnabled: commonConfig.Monitoring.MetricsEnabled,
		}

		// Use simplified logging configuration (no nested struct)
		if commonConfig.Monitoring.Logging != nil {
			agentConfig.Monitoring.LoggingFormat = commonConfig.Monitoring.Logging.Format
			agentConfig.Monitoring.LoggingFields = commonConfig.Monitoring.Logging.Fields
		}
	}

	// Convert traffic shaping config if present
	if commonConfig.TrafficShaping != nil {
		agentConfig.TrafficShaping = &agent.TrafficShapingConfig{
			UploadLimit:   commonConfig.TrafficShaping.UploadLimit,
			DownloadLimit: commonConfig.TrafficShaping.DownloadLimit,
			PerIPLimit:    commonConfig.TrafficShaping.PerIPLimit,
		}
	}

	return agentConfig
}

// startWebSocketHealthMonitoring starts background WebSocket health monitoring for the server
func (s *Server) startWebSocketHealthMonitoring() {
	go func() {
		// Clean up stale connections every 2 minutes
		cleanupTicker := time.NewTicker(2 * time.Minute)
		defer cleanupTicker.Stop()

		// Report connection statistics every 5 minutes
		statsTicker := time.NewTicker(5 * time.Minute)
		defer statsTicker.Stop()

		logger.Debug("🔌 Server WebSocket health monitoring started")

		for {
			select {
			case <-cleanupTicker.C:
				s.cleanupStaleWebSocketConnections()
			case <-statsTicker.C:
				s.logWebSocketStats()
			}
		}
	}()
}

// cleanupStaleWebSocketConnections removes stale WebSocket connections that are no longer active
func (s *Server) cleanupStaleWebSocketConnections() {
	s.wsManager.CleanupStaleConnections()
}

// logWebSocketStats logs WebSocket connection statistics
func (s *Server) logWebSocketStats() {
	total, healthy, stale := s.wsManager.GetStats()
	if total > 0 {
		logger.Info("📊 Server WebSocket Stats: Total=%d, Healthy=%d, Stale=%d", total, healthy, stale)
	}
}

// Implement ConfigReloader interface for shared hot reload

// ReloadConfig implements the ConfigReloader interface
func (s *Server) ReloadConfig() error {
	s.configMu.RLock()
	configPath := s.config.ConfigPath
	s.configMu.RUnlock()

	logger.Info("🔄 Reloading server configuration from %s", configPath)

	// Load new config
	newConfig, err := LoadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load new server config: %w", err)
	}

	// Update server configuration
	s.configMu.Lock()
	oldConfig := s.config
	s.config = newConfig
	s.configMu.Unlock()

	// Apply configuration changes
	if err := s.applyConfigChanges(oldConfig, newConfig); err != nil {
		return fmt.Errorf("failed to apply config changes: %w", err)
	}

	logger.Info("✅ Server configuration reloaded successfully")

	// Log what changed
	s.logConfigChanges(oldConfig, newConfig)

	return nil
}

// GetConfigPath implements the ConfigReloader interface
func (s *Server) GetConfigPath() string {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.config.ConfigPath
}

// IsHotReloadEnabled implements the ConfigReloader interface
func (s *Server) IsHotReloadEnabled() bool {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	if s.config == nil {
		return false
	}
	return s.config.HotReload.Enabled
}

// GetComponentName implements the ConfigReloader interface
func (s *Server) GetComponentName() string {
	return "server"
}

// applyConfigChanges applies configuration changes to the running server
func (s *Server) applyConfigChanges(oldConfig, newConfig *ServerConfig) error {
	// Check for log level changes
	if oldConfig.LogLevel != newConfig.LogLevel {
		if newConfig.LogLevel != "" {
			logger.SetLogLevel(newConfig.LogLevel)
			logger.Info("🔧 Server log level changed to: %s", newConfig.LogLevel)
		}
	}

	// Check for Caddy admin API changes
	if oldConfig.Caddy.AdminAPI != newConfig.Caddy.AdminAPI {
		logger.Info("🔧 Caddy admin API address changed: %s -> %s", oldConfig.Caddy.AdminAPI, newConfig.Caddy.AdminAPI)
		s.caddyAdminAPI = newConfig.Caddy.AdminAPI
		// Note: This would require restarting Caddy for full effect
		logger.Warn("⚠️  Caddy admin API change requires server restart for full effect")
	}

	// Note: TLS certificate changes and port changes would require a server restart
	// For now, we log warnings about these changes
	if oldConfig.Server.CertFile != newConfig.Server.CertFile ||
		oldConfig.Server.KeyFile != newConfig.Server.KeyFile ||
		oldConfig.Server.CAFile != newConfig.Server.CAFile {
		logger.Warn("⚠️  TLS certificate changes detected - server restart required for full effect")
	}

	if oldConfig.Server.ListenAddr != newConfig.Server.ListenAddr ||
		oldConfig.API.ListenAddr != newConfig.API.ListenAddr {
		logger.Warn("⚠️  Listen address changes detected - server restart required for full effect")
	}

	return nil
}

// logConfigChanges logs what changed between server configurations
func (s *Server) logConfigChanges(oldConfig, newConfig *ServerConfig) {
	changes := make([]string, 0)

	// Check for changes
	if oldConfig.LogLevel != newConfig.LogLevel {
		changes = append(changes, fmt.Sprintf("log_level: %s → %s", oldConfig.LogLevel, newConfig.LogLevel))
	}

	if oldConfig.Caddy.AdminAPI != newConfig.Caddy.AdminAPI {
		changes = append(changes, fmt.Sprintf("caddy_admin_api: %s → %s", oldConfig.Caddy.AdminAPI, newConfig.Caddy.AdminAPI))
	}

	if len(changes) > 0 {
		logger.Info("📝 Server config changes: %s", fmt.Sprintf("[%s]", fmt.Sprintf("%v", changes)))
	}
}
