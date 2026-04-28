package ztagents

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/logger"
	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

var log = logger.WithComponent("ztagents")

type App struct {
	ListenAddr string `json:"listen_addr,omitempty"`
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`
	CAFile     string `json:"ca_file,omitempty"`
	CheckAddr  string `json:"check_addr,omitempty"`

	rt *runtime
}

type runtime struct {
	tlsConfig   *tls.Config
	listener    net.Listener
	registry    *registry
	wsManager   *common.WebSocketManager
	checkServer *http.Server
	ctx         context.Context
	cancelCtx   context.CancelFunc
	wg          sync.WaitGroup
}

// New builds an App from the YAML config and provisions it.
// Returned App is ready to Start().
func New(cfg serverconfig.AgentsConfig) (*App, error) {
	a := &App{
		ListenAddr: cfg.Listen,
		CertFile:   cfg.CertFile,
		KeyFile:    cfg.KeyFile,
		CAFile:     cfg.CAFile,
		CheckAddr:  cfg.CheckAddr,
	}
	if err := a.provision(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *App) provision() error {
	if a.ListenAddr == "" {
		a.ListenAddr = ":8443"
	}

	rt := &runtime{
		registry:  newRegistry(),
		wsManager: common.NewWebSocketManager(),
	}
	rt.ctx, rt.cancelCtx = context.WithCancel(context.Background())
	a.rt = rt

	if a.CertFile == "" || a.KeyFile == "" || a.CAFile == "" {
		log.Debug("ztagents: certificate paths not set — Start will fail until config provides them")
		return nil
	}

	cfg, err := loadTLSConfig(a.CertFile, a.KeyFile, a.CAFile)
	if err != nil {
		return fmt.Errorf("ztagents: provision tls: %w", err)
	}
	rt.tlsConfig = cfg
	log.Info("ztagents: TLS configured (listen=%s)", a.ListenAddr)
	return nil
}

func (a *App) Validate() error {
	if a.CertFile == "" || a.KeyFile == "" || a.CAFile == "" {
		return fmt.Errorf("ztagents: cert_file, key_file and ca_file are required")
	}
	return nil
}

func (a *App) Start() error {
	listener, err := tls.Listen("tcp", a.ListenAddr, a.rt.tlsConfig)
	if err != nil {
		return fmt.Errorf("ztagents: listen %s: %w", a.ListenAddr, err)
	}
	a.rt.listener = listener

	log.Info("ztagents: listening on %s", a.ListenAddr)

	if err := a.startCheckServer(); err != nil {
		return fmt.Errorf("ztagents: start check server: %w", err)
	}

	a.rt.wg.Add(1)
	go a.acceptLoop()
	return nil
}

func (a *App) Stop() error {
	log.Info("ztagents: stopping")
	a.rt.cancelCtx()
	a.stopCheckServer()
	if a.rt.listener != nil {
		_ = a.rt.listener.Close()
	}
	for _, agent := range a.rt.registry.snapshot() {
		if agent.Conn != nil {
			_ = agent.Conn.Close()
		}
	}
	a.rt.wg.Wait()
	return nil
}

func (a *App) LookupAgent(host string) (*Agent, bool) {
	return a.rt.registry.lookupByHost(host)
}

// LookupService returns the agent serving host along with a copy of the
// service's on-wire config (e.g. for per-service timeout overrides).
func (a *App) LookupService(host string) (*Agent, *common.ServiceConfig, bool) {
	return a.rt.registry.lookupServiceByHost(host)
}

// AgentCount returns the number of registered agents.
func (a *App) AgentCount() int {
	return len(a.rt.registry.snapshot())
}

// RegisterWebSocket tracks a hijacked client connection for a WebSocket session.
// Called by the router after a successful WebSocket upgrade.
func (a *App) RegisterWebSocket(msgID string, clientConn net.Conn) {
	a.rt.wsManager.AddConnection(msgID, clientConn)
}

// UnregisterWebSocket removes and closes a tracked WebSocket session.
func (a *App) UnregisterWebSocket(msgID string) {
	a.rt.wsManager.RemoveConnection(msgID)
}

// WebSocketCount returns the number of active WebSocket sessions.
func (a *App) WebSocketCount() int {
	return a.rt.wsManager.GetConnectionCount()
}

// AgentServiceCounts returns a snapshot of agentID → number of registered
// services. Used by the metrics layer to populate the ztp_agent_services gauge.
func (a *App) AgentServiceCounts() map[string]int {
	agents := a.rt.registry.snapshot()
	counts := make(map[string]int, len(agents))
	for _, ag := range agents {
		ag.mu.RLock()
		counts[ag.ID] = len(ag.Services)
		ag.mu.RUnlock()
	}
	return counts
}

func (a *App) acceptLoop() {
	defer a.rt.wg.Done()
	for {
		conn, err := a.rt.listener.Accept()
		if err != nil {
			if a.rt.ctx.Err() != nil {
				return
			}
			log.Error("ztagents: accept: %v", err)
			categorizeAcceptError(err)
			continue
		}
		a.rt.wg.Add(1)
		go func(c net.Conn) {
			defer a.rt.wg.Done()
			a.handleAgentConnection(c)
		}(conn)
	}
}

func loadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("append CA certs")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func categorizeAcceptError(err error) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "too many open files"):
		log.Debug("ztagents: fd limit reached")
	case strings.Contains(msg, "certificate"):
		log.Debug("ztagents: client cert validation failed")
	case strings.Contains(msg, "remote error"):
		log.Debug("ztagents: client rejected server cert")
	}
}

