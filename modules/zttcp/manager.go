// Package zttcp manages public TCP listeners for agents that register
// services with protocol=="tcp". Each service gets its own listener bound
// to the port the agent requested (or a free port when 0 is given).
package zttcp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/logger"
)

var log = logger.WithComponent("zttcp")

// MessageSender is satisfied by *ztagents.Agent — defined here to avoid
// the circular import that a direct reference would create.
type MessageSender interface {
	SendMessage(msg *common.Message) error
}

// Manager owns all public TCP listeners. It is safe for concurrent use.
type Manager struct {
	mu         sync.Mutex
	services   map[string]*tcpService  // hostname → service
	portToHost map[int]string          // bound port → hostname (conflict guard)
	conns      map[string]*connEntry   // msgID → active client connection
	connsMu    sync.RWMutex
	pending    map[string]*pendingConn // msgID → waiting for tcp_connect_ack
	pendingMu  sync.Mutex
	offloadTLS *tls.Config
	portMin    int
	portMax    int
}

type tcpService struct {
	agentID    string
	hostname   string
	port       int
	listener   net.Listener
	tlsOffload bool
	sender     MessageSender
}

type connEntry struct {
	conn     net.Conn
	agentID  string
	hostname string
}

type pendingConn struct {
	conn  net.Conn
	ackCh chan error // receives nil on success, non-nil on failure
}

// NewManager returns an empty Manager.
func NewManager() *Manager {
	return &Manager{
		services:   make(map[string]*tcpService),
		portToHost: make(map[int]string),
		conns:      make(map[string]*connEntry),
		pending:    make(map[string]*pendingConn),
	}
}

// SetOffloadTLS sets the TLS config used when a service has TLSOffload=true.
func (m *Manager) SetOffloadTLS(cfg *tls.Config) {
	m.mu.Lock()
	m.offloadTLS = cfg
	m.mu.Unlock()
}

// SetPortRange restricts which ports agents may request. Both values 0
// means unrestricted.
func (m *Manager) SetPortRange(min, max int) {
	m.mu.Lock()
	m.portMin = min
	m.portMax = max
	m.mu.Unlock()
}

// Allocate binds a public TCP port for a service and starts the accept
// loop. Returns the actual bound port (useful when requestedPort==0).
func (m *Manager) Allocate(requestedPort int, agentID, hostname string, tlsOffload bool, sender MessageSender) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.portMin > 0 && m.portMax > 0 && requestedPort != 0 {
		if requestedPort < m.portMin || requestedPort > m.portMax {
			return 0, fmt.Errorf("port %d outside allowed range [%d, %d]", requestedPort, m.portMin, m.portMax)
		}
	}

	addr := fmt.Sprintf(":%d", requestedPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("bind %s: %w", addr, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	if existing, conflict := m.portToHost[port]; conflict {
		_ = ln.Close()
		return 0, fmt.Errorf("port %d already in use by service %q", port, existing)
	}

	svc := &tcpService{
		agentID:    agentID,
		hostname:   hostname,
		port:       port,
		listener:   ln,
		tlsOffload: tlsOffload,
		sender:     sender,
	}
	m.services[hostname] = svc
	m.portToHost[port] = hostname

	go m.serveService(svc)
	log.Info("zttcp: bound :%d for service %q (agent=%s, offload=%v)", port, hostname, agentID, tlsOffload)
	return port, nil
}

// Release closes the listener for a service and tears down any active
// client connections routed to it.
func (m *Manager) Release(hostname string) {
	m.mu.Lock()
	svc, ok := m.services[hostname]
	if ok {
		delete(m.services, hostname)
		delete(m.portToHost, svc.port)
	}
	m.mu.Unlock()

	if !ok {
		return
	}
	_ = svc.listener.Close()
	log.Info("zttcp: released :%d for service %q", svc.port, hostname)
	m.closeConnsForAgent(svc.agentID, hostname)
}

// ReleaseAgent releases all services and connections belonging to an agent.
func (m *Manager) ReleaseAgent(agentID string) {
	m.mu.Lock()
	var toRelease []*tcpService
	for _, svc := range m.services {
		if svc.agentID == agentID {
			toRelease = append(toRelease, svc)
		}
	}
	for _, svc := range toRelease {
		delete(m.services, svc.hostname)
		delete(m.portToHost, svc.port)
		_ = svc.listener.Close()
	}
	m.mu.Unlock()

	for _, svc := range toRelease {
		log.Info("zttcp: released :%d for service %q (agent disconnect)", svc.port, svc.hostname)
		m.closeConnsForAgent(agentID, svc.hostname)
	}
}

// ReleaseAll tears down every listener and connection.
func (m *Manager) ReleaseAll() {
	m.mu.Lock()
	svcs := make([]*tcpService, 0, len(m.services))
	for _, svc := range m.services {
		svcs = append(svcs, svc)
	}
	m.services = make(map[string]*tcpService)
	m.portToHost = make(map[int]string)
	m.mu.Unlock()

	for _, svc := range svcs {
		_ = svc.listener.Close()
	}
	m.connsMu.Lock()
	for _, e := range m.conns {
		_ = e.conn.Close()
	}
	m.conns = make(map[string]*connEntry)
	m.connsMu.Unlock()
}

// HandleConnectAck is called by ztagents when a tcp_connect_ack message
// arrives from the agent. A non-empty errStr signals the agent could not
// reach the backend.
func (m *Manager) HandleConnectAck(msgID, errStr string) {
	m.pendingMu.Lock()
	p, ok := m.pending[msgID]
	if ok {
		delete(m.pending, msgID)
	}
	m.pendingMu.Unlock()

	if !ok {
		return
	}
	if errStr != "" {
		p.ackCh <- errors.New(errStr)
		return
	}
	p.ackCh <- nil
}

// WriteToClient writes data to an active client connection identified by msgID.
func (m *Manager) WriteToClient(msgID string, data []byte) error {
	m.connsMu.RLock()
	e, ok := m.conns[msgID]
	m.connsMu.RUnlock()
	if !ok {
		return fmt.Errorf("no client conn for id=%s", msgID)
	}
	_, err := e.conn.Write(data)
	return err
}

// CloseClient closes an active client connection and removes it from the map.
func (m *Manager) CloseClient(msgID string) {
	m.connsMu.Lock()
	e, ok := m.conns[msgID]
	if ok {
		delete(m.conns, msgID)
	}
	m.connsMu.Unlock()
	if ok {
		_ = e.conn.Close()
	}
}

// closeConnsForAgent closes all client connections that belong to the
// given agentID (and optionally filtered by hostname when non-empty).
func (m *Manager) closeConnsForAgent(agentID, hostname string) {
	m.connsMu.Lock()
	var toClose []string
	for id, e := range m.conns {
		if e.agentID == agentID && (hostname == "" || e.hostname == hostname) {
			toClose = append(toClose, id)
		}
	}
	for _, id := range toClose {
		_ = m.conns[id].conn.Close()
		delete(m.conns, id)
	}
	m.connsMu.Unlock()
}
