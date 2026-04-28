package zttcp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/google/uuid"
)

const (
	connectAckTimeout = 10 * time.Second
	readBufSize       = 32 * 1024
)

// serveService is the per-service accept loop, running in its own goroutine.
func (m *Manager) serveService(svc *tcpService) {
	for {
		conn, err := svc.listener.Accept()
		if err != nil {
			// listener.Close() triggers this; nothing to log beyond what
			// Release/ReleaseAll already logged.
			return
		}
		go m.handleNewConn(svc, conn)
	}
}

// handleNewConn handles a single new client connection for a TCP service.
func (m *Manager) handleNewConn(svc *tcpService, conn net.Conn) {
	if svc.tlsOffload {
		m.mu.Lock()
		tlsCfg := m.offloadTLS
		m.mu.Unlock()
		if tlsCfg == nil {
			log.Error("zttcp: TLS offload requested but no TLS config set for service %q", svc.hostname)
			_ = conn.Close()
			return
		}
		tlsConn := tls.Server(conn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			log.Debug("zttcp: TLS handshake failed for %q: %v", svc.hostname, err)
			_ = tlsConn.Close()
			return
		}
		conn = tlsConn
	}

	msgID := uuid.New().String()

	p := &pendingConn{
		conn:  conn,
		ackCh: make(chan error, 1),
	}
	m.pendingMu.Lock()
	m.pending[msgID] = p
	m.pendingMu.Unlock()

	msg := &common.Message{
		Type: "tcp_connect",
		ID:   msgID,
	}
	if err := svc.sender.SendMessage(msg); err != nil {
		log.Error("zttcp: send tcp_connect id=%s: %v", msgID, err)
		m.pendingMu.Lock()
		delete(m.pending, msgID)
		m.pendingMu.Unlock()
		_ = conn.Close()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), connectAckTimeout)
	defer cancel()

	var ackErr error
	select {
	case ackErr = <-p.ackCh:
	case <-ctx.Done():
		m.pendingMu.Lock()
		delete(m.pending, msgID)
		m.pendingMu.Unlock()
		log.Error("zttcp: tcp_connect_ack timeout id=%s hostname=%s", msgID, svc.hostname)
		_ = conn.Close()
		return
	}

	if ackErr != nil {
		log.Debug("zttcp: agent rejected tcp_connect id=%s: %v", msgID, ackErr)
		_ = conn.Close()
		return
	}

	m.connsMu.Lock()
	m.conns[msgID] = &connEntry{
		conn:     conn,
		agentID:  svc.agentID,
		hostname: svc.hostname,
	}
	m.connsMu.Unlock()

	log.Debug("zttcp: relay started id=%s hostname=%s remote=%s", msgID, svc.hostname, conn.RemoteAddr())
	m.relayClientToAgent(msgID, conn, svc.sender)

	// Relay finished: client closed or error. Notify agent.
	m.connsMu.Lock()
	_, stillActive := m.conns[msgID]
	if stillActive {
		delete(m.conns, msgID)
	}
	m.connsMu.Unlock()

	if stillActive {
		_ = conn.Close()
		_ = svc.sender.SendMessage(&common.Message{
			Type: "tcp_disconnect",
			ID:   msgID,
		})
	}
}

// relayClientToAgent reads bytes from the client and forwards them as
// tcp_data messages to the agent. It returns when the client closes the
// connection or an unrecoverable read error occurs.
func (m *Manager) relayClientToAgent(msgID string, conn net.Conn, sender MessageSender) {
	buf := make([]byte, readBufSize)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			sendErr := sender.SendMessage(&common.Message{
				Type: "tcp_data",
				ID:   msgID,
				TCP:  &common.TCPData{Data: chunk},
			})
			if sendErr != nil {
				log.Debug("zttcp: send tcp_data id=%s: %v", msgID, sendErr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Debug("zttcp: client read id=%s: %v", msgID, err)
			}
			return
		}
	}
}

