package ztagents

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

func (a *App) handleAgentConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)

	var initial common.Message
	if err := decoder.Decode(&initial); err != nil {
		if isExpectedConnError(err) {
			log.Debug("ztagents: rejected pre-auth connection: %v", err)
		} else {
			log.Error("ztagents: read initial message: %v", err)
		}
		return
	}
	if initial.Type != "register" {
		log.Error("ztagents: first message must be register, got %s", initial.Type)
		return
	}
	if initial.ID == "" {
		log.Error("ztagents: missing agent ID in register")
		return
	}

	agent := NewAgent(initial.ID, conn)
	total := a.rt.registry.add(agent)

	ack := &common.Message{Type: "register_response", ID: agent.ID}
	if err := agent.SendMessage(ack); err != nil {
		log.Error("ztagents: send register_response: %v", err)
		a.rt.registry.remove(agent.ID)
		return
	}
	log.Info("ztagents: agent %s connected (total=%d)", agent.ID, total)

	for {
		var msg common.Message
		agent.readMu.Lock()
		err := decoder.Decode(&msg)
		agent.readMu.Unlock()
		if err != nil {
			log.Error("ztagents: read from %s: %v", agent.ID, err)
			break
		}
		if err := a.handleAgentMessage(agent, &msg); err != nil {
			log.Error("ztagents: handle message from %s: %v", agent.ID, err)
			break
		}
	}

	remaining := a.rt.registry.remove(agent.ID)
	a.rt.tcpManager.ReleaseAgent(agent.ID)
	log.Info("ztagents: agent %s disconnected (remaining=%d)", agent.ID, remaining)
}

func (a *App) handleAgentMessage(agent *Agent, msg *common.Message) error {
	if agent == nil {
		return fmt.Errorf("agent is nil")
	}
	if msg == nil {
		return fmt.Errorf("message is nil")
	}

	log.Debug("ztagents: recv %s from %s", msg.Type, agent.ID)

	switch msg.Type {
	case "register":
		agent.mu.Lock()
		alreadyRegistered := agent.Registered
		agent.Registered = true
		agent.mu.Unlock()
		if alreadyRegistered {
			return nil
		}
		return agent.SendMessage(&common.Message{Type: "register_response", ID: msg.ID})

	case "service_add":
		if msg.Service == nil {
			return fmt.Errorf("service config missing")
		}
		hostname := msg.Service.Hostname
		agent.mu.Lock()
		agent.Services[hostname] = msg.Service
		agent.mu.Unlock()
		log.Info("ztagents: service_add host=%s agent=%s", hostname, agent.ID)
		resp := &common.Message{Type: "service_add_response", ID: msg.ID}
		if msg.Service.Protocol == "tcp" {
			port, err := a.rt.tcpManager.Allocate(
				msg.Service.TCPPort, agent.ID, hostname, msg.Service.TLSOffload, agent,
			)
			if err != nil {
				resp.Error = err.Error()
				log.Error("ztagents: TCP allocate for %s: %v", hostname, err)
			} else {
				resp.Service = &common.ServiceConfig{}
				*resp.Service = *msg.Service
				resp.Service.TCPPort = port
			}
		}
		return agent.SendMessage(resp)

	case "service_update":
		if msg.Service == nil {
			return fmt.Errorf("service config missing")
		}
		agent.mu.Lock()
		agent.Services[msg.Service.Hostname] = msg.Service
		agent.mu.Unlock()
		log.Info("ztagents: service_update host=%s agent=%s", msg.Service.Hostname, agent.ID)
		return agent.SendMessage(&common.Message{Type: "service_update_response", ID: msg.ID})

	case "service_remove":
		if msg.Service == nil {
			return fmt.Errorf("service config missing")
		}
		hostname := msg.Service.Hostname
		agent.mu.Lock()
		svc, hasSvc := agent.Services[hostname]
		delete(agent.Services, hostname)
		agent.mu.Unlock()
		if hasSvc && svc != nil && svc.Protocol == "tcp" {
			a.rt.tcpManager.Release(hostname)
		}
		log.Info("ztagents: service_remove host=%s agent=%s", hostname, agent.ID)
		return agent.SendMessage(&common.Message{Type: "service_remove_response", ID: msg.ID})

	case "ping":
		return agent.SendMessage(&common.Message{Type: "pong", ID: msg.ID})

	case "http_response":
		handler, ok := agent.GetResponseHandler(msg.ID)
		if !ok {
			log.Debug("ztagents: no handler for response id=%s", msg.ID)
			return nil
		}
		handler(msg)
		return nil

	case "websocket_frame":
		if msg.HTTP == nil || len(msg.HTTP.Body) == 0 {
			return nil
		}
		wsc, ok := a.rt.wsManager.GetConnection(msg.ID)
		if !ok {
			log.Debug("ztagents: ws frame dropped — no client for id=%s", msg.ID)
			return nil
		}
		wsc.UpdateActivity()
		conn := wsc.GetConn()
		if conn == nil {
			a.rt.wsManager.RemoveConnection(msg.ID)
			return nil
		}
		if _, err := writeAll(conn, msg.HTTP.Body); err != nil {
			log.Error("ztagents: ws write client: %v", err)
			a.rt.wsManager.RemoveConnection(msg.ID)
			_ = agent.SendMessage(&common.Message{Type: "websocket_disconnect", ID: msg.ID})
		}
		return nil

	case "websocket_disconnect":
		a.rt.wsManager.RemoveConnection(msg.ID)
		return nil

	case "tcp_connect_ack":
		a.rt.tcpManager.HandleConnectAck(msg.ID, msg.Error)
		return nil

	case "tcp_data":
		if msg.TCP == nil {
			return nil
		}
		if err := a.rt.tcpManager.WriteToClient(msg.ID, msg.TCP.Data); err != nil {
			log.Debug("ztagents: tcp_data write id=%s: %v", msg.ID, err)
		}
		return nil

	case "tcp_disconnect":
		a.rt.tcpManager.CloseClient(msg.ID)
		return nil

	default:
		log.Debug("ztagents: unknown message type %s from %s", msg.Type, agent.ID)
		return nil
	}
}

// isExpectedConnError returns true for TLS rejections and connection resets
// that are routine on a public mTLS port (port scanners, health checks,
// clients without a certificate). These are noise, not server errors.
func isExpectedConnError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.HasPrefix(msg, "tls:") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "EOF")
}

func writeAll(w interface {
	Write(p []byte) (int, error)
}, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := w.Write(data[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
