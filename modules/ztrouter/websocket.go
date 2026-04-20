package ztrouter

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/modules/ztagents"
)

func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		if strings.Contains(strings.ToLower(v), "upgrade") {
			return true
		}
	}
	return false
}

// handleWebSocketUpgrade writes the 101 response to the hijacked conn, registers
// the conn with the app for agent→client frame delivery, and spawns a client→agent
// relay goroutine. Returns after the relay finishes (client disconnect or read error).
func (h *Handler) handleWebSocketUpgrade(
	w http.ResponseWriter,
	agent *ztagents.Agent,
	msgID string,
	resp *common.Message,
) error {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket upgrade not supported", http.StatusInternalServerError)
		return nil
	}

	clientConn, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed: "+err.Error(), http.StatusInternalServerError)
		return nil
	}

	upgradeResp := &http.Response{
		StatusCode: resp.HTTP.StatusCode,
		Status:     resp.HTTP.StatusMessage,
		Header:     resp.HTTP.Headers,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	if upgradeResp.StatusCode == 0 {
		upgradeResp.StatusCode = http.StatusSwitchingProtocols
	}

	// Register before writing the 101 so agent→client frames that arrive
	// immediately after the handshake have a destination.
	h.app.RegisterWebSocket(msgID, clientConn)

	if err := upgradeResp.Write(clientConn); err != nil {
		h.app.UnregisterWebSocket(msgID)
		_ = clientConn.Close()
		return fmt.Errorf("write upgrade response: %w", err)
	}
	if bufrw != nil {
		_ = bufrw.Writer.Flush()
	}
	log.Info("ztrouter: ws upgraded id=%s agent=%s", msgID, agent.ID)

	h.relayClientFrames(clientConn, bufrw, agent, msgID)
	return nil
}

func (h *Handler) relayClientFrames(clientConn net.Conn, bufrw *bufio.ReadWriter, agent *ztagents.Agent, msgID string) {
	defer func() {
		h.app.UnregisterWebSocket(msgID)
		_ = agent.SendMessage(&common.Message{Type: "websocket_disconnect", ID: msgID})
		_ = clientConn.Close()
		log.Info("ztrouter: ws closed id=%s agent=%s", msgID, agent.ID)
	}()

	var reader io.Reader = clientConn
	if bufrw != nil && bufrw.Reader != nil && bufrw.Reader.Buffered() > 0 {
		reader = io.MultiReader(bufrw.Reader, clientConn)
	}

	buf := make([]byte, 16384)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			frame := make([]byte, n)
			copy(frame, buf[:n])
			msg := &common.Message{
				Type: "websocket_frame",
				ID:   msgID,
				HTTP: &common.HTTPData{Body: frame, IsWebSocket: true},
			}
			if err := agent.SendMessage(msg); err != nil {
				log.Error("ztrouter: ws send to agent: %v", err)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Debug("ztrouter: ws client read: %v", err)
			}
			return
		}
	}
}
