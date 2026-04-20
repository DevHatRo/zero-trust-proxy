package ztrouter

import (
	"fmt"
	"net/http"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/streaming"
	"github.com/devhatro/zero-trust-proxy/modules/ztagents"
)

// handleDownloadStream hijacks the client connection and streams chunks arriving
// on respCh directly to it. The initial response carries the status/headers and
// is passed into the streaming library; subsequent http_response messages flow
// in through respCh as they are dispatched by the agent message handler.
func (h *Handler) handleDownloadStream(
	w http.ResponseWriter,
	agent *ztagents.Agent,
	msgID string,
	initial *common.Message,
	respCh chan *common.Message,
) error {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return nil
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed: "+err.Error(), http.StatusInternalServerError)
		return nil
	}
	defer clientConn.Close()

	log.Info("ztrouter: download stream id=%s size=%d agent=%s",
		msgID, initial.HTTP.TotalSize, agent.ID)

	streamer := streaming.NewStreamingHandler()
	defer streamer.Close()
	if err := streamer.HandleDownloadToConnection(msgID, clientConn, respCh, initial, agent); err != nil {
		log.Error("ztrouter: download stream id=%s: %v", msgID, err)
		return fmt.Errorf("download stream: %w", err)
	}
	return nil
}
