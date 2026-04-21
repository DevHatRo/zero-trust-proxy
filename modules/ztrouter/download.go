package ztrouter

import (
	"fmt"
	"net/http"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/streaming"
	"github.com/devhatro/zero-trust-proxy/modules/ztagents"
)

// handleDownloadStream streams chunks arriving on respCh to the client. The
// initial response carries the status/headers; subsequent http_response
// messages flow in through respCh as they are dispatched by the agent message
// handler.
//
// Under HTTP/1.1 we hijack the client connection so the streaming library can
// write the response directly. Under HTTP/2 the ResponseWriter does not
// implement http.Hijacker — h2 framing handles chunking natively, so we use
// http.Flusher to push each chunk instead.
func (h *Handler) handleDownloadStream(
	w http.ResponseWriter,
	agent *ztagents.Agent,
	msgID string,
	initial *common.Message,
	respCh chan *common.Message,
) error {
	if hijacker, ok := w.(http.Hijacker); ok {
		return h.streamDownloadHijack(w, hijacker, agent, msgID, initial, respCh)
	}
	if flusher, ok := w.(http.Flusher); ok {
		return h.streamDownloadFlush(w, flusher, agent, msgID, initial, respCh)
	}
	http.Error(w, "Streaming not supported", http.StatusInternalServerError)
	return nil
}

func (h *Handler) streamDownloadHijack(
	w http.ResponseWriter,
	hijacker http.Hijacker,
	agent *ztagents.Agent,
	msgID string,
	initial *common.Message,
	respCh chan *common.Message,
) error {
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed: "+err.Error(), http.StatusInternalServerError)
		return nil
	}
	defer clientConn.Close()

	log.Info("ztrouter: download stream (h1) id=%s size=%d agent=%s",
		msgID, initial.HTTP.TotalSize, agent.ID)

	streamer := streaming.NewStreamingHandler()
	defer streamer.Close()
	if err := streamer.HandleDownloadToConnection(msgID, clientConn, respCh, initial, agent); err != nil {
		log.Error("ztrouter: download stream id=%s: %v", msgID, err)
		return fmt.Errorf("download stream: %w", err)
	}
	return nil
}

func (h *Handler) streamDownloadFlush(
	w http.ResponseWriter,
	flusher http.Flusher,
	agent *ztagents.Agent,
	msgID string,
	initial *common.Message,
	respCh chan *common.Message,
) error {
	dst := w.Header()
	for k, v := range initial.HTTP.Headers {
		dst[k] = v
	}
	dst.Del("Transfer-Encoding")
	dst.Del("Connection")

	status := initial.HTTP.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	flusher.Flush()

	log.Info("ztrouter: download stream (h2) id=%s size=%d agent=%s",
		msgID, initial.HTTP.TotalSize, agent.ID)

	timeoutCfg := common.DefaultTimeouts()
	var transferred int64
	var chunkIdx int
	for {
		dyn := common.CalculateStreamingTimeout(initial.HTTP.TotalSize, transferred, timeoutCfg)
		select {
		case chunk, ok := <-respCh:
			if !ok {
				return nil
			}
			if chunk == nil || chunk.HTTP == nil {
				return nil
			}
			if len(chunk.HTTP.Body) > 0 {
				if _, err := w.Write(chunk.HTTP.Body); err != nil {
					return fmt.Errorf("write chunk %d: %w", chunkIdx, err)
				}
				flusher.Flush()
				transferred += int64(len(chunk.HTTP.Body))
				chunkIdx++
			}
			if chunk.HTTP.IsLastChunk {
				log.Info("ztrouter: download stream (h2) done id=%s chunks=%d bytes=%d",
					msgID, chunkIdx, transferred)
				return nil
			}
		case <-time.After(dyn):
			return fmt.Errorf("timeout waiting for chunk %d after %v (received %d bytes)",
				chunkIdx+1, dyn, transferred)
		}
	}
}
