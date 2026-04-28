package ztrouter

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/modules/ztagents"
)

// handleDownloadStream streams chunks arriving on respCh to the client.
// The initial response carries the status/headers; subsequent http_response
// messages flow in through respCh as they are dispatched by the agent message
// handler. Go's http.Flusher path works for both HTTP/1.1 and HTTP/2.
func (h *Handler) handleDownloadStream(
	w http.ResponseWriter,
	r *http.Request,
	agent *ztagents.Agent,
	msgID string,
	initial *common.Message,
	respCh chan *common.Message,
) error {
	if flusher, ok := w.(http.Flusher); ok {
		return h.streamDownloadFlush(w, r, flusher, agent, msgID, initial, respCh)
	}
	http.Error(w, "Streaming not supported", http.StatusInternalServerError)
	return nil
}

func (h *Handler) streamDownloadFlush(
	w http.ResponseWriter,
	r *http.Request,
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

	// SSE connections send infrequent events; the default 60s inter-chunk
	// timeout kills them prematurely. Detect by Content-Type and use a
	// long sentinel timeout instead — the client disconnect (ctx.Done) or
	// a write error will terminate the loop in the normal case.
	isSSE := false
	if ct := initial.HTTP.Headers["Content-Type"]; len(ct) > 0 {
		isSSE = strings.Contains(strings.ToLower(ct[0]), "text/event-stream")
	}

	streamKind := "h2"
	if isSSE {
		streamKind = "h2/sse"
	}
	log.Info("ztrouter: download stream (%s) id=%s size=%d agent=%s",
		streamKind, msgID, initial.HTTP.TotalSize, agent.ID)

	timeoutCfg := h.timeoutCfg
	if timeoutCfg == nil {
		timeoutCfg = common.DefaultTimeouts()
	}
	var transferred int64
	var chunkIdx int

	writeChunk := func(chunk *common.Message) (bool, error) {
		if chunk == nil || chunk.HTTP == nil {
			return true, nil
		}
		if len(chunk.HTTP.Body) > 0 {
			if _, err := w.Write(chunk.HTTP.Body); err != nil {
				return false, fmt.Errorf("write chunk %d: %w", chunkIdx, err)
			}
			flusher.Flush()
			transferred += int64(len(chunk.HTTP.Body))
			chunkIdx++
		}
		if chunk.HTTP.IsLastChunk {
			log.Info("ztrouter: download stream (%s) done id=%s chunks=%d bytes=%d",
				streamKind, msgID, chunkIdx, transferred)
			return true, nil
		}
		return false, nil
	}

	for {
		if isSSE {
			select {
			case chunk, ok := <-respCh:
				if !ok {
					return nil
				}
				if done, err := writeChunk(chunk); done || err != nil {
					return err
				}
			case <-r.Context().Done():
				log.Debug("ztrouter: download stream (%s) cancelled by client id=%s chunks=%d bytes=%d",
					streamKind, msgID, chunkIdx, transferred)
				return nil
			}
		} else {
			dyn := common.CalculateStreamingTimeout(initial.HTTP.TotalSize, transferred, timeoutCfg)
			select {
			case chunk, ok := <-respCh:
				if !ok {
					return nil
				}
				if done, err := writeChunk(chunk); done || err != nil {
					return err
				}
			case <-time.After(dyn):
				return fmt.Errorf("timeout waiting for chunk %d after %v (received %d bytes)",
					chunkIdx+1, dyn, transferred)
			case <-r.Context().Done():
				log.Debug("ztrouter: download stream (%s) cancelled by client id=%s chunks=%d bytes=%d",
					streamKind, msgID, chunkIdx, transferred)
				return nil
			}
		}
	}
}
