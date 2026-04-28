package ztrouter

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/logger"
	"github.com/devhatro/zero-trust-proxy/internal/streaming"
	"github.com/devhatro/zero-trust-proxy/modules/ztagents"
)

var log = logger.WithComponent("ztrouter")

type Handler struct {
	RequestTimeout time.Duration `json:"request_timeout,omitempty"`

	app        *ztagents.App
	timeoutCfg *common.TimeoutConfig // nil → common.DefaultTimeouts(); set in tests
}

// SetApp injects the ztagents App directly. Intended for tests; production code
// constructs the handler via New.
func (h *Handler) SetApp(app *ztagents.App) { h.app = app }

// New builds a Handler. requestTimeout==0 falls back to 2m.
func New(app *ztagents.App, requestTimeout time.Duration) *Handler {
	if requestTimeout == 0 {
		requestTimeout = 2 * time.Minute
	}
	return &Handler{
		RequestTimeout: requestTimeout,
		app:            app,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		http.Error(w, "Missing Host header", http.StatusBadRequest)
		return
	}

	agent, svc, ok := h.app.LookupService(host)
	if !ok {
		log.Debug("ztrouter: no agent for host=%s", host)
		http.Error(w, "No agent for host "+host, http.StatusServiceUnavailable)
		return
	}
	if ri := common.RequestInfoFrom(r.Context()); ri != nil {
		ri.AgentID = agent.ID
	}

	requestTimeout := h.RequestTimeout
	if svc != nil && svc.Timeout > 0 {
		requestTimeout = svc.Timeout
	}

	isWS := isWebSocketUpgrade(r)
	streamUpload := !isWS && streaming.ShouldStreamUpload(r.ContentLength)

	msgID := uuid.New().String()
	headers := make(map[string][]string, len(r.Header)+1)
	for k, v := range r.Header {
		headers[k] = v
	}
	headers["Host"] = []string{host}

	respCh := make(chan *common.Message, 16)
	var closed int32
	agent.SetResponseHandler(msgID, func(m *common.Message) {
		if atomic.LoadInt32(&closed) == 1 {
			return
		}
		select {
		case respCh <- m:
		default:
		}
	})
	defer func() {
		atomic.StoreInt32(&closed, 1)
		agent.TakeResponseHandler(msgID)
	}()

	if streamUpload {
		log.Info("ztrouter: streaming upload id=%s size=%d agent=%s", msgID, r.ContentLength, agent.ID)
		streamer := streaming.NewStreamingHandler()
		defer streamer.Close()
		if err := streamer.HandleUploadFromReaderWithContext(
			msgID, r.Body, msgID, r.ContentLength,
			r.Method, requestURL(r), headers, agent,
		); err != nil {
			log.Error("ztrouter: upload stream to agent %s: %v", agent.ID, err)
			http.Error(w, "Failed to stream upload: "+err.Error(), http.StatusBadGateway)
			return
		}
	} else {
		var body []byte
		if !isWS {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read body: "+err.Error(), http.StatusBadRequest)
				return
			}
			body = b
		}
		httpMsg := &common.Message{
			Type: "http_request",
			ID:   msgID,
			HTTP: &common.HTTPData{
				Method:      r.Method,
				URL:         requestURL(r),
				Headers:     headers,
				Body:        body,
				IsWebSocket: isWS,
			},
		}
		if err := agent.SendMessage(httpMsg); err != nil {
			log.Error("ztrouter: send to agent %s: %v", agent.ID, err)
			http.Error(w, "Failed to forward request", http.StatusBadGateway)
			return
		}
	}

	select {
	case resp := <-respCh:
		if resp.HTTP != nil && resp.HTTP.IsWebSocket {
			if err := h.handleWebSocketUpgrade(w, agent, msgID, resp); err != nil {
				log.Error("ztrouter: ws upgrade: %v", err)
			}
			return
		}
		if resp.HTTP != nil && resp.HTTP.IsStream {
			if err := h.handleDownloadStream(w, r, agent, msgID, resp, respCh); err != nil {
				if isClientGone(err) {
					log.Debug("ztrouter: download stream: client gone id=%s: %v", msgID, err)
				} else {
					log.Error("ztrouter: download stream: %v", err)
				}
			}
			return
		}
		writeAgentResponse(w, resp)
	case <-r.Context().Done():
		return
	case <-time.After(requestTimeout):
		http.Error(w, "Agent response timeout", http.StatusGatewayTimeout)
	}
}

func requestURL(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}
	return r.URL.Path + "?" + r.URL.RawQuery
}

func writeAgentResponse(w http.ResponseWriter, resp *common.Message) {
	if resp.Error != "" {
		http.Error(w, resp.Error, http.StatusBadGateway)
		return
	}
	if resp.HTTP == nil {
		http.Error(w, "Invalid response from agent", http.StatusBadGateway)
		return
	}

	dst := w.Header()
	for k, v := range resp.HTTP.Headers {
		dst[k] = v
	}
	status := resp.HTTP.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if len(resp.HTTP.Body) > 0 {
		_, _ = io.Copy(w, bytes.NewReader(resp.HTTP.Body))
	}
}

// isClientGone returns true for network errors that mean the client disconnected
// mid-stream. These are expected during large downloads and should not be logged
// at ERROR level.
func isClientGone(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed network connection")
}

var _ http.Handler = (*Handler)(nil)
