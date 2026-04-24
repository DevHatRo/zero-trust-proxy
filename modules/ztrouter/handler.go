package ztrouter

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/logger"
	"github.com/devhatro/zero-trust-proxy/internal/streaming"
	"github.com/devhatro/zero-trust-proxy/modules/ztagents"
)

var log = logger.WithComponent("ztrouter")

func init() {
	caddy.RegisterModule(Handler{})
}

type Handler struct {
	RequestTimeout caddy.Duration `json:"request_timeout,omitempty"`

	app        *ztagents.App
	timeoutCfg *common.TimeoutConfig // nil → common.DefaultTimeouts(); set in tests
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.zerotrust_router",
		New: func() caddy.Module { return new(Handler) },
	}
}

// SetApp injects the ztagents App directly. Intended for tests; production code
// resolves the app via Provision.
func (h *Handler) SetApp(app *ztagents.App) { h.app = app }

func (h *Handler) Provision(ctx caddy.Context) error {
	appIface, err := ctx.App("zerotrust.agents")
	if err != nil {
		return fmt.Errorf("ztrouter: load zerotrust.agents app: %w", err)
	}
	app, ok := appIface.(*ztagents.App)
	if !ok {
		return fmt.Errorf("ztrouter: zerotrust.agents app has unexpected type %T", appIface)
	}
	h.app = app
	if h.RequestTimeout == 0 {
		h.RequestTimeout = caddy.Duration(2 * time.Minute)
	}
	log.Debug("ztrouter: provisioned (timeout=%s)", time.Duration(h.RequestTimeout))
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	host := r.Host
	if host == "" {
		http.Error(w, "Missing Host header", http.StatusBadRequest)
		return nil
	}

	agent, ok := h.app.LookupAgent(host)
	if !ok {
		log.Debug("ztrouter: no agent for host=%s", host)
		http.Error(w, "No agent for host "+host, http.StatusServiceUnavailable)
		return nil
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
			return nil
		}
	} else {
		var body []byte
		if !isWS {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read body: "+err.Error(), http.StatusBadRequest)
				return nil
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
			return nil
		}
	}

	select {
	case resp := <-respCh:
		if resp.HTTP != nil && resp.HTTP.IsWebSocket {
			return h.handleWebSocketUpgrade(w, agent, msgID, resp)
		}
		if resp.HTTP != nil && resp.HTTP.IsStream {
			return h.handleDownloadStream(w, r, agent, msgID, resp, respCh)
		}
		return writeAgentResponse(w, resp)
	case <-r.Context().Done():
		return nil
	case <-time.After(time.Duration(h.RequestTimeout)):
		http.Error(w, "Agent response timeout", http.StatusGatewayTimeout)
		return nil
	}
}

func requestURL(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}
	return r.URL.Path + "?" + r.URL.RawQuery
}

func writeAgentResponse(w http.ResponseWriter, resp *common.Message) error {
	if resp.Error != "" {
		http.Error(w, resp.Error, http.StatusBadGateway)
		return nil
	}
	if resp.HTTP == nil {
		http.Error(w, "Invalid response from agent", http.StatusBadGateway)
		return nil
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
		if _, err := io.Copy(w, bytes.NewReader(resp.HTTP.Body)); err != nil {
			return err
		}
	}
	return nil
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
