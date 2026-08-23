package ztrouter

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/logger"
	"github.com/devhatro/zero-trust-proxy/internal/security"
	"github.com/devhatro/zero-trust-proxy/internal/streaming"
	"github.com/devhatro/zero-trust-proxy/modules/ztagents"
)

var log = logger.WithComponent("ztrouter")

type Handler struct {
	RequestTimeout time.Duration `json:"request_timeout,omitempty"`

	app             *ztagents.App
	timeoutCfg      *common.TimeoutConfig // nil → common.DefaultTimeouts(); set in tests
	maxStreamBuffer int64                 // 0 → defaultMaxStreamBuffer; set in tests
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
	// /.ztp/* is the proxy-owned namespace (login callback, logout).
	// The access middleware handles it before the router when enabled;
	// this guard is defence-in-depth so a config with access disabled
	// can never proxy the reserved namespace to a backend. Matched on
	// the dot-segment-collapsed path: "/foo/../.ztp/logout" is the
	// namespace too, and upstreams would resolve it there.
	if isZTPPath(security.CleanPath(r.URL.Path)) {
		http.NotFound(w, r)
		return
	}

	host := r.Host
	if host == "" {
		http.Error(w, "Missing Host header", http.StatusBadRequest)
		return
	}

	agent, svc, ok := h.app.LookupService(host)
	if !ok {
		writeProxyError(w, r, proxyError{
			Status:  http.StatusServiceUnavailable,
			Title:   "Agent Unreachable",
			Summary: "No agent is currently connected to serve this hostname.",
			Advice:  "The service may be starting up or temporarily offline. Wait a moment and retry; if it persists, confirm the agent for this host is running and registered.",
			Failed:  nodeAgent,
		})
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
	setForwardedHeaders(headers, r)

	// Response messages flow: agent read loop → queue.push (never blocks) →
	// pump goroutine → respCh (blocks; backpressure lands on the pump, not
	// the shared read loop). The queue never drops chunks — the previous
	// buffered-channel-with-default-drop here silently lost streaming chunks
	// under bursts, truncating download bodies (and hanging the stream when
	// the IsLastChunk message was the one dropped).
	respCh := make(chan *common.Message, 16)
	queue := newMsgQueue(h.maxStreamBuffer)
	stop := make(chan struct{})
	go queue.pump(r.Context(), stop, respCh)
	agent.SetResponseHandler(msgID, queue.push)
	defer func() {
		agent.TakeResponseHandler(msgID)
		close(stop)
	}()

	if streamUpload {
		log.Info("ztrouter: streaming upload id=%s size=%d agent=%s", msgID, r.ContentLength, agent.ID)
		streamer := streaming.NewStreamingHandler()
		defer streamer.Close()
		if err := streamer.HandleUploadFromReaderWithContext(
			msgID, r.Body, msgID, r.ContentLength,
			r.Method, requestURL(r), headers, agent,
		); err != nil {
			writeProxyError(w, r, proxyError{
				Status:  http.StatusBadGateway,
				Title:   "Upload Failed",
				Summary: "The proxy could not deliver your upload to the agent.",
				Advice:  "The connection to the agent was interrupted. Retry the upload; if it keeps failing, check the agent's connectivity.",
				Detail:  err.Error(),
				Failed:  nodeAgent,
			})
			return
		}
	} else {
		var body []byte
		if !isWS {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				// A MaxBytesReader cap (security.firewall.max_request_bytes)
				// on a chunked body surfaces here — answer 413, not 400.
				var mbe *http.MaxBytesError
				if errors.As(err, &mbe) {
					http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
					return
				}
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
			writeProxyError(w, r, proxyError{
				Status:  http.StatusBadGateway,
				Title:   "Agent Connection Lost",
				Summary: "The connection to the agent dropped before your request could be delivered.",
				Advice:  "The agent may have just disconnected. Retry shortly; if the error continues, verify the agent is connected to the proxy.",
				Detail:  err.Error(),
				Failed:  nodeAgent,
			})
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
					return
				}
				log.Error("ztrouter: download stream: id=%s: %v", msgID, err)
				// Abort the response (HTTP/2 RST_STREAM, HTTP/1.1 connection
				// close mid-body) so the client sees a failed transfer. A
				// plain return would end the stream cleanly and clients —
				// browsers especially — would treat the truncated body as
				// complete and may cache it.
				panic(http.ErrAbortHandler)
			}
			return
		}
		writeAgentResponse(w, r, resp)
	case <-r.Context().Done():
		return
	case <-time.After(requestTimeout):
		writeProxyError(w, r, proxyError{
			Status:  http.StatusGatewayTimeout,
			Title:   "Agent Timeout",
			Summary: "The agent did not respond in time.",
			Advice:  "The backend may be slow or overloaded. Retry in a moment; if timeouts persist, check the upstream service behind the agent.",
			Failed:  nodeAgent,
		})
	}
}

// setForwardedHeaders populates X-Forwarded-For, X-Real-IP, X-Forwarded-Proto,
// and X-Forwarded-Host based on r.RemoteAddr and the TLS state. The proxy is
// the TLS termination point and is authoritative — any client-supplied values
// for these headers are dropped to prevent spoofing.
func setForwardedHeaders(headers map[string][]string, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if host != "" {
		headers["X-Forwarded-For"] = []string{host}
		delete(headers, "X-Real-Ip")
		headers["X-Real-IP"] = []string{host}
	}

	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	headers["X-Forwarded-Proto"] = []string{proto}

	if r.Host != "" {
		headers["X-Forwarded-Host"] = []string{r.Host}
	}
}

// requestURL returns the path (and query) to forward to the agent. It uses
// EscapedPath rather than the decoded Path so that percent-encoded path
// separators (%2F) survive the proxy hop intact. Backends that route on the
// raw path — e.g. branch/ref names like "feature/x" or "release/1.2" carried
// in a single path segment as "feature%2Fx" — would otherwise see an extra
// segment after decoding and fail to match their route.
func requestURL(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return r.URL.EscapedPath()
	}
	return r.URL.EscapedPath() + "?" + r.URL.RawQuery
}

func writeAgentResponse(w http.ResponseWriter, r *http.Request, resp *common.Message) {
	if resp.HTTP != nil && resp.HTTP.BlockedBy != "" {
		writeBlockedResponse(w, r, resp.HTTP)
		return
	}
	if resp.Error != "" {
		writeProxyError(w, r, proxyError{
			Status:  http.StatusBadGateway,
			Title:   "Agent Error",
			Summary: "The agent reported an error while handling your request.",
			Advice:  "This usually means the upstream service behind the agent failed. Retry, or check the backend the agent proxies to.",
			Detail:  resp.Error,
			Failed:  nodeAgent,
		})
		return
	}
	if resp.HTTP == nil {
		writeProxyError(w, r, proxyError{
			Status:  http.StatusBadGateway,
			Title:   "Invalid Agent Response",
			Summary: "The agent returned a malformed response.",
			Advice:  "This is unexpected. Retry the request; if it continues, inspect the agent logs.",
			Failed:  nodeAgent,
		})
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

// isZTPPath reports whether a cleaned path is inside the proxy-owned
// /.ztp namespace (including the bare "/.ztp").
func isZTPPath(cleaned string) bool {
	return cleaned == "/.ztp" || strings.HasPrefix(cleaned, "/.ztp/")
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
