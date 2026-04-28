package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

// accessLogMiddleware emits one JSON line per finished HTTP request to
// the package logger at info level. Opt-in via logging.access_log: true.
//
// Fields: ts, method, host, path, status, bytes, duration_ms,
// agent_id (resolved by ztrouter via common.RequestInfo), client_ip
// (RemoteAddr without port — the proxy is the TLS termination point so
// XFF is not consulted here).
//
// The wrapper transparently forwards http.Hijacker and http.Flusher so
// the WebSocket and streaming-download paths in ztrouter still work.
// Bytes counted after a successful Hijack are 0 because the inner
// handler writes directly to the hijacked conn — that's accepted; the
// status field is best-effort in those cases too.
func accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ri := &common.RequestInfo{}
		r = r.WithContext(common.WithRequestInfo(r.Context(), ri))
		rw := &accessLogRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		entry := struct {
			TS         string `json:"ts"`
			Method     string `json:"method"`
			Host       string `json:"host"`
			Path       string `json:"path"`
			Status     int    `json:"status"`
			Bytes      int64  `json:"bytes"`
			DurationMS int64  `json:"duration_ms"`
			AgentID    string `json:"agent_id,omitempty"`
			ClientIP   string `json:"client_ip,omitempty"`
		}{
			TS:         start.UTC().Format(time.RFC3339Nano),
			Method:     r.Method,
			Host:       r.Host,
			Path:       r.URL.RequestURI(),
			Status:     rw.status,
			Bytes:      rw.bytes,
			DurationMS: time.Since(start).Milliseconds(),
			AgentID:    ri.AgentID,
			ClientIP:   clientIP(r.RemoteAddr),
		}
		b, err := json.Marshal(entry)
		if err != nil {
			return
		}
		log.Info("access %s", string(b))
	})
}

func clientIP(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	if i := strings.LastIndex(remoteAddr, ":"); i >= 0 {
		host := remoteAddr[:i]
		// Strip surrounding [] from IPv6 literals.
		host = strings.TrimPrefix(host, "[")
		host = strings.TrimSuffix(host, "]")
		return host
	}
	return remoteAddr
}

type accessLogRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (a *accessLogRecorder) WriteHeader(code int) {
	if a.wroteHeader {
		return
	}
	a.status = code
	a.wroteHeader = true
	a.ResponseWriter.WriteHeader(code)
}

func (a *accessLogRecorder) Write(b []byte) (int, error) {
	if !a.wroteHeader {
		a.wroteHeader = true
	}
	n, err := a.ResponseWriter.Write(b)
	a.bytes += int64(n)
	return n, err
}

func (a *accessLogRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := a.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("accesslog: underlying ResponseWriter is not a Hijacker")
	}
	return h.Hijack()
}

func (a *accessLogRecorder) Flush() {
	if f, ok := a.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
