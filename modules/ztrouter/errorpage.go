package ztrouter

import (
	"bytes"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

// The three legs of the request path, in order. An error page highlights the
// leg that failed; everything before it is shown as healthy, everything after
// as unknown.
const (
	nodeClient = "client"
	nodeProxy  = "proxy"
	nodeAgent  = "agent"
)

// proxyError describes a gateway-level failure to render. It is the input to
// writeProxyError, which decides between an HTML page (browsers) and a plain
// text body (API clients) based on the request's Accept header.
type proxyError struct {
	Status  int    // HTTP status code written to the client
	Title   string // short headline, e.g. "Agent Unreachable"
	Summary string // one-sentence explanation for a human
	Advice  string // "what can I do" guidance
	Detail  string // technical detail (raw error); LOGGED ONLY, never shown to the client
	Failed  string // which node failed: nodeClient | nodeProxy | nodeAgent
}

// writeProxyError writes a gateway error to the client. Browsers (Accept
// contains text/html) get the branded status page; everything else gets a
// compact plain-text body so curl/JSON clients aren't handed a wall of markup.
// In both cases the request ID is echoed in the X-Request-Id header and logged
// so a user-reported failure can be traced to a log line.
func writeProxyError(w http.ResponseWriter, r *http.Request, pe proxyError) {
	reqID := requestID(r)
	host := r.Host

	w.Header().Set("X-Request-Id", reqID)
	// The response varies by Accept (HTML vs plain text) and must never be
	// cached — a stored 502 would outlive the outage.
	w.Header().Set("Vary", "Accept")
	w.Header().Set("Cache-Control", "no-store")

	// Detail (a raw error string that can contain internal addresses) is kept
	// server-side only: it is logged with the request ID so an operator can
	// trace a client-reported failure, but never written to the client.
	logLine := "ztrouter: %s -> %d host=%s id=%s"
	if pe.Detail != "" {
		log.Error(logLine+" detail=%q", pe.Title, pe.Status, host, reqID, pe.Detail)
	} else {
		log.Warn(logLine, pe.Title, pe.Status, host, reqID)
	}

	if !wantsHTML(r) {
		writePlainError(w, pe, reqID)
		return
	}

	// Render into a buffer first. A template-execution error is then caught
	// before the status line or any bytes are committed, so it can be logged
	// and we can fall back to plain text — rather than streaming directly to
	// the client and leaving a half-written, silently corrupt HTML document on
	// failure.
	var buf bytes.Buffer
	if err := errorPageTmpl.Execute(&buf, errorPageView{
		Status:    pe.Status,
		Title:     pe.Title,
		Summary:   pe.Summary,
		Advice:    pe.Advice,
		Host:      host,
		RequestID: reqID,
		Timestamp: time.Now().UTC().Format("2006-01-02 15:04:05 MST"),
		Nodes:     nodeStatuses(pe.Failed),
	}); err != nil {
		log.Error("ztrouter: render error page failed id=%s: %v", reqID, err)
		writePlainError(w, pe, reqID)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(pe.Status)
	if _, err := buf.WriteTo(w); err != nil && !isClientGone(err) {
		log.Error("ztrouter: write error page failed id=%s: %v", reqID, err)
	}
}

// writePlainError writes the compact text/plain form of a proxy error. It is
// both the response for non-HTML clients and the fallback when HTML rendering
// fails. Shared headers (X-Request-Id, Vary, Cache-Control) are already set by
// writeProxyError before this is called.
func writePlainError(w http.ResponseWriter, pe proxyError, reqID string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(pe.Status)
	var b strings.Builder
	b.WriteString(pe.Title)
	b.WriteByte('\n')
	b.WriteString(pe.Summary)
	b.WriteString("\n\nRequest ID: ")
	b.WriteString(reqID)
	b.WriteByte('\n')
	_, _ = w.Write([]byte(b.String()))
}

// writeBlockedResponse renders the branded page for a request the agent's
// route policy denied (ip_whitelist, rate_limit, no_route). Unlike gateway
// errors, the pipeline worked — the client itself was refused — so the flow
// strip shows the Browser node as blocked and the proxy/agent as healthy.
func writeBlockedResponse(w http.ResponseWriter, r *http.Request, h *common.HTTPData) {
	if h.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(h.RetryAfter))
	}
	var pe proxyError
	switch h.BlockedBy {
	case "ip_whitelist":
		pe = proxyError{
			Status:  http.StatusForbidden,
			Title:   "Access Restricted",
			Summary: "Your IP address is not allowed to access this service.",
			Advice:  "This service is limited to approved networks. If you believe you should have access, connect from an allowed network (for example your home connection or VPN) and retry.",
			Failed:  nodeClient,
		}
	case "rate_limit":
		pe = proxyError{
			Status:  http.StatusTooManyRequests,
			Title:   "Too Many Requests",
			Summary: "You have sent too many requests to this service and have been temporarily rate limited.",
			Advice:  "Wait a moment before retrying. Repeated rapid requests will extend the limit.",
			Failed:  nodeClient,
		}
	case "no_route":
		pe = proxyError{
			Status:  http.StatusNotFound,
			Title:   "No Route Matched",
			Summary: "The agent serving this host has no route configured that matches this request.",
			Advice:  "Check the request path, or add a matching route to the agent's service configuration.",
			Failed:  nodeAgent,
		}
	default:
		pe = proxyError{
			Status:  http.StatusForbidden,
			Title:   "Request Blocked",
			Summary: "The agent's access policy blocked this request.",
			Advice:  "If you believe this is a mistake, contact the operator of this service.",
			Failed:  nodeClient,
		}
	}
	// The agent's status code is authoritative when present (it may evolve
	// independently of this switch).
	if h.StatusCode != 0 {
		pe.Status = h.StatusCode
	}
	writeProxyError(w, r, pe)
}

// requestID returns the request's correlation ID. It reuses the one stamped by
// the access-log middleware when present so the page and the log agree; if that
// middleware is disabled, a fresh ID is minted (and stored back so anything
// downstream sees the same value).
func requestID(r *http.Request) string {
	if ri := common.RequestInfoFrom(r.Context()); ri != nil {
		if ri.RequestID == "" {
			ri.RequestID = common.NewRequestID()
		}
		return ri.RequestID
	}
	return common.NewRequestID()
}

// wantsHTML reports whether the client will accept an HTML response, honoring
// RFC 7231 content negotiation. Browsers list text/html with a positive
// quality; curl (Accept: */*) and most API clients don't list text/html at all
// and keep the plain-text body. A client that sends "text/html;q=0" to
// explicitly opt out is respected and also gets plain text. Note that "*/*"
// alone does not select HTML — only an explicit, non-zero-quality text/html
// does — so API clients aren't surprised with markup.
func wantsHTML(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		if media, q := parseAcceptPart(part); media == "text/html" && q > 0 {
			return true
		}
	}
	return false
}

// parseAcceptPart splits one comma-separated Accept entry into its lowercased
// media type and quality value. Quality defaults to 1.0 when no q parameter is
// present or it fails to parse, matching the RFC 7231 default.
func parseAcceptPart(part string) (media string, q float64) {
	q = 1.0
	fields := strings.Split(part, ";")
	media = strings.ToLower(strings.TrimSpace(fields[0]))
	for _, p := range fields[1:] {
		p = strings.ToLower(strings.TrimSpace(p))
		if strings.HasPrefix(p, "q=") {
			if f, err := strconv.ParseFloat(strings.TrimSpace(p[2:]), 64); err == nil {
				q = f
			}
		}
	}
	return media, q
}

type nodeView struct {
	Label  string
	Sub    string
	State  string // "ok" | "error" | "unknown"
	Symbol string
}

type errorPageView struct {
	Status    int
	Title     string
	Summary   string
	Advice    string
	Host      string
	RequestID string
	Timestamp string
	Nodes     []nodeView
}

// nodeStatuses renders the Browser → Proxy → Agent strip: nodes before the
// failed one are healthy, the failed one is in error, anything after is unknown.
// The client node is special: it only "fails" when a policy (IP whitelist,
// rate limit) refused the request, in which case the request did traverse the
// proxy and agent — so they render healthy and the client renders "Blocked".
func nodeStatuses(failed string) []nodeView {
	order := []struct{ id, label, sub string }{
		{nodeClient, "Browser", "You"},
		{nodeProxy, "Zero Trust Proxy", "Edge"},
		{nodeAgent, "Agent", "Origin"},
	}
	failedIdx := -1
	for i, n := range order {
		if n.id == failed {
			failedIdx = i
			break
		}
	}
	blocked := failed == nodeClient
	out := make([]nodeView, 0, len(order))
	for i, n := range order {
		v := nodeView{Label: n.label, Sub: n.sub}
		switch {
		case i == failedIdx && blocked:
			v.State, v.Symbol = "blocked", "✕"
		case failedIdx == -1 || i < failedIdx || blocked:
			v.State, v.Symbol = "ok", "✓"
		case i == failedIdx:
			v.State, v.Symbol = "error", "✕"
		default:
			v.State, v.Symbol = "unknown", "?"
		}
		out = append(out, v)
	}
	return out
}

// errorPageTmpl is fully self-contained (inline CSS, no external assets): when
// the origin is down we cannot rely on fetching a stylesheet. html/template
// auto-escapes all interpolated values, which matters because Host and Detail
// are attacker-influenced.
var errorPageTmpl = template.Must(template.New("errorpage").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.Status}} · {{.Title}}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh;
    font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1d2430; background: #f5f6f8;
    display: flex; align-items: flex-start; justify-content: center;
  }
  @media (prefers-color-scheme: dark) {
    body { background: #16181d; }
    .card { background: #1e2127; border-color: #2c313a; color: #e6e8eb; }
    .nodes { background: #181b20; border-color: #2c313a; }
    .detail { background: #14171b; border-color: #2c313a; color: #aab2bd; }
    .foot { color: #8a929e; border-color: #2c313a; }
    .sub { color: #8a929e; }
  }
  .wrap { width: 100%; max-width: 760px; padding: 48px 20px; }
  /* The card sets its own foreground colour alongside its background so the
     two always theme together — never light text on a light card. */
  .card {
    background: #fff; color: #1d2430; border: 1px solid #e3e6ea; border-radius: 12px;
    padding: 40px; box-shadow: 0 1px 2px rgba(0,0,0,.04);
  }
  .code { font-size: 13px; letter-spacing: .12em; text-transform: uppercase; color: #f0843a; font-weight: 700; }
  h1 { margin: 6px 0 10px; font-size: 28px; line-height: 1.2; }
  .summary { margin: 0 0 8px; font-size: 17px; }
  .nodes {
    display: flex; align-items: stretch; gap: 0; margin: 28px 0;
    background: #fafbfc; border: 1px solid #e3e6ea; border-radius: 10px; overflow: hidden;
  }
  .node { flex: 1; text-align: center; padding: 22px 8px; position: relative; }
  .node + .node::before {
    content: ""; position: absolute; left: 0; top: 50%; width: 1px; height: 40px;
    background: #e3e6ea; transform: translateY(-50%);
  }
  .dot { width: 36px; height: 36px; border-radius: 50%; margin: 0 auto 10px;
    display: flex; align-items: center; justify-content: center; font-weight: 700; color: #fff; }
  .ok .dot { background: #2eb872; }
  .error .dot, .blocked .dot { background: #e2453c; }
  .unknown .dot { background: #9aa3af; }
  .node .label { font-weight: 600; font-size: 14px; }
  .sub { color: #6b7280; font-size: 12px; }
  .state { font-size: 12px; margin-top: 4px; font-weight: 600; }
  .ok .state { color: #2eb872; }
  .error .state, .blocked .state { color: #e2453c; }
  .unknown .state { color: #9aa3af; }
  .advice { margin: 18px 0 0; }
  .advice h2 { font-size: 14px; text-transform: uppercase; letter-spacing: .06em; color: #6b7280; margin: 0 0 6px; }
  .foot {
    margin-top: 28px; padding-top: 16px; border-top: 1px solid #e3e6ea;
    display: flex; flex-wrap: wrap; gap: 6px 20px; color: #6b7280; font-size: 13px;
  }
  .foot code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="code">Error {{.Status}}</div>
      <h1>{{.Title}}</h1>
      <p class="summary">{{.Summary}}</p>

      <div class="nodes">
        {{range .Nodes}}
        <div class="node {{.State}}">
          <div class="dot">{{.Symbol}}</div>
          <div class="label">{{.Label}}</div>
          <div class="sub">{{.Sub}}</div>
          <div class="state">{{if eq .State "ok"}}Working{{else if eq .State "error"}}Error{{else if eq .State "blocked"}}Blocked{{else}}Unknown{{end}}</div>
        </div>
        {{end}}
      </div>

      {{if .Advice}}
      <div class="advice">
        <h2>What can I do?</h2>
        <p>{{.Advice}}</p>
      </div>
      {{end}}

      <div class="foot">
        <span>Host: <code>{{.Host}}</code></span>
        <span>Request ID: <code>{{.RequestID}}</code></span>
        <span>{{.Timestamp}}</span>
      </div>
    </div>
  </div>
</body>
</html>`))
