package common

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// RequestInfo is a mutable holder threaded through request context so
// the public-listener middleware (e.g. access log) can read values that
// are only resolved deeper in the handler chain (e.g. the agent ID
// chosen by ztrouter for the request's Host).
//
// The middleware allocates one of these per request and stashes it in
// context; downstream handlers fill in fields. Reads happen after
// next.ServeHTTP returns, so no synchronization is needed.
type RequestInfo struct {
	// AgentID is the agent resolved for the request's Host (set by ztrouter).
	AgentID string
	// RequestID is a short opaque per-request identifier surfaced to clients
	// (the X-Request-Id header and the error page) so a user-reported failure
	// can be correlated with a log line. Set by the access-log middleware.
	RequestID string
}

// NewRequestID returns a short, opaque, URL-safe request identifier (16 hex
// chars from 8 random bytes). It is the project's "Ray ID" equivalent: shown
// on error pages and emitted in access logs so a reported failure maps to a
// log line. On the (practically impossible) RNG failure it returns a fixed
// sentinel rather than an error — a non-unique ID is preferable to failing
// the request over a cosmetic identifier.
func NewRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}

type requestInfoKey struct{}

// WithRequestInfo returns a new context carrying ri. Callers should
// allocate ri before calling next.ServeHTTP and read from it after.
func WithRequestInfo(ctx context.Context, ri *RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, ri)
}

// RequestInfoFrom returns the RequestInfo attached to ctx, or nil.
func RequestInfoFrom(ctx context.Context) *RequestInfo {
	ri, _ := ctx.Value(requestInfoKey{}).(*RequestInfo)
	return ri
}
