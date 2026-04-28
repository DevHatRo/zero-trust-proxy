package common

import "context"

// RequestInfo is a mutable holder threaded through request context so
// the public-listener middleware (e.g. access log) can read values that
// are only resolved deeper in the handler chain (e.g. the agent ID
// chosen by ztrouter for the request's Host).
//
// The middleware allocates one of these per request and stashes it in
// context; downstream handlers fill in fields. Reads happen after
// next.ServeHTTP returns, so no synchronization is needed.
type RequestInfo struct {
	AgentID string
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
