package ztrouter

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("zerotrust_router", parseHandlerCaddyfile)
}

// parseHandlerCaddyfile is the HTTP handler directive parser. Example:
//
//	zerotrust_router {
//	    request_timeout 2m
//	}
func parseHandlerCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var h Handler
	if err := h.UnmarshalCaddyfile(helper.Dispenser); err != nil {
		return nil, err
	}
	return &h, nil
}

// UnmarshalCaddyfile reads the handler's Caddyfile block.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "request_timeout":
				var s string
				if !d.Args(&s) {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(s)
				if err != nil {
					return d.Errf("invalid request_timeout %q: %v", s, err)
				}
				h.RequestTimeout = caddy.Duration(dur)
			default:
				return d.Errf("unknown zerotrust_router option %q", d.Val())
			}
		}
	}
	return nil
}

var _ caddyfile.Unmarshaler = (*Handler)(nil)
