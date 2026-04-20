package ztagents

import (
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("zerotrust_agents", parseGlobalOption)
}

// parseGlobalOption parses the `zerotrust_agents` global option in a Caddyfile.
// Example:
//
//	{
//	    zerotrust_agents {
//	        listen :8443
//	        cert_file /etc/certs/server.crt
//	        key_file /etc/certs/server.key
//	        ca_file  /etc/certs/ca.crt
//	    }
//	}
func parseGlobalOption(d *caddyfile.Dispenser, _ any) (any, error) {
	app := new(App)
	if err := app.UnmarshalCaddyfile(d); err != nil {
		return nil, err
	}
	return httpcaddyfile.App{
		Name:  "zerotrust.agents",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

// UnmarshalCaddyfile reads the app's Caddyfile block.
func (a *App) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "listen":
				if !d.Args(&a.ListenAddr) {
					return d.ArgErr()
				}
			case "cert_file":
				if !d.Args(&a.CertFile) {
					return d.ArgErr()
				}
			case "key_file":
				if !d.Args(&a.KeyFile) {
					return d.ArgErr()
				}
			case "ca_file":
				if !d.Args(&a.CAFile) {
					return d.ArgErr()
				}
			default:
				return d.Errf("unknown zerotrust_agents option %q", d.Val())
			}
		}
	}
	return nil
}

var _ caddyfile.Unmarshaler = (*App)(nil)
