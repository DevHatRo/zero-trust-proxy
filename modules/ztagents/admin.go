package ztagents

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
)

// Routes implements caddy.AdminRouter. It registers a domain-check endpoint
// used by Caddy's on_demand_tls to validate a domain before requesting a
// Let's Encrypt certificate. Returns 200 if the domain has a registered
// service, 403 otherwise.
func (a *App) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/zero-trust/check-domain",
			Handler: caddy.AdminHandlerFunc(a.serveCheckDomain),
		},
	}
}

func (a *App) serveCheckDomain(w http.ResponseWriter, r *http.Request) error {
	domain := r.URL.Query().Get("domain")
	if domain == "" || a.rt == nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}
	_, ok := a.rt.registry.lookupByHost(domain)
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return nil
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

var _ caddy.AdminRouter = (*App)(nil)
