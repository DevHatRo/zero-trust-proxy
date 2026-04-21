package ztagents

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

const defaultCheckAddr = "127.0.0.1:2020"

// startCheckServer runs a localhost HTTP listener that answers Caddy's
// on_demand_tls `ask` queries. Returns 200 if the requested domain has an
// active agent-registered service, 403 otherwise. We don't use Caddy's admin
// API here because module-provided admin routes are unreliable across Caddy
// versions; this internal listener is deterministic and testable.
func (a *App) startCheckServer() error {
	addr := a.CheckAddr
	if addr == "" {
		addr = defaultCheckAddr
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("check server listen %s: %w", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/zero-trust/check-domain", a.serveCheckDomain)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	a.rt.checkServer = srv

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Error("ztagents: check server: %v", err)
		}
	}()

	log.Info("ztagents: check server listening on %s", addr)
	return nil
}

func (a *App) stopCheckServer() {
	if a.rt == nil || a.rt.checkServer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = a.rt.checkServer.Shutdown(ctx)
}

func (a *App) serveCheckDomain(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" || a.rt == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, ok := a.rt.registry.lookupByHost(domain); !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
}
