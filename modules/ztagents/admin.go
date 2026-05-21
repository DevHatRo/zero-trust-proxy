package ztagents

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

const defaultCheckAddr = "127.0.0.1:2020"

// startCheckServer runs the optional legacy localhost domain-check
// endpoint (configured via agents.check_addr). Returns 200 if the
// requested domain has an active agent-registered service, 403
// otherwise. The in-process ACME HostPolicy consults the same registry
// directly; this listener is retained only for external tooling.
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
