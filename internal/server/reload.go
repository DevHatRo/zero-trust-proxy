package server

import (
	"fmt"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// Reload applies hot-reloadable fields from newCfg in place. Fields
// that cannot be changed without a restart (listen addresses, TLS
// mode, ACME storage path, agent listener) are diffed against the
// running config; if any have changed, Reload returns an error and
// applies nothing.
//
// Reloadable:
//   - router.request_timeout
//   - logging.level / logging.format
//   - manual / sni cert files (re-read from disk; atomic-pointer swap
//     so live connections aren't dropped)
//
// Restart-only:
//   - listen.http / listen.https
//   - tls.mode
//   - tls.acme.storage_dir
//   - agents.listen
func (s *Server) Reload(newCfg *serverconfig.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return fmt.Errorf("reload: server not started")
	}
	if err := diffRestartOnly(s.cfg, newCfg); err != nil {
		return err
	}

	if err := s.tls.reloadCerts(); err != nil {
		return fmt.Errorf("reload tls: %w", err)
	}

	s.router.RequestTimeout = newCfg.Router.RequestTimeout
	s.cfg = newCfg
	return nil
}

func diffRestartOnly(old, new *serverconfig.Config) error {
	switch {
	case old.Listen.HTTP != new.Listen.HTTP:
		return fmt.Errorf("listen.http change requires restart (%q→%q)", old.Listen.HTTP, new.Listen.HTTP)
	case old.Listen.HTTPS != new.Listen.HTTPS:
		return fmt.Errorf("listen.https change requires restart (%q→%q)", old.Listen.HTTPS, new.Listen.HTTPS)
	case old.TLS.Mode != new.TLS.Mode:
		return fmt.Errorf("tls.mode change requires restart (%q→%q)", old.TLS.Mode, new.TLS.Mode)
	case old.Agents.Listen != new.Agents.Listen:
		return fmt.Errorf("agents.listen change requires restart (%q→%q)", old.Agents.Listen, new.Agents.Listen)
	}
	return nil
}
