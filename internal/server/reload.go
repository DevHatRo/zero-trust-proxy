package server

import (
	"fmt"
	"reflect"

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
//   - security rules and limits (atomic swap; rate-limit buckets reset)
//   - access.rules / access.service_tokens (atomic snapshot swap)
//   - agents.revocation (denied serials + CRL re-read; applies to new
//     handshakes)
//
// Restart-only:
//   - listen.http / listen.https
//   - tls.mode
//   - tls.acme.storage_dir
//   - agents.listen
//   - agents.identity / agents.acl (compiled into the listener at
//     provision; already-connected agents keep their compiled ACL)
//   - security.*.enabled (the middleware is only inserted at startup)
//   - access.enabled / access.session / access.identity_providers
//     (live sessions are signed with the current secret; in-flight
//     login flows hold state cookies)
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

	if s.security != nil {
		if err := s.security.Reload(newCfg.Security); err != nil {
			return fmt.Errorf("reload security: %w", err)
		}
	}

	if err := s.agents.ReloadRevocation(newCfg.Agents.Revocation); err != nil {
		return fmt.Errorf("reload revocation: %w", err)
	}

	if s.access != nil {
		if err := s.access.Reload(newCfg.Access); err != nil {
			return fmt.Errorf("reload access: %w", err)
		}
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
	case old.Security.RateLimit.Enabled != new.Security.RateLimit.Enabled:
		return fmt.Errorf("security.rate_limit.enabled change requires restart")
	case old.Security.Firewall.Enabled != new.Security.Firewall.Enabled:
		return fmt.Errorf("security.firewall.enabled change requires restart")
	case old.Agents.Identity != new.Agents.Identity:
		return fmt.Errorf("agents.identity change requires restart")
	case !reflect.DeepEqual(old.Agents.ACL, new.Agents.ACL):
		return fmt.Errorf("agents.acl change requires restart")
	case old.Access.Enabled != new.Access.Enabled:
		return fmt.Errorf("access.enabled change requires restart")
	case !reflect.DeepEqual(old.Access.Session, new.Access.Session):
		return fmt.Errorf("access.session change requires restart")
	case !reflect.DeepEqual(old.Access.IdentityProviders, new.Access.IdentityProviders):
		return fmt.Errorf("access.identity_providers change requires restart")
	}
	return nil
}
