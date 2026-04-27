package server

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// Run starts a Server from the given config and blocks until SIGINT or
// SIGTERM. SIGHUP triggers a config reload from the same path. Returns
// the first non-nil error from Start or Shutdown.
func Run(cfgPath string) error {
	cfg, err := serverconfig.Load(cfgPath)
	if err != nil {
		return err
	}
	return RunWithConfig(cfg, cfgPath)
}

// RunWithConfig is Run with a pre-loaded config (so callers can apply
// CLI overrides before starting). reloadPath is the path used for
// SIGHUP reloads; pass "" to disable reload.
func RunWithConfig(cfg *serverconfig.Config, reloadPath string) error {
	srv, err := New(cfg)
	if err != nil {
		return err
	}
	if err := srv.Start(context.Background()); err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			if reloadPath == "" {
				log.Info("SIGHUP ignored: no reload path configured")
				continue
			}
			newCfg, lerr := serverconfig.Load(reloadPath)
			if lerr != nil {
				log.Error("reload: %v", lerr)
				continue
			}
			if rerr := srv.Reload(newCfg); rerr != nil {
				log.Error("reload: %v", rerr)
			} else {
				log.Info("reloaded config from %s", reloadPath)
			}
		case syscall.SIGINT, syscall.SIGTERM:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if serr := srv.Shutdown(ctx); serr != nil && !errors.Is(serr, context.Canceled) {
				return serr
			}
			return nil
		}
	}
	return nil
}
