// Package server is the lifecycle orchestrator for the custom
// zero-trust-proxy binary. It owns the agent mTLS listener, the public
// HTTPS listener, and the optional HTTP redirector, and wires the
// existing modules/ztagents and modules/ztrouter packages together
// without going through Caddy.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/devhatro/zero-trust-proxy/internal/logger"
	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
	"github.com/devhatro/zero-trust-proxy/modules/ztagents"
	"github.com/devhatro/zero-trust-proxy/modules/ztrouter"
)

var log = logger.WithComponent("server")

// Server is the top-level lifecycle object.
type Server struct {
	cfg *serverconfig.Config

	agents     *ztagents.App
	router     *ztrouter.Handler
	httpsLn    net.Listener
	httpLn     net.Listener
	metricsLn  net.Listener
	httpsSr    *http.Server
	httpSr     *http.Server
	metricsSr  *http.Server
	http3Sr    *http3.Server
	tls        *tlsBundle // owns cert hot-swap pointers
	metrics    *metrics
	metricsTkr *time.Ticker
	metricsCh  chan struct{}

	mu       sync.Mutex
	started  bool
	stopped  bool
	stopOnce sync.Once
}

// New constructs a Server but does not bind any sockets.
func New(cfg *serverconfig.Config) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("server: nil config")
	}
	agents, err := ztagents.New(cfg.Agents)
	if err != nil {
		return nil, fmt.Errorf("agents: %w", err)
	}
	router := ztrouter.New(agents, cfg.Router.RequestTimeout)
	s := &Server{cfg: cfg, agents: agents, router: router}
	if cfg.Metrics.Addr != "" {
		s.metrics = newMetrics()
	}
	return s, nil
}

// Start brings up listeners in order: agents → HTTPS → HTTP. It
// returns once all listeners are listening; serving continues in
// background goroutines until Shutdown.
func (s *Server) Start(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("server: already started")
	}

	if err := s.agents.Start(); err != nil {
		return fmt.Errorf("agents start: %w", err)
	}

	bundle, err := buildTLSConfig(s.cfg.TLS, s.lookupHost)
	if err != nil {
		_ = s.agents.Stop()
		return fmt.Errorf("tls: %w", err)
	}
	s.tls = bundle

	if s.cfg.Listen.HTTPS != "" {
		if bundle.tlsConfig == nil {
			_ = s.agents.Stop()
			return fmt.Errorf("listen.https=%q but tls.mode=none", s.cfg.Listen.HTTPS)
		}
		ln, err := net.Listen("tcp", s.cfg.Listen.HTTPS)
		if err != nil {
			_ = s.agents.Stop()
			return fmt.Errorf("https listen %s: %w", s.cfg.Listen.HTTPS, err)
		}
		s.httpsLn = ln
		var publicHandler http.Handler = s.router
		if s.metrics != nil {
			publicHandler = metricsMiddleware(s.metrics, publicHandler)
		}
		if s.cfg.Logging.AccessLog {
			publicHandler = accessLogMiddleware(publicHandler)
		}
		// Snapshot the TLS config for HTTP/3 *before* httpsSr.ServeTLS
		// runs — the stdlib http.Server mutates its TLSConfig
		// asynchronously to set up h2 NextProtos.
		var http3TLS *tls.Config
		if s.cfg.Listen.HTTP3 != "" {
			http3TLS = bundle.tlsConfig.Clone()
			// Advertise the QUIC endpoint to TCP/TLS clients so
			// browsers actually upgrade.
			publicHandler = altSvcMiddleware(s.cfg.Listen.HTTP3, publicHandler)
		}
		s.httpsSr = &http.Server{
			Handler:           publicHandler,
			TLSConfig:         bundle.tlsConfig,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := s.httpsSr.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("https serve: %v", err)
			}
		}()
		log.Info("https listening on %s", s.cfg.Listen.HTTPS)

		if s.cfg.Listen.HTTP3 != "" {
			h3, err := startHTTP3(s.cfg.Listen.HTTP3, publicHandler, http3TLS)
			if err != nil {
				_ = s.shutdownHTTPS(context.Background())
				_ = s.agents.Stop()
				return fmt.Errorf("http3: %w", err)
			}
			s.http3Sr = h3
			log.Info("http3 (quic) listening on %s", s.cfg.Listen.HTTP3)
		}
	}

	if s.cfg.Listen.HTTP != "" {
		ln, err := net.Listen("tcp", s.cfg.Listen.HTTP)
		if err != nil {
			_ = s.shutdownHTTPS(context.Background())
			_ = s.agents.Stop()
			return fmt.Errorf("http listen %s: %w", s.cfg.Listen.HTTP, err)
		}
		s.httpLn = ln
		var handler http.Handler
		if s.cfg.Listen.HTTPRedirect {
			handler = newRedirectHandler(bundle.acmeHandler)
		} else if bundle.acmeHandler != nil {
			handler = bundle.acmeHandler
		} else {
			handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "HTTPS only", http.StatusBadRequest)
			})
		}
		s.httpSr = &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := s.httpSr.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("http serve: %v", err)
			}
		}()
		log.Info("http listening on %s (redirect=%v)", s.cfg.Listen.HTTP, s.cfg.Listen.HTTPRedirect)
	}

	if s.metrics != nil && s.cfg.Metrics.Addr != "" {
		ln, err := net.Listen("tcp", s.cfg.Metrics.Addr)
		if err != nil {
			_ = s.httpSr.Shutdown(context.Background())
			_ = s.shutdownHTTPS(context.Background())
			_ = s.agents.Stop()
			return fmt.Errorf("metrics listen %s: %w", s.cfg.Metrics.Addr, err)
		}
		s.metricsLn = ln
		s.metricsSr = &http.Server{
			Handler:           s.metrics,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			if err := s.metricsSr.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics serve: %v", err)
			}
		}()
		s.metricsCh = make(chan struct{})
		s.metricsTkr = time.NewTicker(5 * time.Second)
		go s.refreshGauges()
		log.Info("metrics listening on %s/metrics", s.cfg.Metrics.Addr)
	}

	s.started = true
	return nil
}

// refreshGauges polls the agent registry / WS manager for gauge
// values. Cheap (read locks only) and bounded — runs every 5s until
// metricsCh closes.
func (s *Server) refreshGauges() {
	defer s.metricsTkr.Stop()
	for {
		select {
		case <-s.metricsCh:
			return
		case <-s.metricsTkr.C:
			s.metrics.setWebSocketSessions(s.agents.WebSocketCount())
			s.metrics.setAgentsRegistered(s.agents.AgentCount())
			s.metrics.setAgentServices(s.agents.AgentServiceCounts())
		}
	}
}

// Shutdown drains HTTP, then HTTPS, then closes the agent listener.
// Idempotent.
func (s *Server) Shutdown(ctx context.Context) error {
	var firstErr error
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.stopped = true
		s.mu.Unlock()

		if s.metricsCh != nil {
			close(s.metricsCh)
		}
		if s.metricsSr != nil {
			if err := s.metricsSr.Shutdown(ctx); err != nil {
				log.Error("metrics shutdown: %v", err)
				if firstErr == nil {
					firstErr = err
				}
			}
		}
		if s.httpSr != nil {
			if err := s.httpSr.Shutdown(ctx); err != nil {
				log.Error("http shutdown: %v", err)
				firstErr = err
			}
		}
		if s.http3Sr != nil {
			if err := s.http3Sr.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := s.shutdownHTTPS(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := s.agents.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
	})
	return firstErr
}

func (s *Server) shutdownHTTPS(ctx context.Context) error {
	if s.httpsSr == nil {
		return nil
	}
	if err := s.httpsSr.Shutdown(ctx); err != nil {
		log.Error("https shutdown: %v", err)
		return err
	}
	return nil
}

// lookupHost is bound to the agent registry; it's used by ACME
// HostPolicy and (if you mount the legacy :2020 endpoint elsewhere) by
// external "ask" probes.
func (s *Server) lookupHost(host string) bool {
	_, ok := s.agents.LookupAgent(host)
	return ok
}
