package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/acme/autocert"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// HostLookup reports whether the given host has an active service in
// the agent registry. Used by ACME HostPolicy to gate cert issuance.
type HostLookup func(host string) bool

// certEntry is a (path-pair, atomic cert pointer) tuple. Holds the
// disk paths so SIGHUP reload can re-read them and Store a new value
// into the same pointer — the GetCertificate closure observes the
// swap atomically.
type certEntry struct {
	certFile string
	keyFile  string
	ptr      *atomic.Pointer[tls.Certificate]
}

// tlsBundle is the result of buildTLSConfig: a TLS config for the
// HTTPS listener plus optional state for ACME and reload.
type tlsBundle struct {
	tlsConfig   *tls.Config
	acmeHandler http.Handler        // mount at :80 for HTTP-01 challenges (acme mode only)
	acme        *autocert.Manager   // nil unless mode == acme
	mode        serverconfig.TLSMode
	manualCert  *certEntry          // mode == manual
	sniCerts    map[string]*certEntry // mode == sni; key is lowercase hostname
}

// reloadCerts re-reads each cert pair from disk and atomically swaps
// the pointer. Errors on any individual file read are returned as a
// single message; partial swaps are not rolled back since each file
// pair is loaded fully before its Store, so a failure mid-fleet
// leaves earlier-swapped certs in place — operator can fix and
// SIGHUP again.
func (b *tlsBundle) reloadCerts() error {
	if b == nil {
		return nil
	}
	switch b.mode {
	case serverconfig.TLSModeManual:
		if b.manualCert == nil {
			return nil
		}
		return reloadEntry(b.manualCert)
	case serverconfig.TLSModeSNI:
		var firstErr error
		for host, e := range b.sniCerts {
			if err := reloadEntry(e); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("sni[%q]: %w", host, err)
			}
		}
		return firstErr
	}
	return nil
}

func reloadEntry(e *certEntry) error {
	cert, err := tls.LoadX509KeyPair(e.certFile, e.keyFile)
	if err != nil {
		return fmt.Errorf("load %s/%s: %w", e.certFile, e.keyFile, err)
	}
	e.ptr.Store(&cert)
	return nil
}

// buildTLSConfig constructs a *tls.Config for the public HTTPS
// listener according to cfg. lookup is consulted by the ACME
// HostPolicy and may be nil for manual/sni/none modes.
func buildTLSConfig(cfg serverconfig.TLSConfig, lookup HostLookup) (*tlsBundle, error) {
	switch cfg.Mode {
	case serverconfig.TLSModeNone:
		return &tlsBundle{mode: cfg.Mode}, nil

	case serverconfig.TLSModeManual:
		entry, err := newCertEntry(cfg.Manual.CertFile, cfg.Manual.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("manual: %w", err)
		}
		return &tlsBundle{
			mode:       cfg.Mode,
			manualCert: entry,
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return entry.ptr.Load(), nil
				},
			},
		}, nil

	case serverconfig.TLSModeSNI:
		entries := make(map[string]*certEntry, len(cfg.SNI))
		for host, mc := range cfg.SNI {
			entry, err := newCertEntry(mc.CertFile, mc.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("sni[%q]: %w", host, err)
			}
			entries[strings.ToLower(host)] = entry
		}
		return &tlsBundle{
			mode:     cfg.Mode,
			sniCerts: entries,
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
					name := strings.ToLower(chi.ServerName)
					if e, ok := entries[name]; ok {
						return e.ptr.Load(), nil
					}
					return nil, fmt.Errorf("no certificate for SNI %q", chi.ServerName)
				},
			},
		}, nil

	case serverconfig.TLSModeACME:
		hostPolicy := autocert.HostPolicy(func(_ context.Context, host string) error {
			if lookup == nil {
				return fmt.Errorf("no host lookup configured")
			}
			if !lookup(host) {
				return fmt.Errorf("host %q not registered with any agent", host)
			}
			return nil
		})
		m := &autocert.Manager{
			Cache:      autocert.DirCache(cfg.ACME.StorageDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: hostPolicy,
			Email:      cfg.ACME.Email,
		}
		if cfg.ACME.CAURL != "" {
			m.Client = &autocertClient{DirectoryURL: cfg.ACME.CAURL}
		}
		return &tlsBundle{
			mode:        cfg.Mode,
			tlsConfig:   m.TLSConfig(),
			acmeHandler: m.HTTPHandler(nil),
			acme:        m,
		}, nil

	default:
		return nil, fmt.Errorf("unknown tls.mode %q", cfg.Mode)
	}
}

func newCertEntry(certFile, keyFile string) (*certEntry, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load key pair %s/%s: %w", certFile, keyFile, err)
	}
	var ptr atomic.Pointer[tls.Certificate]
	ptr.Store(&cert)
	return &certEntry{certFile: certFile, keyFile: keyFile, ptr: &ptr}, nil
}
