package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/http3"
)

// altSvcMiddleware advertises the HTTP/3 endpoint to capable clients
// via the Alt-Svc header. Without this, browsers won't try QUIC even
// if the listener is up. ma=2592000 (30 days) is the canonical value.
//
// quicAddr is the value from listen.http3 — typically ":443" or
// ":8443". Bare port form (":443") tells the client to try the same
// host; this is what we want.
func altSvcMiddleware(quicAddr string, next http.Handler) http.Handler {
	header := buildAltSvcHeader(quicAddr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", header)
		next.ServeHTTP(w, r)
	})
}

func buildAltSvcHeader(quicAddr string) string {
	port := quicAddr
	if i := strings.LastIndex(quicAddr, ":"); i >= 0 {
		port = quicAddr[i:]
	}
	return `h3=` + strconv.Quote(port) + `; ma=2592000`
}

// startHTTP3 brings up an HTTP/3 (QUIC) listener using the same
// handler and TLS config as the HTTPS listener. Called from
// Server.Start when listen.http3 is set.
//
// IMPORTANT: tlsCfg must already be a snapshot/clone the caller owns.
// We do not Clone() here because net/http's ServeTLS goroutine
// concurrently mutates the original tls.Config (h2 NextProto setup),
// which would race with a Clone in this function. The caller takes
// the snapshot synchronously before the HTTPS goroutine starts.
func startHTTP3(addr string, handler http.Handler, tlsCfg *tls.Config) (*http3.Server, error) {
	if tlsCfg == nil {
		return nil, fmt.Errorf("http3: tls config required")
	}
	srv := &http3.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: tlsCfg,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Error("http3 serve: %v", err)
		}
	}()
	return srv, nil
}
