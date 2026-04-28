package server

import (
	"net/http"
	"strings"
)

// newRedirectHandler returns an http.Handler that:
//   - forwards GET /.well-known/acme-challenge/* to acmeHandler when non-nil
//     (for ACME HTTP-01 challenges issued by autocert);
//   - 308-redirects everything else to https://{host}{uri}.
func newRedirectHandler(acmeHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if acmeHandler != nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			acmeHandler.ServeHTTP(w, r)
			return
		}
		host := r.Host
		if host == "" {
			http.Error(w, "Missing Host header", http.StatusBadRequest)
			return
		}
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}
