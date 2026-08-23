package ztagents

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// Phase 0 control-plane hardening: certificate revocation, agent
// identity binding (register ID ↔ client cert), and the per-agent
// hostname ACL. All default off / allow-all so an unconfigured server
// behaves exactly as before.

// revocationSet is the immutable set of denied certificate serials
// (lowercase hex). Swapped atomically on SIGHUP so a CRL re-read never
// races the handshake path.
type revocationSet struct {
	serials map[string]struct{}
}

func (r *revocationSet) has(serial string) bool {
	if r == nil || len(r.serials) == 0 {
		return false
	}
	_, ok := r.serials[strings.ToLower(serial)]
	return ok
}

func (r *revocationSet) empty() bool { return r == nil || len(r.serials) == 0 }

// buildRevocationSet merges the inline denylist with the CRL file (if
// configured). CRL read errors are returned so a SIGHUP with a broken
// CRL keeps the previous set in force.
func buildRevocationSet(cfg serverconfig.RevocationConfig) (*revocationSet, error) {
	set := &revocationSet{serials: make(map[string]struct{})}
	for _, s := range cfg.DeniedSerials {
		set.serials[strings.ToLower(s)] = struct{}{}
	}
	if cfg.CRLFile != "" {
		serials, err := serverconfig.LoadCRLSerials(cfg.CRLFile)
		if err != nil {
			return nil, err
		}
		for _, s := range serials {
			set.serials[s] = struct{}{}
		}
	}
	return set, nil
}

// peerIdentity returns the identity string the agent's register ID
// must match under the configured bind mode. ok=false means no check
// applies (bind_to: none or "").
func peerIdentity(cert *x509.Certificate, mode string) (id string, ok bool) {
	switch mode {
	case "cn":
		return cert.Subject.CommonName, true
	case "san":
		// Documented contract: the agent ID lives in the first DNS SAN.
		if len(cert.DNSNames) > 0 {
			return cert.DNSNames[0], true
		}
		return "", true // no SAN present — any ID mismatches, rejected
	default:
		return "", false
	}
}

// certSerialHex renders a certificate serial as lowercase hex, the
// canonical form used by the revocation set and logs.
func certSerialHex(cert *x509.Certificate) string {
	return strings.ToLower(cert.SerialNumber.Text(16))
}

// normalizedVersion maps the on-wire version to the effective one
// (0 = an agent built before versioning = version 1).
func normalizedVersion(v int) int {
	if v == 0 {
		return 1
	}
	return v
}

// IdentityHooks are optional metric callbacks; nil funcs are skipped.
type IdentityHooks struct {
	// IdentityMismatch fires when the register ID differs from the cert
	// identity — including in bind_to:none observe mode.
	IdentityMismatch func()
	// RegisterRejected fires with reason "version" | "identity" | "acl".
	// (Revoked certs fail the TLS handshake before register.)
	RegisterRejected func(reason string)
}

// registerError encodes a register-time rejection.
type registerError struct {
	reason string // metric label
	msg    string // sent to the agent in register_response.Error
}

func (e *registerError) Error() string { return e.msg }

// checkRegister runs the Phase 0 gate: protocol version, identity
// binding, and ACL membership — in that order, all before the agent is
// added to the registry. On success it returns the compiled ACL globs
// for the agent (nil = unrestricted). A wire version of 0 (an agent
// built before versioning) is treated as version 1.
func (a *App) checkRegister(id string, version int, cert *x509.Certificate) ([]hostGlob, *registerError) {
	if version == 0 {
		version = 1
	}
	if version < common.MinSupportedVersion || version > common.ProtocolVersion {
		return nil, &registerError{
			reason: "version",
			msg: fmt.Sprintf("unsupported protocol version %d (server supports %d–%d)",
				version, common.MinSupportedVersion, common.ProtocolVersion),
		}
	}

	hooks := a.rt.identityHooks()
	if cert == nil {
		// No peer certificate. Impossible over the real mTLS listener
		// (RequireAndVerifyClientCert), but this function must fail
		// closed on its own: if identity binding is configured, a
		// cert-less connection (non-TLS test harness, future reuse of
		// the handler) must not bypass it.
		if a.rt.bindTo == "cn" || a.rt.bindTo == "san" {
			return nil, &registerError{
				reason: "identity",
				msg:    fmt.Sprintf("no client certificate to verify agent identity (bind_to=%s)", a.rt.bindTo),
			}
		}
	} else {
		if want, enforce := peerIdentity(cert, a.rt.bindTo); enforce {
			if id != want {
				if hooks.IdentityMismatch != nil {
					hooks.IdentityMismatch()
				}
				return nil, &registerError{
					reason: "identity",
					msg:    fmt.Sprintf("agent ID %q does not match certificate identity %q (bind_to=%s)", id, want, a.rt.bindTo),
				}
			}
		} else {
			// Observe mode (bind_to none/""): count and log would-be
			// mismatches against the CN so operators can rotate certs
			// before flipping to cn.
			if cn := cert.Subject.CommonName; cn != "" && cn != id {
				if hooks.IdentityMismatch != nil {
					hooks.IdentityMismatch()
				}
				log.Warn("ztagents: agent %s cert CN is %q — would be rejected under identity.bind_to=cn", id, cn)
			}
		}
	}

	entry, listed := a.rt.acl[id]
	if !listed && !a.rt.aclUnlisted {
		return nil, &registerError{
			reason: "acl",
			msg:    fmt.Sprintf("agent %q is not in the server ACL and allow_unlisted is false", id),
		}
	}
	return entry, nil
}
