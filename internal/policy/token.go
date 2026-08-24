package policy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// tokenEntry is one compiled service token: the SHA-256 of the secret
// (config never carries plaintext) plus the identity it grants.
type tokenEntry struct {
	name   string
	hash   [sha256.Size]byte
	groups []string
}

// tokenTable is the compiled service-token list. Immutable; swapped
// with the engine snapshot on reload.
type tokenTable struct {
	entries []tokenEntry
}

func compileTokens(tokens []serverconfig.ServiceToken) (*tokenTable, error) {
	t := &tokenTable{entries: make([]tokenEntry, 0, len(tokens))}
	for _, st := range tokens {
		hexPart := strings.TrimPrefix(st.Hash, "sha256:")
		raw, err := hex.DecodeString(hexPart)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("service token %q: invalid sha256 hash", st.Name)
		}
		e := tokenEntry{name: st.Name, groups: st.Groups}
		copy(e.hash[:], raw)
		t.entries = append(t.entries, e)
	}
	return t, nil
}

// lookup resolves a presented bearer secret. The comparison is
// constant-time over the FULL table — no early exit — so response
// timing reveals neither which token matched nor whether any did.
func (t *tokenTable) lookup(presented string) (*Identity, bool) {
	sum := sha256.Sum256([]byte(presented))
	matched := -1
	for i := range t.entries {
		if subtle.ConstantTimeCompare(sum[:], t.entries[i].hash[:]) == 1 {
			matched = i
		}
	}
	if matched < 0 {
		return nil, false
	}
	e := &t.entries[matched]
	return &Identity{
		Source:  SourceServiceToken,
		Subject: e.name,
		Groups:  e.groups,
	}, true
}

// bearerToken extracts the presented token from the request headers:
// `Authorization: Bearer <t>` or `X-ZTP-Token: <t>`. The Bearer scheme
// is matched case-insensitively (RFC 7235: auth-scheme is a
// case-insensitive token) and whitespace-only values count as absent.
func bearerToken(authorization, xToken string) (string, bool) {
	const prefix = "bearer "
	if len(authorization) >= len(prefix) && strings.EqualFold(authorization[:len(prefix)], prefix) {
		if t := strings.TrimSpace(authorization[len(prefix):]); t != "" {
			return t, true
		}
	}
	if t := strings.TrimSpace(xToken); t != "" {
		return t, true
	}
	return "", false
}
