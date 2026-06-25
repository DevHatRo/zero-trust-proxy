package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// knownHosts is the persistent set of hostnames that an agent has registered
// at some point. It exists to decouple TLS certificate serving from a live
// agent connection: in ACME mode the HostPolicy gates cert issuance, and
// without this set a restart with no agents connected (or a stopped agent)
// would refuse to serve even a cached certificate — failing the TLS handshake
// with ERR_SSL_PROTOCOL_ERROR before any HTTP error page could be rendered.
//
// By remembering hosts that were genuinely registered, the handshake can
// complete from the ACME cache while the agent is down, letting ztrouter
// return the branded "Agent Unreachable" page instead. Hosts are only ever
// added when an agent is actually serving them, so this never broadens cert
// issuance to arbitrary SNI values.
//
// The set is persisted as a sorted JSON array via atomic temp-file rename.
// Persistence failures are non-fatal (logged): the in-memory set still works
// for the life of the process.
type knownHosts struct {
	mu   sync.Mutex
	set  map[string]struct{}
	path string // empty disables persistence (used in tests)
}

// loadKnownHosts reads the persisted set from path. A missing or unparseable
// file yields an empty set — this is expected on first run and must not fail
// startup.
func loadKnownHosts(path string) *knownHosts {
	kh := &knownHosts{set: make(map[string]struct{}), path: path}
	if path == "" {
		return kh
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return kh // missing file on first run is normal
	}
	var hosts []string
	if err := json.Unmarshal(data, &hosts); err != nil {
		log.Warn("known-hosts: ignoring unparseable %s: %v", path, err)
		return kh
	}
	for _, h := range hosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			kh.set[h] = struct{}{}
		}
	}
	return kh
}

// has reports whether host is in the set (case-insensitive).
func (kh *knownHosts) has(host string) bool {
	host = strings.ToLower(host)
	kh.mu.Lock()
	defer kh.mu.Unlock()
	_, ok := kh.set[host]
	return ok
}

// add records host and persists the set if it changed. It is a no-op when host
// is already present, so the common (already-known) path does no disk I/O.
func (kh *knownHosts) add(host string) {
	host = strings.ToLower(host)
	kh.mu.Lock()
	defer kh.mu.Unlock()
	if _, ok := kh.set[host]; ok {
		return
	}
	kh.set[host] = struct{}{}
	kh.persistLocked()
}

// persistLocked writes the set to disk atomically. Caller holds kh.mu.
func (kh *knownHosts) persistLocked() {
	if kh.path == "" {
		return
	}
	hosts := make([]string, 0, len(kh.set))
	for h := range kh.set {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	data, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		log.Error("known-hosts: marshal failed: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(kh.path), 0o700); err != nil {
		log.Error("known-hosts: mkdir %s: %v", filepath.Dir(kh.path), err)
		return
	}
	tmp := kh.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Error("known-hosts: write %s: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, kh.path); err != nil {
		log.Error("known-hosts: rename %s -> %s: %v", tmp, kh.path, err)
	}
}
