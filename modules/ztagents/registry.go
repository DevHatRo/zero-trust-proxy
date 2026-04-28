package ztagents

import (
	"sync"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

type registry struct {
	mu     sync.RWMutex
	agents map[string]*Agent
}

func newRegistry() *registry {
	return &registry{agents: make(map[string]*Agent)}
}

func (r *registry) add(a *Agent) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[a.ID] = a
	return len(r.agents)
}

func (r *registry) remove(id string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.agents, id)
	return len(r.agents)
}

func (r *registry) get(id string) (*Agent, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.agents[id]
	return a, ok
}

func (r *registry) lookupByHost(host string) (*Agent, bool) {
	a, _, ok := r.lookupServiceByHost(host)
	return a, ok
}

// lookupServiceByHost returns the agent serving the given host along with
// a copy of its on-wire ServiceConfig (so callers don't read the agent's
// internal map without its lock).
func (r *registry) lookupServiceByHost(host string) (*Agent, *common.ServiceConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, a := range r.agents {
		a.mu.RLock()
		svc, ok := a.Services[host]
		var copy common.ServiceConfig
		if ok && svc != nil {
			copy = *svc
		}
		a.mu.RUnlock()
		if ok {
			return a, &copy, true
		}
	}
	return nil, nil, false
}

func (r *registry) snapshot() []*Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Agent, 0, len(r.agents))
	for _, a := range r.agents {
		out = append(out, a)
	}
	return out
}
