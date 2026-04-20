package ztagents

import "sync"

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
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, a := range r.agents {
		a.mu.RLock()
		_, ok := a.Services[host]
		a.mu.RUnlock()
		if ok {
			return a, true
		}
	}
	return nil, false
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
