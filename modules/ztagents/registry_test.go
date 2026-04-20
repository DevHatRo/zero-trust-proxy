package ztagents

import (
	"testing"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/types"
)

func newTestAgent(id string, hosts ...string) *Agent {
	a := NewAgent(id, nil)
	for _, h := range hosts {
		a.Services[h] = &common.ServiceConfig{
			ServiceConfig: types.ServiceConfig{Hostname: h},
		}
	}
	return a
}

func TestRegistryAddRemove(t *testing.T) {
	r := newRegistry()
	if n := r.add(newTestAgent("a1")); n != 1 {
		t.Fatalf("add returned %d, want 1", n)
	}
	if n := r.add(newTestAgent("a2")); n != 2 {
		t.Fatalf("add returned %d, want 2", n)
	}
	if _, ok := r.get("a1"); !ok {
		t.Fatal("get(a1): not found")
	}
	if n := r.remove("a1"); n != 1 {
		t.Fatalf("remove returned %d, want 1", n)
	}
	if _, ok := r.get("a1"); ok {
		t.Fatal("get(a1): still present after remove")
	}
}

func TestRegistryLookupByHost(t *testing.T) {
	r := newRegistry()
	r.add(newTestAgent("a1", "svc-a.example.com"))
	r.add(newTestAgent("a2", "svc-b.example.com", "svc-c.example.com"))

	tests := []struct {
		host    string
		wantID  string
		wantHit bool
	}{
		{"svc-a.example.com", "a1", true},
		{"svc-b.example.com", "a2", true},
		{"svc-c.example.com", "a2", true},
		{"missing.example.com", "", false},
	}
	for _, tc := range tests {
		got, ok := r.lookupByHost(tc.host)
		if ok != tc.wantHit {
			t.Errorf("lookupByHost(%q): hit=%v, want %v", tc.host, ok, tc.wantHit)
			continue
		}
		if ok && got.ID != tc.wantID {
			t.Errorf("lookupByHost(%q): id=%s, want %s", tc.host, got.ID, tc.wantID)
		}
	}
}

func TestAppLookupAgentDelegatesToRegistry(t *testing.T) {
	app := &App{rt: &runtime{registry: newRegistry()}}
	app.rt.registry.add(newTestAgent("a1", "foo.example.com"))

	if _, ok := app.LookupAgent("foo.example.com"); !ok {
		t.Fatal("LookupAgent should find foo.example.com")
	}
	if _, ok := app.LookupAgent("bar.example.com"); ok {
		t.Fatal("LookupAgent should miss bar.example.com")
	}
}
