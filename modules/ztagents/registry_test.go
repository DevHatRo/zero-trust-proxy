package ztagents

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestRegistry_LookupServiceByHost_ReturnsCopyWithTimeout(t *testing.T) {
	r := newRegistry()
	a := NewAgent("a1", nil)
	a.Services["svc.example"] = &common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{
			Hostname: "svc.example",
			Backend:  "127.0.0.1:9000",
			Timeout:  500 * time.Millisecond,
		},
	}
	r.add(a)

	gotAgent, gotSvc, ok := r.lookupServiceByHost("svc.example")
	if !ok {
		t.Fatal("lookupServiceByHost: not found")
	}
	if gotAgent.ID != "a1" {
		t.Fatalf("agent ID = %q, want a1", gotAgent.ID)
	}
	if gotSvc.Timeout != 500*time.Millisecond {
		t.Fatalf("timeout = %v, want 500ms", gotSvc.Timeout)
	}

	// Mutating the returned copy must not affect the registry's stored
	// service config — guards against callers stomping shared state.
	gotSvc.Timeout = 9 * time.Second
	_, again, _ := r.lookupServiceByHost("svc.example")
	if again.Timeout != 500*time.Millisecond {
		t.Fatalf("registry mutated through returned copy: %v", again.Timeout)
	}

	if _, _, ok := r.lookupServiceByHost("missing.example"); ok {
		t.Fatal("expected miss for unknown host")
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

func TestRegistrySnapshot(t *testing.T) {
	r := newRegistry()
	r.add(newTestAgent("a1", "svc1.example.com"))
	r.add(newTestAgent("a2", "svc2.example.com"))

	snap := r.snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len=%d, want 2", len(snap))
	}
	ids := map[string]bool{}
	for _, a := range snap {
		ids[a.ID] = true
	}
	if !ids["a1"] || !ids["a2"] {
		t.Fatalf("snapshot missing agents: %v", ids)
	}
}

func TestAgent_TakeResponseHandler(t *testing.T) {
	a := NewAgent("take-test", nil)
	called := false
	a.SetResponseHandler("r1", func(*common.Message) { called = true })

	h, ok := a.TakeResponseHandler("r1")
	if !ok || h == nil {
		t.Fatal("TakeResponseHandler should return handler")
	}
	h(nil)
	if !called {
		t.Fatal("handler should be callable after Take")
	}

	// Second take should return ok=false (handler removed).
	_, ok = a.TakeResponseHandler("r1")
	if ok {
		t.Fatal("handler should be removed after TakeResponseHandler")
	}
}

func TestNewTestApp_And_Helpers(t *testing.T) {
	app := NewTestApp()
	if app == nil {
		t.Fatal("NewTestApp returned nil")
	}

	agent := newTestAgent("ta1", "helper.example.com")
	app.AddAgent(agent)

	found, ok := app.LookupAgent("helper.example.com")
	if !ok || found != agent {
		t.Fatalf("LookupAgent after AddAgent: ok=%v", ok)
	}

	// DispatchAgentMessageForTest — use a known-good message type
	err := app.DispatchAgentMessageForTest(agent, &common.Message{Type: "unknown_op", ID: "x"})
	if err != nil {
		t.Fatalf("DispatchAgentMessageForTest: %v", err)
	}
}

func TestServeCheckDomain_OK(t *testing.T) {
	app := &App{rt: &runtime{registry: newRegistry(), wsManager: nil}}
	app.rt.registry.add(newTestAgent("a1", "ok.example.com"))

	req := httptest.NewRequest(http.MethodGet, "/zero-trust/check-domain?domain=ok.example.com", nil)
	rr := httptest.NewRecorder()
	app.serveCheckDomain(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
}

func TestServeCheckDomain_NotFound(t *testing.T) {
	app := &App{rt: &runtime{registry: newRegistry(), wsManager: nil}}

	req := httptest.NewRequest(http.MethodGet, "/zero-trust/check-domain?domain=missing.example.com", nil)
	rr := httptest.NewRecorder()
	app.serveCheckDomain(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", rr.Code)
	}
}

func TestServeCheckDomain_MissingDomain(t *testing.T) {
	app := &App{rt: &runtime{registry: newRegistry(), wsManager: nil}}

	req := httptest.NewRequest(http.MethodGet, "/zero-trust/check-domain", nil)
	rr := httptest.NewRecorder()
	app.serveCheckDomain(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
}

func TestServeCheckDomain_NilRuntime(t *testing.T) {
	app := &App{}

	req := httptest.NewRequest(http.MethodGet, "/zero-trust/check-domain?domain=any.example.com", nil)
	rr := httptest.NewRecorder()
	app.serveCheckDomain(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
}
