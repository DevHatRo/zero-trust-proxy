package ztagents

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/types"
)

func newAppWithPipe(t *testing.T) (*App, *Agent, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	app := &App{rt: &runtime{registry: newRegistry()}}
	agent := NewAgent("test-agent", server)
	app.rt.registry.add(agent)
	return app, agent, client
}

func readMessage(t *testing.T, c net.Conn) *common.Message {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg common.Message
	if err := json.NewDecoder(c).Decode(&msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return &msg
}

func TestHandleMessagePing(t *testing.T) {
	app, agent, client := newAppWithPipe(t)

	go func() {
		_ = app.handleAgentMessage(agent, &common.Message{Type: "ping", ID: "p1"})
	}()

	resp := readMessage(t, client)
	if resp.Type != "pong" || resp.ID != "p1" {
		t.Fatalf("got %+v, want pong p1", resp)
	}
}

func TestHandleMessageServiceAddRegistersHost(t *testing.T) {
	app, agent, client := newAppWithPipe(t)

	msg := &common.Message{
		Type: "service_add",
		ID:   "s1",
		Service: &common.ServiceConfig{
			ServiceConfig: types.ServiceConfig{Hostname: "app.example.com"},
		},
	}
	go func() { _ = app.handleAgentMessage(agent, msg) }()

	resp := readMessage(t, client)
	if resp.Type != "service_add_response" {
		t.Fatalf("got %s, want service_add_response", resp.Type)
	}

	if found, ok := app.LookupAgent("app.example.com"); !ok || found != agent {
		t.Fatalf("LookupAgent: ok=%v agent=%v", ok, found)
	}
}

func TestHandleMessageServiceRemoveUnregistersHost(t *testing.T) {
	app, agent, client := newAppWithPipe(t)
	agent.Services["app.example.com"] = &common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{Hostname: "app.example.com"},
	}

	msg := &common.Message{
		Type: "service_remove",
		ID:   "s1",
		Service: &common.ServiceConfig{
			ServiceConfig: types.ServiceConfig{Hostname: "app.example.com"},
		},
	}
	go func() { _ = app.handleAgentMessage(agent, msg) }()

	resp := readMessage(t, client)
	if resp.Type != "service_remove_response" {
		t.Fatalf("got %s, want service_remove_response", resp.Type)
	}

	if _, ok := app.LookupAgent("app.example.com"); ok {
		t.Fatal("host should be unregistered")
	}
}

func TestHandleMessageHttpResponseRoutesToHandler(t *testing.T) {
	app, agent, _ := newAppWithPipe(t)

	got := make(chan *common.Message, 4)
	agent.SetResponseHandler("req-42", func(m *common.Message) { got <- m })

	// Dispatch twice — the same handler must be reachable for both, since
	// download streaming delivers the initial response plus subsequent chunks
	// through the same registration. The router's defer is responsible for
	// removing the handler when the request finishes.
	for i := 0; i < 2; i++ {
		err := app.handleAgentMessage(agent, &common.Message{
			Type: "http_response",
			ID:   "req-42",
			HTTP: &common.HTTPData{StatusCode: 200},
		})
		if err != nil {
			t.Fatalf("handleAgentMessage #%d: %v", i, err)
		}
	}

	for i := 0; i < 2; i++ {
		select {
		case m := <-got:
			if m.HTTP.StatusCode != 200 {
				t.Fatalf("status=%d, want 200", m.HTTP.StatusCode)
			}
		case <-time.After(1 * time.Second):
			t.Fatalf("handler not invoked for dispatch #%d", i)
		}
	}

	if _, ok := agent.GetResponseHandler("req-42"); !ok {
		t.Fatal("handler should still be registered; removal is the caller's job")
	}
}

func TestHandleMessageRejectsMissingService(t *testing.T) {
	app, agent, _ := newAppWithPipe(t)
	err := app.handleAgentMessage(agent, &common.Message{Type: "service_add", ID: "x"})
	if err == nil {
		t.Fatal("expected error for service_add without config")
	}
}
