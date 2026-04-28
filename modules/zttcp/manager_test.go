package zttcp

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

type fakeSender struct {
	msgs []*common.Message
}

func (f *fakeSender) SendMessage(msg *common.Message) error {
	f.msgs = append(f.msgs, msg)
	return nil
}

func TestAllocateAndRelease(t *testing.T) {
	m := NewManager()
	sender := &fakeSender{}

	port, err := m.Allocate(0, "agent1", "svc.example.com", false, sender)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if port == 0 {
		t.Fatal("expected non-zero port")
	}

	// Verify we can connect to it.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	m.Release("svc.example.com")

	// After release, port should be gone.
	_, err = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 200*time.Millisecond)
	if err == nil {
		t.Error("expected dial to fail after Release")
	}
}

func TestAllocatePortRange(t *testing.T) {
	m := NewManager()
	m.SetPortRange(20000, 20100)
	sender := &fakeSender{}

	_, err := m.Allocate(19999, "agent1", "svc.example.com", false, sender)
	if err == nil {
		t.Fatal("expected error for out-of-range port")
	}
}

func TestReleaseAgent(t *testing.T) {
	m := NewManager()
	sender := &fakeSender{}

	port1, err := m.Allocate(0, "agentA", "svc1.example.com", false, sender)
	if err != nil {
		t.Fatalf("Allocate svc1: %v", err)
	}
	port2, err := m.Allocate(0, "agentA", "svc2.example.com", false, sender)
	if err != nil {
		t.Fatalf("Allocate svc2: %v", err)
	}

	m.ReleaseAgent("agentA")

	for _, port := range []int{port1, port2} {
		_, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 200*time.Millisecond)
		if err == nil {
			t.Errorf("port %d still listening after ReleaseAgent", port)
		}
	}
}

func TestHandleConnectAck(t *testing.T) {
	m := NewManager()
	ch := make(chan error, 1)
	m.pendingMu.Lock()
	m.pending["test-id"] = &pendingConn{
		conn:  nil,
		ackCh: ch,
	}
	m.pendingMu.Unlock()

	m.HandleConnectAck("test-id", "")
	select {
	case err := <-ch:
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ack")
	}
}

func TestHandleConnectAckError(t *testing.T) {
	m := NewManager()
	ch := make(chan error, 1)
	m.pendingMu.Lock()
	m.pending["test-id"] = &pendingConn{ackCh: ch}
	m.pendingMu.Unlock()

	m.HandleConnectAck("test-id", "backend unreachable")
	select {
	case err := <-ch:
		if err == nil {
			t.Error("expected error, got nil")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestWriteToClientAndClose(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	m := NewManager()
	m.connsMu.Lock()
	m.conns["id1"] = &connEntry{conn: server}
	m.connsMu.Unlock()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := client.Read(buf)
		done <- buf[:n]
	}()

	if err := m.WriteToClient("id1", []byte("hello")); err != nil {
		t.Fatalf("WriteToClient: %v", err)
	}

	select {
	case got := <-done:
		if string(got) != "hello" {
			t.Errorf("got %q, want %q", got, "hello")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	m.CloseClient("id1")
	// After CloseClient the conn should be gone from the map.
	m.connsMu.RLock()
	_, ok := m.conns["id1"]
	m.connsMu.RUnlock()
	if ok {
		t.Error("expected conn to be removed after CloseClient")
	}
}

func TestReleaseAll(t *testing.T) {
	m := NewManager()
	sender := &fakeSender{}

	_, err := m.Allocate(0, "agent1", "svc.example.com", false, sender)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	server, client := net.Pipe()
	defer client.Close()
	m.connsMu.Lock()
	m.conns["id1"] = &connEntry{conn: server}
	m.connsMu.Unlock()

	m.ReleaseAll()

	// After ReleaseAll: no services, no conns.
	m.mu.Lock()
	nSvcs := len(m.services)
	m.mu.Unlock()
	if nSvcs != 0 {
		t.Errorf("expected 0 services, got %d", nSvcs)
	}
	m.connsMu.RLock()
	nConns := len(m.conns)
	m.connsMu.RUnlock()
	if nConns != 0 {
		t.Errorf("expected 0 conns, got %d", nConns)
	}
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
