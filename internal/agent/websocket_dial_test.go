package agent

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/types"
)

func svcWithProtocol(protocol string) *common.ServiceConfig {
	return &common.ServiceConfig{
		ServiceConfig: types.ServiceConfig{Hostname: "svc.example.com", Protocol: protocol},
	}
}

// TestWSDialPlan verifies that the backend's explicit scheme wins over the
// client-facing service protocol — the regression that made WebSocket dials
// use TLS against plain-http backends (e.g. Home Assistant behind an https
// service) while regular HTTP requests to the same backend worked.
func TestWSDialPlan(t *testing.T) {
	cases := []struct {
		name     string
		protocol string // service.Protocol (client-facing)
		backend  string
		wantAddr string
		wantTLS  bool
	}{
		{"http backend under https service", "https", "http://10.0.0.5:8123", "10.0.0.5:8123", false},
		{"ws backend under https service", "https", "ws://10.0.0.5:8123", "10.0.0.5:8123", false},
		{"https backend under http service", "http", "https://10.0.0.5:8443", "10.0.0.5:8443", true},
		{"wss backend", "http", "wss://10.0.0.5:8443", "10.0.0.5:8443", true},
		{"no scheme falls back to service protocol https", "https", "10.0.0.5:8123", "10.0.0.5:8123", true},
		{"no scheme falls back to service protocol http", "http", "10.0.0.5:8123", "10.0.0.5:8123", false},
		{"https backend without port gets 443", "http", "https://backend.internal", "backend.internal:443", true},
		{"http backend without port gets 80", "https", "http://backend.internal", "backend.internal:80", false},
		{"path component is stripped", "https", "http://10.0.0.5:8123/api/websocket", "10.0.0.5:8123", false},
		{"path without port is stripped before defaulting", "http", "http://backend.internal/ws", "backend.internal:80", false},
		{"no scheme with path", "http", "10.0.0.5:8123/ws", "10.0.0.5:8123", false},
		{"ipv6 with port kept as-is", "http", "http://[::1]:8123", "[::1]:8123", false},
		{"ipv6 without port gets default", "http", "http://[::1]", "[::1]:80", false},
		{"ipv6 without port or brackets normalised", "https", "https://[fd00::5]", "[fd00::5]:443", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, useTLS := wsDialPlan(svcWithProtocol(tc.protocol), tc.backend)
			if addr != tc.wantAddr || useTLS != tc.wantTLS {
				t.Fatalf("wsDialPlan(%q, protocol=%q) = (%q, %v), want (%q, %v)",
					tc.backend, tc.protocol, addr, useTLS, tc.wantAddr, tc.wantTLS)
			}
		})
	}
}

// TestReadUpgradeResponse_GluedFrame verifies that bytes the backend sends in
// the same segment as its 101 response (its first WebSocket frame) are
// preserved rather than truncated away.
func TestReadUpgradeResponse_GluedFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	headers := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	frame := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'} // tiny WS text frame
	go func() {
		_, _ = server.Write(append([]byte(headers), frame...))
	}()

	raw, err := readUpgradeResponse(client, 2*time.Second)
	if err != nil {
		t.Fatalf("readUpgradeResponse: %v", err)
	}
	if !strings.HasPrefix(string(raw), "HTTP/1.1 101") {
		t.Fatalf("raw does not start with the status line: %q", raw[:min(len(raw), 40)])
	}
	if !bytes.HasSuffix(raw, frame) {
		t.Fatalf("glued frame bytes were lost: raw ends with %q", raw[max(0, len(raw)-10):])
	}
}

// TestReadUpgradeResponse_SplitHeaders verifies that headers spanning
// multiple reads are reassembled instead of being cut at the first read.
func TestReadUpgradeResponse_SplitHeaders(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	part1 := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: web"
	part2 := "socket\r\n\r\n"
	go func() {
		_, _ = server.Write([]byte(part1))
		time.Sleep(20 * time.Millisecond)
		_, _ = server.Write([]byte(part2))
	}()

	raw, err := readUpgradeResponse(client, 2*time.Second)
	if err != nil {
		t.Fatalf("readUpgradeResponse: %v", err)
	}
	if string(raw) != part1+part2 {
		t.Fatalf("raw = %q, want reassembled headers", raw)
	}
}

// TestReadUpgradeResponse_OversizedHeaders verifies the 64KiB guard.
func TestReadUpgradeResponse_OversizedHeaders(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		junk := bytes.Repeat([]byte("X"), 4096)
		for i := 0; i < 20; i++ { // 80KiB, no terminator
			if _, err := server.Write(junk); err != nil {
				return
			}
		}
	}()

	if _, err := readUpgradeResponse(client, 2*time.Second); err == nil {
		t.Fatal("expected error for oversized headers, got nil")
	}
}

// TestReadUpgradeResponse_StalledBackend verifies that a backend which sends
// partial headers and then goes silent cannot pin the goroutine forever — the
// read deadline aborts the wait.
func TestReadUpgradeResponse_StalledBackend(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = server.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: web")) // never finishes
	}()

	start := time.Now()
	_, err := readUpgradeResponse(client, 150*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error for stalled backend, got nil")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stalled read took %v — deadline not applied", elapsed)
	}
}
