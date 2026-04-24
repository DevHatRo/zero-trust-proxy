package ztrouter

import (
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func TestHandler_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr string
	}{
		{
			name:  "explicit timeout",
			input: "zerotrust_router {\n\trequest_timeout 30s\n}\n",
			want:  30 * time.Second,
		},
		{
			name:  "no options",
			input: "zerotrust_router\n",
			want:  0, // provisioner assigns the default at runtime
		},
		{
			name:    "unknown option",
			input:   "zerotrust_router {\n\tnope 1s\n}\n",
			wantErr: `unknown zerotrust_router option "nope"`,
		},
		{
			name:    "bad duration",
			input:   "zerotrust_router {\n\trequest_timeout not-a-duration\n}\n",
			wantErr: `invalid request_timeout`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tc.input)
			var h Handler
			err := h.UnmarshalCaddyfile(d)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%q, want substring %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := time.Duration(h.RequestTimeout); got != tc.want {
				t.Fatalf("RequestTimeout=%v want %v", got, tc.want)
			}
		})
	}
}

// TestParseHandlerCaddyfile exercises parseHandlerCaddyfile via Helper.
func TestParseHandlerCaddyfile(t *testing.T) {
	input := "zerotrust_router {\n\trequest_timeout 1m\n}\n"
	d := caddyfile.NewTestDispenser(input)
	h := httpcaddyfile.Helper{Dispenser: d}
	handler, err := parseHandlerCaddyfile(h)
	if err != nil {
		t.Fatalf("parseHandlerCaddyfile: %v", err)
	}
	if handler == nil {
		t.Fatal("parseHandlerCaddyfile returned nil handler")
	}
}

func TestParseHandlerCaddyfile_Error(t *testing.T) {
	input := "zerotrust_router {\n\tbadopt 1m\n}\n"
	d := caddyfile.NewTestDispenser(input)
	h := httpcaddyfile.Helper{Dispenser: d}
	_, err := parseHandlerCaddyfile(h)
	if err == nil {
		t.Fatal("expected error for unknown option")
	}
	if !strings.Contains(err.Error(), "badopt") {
		t.Fatalf("err=%q, expected to mention badopt", err.Error())
	}
}
