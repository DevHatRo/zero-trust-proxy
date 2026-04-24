package ztagents

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestApp_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    App
		wantErr string
	}{
		{
			name: "full config",
			input: "zerotrust_agents {\n" +
				"\tlisten :18443\n" +
				"\tcert_file /tmp/server.crt\n" +
				"\tkey_file /tmp/server.key\n" +
				"\tca_file /tmp/ca.crt\n" +
				"}\n",
			want: App{
				ListenAddr: ":18443",
				CertFile:   "/tmp/server.crt",
				KeyFile:    "/tmp/server.key",
				CAFile:     "/tmp/ca.crt",
			},
		},
		{
			name:    "unknown option",
			input:   "zerotrust_agents {\n\tnope 1\n}\n",
			wantErr: `unknown zerotrust_agents option "nope"`,
		},
		{
			name:    "missing arg",
			input:   "zerotrust_agents {\n\tlisten\n}\n",
			wantErr: `wrong argument count`,
		},
		{
			name: "check_addr option",
			input: "zerotrust_agents {\n" +
				"\tlisten :18443\n" +
				"\tcheck_addr 127.0.0.1:2021\n" +
				"}\n",
			want: App{ListenAddr: ":18443", CheckAddr: "127.0.0.1:2021"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tc.input)
			var a App
			err := a.UnmarshalCaddyfile(d)
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
			if a.ListenAddr != tc.want.ListenAddr ||
				a.CertFile != tc.want.CertFile ||
				a.KeyFile != tc.want.KeyFile ||
				a.CAFile != tc.want.CAFile ||
				a.CheckAddr != tc.want.CheckAddr {
				t.Fatalf("got %+v want %+v", a, tc.want)
			}
		})
	}
}

// TestParseGlobalOption exercises parseGlobalOption directly.
func TestParseGlobalOption_Valid(t *testing.T) {
	input := "zerotrust_agents {\n\tlisten :18443\n\tcert_file /c.crt\n\tkey_file /k.key\n\tca_file /ca.crt\n}\n"
	d := caddyfile.NewTestDispenser(input)
	result, err := parseGlobalOption(d, nil)
	if err != nil {
		t.Fatalf("parseGlobalOption: %v", err)
	}
	if result == nil {
		t.Fatal("parseGlobalOption returned nil result")
	}
}

func TestParseGlobalOption_Error(t *testing.T) {
	input := "zerotrust_agents {\n\tunknown_opt val\n}\n"
	d := caddyfile.NewTestDispenser(input)
	_, err := parseGlobalOption(d, nil)
	if err == nil {
		t.Fatal("expected error for unknown option")
	}
}
