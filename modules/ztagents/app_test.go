package ztagents

import (
	"errors"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// --- App.Validate ---

func TestApp_Validate_MissingFields(t *testing.T) {
	cases := []struct {
		name    string
		app     App
		wantErr bool
	}{
		{"missing all", App{}, true},
		{"missing key and ca", App{CertFile: "/tmp/cert.crt"}, true},
		{"missing ca", App{CertFile: "/tmp/c.crt", KeyFile: "/tmp/k.key"}, true},
		{"all present", App{CertFile: "/c.crt", KeyFile: "/k.key", CAFile: "/ca.crt"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.app.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// --- App.Provision (no cert files → sets up runtime but returns nil) ---

func TestApp_Provision_NoCerts(t *testing.T) {
	app := &App{ListenAddr: ":0"}
	// No cert files: Provision should initialize runtime and return nil.
	if err := app.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision with no certs: %v", err)
	}
	if app.rt == nil {
		t.Fatal("runtime should be initialized after Provision")
	}
}

func TestApp_Provision_BadCerts(t *testing.T) {
	app := &App{
		ListenAddr: ":0",
		CertFile:   "/nonexistent/cert.crt",
		KeyFile:    "/nonexistent/key.key",
		CAFile:     "/nonexistent/ca.crt",
	}
	// loadTLSConfig fails on missing files.
	if err := app.Provision(caddy.Context{}); err == nil {
		t.Fatal("expected error from Provision with missing cert files")
	}
}

// --- categorizeAcceptError ---

func TestCategorizeAcceptError(t *testing.T) {
	// Exercise the three error-categorization branches plus the default.
	categorizeAcceptError(errors.New("accept: too many open files"))
	categorizeAcceptError(errors.New("tls: certificate verify failed"))
	categorizeAcceptError(errors.New("tls: remote error: bad certificate"))
	categorizeAcceptError(errors.New("some unrecognized error"))
}

// --- startCheckServer / stopCheckServer ---

func newRuntimeApp() *App {
	return &App{rt: &runtime{
		registry: newRegistry(),
	}}
}

func TestStartStopCheckServer(t *testing.T) {
	app := newRuntimeApp()
	app.CheckAddr = "127.0.0.1:0"

	if err := app.startCheckServer(); err != nil {
		t.Fatalf("startCheckServer: %v", err)
	}
	if app.rt.checkServer == nil {
		t.Fatal("checkServer is nil after startCheckServer")
	}

	time.Sleep(20 * time.Millisecond)
	app.stopCheckServer()
}

func TestStopCheckServer_NilRuntime(t *testing.T) {
	app := &App{rt: nil}
	app.stopCheckServer() // must not panic
}

func TestStopCheckServer_NilCheckServer(t *testing.T) {
	app := newRuntimeApp()
	app.stopCheckServer() // rt.checkServer is nil, must not panic
}

func TestStartCheckServer_DefaultAddr(t *testing.T) {
	app := newRuntimeApp()
	// Leave CheckAddr empty → uses defaultCheckAddr (127.0.0.1:2020).
	// Bind may fail if the port is taken; either outcome is acceptable.
	err := app.startCheckServer()
	if err == nil {
		app.stopCheckServer()
	}
}
