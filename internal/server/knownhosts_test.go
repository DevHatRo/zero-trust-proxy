package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKnownHosts_AddHasPersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "known_hosts.json")

	kh := loadKnownHosts(path)
	if kh.has("a.example") {
		t.Fatal("fresh set should be empty")
	}

	kh.add("A.Example") // mixed case — stored lowercased
	kh.add("b.example")
	kh.add("a.example") // duplicate — no-op

	if !kh.has("a.example") || !kh.has("b.example") {
		t.Fatal("added hosts not found")
	}
	if !kh.has("A.EXAMPLE") {
		t.Fatal("lookup should be case-insensitive")
	}

	// The file (and its parent dir) should have been created.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("persisted file missing: %v", err)
	}

	// A reload from disk sees the same hosts.
	reloaded := loadKnownHosts(path)
	if !reloaded.has("a.example") || !reloaded.has("b.example") {
		t.Fatal("reloaded set missing persisted hosts")
	}
}

func TestKnownHosts_MissingFileIsEmptyNotError(t *testing.T) {
	kh := loadKnownHosts(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if kh == nil {
		t.Fatal("loadKnownHosts returned nil")
	}
	if kh.has("anything.example") {
		t.Fatal("missing file should yield empty set")
	}
}

func TestKnownHosts_UnparseableFileIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	kh := loadKnownHosts(path) // must not panic or fail
	if kh.has("x.example") {
		t.Fatal("garbage file should yield empty set")
	}
	// And it should still be usable afterwards.
	kh.add("x.example")
	if !kh.has("x.example") {
		t.Fatal("add after ignoring garbage file failed")
	}
}

func TestKnownHosts_EmptyPathDisablesPersistence(t *testing.T) {
	kh := loadKnownHosts("")
	kh.add("x.example") // must not panic with empty path
	if !kh.has("x.example") {
		t.Fatal("in-memory add should still work with persistence disabled")
	}
}
