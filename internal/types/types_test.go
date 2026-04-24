package types

import (
	"strings"
	"testing"
)

func TestValidationError_Error(t *testing.T) {
	ve := ValidationError{Field: "hostname", Message: "must not be empty", Code: "REQUIRED"}
	s := ve.Error()
	if !strings.Contains(s, "hostname") {
		t.Fatalf("error string missing field: %q", s)
	}
	if !strings.Contains(s, "must not be empty") {
		t.Fatalf("error string missing message: %q", s)
	}
	if !strings.Contains(s, "REQUIRED") {
		t.Fatalf("error string missing code: %q", s)
	}
}
