package cli

import (
	"strings"
	"testing"
)

func TestValidateClientIDs(t *testing.T) {
	if err := validateClientIDs([]string{"claude-code", "cursor"}); err != nil {
		t.Fatalf("valid ids rejected: %v", err)
	}
	err := validateClientIDs([]string{"claude"})
	if err == nil || !strings.Contains(err.Error(), `"claude"`) || !strings.Contains(err.Error(), "claude-code") {
		t.Fatalf("want unknown-id error naming valid ids, got %v", err)
	}
}
