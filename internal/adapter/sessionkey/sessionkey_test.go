package sessionkey_test

import (
	"regexp"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/adapter/sessionkey"
)

func TestStableReturnsDeterministicOpaqueSessionKey(t *testing.T) {
	startedAt := time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC)

	first := sessionkey.Stable("session-1", "codex", "/private/repo", startedAt)
	second := sessionkey.Stable(" session-1 ", "codex", " /private/repo ", startedAt)
	other := sessionkey.Stable("session-1", "claude-code", "/private/repo", startedAt)

	if first != second {
		t.Fatalf("keys should be stable after trimming: %q != %q", first, second)
	}
	if first == other {
		t.Fatal("different tool names should produce different keys")
	}
	uuidPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidPattern.MatchString(first) {
		t.Fatalf("key should be a deterministic v4 uuid: %q", first)
	}
}
