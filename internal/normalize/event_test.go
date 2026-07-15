package normalize

import "testing"

func TestAgentNameTrimsWhitespace(t *testing.T) {
	got := AgentName("  codex  ")
	if got != "codex" {
		t.Fatalf("AgentName() = %q, want %q", got, "codex")
	}
}
