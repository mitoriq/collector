package contracts

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCollectorBatchJSONOmitsLocalGateMetadata(t *testing.T) {
	body, err := json.Marshal(CollectorBatch{Events: []AgentEvent{
		{
			ID:                     "evt_1",
			SchemaVersion:          1,
			SessionID:              "session-1",
			Source:                 "codex-cli",
			OccurredAt:             "2026-07-09T00:00:00Z",
			IdempotencyKey:         "key-1",
			PrivacyLevel:           "L2",
			Type:                   EventTypeToolCompleted,
			Payload:                map[string]any{"filesChanged": float64(1)},
			LocalDenyPaths:         []string{"secrets/token.txt"},
			LocalRepoRemoteURLHash: "repo-hash",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(body)
	if strings.Contains(encoded, "LocalDenyPaths") || strings.Contains(encoded, "secrets/token.txt") || strings.Contains(encoded, "repo-hash") {
		t.Fatalf("collector batch leaked local gate metadata: %s", encoded)
	}
}
