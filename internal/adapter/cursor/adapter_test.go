package cursor_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/adapter/cursor"
	"github.com/mitoriq/collector/internal/contracts"
	_ "modernc.org/sqlite"
)

var testIdentity = cursor.Identity{
	MachineEnrollmentID: "enrollment-1",
	MachineID:           "machine-1",
	MemberID:            "member-1",
	OrganizationID:      "org-1",
}

func TestCollectLocalStateReadsAiCodeTrackingCountersOnly(t *testing.T) {
	dbPath := makeCursorStateDB(t, map[string]string{
		"aiCodeTracking.dailyStats.v1.5.2026-07-04": `{"total_accepts":3,"total_lines_accepted":27,"prompt":"private prompt"}`,
		"notCursor": `{"total_accepts":999}`,
	})
	occurredAt := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)

	result, err := cursor.CollectLocalState(context.Background(), cursor.Options{
		Identity:         testIdentity,
		LocalStateDBPath: dbPath,
		Now:              func() time.Time { return occurredAt },
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.UsageMetrics) != 2 {
		t.Fatalf("usage metrics = %#v", result.UsageMetrics)
	}
	if result.UsageMetrics[0].Source != cursor.Source {
		t.Fatalf("source = %s", result.UsageMetrics[0].Source)
	}
	if result.UsageMetrics[0].Cost.Accuracy != contracts.CostAccuracyUnknown {
		t.Fatalf("cost = %#v", result.UsageMetrics[0].Cost)
	}
	if containsSensitiveValue(result, "private prompt") {
		t.Fatalf("result leaked local state value: %#v", result)
	}
}

func TestCollectLocalStateSkipsUndatedAggregateCounters(t *testing.T) {
	dbPath := makeCursorStateDB(t, map[string]string{
		"aiCodeTracking.total": `{"usage":7}`,
	})

	result, err := cursor.CollectLocalState(context.Background(), cursor.Options{
		Identity:         testIdentity,
		LocalStateDBPath: dbPath,
		Now:              func() time.Time { return time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.UsageMetrics) != 0 {
		t.Fatalf("usage metrics = %#v", result.UsageMetrics)
	}
}

func TestFetchAnalyticsCollectsTeamUsageCountsWithBasicAuth(t *testing.T) {
	var authHeaders []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authHeaders = append(authHeaders, request.Header.Get("authorization"))
		writer.Header().Set("content-type", "application/json")
		switch request.URL.Path {
		case "/analytics/team/agent-edits":
			_, _ = writer.Write([]byte(`{"data":[{"date":"2026-07-04","total_accepts":5,"total_lines_accepted":120}]}`))
		case "/analytics/team/models":
			_, _ = writer.Write([]byte(`{"data":[{"event_date":"2026-07-04","model":"claude-sonnet-4.5","usage":9}]}`))
		default:
			t.Fatalf("unexpected path = %s", request.URL.Path)
		}
	}))
	defer server.Close()

	result, err := cursor.FetchAnalytics(context.Background(), cursor.Options{
		APIBaseURL: server.URL,
		APIKey:     "cursor_key",
		HTTPClient: server.Client(),
		Identity:   testIdentity,
		Now:        func() time.Time { return time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(authHeaders) != 2 || !strings.HasPrefix(authHeaders[0], "Basic ") {
		t.Fatalf("auth headers = %#v", authHeaders)
	}
	if len(result.UsageMetrics) != 3 {
		t.Fatalf("usage metrics = %#v", result.UsageMetrics)
	}
	if result.UsageMetrics[0].UsageCount != 5 || result.UsageMetrics[0].Model != "cursor-agent-edits.accepts" {
		t.Fatalf("metric = %#v", result.UsageMetrics[0])
	}
	if result.UsageMetrics[2].UsageCount != 9 || result.UsageMetrics[2].Model != "claude-sonnet-4.5" {
		t.Fatalf("metric = %#v", result.UsageMetrics[2])
	}
}

func TestFetchAnalyticsSkipsRecordsWithoutDates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("content-type", "application/json")
		switch request.URL.Path {
		case "/analytics/team/agent-edits":
			_, _ = writer.Write([]byte(`{"data":[{"total_accepts":5,"total_lines_accepted":120}]}`))
		case "/analytics/team/models":
			_, _ = writer.Write([]byte(`{"data":[{"model":"claude-sonnet-4.5","usage":9}]}`))
		default:
			t.Fatalf("unexpected path = %s", request.URL.Path)
		}
	}))
	defer server.Close()

	result, err := cursor.FetchAnalytics(context.Background(), cursor.Options{
		APIBaseURL: server.URL,
		APIKey:     "cursor_key",
		HTTPClient: server.Client(),
		Identity:   testIdentity,
		Now:        func() time.Time { return time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.UsageMetrics) != 0 {
		t.Fatalf("usage metrics = %#v", result.UsageMetrics)
	}
}

func TestUsageCountersScopeSessionIDsToIdentity(t *testing.T) {
	dbPath := makeCursorStateDB(t, map[string]string{
		"aiCodeTracking.dailyStats.v1.5.2026-07-04": `{"usage":3}`,
	})
	occurredAt := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	secondIdentity := testIdentity
	secondIdentity.MachineEnrollmentID = "enrollment-2"

	first, err := cursor.CollectLocalState(context.Background(), cursor.Options{
		Identity:         testIdentity,
		LocalStateDBPath: dbPath,
		Now:              func() time.Time { return occurredAt },
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := cursor.CollectLocalState(context.Background(), cursor.Options{
		Identity:         secondIdentity,
		LocalStateDBPath: dbPath,
		Now:              func() time.Time { return occurredAt },
	})
	if err != nil {
		t.Fatal(err)
	}

	if first.UsageMetrics[0].SessionID == second.UsageMetrics[0].SessionID {
		t.Fatalf("session ids should be identity scoped: %s", first.UsageMetrics[0].SessionID)
	}
	if first.UsageMetrics[0].IdempotencyKey == second.UsageMetrics[0].IdempotencyKey {
		t.Fatalf("idempotency keys should be identity scoped: %s", first.UsageMetrics[0].IdempotencyKey)
	}
}

func TestNormalizeHookMapsStableLifecycleEvents(t *testing.T) {
	tests := []struct {
		name      string
		hookEvent string
		eventType contracts.EventType
	}{
		{name: "session start", hookEvent: "sessionStart", eventType: contracts.EventTypeSessionStarted},
		{name: "prompt", hookEvent: "beforeSubmitPrompt", eventType: contracts.EventTypePromptSubmitted},
		{name: "tool start", hookEvent: "preToolUse", eventType: contracts.EventTypeToolStarted},
		{name: "tool completion", hookEvent: "postToolUse", eventType: contracts.EventTypeToolCompleted},
		{name: "tool failure", hookEvent: "postToolUseFailure", eventType: contracts.EventTypeToolFailed},
		{name: "session end", hookEvent: "sessionEnd", eventType: contracts.EventTypeSessionStopped},
	}

	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(fmt.Sprintf(`{
				"conversation_id": "cursor-conversation-1",
				"hook_event_name": %q,
				"model": "cursor-auto",
				"timestamp": "2026-07-04T01:00:0%dZ",
				"tool_name": "Shell"
			}`, test.hookEvent, index))
			result, err := cursor.NormalizeHookJSON(body, cursor.Options{
				EnableHooksBeta: true,
				Identity:        testIdentity,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Events) != 1 || result.Events[0].Type != test.eventType {
				t.Fatalf("events = %#v", result.Events)
			}
		})
	}
}

func TestNormalizeHookUsesConversationIDAcrossWorkspaceChanges(t *testing.T) {
	first, err := cursor.NormalizeHookJSON([]byte(`{
		"conversation_id": "cursor-conversation-1",
		"cwd": "/repo/first",
		"hook_event_name": "sessionStart",
		"timestamp": "2026-07-04T01:00:00Z"
	}`), cursor.Options{EnableHooksBeta: true, Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}
	second, err := cursor.NormalizeHookJSON([]byte(`{
		"conversation_id": "cursor-conversation-1",
		"cwd": "/repo/second",
		"hook_event_name": "sessionEnd",
		"timestamp": "2026-07-04T01:00:01Z"
	}`), cursor.Options{EnableHooksBeta: true, Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}

	if len(first.Events) != 1 || len(second.Events) != 1 {
		t.Fatalf("events = first:%#v second:%#v", first.Events, second.Events)
	}
	if first.Events[0].SessionID != second.Events[0].SessionID {
		t.Fatalf("session ids differ: %s != %s", first.Events[0].SessionID, second.Events[0].SessionID)
	}
}

func TestNormalizeHookPrefersConversationIDOverLegacySessionID(t *testing.T) {
	withLegacyID, err := cursor.NormalizeHookJSON([]byte(`{
		"conversation_id": "cursor-conversation-1",
		"session_id": "legacy-session-1",
		"cwd": "/repo/first",
		"hook_event_name": "sessionStart",
		"timestamp": "2026-07-04T01:00:00Z"
	}`), cursor.Options{EnableHooksBeta: true, Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}
	conversationOnly, err := cursor.NormalizeHookJSON([]byte(`{
		"conversation_id": "cursor-conversation-1",
		"cwd": "/repo/second",
		"hook_event_name": "sessionStart",
		"timestamp": "2026-07-04T01:00:01Z"
	}`), cursor.Options{EnableHooksBeta: true, Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}

	if withLegacyID.Events[0].SessionID != conversationOnly.Events[0].SessionID {
		t.Fatalf(
			"conversation id did not win: %s != %s",
			withLegacyID.Events[0].SessionID,
			conversationOnly.Events[0].SessionID,
		)
	}
}

func TestNormalizeHookSeparatesConversationIDs(t *testing.T) {
	first, err := cursor.NormalizeHookJSON([]byte(`{
		"conversation_id": "cursor-conversation-1",
		"cwd": "/repo",
		"hook_event_name": "sessionStart"
	}`), cursor.Options{EnableHooksBeta: true, Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}
	second, err := cursor.NormalizeHookJSON([]byte(`{
		"conversation_id": "cursor-conversation-2",
		"cwd": "/repo",
		"hook_event_name": "sessionStart"
	}`), cursor.Options{EnableHooksBeta: true, Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}

	if first.Events[0].SessionID == second.Events[0].SessionID {
		t.Fatalf("different conversations shared session id: %s", first.Events[0].SessionID)
	}
}

func TestNormalizeHookScopesSessionIDToEnrollmentAndOrganization(t *testing.T) {
	body := []byte(`{
		"conversation_id": "cursor-conversation-1",
		"hook_event_name": "sessionStart"
	}`)
	first, err := cursor.NormalizeHookJSON(body, cursor.Options{
		EnableHooksBeta: true,
		Identity:        testIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherIdentity := testIdentity
	otherIdentity.MachineEnrollmentID = "enrollment-2"
	second, err := cursor.NormalizeHookJSON(body, cursor.Options{
		EnableHooksBeta: true,
		Identity:        otherIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}

	if first.Events[0].SessionID == second.Events[0].SessionID {
		t.Fatalf("different enrollments shared session id: %s", first.Events[0].SessionID)
	}
}

func TestNormalizeHookUsesStableInvocationIDsForIdempotency(t *testing.T) {
	body := []byte(`{
		"conversation_id": "cursor-conversation-1",
		"generation_id": "generation-1",
		"hook_event_name": "beforeSubmitPrompt"
	}`)
	first, err := cursor.NormalizeHookJSON(body, cursor.Options{
		EnableHooksBeta: true,
		Identity:        testIdentity,
		Now:             func() time.Time { return time.Date(2026, 7, 4, 1, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := cursor.NormalizeHookJSON(body, cursor.Options{
		EnableHooksBeta: true,
		Identity:        testIdentity,
		Now:             func() time.Time { return time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}

	if first.Events[0].IdempotencyKey != second.Events[0].IdempotencyKey {
		t.Fatalf(
			"redelivery changed idempotency key: %s != %s",
			first.Events[0].IdempotencyKey,
			second.Events[0].IdempotencyKey,
		)
	}
}

func TestNormalizeHookSeparatesToolUseIDsAtTheSameTimestamp(t *testing.T) {
	collect := func(toolUseID string) contracts.AgentEvent {
		result, err := cursor.NormalizeHookJSON([]byte(fmt.Sprintf(`{
			"conversation_id": "cursor-conversation-1",
			"hook_event_name": "preToolUse",
			"timestamp": "2026-07-04T01:00:00Z",
			"tool_name": "Shell",
			"tool_use_id": %q
		}`, toolUseID)), cursor.Options{EnableHooksBeta: true, Identity: testIdentity})
		if err != nil {
			t.Fatal(err)
		}

		return result.Events[0]
	}

	first := collect("tool-use-1")
	second := collect("tool-use-2")
	if first.IdempotencyKey == second.IdempotencyKey {
		t.Fatalf("different tool calls shared idempotency key: %s", first.IdempotencyKey)
	}
}

func TestNormalizeHookDoesNotLeakRawHookContent(t *testing.T) {
	result, err := cursor.NormalizeHookJSON([]byte(`{
		"conversation_id": "cursor-conversation-1",
		"workspace": "/repo",
		"hook_event_name": "preToolUse",
		"prompt": "private prompt",
		"tool_input": {"command": "cat /repo/private.txt"},
		"tool_name": "Shell"
	}`), cursor.Options{
		EnableHooksBeta:  true,
		Identity:         testIdentity,
		Now:              func() time.Time { return time.Date(2026, 7, 4, 1, 0, 0, 0, time.UTC) },
		SessionStartedAt: time.Date(2026, 7, 4, 1, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Events) != 1 {
		t.Fatalf("events = %#v", result.Events)
	}
	event := result.Events[0]
	if event.Type != contracts.EventTypeToolStarted || event.Source != cursor.Source {
		t.Fatalf("event = %#v", event)
	}
	for _, sensitive := range []string{"private prompt", "/repo/private.txt", "cat /repo"} {
		if containsSensitiveValue(result, sensitive) {
			t.Fatalf("result leaked %q: %#v", sensitive, result)
		}
	}
}

func TestNormalizeHookRequiresBetaFlag(t *testing.T) {
	_, err := cursor.NormalizeHookJSON([]byte(`{"conversation_id":"cursor-conversation-1"}`), cursor.Options{
		Identity: testIdentity,
	})

	if err == nil || !strings.Contains(err.Error(), "hooks beta") {
		t.Fatalf("err = %v", err)
	}
}

func TestNormalizeHookIgnoresUnsupportedPermissionSignal(t *testing.T) {
	result, err := cursor.NormalizeHookJSON([]byte(`{
		"conversation_id": "cursor-conversation-1",
		"hook_event_name": "permissionRequest"
	}`), cursor.Options{EnableHooksBeta: true, Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("unsupported permission signal produced events: %#v", result.Events)
	}
}

func TestNormalizeHookIgnoresTurnCompletionWithoutSynthesizingUsage(t *testing.T) {
	result, err := cursor.NormalizeHookJSON([]byte(`{
		"conversation_id": "cursor-conversation-1",
		"hook_event_name": "stop",
		"model": "cursor-auto"
	}`), cursor.Options{EnableHooksBeta: true, Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 || len(result.UsageMetrics) != 0 {
		t.Fatalf("turn completion produced telemetry: %#v", result)
	}
}

func TestNormalizeHookIgnoresToolSpecificAliases(t *testing.T) {
	result, err := cursor.NormalizeHookJSON([]byte(`{
		"conversation_id": "cursor-conversation-1",
		"hook_event_name": "beforeShellExecution",
		"tool_use_id": "tool-use-1"
	}`), cursor.Options{EnableHooksBeta: true, Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("tool-specific alias produced duplicate-prone event: %#v", result.Events)
	}
}

func makeCursorStateDB(t *testing.T, values map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.vscdb")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`create table ItemTable(key text primary key, value text not null)`); err != nil {
		t.Fatal(err)
	}
	for key, value := range values {
		if _, err := db.Exec(`insert into ItemTable(key, value) values(?, ?)`, key, value); err != nil {
			t.Fatal(err)
		}
	}

	return path
}

func containsSensitiveValue(value any, needle string) bool {
	body, _ := json.Marshal(value)
	return strings.Contains(string(body), needle)
}
