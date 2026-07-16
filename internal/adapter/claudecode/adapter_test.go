package claudecode_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/adapter/claudecode"
	"github.com/mitoriq/collector/internal/adapter/gitcontext"
	"github.com/mitoriq/collector/internal/contracts"
)

var testIdentity = claudecode.Identity{
	MachineEnrollmentID: "enrollment-1",
	MachineID:           "machine-1",
	MemberID:            "member-1",
	OrganizationID:      "org-1",
}

func TestNormalizeHookJSONMapsSessionStartToMetadataOnlyEvent(t *testing.T) {
	startedAt := time.Date(2026, 7, 4, 1, 2, 3, 0, time.UTC)
	body := []byte(`{
		"session_id": "claude-session-1",
		"transcript_path": "/Users/dev/.claude/projects/private.jsonl",
		"cwd": "/Users/dev/private-project",
		"hook_event_name": "SessionStart",
		"source": "startup",
		"model": "claude-sonnet-5"
	}`)

	result, err := claudecode.NormalizeHookJSON(body, claudecode.Options{
		Identity:         testIdentity,
		Now:              func() time.Time { return startedAt },
		SessionStartedAt: startedAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(result.Events))
	}
	event := result.Events[0]
	if event.Type != contracts.EventTypeSessionStarted {
		t.Fatalf("type = %s, want session.started", event.Type)
	}
	if event.Source != claudecode.Source {
		t.Fatalf("source = %s, want %s", event.Source, claudecode.Source)
	}
	if event.SessionID != claudecode.StableSessionKey("claude-session-1", claudecode.Source, "/Users/dev/private-project", startedAt) {
		t.Fatalf("session id = %q", event.SessionID)
	}
	if event.Payload["model"] != "claude-sonnet-5" || event.Payload["repo"] != nil {
		t.Fatalf("payload = %#v", event.Payload)
	}
	if containsSensitiveValue(event.Payload, "private-project") || containsSensitiveValue(event.Payload, "private.jsonl") {
		t.Fatalf("payload leaked local path: %#v", event.Payload)
	}
}

func TestNormalizeHookJSONAddsRepoMetadataFromResolver(t *testing.T) {
	startedAt := time.Date(2026, 7, 4, 1, 2, 3, 0, time.UTC)
	relativePath := "apps/collector"
	body := []byte(`{
		"session_id": "claude-session-1",
		"cwd": "/Users/dev/work/example-repo/apps/collector",
		"hook_event_name": "SessionStart"
	}`)

	result, err := claudecode.NormalizeHookJSON(body, claudecode.Options{
		Identity: testIdentity,
		Now:      func() time.Time { return startedAt },
		RepoResolver: func(cwd string) (gitcontext.Snapshot, error) {
			if cwd != "/Users/dev/work/example-repo/apps/collector" {
				t.Fatalf("cwd = %q", cwd)
			}

			return gitcontext.Snapshot{
				DiffStat: gitcontext.DiffStat{FilesChanged: 2, AddedLines: 5, DeletedLines: 1},
				Repo: &contracts.RepoRef{
					RemoteURLHash:        strings.Repeat("a", 64),
					Branch:               "feat/git-adapter",
					WorktreeRelativePath: &relativePath,
				},
			}, nil
		},
		SessionStartedAt: startedAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	event := result.Events[0]
	if event.PrivacyLevel != "L2" {
		t.Fatalf("privacy level = %s", event.PrivacyLevel)
	}
	repo, ok := event.Payload["repo"].(map[string]any)
	if !ok {
		t.Fatalf("repo payload = %#v", event.Payload["repo"])
	}
	if repo["remoteUrlHash"] != strings.Repeat("a", 64) || repo["branch"] != "feat/git-adapter" {
		t.Fatalf("repo = %#v", repo)
	}
	if strings.Contains(fmt.Sprintf("%#v", event.Payload), "/Users/dev") {
		t.Fatalf("payload leaked absolute path: %#v", event.Payload)
	}
}

func TestNormalizeHookJSONMapsPermissionAndNotificationWaitingEvents(t *testing.T) {
	startedAt := time.Date(2026, 7, 4, 1, 0, 0, 0, time.UTC)
	now := startedAt.Add(45 * time.Second)
	permissionBody := []byte(`{
		"session_id": "claude-session-1",
		"cwd": "/repo",
		"hook_event_name": "PermissionRequest",
		"tool_name": "Bash",
		"tool_input": {"command": "cat secret.txt"}
	}`)
	notificationBody := []byte(`{
		"session_id": "claude-session-1",
		"cwd": "/repo",
		"hook_event_name": "Notification",
		"notification_type": "elicitation_dialog",
		"message": "raw prompt text"
	}`)

	options := claudecode.Options{
		Identity:         testIdentity,
		Now:              func() time.Time { return now },
		SessionStartedAt: startedAt,
	}
	permission, err := claudecode.NormalizeHookJSON(permissionBody, options)
	if err != nil {
		t.Fatal(err)
	}
	notification, err := claudecode.NormalizeHookJSON(notificationBody, options)
	if err != nil {
		t.Fatal(err)
	}

	if permission.Events[0].Type != contracts.EventTypePermissionRequested {
		t.Fatalf("permission type = %s", permission.Events[0].Type)
	}
	if permission.Events[0].Payload["toolName"] != "Bash" {
		t.Fatalf("permission payload = %#v", permission.Events[0].Payload)
	}
	if containsSensitiveValue(permission.Events[0].Payload, "secret.txt") {
		t.Fatalf("permission payload leaked tool input: %#v", permission.Events[0].Payload)
	}
	if notification.Events[0].Type != contracts.EventTypeUserInputRequested {
		t.Fatalf("notification type = %s", notification.Events[0].Type)
	}
	if containsSensitiveValue(notification.Events[0].Payload, "raw prompt text") {
		t.Fatalf("notification payload leaked message: %#v", notification.Events[0].Payload)
	}
	if notification.Events[0].OccurredAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("occurredAt = %s", notification.Events[0].OccurredAt)
	}
}

func TestNormalizeHookJSONMapsToolAndSessionEndEvents(t *testing.T) {
	startedAt := time.Date(2026, 7, 4, 1, 0, 0, 0, time.UTC)
	options := claudecode.Options{
		Identity:         testIdentity,
		Now:              func() time.Time { return startedAt.Add(2 * time.Minute) },
		SessionStartedAt: startedAt,
	}
	cases := []struct {
		name      string
		body      string
		eventType contracts.EventType
		payload   map[string]any
	}{
		{
			name: "tool completed",
			body: `{
				"session_id": "claude-session-1",
				"cwd": "/repo",
				"hook_event_name": "PostToolUse",
				"tool_name": "Edit",
				"tool_use_id": "toolu-1",
				"duration_ms": 125.5,
				"tool_response": {"filePath": "/repo/private.ts"}
			}`,
			eventType: contracts.EventTypeToolCompleted,
			payload:   map[string]any{"toolName": "Edit", "durationMs": 125.5},
		},
		{
			name: "tool failed",
			body: `{
				"session_id": "claude-session-1",
				"cwd": "/repo",
				"hook_event_name": "PostToolUseFailure",
				"tool_name": "Bash",
				"tool_use_id": "toolu-2"
			}`,
			eventType: contracts.EventTypeToolFailed,
			payload:   map[string]any{"toolName": "Bash"},
		},
		{
			name: "session stopped",
			body: `{
				"session_id": "claude-session-1",
				"cwd": "/repo",
				"hook_event_name": "SessionEnd",
				"reason": "prompt_input_exit",
				"duration_ms": 90000
			}`,
			eventType: contracts.EventTypeSessionStopped,
			payload:   map[string]any{"reason": "user_cancelled", "durationMs": 90000.0},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			result, err := claudecode.NormalizeHookJSON([]byte(tt.body), options)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(result.Events))
			}
			event := result.Events[0]
			if event.Type != tt.eventType {
				t.Fatalf("type = %s, want %s", event.Type, tt.eventType)
			}
			for key, want := range tt.payload {
				if event.Payload[key] != want {
					t.Fatalf("payload[%s] = %#v, want %#v in %#v", key, event.Payload[key], want, event.Payload)
				}
			}
			if containsSensitiveValue(event.Payload, "private.ts") {
				t.Fatalf("payload leaked tool response: %#v", event.Payload)
			}
		})
	}
}

func TestNormalizeHookJSONAddsRepoHashToDiffStatEvent(t *testing.T) {
	hash := strings.Repeat("a", 64)
	result, err := claudecode.NormalizeHookJSON([]byte(`{
		"session_id": "claude-session-1",
		"cwd": "/repo",
		"hook_event_name": "PostToolUse",
		"tool_name": "Edit",
		"tool_use_id": "toolu-1"
	}`), claudecode.Options{
		Identity: testIdentity,
		RepoResolver: func(cwd string) (gitcontext.Snapshot, error) {
			return gitcontext.Snapshot{
				DiffStat: gitcontext.DiffStat{FilesChanged: 1},
				Repo:     &contracts.RepoRef{RemoteURLHash: hash, Branch: "private-branch"},
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("events = %#v", result.Events)
	}
	if result.Events[0].Payload["repo"] != nil || result.Events[0].LocalRepoRemoteURLHash != hash {
		t.Fatalf("event = %#v", result.Events[0])
	}
}

func TestParseJSONLFallbackExtractsUsageWithoutPromptOrResponseText(t *testing.T) {
	startedAt := time.Date(2026, 7, 4, 1, 0, 0, 0, time.UTC)
	lines := strings.NewReader(`{"sessionId":"claude-session-1","cwd":"/repo","hook_event_name":"SessionStart","model":"claude-sonnet-5","timestamp":"2026-07-04T01:00:00Z"}
{"sessionId":"claude-session-1","cwd":"/repo","type":"assistant","message":{"model":"claude-sonnet-5","content":[{"type":"text","text":"private answer"}],"usage":{"input_tokens":12,"output_tokens":34}},"timestamp":"2026-07-04T01:01:00Z"}`)

	result, err := claudecode.ParseJSONLFallback(lines, claudecode.Options{
		Identity:         testIdentity,
		Now:              func() time.Time { return startedAt },
		SessionStartedAt: startedAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(result.Events))
	}
	if len(result.UsageMetrics) != 1 {
		t.Fatalf("usage metrics = %d, want 1", len(result.UsageMetrics))
	}
	metric := result.UsageMetrics[0]
	if metric.Model != "claude-sonnet-5" || *metric.InputTokens != 12 || *metric.OutputTokens != 34 {
		t.Fatalf("metric = %#v", metric)
	}
	if metric.Cost.Accuracy != contracts.CostAccuracyUnknown {
		t.Fatalf("cost accuracy = %s", metric.Cost.Accuracy)
	}
	if containsSensitiveValue(metric, "private answer") {
		t.Fatalf("usage metric leaked raw response: %#v", metric)
	}
}

func TestParseJSONLFallbackBuildsRedactedPromptSummary(t *testing.T) {
	startedAt := time.Date(2026, 7, 4, 1, 0, 0, 0, time.UTC)
	githubToken := "gh" + "p_" + strings.Repeat("a", 36)
	lines := strings.NewReader(fmt.Sprintf(
		`{"sessionId":"claude-session-1","cwd":"/repo","hook_event_name":"SessionStart","timestamp":"2026-07-04T01:00:00Z"}
{"sessionId":"claude-session-1","cwd":"/repo","type":"user","message":{"role":"user","content":"debug %s without leaking it"},"timestamp":"2026-07-04T01:00:20Z"}`,
		githubToken,
	))

	result, err := claudecode.ParseJSONLFallback(lines, claudecode.Options{
		Identity:         testIdentity,
		Now:              func() time.Time { return startedAt },
		SessionStartedAt: startedAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Events) != 2 {
		t.Fatalf("events = %d, want 2", len(result.Events))
	}
	event := result.Events[1]
	if event.Type != contracts.EventTypePromptSubmitted || event.PrivacyLevel != "L3" {
		t.Fatalf("event = %#v", event)
	}
	if containsSensitiveValue(event.Payload, "ghp_") {
		t.Fatalf("prompt summary leaked token: %#v", event.Payload)
	}
	if !containsSensitiveValue(event.Payload, "[REDACTED:github_token]") {
		t.Fatalf("prompt summary missing redaction placeholder: %#v", event.Payload)
	}
}

func TestParseJSONLFallbackUsesTypeAsHookNameAndSkipsUnknownRows(t *testing.T) {
	startedAt := time.Date(2026, 7, 4, 1, 0, 0, 0, time.UTC)
	lines := strings.NewReader(`
{"sessionId":"claude-session-1","cwd":"/repo","type":"PreToolUse","tool_name":"Read","timestamp":"2026-07-04T01:00:30Z"}
{"sessionId":"claude-session-1","cwd":"/repo","type":"unrelated","message":{"content":"private prompt"}}`)

	result, err := claudecode.ParseJSONLFallback(lines, claudecode.Options{
		Identity:         testIdentity,
		Now:              func() time.Time { return startedAt },
		SessionStartedAt: startedAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(result.Events))
	}
	if result.Events[0].Type != contracts.EventTypeToolStarted {
		t.Fatalf("type = %s, want tool.started", result.Events[0].Type)
	}
	if containsSensitiveValue(result, "private prompt") {
		t.Fatalf("result leaked unknown row content: %#v", result)
	}
}

func TestParseOTelJSONExtractsActualUsageMetric(t *testing.T) {
	occurredAt := time.Date(2026, 7, 4, 1, 2, 3, 0, time.UTC)
	body := []byte(`{
		"resourceLogs": [{
			"scopeLogs": [{
				"logRecords": [{
					"timeUnixNano": "1783126923000000000",
					"attributes": [
						{"key":"event.name","value":{"stringValue":"api_request"}},
						{"key":"session.id","value":{"stringValue":"claude-session-1"}},
						{"key":"cwd","value":{"stringValue":"/repo"}},
						{"key":"model","value":{"stringValue":"claude-sonnet-5"}},
						{"key":"input_tokens","value":{"intValue":"20"}},
						{"key":"output_tokens","value":{"intValue":"30"}},
						{"key":"cost_usd","value":{"doubleValue":0.12}}
					]
				}]
			}]
		}]
	}`)

	result, err := claudecode.ParseOTelJSON(body, claudecode.Options{
		Identity:         testIdentity,
		Now:              func() time.Time { return occurredAt },
		SessionStartedAt: occurredAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.UsageMetrics) != 1 {
		t.Fatalf("usage metrics = %d, want 1", len(result.UsageMetrics))
	}
	metric := result.UsageMetrics[0]
	if metric.Cost.Accuracy != contracts.CostAccuracyActual {
		t.Fatalf("cost accuracy = %s", metric.Cost.Accuracy)
	}
	if metric.Cost.AmountUSD == nil || *metric.Cost.AmountUSD != 0.12 {
		t.Fatalf("cost = %#v", metric.Cost)
	}
	if metric.OccurredAt != occurredAt.Format(time.RFC3339Nano) {
		t.Fatalf("occurredAt = %s", metric.OccurredAt)
	}
}

func TestParseOTelJSONIgnoresNonUsageEvents(t *testing.T) {
	body := []byte(`{
		"resourceLogs": [{
			"scopeLogs": [{
				"logRecords": [{
					"attributes": [
						{"key":"event.name","value":{"stringValue":"tool_result"}},
						{"key":"tool_input","value":{"stringValue":"private command"}}
					]
				}]
			}]
		}]
	}`)

	result, err := claudecode.ParseOTelJSON(body, claudecode.Options{Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Events) != 0 || len(result.UsageMetrics) != 0 {
		t.Fatalf("result = %#v, want empty", result)
	}
}

func containsSensitiveValue(value any, needle string) bool {
	return strings.Contains(fmt.Sprintf("%#v", value), needle)
}
