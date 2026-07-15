package codexcli_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/adapter/codexcli"
	"github.com/mitoriq/collector/internal/adapter/gitcontext"
	"github.com/mitoriq/collector/internal/contracts"
)

var testIdentity = codexcli.Identity{
	MachineEnrollmentID: "enrollment-1",
	MachineID:           "machine-1",
	MemberID:            "member-1",
	OrganizationID:      "org-1",
}

func TestParseSessionJSONLEmitsEventsWithoutRawPrompt(t *testing.T) {
	startedAt := time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC)
	lines := strings.NewReader(`{"type":"session_meta","payload":{"session_id":"codex-session-1","cwd":"/repo","model":"gpt-5.1"},"timestamp":"2026-07-04T02:00:00Z"}
{"type":"response_item","payload":{"item":{"type":"function_call","name":"shell","call_id":"call-1","arguments":"cat secret.txt"}},"timestamp":"2026-07-04T02:00:10Z"}
{"type":"event_msg","payload":{"event":"approval_request","tool":"shell","sandbox":"workspace-write","prompt":"raw prompt"},"timestamp":"2026-07-04T02:00:15Z"}
{"type":"response_item","payload":{"item":{"type":"function_call_output","name":"shell","call_id":"call-1","output":"private output"}},"timestamp":"2026-07-04T02:00:20Z"}`)

	result, err := codexcli.ParseSessionJSONL(lines, codexcli.Options{
		Identity:         testIdentity,
		Now:              func() time.Time { return startedAt },
		SessionStartedAt: startedAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Events) != 4 {
		t.Fatalf("events = %d, want 4", len(result.Events))
	}
	wantTypes := []contracts.EventType{
		contracts.EventTypeSessionStarted,
		contracts.EventTypeToolStarted,
		contracts.EventTypePermissionRequested,
		contracts.EventTypeToolCompleted,
	}
	for index, want := range wantTypes {
		if result.Events[index].Type != want {
			t.Fatalf("event[%d] type = %s, want %s", index, result.Events[index].Type, want)
		}
	}
	if result.Events[0].Source != codexcli.Source {
		t.Fatalf("source = %s", result.Events[0].Source)
	}
	wantSessionID := codexcli.StableSessionKey("codex-session-1", codexcli.Source, "/repo", startedAt)
	for index, event := range result.Events {
		if event.SessionID != wantSessionID {
			t.Fatalf("event[%d] session id = %q, want %q", index, event.SessionID, wantSessionID)
		}
	}
	if containsSensitiveValue(result, "secret.txt") || containsSensitiveValue(result, "raw prompt") || containsSensitiveValue(result, "private output") {
		t.Fatalf("result leaked raw content: %#v", result)
	}
}

func TestParseSessionJSONLAddsRepoMetadataFromResolver(t *testing.T) {
	startedAt := time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC)
	relativePath := "apps/collector"
	lines := strings.NewReader(`{"type":"session_meta","payload":{"session_id":"codex-session-1","cwd":"/Users/dev/work/example-repo/apps/collector"},"timestamp":"2026-07-04T02:00:00Z"}`)

	result, err := codexcli.ParseSessionJSONL(lines, codexcli.Options{
		Identity: testIdentity,
		Now:      func() time.Time { return startedAt },
		RepoResolver: func(cwd string) (gitcontext.Snapshot, error) {
			if cwd != "/Users/dev/work/example-repo/apps/collector" {
				t.Fatalf("cwd = %q", cwd)
			}

			return gitcontext.Snapshot{
				DiffStat: gitcontext.DiffStat{FilesChanged: 2, AddedLines: 5, DeletedLines: 1},
				Repo: &contracts.RepoRef{
					RemoteURLHash:        strings.Repeat("b", 64),
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
	if repo["remoteUrlHash"] != strings.Repeat("b", 64) || repo["branch"] != "feat/git-adapter" {
		t.Fatalf("repo = %#v", repo)
	}
	if containsSensitiveValue(event.Payload, "/Users/dev") {
		t.Fatalf("payload leaked absolute path: %#v", event.Payload)
	}
}

func TestParseSessionJSONLBuildsRedactedPromptSummary(t *testing.T) {
	startedAt := time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC)
	githubToken := "gh" + "p_" + strings.Repeat("a", 36)
	lines := strings.NewReader(fmt.Sprintf(
		`{"type":"session_meta","payload":{"session_id":"codex-session-1","cwd":"/repo"},"timestamp":"2026-07-04T02:00:00Z"}
{"type":"response_item","payload":{"item":{"type":"message","role":"user","content":"please inspect %s before editing"}},"timestamp":"2026-07-04T02:00:05Z"}`,
		githubToken,
	))

	result, err := codexcli.ParseSessionJSONL(lines, codexcli.Options{
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

func TestParseSessionJSONLExtractsUsageMetricFromResponseItem(t *testing.T) {
	startedAt := time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC)
	lines := strings.NewReader(`{"type":"session_meta","payload":{"session_id":"codex-session-1","cwd":"/repo"},"timestamp":"2026-07-04T02:00:00Z"}
{"type":"response_item","payload":{"item":{"type":"message","model":"gpt-5.1","content":"private answer","usage":{"input_tokens":9,"output_tokens":7}}},"timestamp":"2026-07-04T02:01:00Z"}`)

	result, err := codexcli.ParseSessionJSONL(lines, codexcli.Options{
		Identity:         testIdentity,
		Now:              func() time.Time { return startedAt },
		SessionStartedAt: startedAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.UsageMetrics) != 1 {
		t.Fatalf("usage metrics = %d, want 1", len(result.UsageMetrics))
	}
	metric := result.UsageMetrics[0]
	if metric.Model != "gpt-5.1" || *metric.InputTokens != 9 || *metric.OutputTokens != 7 {
		t.Fatalf("metric = %#v", metric)
	}
	if metric.Cost.Accuracy != contracts.CostAccuracyEstimated {
		t.Fatalf("cost accuracy = %s", metric.Cost.Accuracy)
	}
	if metric.SessionID != codexcli.StableSessionKey("codex-session-1", codexcli.Source, "/repo", startedAt) {
		t.Fatalf("metric session id = %q", metric.SessionID)
	}
	if containsSensitiveValue(metric, "private answer") {
		t.Fatalf("metric leaked raw response: %#v", metric)
	}
}

func TestParseSessionJSONLRejectsMalformedLine(t *testing.T) {
	_, err := codexcli.ParseSessionJSONL(strings.NewReader("{"), codexcli.Options{Identity: testIdentity})

	if err == nil {
		t.Fatal("expected malformed JSONL error")
	}
}

func TestNormalizeHookJSONMapsPermissionAndPostToolUse(t *testing.T) {
	startedAt := time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC)
	options := codexcli.Options{
		Identity:         testIdentity,
		Now:              func() time.Time { return startedAt.Add(30 * time.Second) },
		SessionStartedAt: startedAt,
	}
	permission, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"cwd": "/repo",
		"hook_event_name": "PermissionRequest",
		"tool_name": "shell",
		"tool_input": {"command": "rm secret.txt"}
	}`), options)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"cwd": "/repo",
		"hook_event_name": "PostToolUse",
		"tool_name": "shell",
		"duration_ms": 10
	}`), options)
	if err != nil {
		t.Fatal(err)
	}

	if permission.Events[0].Type != contracts.EventTypePermissionRequested {
		t.Fatalf("permission type = %s", permission.Events[0].Type)
	}
	if completed.Events[0].Type != contracts.EventTypeToolCompleted {
		t.Fatalf("completed type = %s", completed.Events[0].Type)
	}
	if containsSensitiveValue(permission, "secret.txt") {
		t.Fatalf("permission leaked tool input: %#v", permission)
	}
}

func TestNormalizeHookJSONMapsTurnScopedLifecycle(t *testing.T) {
	startedAt := time.Date(2026, 7, 10, 1, 0, 0, 0, time.UTC)
	githubToken := "gh" + "p_" + strings.Repeat("a", 36)
	options := codexcli.Options{
		Identity:         testIdentity,
		Now:              func() time.Time { return startedAt },
		SessionStartedAt: startedAt,
	}
	prompt, err := codexcli.NormalizeHookJSON([]byte(fmt.Sprintf(`{
		"session_id": "codex-session-1",
		"turn_id": "turn-1",
		"cwd": "/repo",
		"hook_event_name": "UserPromptSubmit",
		"model": "gpt-5.1",
		"prompt": "inspect %s"
	}`, githubToken)), options)
	if err != nil {
		t.Fatal(err)
	}
	tool, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"turn_id": "turn-1",
		"cwd": "/repo",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "call-1"
	}`), options)
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"turn_id": "turn-1",
		"cwd": "/repo",
		"hook_event_name": "Stop",
		"model": "gpt-5.1",
		"last_assistant_message": "private final answer"
	}`), options)
	if err != nil {
		t.Fatal(err)
	}

	wantSessionID := codexcli.StableSessionKey("codex-session-1\x00turn-1", codexcli.Source, "/repo", startedAt)
	for _, event := range append(append(prompt.Events, tool.Events...), stopped.Events...) {
		if event.SessionID != wantSessionID {
			t.Fatalf("session id = %q, want %q", event.SessionID, wantSessionID)
		}
	}
	assertEventTypes(t, prompt.Events, []contracts.EventType{
		contracts.EventTypeSessionStarted,
		contracts.EventTypePromptSubmitted,
	})
	assertEventTypes(t, tool.Events, []contracts.EventType{contracts.EventTypeToolStarted})
	assertEventTypes(t, stopped.Events, []contracts.EventType{
		contracts.EventTypeModelResponseCompleted,
		contracts.EventTypeSessionStopped,
	})
	if prompt.Events[0].Payload["model"] != "gpt-5.1" {
		t.Fatalf("session started payload = %#v", prompt.Events[0].Payload)
	}
	if stopped.Events[1].Payload["reason"] != "normal" || stopped.Events[1].Payload["durationMs"] != float64(0) {
		t.Fatalf("session stopped payload = %#v", stopped.Events[1].Payload)
	}
	cost, ok := stopped.Events[0].Payload["cost"].(map[string]any)
	if !ok || cost["accuracy"] != string(contracts.CostAccuracyUnknown) {
		t.Fatalf("model response payload = %#v", stopped.Events[0].Payload)
	}
	if containsSensitiveValue(append(append(prompt.Events, tool.Events...), stopped.Events...), githubToken) ||
		containsSensitiveValue(append(append(prompt.Events, tool.Events...), stopped.Events...), "private final answer") {
		t.Fatalf("turn lifecycle leaked raw content")
	}
}

func TestNormalizeHookJSONMapsNonZeroExitCodeToToolFailed(t *testing.T) {
	result, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"turn_id": "turn-1",
		"cwd": "/repo",
		"hook_event_name": "PostToolUse",
		"tool_name": "Bash",
		"tool_use_id": "call-1",
		"tool_response": {"exit_code": 17, "output": "private command output"}
	}`), codexcli.Options{Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}

	assertEventTypes(t, result.Events, []contracts.EventType{contracts.EventTypeToolFailed})
	if result.Events[0].Payload["toolName"] != "Bash" || result.Events[0].Payload["exitCode"] != float64(17) {
		t.Fatalf("tool failed payload = %#v", result.Events[0].Payload)
	}
	if containsSensitiveValue(result, "private command output") {
		t.Fatalf("tool failure leaked raw output: %#v", result)
	}
}

func TestNormalizeHookJSONMapsExplicitUserInputTool(t *testing.T) {
	result, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"turn_id": "turn-1",
		"cwd": "/repo",
		"hook_event_name": "PreToolUse",
		"tool_name": "request_user_input",
		"tool_use_id": "call-1",
		"tool_input": {"question": "private question"}
	}`), codexcli.Options{Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}

	assertEventTypes(t, result.Events, []contracts.EventType{contracts.EventTypeUserInputRequested})
	if result.Events[0].Payload["reason"] != "elicitation" {
		t.Fatalf("user input payload = %#v", result.Events[0].Payload)
	}
	if containsSensitiveValue(result, "private question") {
		t.Fatalf("user input leaked raw prompt: %#v", result)
	}
}

func TestNormalizeHookJSONIgnoresStopWithoutTurnID(t *testing.T) {
	result, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"cwd": "/repo",
		"hook_event_name": "Stop",
		"model": "gpt-5.1"
	}`), codexcli.Options{Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("events = %#v, want none", result.Events)
	}
}

func TestNormalizeHookSessionStoppedWithDiffUsesL2Privacy(t *testing.T) {
	result, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"turn_id": "turn-1",
		"cwd": "/repo",
		"hook_event_name": "Stop",
		"model": "gpt-5.1"
	}`), codexcli.Options{
		Identity: testIdentity,
		RepoResolver: func(string) (gitcontext.Snapshot, error) {
			return gitcontext.Snapshot{DiffStat: gitcontext.DiffStat{FilesChanged: 1}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	stopped := result.Events[1]
	if stopped.Type != contracts.EventTypeSessionStopped || stopped.PrivacyLevel != "L2" || stopped.Payload["filesChanged"] != float64(1) {
		t.Fatalf("session stopped event = %#v", stopped)
	}
}

func TestNormalizeHookUsesStableIdsForHookRetriesWithoutTimestamp(t *testing.T) {
	body := []byte(`{
		"session_id": "codex-session-1",
		"turn_id": "turn-1",
		"cwd": "/repo",
		"hook_event_name": "UserPromptSubmit",
		"model": "gpt-5.1",
		"prompt": "inspect the working tree"
	}`)
	first, err := codexcli.NormalizeHookJSON(body, codexcli.Options{
		Identity: testIdentity,
		Now: func() time.Time {
			return time.Date(2026, 7, 10, 1, 0, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := codexcli.NormalizeHookJSON(body, codexcli.Options{
		Identity: testIdentity,
		Now: func() time.Time {
			return time.Date(2026, 7, 10, 1, 1, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for index, firstEvent := range first.Events {
		secondEvent := second.Events[index]
		if firstEvent.ID != secondEvent.ID || firstEvent.IdempotencyKey != secondEvent.IdempotencyKey {
			t.Fatalf("retry identifiers differ: first=%#v second=%#v", firstEvent, secondEvent)
		}
	}
}

func TestNormalizeHookDistinguishesPermissionRequestsWithoutToolUseID(t *testing.T) {
	options := codexcli.Options{Identity: testIdentity}
	first, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"turn_id": "turn-1",
		"cwd": "/repo",
		"hook_event_name": "PermissionRequest",
		"tool_name": "Bash",
		"tool_input": {"command": "git status"}
	}`), options)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"turn_id": "turn-1",
		"cwd": "/repo",
		"hook_event_name": "PermissionRequest",
		"tool_name": "Bash",
		"tool_input": { "command" : "git status" }
	}`), options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"turn_id": "turn-1",
		"cwd": "/repo",
		"hook_event_name": "PermissionRequest",
		"tool_name": "apply_patch",
		"tool_input": {"command": "*** Begin Patch"}
	}`), options)
	if err != nil {
		t.Fatal(err)
	}

	if first.Events[0].ID != retry.Events[0].ID || first.Events[0].IdempotencyKey != retry.Events[0].IdempotencyKey {
		t.Fatalf("permission retry identifiers differ: first=%#v retry=%#v", first.Events[0], retry.Events[0])
	}
	if first.Events[0].ID == second.Events[0].ID || first.Events[0].IdempotencyKey == second.Events[0].IdempotencyKey {
		t.Fatalf("distinct permission requests collided: first=%#v second=%#v", first.Events[0], second.Events[0])
	}
	if containsSensitiveValue(first, "git status") || containsSensitiveValue(second, "Begin Patch") {
		t.Fatalf("permission event leaked tool input")
	}
}

func TestParseSessionJSONLMapsExplicitUserInputTool(t *testing.T) {
	lines := strings.NewReader(`{"type":"session_meta","payload":{"id":"codex-session-1","cwd":"/repo"},"timestamp":"2026-07-10T01:00:00Z"}
{"type":"turn_context","payload":{"turn_id":"turn-1","cwd":"/repo"},"timestamp":"2026-07-10T01:00:01Z"}
{"type":"response_item","payload":{"item":{"type":"function_call","name":"request_user_input","call_id":"call-1","arguments":"private question"}},"timestamp":"2026-07-10T01:00:10Z"}`)

	result, err := codexcli.ParseSessionJSONL(lines, codexcli.Options{Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}

	assertEventTypes(t, result.Events, []contracts.EventType{
		contracts.EventTypeSessionStarted,
		contracts.EventTypeUserInputRequested,
	})
	if result.Events[1].Payload["reason"] != "elicitation" {
		t.Fatalf("user input event = %#v", result.Events[1])
	}
	wantSessionID := codexcli.StableSessionKey("codex-session-1\x00turn-1", codexcli.Source, "/repo", time.Unix(0, 0).UTC())
	if result.Events[1].SessionID != wantSessionID {
		t.Fatalf("user input session id = %q, want %q", result.Events[1].SessionID, wantSessionID)
	}
	if containsSensitiveValue(result, "private question") {
		t.Fatalf("user input leaked raw prompt: %#v", result)
	}
}

func TestNormalizeHookJSONAddsRepoHashToDiffStatEvent(t *testing.T) {
	hash := strings.Repeat("b", 64)
	result, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"cwd": "/repo",
		"hook_event_name": "PostToolUse",
		"tool_name": "shell"
	}`), codexcli.Options{
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

func TestNormalizeHookUsesStableFallbackSessionKeyWithoutStartTime(t *testing.T) {
	permission, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"cwd": "/repo",
		"hook_event_name": "PermissionRequest",
		"timestamp": "2026-07-04T02:00:30Z",
		"tool_name": "shell"
	}`), codexcli.Options{Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := codexcli.NormalizeHookJSON([]byte(`{
		"session_id": "codex-session-1",
		"cwd": "/repo",
		"hook_event_name": "PostToolUse",
		"timestamp": "2026-07-04T02:00:45Z",
		"tool_name": "shell"
	}`), codexcli.Options{Identity: testIdentity})
	if err != nil {
		t.Fatal(err)
	}

	wantSessionID := codexcli.StableSessionKey("codex-session-1", codexcli.Source, "/repo", time.Unix(0, 0).UTC())
	if permission.Events[0].SessionID != wantSessionID || completed.Events[0].SessionID != wantSessionID {
		t.Fatalf("session ids = %q %q, want %q", permission.Events[0].SessionID, completed.Events[0].SessionID, wantSessionID)
	}
}

func TestParseOTelJSONExtractsEstimatedResponseCompletedUsage(t *testing.T) {
	occurredAt := time.Date(2026, 7, 4, 2, 1, 0, 0, time.UTC)
	body := []byte(`{
		"resourceLogs": [{
			"scopeLogs": [{
				"logRecords": [{
					"timeUnixNano": "1783130460000000000",
					"attributes": [
						{"key":"event.name","value":{"stringValue":"response.completed"}},
						{"key":"session.id","value":{"stringValue":"codex-session-1"}},
						{"key":"cwd","value":{"stringValue":"/repo"}},
						{"key":"model","value":{"stringValue":"gpt-5.1"}},
						{"key":"input_tokens","value":{"intValue":"11"}},
						{"key":"output_tokens","value":{"intValue":"13"}}
					]
				}]
			}]
		}]
	}`)

	result, err := codexcli.ParseOTelJSON(body, codexcli.Options{
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
	if metric.Cost.Accuracy != contracts.CostAccuracyEstimated {
		t.Fatalf("cost accuracy = %s", metric.Cost.Accuracy)
	}
	if *metric.InputTokens != 11 || *metric.OutputTokens != 13 {
		t.Fatalf("metric = %#v", metric)
	}
}

func containsSensitiveValue(value any, needle string) bool {
	return strings.Contains(fmt.Sprintf("%#v", value), needle)
}

func assertEventTypes(t *testing.T, events []contracts.AgentEvent, want []contracts.EventType) {
	t.Helper()
	if len(events) != len(want) {
		t.Fatalf("events = %#v, want %d events", events, len(want))
	}
	for index, eventType := range want {
		if events[index].Type != eventType {
			t.Fatalf("event[%d] type = %s, want %s", index, events[index].Type, eventType)
		}
	}
}
