package normalize

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactPayloadRemovesHostEnvUserAndAbsolutePaths(t *testing.T) {
	repoRoot := filepath.Join(t.TempDir(), "repo")
	input := map[string]any{
		"cwd":                    filepath.Join(repoRoot, "apps", "api"),
		"outside":                filepath.Join(t.TempDir(), "secret", "file.txt"),
		"dev-macbook-pro-secret": "key name should be redacted too",
		"host":                   "dev-macbook-pro",
		"message":                "run by dev with sensitive-api-key-fixture",
		"nested": map[string]any{
			"path": filepath.Join(repoRoot, "packages", "contracts", "src", "index.ts"),
		},
		"typed": map[string]string{
			"env": "sensitive-api-key-fixture",
		},
	}

	got, err := RedactPayload(input, RedactionOptions{
		Environment: map[string]string{"OPENAI_API_KEY": "sensitive-api-key-fixture"},
		Hostname:    "dev-macbook-pro",
		RepoRoot:    repoRoot,
		Username:    "dev",
	})
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, leaked := range []string{"dev-macbook-pro", "sensitive-api-key-fixture", "run by dev", repoRoot} {
		if strings.Contains(text, leaked) {
			t.Fatalf("redacted payload leaked %q: %s", leaked, text)
		}
	}
	if !strings.Contains(text, "apps/api") {
		t.Fatalf("repo-relative path missing from payload: %s", text)
	}
	if strings.Contains(text, "secret/file.txt") {
		t.Fatalf("outside absolute path leaked: %s", text)
	}
}

func TestRedactPayloadRemovesKnownSecretPatterns(t *testing.T) {
	awsAccessKey := "AK" + "IA" + "ABCDEFGHIJKLMNOP"
	githubToken := "gh" + "p_" + strings.Repeat("a", 36)
	privateKey := "-----BEGIN " + "PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n-----END PRIVATE KEY-----"
	input := map[string]any{
		"connection": "postgres://user:pass@localhost:5432/app",
		"jwt":        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature",
		"keys": strings.Join([]string{
			awsAccessKey,
			"AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;EndpointSuffix=core.windows.net",
			githubToken,
			"glpat-bbbbbbbbbbbbbbbbbbbb",
			"mtq_e_abcdefghijklmnop_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
			"zA9xY8vW7uT6sR5qP4nM3kL2jH1gF0dS9aB8cV7nM6q",
		}, " "),
		"privateKey": privateKey,
	}

	got, err := RedactPayload(input, RedactionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, leaked := range []string{
		"postgres://user:pass",
		"eyJhbGciOiJIUzI1NiJ9",
		awsAccessKey,
		"AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"AccountKey=AAAAAAAA",
		"gh" + "p_" + strings.Repeat("a", 8),
		"glpat-bbbbb",
		"mtq_e_abcdefghijklmnop",
		"zA9xY8vW7uT6sR5q",
		"BEGIN PRIVATE KEY",
	} {
		if strings.Contains(text, leaked) {
			t.Fatalf("secret pattern leaked %q: %s", leaked, text)
		}
	}
	for _, placeholder := range []string{
		"[REDACTED:aws_key]",
		"[REDACTED:gcp_key]",
		"[REDACTED:azure_key]",
		"[REDACTED:github_token]",
		"[REDACTED:gitlab_token]",
		"[REDACTED:mitoriq_token]",
		"[REDACTED:jwt]",
		"[REDACTED:db_connection]",
		"[REDACTED:private-key]",
		"[REDACTED:high_entropy]",
	} {
		if !strings.Contains(text, placeholder) {
			t.Fatalf("placeholder %q missing from payload: %s", placeholder, text)
		}
	}
}

func TestRedactTextRemovesProviderSecretPatterns(t *testing.T) {
	testCases := []struct {
		name        string
		secret      string
		placeholder string
	}{
		{
			name:        "OpenAI legacy key",
			secret:      "sk-" + strings.Repeat("o", 12),
			placeholder: "[REDACTED:openai_key]",
		},
		{
			name:        "OpenAI project key",
			secret:      "sk-" + "proj-" + strings.Repeat("p", 12),
			placeholder: "[REDACTED:openai_key]",
		},
		{
			name:        "OpenAI admin key",
			secret:      "sk-" + "admin-" + strings.Repeat("d", 8),
			placeholder: "[REDACTED:openai_key]",
		},
		{
			name:        "Anthropic key",
			secret:      "sk-" + "ant-api03-" + strings.Repeat("a", 12),
			placeholder: "[REDACTED:anthropic_key]",
		},
		{
			name:        "Slack bot token",
			secret:      "xoxb-" + strings.Repeat("b", 12),
			placeholder: "[REDACTED:slack_token]",
		},
		{
			name:        "Slack app token",
			secret:      "xoxa-" + strings.Repeat("a", 12),
			placeholder: "[REDACTED:slack_token]",
		},
		{
			name:        "Slack user token",
			secret:      "xoxp-" + strings.Repeat("p", 12),
			placeholder: "[REDACTED:slack_token]",
		},
		{
			name:        "Slack refresh token",
			secret:      "xoxr-" + strings.Repeat("r", 12),
			placeholder: "[REDACTED:slack_token]",
		},
		{
			name:        "Slack session token",
			secret:      "xoxs-" + strings.Repeat("s", 12),
			placeholder: "[REDACTED:slack_token]",
		},
		{
			name:        "Stripe live secret key",
			secret:      "sk_" + "live_" + strings.Repeat("l", 12),
			placeholder: "[REDACTED:stripe_key]",
		},
		{
			name:        "Stripe test secret key",
			secret:      "sk_" + "test_" + strings.Repeat("t", 12),
			placeholder: "[REDACTED:stripe_key]",
		},
		{
			name:        "OpenAI project key ending in hyphen",
			secret:      "sk-" + "proj-" + strings.Repeat("p", 8) + "-",
			placeholder: "[REDACTED:openai_key]",
		},
		{
			name:        "Anthropic key ending in hyphen",
			secret:      "sk-" + "ant-" + strings.Repeat("a", 8) + "-",
			placeholder: "[REDACTED:anthropic_key]",
		},
		{
			name:        "Slack token ending in hyphen",
			secret:      "xoxb-" + strings.Repeat("b", 8) + "-",
			placeholder: "[REDACTED:slack_token]",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if len(testCase.secret) >= 32 {
				t.Fatalf("test secret length = %d, want less than entropy fallback minimum", len(testCase.secret))
			}

			got := RedactText("token="+testCase.secret+";", RedactionOptions{})
			want := "token=" + testCase.placeholder + ";"
			if got != want {
				t.Fatalf("RedactText() = %q, want %q", got, want)
			}
		})
	}
}

func TestRedactTextKeepsProviderLikeNonSecrets(t *testing.T) {
	testCases := []string{
		"sk-example",
		"sk-example-value",
		"ask-" + strings.Repeat("o", 12),
		"xoxb-short",
		"sk_" + "test_short",
	}

	for _, testCase := range testCases {
		t.Run(testCase, func(t *testing.T) {
			if got := RedactText(testCase, RedactionOptions{}); got != testCase {
				t.Fatalf("RedactText() = %q, want unchanged %q", got, testCase)
			}
		})
	}
}

func TestPromptSummaryRedactsBeforeTruncating(t *testing.T) {
	githubToken := "gh" + "p_" + strings.Repeat("a", 36)
	summary := PromptSummary(
		"please inspect "+githubToken+" before editing",
		RedactionOptions{},
	)

	if strings.Contains(summary, "ghp_") {
		t.Fatalf("summary leaked secret: %q", summary)
	}
	if !strings.Contains(summary, "[REDACTED:github_token]") {
		t.Fatalf("summary did not keep redaction placeholder: %q", summary)
	}
}

func TestRedactPayloadRemovesEmbeddedExternalAbsolutePaths(t *testing.T) {
	got, err := RedactPayload(map[string]any{
		"command": "cat /private/tmp/secret/file.txt",
	}, RedactionOptions{})
	if err != nil {
		t.Fatal(err)
	}

	command, ok := got["command"].(string)
	if !ok {
		t.Fatalf("payload = %#v", got)
	}
	if strings.Contains(command, "/private/tmp/secret/file.txt") {
		t.Fatalf("embedded absolute path leaked: %q", command)
	}
}

func TestRedactPayloadKeepsRepoRelativePathsAndBranchNames(t *testing.T) {
	got, err := RedactPayload(map[string]any{
		"branch":               "feat/git-adapter",
		"worktreeRelativePath": "apps/collector",
	}, RedactionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got["branch"] != "feat/git-adapter" {
		t.Fatalf("branch = %#v", got["branch"])
	}
	if got["worktreeRelativePath"] != "apps/collector" {
		t.Fatalf("worktreeRelativePath = %#v", got["worktreeRelativePath"])
	}
}

func TestRedactPayloadDoesNotTreatSiblingPathAsRepoRelative(t *testing.T) {
	repoRoot := filepath.Join(t.TempDir(), "repo")
	siblingPath := repoRoot + "-secret/file.txt"
	got, err := RedactPayload(map[string]any{
		"message": "cat " + siblingPath,
	}, RedactionOptions{
		RepoRoot: repoRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	message, ok := got["message"].(string)
	if !ok {
		t.Fatalf("payload = %#v", got)
	}
	if strings.Contains(message, "secret/file.txt") || strings.Contains(message, siblingPath) {
		t.Fatalf("sibling absolute path leaked: %q", message)
	}
	if !strings.Contains(message, "[redacted:absolute-path]") {
		t.Fatalf("absolute path placeholder missing: %q", message)
	}
}

func TestRedactPayloadHandlesWindowsDrivePaths(t *testing.T) {
	got, err := RedactPayload(map[string]any{
		"command": `type C:\Users\dev\work\example-repo\apps\collector\main.go && type D:\secret\key.txt`,
	}, RedactionOptions{
		RepoRoot: `C:\Users\DEV\work\example-repo`,
	})
	if err != nil {
		t.Fatal(err)
	}

	command, ok := got["command"].(string)
	if !ok {
		t.Fatalf("payload = %#v", got)
	}
	if strings.Contains(command, `C:\Users\dev`) || strings.Contains(command, `D:\secret`) {
		t.Fatalf("windows absolute path leaked: %q", command)
	}
	if !strings.Contains(command, "apps/collector/main.go") {
		t.Fatalf("repo-relative windows path missing: %q", command)
	}
}

func TestRedactPayloadHandlesWindowsUNCPaths(t *testing.T) {
	got, err := RedactPayload(map[string]any{
		"transcript": `\\wsl$\Ubuntu\home\dev\.codex\sessions\session.jsonl`,
	}, RedactionOptions{})
	if err != nil {
		t.Fatal(err)
	}

	transcript, ok := got["transcript"].(string)
	if !ok {
		t.Fatalf("payload = %#v", got)
	}
	if strings.Contains(transcript, `\\wsl$`) || strings.Contains(transcript, `session.jsonl`) {
		t.Fatalf("UNC path leaked: %q", transcript)
	}
	if transcript != "[redacted:absolute-path]" {
		t.Fatalf("transcript = %q", transcript)
	}
}

func TestRedactPayloadRedactsNestedSlices(t *testing.T) {
	got, err := RedactPayload(map[string]any{
		"commands": []any{
			"cat /private/tmp/secret/file.txt",
			map[string]any{"host": "dev-macbook-pro"},
		},
	}, RedactionOptions{
		Hostname: "dev-macbook-pro",
	})
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, leaked := range []string{"/private/tmp/secret/file.txt", "dev-macbook-pro"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("redacted payload leaked %q: %s", leaked, text)
		}
	}
}

func TestRedactPayloadReturnsMarshalError(t *testing.T) {
	_, err := RedactPayload(map[string]any{
		"invalid": func() {},
	}, RedactionOptions{})

	if err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestNormalizeRawHeartbeatDefaultsToL0(t *testing.T) {
	event, err := NormalizeRawEvent(RawEvent{
		ID:         "heartbeat-1",
		SessionID:  "session-1",
		Source:     "codex",
		Type:       "heartbeat",
		OccurredAt: "2026-07-04T00:00:00Z",
		Payload: map[string]any{
			"collectorVersion": "0.1.0",
		},
	}, NormalizeOptions{
		MachineEnrollmentID: "enrollment-1",
		MachineID:           "machine-1",
		MemberID:            "member-1",
		OrganizationID:      "org-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	if event.PrivacyLevel != "L0" {
		t.Fatalf("privacyLevel = %q, want L0", event.PrivacyLevel)
	}
}

func TestNormalizeRawEventRejectsInvalidPrivacyForType(t *testing.T) {
	_, err := NormalizeRawEvent(RawEvent{
		ID:         "heartbeat-1",
		SessionID:  "session-1",
		Source:     "codex",
		Type:       "heartbeat",
		OccurredAt: "2026-07-04T00:00:00Z",
		Payload: map[string]any{
			"collectorVersion": "0.1.0",
		},
	}, NormalizeOptions{
		MachineEnrollmentID: "enrollment-1",
		MachineID:           "machine-1",
		MemberID:            "member-1",
		OrganizationID:      "org-1",
		PrivacyLevel:        "L1",
	})

	if err == nil {
		t.Fatal("expected invalid privacy error")
	}
}

func TestNormalizeRawEventRejectsUnknownType(t *testing.T) {
	_, err := NormalizeRawEvent(RawEvent{
		ID:         "event-1",
		SessionID:  "session-1",
		Source:     "codex",
		Type:       "unknown.event",
		OccurredAt: "2026-07-04T00:00:00Z",
		Payload: map[string]any{
			"toolName": "exec",
		},
	}, NormalizeOptions{
		MachineEnrollmentID: "enrollment-1",
		MachineID:           "machine-1",
		MemberID:            "member-1",
		OrganizationID:      "org-1",
	})

	if err == nil {
		t.Fatal("expected unknown event type error")
	}
}

func TestNormalizeRawEventBuildsContractEventWithRedactedPayload(t *testing.T) {
	repoRoot := filepath.Join(t.TempDir(), "repo")
	event, err := NormalizeRawEvent(RawEvent{
		ID:         "event-1",
		SessionID:  "session-1",
		Source:     "codex",
		Type:       "tool.started",
		OccurredAt: "2026-07-04T00:00:00Z",
		Payload: map[string]any{
			"toolName": "exec",
			"command":  "cat " + filepath.Join(repoRoot, "README.md"),
		},
	}, NormalizeOptions{
		MachineEnrollmentID: "enrollment-1",
		MachineID:           "machine-1",
		MemberID:            "member-1",
		OrganizationID:      "org-1",
		PrivacyLevel:        "L3",
		Redaction: RedactionOptions{
			RepoRoot: repoRoot,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if event.SchemaVersion != 1 {
		t.Fatalf("schemaVersion = %d", event.SchemaVersion)
	}
	if event.IdempotencyKey == "" {
		t.Fatal("idempotencyKey should be generated")
	}
	command, ok := event.Payload["command"].(string)
	if !ok {
		t.Fatalf("payload = %#v", event.Payload)
	}
	if strings.Contains(command, repoRoot) {
		t.Fatalf("command leaked absolute repo path: %q", command)
	}
}
