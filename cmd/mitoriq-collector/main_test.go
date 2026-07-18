package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/adapter/cursor"
	"github.com/mitoriq/collector/internal/contracts"
	"github.com/mitoriq/collector/internal/filelock"
	"github.com/mitoriq/collector/internal/localaudit"
	"github.com/mitoriq/collector/internal/localconfig"
	"github.com/mitoriq/collector/internal/queue"
	"github.com/mitoriq/collector/internal/uplink"
	"github.com/mitoriq/collector/internal/version"
)

const maxHookFallbackDuration = time.Second

func TestRunDoctorSubcommandReportsCollectorStatus(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"doctor"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "collector_status=ok") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "os=") || !strings.Contains(stdout.String(), "arch=") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunAuditLogPrintsRecentMetadataOnlyEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector-audit.jsonl")
	store := localaudit.Store{Path: path}
	if err := store.Append(localaudit.Entry{
		Category:      "events",
		Phase:         "attempted",
		Count:         1,
		PrivacyLevels: map[string]int{"L2": 1},
		EventTypes:    map[string]int{"tool.completed": 1},
	}); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"audit-log", "--path", path, "--limit", "10"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"category":"events"`) || strings.Contains(stdout.String(), "payload") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunDoctorSubcommandReportsDenyConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "collector.json")
	if err := (localconfig.Store{Path: configPath}).Save(localconfig.Config{
		Deny: localconfig.DenyRules{
			PathGlobs:   []string{"secrets/**"},
			PathRegexes: []string{`(^|/)private/`},
			Repos: []localconfig.RepoDenyEntry{
				{Alias: "sandbox", RemoteURLHash: "deny-hash"},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"doctor", "--config", configPath}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	output := stdout.String()
	for _, expected := range []string{
		"deny_status=configured fail_closed=false repos=1 path_globs=1 path_regexes=1 applies_to=L2+",
		`deny_repo alias="sandbox" remote_url_hash="deny-hash"`,
		`deny_path_glob pattern="secrets/**"`,
		`deny_path_regex pattern="(^|/)private/"`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("stdout missing %q: %s", expected, output)
		}
	}
}

func TestRunVersionSubcommandReportsBuildInfo(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "version=") || !strings.Contains(stdout.String(), "commit=") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunTopLevelHelpPrintsUsage(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-h"},
		{"--help"},
		{"help"},
	} {
		t.Run(fmt.Sprintf("args=%v", args), func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(args, &stdout, &stderr)

			if code != 0 {
				t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
			}
			for _, expected := range []string{
				"Usage: mitoriq-collector <command> [options]",
				"Commands:",
				"audit-log",
				"claude-hook",
				"codex-hook",
				"cursor-collect",
				"cursor-hook",
				"daemon",
				"doctor",
				"enroll",
				"install",
				"status",
				"uninstall",
				"update",
				"version",
			} {
				if !strings.Contains(stdout.String(), expected) {
					t.Fatalf("stdout missing %q: %s", expected, stdout.String())
				}
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

func TestRunSubcommandHelpExitsSuccessfullyWithoutError(t *testing.T) {
	for _, command := range []string{
		"audit-log",
		"claude-hook",
		"codex-hook",
		"cursor-collect",
		"cursor-hook",
		"daemon",
		"doctor",
		"enroll",
		"install",
		"status",
		"uninstall",
		"update",
		"version",
	} {
		t.Run(command, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run([]string{command, "-h"}, &stdout, &stderr)

			if code != 0 {
				t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "Usage of "+command+":") {
				t.Fatalf("stderr = %q", stderr.String())
			}
			for _, unexpected := range []string{"エラー:", "flag: help requested", "cursor_hook_warning"} {
				if strings.Contains(stderr.String(), unexpected) {
					t.Fatalf("stderr contains %q: %s", unexpected, stderr.String())
				}
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q", stdout.String())
			}
		})
	}
}

func TestRunVersionRejectsInvalidFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"version", "--unknown"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunDaemonOnceReportsOTLPAddress(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"daemon", "--once", "--otlp-http-addr", "127.0.0.1:9999"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "collector_status=daemon_ready otlp_http_addr=127.0.0.1:9999") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunClaudeHookSendsMetadataOnlyEvent(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var received contracts.CollectorBatch
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/collector/events" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		if request.Header.Get("authorization") != "Bearer mtq_e_token_secret" {
			t.Fatalf("authorization = %q", request.Header.Get("authorization"))
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	body := strings.NewReader(`{
		"session_id": "claude-session-1",
		"cwd": "/repo",
		"hook_event_name": "PermissionRequest",
		"tool_name": "Bash",
		"tool_input": {"command": "cat secret.txt"}
	}`)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runClaudeHook([]string{
		"--api-url", server.URL,
		"--allow-insecure-http",
		"--token", "mtq_e_token_secret",
		"--organization-id", "org-1",
		"--machine-id", "machine-1",
		"--machine-enrollment-id", "enrollment-1",
		"--member-id", "member-1",
	}, body, &stdout, &stderr)

	if err != nil {
		t.Fatalf("err = %v stderr = %s", err, stderr.String())
	}
	if len(received.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(received.Events))
	}
	event := received.Events[0]
	if event.Type != contracts.EventTypePermissionRequested {
		t.Fatalf("type = %s", event.Type)
	}
	if strings.Contains(string(mustJSON(t, received)), "secret.txt") {
		t.Fatalf("event batch leaked raw tool input: %#v", received)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunCursorHookSendsCurrentLifecycleEventBehindBetaFlag(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var received contracts.CollectorBatch
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	body := strings.NewReader(`{
		"conversation_id": "cursor-conversation-1",
		"hook_event_name": "beforeSubmitPrompt",
		"model": "cursor-auto"
	}`)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runCursorHook([]string{
		"--cursor-hooks-beta",
		"--api-url", server.URL,
		"--allow-insecure-http",
		"--token", "mtq_e_token_secret",
		"--organization-id", "org-1",
		"--machine-id", "machine-1",
		"--machine-enrollment-id", "enrollment-1",
		"--member-id", "member-1",
	}, body, &stdout, &stderr)

	if err != nil {
		t.Fatalf("err = %v stderr = %s", err, stderr.String())
	}
	if len(received.Events) != 1 || received.Events[0].Type != contracts.EventTypePromptSubmitted {
		t.Fatalf("events = %#v", received.Events)
	}
	if received.Events[0].Source != cursor.Source {
		t.Fatalf("source = %s", received.Events[0].Source)
	}
	if strings.TrimSpace(stdout.String()) != `{"continue":true}` {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "cursor_hook_events=1") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestReadCursorHookBodyRejectsOversizedPayload(t *testing.T) {
	_, err := readCursorHookBody(strings.NewReader(strings.Repeat("x", (1<<20)+1)))

	if err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunCursorHookFailsOpenWhenTelemetryInputIsInvalid(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runCursorHook([]string{
		"--cursor-hooks-beta",
		"--api-url", "https://api.mitoriq.example",
		"--token", "mtq_e_token_secret",
		"--organization-id", "org-1",
		"--machine-id", "machine-1",
		"--machine-enrollment-id", "enrollment-1",
		"--member-id", "member-1",
	}, strings.NewReader(`{"invalid"`), &stdout, &stderr)

	if err != nil {
		t.Fatalf("hook blocked Cursor: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != `{"continue":true}` {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "cursor_hook_warning=") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunCursorHookFailsOpenWhenTelemetryUploadFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte(`{"error":"temporarily unavailable"}`))
	}))
	defer server.Close()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runCursorHook([]string{
		"--cursor-hooks-beta",
		"--api-url", server.URL,
		"--allow-insecure-http",
		"--token", "mtq_e_token_secret",
		"--organization-id", "org-1",
		"--machine-id", "machine-1",
		"--machine-enrollment-id", "enrollment-1",
		"--member-id", "member-1",
	}, strings.NewReader(`{
		"conversation_id": "cursor-conversation-1",
		"hook_event_name": "sessionStart"
	}`), &stdout, &stderr)

	if err != nil {
		t.Fatalf("hook blocked Cursor: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != `{"continue":true}` {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "cursor_hook_warning=") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	store, err := openEventQueue(daemonAdapterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	count, err := store.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("queued events = %d, want 1", count)
	}
}

func TestHooksPersistEventsWhenTheUplinkIsUnavailable(t *testing.T) {
	tests := []struct {
		name   string
		source string
		run    func([]string, io.Reader, io.Writer, io.Writer) error
		body   string
	}{
		{
			name:   "claude",
			source: "claude-code",
			run: func(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
				return runClaudeHook(args, stdin, stdout, stderr)
			},
			body: `{"session_id":"claude-session-1","cwd":"/repo","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"pwd"}}`,
		},
		{
			name:   "codex",
			source: "codex",
			run: func(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
				return runCodexHook(args, stdin, stdout, stderr)
			},
			body: `{"session_id":"codex-session-1","cwd":"/repo","hook_event_name":"PermissionRequest","tool_name":"shell","tool_input":{"command":"pwd"}}`,
		},
		{
			name:   "cursor",
			source: "cursor",
			run: func(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
				return runCursorHook(append([]string{"--cursor-hooks-beta"}, args...), stdin, stdout, stderr)
			},
			body: `{"conversation_id":"cursor-conversation-1","hook_event_name":"sessionStart"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			var sent contracts.CollectorBatch
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if err := json.NewDecoder(request.Body).Decode(&sent); err != nil {
					t.Fatal(err)
				}
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = writer.Write([]byte(`{"error":"temporarily unavailable"}`))
			}))
			defer server.Close()
			args := hookFailureArgs()
			for index, value := range args {
				if value == "http://127.0.0.1:1" {
					args[index] = server.URL
				}
			}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			if err := test.run(args, strings.NewReader(test.body), &stdout, &stderr); err != nil {
				t.Fatalf("run hook: %v", err)
			}
			store, err := openEventQueue(daemonAdapterConfig{})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			records, err := store.Due(context.Background(), 10, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 {
				t.Fatalf("persisted events = %#v", records)
			}
			if records[0].Event.Source != test.source {
				t.Fatalf("persisted source = %q, want %q", records[0].Event.Source, test.source)
			}
			if len(sent.Events) != 1 || records[0].Event.IdempotencyKey != sent.Events[0].IdempotencyKey {
				t.Fatalf("sent events = %#v persisted events = %#v", sent.Events, records)
			}
		})
	}
}

func TestClaudeAndCodexHooksQueueEventsWhenTheUplinkTimesOut(t *testing.T) {
	previousTimeout := eventDeliveryTimeout
	eventDeliveryTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		eventDeliveryTimeout = previousTimeout
	})
	tests := []struct {
		name string
		run  func([]string, io.Reader, io.Writer, io.Writer) error
		body string
	}{
		{
			name: "claude",
			run:  runClaudeHook,
			body: `{"session_id":"claude-session-1","cwd":"/repo","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"pwd"}}`,
		},
		{
			name: "codex",
			run:  runCodexHook,
			body: `{"session_id":"codex-session-1","cwd":"/repo","hook_event_name":"PermissionRequest","tool_name":"shell","tool_input":{"command":"pwd"}}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				<-release
			}))
			defer server.Close()
			defer close(release)
			args := hookFailureArgs()
			for index, value := range args {
				if value == "http://127.0.0.1:1" {
					args[index] = server.URL
				}
			}
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			startedAt := time.Now()

			if err := test.run(args, strings.NewReader(test.body), &stdout, &stderr); err != nil {
				t.Fatalf("run hook: %v", err)
			}
			if elapsed := time.Since(startedAt); elapsed > maxHookFallbackDuration {
				t.Fatalf("hook response exceeded queueing budget: %s", elapsed)
			}
			store, err := openEventQueue(daemonAdapterConfig{})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			count, err := store.Count(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("queued events = %d, want 1", count)
			}
		})
	}
}

func TestClaudeHookReservesTimeToQueueWithDefaultDeliveryTimeout(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)
	args := hookFailureArgs()
	for index, value := range args {
		if value == "http://127.0.0.1:1" {
			args[index] = server.URL
		}
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	startedAt := time.Now()

	if err := runClaudeHook(
		args,
		strings.NewReader(
			`{"session_id":"claude-session-1","cwd":"/repo","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"pwd"}}`,
		),
		&stdout,
		&stderr,
	); err != nil {
		t.Fatalf("run hook: %v", err)
	}
	if elapsed := time.Since(startedAt); elapsed >= maxHookFallbackDuration {
		t.Fatalf("hook response exceeded queueing budget: %s", elapsed)
	}
	store, err := openEventQueue(daemonAdapterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	count, err := store.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("queued events = %d, want 1", count)
	}
}

func TestRunClaudeHookWaitsForBriefAuditContentionBeforeQueueFallback(t *testing.T) {
	const briefAuditContention = 25 * time.Millisecond

	home := t.TempDir()
	t.Setenv("HOME", home)
	auditPath := filepath.Join(home, "collector-audit.jsonl")
	locked := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- filelock.With(auditPath+".lock", func() error {
			close(locked)
			<-release
			return nil
		})
	}()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("timed out acquiring holder lock")
	}

	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	startedAt := time.Now()
	go func() {
		time.Sleep(briefAuditContention)
		close(release)
	}()

	err := runClaudeHook([]string{
		"--api-url", server.URL,
		"--allow-insecure-http",
		"--audit-log", auditPath,
		"--token", "mtq_e_token_secret",
		"--organization-id", "org-1",
		"--machine-id", "machine-1",
		"--machine-enrollment-id", "enrollment-1",
		"--member-id", "member-1",
	}, strings.NewReader(
		`{"session_id":"claude-session-1","cwd":"/repo","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"pwd"}}`,
	), &stdout, &stderr)

	if err != nil {
		t.Fatalf("run hook: %v", err)
	}
	if holderErr := <-holderDone; holderErr != nil {
		t.Fatal(holderErr)
	}
	select {
	case <-requests:
	default:
		t.Fatal("brief audit contention caused a queue fallback instead of direct delivery")
	}
	if elapsed := time.Since(startedAt); elapsed >= 500*time.Millisecond {
		t.Fatalf("hook response exceeded delivery budget: %s", elapsed)
	}
}

func TestSendHookEventsOrQueueOpensQueueWhileDeliveryIsPending(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	config := daemonAdapterConfig{
		AuditLogPath: filepath.Join(home, "collector-audit.jsonl"),
	}
	queueOpenStarted := make(chan struct{})
	directDelivered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-queueOpenStarted:
			writer.Header().Set("content-type", "application/json")
			_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
			close(directDelivered)
		case <-request.Context().Done():
		}
	}))
	defer server.Close()
	client := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		HTTPClient:        &http.Client{Timeout: hookDeliveryTimeout},
	})
	hookCtx, stopHook := context.WithTimeout(context.Background(), hookCollectionTimeout)
	defer stopHook()

	err := sendHookEventsOrQueueWithOpener(
		hookCtx,
		config,
		hookDeliveryTimeout,
		client,
		[]contracts.AgentEvent{{IdempotencyKey: "concurrent-open"}},
		func(ctx context.Context, config daemonAdapterConfig) (*queue.Store, error) {
			close(queueOpenStarted)
			return openHookEventQueueContext(ctx, config)
		},
	)

	if err != nil {
		t.Fatalf("send hook events: %v", err)
	}
	select {
	case <-directDelivered:
	default:
		t.Fatal("queue initialization did not overlap direct delivery")
	}
	store, err := openEventQueue(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	count, err := store.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("queued events = %d, want 0 after direct delivery", count)
	}
}

func TestSendHookEventsOrQueueReservesQueueBudgetAfterHookDeadline(t *testing.T) {
	const expiredHookTimeout = 25 * time.Millisecond

	queuePath := filepath.Join(t.TempDir(), "queue.db")
	store, err := queue.Open(queuePath, queue.Options{})
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(
		http.ResponseWriter,
		*http.Request,
	) {
		<-release
	}))
	defer server.Close()
	defer close(release)
	client := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		HTTPClient:        server.Client(),
	})
	hookCtx, stopHook := context.WithTimeout(context.Background(), expiredHookTimeout)
	defer stopHook()

	err = sendHookEventsOrQueueWithOpener(
		hookCtx,
		daemonAdapterConfig{},
		expiredHookTimeout,
		client,
		[]contracts.AgentEvent{{IdempotencyKey: "expired-hook-fallback"}},
		func(context.Context, daemonAdapterConfig) (*queue.Store, error) {
			<-hookCtx.Done()
			return store, nil
		},
	)

	if err != nil {
		t.Fatalf("send hook events after delivery deadline: %v", err)
	}
	reopenedStore, err := queue.Open(queuePath, queue.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedStore.Close()
	count, err := reopenedStore.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("queued events = %d, want 1 after delivery deadline", count)
	}
}

func TestSendHookEventsOrQueueStopsQueueOpenAfterFallbackBudget(t *testing.T) {
	const (
		slowDeliveryTimeout = time.Second
		maxFallbackDuration = 750 * time.Millisecond
	)

	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		HTTPClient:        server.Client(),
	})
	queueOpenStopped := make(chan struct{})
	startedAt := time.Now()

	err := sendHookEventsOrQueueWithOpener(
		context.Background(),
		daemonAdapterConfig{},
		slowDeliveryTimeout,
		client,
		[]contracts.AgentEvent{{IdempotencyKey: "bounded-fallback-open"}},
		func(ctx context.Context, _ daemonAdapterConfig) (*queue.Store, error) {
			<-ctx.Done()
			close(queueOpenStopped)
			return nil, ctx.Err()
		},
	)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queue open error = %v, want context deadline exceeded", err)
	}
	select {
	case <-queueOpenStopped:
	default:
		t.Fatal("fallback queue opener was not joined after timeout")
	}
	if elapsed := time.Since(startedAt); elapsed >= maxFallbackDuration {
		t.Fatalf("fallback queue open exceeded hook budget: %s", elapsed)
	}
}

func TestSendHookEventsOrQueueCancelsAndJoinsSpeculativeQueue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	client := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		HTTPClient:        &http.Client{Timeout: hookDeliveryTimeout},
	})
	hookCtx, stopHook := context.WithTimeout(context.Background(), hookCollectionTimeout)
	defer stopHook()
	queueOpenStopped := make(chan struct{})

	err := sendHookEventsOrQueueWithOpener(
		hookCtx,
		daemonAdapterConfig{},
		hookDeliveryTimeout,
		client,
		[]contracts.AgentEvent{{IdempotencyKey: "direct-delivery"}},
		func(ctx context.Context, _ daemonAdapterConfig) (*queue.Store, error) {
			<-ctx.Done()
			close(queueOpenStopped)
			return nil, ctx.Err()
		},
	)

	if err != nil {
		t.Fatalf("send hook events: %v", err)
	}
	select {
	case <-queueOpenStopped:
	default:
		t.Fatal("speculative queue opener was not joined after cancellation")
	}
}

func TestSendHookEventsOrQueueRejectsNilQueueAfterDeliveryFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		HTTPClient:        &http.Client{Timeout: hookDeliveryTimeout},
	})
	hookCtx, stopHook := context.WithTimeout(context.Background(), hookCollectionTimeout)
	defer stopHook()

	err := sendHookEventsOrQueueWithOpener(
		hookCtx,
		daemonAdapterConfig{},
		hookDeliveryTimeout,
		client,
		[]contracts.AgentEvent{{IdempotencyKey: "failed-delivery"}},
		func(context.Context, daemonAdapterConfig) (*queue.Store, error) {
			return nil, nil
		},
	)

	if err == nil || !strings.Contains(err.Error(), "returned nil store") {
		t.Fatalf("send hook events error = %v, want nil store error", err)
	}
}

func TestHookFallbackStopsWaitingWithinQueueBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	firstStore, err := queue.Open(path, queue.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer firstStore.Close()
	secondStore, err := queue.Open(path, queue.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer secondStore.Close()

	lockDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer lockDB.Close()
	transaction, err := lockDB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(context.Background(), `INSERT INTO queue_events
		(idempotency_key, payload, attempts, available_at, created_at)
		VALUES (?, ?, 0, ?, ?)`, "held-key", "{}", time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	startedAt := time.Now()
	err = sendEventsOrQueue(
		ctx,
		testClient("http://127.0.0.1:1"),
		secondStore,
		[]contracts.AgentEvent{{IdempotencyKey: "waiting-key"}},
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("enqueue error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(startedAt); elapsed >= maxHookFallbackDuration {
		t.Fatalf("enqueue fallback exceeded hook budget: %s", elapsed)
	}
}

func TestClaudeHookReturnsWithinBudgetWhenQueueWriterStaysLocked(t *testing.T) {
	previousTimeout := eventDeliveryTimeout
	eventDeliveryTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		eventDeliveryTimeout = previousTimeout
	})
	home := t.TempDir()
	t.Setenv("HOME", home)
	store, err := openEventQueue(daemonAdapterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(home, ".local", "state", "mitoriq", "collector-queue.db")
	lockDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer lockDB.Close()
	transaction, err := lockDB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(context.Background(), `INSERT INTO queue_events
		(idempotency_key, payload, attempts, available_at, created_at)
		VALUES (?, ?, 0, ?, ?)`, "held-key", "{}", now, now); err != nil {
		t.Fatal(err)
	}

	body := strings.NewReader(
		`{"session_id":"claude-session-1","cwd":"/repo","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"pwd"}}`,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	startedAt := time.Now()
	err = runClaudeHook(hookFailureArgs(), body, &stdout, &stderr)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hook error = %v, want context deadline exceeded", err)
	}
	if !strings.Contains(err.Error(), "enqueue collector event") {
		t.Fatalf("hook error = %v, want queue persistence failure", err)
	}
	if elapsed := time.Since(startedAt); elapsed >= maxHookFallbackDuration {
		t.Fatalf("hook response exceeded queueing budget: %s", elapsed)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	if err := runClaudeHook(
		hookFailureArgs(),
		strings.NewReader(
			`{"session_id":"claude-session-1","cwd":"/repo","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"pwd"}}`,
		),
		&stdout,
		&stderr,
	); err != nil {
		t.Fatalf("retry hook after writer release: %v", err)
	}
	store, err = openEventQueue(daemonAdapterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	count, err := store.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("queued events after retry = %d, want 1", count)
	}
}

func TestClaudeHookReturnsWithinBudgetWhenUplinkAndQueueWriterStayBlocked(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	store, err := openEventQueue(daemonAdapterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(home, ".local", "state", "mitoriq", "collector-queue.db")
	lockDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer lockDB.Close()
	transaction, err := lockDB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(context.Background(), `INSERT INTO queue_events
		(idempotency_key, payload, attempts, available_at, created_at)
		VALUES (?, ?, 0, ?, ?)`, "held-key", "{}", now, now); err != nil {
		t.Fatal(err)
	}

	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)
	args := hookFailureArgs()
	for index, value := range args {
		if value == "http://127.0.0.1:1" {
			args[index] = server.URL
		}
	}
	startedAt := time.Now()

	err = runClaudeHook(
		args,
		strings.NewReader(
			`{"session_id":"claude-session-1","cwd":"/repo","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"pwd"}}`,
		),
		io.Discard,
		io.Discard,
	)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hook error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(startedAt); elapsed >= maxHookFallbackDuration {
		t.Fatalf("hook response exceeded queueing budget: %s", elapsed)
	}
}

func hookFailureArgs() []string {
	return []string{
		"--api-url", "http://127.0.0.1:1",
		"--allow-insecure-http",
		"--token", "mtq_e_token_secret",
		"--organization-id", "org-1",
		"--machine-id", "machine-1",
		"--machine-enrollment-id", "enrollment-1",
		"--member-id", "member-1",
	}
}

func TestRunQueueDrainLoopDeliversPersistedEvents(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	store, err := openEventQueue(daemonAdapterConfig{ConfigPath: filepath.Join(t.TempDir(), "collector.json")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Enqueue(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}

	delivered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/collector/events" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		delivered <- struct{}{}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runQueueDrainLoop(ctx, store, testClient(server.URL), io.Discard)
	}()

	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for queued event delivery")
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		count, err := store.Count(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatalf("queued event count = %d, want 0", count)
		case <-ticker.C:
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out stopping queue drain loop")
	}
}

func TestRunCursorHookFailsOpenWhenTelemetryUploadStalls(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	startedAt := time.Now()

	err := runCursorHookWithTimeout([]string{
		"--cursor-hooks-beta",
		"--api-url", server.URL,
		"--allow-insecure-http",
		"--token", "mtq_e_token_secret",
		"--organization-id", "org-1",
		"--machine-id", "machine-1",
		"--machine-enrollment-id", "enrollment-1",
		"--member-id", "member-1",
	}, strings.NewReader(`{
		"conversation_id": "cursor-conversation-1",
		"hook_event_name": "sessionStart"
	}`), &stdout, &stderr, 50*time.Millisecond)

	if err != nil {
		t.Fatalf("hook blocked Cursor: %v", err)
	}
	if elapsed := time.Since(startedAt); elapsed > maxHookFallbackDuration {
		t.Fatalf("hook response exceeded fail-open budget: %s", elapsed)
	}
	if strings.TrimSpace(stdout.String()) != `{"continue":true}` {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "cursor_hook_warning=") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	store, err := openEventQueue(daemonAdapterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	count, err := store.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("queued events = %d, want 1", count)
	}
}

func TestRunCursorHookUsesBoundedDefaultDeliveryTimeout(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	startedAt := time.Now()

	err := runCursorHook([]string{
		"--cursor-hooks-beta",
		"--api-url", server.URL,
		"--allow-insecure-http",
		"--token", "mtq_e_token_secret",
		"--organization-id", "org-1",
		"--machine-id", "machine-1",
		"--machine-enrollment-id", "enrollment-1",
		"--member-id", "member-1",
	}, strings.NewReader(`{
		"conversation_id": "cursor-conversation-1",
		"hook_event_name": "sessionStart"
	}`), &stdout, &stderr)

	if err != nil {
		t.Fatalf("hook blocked Cursor: %v", err)
	}
	if elapsed := time.Since(startedAt); elapsed > maxHookFallbackDuration {
		t.Fatalf("hook response exceeded fail-open budget: %s", elapsed)
	}
	if strings.TrimSpace(stdout.String()) != `{"continue":true}` {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "cursor_hook_warning=") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	store, err := openEventQueue(daemonAdapterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	count, err := store.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("queued events = %d, want 1", count)
	}
}

func TestRunCursorHookFailsOpenWhenAuditLockIsContended(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	auditPath := filepath.Join(home, "collector-audit.jsonl")
	locked := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- filelock.With(auditPath+".lock", func() error {
			close(locked)
			<-release
			return nil
		})
	}()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("timed out acquiring holder lock")
	}
	var releaseOnce sync.Once
	releaseHolder := func() {
		releaseOnce.Do(func() {
			close(release)
			if err := <-holderDone; err != nil {
				t.Errorf("release holder lock: %v", err)
			}
		})
	}
	t.Cleanup(releaseHolder)
	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- runCursorHookWithTimeout([]string{
			"--cursor-hooks-beta",
			"--api-url", server.URL,
			"--allow-insecure-http",
			"--audit-log", auditPath,
			"--token", "mtq_e_token_secret",
			"--organization-id", "org-1",
			"--machine-id", "machine-1",
			"--machine-enrollment-id", "enrollment-1",
			"--member-id", "member-1",
		}, strings.NewReader(`{
			"conversation_id": "cursor-conversation-1",
			"hook_event_name": "sessionStart"
		}`), &stdout, &stderr, 50*time.Millisecond)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("hook blocked Cursor: %v", err)
		}
	case <-time.After(maxHookFallbackDuration):
		releaseHolder()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("hook response exceeded fail-open budget")
	}
	if strings.TrimSpace(stdout.String()) != `{"continue":true}` {
		t.Fatalf("stdout = %q", stdout.String())
	}
	select {
	case <-requests:
		t.Fatal("request should not be sent while audit lock is contended")
	default:
	}
	store, err := openEventQueue(daemonAdapterConfig{AuditLogPath: auditPath})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	count, err := store.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("queued events = %d, want 1", count)
	}
}

func TestRunClaudeHookRequiresAdapterConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runClaudeHook(nil, strings.NewReader(`{}`), &stdout, &stderr)

	if err == nil {
		t.Fatal("expected adapter config error")
	}
	if !strings.Contains(err.Error(), "--api-url") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunClaudeHookUsesSavedConfigAndToken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	token := "mtq_e_token_secret"
	writeFallbackToken(t, home, token)

	var received contracts.CollectorBatch
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("authorization") != "Bearer "+token {
			t.Fatalf("authorization = %q", request.Header.Get("authorization"))
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	if err := (localconfig.Store{}).Save(localconfig.Config{
		APIURL:              server.URL,
		AllowInsecureHTTP:   true,
		MachineEnrollmentID: "enrollment-1",
		MachineID:           "machine-1",
		MemberID:            "member-1",
		OrganizationID:      "org-1",
	}); err != nil {
		t.Fatal(err)
	}
	body := strings.NewReader(`{
		"session_id": "claude-session-1",
		"cwd": "/repo",
		"hook_event_name": "PermissionRequest",
		"tool_name": "Bash",
		"tool_input": {"command": "cat secret.txt"}
	}`)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runClaudeHook(nil, body, &stdout, &stderr)

	if err != nil {
		t.Fatalf("err = %v stderr = %s", err, stderr.String())
	}
	if len(received.Events) != 1 {
		t.Fatalf("events = %#v", received.Events)
	}
	if strings.Contains(string(mustJSON(t, received)), "secret.txt") {
		t.Fatalf("event batch leaked raw tool input: %#v", received)
	}
}

func TestRunClaudeHookPrefersOrganizationScopedToken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	writeFallbackToken(t, home, "legacy-token")
	writeOrganizationToken(t, home, "org-1", "org-token")

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("authorization") != "Bearer org-token" {
			t.Fatalf("authorization = %q", request.Header.Get("authorization"))
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	if err := (localconfig.Store{}).Save(localconfig.Config{
		APIURL:              server.URL,
		AllowInsecureHTTP:   true,
		MachineEnrollmentID: "enrollment-1",
		MachineID:           "machine-1",
		MemberID:            "member-1",
		OrganizationID:      "org-1",
	}); err != nil {
		t.Fatal(err)
	}
	body := strings.NewReader(`{
		"session_id": "claude-session-1",
		"cwd": "/repo",
		"hook_event_name": "PermissionRequest",
		"tool_name": "Bash",
		"tool_input": {"command": "cat secret.txt"}
	}`)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runClaudeHook(nil, body, &stdout, &stderr)

	if err != nil {
		t.Fatal(err)
	}
}

func TestRunCodexHookSendsMetadataOnlyEvent(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var received contracts.CollectorBatch
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/collector/events" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	body := strings.NewReader(`{
		"session_id": "codex-session-1",
		"cwd": "/repo",
		"hook_event_name": "PermissionRequest",
		"tool_name": "shell",
		"tool_input": {"command": "cat secret.txt"}
	}`)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runCodexHook([]string{
		"--api-url", server.URL,
		"--allow-insecure-http",
		"--token", "mtq_e_token_secret",
		"--organization-id", "org-1",
		"--machine-id", "machine-1",
		"--machine-enrollment-id", "enrollment-1",
		"--member-id", "member-1",
	}, body, &stdout, &stderr)

	if err != nil {
		t.Fatalf("err = %v stderr = %s", err, stderr.String())
	}
	if len(received.Events) != 1 || received.Events[0].Source != "codex" {
		t.Fatalf("received events = %#v", received.Events)
	}
	if strings.Contains(string(mustJSON(t, received)), "secret.txt") {
		t.Fatalf("event batch leaked raw tool input: %#v", received)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunCodexHookDeliversTurnScopedLifecycle(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var batches []contracts.CollectorBatch
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/collector/events" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		var batch contracts.CollectorBatch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			t.Fatal(err)
		}
		batches = append(batches, batch)
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":2,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	args := []string{
		"--api-url", server.URL,
		"--allow-insecure-http",
		"--token", "mtq_e_token_secret",
		"--organization-id", "org-1",
		"--machine-id", "machine-1",
		"--machine-enrollment-id", "enrollment-1",
		"--member-id", "member-1",
	}

	for index, body := range []string{
		`{
			"session_id": "codex-session-1",
			"turn_id": "turn-1",
			"cwd": "/repo",
			"hook_event_name": "UserPromptSubmit",
			"model": "gpt-5.1",
			"prompt": "inspect the working tree"
		}`,
		`{
			"session_id": "codex-session-1",
			"turn_id": "turn-1",
			"cwd": "/repo",
			"hook_event_name": "Stop",
			"model": "gpt-5.1"
		}`,
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if err := runCodexHook(args, strings.NewReader(body), &stdout, &stderr); err != nil {
			t.Fatalf("err = %v stderr = %s", err, stderr.String())
		}
		if index == 0 && stdout.Len() != 0 {
			t.Fatalf("stdout = %q", stdout.String())
		}
		if index == 1 && stdout.String() != "{\"continue\":true}\n" {
			t.Fatalf("stdout = %q", stdout.String())
		}
	}

	if len(batches) != 2 {
		t.Fatalf("batches = %#v", batches)
	}
	firstEvents := batches[0].Events
	secondEvents := batches[1].Events
	if len(firstEvents) != 2 || len(secondEvents) != 2 {
		t.Fatalf("batches = %#v", batches)
	}
	if firstEvents[0].Type != contracts.EventTypeSessionStarted ||
		firstEvents[1].Type != contracts.EventTypePromptSubmitted ||
		secondEvents[0].Type != contracts.EventTypeModelResponseCompleted ||
		secondEvents[1].Type != contracts.EventTypeSessionStopped {
		t.Fatalf("events = %#v", batches)
	}
	for _, event := range append(firstEvents, secondEvents...) {
		if event.SessionID != firstEvents[0].SessionID {
			t.Fatalf("session ids = %#v", batches)
		}
	}
}

func TestRunCodexHookUsesTranscriptForWaitingUser(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	transcriptPath := filepath.Join(t.TempDir(), "rollout.jsonl")
	transcript := `{"type":"session_meta","payload":{"id":"codex-session-1","cwd":"/repo"},"timestamp":"2026-07-10T01:00:00Z"}
{"type":"turn_context","payload":{"turn_id":"turn-1","cwd":"/repo"},"timestamp":"2026-07-10T01:00:01Z"}
{"type":"response_item","payload":{"item":{"type":"function_call","name":"request_user_input","call_id":"call-1","arguments":"private question"}},"timestamp":"2026-07-10T01:00:02Z"}`
	if err := os.WriteFile(transcriptPath, []byte(transcript), 0o600); err != nil {
		t.Fatal(err)
	}
	var received contracts.CollectorBatch
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":2,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := runCodexHook([]string{
		"--api-url", server.URL,
		"--allow-insecure-http",
		"--token", "mtq_e_token_secret",
		"--organization-id", "org-1",
		"--machine-id", "machine-1",
		"--machine-enrollment-id", "enrollment-1",
		"--member-id", "member-1",
	}, strings.NewReader(fmt.Sprintf(`{
		"session_id": "codex-session-1",
		"turn_id": "turn-1",
		"cwd": "/repo",
		"hook_event_name": "Stop",
		"model": "gpt-5.1",
		"transcript_path": %q
	}`, transcriptPath)), &stdout, &stderr)
	if err != nil {
		t.Fatalf("err = %v stderr = %s", err, stderr.String())
	}
	if stdout.String() != "{\"continue\":true}\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if len(received.Events) != 2 {
		t.Fatalf("events = %#v", received.Events)
	}
	if received.Events[0].Type != contracts.EventTypeUserInputRequested ||
		received.Events[1].Type != contracts.EventTypeModelResponseCompleted {
		t.Fatalf("events = %#v", received.Events)
	}
	if received.Events[0].SessionID != received.Events[1].SessionID {
		t.Fatalf("session ids = %#v", received.Events)
	}
	if strings.Contains(string(mustJSON(t, received)), "private question") {
		t.Fatalf("event batch leaked raw transcript content: %#v", received)
	}
}

func TestRunCodexHookRejectsInvalidJSON(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runCodexHook([]string{
		"--api-url", "http://localhost:8787",
		"--allow-insecure-http",
		"--token", "mtq_e_token_secret",
		"--organization-id", "org-1",
		"--machine-id", "machine-1",
		"--machine-enrollment-id", "enrollment-1",
		"--member-id", "member-1",
	}, strings.NewReader(`{`), &stdout, &stderr)

	if err == nil {
		t.Fatal("expected invalid JSON error")
	}
}

func TestGateRepoAllowlistDowngradesUnmappedL2RepoFields(t *testing.T) {
	hash := strings.Repeat("a", 64)
	events := gateRepoAllowlist([]contracts.AgentEvent{
		testSessionStartedEvent(hash),
		testToolCompletedEvent(),
	}, daemonAdapterConfig{})

	if len(events) != 2 {
		t.Fatalf("events = %#v", events)
	}
	if events[0].PrivacyLevel != "L1" || events[0].Payload["repo"] != nil {
		t.Fatalf("session event = %#v", events[0])
	}
	discovery, ok := events[0].Payload["repoDiscovery"].(map[string]any)
	if !ok || discovery["remoteUrlHash"] != hash {
		t.Fatalf("repo discovery = %#v", events[0].Payload["repoDiscovery"])
	}
	if events[1].PrivacyLevel != "L1" || events[1].Payload["filesChanged"] != nil {
		t.Fatalf("tool event = %#v", events[1])
	}
}

func TestGateRepoAllowlistKeepsApprovedL2RepoFields(t *testing.T) {
	hash := strings.Repeat("a", 64)
	events := gateRepoAllowlist([]contracts.AgentEvent{
		testSessionStartedEvent(hash),
		testToolCompletedEvent(),
	}, daemonAdapterConfig{
		RepoAllowlist: []localconfig.RepoAllowlistEntry{
			{Alias: "mitoriq", RemoteURLHash: hash},
		},
	})

	if len(events) != 2 {
		t.Fatalf("events = %#v", events)
	}
	if events[0].PrivacyLevel != "L2" || events[0].Payload["repo"] == nil {
		t.Fatalf("session event = %#v", events[0])
	}
	if events[1].PrivacyLevel != "L2" || events[1].Payload["filesChanged"] == nil {
		t.Fatalf("tool event = %#v", events[1])
	}
}

func TestGateRepoAllowlistKeepsApprovedStandaloneToolEventAtL2(t *testing.T) {
	hash := strings.Repeat("a", 64)
	event := testToolCompletedEvent()
	event.LocalRepoRemoteURLHash = hash

	events := gateRepoAllowlist([]contracts.AgentEvent{event}, daemonAdapterConfig{
		RepoAllowlist: []localconfig.RepoAllowlistEntry{
			{Alias: "mitoriq", RemoteURLHash: hash},
		},
	})

	if len(events) != 1 {
		t.Fatalf("events = %#v", events)
	}
	if events[0].PrivacyLevel != "L2" || events[0].Payload["filesChanged"] == nil {
		t.Fatalf("tool event = %#v", events[0])
	}
	if events[0].Payload["repo"] != nil {
		t.Fatalf("repo gate metadata should not be sent: %#v", events[0])
	}
}

func TestGateRepoAllowlistDowngradesUnapprovedStandaloneToolEvent(t *testing.T) {
	event := testToolCompletedEvent()
	event.LocalRepoRemoteURLHash = strings.Repeat("a", 64)

	events := gateRepoAllowlist([]contracts.AgentEvent{event}, daemonAdapterConfig{})

	if len(events) != 1 {
		t.Fatalf("events = %#v", events)
	}
	if events[0].PrivacyLevel != "L1" || events[0].Payload["filesChanged"] != nil {
		t.Fatalf("tool event = %#v", events[0])
	}
}

func TestGateRepoAllowlistDropsUnapprovedStandaloneToolEventWhenConfigured(t *testing.T) {
	event := testToolCompletedEvent()
	event.LocalRepoRemoteURLHash = strings.Repeat("a", 64)

	events := gateRepoAllowlist([]contracts.AgentEvent{event}, daemonAdapterConfig{UnmappedRepoMode: "drop"})

	if len(events) != 0 {
		t.Fatalf("events = %#v", events)
	}
}

func TestGateRepoAllowlistDowngradesDeniedStandaloneToolEvent(t *testing.T) {
	hash := strings.Repeat("a", 64)
	event := testToolCompletedEvent()
	event.LocalRepoRemoteURLHash = hash

	events := gateRepoAllowlist([]contracts.AgentEvent{event}, daemonAdapterConfig{
		Deny: localconfig.DenyRules{
			Repos: []localconfig.RepoDenyEntry{{Alias: "private", RemoteURLHash: hash}},
		},
		RepoAllowlist: []localconfig.RepoAllowlistEntry{
			{Alias: "mitoriq", RemoteURLHash: hash},
		},
	})

	if len(events) != 1 {
		t.Fatalf("events = %#v", events)
	}
	if events[0].PrivacyLevel != "L1" || events[0].Payload["filesChanged"] != nil {
		t.Fatalf("tool event = %#v", events[0])
	}
}

func TestGateRepoAllowlistDowngradesStandaloneToolEventForDeniedPath(t *testing.T) {
	hash := strings.Repeat("a", 64)
	event := testToolCompletedEventWithLocalPaths("apps/api/public.ts", "secrets/token.txt")
	event.LocalRepoRemoteURLHash = hash

	events := gateRepoAllowlist([]contracts.AgentEvent{event}, daemonAdapterConfig{
		Deny: localconfig.DenyRules{PathGlobs: []string{"secrets/**"}},
		RepoAllowlist: []localconfig.RepoAllowlistEntry{
			{Alias: "mitoriq", RemoteURLHash: hash},
		},
	})

	if len(events) != 1 {
		t.Fatalf("events = %#v", events)
	}
	if events[0].PrivacyLevel != "L1" || events[0].Payload["filesChanged"] != nil {
		t.Fatalf("tool event = %#v", events[0])
	}
}

func TestGateRepoAllowlistDropsL3FieldsWhenUserOptInIsBelowL3(t *testing.T) {
	events := gateRepoAllowlist([]contracts.AgentEvent{
		testToolStartedL3Event(),
	}, daemonAdapterConfig{MaxPrivacyLevel: "L2"})

	if len(events) != 1 {
		t.Fatalf("events = %#v", events)
	}
	if events[0].PrivacyLevel != "L2" {
		t.Fatalf("privacy level = %s, want L2", events[0].PrivacyLevel)
	}
	if _, ok := events[0].Payload["command"]; ok {
		t.Fatalf("L3 command should be dropped: %#v", events[0])
	}
	if events[0].Payload["toolName"] != "shell" {
		t.Fatalf("tool name should be retained: %#v", events[0])
	}
}

func TestGateUserDenyRepoOverridesApprovedL2RepoFields(t *testing.T) {
	hash := strings.Repeat("a", 64)
	events := gateRepoAllowlist([]contracts.AgentEvent{
		testSessionStartedEvent(hash),
		testToolCompletedEvent(),
	}, daemonAdapterConfig{
		Deny: localconfig.DenyRules{
			Repos: []localconfig.RepoDenyEntry{{Alias: "private", RemoteURLHash: hash}},
		},
		RepoAllowlist: []localconfig.RepoAllowlistEntry{
			{Alias: "mitoriq", RemoteURLHash: hash},
		},
	})

	if len(events) != 2 {
		t.Fatalf("events = %#v", events)
	}
	if events[0].PrivacyLevel != "L1" || events[0].Payload["repo"] != nil {
		t.Fatalf("session event = %#v", events[0])
	}
	if events[0].Payload["repoDiscovery"] != nil {
		t.Fatalf("repo discovery should not be sent for user-denied repo: %#v", events[0])
	}
	if events[1].PrivacyLevel != "L1" || events[1].Payload["filesChanged"] != nil {
		t.Fatalf("tool event = %#v", events[1])
	}
}

func TestGateUserDenyPathGlobDowngradesL2Metadata(t *testing.T) {
	hash := strings.Repeat("a", 64)
	events := gateRepoAllowlist([]contracts.AgentEvent{
		testSessionStartedEvent(hash),
		testToolCompletedEventWithLocalPaths("apps/api/public.ts", "secrets/token.txt"),
	}, daemonAdapterConfig{
		Deny: localconfig.DenyRules{
			PathGlobs: []string{"secrets/**"},
		},
		RepoAllowlist: []localconfig.RepoAllowlistEntry{
			{Alias: "mitoriq", RemoteURLHash: hash},
		},
	})

	if len(events) != 2 {
		t.Fatalf("events = %#v", events)
	}
	if events[0].PrivacyLevel != "L2" || events[0].Payload["repo"] == nil {
		t.Fatalf("session event should keep approved repo metadata: %#v", events[0])
	}
	if events[1].PrivacyLevel != "L1" || events[1].Payload["filesChanged"] != nil {
		t.Fatalf("tool event should remove denied path L2 metadata: %#v", events[1])
	}
	if len(events[1].LocalDenyPaths) != 0 {
		t.Fatalf("local deny paths should not leave gating: %#v", events[1].LocalDenyPaths)
	}
}

func TestGateUserDenyInvalidConfigFailsClosedForL2Only(t *testing.T) {
	l1Event := testEvent()
	events := gateRepoAllowlist([]contracts.AgentEvent{
		l1Event,
		testToolCompletedEvent(),
	}, daemonAdapterConfig{
		Deny: localconfig.DenyRules{PathRegexes: []string{"("}},
	})

	if len(events) != 2 {
		t.Fatalf("events = %#v", events)
	}
	if events[0].PrivacyLevel != "L1" || events[0].Payload["toolName"] != "shell" {
		t.Fatalf("L1 event should be unaffected: %#v", events[0])
	}
	if events[1].PrivacyLevel != "L1" || events[1].Payload["filesChanged"] != nil {
		t.Fatalf("L2 event should fail closed to L1: %#v", events[1])
	}
}

func TestGateRepoAllowlistDropsUnmappedL2WhenConfigured(t *testing.T) {
	hash := strings.Repeat("a", 64)
	events := gateRepoAllowlist([]contracts.AgentEvent{
		testSessionStartedEvent(hash),
		testToolCompletedEvent(),
	}, daemonAdapterConfig{UnmappedRepoMode: "drop"})

	if len(events) != 1 {
		t.Fatalf("events = %#v, want repo discovery only", events)
	}
	if events[0].PrivacyLevel != "L1" || events[0].Payload["repo"] != nil {
		t.Fatalf("session event = %#v", events[0])
	}
	discovery, ok := events[0].Payload["repoDiscovery"].(map[string]any)
	if !ok || discovery["remoteUrlHash"] != hash {
		t.Fatalf("repo discovery = %#v", events[0].Payload["repoDiscovery"])
	}
}

func TestDaemonAdapterStateAppliesUpdatedAllowlistToKnownSessionRepo(t *testing.T) {
	hash := strings.Repeat("a", 64)
	state := newDaemonAdapterState(daemonAdapterConfig{})
	discoveryEvents := state.gateRepoAllowlist([]contracts.AgentEvent{testSessionStartedEvent(hash)})

	if len(discoveryEvents) != 1 || discoveryEvents[0].PrivacyLevel != "L1" {
		t.Fatalf("discovery events = %#v", discoveryEvents)
	}

	deniedToolEvents := state.gateRepoAllowlist([]contracts.AgentEvent{testToolCompletedEvent()})
	if len(deniedToolEvents) != 1 || deniedToolEvents[0].PrivacyLevel != "L1" {
		t.Fatalf("denied tool events = %#v", deniedToolEvents)
	}

	state.updateRepoAllowlist([]contracts.RepoAllowlistEntry{
		{Alias: "mitoriq", RemoteURLHash: hash},
	})
	allowedToolEvents := state.gateRepoAllowlist([]contracts.AgentEvent{testToolCompletedEvent()})
	if len(allowedToolEvents) != 1 || allowedToolEvents[0].PrivacyLevel != "L2" {
		t.Fatalf("allowed tool events = %#v", allowedToolEvents)
	}
}

func TestDaemonAdapterStateKeepsPathDenyForKnownSession(t *testing.T) {
	hash := strings.Repeat("a", 64)
	state := newDaemonAdapterState(daemonAdapterConfig{
		Deny: localconfig.DenyRules{PathGlobs: []string{"apps/private/**"}},
		RepoAllowlist: []localconfig.RepoAllowlistEntry{
			{Alias: "mitoriq", RemoteURLHash: hash},
		},
	})
	sessionEvent := testSessionStartedEvent(hash)
	sessionEvent.LocalDenyPaths = []string{"apps/private"}

	deniedSessionEvents := state.gateRepoAllowlist([]contracts.AgentEvent{sessionEvent})
	deniedToolEvents := state.gateRepoAllowlist([]contracts.AgentEvent{testToolCompletedEvent()})

	if len(deniedSessionEvents) != 1 || deniedSessionEvents[0].PrivacyLevel != "L1" {
		t.Fatalf("session events = %#v", deniedSessionEvents)
	}
	if len(deniedToolEvents) != 1 || deniedToolEvents[0].PrivacyLevel != "L1" {
		t.Fatalf("tool events = %#v", deniedToolEvents)
	}
}

func TestResolveGitContextReturnsNullRepoOutsideGitWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	snapshot, err := resolveGitContext("/tmp/not-a-mitoriq-git-worktree")

	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Repo != nil {
		t.Fatalf("repo = %#v", snapshot.Repo)
	}
}

func TestDaemonHandlerWithoutAdapterStillAcceptsOTLP(t *testing.T) {
	handler := newDaemonHandler(daemonAdapterConfig{})
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(`{}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestOTLPHandlerSendsUsageMetric(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var received contracts.CollectorUsageBatch
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/collector/usage" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	handler := newDaemonHandler(daemonAdapterConfig{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		Token:             "mtq_e_token_secret",
		Identity: adapterIdentity{
			MachineEnrollmentID: "enrollment-1",
			MachineID:           "machine-1",
			MemberID:            "member-1",
			OrganizationID:      "org-1",
		},
	})
	body := strings.NewReader(`{
		"resourceLogs": [{
			"scopeLogs": [{
				"logRecords": [{
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
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", body)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if len(received.Metrics) != 1 || received.Metrics[0].Model != "claude-sonnet-5" {
		t.Fatalf("received usage = %#v", received)
	}
}

func TestSyncRepoAllowlistPersistsHeartbeatAllowlist(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	hash := strings.Repeat("c", 64)
	configPath := filepath.Join(t.TempDir(), "collector.json")
	var received contracts.HeartbeatRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/collector/heartbeat" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":true,"serverTime":"2026-07-04T00:00:01Z","repoAllowlist":[{"remoteUrlHash":"` + hash + `","alias":"client-api"}]}`))
	}))
	defer server.Close()
	state := newDaemonAdapterState(daemonAdapterConfig{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		ConfigPath:        configPath,
		Identity: adapterIdentity{
			MachineEnrollmentID: "enrollment-1",
			MachineID:           "machine-1",
			MemberID:            "member-1",
			OrganizationID:      "org-1",
		},
		Token: "mtq_e_token_secret",
	})

	syncRepoAllowlist(context.Background(), state, server.Client())

	if received.MachineEnrollmentID != "enrollment-1" {
		t.Fatalf("heartbeat = %#v", received)
	}
	if state.snapshot().RepoAllowlist[0].RemoteURLHash != hash {
		t.Fatalf("state = %#v", state.snapshot())
	}
	saved, err := (localconfig.Store{Path: configPath}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.RepoAllowlist) != 1 || saved.RepoAllowlist[0].Alias != "client-api" {
		t.Fatalf("saved config = %#v", saved)
	}
}

func TestDeliverCollectionRejectsPartialEventAcceptance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/collector/events" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":0,"duplicated":0,"rejected":1}`))
	}))
	defer server.Close()
	client := testClient(server.URL)

	err := deliverCollection(nilContext(), client, nil, []contracts.AgentEvent{testEvent()}, nil)

	if err == nil || !strings.Contains(err.Error(), "events not fully accepted") {
		t.Fatalf("err = %v", err)
	}
}

func TestDeliverCollectionQueuesPartialEventAcceptance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/collector/events" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":0,"duplicated":0,"rejected":1}`))
	}))
	defer server.Close()
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	eventQueue, err := queue.Open(filepath.Join(t.TempDir(), "collector-queue.db"), queue.Options{
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eventQueue.Close()
	event := testEvent()

	if err := deliverCollection(nilContext(), testClient(server.URL), eventQueue, []contracts.AgentEvent{event}, nil); err != nil {
		t.Fatalf("deliver collection: %v", err)
	}
	records, err := eventQueue.Due(context.Background(), 10, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Event.IdempotencyKey != event.IdempotencyKey {
		t.Fatalf("persisted events = %#v", records)
	}
	if records[0].Event.CollectorVersion != version.Current().Version {
		t.Fatalf("collector version = %q", records[0].Event.CollectorVersion)
	}
}

func TestDeliverCollectionPreservesAnEventCollectorVersion(t *testing.T) {
	var received contracts.CollectorBatch
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	event := testEvent()
	event.CollectorVersion = "0.1.3"

	if err := deliverCollection(nilContext(), testClient(server.URL), nil, []contracts.AgentEvent{event}, nil); err != nil {
		t.Fatalf("deliver collection: %v", err)
	}
	if len(received.Events) != 1 || received.Events[0].CollectorVersion != "0.1.3" {
		t.Fatalf("received events = %#v", received.Events)
	}
}

func TestDeliverCollectionRejectsPartialUsageAcceptance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/collector/usage" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":0,"duplicated":0,"rejected":1}`))
	}))
	defer server.Close()
	client := testClient(server.URL)

	err := deliverCollection(nilContext(), client, nil, nil, []contracts.UsageMetric{testUsageMetric()})

	if err == nil || !strings.Contains(err.Error(), "usage metrics not fully accepted") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunDaemonReturnsListenErrorForInvalidAddress(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"daemon", "--otlp-http-addr", "127.0.0.1:not-a-port"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if !strings.Contains(stderr.String(), "エラー") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func nilContext() context.Context {
	return context.Background()
}

func testClient(apiURL string) uplink.Client {
	return uplink.NewClient(uplink.Config{
		APIURL:            apiURL,
		AllowInsecureHTTP: true,
		HTTPClient:        http.DefaultClient,
		Token:             "mtq_e_token_secret",
	})
}

func testEvent() contracts.AgentEvent {
	return contracts.AgentEvent{
		ID:                  "event-1",
		SchemaVersion:       1,
		OrganizationID:      "org-1",
		MachineID:           "machine-1",
		MachineEnrollmentID: "enrollment-1",
		MemberID:            "member-1",
		SessionID:           "session-1",
		Source:              "codex",
		OccurredAt:          "2026-07-04T00:00:00Z",
		IdempotencyKey:      "event-key-1",
		PrivacyLevel:        "L1",
		Type:                contracts.EventTypePermissionRequested,
		Payload:             map[string]any{"toolName": "shell", "action": "approval_required"},
	}
}

func testSessionStartedEvent(remoteURLHash string) contracts.AgentEvent {
	event := testEvent()
	event.ID = "session-started-1"
	event.Type = contracts.EventTypeSessionStarted
	event.PrivacyLevel = "L2"
	event.Payload = map[string]any{
		"model": "gpt-5",
		"repo": map[string]any{
			"branch":        "main",
			"remoteUrlHash": remoteURLHash,
		},
	}

	return event
}

func testToolCompletedEvent() contracts.AgentEvent {
	event := testEvent()
	event.ID = "tool-completed-1"
	event.Type = contracts.EventTypeToolCompleted
	event.PrivacyLevel = "L2"
	event.Payload = map[string]any{
		"filesChanged": 2,
		"toolName":     "apply_patch",
	}

	return event
}

func testToolStartedL3Event() contracts.AgentEvent {
	event := testEvent()
	event.ID = "tool-started-1"
	event.Type = contracts.EventTypeToolStarted
	event.PrivacyLevel = "L3"
	event.Payload = map[string]any{
		"command":  "cat /private/tmp/secret.txt",
		"toolName": "shell",
	}

	return event
}

func testToolCompletedEventWithLocalPaths(paths ...string) contracts.AgentEvent {
	event := testToolCompletedEvent()
	event.LocalDenyPaths = append([]string(nil), paths...)

	return event
}

func testUsageMetric() contracts.UsageMetric {
	return contracts.UsageMetric{
		ID:                  "metric-1",
		SchemaVersion:       1,
		OrganizationID:      "org-1",
		MachineEnrollmentID: "enrollment-1",
		SessionID:           "session-1",
		Model:               "gpt-5.1",
		OccurredAt:          "2026-07-04T00:00:00Z",
		Cost:                contracts.Cost{Accuracy: contracts.CostAccuracyUnknown},
		IdempotencyKey:      "metric-key-1",
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	bytes, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return bytes
}

func TestRunDaemonRejectsInvalidFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"daemon", "--unknown"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunEnrollRequiresBootstrapCode(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"enroll", "--local-uuid", "local-1"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if !strings.Contains(stderr.String(), "--bootstrap-code is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunEnrollStoresTokenWithoutPrintingSecret(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	if err := (localconfig.Store{}).Save(localconfig.Config{UpdateChannel: localconfig.UpdateChannelStable}); err != nil {
		t.Fatal(err)
	}
	token := "mtq_e_tokenid_secretvalue"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/machines/enrollments" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{
			"enrollmentToken":"` + token + `",
			"machineEnrollmentId":"enrollment-1",
			"machineId":"machine-1",
			"memberId":"member-1",
			"organizationId":"org-1",
			"tokenPrefix":"mtq_e_tokenid"
		}`))
	}))
	defer server.Close()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{
		"enroll",
		"--api-url", server.URL,
		"--bootstrap-code", "mtq_b_bootstrap",
		"--display-name", "Mitoriq Test",
		"--local-uuid", "local-1",
		"--os", "macos",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), token) || strings.Contains(stderr.String(), token) {
		t.Fatalf("token leaked stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "enrolled machine_id=machine-1") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	config, err := (localconfig.Store{}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.MemberID != "member-1" || config.MachineEnrollmentID != "enrollment-1" {
		t.Fatalf("config = %#v", config)
	}
	if config.UpdateChannel != localconfig.UpdateChannelStable {
		t.Fatalf("update channel = %q", config.UpdateChannel)
	}
	if !config.AllowInsecureHTTP {
		t.Fatalf("config = %#v", config)
	}
}

func TestRunInstallDryRunPrintsLaunchdAndHookSnippets(t *testing.T) {
	setTestUserHome(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runInstallForOS([]string{
		"--binary", "/opt/homebrew/bin/mitoriq-collector",
		"--dry-run",
		"--tools", "claude,codex",
	}, &stdout, &stderr, "darwin", &recordingCommandRunner{}, "")

	if err != nil {
		t.Fatalf("error = %v, stderr = %s", err, stderr.String())
	}
	output := stdout.String()
	for _, expected := range []string{
		"collector_install_status=planned",
		"com.mitoriq.collector.plist",
		"claude_hook_command=/opt/homebrew/bin/mitoriq-collector claude-hook",
		"codex_hook_command=/opt/homebrew/bin/mitoriq-collector codex-hook",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("stdout missing %q: %s", expected, output)
		}
	}
}

func TestRunUninstallDryRunPrintsOwnedLaunchdPath(t *testing.T) {
	setTestUserHome(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runUninstallForOS(
		[]string{"--dry-run"},
		&stdout,
		&stderr,
		"darwin",
		&recordingCommandRunner{},
		"",
	)

	if err != nil {
		t.Fatalf("error = %v, stderr = %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "collector_uninstall_status=planned") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "com.mitoriq.collector.plist") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunRejectsUnknownSubcommandInJapanese(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"unknown"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if !strings.Contains(stderr.String(), "エラー") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestDefaultOSReturnsKnownCollectorValue(t *testing.T) {
	switch got := defaultOS(); got {
	case "macos", "linux", "windows", "unknown":
	default:
		t.Fatalf("defaultOS = %q", got)
	}
}

func writeFallbackToken(t *testing.T, home string, token string) {
	t.Helper()
	path := filepath.Join(home, ".config", "mitoriq", "enrollment-token")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeOrganizationToken(t *testing.T, home string, organizationID string, token string) {
	t.Helper()
	path := filepath.Join(home, ".config", "mitoriq", "enrollment-tokens", organizationID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
