package uplink_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/contracts"
	"github.com/mitoriq/collector/internal/filelock"
	"github.com/mitoriq/collector/internal/localaudit"
	"github.com/mitoriq/collector/internal/queue"
	"github.com/mitoriq/collector/internal/uplink"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func uplinkTestEvent() contracts.AgentEvent {
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
		PrivacyLevel:        "L0",
		Type:                contracts.EventTypeHeartbeat,
		Payload:             map[string]any{"collectorVersion": "0.1.0"},
	}
}

func TestSendEventsPostsAuthenticatedCollectorBatch(t *testing.T) {
	now := time.Date(2026, 7, 4, 0, 0, 1, 0, time.UTC)
	var receivedAuth string
	var receivedBatch contracts.CollectorBatch
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/collector/events" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		receivedAuth = request.Header.Get("authorization")
		if err := json.NewDecoder(request.Body).Decode(&receivedBatch); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()

	client := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		HTTPClient:        server.Client(),
		Now:               func() time.Time { return now },
		Token:             "mtq_e_token_secret",
	})
	result, err := client.SendEvents(context.Background(), []contracts.AgentEvent{uplinkTestEvent()})
	if err != nil {
		t.Fatal(err)
	}

	if receivedAuth != "Bearer mtq_e_token_secret" {
		t.Fatalf("authorization = %q", receivedAuth)
	}
	if len(receivedBatch.Events) != 1 || receivedBatch.Events[0].IdempotencyKey != "event-key-1" {
		t.Fatalf("received batch = %#v", receivedBatch)
	}
	if receivedBatch.SentAt != "2026-07-04T00:00:01Z" {
		t.Fatalf("sentAt = %q", receivedBatch.SentAt)
	}
	if result.Accepted != 1 {
		t.Fatalf("accepted = %d", result.Accepted)
	}
}

func TestSendEventsWritesMetadataOnlyLocalAuditLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector-audit.jsonl")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()

	event := uplinkTestEvent()
	event.PrivacyLevel = "L2"
	event.Type = contracts.EventTypeToolCompleted
	event.Payload = map[string]any{"rawPrompt": "do not persist this"}
	client := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		AuditLog:          &localaudit.Store{Path: path},
		HTTPClient:        server.Client(),
		Token:             "mtq_e_token_secret",
	})

	if _, err := client.SendEvents(context.Background(), []contracts.AgentEvent{event}); err != nil {
		t.Fatal(err)
	}
	entries, err := (localaudit.Store{Path: path}).Tail(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Phase != "attempted" || entries[1].Phase != "accepted" {
		t.Fatalf("entries = %#v", entries)
	}
	if entries[0].PrivacyLevels["L2"] != 1 || entries[0].EventTypes[string(contracts.EventTypeToolCompleted)] != 1 {
		t.Fatalf("attempt entry = %#v", entries[0])
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"do not persist this", "mtq_e_token_secret", "event-key-1", "session-1"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("audit log contains %q: %s", forbidden, body)
		}
	}
}

func TestSendEventsDoesNotTransmitWhenLocalAuditLogCannotBeWritten(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()

	client := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		AuditLog:          &localaudit.Store{Path: t.TempDir()},
		HTTPClient:        server.Client(),
		Token:             "mtq_e_token_secret",
	})
	_, err := client.SendEvents(context.Background(), []contracts.AgentEvent{uplinkTestEvent()})

	if err == nil {
		t.Fatal("expected audit log error")
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want 0", requests)
	}
}

func TestSendEventsStopsWaitingForAuditLockWhenContextCanceled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector-audit.jsonl")
	locked := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- filelock.With(path+".lock", func() error {
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
	t.Cleanup(func() {
		close(release)
		if err := <-holderDone; err != nil {
			t.Errorf("release holder lock: %v", err)
		}
	})
	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	client := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		AuditLog:          &localaudit.Store{Path: path},
		HTTPClient:        server.Client(),
		Token:             "mtq_e_token_secret",
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.SendEvents(ctx, []contracts.AgentEvent{uplinkTestEvent()})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	select {
	case <-requests:
		t.Fatal("request should not be sent after context cancellation")
	default:
	}
}

func TestSendEventsReturnsAuthStoppedErrorOnRevokedEnrollment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, `{"code":"collector_token_invalid"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	client := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		HTTPClient:        server.Client(),
		Token:             "revoked-token",
	})
	_, err := client.SendEvents(context.Background(), []contracts.AgentEvent{uplinkTestEvent()})

	if !errors.Is(err, uplink.ErrEnrollmentRejected) {
		t.Fatalf("err = %v, want ErrEnrollmentRejected", err)
	}
	var rejectedErr uplink.EnrollmentRejectedError
	if !errors.As(err, &rejectedErr) {
		t.Fatalf("err = %T, want EnrollmentRejectedError", err)
	}
	if rejectedErr.UserMessage() == "" {
		t.Fatal("user message should be present")
	}
}

func TestSendHeartbeatUsesDedicatedEndpoint(t *testing.T) {
	var received contracts.HeartbeatRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/collector/heartbeat" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":true,"serverTime":"2026-07-04T00:00:01Z","repoAllowlist":[{"remoteUrlHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","alias":"mitoriq"}]}`))
	}))
	defer server.Close()

	client := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		HTTPClient:        server.Client(),
		Token:             "mtq_e_token_secret",
	})
	response, err := client.SendHeartbeat(context.Background(), contracts.HeartbeatRequest{
		SchemaVersion:       1,
		MachineID:           "machine-1",
		MachineEnrollmentID: "enrollment-1",
		CollectorVersion:    "0.1.0",
		OccurredAt:          "2026-07-04T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if received.MachineEnrollmentID != "enrollment-1" {
		t.Fatalf("heartbeat = %#v", received)
	}
	if len(response.RepoAllowlist) != 1 || response.RepoAllowlist[0].Alias != "mitoriq" {
		t.Fatalf("heartbeat response = %#v", response)
	}
}

func TestSendUsagePostsAuthenticatedMetrics(t *testing.T) {
	now := time.Date(2026, 7, 4, 0, 0, 1, 0, time.UTC)
	inputTokens := 12
	outputTokens := 34
	var received contracts.CollectorUsageBatch
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/collector/usage" {
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

	client := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		HTTPClient:        server.Client(),
		Now:               func() time.Time { return now },
		Token:             "mtq_e_token_secret",
	})
	result, err := client.SendUsage(context.Background(), []contracts.UsageMetric{{
		ID:                  "metric-1",
		SchemaVersion:       1,
		OrganizationID:      "org-1",
		MachineEnrollmentID: "enrollment-1",
		SessionID:           "session-1",
		Model:               "claude-sonnet-5",
		OccurredAt:          "2026-07-04T00:00:00Z",
		InputTokens:         &inputTokens,
		OutputTokens:        &outputTokens,
		Cost:                contracts.Cost{Accuracy: contracts.CostAccuracyUnknown},
		IdempotencyKey:      "metric-key-1",
	}})
	if err != nil {
		t.Fatal(err)
	}

	if len(received.Metrics) != 1 || received.Metrics[0].Model != "claude-sonnet-5" {
		t.Fatalf("received usage batch = %#v", received)
	}
	if received.SentAt != "2026-07-04T00:00:01Z" {
		t.Fatalf("sentAt = %q", received.SentAt)
	}
	if result.Accepted != 1 {
		t.Fatalf("accepted = %d", result.Accepted)
	}
}

func TestHeartbeatIntervalIsSixtySeconds(t *testing.T) {
	if uplink.HeartbeatInterval != time.Minute {
		t.Fatalf("HeartbeatInterval = %s, want %s", uplink.HeartbeatInterval, time.Minute)
	}
}

func TestDrainQueueKeepsEventsOnNetworkFailureAndDeletesAfterRecovery(t *testing.T) {
	now := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	store, err := queue.Open(filepath.Join(t.TempDir(), "queue.db"), queue.Options{
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	if _, err := store.Enqueue(ctx, uplinkTestEvent()); err != nil {
		t.Fatal(err)
	}

	badClient := uplink.NewClient(uplink.Config{
		APIURL: "http://collector.invalid",
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return nil, errors.New("network down")
			}),
		},
		Token: "mtq_e_token_secret",
	})
	if err := uplink.DrainQueue(ctx, store, badClient, uplink.DrainOptions{
		BatchSize: 10,
		Now:       func() time.Time { return time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC) },
	}); err == nil {
		t.Fatal("expected network error")
	}
	count, err := store.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("queue count after failure = %d, want 1", count)
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
	}))
	defer server.Close()
	goodClient := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		HTTPClient:        server.Client(),
		Token:             "mtq_e_token_secret",
	})
	if err := uplink.DrainQueue(ctx, store, goodClient, uplink.DrainOptions{
		BatchSize: 10,
		Now:       func() time.Time { return time.Date(2026, 7, 4, 0, 1, 0, 0, time.UTC) },
	}); err != nil {
		t.Fatal(err)
	}
	count, err = store.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("queue count after recovery = %d, want 0", count)
	}
}

func TestSendEventsRejectsPlainHTTPForNonLoopbackAPI(t *testing.T) {
	client := uplink.NewClient(uplink.Config{
		APIURL:     "http://collector.example.com",
		HTTPClient: http.DefaultClient,
		Token:      "mtq_e_token_secret",
	})

	_, err := client.SendEvents(context.Background(), []contracts.AgentEvent{uplinkTestEvent()})

	if err == nil {
		t.Fatal("expected insecure API URL error")
	}
}

func TestSendEventsRejectsExplicitPlainHTTPForNonLoopbackAPI(t *testing.T) {
	client := uplink.NewClient(uplink.Config{
		APIURL:            "http://collector.example.com",
		AllowInsecureHTTP: true,
		HTTPClient:        http.DefaultClient,
		Token:             "mtq_e_token_secret",
	})

	_, err := client.SendEvents(context.Background(), []contracts.AgentEvent{uplinkTestEvent()})

	if err == nil {
		t.Fatal("expected non-loopback insecure API URL error")
	}
}

func TestSendEventsAllowsExplicitLoopbackHTTPOnly(t *testing.T) {
	client := uplink.NewClient(uplink.Config{
		APIURL:            "http://127.0.0.1:4318",
		AllowInsecureHTTP: true,
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Host != "127.0.0.1:4318" {
					t.Fatalf("host = %s", request.URL.Host)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"accepted":1,"duplicated":0,"rejected":0}`)),
					Header:     make(http.Header),
				}, nil
			}),
		},
		Token: "mtq_e_token_secret",
	})

	counts, err := client.SendEvents(context.Background(), []contracts.AgentEvent{uplinkTestEvent()})
	if err != nil {
		t.Fatal(err)
	}
	if counts.Accepted != 1 {
		t.Fatalf("counts = %#v", counts)
	}
}

func TestDrainQueueReturnsNilWhenNoRecordsAreDue(t *testing.T) {
	store, err := queue.Open(filepath.Join(t.TempDir(), "queue.db"), queue.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	client := uplink.NewClient(uplink.Config{
		APIURL: "https://collector.example.com",
		Token:  "mtq_e_token_secret",
	})

	if err := uplink.DrainQueue(context.Background(), store, client, uplink.DrainOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestDrainQueueKeepsRejectedBatchForLaterRetry(t *testing.T) {
	now := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	store, err := queue.Open(filepath.Join(t.TempDir(), "queue.db"), queue.Options{
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	if _, err := store.Enqueue(ctx, uplinkTestEvent()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{"accepted":0,"duplicated":0,"rejected":1}`))
	}))
	defer server.Close()
	client := uplink.NewClient(uplink.Config{
		APIURL:            server.URL,
		AllowInsecureHTTP: true,
		HTTPClient:        server.Client(),
		Token:             "mtq_e_token_secret",
	})

	err = uplink.DrainQueue(ctx, store, client, uplink.DrainOptions{
		BatchSize: 10,
		Now:       func() time.Time { return now },
	})

	if err == nil {
		t.Fatal("expected partial rejection error")
	}
	immediateDue, err := store.Due(ctx, 10, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(immediateDue) != 0 {
		t.Fatalf("immediate due events = %d, want 0", len(immediateDue))
	}
	laterDue, err := store.Due(ctx, 10, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(laterDue) != 1 || laterDue[0].Attempts != 1 {
		t.Fatalf("later due = %#v", laterDue)
	}
}
