package queue_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/contracts"
	"github.com/mitoriq/collector/internal/queue"
)

func queueTestEvent() contracts.AgentEvent {
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
		PrivacyLevel:        "L0",
		Type:                contracts.EventTypeHeartbeat,
		Payload:             map[string]any{"collectorVersion": "0.1.0"},
	}
}

func TestOpenCreatesSQLiteQueueFileWith0600Permissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")

	store, err := queue.Open(path, queue.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("queue file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestOpenReturnsErrorWhenParentPathIsFile(t *testing.T) {
	parentFile := filepath.Join(t.TempDir(), "queue-parent")
	if err := os.WriteFile(parentFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := queue.Open(filepath.Join(parentFile, "queue.db"), queue.Options{})

	if err == nil {
		t.Fatal("expected parent path error")
	}
}

func TestEnqueueAssignsIdempotencyKeyOnceAndSuppressesDuplicates(t *testing.T) {
	store, err := queue.Open(filepath.Join(t.TempDir(), "queue.db"), queue.Options{
		KeyGenerator: func() (string, error) {
			return "generated-key-1", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	first, err := store.Enqueue(ctx, queueTestEvent())
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Enqueue(ctx, first.Event)
	if err != nil {
		t.Fatal(err)
	}

	if first.Event.IdempotencyKey != "generated-key-1" {
		t.Fatalf("idempotency key = %q", first.Event.IdempotencyKey)
	}
	if !first.Inserted {
		t.Fatal("first enqueue should insert")
	}
	if second.Inserted {
		t.Fatal("second enqueue should be treated as duplicate")
	}
	count, err := store.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("queue count = %d, want 1", count)
	}
}

func TestEnqueueUsesDefaultRandomIdempotencyKey(t *testing.T) {
	store, err := queue.Open(filepath.Join(t.TempDir(), "queue.db"), queue.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	result, err := store.Enqueue(context.Background(), queueTestEvent())
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(result.Event.IdempotencyKey, "evt_") {
		t.Fatalf("idempotency key = %q", result.Event.IdempotencyKey)
	}
	if len(result.Event.IdempotencyKey) != len("evt_")+32 {
		t.Fatalf("idempotency key length = %d", len(result.Event.IdempotencyKey))
	}
}

func TestDueEventsStayQueuedUntilMarkedDelivered(t *testing.T) {
	now := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	store, err := queue.Open(filepath.Join(t.TempDir(), "queue.db"), queue.Options{
		KeyGenerator: func() (string, error) {
			return "retry-key-1", nil
		},
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	queued, err := store.Enqueue(ctx, queueTestEvent())
	if err != nil {
		t.Fatal(err)
	}

	due, err := store.Due(ctx, 10, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 {
		t.Fatalf("due events = %d, want 1", len(due))
	}
	if due[0].Event.IdempotencyKey != queued.Event.IdempotencyKey {
		t.Fatalf("due idempotency key = %q", due[0].Event.IdempotencyKey)
	}

	if err := store.MarkDelivered(ctx, []int64{due[0].ID}); err != nil {
		t.Fatal(err)
	}
	count, err := store.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("queue count after delivery = %d, want 0", count)
	}
}

func TestMarkRetryDelaysDueEventAndIncrementsAttempts(t *testing.T) {
	now := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	store, err := queue.Open(filepath.Join(t.TempDir(), "queue.db"), queue.Options{
		KeyGenerator: func() (string, error) {
			return "retry-key-2", nil
		},
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	if _, err := store.Enqueue(ctx, queueTestEvent()); err != nil {
		t.Fatal(err)
	}
	due, err := store.Due(ctx, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 {
		t.Fatalf("due events = %d, want 1", len(due))
	}

	availableAt := now.Add(time.Minute)
	if err := store.MarkRetry(ctx, due[0].ID, availableAt); err != nil {
		t.Fatal(err)
	}
	notYetDue, err := store.Due(ctx, 10, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(notYetDue) != 0 {
		t.Fatalf("notYetDue events = %d, want 0", len(notYetDue))
	}
	dueAgain, err := store.Due(ctx, 10, availableAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(dueAgain) != 1 || dueAgain[0].Attempts != 1 {
		t.Fatalf("dueAgain = %#v", dueAgain)
	}
}

func TestEnqueueReturnsKeyGeneratorError(t *testing.T) {
	expectedErr := errors.New("entropy unavailable")
	store, err := queue.Open(filepath.Join(t.TempDir(), "queue.db"), queue.Options{
		KeyGenerator: func() (string, error) {
			return "", expectedErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	_, err = store.Enqueue(context.Background(), queueTestEvent())

	if !errors.Is(err, expectedErr) {
		t.Fatalf("err = %v, want %v", err, expectedErr)
	}
}

func TestClosedStoreOperationsReturnErrors(t *testing.T) {
	store, err := queue.Open(filepath.Join(t.TempDir(), "queue.db"), queue.Options{
		KeyGenerator: func() (string, error) {
			return "closed-key-1", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if _, err := store.Enqueue(ctx, queueTestEvent()); err == nil {
		t.Fatal("expected enqueue error after close")
	}
	if _, err := store.Due(ctx, 10, time.Now()); err == nil {
		t.Fatal("expected due error after close")
	}
	if err := store.MarkDelivered(ctx, []int64{1}); err == nil {
		t.Fatal("expected mark delivered error after close")
	}
	if _, err := store.Count(ctx); err == nil {
		t.Fatal("expected count error after close")
	}
}
