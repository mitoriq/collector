package queue

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/contracts"
)

func TestEnqueueWaitsForConcurrentWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	firstStore, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer firstStore.Close()
	secondStore, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer secondStore.Close()

	transaction, err := firstStore.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	now := formatTime(time.Now())
	if _, err := transaction.ExecContext(context.Background(), `INSERT INTO queue_events
		(idempotency_key, payload, attempts, available_at, created_at)
		VALUES (?, ?, 0, ?, ?)`, "held-key", "{}", now, now); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := secondStore.Enqueue(context.Background(), contracts.AgentEvent{IdempotencyKey: "waiting-key"})
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("enqueue returned before the writer released its lock: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("enqueue did not resume after the writer released its lock")
	}
}
