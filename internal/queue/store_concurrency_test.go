package queue

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/contracts"
	sqlite3 "modernc.org/sqlite/lib"
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

func TestEnqueueStopsWaitingWhenContextDeadlineExpires(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	startedAt := time.Now()
	_, err = secondStore.Enqueue(ctx, contracts.AgentEvent{IdempotencyKey: "waiting-key"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("enqueue error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(startedAt); elapsed >= time.Second {
		t.Fatalf("enqueue observed deadline after %s, want less than 1s", elapsed)
	}
}

func TestIsSQLiteBusyRecognizesExtendedCodes(t *testing.T) {
	tests := []struct {
		name string
		code int
		want bool
	}{
		{name: "busy", code: sqlite3.SQLITE_BUSY, want: true},
		{name: "busy recovery", code: sqlite3.SQLITE_BUSY_RECOVERY, want: true},
		{name: "busy snapshot", code: sqlite3.SQLITE_BUSY_SNAPSHOT, want: true},
		{name: "busy timeout", code: sqlite3.SQLITE_BUSY_TIMEOUT, want: true},
		{name: "locked", code: sqlite3.SQLITE_LOCKED, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isSQLiteBusy(sqliteCodeError{code: test.code}); got != test.want {
				t.Fatalf("isSQLiteBusy(code=%d) = %t, want %t", test.code, got, test.want)
			}
		})
	}
}

type sqliteCodeError struct {
	code int
}

func (err sqliteCodeError) Error() string {
	return "sqlite error"
}

func (err sqliteCodeError) Code() int {
	return err.code
}
