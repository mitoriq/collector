package queue

import (
	"context"
	"database/sql"
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

func TestOpenConfiguresConcurrentWritePragmas(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "queue.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var busyTimeout int
	if err := store.db.QueryRowContext(context.Background(), `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatal(err)
	}
	if busyTimeout != int(sqliteBusyTimeout/time.Millisecond) {
		t.Fatalf("busy timeout = %d, want %d", busyTimeout, sqliteBusyTimeout/time.Millisecond)
	}

	var journalMode string
	if err := store.db.QueryRowContext(context.Background(), `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal mode = %q, want wal", journalMode)
	}
}

func TestOpenCanSkipJournalModeConfiguration(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "queue.db"), Options{
		SkipJournalModeConfiguration: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var busyTimeout int
	if err := store.db.QueryRowContext(context.Background(), `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatal(err)
	}
	if busyTimeout != int(sqliteBusyTimeout/time.Millisecond) {
		t.Fatalf("busy timeout = %d, want %d", busyTimeout, sqliteBusyTimeout/time.Millisecond)
	}

	var journalMode string
	if err := store.db.QueryRowContext(context.Background(), `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "delete" {
		t.Fatalf("journal mode = %q, want delete", journalMode)
	}

	event := contracts.AgentEvent{IdempotencyKey: "hook-fallback"}
	if _, err := store.Enqueue(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	records, err := store.Due(context.Background(), 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Event.IdempotencyKey != event.IdempotencyKey {
		t.Fatalf("queued records = %#v, want hook fallback event", records)
	}
}

func TestOpenSkippingJournalModePreservesExistingWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	normalStore, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer normalStore.Close()

	hookStore, err := Open(path, Options{
		SkipJournalModeConfiguration: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hookStore.Close()

	var journalMode string
	if err := hookStore.db.QueryRowContext(context.Background(), `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal mode = %q, want wal", journalMode)
	}

	event := contracts.AgentEvent{IdempotencyKey: "existing-wal"}
	if _, err := hookStore.Enqueue(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	records, err := normalStore.Due(context.Background(), 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Event.IdempotencyKey != event.IdempotencyKey {
		t.Fatalf("queued records = %#v, want existing WAL event", records)
	}
}

func TestOpenMigratesToWALAfterConcurrentDeleteJournalWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	seedStore, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := seedStore.Close(); err != nil {
		t.Fatal(err)
	}

	lockDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer lockDB.Close()
	var journalMode string
	if err := lockDB.QueryRowContext(context.Background(), `PRAGMA journal_mode = DELETE`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "delete" {
		t.Fatalf("journal mode = %q, want delete", journalMode)
	}
	transaction, err := lockDB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := formatTime(time.Now())
	if _, err := transaction.ExecContext(context.Background(), `INSERT INTO queue_events
		(idempotency_key, payload, attempts, available_at, created_at)
		VALUES (?, ?, 0, ?, ?)`, "held-key", "{}", now, now); err != nil {
		t.Fatal(err)
	}
	commitResult := make(chan error, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		commitResult <- transaction.Commit()
	}()

	store, openErr := Open(path, Options{})
	if commitErr := <-commitResult; commitErr != nil {
		t.Fatal(commitErr)
	}
	if openErr != nil {
		t.Fatalf("open while delete journal writer commits: %v", openErr)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopenedStore, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedStore.Close()
	if err := reopenedStore.db.QueryRowContext(context.Background(), `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal mode = %q, want wal", journalMode)
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

func TestIsSQLiteBusyRecognizesDriverMessageWithoutCode(t *testing.T) {
	err := errors.New("database is locked (5) (SQLITE_BUSY)")
	if !isSQLiteBusy(err) {
		t.Fatalf("isSQLiteBusy(%q) = false, want true", err)
	}
	if isSQLiteBusy(nil) {
		t.Fatal("isSQLiteBusy(nil) = true, want false")
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
