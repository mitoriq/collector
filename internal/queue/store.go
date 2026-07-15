package queue

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mitoriq/collector/internal/contracts"
	_ "modernc.org/sqlite"
)

type KeyGenerator func() (string, error)

const busyTimeoutMilliseconds = 5000

type Options struct {
	KeyGenerator KeyGenerator
	Now          func() time.Time
}

type Store struct {
	db           *sql.DB
	keyGenerator KeyGenerator
	now          func() time.Time
}

type EnqueueResult struct {
	Event    contracts.AgentEvent
	Inserted bool
}

type Record struct {
	ID       int64
	Event    contracts.AgentEvent
	Attempts int
}

func Open(path string, options Options) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(context.Background(), fmt.Sprintf("PRAGMA busy_timeout = %d", busyTimeoutMilliseconds)); err != nil {
		_ = db.Close()
		return nil, err
	}

	store := &Store{
		db:           db,
		keyGenerator: options.KeyGenerator,
		now:          options.Now,
	}
	if store.keyGenerator == nil {
		store.keyGenerator = randomKey
	}
	if store.now == nil {
		store.now = func() time.Time {
			return time.Now().UTC()
		}
	}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (store *Store) Close() error {
	return store.db.Close()
}

func (store *Store) Enqueue(
	ctx context.Context,
	event contracts.AgentEvent,
) (EnqueueResult, error) {
	nextEvent := event
	if nextEvent.IdempotencyKey == "" {
		key, err := store.keyGenerator()
		if err != nil {
			return EnqueueResult{}, err
		}
		nextEvent.IdempotencyKey = key
	}

	payload, err := json.Marshal(nextEvent)
	if err != nil {
		return EnqueueResult{}, err
	}
	now := formatTime(store.now())
	result, err := store.db.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO queue_events
			(idempotency_key, payload, attempts, available_at, created_at)
			VALUES (?, ?, 0, ?, ?)`,
		nextEvent.IdempotencyKey,
		string(payload),
		now,
		now,
	)
	if err != nil {
		return EnqueueResult{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return EnqueueResult{}, err
	}

	return EnqueueResult{Event: nextEvent, Inserted: rows == 1}, nil
}

func (store *Store) Due(ctx context.Context, limit int, now time.Time) ([]Record, error) {
	if limit < 1 {
		limit = 1
	}
	rows, err := store.db.QueryContext(
		ctx,
		`SELECT id, payload, attempts
			FROM queue_events
			WHERE available_at <= ?
			ORDER BY id ASC
			LIMIT ?`,
		formatTime(now),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []Record
	for rows.Next() {
		var record Record
		var payload string
		if err := rows.Scan(&record.ID, &payload, &record.Attempts); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(payload), &record.Event); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

func (store *Store) MarkDelivered(ctx context.Context, ids []int64) error {
	for _, id := range ids {
		if _, err := store.db.ExecContext(ctx, `DELETE FROM queue_events WHERE id = ?`, id); err != nil {
			return err
		}
	}

	return nil
}

func (store *Store) MarkRetry(ctx context.Context, id int64, availableAt time.Time) error {
	_, err := store.db.ExecContext(
		ctx,
		`UPDATE queue_events
			SET attempts = attempts + 1, available_at = ?
			WHERE id = ?`,
		formatTime(availableAt),
		id,
	)

	return err
}

func (store *Store) Count(ctx context.Context) (int, error) {
	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM queue_events`).Scan(&count); err != nil {
		return 0, err
	}

	return count, nil
}

func (store *Store) migrate(ctx context.Context) error {
	_, err := store.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS queue_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			idempotency_key TEXT NOT NULL UNIQUE,
			payload TEXT NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0,
			available_at TEXT NOT NULL,
			created_at TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS queue_events_available_at_idx
			ON queue_events(available_at, id);
	`)

	return err
}

func randomKey() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return fmt.Sprintf("evt_%s", hex.EncodeToString(bytes)), nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
