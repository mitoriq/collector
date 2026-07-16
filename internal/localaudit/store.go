package localaudit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mitoriq/collector/internal/filelock"
)

const (
	defaultMaxBytes  = 5 << 20
	defaultTailLimit = 100
)

var ErrNotFound = errors.New("collector audit log not found")

type Result struct {
	Accepted   int `json:"accepted"`
	Duplicated int `json:"duplicated"`
	Rejected   int `json:"rejected"`
}

type Entry struct {
	OccurredAt       string         `json:"occurredAt"`
	Category         string         `json:"category"`
	Phase            string         `json:"phase"`
	Count            int            `json:"count"`
	PrivacyLevels    map[string]int `json:"privacyLevels,omitempty"`
	EventTypes       map[string]int `json:"eventTypes,omitempty"`
	Sources          map[string]int `json:"sources,omitempty"`
	Result           *Result        `json:"result,omitempty"`
	FailureCode      string         `json:"failureCode,omitempty"`
	ReleaseKeySHA256 string         `json:"releaseKeySha256,omitempty"`
	Version          string         `json:"version,omitempty"`
}

type Store struct {
	Home     string
	MaxBytes int64
	Now      func() time.Time
	Path     string
}

func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

func (store Store) Append(entry Entry) error {
	return store.append(entry, filelock.With)
}

func (store Store) AppendContext(ctx context.Context, entry Entry) error {
	return store.append(entry, func(path string, fn func() error) error {
		return filelock.WithContext(ctx, path, fn)
	})
}

func (store Store) append(
	entry Entry,
	withLock func(string, func() error) error,
) error {
	if err := validateEntry(entry); err != nil {
		return err
	}
	if entry.OccurredAt == "" {
		entry.OccurredAt = store.now().UTC().Format(time.RFC3339Nano)
	}
	body, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal collector audit entry: %w", err)
	}
	body = append(body, '\n')
	maxBytes := store.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	if int64(len(body)) > maxBytes {
		return fmt.Errorf("collector audit entry exceeds log size limit")
	}

	path := store.ResolvedPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create collector audit directory: %w", err)
	}
	return withLock(path+".lock", func() error {
		if err := rotateIfNeeded(path, int64(len(body)), maxBytes); err != nil {
			return err
		}
		file, err := openAuditFile(path)
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err := file.Write(body); err != nil {
			return fmt.Errorf("append collector audit log: %w", err)
		}

		return file.Sync()
	})
}

func rotateIfNeeded(path string, appendBytes int64, maxBytes int64) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return fmt.Errorf("stat collector audit log: %w", err)
	}
	if info.Size()+appendBytes <= maxBytes {
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("collector audit log must be a regular file")
	}
	backupPath := path + ".1"
	if err := os.Remove(backupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove previous collector audit log: %w", err)
	}
	if err := os.Rename(path, backupPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("rotate collector audit log: %w", err)
	}

	return nil
}

func (store Store) Tail(limit int) ([]Entry, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("audit log limit must be positive")
	}
	path := store.ResolvedPath()
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}

		return nil, fmt.Errorf("stat collector audit log: %w", err)
	}
	var entries []Entry
	err := filelock.With(path+".lock", func() error {
		var readErr error
		entries, readErr = tailUnlocked(path, limit)
		return readErr
	})

	return entries, err
}

func tailUnlocked(path string, limit int) ([]Entry, error) {
	file, err := openAuditFileRead(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}

		return nil, fmt.Errorf("open collector audit log: %w", err)
	}
	defer file.Close()

	entries := make([]Entry, 0, min(limit, defaultTailLimit))
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("decode collector audit log: %w", err)
		}
		if len(entries) == limit {
			copy(entries, entries[1:])
			entries[len(entries)-1] = entry
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read collector audit log: %w", err)
	}

	return entries, nil
}

func (store Store) ResolvedPath() string {
	if store.Path != "" {
		return store.Path
	}
	if stateHome := os.Getenv("XDG_STATE_HOME"); stateHome != "" {
		return filepath.Join(stateHome, "mitoriq", "collector-audit.jsonl")
	}

	home := store.Home
	if home == "" {
		home = os.Getenv("HOME")
	}
	if home == "" {
		if userHome, err := os.UserHomeDir(); err == nil {
			home = userHome
		}
	}
	if home == "" {
		home = "."
	}

	return filepath.Join(home, ".local", "state", "mitoriq", "collector-audit.jsonl")
}

func (store Store) now() time.Time {
	if store.Now != nil {
		return store.Now()
	}

	return time.Now()
}

func validateEntry(entry Entry) error {
	if entry.Category != "events" && entry.Category != "usage" && entry.Category != "heartbeat" && entry.Category != "update" {
		return fmt.Errorf("invalid collector audit category: %q", entry.Category)
	}
	if entry.Phase != "attempted" && entry.Phase != "accepted" && entry.Phase != "failed" {
		return fmt.Errorf("invalid collector audit phase: %q", entry.Phase)
	}
	if entry.Count < 0 {
		return fmt.Errorf("collector audit count must not be negative")
	}

	return nil
}
