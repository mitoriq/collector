package localaudit_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/filelock"
	"github.com/mitoriq/collector/internal/localaudit"
)

func TestStoreAppendAndTailKeepMetadataOnlyJSONLAt0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "collector.jsonl")
	store := localaudit.Store{
		Path: path,
		Now: func() time.Time {
			return time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
		},
	}

	for _, entry := range []localaudit.Entry{
		{
			Category:      "events",
			Phase:         "attempted",
			Count:         2,
			PrivacyLevels: map[string]int{"L1": 1, "L2": 1},
			EventTypes:    map[string]int{"session.started": 1, "tool.completed": 1},
			Sources:       map[string]int{"codex": 2},
		},
		{
			Category: "events",
			Phase:    "accepted",
			Count:    2,
			Result:   &localaudit.Result{Accepted: 2},
		},
	} {
		if err := store.Append(entry); err != nil {
			t.Fatal(err)
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}

	entries, err := store.Tail(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Phase != "accepted" || entries[0].OccurredAt != "2026-07-10T00:00:00Z" {
		t.Fatalf("entries = %#v", entries)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"prompt", "source code", "mtq_e_"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("audit log contains %q: %s", forbidden, body)
		}
	}
}

func TestStoreTailRejectsInvalidLimit(t *testing.T) {
	_, err := (localaudit.Store{Path: filepath.Join(t.TempDir(), "audit.jsonl")}).Tail(0)
	if err == nil {
		t.Fatal("expected invalid limit error")
	}
}

func TestStoreRotatesOneGenerationAtConfiguredLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector.jsonl")
	store := localaudit.Store{Path: path, MaxBytes: 180}
	entry := localaudit.Entry{
		Category:      "events",
		Phase:         "attempted",
		Count:         1,
		PrivacyLevels: map[string]int{"L2": 1},
		EventTypes:    map[string]int{"tool.completed": 1},
	}
	if err := store.Append(entry); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(entry); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotated log missing: %v", err)
	}
	entries, err := store.Tail(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("current entries = %d, want 1", len(entries))
	}
}

func TestStoreAppendContextStopsWaitingWhenContextCanceled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector.jsonl")
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
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := (localaudit.Store{Path: path}).AppendContext(ctx, localaudit.Entry{
		Category: "events",
		Phase:    "attempted",
		Count:    1,
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
