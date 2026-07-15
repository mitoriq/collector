//go:build !windows

package localaudit_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mitoriq/collector/internal/localaudit"
)

func TestStoreRejectsSymlinkAuditPath(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "collector.jsonl")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	err := (localaudit.Store{Path: path}).Append(localaudit.Entry{
		Category: "events",
		Phase:    "attempted",
		Count:    1,
	})
	if err == nil {
		t.Fatal("expected symlink audit path to be rejected")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "original" {
		t.Fatalf("target = %q", body)
	}
}
