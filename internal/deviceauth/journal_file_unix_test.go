//go:build darwin || linux

package deviceauth

import (
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestJournalRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := (JournalStore{Path: path}).Load()
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("FIFO journal was accepted")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("loading a FIFO journal blocked")
	}
}
