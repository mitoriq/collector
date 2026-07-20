//go:build darwin || linux

package enroll

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type tokenLoadResult struct {
	token string
	err   error
}

func loadTokenWithTimeout(t *testing.T, store TokenStore, unblock func()) tokenLoadResult {
	t.Helper()
	result := make(chan tokenLoadResult, 1)
	go func() {
		token, err := store.Load(context.Background())
		result <- tokenLoadResult{token: token, err: err}
	}()
	select {
	case loaded := <-result:
		return loaded
	case <-time.After(500 * time.Millisecond):
		if unblock != nil {
			unblock()
		}
		select {
		case <-result:
		case <-time.After(time.Second):
		}
		t.Fatal("loading an insecure token file blocked")
		return tokenLoadResult{}
	}
}

func createTokenFIFO(t *testing.T, path string) {
	t.Helper()
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func unblockTokenFIFO(path string) func() {
	return func() {
		file, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0)
		if err == nil {
			_ = file.Close()
		}
	}
}

func TestLoadEnrollmentTokenRejectsSymlinkToFIFOBeforeOpen(t *testing.T) {
	home := t.TempDir()
	tokenPath := filepath.Join(home, ".config", "mitoriq", "enrollment-token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatal(err)
	}
	fifoPath := filepath.Join(home, "token-fifo")
	createTokenFIFO(t, fifoPath)
	if err := os.Symlink(fifoPath, tokenPath); err != nil {
		t.Fatal(err)
	}
	var openAttempted atomic.Bool
	loaded := loadTokenWithTimeout(t, TokenStore{
		GOOS: "linux",
		Home: home,
		beforeTokenFileOpen: func() {
			openAttempted.Store(true)
		},
	}, unblockTokenFIFO(tokenPath))
	if loaded.err == nil {
		t.Fatalf("symlink to FIFO returned token %q", loaded.token)
	}
	if openAttempted.Load() {
		t.Fatal("symlink to FIFO reached the open step")
	}
	if strings.Contains(loaded.err.Error(), home) {
		t.Fatalf("error leaked token path: %q", loaded.err)
	}
}

func TestLoadEnrollmentTokenDoesNotBlockWhenPathIsSwappedToFIFO(t *testing.T) {
	for _, test := range []struct {
		name        string
		replacement func(t *testing.T, home string) string
	}{
		{
			name: "direct FIFO",
			replacement: func(t *testing.T, home string) string {
				t.Helper()
				fifoPath := filepath.Join(home, "replacement-fifo")
				createTokenFIFO(t, fifoPath)
				return fifoPath
			},
		},
		{
			name: "symlink to FIFO",
			replacement: func(t *testing.T, home string) string {
				t.Helper()
				fifoPath := filepath.Join(home, "replacement-fifo")
				createTokenFIFO(t, fifoPath)
				symlinkPath := filepath.Join(home, "replacement-symlink")
				if err := os.Symlink(fifoPath, symlinkPath); err != nil {
					t.Fatal(err)
				}
				return symlinkPath
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			tokenPath := filepath.Join(home, ".config", "mitoriq", "enrollment-token")
			if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tokenPath, []byte("mtq_e_original_secret\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			replacementPath := test.replacement(t, home)
			var swapErr error
			store := TokenStore{
				GOOS: "linux",
				Home: home,
				beforeTokenFileOpen: func() {
					swapErr = os.Rename(replacementPath, tokenPath)
				},
			}

			loaded := loadTokenWithTimeout(t, store, unblockTokenFIFO(tokenPath))
			if swapErr != nil {
				t.Fatal(swapErr)
			}
			if loaded.err == nil {
				t.Fatalf("swapped FIFO returned token %q", loaded.token)
			}
			if errors.Is(loaded.err, context.DeadlineExceeded) || strings.Contains(loaded.err.Error(), home) || strings.Contains(loaded.err.Error(), "original_secret") {
				t.Fatalf("unsafe token load error: %q", loaded.err)
			}
		})
	}
}
