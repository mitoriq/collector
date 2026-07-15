//go:build windows

package filelock

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func With(path string, fn func() error) error {
	return with(path, func(handle windows.Handle, overlapped *windows.Overlapped) error {
		return windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped)
	}, fn)
}

func WithContext(ctx context.Context, path string, fn func() error) error {
	if ctx.Done() == nil {
		return With(path, fn)
	}
	return with(path, func(handle windows.Handle, overlapped *windows.Overlapped) error {
		return acquire(ctx, handle, overlapped)
	}, fn)
}

func with(
	path string,
	lock func(windows.Handle, *windows.Overlapped) error,
	fn func() error,
) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("file lock must not be a symlink")
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat file lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open file lock: %w", err)
	}
	defer file.Close()
	var overlapped windows.Overlapped
	handle := windows.Handle(file.Fd())
	if err := lock(handle, &overlapped); err != nil {
		return fmt.Errorf("acquire file lock: %w", err)
	}
	defer windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat file lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("file lock is not a regular file")
	}

	return fn()
}

func acquire(ctx context.Context, handle windows.Handle, overlapped *windows.Overlapped) error {
	return acquireWithRetry(ctx, func() error {
		return windows.LockFileEx(
			handle,
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0,
			1,
			0,
			overlapped,
		)
	}, func(err error) bool {
		return errors.Is(err, windows.ERROR_LOCK_VIOLATION)
	})
}
