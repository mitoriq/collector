//go:build !windows

package filelock

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func With(path string, fn func() error) error {
	return with(path, func(fileDescriptor int) error {
		return unix.Flock(fileDescriptor, unix.LOCK_EX)
	}, fn)
}

func WithContext(ctx context.Context, path string, fn func() error) error {
	if ctx.Done() == nil {
		return With(path, fn)
	}
	return with(path, func(fileDescriptor int) error {
		return acquire(ctx, fileDescriptor)
	}, fn)
}

func with(path string, lock func(int) error, fn func() error) error {
	fileDescriptor, err := unix.Open(
		path,
		unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("open file lock: %w", err)
	}
	file := os.NewFile(uintptr(fileDescriptor), path)
	defer file.Close()
	if err := lock(fileDescriptor); err != nil {
		return fmt.Errorf("acquire file lock: %w", err)
	}
	defer unix.Flock(fileDescriptor, unix.LOCK_UN)
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure file lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat file lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("file lock is not a regular file")
	}

	return fn()
}

func acquire(ctx context.Context, fileDescriptor int) error {
	return acquireWithRetry(ctx, func() error {
		return unix.Flock(fileDescriptor, unix.LOCK_EX|unix.LOCK_NB)
	}, func(err error) bool {
		return errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN)
	})
}
