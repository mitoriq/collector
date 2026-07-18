package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitoriq/collector/internal/filelock"
)

const (
	launchdLifecycleLockDirectory = "Mitoriq"
	launchdLifecycleLockFileName  = "service-lifecycle.lock"
)

type launchdLifecycleLockError struct {
	cause error
}

func (err *launchdLifecycleLockError) Error() string {
	return fmt.Sprintf("lock launchd lifecycle: %v", err.cause)
}

func (err *launchdLifecycleLockError) Unwrap() error {
	return err.cause
}

func withLaunchdLifecycleLock(launchdPath string, operation func() error) error {
	lockPath := launchdLifecycleLockPath(launchdPath)
	if err := secureLaunchdLifecycleLockDirectory(filepath.Dir(lockPath)); err != nil {
		return &launchdLifecycleLockError{cause: err}
	}
	operationStarted := false
	err := filelock.With(lockPath, func() error {
		operationStarted = true

		return operation()
	})
	if err == nil || operationStarted {
		return err
	}

	return &launchdLifecycleLockError{cause: err}
}

func launchdLifecycleLockPath(launchdPath string) string {
	libraryDirectory := filepath.Dir(filepath.Dir(launchdPath))

	return filepath.Join(
		libraryDirectory,
		"Application Support",
		launchdLifecycleLockDirectory,
		launchdLifecycleLockFileName,
	)
}

func secureLaunchdLifecycleLockDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("create launchd lifecycle lock directory: %w", err)
		}
		info, err = os.Lstat(directory)
	}
	if err != nil {
		return fmt.Errorf("inspect launchd lifecycle lock directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("launchd lifecycle lock directory must not be a symlink")
	}
	if !info.IsDir() {
		return fmt.Errorf("launchd lifecycle lock directory is not a directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure launchd lifecycle lock directory: %w", err)
	}

	return nil
}
