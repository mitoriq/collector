package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

type launchdAtomicFileOps struct {
	createTemp func(directory string, pattern string) (*os.File, error)
	remove     func(path string) error
	rename     func(oldPath string, newPath string) error
	write      func(file *os.File, body []byte) error
}

func defaultLaunchdAtomicFileOps() launchdAtomicFileOps {
	return launchdAtomicFileOps{
		createTemp: os.CreateTemp,
		remove:     os.Remove,
		rename:     os.Rename,
		write: func(file *os.File, body []byte) error {
			written, err := file.Write(body)
			if err != nil {
				return err
			}
			if written != len(body) {
				return io.ErrShortWrite
			}

			return nil
		},
	}
}

func writeAtomicLaunchdPlist(path string, body string, mode os.FileMode) error {
	return writeAtomicLaunchdPlistWithOps(
		path,
		body,
		mode,
		defaultLaunchdAtomicFileOps(),
	)
}

func writeAtomicLaunchdPlistWithOps(
	path string,
	body string,
	mode os.FileMode,
	ops launchdAtomicFileOps,
) error {
	return writeAtomicLaunchdPlistBytesWithOps(path, []byte(body+"\n"), mode, ops)
}

func writeAtomicLaunchdPlistBytes(path string, body []byte, mode os.FileMode) error {
	return writeAtomicLaunchdPlistBytesWithOps(path, body, mode, defaultLaunchdAtomicFileOps())
}

func writeAtomicLaunchdPlistBytesWithOps(
	path string,
	body []byte,
	mode os.FileMode,
	ops launchdAtomicFileOps,
) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("launchd plist must not be a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat launchd plist before write: %w", err)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create LaunchAgents directory: %w", err)
	}
	temporary, err := ops.createTemp(directory, "."+launchdPlistName+"-*")
	if err != nil {
		return fmt.Errorf("create temporary launchd plist: %w", err)
	}
	temporaryPath := temporary.Name()
	shouldRemove := true
	defer func() {
		_ = temporary.Close()
		if shouldRemove {
			_ = ops.remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode.Perm()); err != nil {
		return fmt.Errorf("set launchd plist permissions: %w", err)
	}
	if err := ops.write(temporary, body); err != nil {
		return fmt.Errorf("write temporary launchd plist: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary launchd plist: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary launchd plist: %w", err)
	}
	if err := ops.rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace launchd plist: %w", err)
	}
	shouldRemove = false
	if runtime.GOOS != "windows" {
		directoryHandle, err := os.Open(directory)
		if err != nil {
			return fmt.Errorf("open LaunchAgents directory for sync: %w", err)
		}
		defer directoryHandle.Close()
		if err := directoryHandle.Sync(); err != nil {
			return fmt.Errorf("sync LaunchAgents directory: %w", err)
		}
	}

	return nil
}
