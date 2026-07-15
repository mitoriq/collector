//go:build !windows

package autoupdate

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func syncDirectory(path string) error {
	fileDescriptor, err := unix.Open(filepath.Clean(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open executable directory: %w", err)
	}
	defer unix.Close(fileDescriptor)
	if err := unix.Fsync(fileDescriptor); err != nil {
		return fmt.Errorf("sync executable directory: %w", err)
	}

	return nil
}
