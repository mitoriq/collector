//go:build !windows

package localaudit

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openAuditFile(path string) (*os.File, error) {
	return openAuditFileUnix(path, unix.O_APPEND|unix.O_CREAT|unix.O_WRONLY, 0o600)
}

func openAuditFileRead(path string) (*os.File, error) {
	return openAuditFileUnix(path, unix.O_RDONLY, 0)
}

func openAuditFileUnix(path string, flags int, mode uint32) (*os.File, error) {
	fileDescriptor, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if err != nil {
		return nil, fmt.Errorf("open collector audit log: %w", err)
	}
	file := os.NewFile(uintptr(fileDescriptor), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat collector audit log: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fileDescriptor, &stat); err != nil {
		file.Close()
		return nil, fmt.Errorf("inspect collector audit log: %w", err)
	}
	if !info.Mode().IsRegular() || stat.Nlink != 1 {
		file.Close()
		return nil, fmt.Errorf("collector audit log must be a single-link regular file")
	}
	if flags&unix.O_WRONLY != 0 {
		if err := file.Chmod(0o600); err != nil {
			file.Close()
			return nil, fmt.Errorf("secure collector audit log: %w", err)
		}
	}

	return file, nil
}
