//go:build windows

package localaudit

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func openAuditFile(path string) (*os.File, error) {
	return openAuditFileWindows(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
}

func openAuditFileRead(path string) (*os.File, error) {
	return openAuditFileWindows(path, os.O_RDONLY, 0)
}

func openAuditFileWindows(path string, flags int, mode os.FileMode) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("collector audit log must not be a symlink")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat collector audit log: %w", err)
	}
	file, err := os.OpenFile(path, flags, mode)
	if err != nil {
		return nil, fmt.Errorf("open collector audit log: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat collector audit log: %w", err)
	}
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &handleInfo); err != nil {
		file.Close()
		return nil, fmt.Errorf("inspect collector audit log: %w", err)
	}
	if !info.Mode().IsRegular() || handleInfo.NumberOfLinks != 1 {
		file.Close()
		return nil, fmt.Errorf("collector audit log must be a single-link regular file")
	}

	return file, nil
}
