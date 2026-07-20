//go:build darwin || linux

package enroll

import (
	"os"

	"golang.org/x/sys/unix"
)

func openTokenFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "enrollment-token")
	if file == nil {
		_ = unix.Close(fd)
		return nil, unix.EBADF
	}
	return file, nil
}
