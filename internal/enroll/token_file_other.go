//go:build !darwin && !linux

package enroll

import "os"

func openTokenFile(path string) (*os.File, error) {
	return os.Open(path)
}
