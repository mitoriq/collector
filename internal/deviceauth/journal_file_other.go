//go:build !darwin && !linux && !windows

package deviceauth

import "os"

func openJournalFile(path string) (*os.File, error) {
	return os.Open(path)
}
