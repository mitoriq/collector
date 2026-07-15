package sessionkey

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

func Stable(sourceSessionID string, tool string, cwd string, startedAt time.Time) string {
	normalized := strings.Join([]string{
		strings.TrimSpace(sourceSessionID),
		strings.TrimSpace(tool),
		strings.TrimSpace(cwd),
		startedAt.UTC().Format(time.RFC3339Nano),
	}, "\x00")
	sum := sha256.Sum256([]byte(normalized))
	bytes := sum[:16]
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80

	return strings.Join([]string{
		hex.EncodeToString(bytes[0:4]),
		hex.EncodeToString(bytes[4:6]),
		hex.EncodeToString(bytes[6:8]),
		hex.EncodeToString(bytes[8:10]),
		hex.EncodeToString(bytes[10:16]),
	}, "-")
}
