package autoupdate

import (
	"regexp"
	"strings"
)

type versionState uint8

const (
	versionInvalid versionState = iota
	versionStable
	versionPrerelease
)

type semanticVersion struct {
	canonical string
	major     string
	minor     string
	patch     string
}

var semanticVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func parseVersion(raw string) (semanticVersion, versionState) {
	normalized := strings.TrimSpace(raw)
	if strings.HasPrefix(normalized, "v") {
		normalized = strings.TrimPrefix(normalized, "v")
	}
	matches := semanticVersionPattern.FindStringSubmatch(normalized)
	if len(matches) != 5 {
		return semanticVersion{}, versionInvalid
	}
	version := semanticVersion{canonical: normalized, major: matches[1], minor: matches[2], patch: matches[3]}
	if matches[4] != "" {
		return version, versionPrerelease
	}
	return version, versionStable
}

func compareVersions(left semanticVersion, right semanticVersion) int {
	for _, pair := range [][2]string{{left.major, right.major}, {left.minor, right.minor}, {left.patch, right.patch}} {
		if comparison := compareNumericIdentifier(pair[0], pair[1]); comparison != 0 {
			return comparison
		}
	}
	return 0
}

func compareNumericIdentifier(left string, right string) int {
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return strings.Compare(left, right)
}
