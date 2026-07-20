package releasearchive

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fixtureEntry struct {
	name     string
	typeflag byte
	linkname string
	mode     int64
}

var fixtureThirdPartyEntries = []string{
	"THIRD_PARTY_LICENSES/github.com/google/uuid/LICENSE",
	"THIRD_PARTY_LICENSES/modernc.org/libc/LICENSE-3RD-PARTY.md",
}

func TestVerifyDirectoryAcceptsExactRegularFileMatrix(t *testing.T) {
	t.Parallel()
	distDir := t.TempDir()
	writeValidMatrix(t, distDir)

	if err := VerifyDirectory(distDir, fixtureThirdPartyEntries); err != nil {
		t.Fatalf("VerifyDirectory() error = %v", err)
	}
}

func TestVerifyDirectoryRejectsUnsafeOrIncompleteArchives(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		mutate      func(t *testing.T, distDir string)
		errorDetail string
	}{
		{
			name: "symlink entry",
			mutate: func(t *testing.T, distDir string) {
				entries := replaceEntry(archiveEntries("darwin", "amd64"), "mitoriq-collector", fixtureEntry{
					name: "mitoriq-collector", typeflag: tar.TypeSymlink, linkname: "payload",
				})
				writeArchive(t, archivePath(distDir, "darwin", "amd64"), entries)
			},
			errorDetail: "must be a regular file",
		},
		{
			name: "hardlink entry",
			mutate: func(t *testing.T, distDir string) {
				entries := replaceEntry(archiveEntries("linux", "amd64"), "mitoriq-collector", fixtureEntry{
					name: "mitoriq-collector", typeflag: tar.TypeLink, linkname: "LICENSE",
				})
				writeArchive(t, archivePath(distDir, "linux", "amd64"), entries)
			},
			errorDetail: "must be a regular file",
		},
		{
			name: "character device entry",
			mutate: func(t *testing.T, distDir string) {
				entries := replaceEntry(archiveEntries("linux", "arm64"), "mitoriq-collector", fixtureEntry{
					name: "mitoriq-collector", typeflag: tar.TypeChar,
				})
				writeArchive(t, archivePath(distDir, "linux", "arm64"), entries)
			},
			errorDetail: "must be a regular file",
		},
		{
			name: "fifo entry",
			mutate: func(t *testing.T, distDir string) {
				entries := replaceEntry(archiveEntries("darwin", "arm64"), "mitoriq-collector", fixtureEntry{
					name: "mitoriq-collector", typeflag: tar.TypeFifo,
				})
				writeArchive(t, archivePath(distDir, "darwin", "arm64"), entries)
			},
			errorDetail: "must be a regular file",
		},
		{
			name: "newline in entry name",
			mutate: func(t *testing.T, distDir string) {
				entries := append(archiveEntries("darwin", "amd64"), fixtureEntry{name: "payload\nLICENSE", typeflag: tar.TypeReg})
				writeArchive(t, archivePath(distDir, "darwin", "amd64"), entries)
			},
			errorDetail: "invalid characters",
		},
		{
			name: "parent traversal entry",
			mutate: func(t *testing.T, distDir string) {
				entries := append(archiveEntries("linux", "amd64"), fixtureEntry{name: "../payload", typeflag: tar.TypeReg})
				writeArchive(t, archivePath(distDir, "linux", "amd64"), entries)
			},
			errorDetail: "unsafe path",
		},
		{
			name: "duplicate entry",
			mutate: func(t *testing.T, distDir string) {
				entries := append(archiveEntries("darwin", "arm64"), fixtureEntry{name: "LICENSE", typeflag: tar.TypeReg})
				writeArchive(t, archivePath(distDir, "darwin", "arm64"), entries)
			},
			errorDetail: "duplicate entry",
		},
		{
			name: "missing linux signature",
			mutate: func(t *testing.T, distDir string) {
				entries := removeEntry(archiveEntries("linux", "arm64"), "mitoriq-collector_linux_arm64.sig")
				writeArchive(t, archivePath(distDir, "linux", "arm64"), entries)
			},
			errorDetail: "missing entries: mitoriq-collector_linux_arm64.sig",
		},
		{
			name: "linux signature for another architecture",
			mutate: func(t *testing.T, distDir string) {
				entries := replaceEntry(
					archiveEntries("linux", "arm64"),
					"mitoriq-collector_linux_arm64.sig",
					fixtureEntry{name: "mitoriq-collector_linux_amd64.sig", typeflag: tar.TypeReg, mode: 0o644},
				)
				writeArchive(t, archivePath(distDir, "linux", "arm64"), entries)
			},
			errorDetail: "unexpected entry",
		},
		{
			name: "collector without owner execute bit",
			mutate: func(t *testing.T, distDir string) {
				entries := replaceEntry(archiveEntries("darwin", "arm64"), "mitoriq-collector", fixtureEntry{
					name: "mitoriq-collector", typeflag: tar.TypeReg, mode: 0o655,
				})
				writeArchive(t, archivePath(distDir, "darwin", "arm64"), entries)
			},
			errorDetail: "collector binary must be executable",
		},
		{
			name: "missing target archive",
			mutate: func(t *testing.T, distDir string) {
				if err := os.Remove(archivePath(distDir, "linux", "arm64")); err != nil {
					t.Fatalf("remove archive: %v", err)
				}
			},
			errorDetail: "missing archive target: linux_arm64",
		},
		{
			name: "mixed release versions",
			mutate: func(t *testing.T, distDir string) {
				if err := os.Remove(archivePath(distDir, "linux", "arm64")); err != nil {
					t.Fatalf("remove archive: %v", err)
				}
				writeArchive(t, archivePathForVersion(distDir, "0.0.2-next", "linux", "arm64"), archiveEntries("linux", "arm64"))
			},
			errorDetail: "archive version mismatch",
		},
		{
			name: "non-semver release version",
			mutate: func(t *testing.T, distDir string) {
				writeArchive(t, archivePathForVersion(distDir, "garbage", "linux", "arm64"), archiveEntries("linux", "arm64"))
			},
			errorDetail: "unsupported release archive name",
		},
		{
			name: "prerelease numeric identifier with leading zero",
			mutate: func(t *testing.T, distDir string) {
				writeArchive(t, archivePathForVersion(distDir, "1.2.3-01", "linux", "arm64"), archiveEntries("linux", "arm64"))
			},
			errorDetail: "invalid semantic version",
		},
		{
			name: "unexpected zip archive",
			mutate: func(t *testing.T, distDir string) {
				if err := os.WriteFile(filepath.Join(distDir, "payload.zip"), []byte("fixture"), 0o600); err != nil {
					t.Fatalf("write unexpected archive: %v", err)
				}
			},
			errorDetail: "unsupported archive format: payload.zip",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			distDir := t.TempDir()
			writeValidMatrix(t, distDir)
			test.mutate(t, distDir)

			err := VerifyDirectory(distDir, fixtureThirdPartyEntries)
			if err == nil {
				t.Fatal("VerifyDirectory() error = nil")
			}
			if !strings.Contains(err.Error(), test.errorDetail) {
				t.Fatalf("VerifyDirectory() error = %q, want detail %q", err, test.errorDetail)
			}
		})
	}
}

func TestCollectThirdPartyEntriesReturnsSortedRegularFiles(t *testing.T) {
	t.Parallel()
	repoRoot := t.TempDir()
	want := []string{
		"THIRD_PARTY_LICENSES/github.com/google/uuid/LICENSE",
		"THIRD_PARTY_LICENSES/modernc.org/libc/LICENSE-3RD-PARTY.md",
	}
	for _, entry := range []string{want[1], want[0]} {
		filePath := filepath.Join(repoRoot, filepath.FromSlash(entry))
		if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
			t.Fatalf("create license directory: %v", err)
		}
		if err := os.WriteFile(filePath, []byte("fixture\n"), 0o600); err != nil {
			t.Fatalf("write license: %v", err)
		}
	}

	got, err := CollectThirdPartyEntries(repoRoot)
	if err != nil {
		t.Fatalf("CollectThirdPartyEntries() error = %v", err)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("CollectThirdPartyEntries() = %v, want %v", got, want)
	}
}

func TestCollectThirdPartyEntriesRejectsEmptyInventory(t *testing.T) {
	t.Parallel()
	repoRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(repoRoot, "THIRD_PARTY_LICENSES"), 0o755); err != nil {
		t.Fatalf("create license root: %v", err)
	}

	_, err := CollectThirdPartyEntries(repoRoot)
	if err == nil {
		t.Fatal("CollectThirdPartyEntries() error = nil")
	}
	if !strings.Contains(err.Error(), "no third-party license files found") {
		t.Fatalf("CollectThirdPartyEntries() error = %q", err)
	}
}

func writeValidMatrix(t *testing.T, distDir string) {
	t.Helper()
	for _, target := range []struct {
		goos   string
		goarch string
	}{
		{goos: "darwin", goarch: "amd64"},
		{goos: "darwin", goarch: "arm64"},
		{goos: "linux", goarch: "amd64"},
		{goos: "linux", goarch: "arm64"},
	} {
		writeArchive(t, archivePath(distDir, target.goos, target.goarch), archiveEntries(target.goos, target.goarch))
	}
}

func archivePath(distDir string, goos string, goarch string) string {
	return archivePathForVersion(distDir, "0.0.1-next", goos, goarch)
}

func archivePathForVersion(distDir string, version string, goos string, goarch string) string {
	return filepath.Join(distDir, "mitoriq-collector_"+version+"_"+goos+"_"+goarch+".tar.gz")
}

func archiveEntries(goos string, goarch string) []fixtureEntry {
	names := []string{"LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"}
	names = append(names, fixtureThirdPartyEntries...)
	names = append(names, "mitoriq-collector")
	if goos == "linux" {
		names = append(names, "mitoriq-collector_linux_"+goarch+".sig")
	}

	entries := make([]fixtureEntry, 0, len(names))
	for _, name := range names {
		mode := int64(0o644)
		if name == "mitoriq-collector" {
			mode = 0o755
		}
		entries = append(entries, fixtureEntry{name: name, typeflag: tar.TypeReg, mode: mode})
	}
	return entries
}

func replaceEntry(entries []fixtureEntry, name string, replacement fixtureEntry) []fixtureEntry {
	result := make([]fixtureEntry, len(entries))
	copy(result, entries)
	for index, entry := range result {
		if entry.name == name {
			result[index] = replacement
		}
	}
	return result
}

func removeEntry(entries []fixtureEntry, name string) []fixtureEntry {
	result := make([]fixtureEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.name != name {
			result = append(result, entry)
		}
	}
	return result
}

func writeArchive(t *testing.T, archivePath string, entries []fixtureEntry) {
	t.Helper()
	archiveFile, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}

	gzipWriter := gzip.NewWriter(archiveFile)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		body := []byte("fixture\n")
		header := &tar.Header{
			Name:     entry.name,
			Mode:     entry.mode,
			Typeflag: entry.typeflag,
			Linkname: entry.linkname,
		}
		if entry.typeflag == tar.TypeReg || entry.typeflag == tar.TypeRegA {
			header.Size = int64(len(body))
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if header.Size > 0 {
			if _, err := tarWriter.Write(body); err != nil {
				t.Fatalf("write tar body: %v", err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	if err := archiveFile.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
}
