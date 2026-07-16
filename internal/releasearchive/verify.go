package releasearchive

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxArchiveUncompressedSize = int64(512 << 20)

var (
	archiveNamePattern = regexp.MustCompile(`^mitoriq-collector_((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)_(darwin|linux)_(amd64|arm64)\.tar\.gz$`)
	expectedTargets    = []string{"darwin_amd64", "darwin_arm64", "linux_amd64", "linux_arm64"}
	archiveSuffixes    = []string{".tar.gz", ".tar.xz", ".tar.zst", ".tgz", ".txz", ".tzst", ".zip", ".tar", ".gz", ".xz", ".zst"}
)

type archiveTarget struct {
	version string
	goos    string
	goarch  string
}

func VerifyDirectory(distDir string, thirdPartyEntries []string) error {
	directoryEntries, err := os.ReadDir(distDir)
	if err != nil {
		return fmt.Errorf("read release directory: %w", err)
	}

	foundTargets := make(map[string]struct{}, len(expectedTargets))
	releaseVersion := ""
	for _, directoryEntry := range directoryEntries {
		if directoryEntry.IsDir() || !hasArchiveSuffix(directoryEntry.Name()) {
			continue
		}

		target, err := classifyArchive(directoryEntry.Name())
		if err != nil {
			return err
		}
		if directoryEntry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("release archive must be a regular file: %s", directoryEntry.Name())
		}
		info, err := directoryEntry.Info()
		if err != nil {
			return fmt.Errorf("stat release archive %s: %w", directoryEntry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("release archive must be a regular file: %s", directoryEntry.Name())
		}
		if releaseVersion == "" {
			releaseVersion = target.version
		} else if target.version != releaseVersion {
			return fmt.Errorf("archive version mismatch: got %s, want %s", target.version, releaseVersion)
		}

		targetKey := target.goos + "_" + target.goarch
		if _, exists := foundTargets[targetKey]; exists {
			return fmt.Errorf("duplicate archive target: %s", targetKey)
		}
		if err := verifyArchive(filepath.Join(distDir, directoryEntry.Name()), expectedEntries(target.goos, thirdPartyEntries)); err != nil {
			return err
		}
		foundTargets[targetKey] = struct{}{}
	}

	for _, target := range expectedTargets {
		if _, exists := foundTargets[target]; !exists {
			return fmt.Errorf("missing archive target: %s", target)
		}
	}
	return nil
}

func CollectThirdPartyEntries(repoRoot string) ([]string, error) {
	licensesRoot := filepath.Join(repoRoot, "THIRD_PARTY_LICENSES")
	entries := make([]string, 0)
	err := filepath.WalkDir(licensesRoot, func(filePath string, directoryEntry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if directoryEntry.IsDir() {
			return nil
		}
		info, err := directoryEntry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("third-party license must be a regular file: %s", filePath)
		}
		relativePath, err := filepath.Rel(repoRoot, filePath)
		if err != nil {
			return err
		}
		entryName := filepath.ToSlash(relativePath)
		if err := validateEntryName(entryName); err != nil {
			return fmt.Errorf("invalid third-party license path %s: %w", entryName, err)
		}
		entries = append(entries, entryName)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("collect third-party licenses: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("no third-party license files found")
	}
	sort.Strings(entries)
	return entries, nil
}

func classifyArchive(name string) (archiveTarget, error) {
	if !strings.HasSuffix(name, ".tar.gz") {
		return archiveTarget{}, fmt.Errorf("unsupported archive format: %s", name)
	}
	matches := archiveNamePattern.FindStringSubmatch(name)
	if matches == nil {
		return archiveTarget{}, fmt.Errorf("unsupported release archive name: %s", name)
	}
	if err := validateSemanticVersion(matches[1]); err != nil {
		return archiveTarget{}, fmt.Errorf("invalid semantic version in release archive %s: %w", name, err)
	}
	return archiveTarget{version: matches[1], goos: matches[2], goarch: matches[3]}, nil
}

func validateSemanticVersion(version string) error {
	withoutBuild := strings.SplitN(version, "+", 2)[0]
	versionParts := strings.SplitN(withoutBuild, "-", 2)
	if len(versionParts) != 2 {
		return nil
	}
	for _, identifier := range strings.Split(versionParts[1], ".") {
		if len(identifier) > 1 && identifier[0] == '0' && isNumeric(identifier) {
			return fmt.Errorf("numeric prerelease identifier has a leading zero: %s", identifier)
		}
	}
	return nil
}

func isNumeric(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func hasArchiveSuffix(name string) bool {
	for _, suffix := range archiveSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func expectedEntries(goos string, thirdPartyEntries []string) map[string]struct{} {
	entries := []string{"LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "mitoriq-collector"}
	entries = append(entries, thirdPartyEntries...)
	if goos == "linux" {
		entries = append(entries, "mitoriq-collector.sig")
	}
	expected := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		expected[entry] = struct{}{}
	}
	return expected
}

func verifyArchive(archivePath string, expected map[string]struct{}) (resultErr error) {
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open release archive %s: %w", archivePath, err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, archiveFile.Close())
	}()

	gzipReader, err := gzip.NewReader(archiveFile)
	if err != nil {
		return fmt.Errorf("open gzip stream %s: %w", archivePath, err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, gzipReader.Close())
	}()

	seen := make(map[string]struct{}, len(expected))
	var totalSize int64
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read release archive %s: %w", archivePath, err)
		}
		if err := validateEntryName(header.Name); err != nil {
			return fmt.Errorf("invalid archive entry %q in %s: %w", header.Name, archivePath, err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return fmt.Errorf("archive entry %q in %s must be a regular file", header.Name, archivePath)
		}
		if header.Linkname != "" {
			return fmt.Errorf("regular archive entry %q in %s must not set a link target", header.Name, archivePath)
		}
		if header.Name == "mitoriq-collector" && header.Mode&0o100 == 0 {
			return fmt.Errorf("collector binary must be executable in %s", archivePath)
		}
		if _, exists := seen[header.Name]; exists {
			return fmt.Errorf("duplicate entry %q in %s", header.Name, archivePath)
		}
		if _, exists := expected[header.Name]; !exists {
			return fmt.Errorf("unexpected entry %q in %s", header.Name, archivePath)
		}
		if header.Size < 0 || header.Size > maxArchiveUncompressedSize-totalSize {
			return fmt.Errorf("archive %s exceeds the uncompressed size limit", archivePath)
		}
		totalSize += header.Size
		if _, err := io.Copy(io.Discard, tarReader); err != nil {
			return fmt.Errorf("read archive entry %q in %s: %w", header.Name, archivePath, err)
		}
		seen[header.Name] = struct{}{}
	}

	missing := make([]string, 0)
	for entry := range expected {
		if _, exists := seen[entry]; !exists {
			missing = append(missing, entry)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("archive %s missing entries: %s", archivePath, strings.Join(missing, ", "))
	}
	return nil
}

func validateEntryName(name string) error {
	if !utf8.ValidString(name) || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return errors.New("entry name contains invalid characters")
	}
	if name == "." || name == ".." || strings.HasPrefix(name, "../") || path.IsAbs(name) || path.Clean(name) != name || strings.Contains(name, `\`) {
		return errors.New("entry name uses an unsafe path")
	}
	return nil
}
