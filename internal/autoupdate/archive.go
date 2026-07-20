package autoupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

type extractedRelease struct {
	binary    []byte
	signature []byte
}

func extractReleaseArchive(archive []byte, config Config) (extractedRelease, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return extractedRelease{}, fmt.Errorf("%w: open gzip stream: %v", ErrUnsafeArchive, err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	var result extractedRelease
	var expandedSize int64
	foundBinary := false
	foundSignature := false
	signatureName := binarySignatureName(config)
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return extractedRelease{}, fmt.Errorf("%w: read tar header: %v", ErrUnsafeArchive, nextErr)
		}
		if err := validateArchiveHeader(header, config, expandedSize); err != nil {
			return extractedRelease{}, err
		}
		expandedSize += header.Size
		switch header.Name {
		case config.BinaryName:
			if foundBinary {
				return extractedRelease{}, fmt.Errorf("%w: duplicate binary", ErrUnsafeArchive)
			}
			content, readErr := readTarFile(tarReader, header.Size, config.BinaryMaxBytes)
			if readErr != nil {
				return extractedRelease{}, readErr
			}
			result.binary = content
			foundBinary = true
		case signatureName:
			if foundSignature {
				return extractedRelease{}, fmt.Errorf("%w: duplicate binary signature", ErrUnsafeArchive)
			}
			content, readErr := readTarFile(tarReader, header.Size, config.SignatureMaxBytes)
			if readErr != nil {
				return extractedRelease{}, readErr
			}
			result.signature = content
			foundSignature = true
		}
	}
	if !foundBinary || len(result.binary) == 0 {
		return extractedRelease{}, fmt.Errorf("%w: binary missing", ErrAssetNotFound)
	}
	if config.GOOS == "linux" && (!foundSignature || len(result.signature) == 0) {
		return extractedRelease{}, fmt.Errorf("%w: Linux binary signature missing", ErrAssetNotFound)
	}
	return result, nil
}

func validateArchiveHeader(header *tar.Header, config Config, expandedSize int64) error {
	if header == nil || header.Name == "" || header.Size < 0 {
		return fmt.Errorf("%w: invalid tar header", ErrUnsafeArchive)
	}
	cleanName := path.Clean(header.Name)
	if strings.Contains(header.Name, "\\") || path.IsAbs(header.Name) || cleanName != header.Name || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
		return fmt.Errorf("%w: unsafe path %q", ErrUnsafeArchive, header.Name)
	}
	if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir {
		return fmt.Errorf("%w: unsupported entry type for %q", ErrUnsafeArchive, header.Name)
	}
	if header.Typeflag == tar.TypeDir && header.Size != 0 {
		return fmt.Errorf("%w: directory has content", ErrUnsafeArchive)
	}
	if header.Size > config.ExpandedArchiveMaxBytes-expandedSize {
		return fmt.Errorf("%w: expanded archive exceeds %d bytes", ErrDownloadTooLarge, config.ExpandedArchiveMaxBytes)
	}
	if header.Name == config.BinaryName && header.Size > config.BinaryMaxBytes {
		return fmt.Errorf("%w: binary exceeds %d bytes", ErrDownloadTooLarge, config.BinaryMaxBytes)
	}
	if header.Name == binarySignatureName(config) && header.Size > config.SignatureMaxBytes {
		return fmt.Errorf("%w: binary signature exceeds %d bytes", ErrDownloadTooLarge, config.SignatureMaxBytes)
	}
	return nil
}

func binarySignatureName(config Config) string {
	return fmt.Sprintf("%s_%s_%s.sig", config.BinaryName, config.GOOS, config.GOARCH)
}

func readTarFile(reader io.Reader, declaredSize int64, maxBytes int64) ([]byte, error) {
	if declaredSize > maxBytes {
		return nil, fmt.Errorf("%w: archive entry exceeds %d bytes", ErrDownloadTooLarge, maxBytes)
	}
	content, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read archive entry: %v", ErrUnsafeArchive, err)
	}
	if int64(len(content)) != declaredSize || int64(len(content)) > maxBytes {
		return nil, fmt.Errorf("%w: archive entry size mismatch", ErrUnsafeArchive)
	}
	return content, nil
}
