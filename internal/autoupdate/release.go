package autoupdate

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type releaseMetadata struct {
	TagName    string         `json:"tag_name"`
	Assets     []releaseAsset `json:"assets"`
	Draft      bool           `json:"draft"`
	Prerelease bool           `json:"prerelease"`
}

type releaseAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
}

type selectedAssets struct {
	archive           releaseAsset
	manifest          releaseAsset
	manifestSignature releaseAsset
}

func (manager *Manager) fetchRelease(ctx context.Context) (releaseMetadata, error) {
	content, err := manager.download(ctx, manager.config.ReleaseURL, manager.config.ReleaseMaxBytes)
	if err != nil {
		return releaseMetadata{}, fmt.Errorf("download latest release metadata: %w", err)
	}
	var release releaseMetadata
	if err := json.Unmarshal(content, &release); err != nil {
		return releaseMetadata{}, fmt.Errorf("%w: decode latest release: %v", ErrInvalidRelease, err)
	}
	if strings.TrimSpace(release.TagName) == "" {
		return releaseMetadata{}, fmt.Errorf("%w: release tag is empty", ErrInvalidRelease)
	}
	return release, nil
}

func (manager *Manager) download(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse download URL: %w", err)
	}
	if err := validateDownloadURL(parsed, manager.config.AllowLoopbackHTTP, manager.config.AllowedHTTPSHosts); err != nil {
		return nil, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, manager.config.DownloadTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create download request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "mitoriq-collector-autoupdate")
	response, err := manager.config.HTTPClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("send download request: %w", err)
	}
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("%w: empty HTTP response", ErrInvalidRelease)
	}
	defer response.Body.Close()
	if response.Request != nil {
		if err := validateDownloadURL(response.Request.URL, manager.config.AllowLoopbackHTTP, manager.config.AllowedHTTPSHosts); err != nil {
			return nil, err
		}
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d", ErrUnexpectedStatus, response.StatusCode)
	}
	if response.ContentLength > maxBytes {
		return nil, fmt.Errorf("%w: content length %d exceeds %d", ErrDownloadTooLarge, response.ContentLength, maxBytes)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read download response: %w", err)
	}
	if int64(len(content)) > maxBytes {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrDownloadTooLarge, maxBytes)
	}
	return content, nil
}

func selectAssets(assets []releaseAsset, config Config, releaseVersion string) (selectedAssets, error) {
	expectedArchiveName := config.BinaryName + "_" + releaseVersion + "_" + config.GOOS + "_" + config.GOARCH + ".tar.gz"
	var selected selectedAssets
	archiveCount := 0
	manifestCount := 0
	signatureCount := 0
	for _, asset := range assets {
		switch {
		case asset.Name == expectedArchiveName:
			selected.archive = asset
			archiveCount++
		case asset.Name == "checksums.txt":
			selected.manifest = asset
			manifestCount++
		case asset.Name == "checksums.txt.sig":
			selected.manifestSignature = asset
			signatureCount++
		}
	}
	if archiveCount != 1 || manifestCount != 1 || signatureCount != 1 {
		return selectedAssets{}, fmt.Errorf(
			"%w: archive=%d checksums=%d signature=%d",
			ErrAssetNotFound,
			archiveCount,
			manifestCount,
			signatureCount,
		)
	}
	return selected, nil
}

func verifyBlob(publicKey *ecdsa.PublicKey, content []byte, encodedSignature []byte) error {
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedSignature)))
	if err != nil {
		return fmt.Errorf("%w: decode base64 signature: %v", ErrInvalidSignature, err)
	}
	digest := sha256.Sum256(content)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return ErrInvalidSignature
	}
	return nil
}

func verifyBlobAny(publicKeys []*ecdsa.PublicKey, content []byte, encodedSignature []byte) error {
	for _, publicKey := range publicKeys {
		if verifyBlob(publicKey, content, encodedSignature) == nil {
			return nil
		}
	}

	return ErrInvalidSignature
}

var checksumLinePattern = regexp.MustCompile(`^([0-9a-fA-F]{64})[ \t]+\*?([^\r\n]+)$`)

func checksumForAsset(manifest []byte, assetName string) ([]byte, error) {
	var match []byte
	for _, line := range strings.Split(string(manifest), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := checksumLinePattern.FindStringSubmatch(line)
		if len(parts) != 3 {
			return nil, fmt.Errorf("%w: malformed checksum manifest", ErrInvalidRelease)
		}
		if parts[2] != assetName {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("%w: duplicate checksum for %s", ErrInvalidRelease, assetName)
		}
		decoded, err := hex.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("%w: decode checksum: %v", ErrInvalidRelease, err)
		}
		match = decoded
	}
	if match == nil {
		return nil, fmt.Errorf("%w: checksum for %s", ErrAssetNotFound, assetName)
	}
	return match, nil
}

func verifyChecksum(content []byte, expected []byte) error {
	actual := sha256.Sum256(content)
	if !equalBytes(actual[:], expected) {
		return ErrChecksumMismatch
	}
	return nil
}

func equalBytes(left []byte, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
