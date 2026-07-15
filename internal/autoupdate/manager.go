package autoupdate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mitoriq/collector/internal/filelock"
)

const (
	defaultBinaryName        = "mitoriq-collector"
	defaultDownloadTimeout   = 30 * time.Second
	defaultValidationTimeout = 15 * time.Second
	defaultReleaseMaxBytes   = 1 << 20
	defaultManifestMaxBytes  = 4 << 20
	defaultSignatureMaxBytes = 16 << 10
	defaultArchiveMaxBytes   = 128 << 20
	defaultExpandedMaxBytes  = 256 << 20
	defaultBinaryMaxBytes    = 128 << 20
)

var (
	ErrAssetNotFound    = errors.New("required release asset not found")
	ErrChecksumMismatch = errors.New("archive checksum mismatch")
	ErrDownloadTooLarge = errors.New("download exceeds size limit")
	ErrInsecureURL      = errors.New("release URL must use HTTPS")
	ErrInvalidRelease   = errors.New("invalid release metadata")
	ErrInvalidSignature = errors.New("invalid release signature")
	ErrRollbackFailed   = errors.New("update rollback failed")
	ErrUnexpectedStatus = errors.New("unexpected HTTP response status")
	ErrUnsafeArchive    = errors.New("unsafe release archive")
)

type NoUpdateReason string

const (
	NoUpdateCurrentVersionNotStable NoUpdateReason = "current_version_not_stable"
	NoUpdateReleaseIsDraft          NoUpdateReason = "release_is_draft"
	NoUpdateReleaseVersionInvalid   NoUpdateReason = "release_version_invalid"
	NoUpdateReleaseIsPrerelease     NoUpdateReason = "release_is_prerelease"
	NoUpdateReleaseNotNewer         NoUpdateReason = "release_not_newer"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Validator interface {
	Validate(context.Context, string) error
}

type ValidatorFunc func(context.Context, string) error

func (validator ValidatorFunc) Validate(ctx context.Context, path string) error {
	return validator(ctx, path)
}

type Config struct {
	ReleaseURL              string
	PublicKeyPEM            []byte
	AdditionalPublicKeysPEM [][]byte
	CurrentVersion          string
	ExecutablePath          string
	BinaryName              string
	GOOS                    string
	GOARCH                  string
	MacOSTeamID             string
	AllowedHTTPSHosts       []string
	HTTPClient              HTTPClient
	Validator               Validator
	AllowLoopbackHTTP       bool
	DownloadTimeout         time.Duration
	ValidationTimeout       time.Duration
	ReleaseMaxBytes         int64
	ManifestMaxBytes        int64
	SignatureMaxBytes       int64
	ArchiveMaxBytes         int64
	ExpandedArchiveMaxBytes int64
	BinaryMaxBytes          int64
}

type Result struct {
	Updated        bool
	RolledBack     bool
	TagName        string
	ArchiveName    string
	BackupPath     string
	NoUpdateReason NoUpdateReason
}

type Manager struct {
	config     Config
	publicKeys []*ecdsa.PublicKey
	mu         sync.Mutex
}

func New(config Config) (*Manager, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	publicKey, err := parsePublicKey(normalized.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	if normalized.HTTPClient == nil {
		normalized.HTTPClient = defaultHTTPClient(normalized)
	}
	if normalized.Validator == nil {
		normalized.Validator = commandValidator{}
	}

	publicKeys := []*ecdsa.PublicKey{publicKey}
	for _, encoded := range normalized.AdditionalPublicKeysPEM {
		additionalKey, err := parsePublicKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("parse additional release public key: %w", err)
		}
		if samePublicKey(publicKey, additionalKey) {
			return nil, fmt.Errorf("additional release public key duplicates current key")
		}
		publicKeys = append(publicKeys, additionalKey)
	}

	return &Manager{config: normalized, publicKeys: publicKeys}, nil
}

func (manager *Manager) Update(ctx context.Context) (Result, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	var result Result
	err := filelock.With(manager.config.ExecutablePath+".update.lock", func() error {
		var updateErr error
		result, updateErr = manager.updateLocked(ctx)
		return updateErr
	})

	return result, err
}

func (manager *Manager) updateLocked(ctx context.Context) (Result, error) {

	currentVersion, currentState := parseVersion(manager.config.CurrentVersion)
	if currentState != versionStable {
		return Result{NoUpdateReason: NoUpdateCurrentVersionNotStable}, nil
	}

	release, err := manager.fetchRelease(ctx)
	if err != nil {
		return Result{}, err
	}
	result := Result{TagName: release.TagName}
	releaseVersion, releaseState := parseVersion(release.TagName)
	if release.Draft {
		result.NoUpdateReason = NoUpdateReleaseIsDraft
		return result, nil
	}
	if release.Prerelease {
		result.NoUpdateReason = NoUpdateReleaseIsPrerelease
		return result, nil
	}
	switch releaseState {
	case versionPrerelease:
		result.NoUpdateReason = NoUpdateReleaseIsPrerelease
		return result, nil
	case versionInvalid:
		result.NoUpdateReason = NoUpdateReleaseVersionInvalid
		return result, nil
	}
	if compareVersions(releaseVersion, currentVersion) <= 0 {
		result.NoUpdateReason = NoUpdateReleaseNotNewer
		return result, nil
	}

	assets, err := selectAssets(release.Assets, manager.config, releaseVersion.canonical)
	if err != nil {
		return result, err
	}
	result.ArchiveName = assets.archive.Name
	manifest, err := manager.download(ctx, assets.manifest.DownloadURL, manager.config.ManifestMaxBytes)
	if err != nil {
		return result, fmt.Errorf("download checksum manifest: %w", err)
	}
	manifestSignature, err := manager.download(ctx, assets.manifestSignature.DownloadURL, manager.config.SignatureMaxBytes)
	if err != nil {
		return result, fmt.Errorf("download checksum signature: %w", err)
	}
	if err := verifyBlobAny(manager.publicKeys, manifest, manifestSignature); err != nil {
		return result, fmt.Errorf("verify checksum manifest: %w", err)
	}
	expectedChecksum, err := checksumForAsset(manifest, assets.archive.Name)
	if err != nil {
		return result, err
	}
	archive, err := manager.download(ctx, assets.archive.DownloadURL, manager.config.ArchiveMaxBytes)
	if err != nil {
		return result, fmt.Errorf("download release archive: %w", err)
	}
	if err := verifyChecksum(archive, expectedChecksum); err != nil {
		return result, err
	}
	extracted, err := extractReleaseArchive(archive, manager.config)
	if err != nil {
		return result, err
	}
	if manager.config.GOOS == "linux" {
		if err := verifyBlobAny(manager.publicKeys, extracted.binary, extracted.signature); err != nil {
			return result, fmt.Errorf("verify collector binary: %w", err)
		}
	}

	validator := manager.config.Validator
	if _, usesDefaultValidator := validator.(commandValidator); usesDefaultValidator {
		if manager.config.GOOS == "darwin" && strings.TrimSpace(manager.config.MacOSTeamID) == "" {
			return result, fmt.Errorf("macOS release Team ID is required")
		}
		validator = releaseCommandValidator{
			expectedVersion:        releaseVersion.canonical,
			goos:                   manager.config.GOOS,
			macOSTeamID:            manager.config.MacOSTeamID,
			trustedKeyFingerprints: publicKeyFingerprints(manager.publicKeys),
		}
	}
	replaceResult, err := manager.replace(ctx, extracted, validator)
	result.Updated = replaceResult.updated
	result.RolledBack = replaceResult.rolledBack
	result.BackupPath = replaceResult.backupPath
	return result, err
}

func normalizeConfig(config Config) (Config, error) {
	normalized := config
	normalized.PublicKeyPEM = append([]byte(nil), config.PublicKeyPEM...)
	normalized.AdditionalPublicKeysPEM = make([][]byte, 0, len(config.AdditionalPublicKeysPEM))
	for _, key := range config.AdditionalPublicKeysPEM {
		normalized.AdditionalPublicKeysPEM = append(normalized.AdditionalPublicKeysPEM, append([]byte(nil), key...))
	}
	if strings.TrimSpace(normalized.ReleaseURL) == "" {
		return Config{}, fmt.Errorf("release URL is required")
	}
	if len(normalized.PublicKeyPEM) == 0 {
		return Config{}, fmt.Errorf("release public key is required")
	}
	if normalized.ExecutablePath == "" {
		path, err := os.Executable()
		if err != nil {
			return Config{}, fmt.Errorf("resolve current executable: %w", err)
		}
		normalized.ExecutablePath = path
	}
	if normalized.BinaryName == "" {
		normalized.BinaryName = defaultBinaryName
	}
	if normalized.GOOS == "" {
		normalized.GOOS = runtime.GOOS
	}
	if normalized.GOOS != "darwin" && normalized.GOOS != "linux" {
		return Config{}, fmt.Errorf("unsupported update platform: %s", normalized.GOOS)
	}
	if normalized.GOARCH == "" {
		normalized.GOARCH = runtime.GOARCH
	}
	normalized.AllowedHTTPSHosts = normalizeAllowedHosts(normalized.ReleaseURL, config.AllowedHTTPSHosts)
	setConfigDefaults(&normalized)
	return normalized, nil
}

func setConfigDefaults(config *Config) {
	if config.DownloadTimeout <= 0 {
		config.DownloadTimeout = defaultDownloadTimeout
	}
	if config.ValidationTimeout <= 0 {
		config.ValidationTimeout = defaultValidationTimeout
	}
	if config.ReleaseMaxBytes <= 0 {
		config.ReleaseMaxBytes = defaultReleaseMaxBytes
	}
	if config.ManifestMaxBytes <= 0 {
		config.ManifestMaxBytes = defaultManifestMaxBytes
	}
	if config.SignatureMaxBytes <= 0 {
		config.SignatureMaxBytes = defaultSignatureMaxBytes
	}
	if config.ArchiveMaxBytes <= 0 {
		config.ArchiveMaxBytes = defaultArchiveMaxBytes
	}
	if config.ExpandedArchiveMaxBytes <= 0 {
		config.ExpandedArchiveMaxBytes = defaultExpandedMaxBytes
	}
	if config.BinaryMaxBytes <= 0 {
		config.BinaryMaxBytes = defaultBinaryMaxBytes
	}
}

func parsePublicKey(content []byte) (*ecdsa.PublicKey, error) {
	block, remainder := pem.Decode(content)
	if block == nil || len(strings.TrimSpace(string(remainder))) != 0 {
		return nil, fmt.Errorf("parse release public key PEM: invalid PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse release public key: %w", err)
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve == nil || publicKey.Curve.Params().Name != elliptic.P256().Params().Name {
		return nil, fmt.Errorf("release public key must be ECDSA P-256")
	}
	return publicKey, nil
}

func samePublicKey(left *ecdsa.PublicKey, right *ecdsa.PublicKey) bool {
	return left != nil && right != nil && left.X.Cmp(right.X) == 0 && left.Y.Cmp(right.Y) == 0
}

func defaultHTTPClient(config Config) *http.Client {
	return &http.Client{
		Timeout: config.DownloadTimeout,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			return validateDownloadURL(request.URL, config.AllowLoopbackHTTP, config.AllowedHTTPSHosts)
		},
	}
}

func normalizeAllowedHosts(releaseURL string, configured []string) []string {
	if len(configured) > 0 {
		hosts := make([]string, 0, len(configured))
		for _, host := range configured {
			trimmed := strings.ToLower(strings.TrimSpace(host))
			if trimmed != "" {
				hosts = append(hosts, trimmed)
			}
		}

		return hosts
	}
	parsed, err := url.Parse(releaseURL)
	if err != nil || parsed.Hostname() == "" {
		return nil
	}

	return []string{strings.ToLower(parsed.Hostname())}
}

func validateDownloadURL(parsed *url.URL, allowLoopbackHTTP bool, allowedHTTPSHosts []string) error {
	if parsed == nil || parsed.Hostname() == "" || parsed.User != nil {
		return fmt.Errorf("%w: invalid URL", ErrInsecureURL)
	}
	if parsed.Scheme == "https" {
		for _, host := range allowedHTTPSHosts {
			if strings.EqualFold(parsed.Hostname(), host) {
				return nil
			}
		}

		return fmt.Errorf("%w: HTTPS host is not allowlisted", ErrInsecureURL)
	}
	if parsed.Scheme == "http" && allowLoopbackHTTP && isLoopbackHost(parsed.Hostname()) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInsecureURL, parsed.Redacted())
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

type commandValidator struct{}

func (commandValidator) Validate(context.Context, string) error {
	return fmt.Errorf("release validator is not configured")
}

type releaseCommandValidator struct {
	expectedVersion        string
	goos                   string
	macOSTeamID            string
	trustedKeyFingerprints []string
}

func (validator releaseCommandValidator) Validate(ctx context.Context, path string) error {
	if validator.goos == "darwin" {
		if err := validateMacOSSignature(ctx, path, validator.macOSTeamID); err != nil {
			return err
		}
	}
	command := exec.CommandContext(ctx, path, "version")
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("run updated collector version check: %w", err)
	}
	if err := validateVersionOutput(
		string(output),
		validator.expectedVersion,
		validator.macOSTeamID,
		validator.trustedKeyFingerprints,
	); err != nil {
		return err
	}
	return nil
}

func validateMacOSSignature(ctx context.Context, path string, expectedTeamID string) error {
	verify := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "--verbose=2", path)
	verify.Stdout = io.Discard
	verify.Stderr = io.Discard
	if err := verify.Run(); err != nil {
		return fmt.Errorf("verify updated collector Developer ID signature: %w", err)
	}
	details := exec.CommandContext(ctx, "/usr/bin/codesign", "-dv", "--verbose=4", path)
	output, err := details.CombinedOutput()
	if err != nil {
		return fmt.Errorf("read updated collector signing identity: %w", err)
	}
	if teamID := codesignTeamID(string(output)); teamID != expectedTeamID {
		return fmt.Errorf("updated collector signing Team ID mismatch")
	}
	assess := exec.CommandContext(ctx, "/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", path)
	assess.Stdout = io.Discard
	assess.Stderr = io.Discard
	if err := assess.Run(); err != nil {
		return fmt.Errorf("verify updated collector notarization: %w", err)
	}

	return nil
}

func codesignTeamID(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if value, found := strings.CutPrefix(strings.TrimSpace(line), "TeamIdentifier="); found {
			return strings.TrimSpace(value)
		}
	}

	return ""
}

func validateVersionOutput(output string, expected string, expectedTeamID string, trustedKeyFingerprints []string) error {
	fields := make(map[string]string)
	for _, field := range strings.Fields(output) {
		key, value, found := strings.Cut(field, "=")
		if found {
			fields[key] = value
		}
	}
	if fields["version"] != expected {
		return fmt.Errorf("updated collector version mismatch")
	}
	if fields["release_team_id"] != expectedTeamID {
		return fmt.Errorf("updated collector release Team ID mismatch")
	}
	keyFingerprint := fields["release_key_sha256"]
	decodedFingerprint, err := hex.DecodeString(keyFingerprint)
	if err != nil || len(decodedFingerprint) != sha256.Size {
		return fmt.Errorf("updated collector release trust is invalid")
	}
	if !containsString(trustedKeyFingerprints, keyFingerprint) {
		return fmt.Errorf("updated collector release key is not trusted")
	}
	if fields["release_trust"] == "unconfigured" {
		return fmt.Errorf("updated collector release trust is unconfigured")
	}

	return nil
}

func publicKeyFingerprints(publicKeys []*ecdsa.PublicKey) []string {
	fingerprints := make([]string, 0, len(publicKeys))
	for _, publicKey := range publicKeys {
		encoded, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			continue
		}
		digest := sha256.Sum256(encoded)
		fingerprints = append(fingerprints, hex.EncodeToString(digest[:]))
	}

	return fingerprints
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}

	return false
}
