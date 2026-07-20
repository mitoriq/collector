package autoupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type releaseFixture struct {
	archive      []byte
	archiveName  string
	draft        bool
	goarch       string
	goos         string
	manifest     []byte
	manifestSig  []byte
	prerelease   bool
	publicKeyPEM []byte
	tagName      string
}

type fakeHTTPClient func(*http.Request) (*http.Response, error)

func (client fakeHTTPClient) Do(request *http.Request) (*http.Response, error) {
	return client(request)
}

func TestManagerUpdateInstallsVerifiedRelease(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("new collector"), nil)
	executablePath := writeCurrentExecutable(t, []byte("old collector"))
	server := newReleaseServer(t, fixture, http.StatusOK)

	manager, err := New(Config{
		ReleaseURL:        server.URL + "/latest",
		PublicKeyPEM:      fixture.publicKeyPEM,
		CurrentVersion:    "1.2.2",
		ExecutablePath:    executablePath,
		GOOS:              fixture.goos,
		GOARCH:            fixture.goarch,
		AllowLoopbackHTTP: true,
		Validator: ValidatorFunc(func(_ context.Context, path string) error {
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if string(content) != "new collector" {
				return fmt.Errorf("unexpected installed binary: %q", content)
			}
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := manager.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.TagName != "v1.2.3" || result.ArchiveName != fixture.archiveName {
		t.Fatalf("result = %#v", result)
	}
	if result.RolledBack {
		t.Fatalf("result.RolledBack = true")
	}
	assertFileContent(t, executablePath, "new collector")
}

func TestManagerUpdateAcceptsAdditionalTrustedKeyDuringRotation(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("new collector"), nil)
	executablePath := writeCurrentExecutable(t, []byte("old collector"))
	server := newReleaseServer(t, fixture, http.StatusOK)
	primaryKey := newSigningKey(t)
	manager, err := New(Config{
		ReleaseURL:              server.URL + "/latest",
		PublicKeyPEM:            marshalPublicKey(t, &primaryKey.PublicKey),
		AdditionalPublicKeysPEM: [][]byte{fixture.publicKeyPEM},
		CurrentVersion:          "1.0.0",
		ExecutablePath:          executablePath,
		GOOS:                    "darwin",
		GOARCH:                  "arm64",
		AllowLoopbackHTTP:       true,
		Validator: ValidatorFunc(func(_ context.Context, _ string) error {
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := manager.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Updated {
		t.Fatalf("result = %#v", result)
	}
}

func TestManagerUpdateRejectsTamperedBinary(t *testing.T) {
	fixture := newReleaseFixtureForPlatform(t, []byte("tampered collector"), []byte("signed collector"), "linux", "arm64", true)
	executablePath := writeCurrentExecutable(t, []byte("old collector"))
	server := newReleaseServer(t, fixture, http.StatusOK)
	manager := mustNewManager(t, fixture, server.URL+"/latest", executablePath, nil)

	_, err := manager.Update(context.Background())
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("error = %v, want ErrInvalidSignature", err)
	}
	assertFileContent(t, executablePath, "old collector")
}

func TestManagerUpdateAllowsDarwinArchiveWithoutBinarySignature(t *testing.T) {
	fixture := newReleaseFixtureForPlatform(t, []byte("notarized collector"), nil, "darwin", "arm64", false)
	executablePath := writeCurrentExecutable(t, []byte("old collector"))
	server := newReleaseServer(t, fixture, http.StatusOK)
	manager := mustNewManager(t, fixture, server.URL+"/latest", executablePath, ValidatorFunc(
		func(_ context.Context, _ string) error { return nil },
	))

	result, err := manager.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Updated {
		t.Fatalf("result = %#v", result)
	}
	assertFileContent(t, executablePath, "notarized collector")
}

func TestManagerUpdateRequiresLinuxBinarySignature(t *testing.T) {
	fixture := newReleaseFixtureForPlatform(t, []byte("unsigned collector"), nil, "linux", "arm64", false)
	executablePath := writeCurrentExecutable(t, []byte("old collector"))
	server := newReleaseServer(t, fixture, http.StatusOK)
	manager := mustNewManager(t, fixture, server.URL+"/latest", executablePath, nil)

	_, err := manager.Update(context.Background())
	if !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("error = %v, want ErrAssetNotFound", err)
	}
	assertFileContent(t, executablePath, "old collector")
}

func TestManagerUpdateRollsBackWhenValidatorFails(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("new collector"), nil)
	executablePath := writeCurrentExecutable(t, []byte("old collector"))
	server := newReleaseServer(t, fixture, http.StatusOK)
	validationErr := errors.New("new binary did not start")
	manager := mustNewManager(t, fixture, server.URL+"/latest", executablePath, ValidatorFunc(
		func(_ context.Context, _ string) error { return validationErr },
	))

	result, err := manager.Update(context.Background())
	if !errors.Is(err, validationErr) {
		t.Fatalf("error = %v, want validation error", err)
	}
	if !result.RolledBack {
		t.Fatalf("result.RolledBack = false")
	}
	assertFileContent(t, executablePath, "old collector")
	if result.BackupPath != "" {
		if _, statErr := os.Stat(result.BackupPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("backup still exists: %v", statErr)
		}
	}
}

func TestManagerUpdateRejectsArchivePathTraversal(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("new collector"), nil)
	fixture.archive = appendTarEntry(t, fixture.archive, "../escaped", []byte("owned"))
	fixture = resignArchive(t, fixture)
	executablePath := writeCurrentExecutable(t, []byte("old collector"))
	server := newReleaseServer(t, fixture, http.StatusOK)
	manager := mustNewManager(t, fixture, server.URL+"/latest", executablePath, nil)

	_, err := manager.Update(context.Background())
	if !errors.Is(err, ErrUnsafeArchive) {
		t.Fatalf("error = %v, want ErrUnsafeArchive", err)
	}
	assertFileContent(t, executablePath, "old collector")
}

func TestManagerUpdateRejectsInsecureReleaseURL(t *testing.T) {
	privateKey := newSigningKey(t)
	manager, err := New(Config{
		ReleaseURL:     "http://releases.example.com/latest",
		PublicKeyPEM:   marshalPublicKey(t, &privateKey.PublicKey),
		CurrentVersion: "1.2.2",
		ExecutablePath: filepath.Join(t.TempDir(), "collector"),
		GOOS:           "linux",
		GOARCH:         "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = manager.Update(context.Background())
	if !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("error = %v, want ErrInsecureURL", err)
	}
}

func TestValidateDownloadURLRejectsUnlistedPrivateHost(t *testing.T) {
	parsed, err := url.Parse("https://127.0.0.1/internal")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDownloadURL(parsed, false, []string{"api.github.com"}); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("err = %v, want ErrInsecureURL", err)
	}
}

func TestValidateVersionOutputRequiresVersionTrustAndTeamID(t *testing.T) {
	fingerprint := strings.Repeat("a", 64)
	valid := "version=1.2.3 commit=abc release_key_sha256=" + fingerprint + " release_team_id=TEAMID1234"
	if err := validateVersionOutput(valid, "1.2.3", "TEAMID1234", []string{fingerprint}); err != nil {
		t.Fatal(err)
	}
	if err := validateVersionOutput("version=1.2.3 release_trust=unconfigured", "1.2.3", "TEAMID1234", []string{fingerprint}); err == nil {
		t.Fatal("expected unconfigured trust to be rejected")
	}
	if err := validateVersionOutput(valid, "1.2.3", "TEAMID1234", []string{strings.Repeat("b", 64)}); err == nil {
		t.Fatal("expected untrusted release key to be rejected")
	}
}

func TestNewRejectsPlatformWithoutDefinedSignaturePolicy(t *testing.T) {
	privateKey := newSigningKey(t)
	_, err := New(Config{
		ReleaseURL:     "https://releases.example.com/latest",
		PublicKeyPEM:   marshalPublicKey(t, &privateKey.PublicKey),
		CurrentVersion: "1.2.2",
		ExecutablePath: filepath.Join(t.TempDir(), "collector"),
		GOOS:           "windows",
		GOARCH:         "amd64",
	})
	if err == nil {
		t.Fatal("expected unsupported platform error")
	}
}

func TestManagerUpdateDoesNotRunForDevelopmentBuild(t *testing.T) {
	privateKey := newSigningKey(t)
	requested := false
	manager, err := New(Config{
		ReleaseURL:     "https://releases.example.com/latest",
		PublicKeyPEM:   marshalPublicKey(t, &privateKey.PublicKey),
		CurrentVersion: "dev",
		ExecutablePath: filepath.Join(t.TempDir(), "collector"),
		GOOS:           "linux",
		GOARCH:         "amd64",
		HTTPClient: fakeHTTPClient(func(_ *http.Request) (*http.Response, error) {
			requested = true
			return nil, errors.New("unexpected request")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := manager.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.NoUpdateReason != NoUpdateCurrentVersionNotStable || requested {
		t.Fatalf("result = %#v, requested = %v", result, requested)
	}
}

func TestManagerUpdateOnlyAcceptsNewerStableRelease(t *testing.T) {
	tests := []struct {
		name           string
		currentVersion string
		releaseTag     string
		expectedReason NoUpdateReason
	}{
		{name: "prerelease", currentVersion: "1.2.3", releaseTag: "v1.2.4-rc.1", expectedReason: NoUpdateReleaseIsPrerelease},
		{name: "same version", currentVersion: "1.2.3", releaseTag: "v1.2.3", expectedReason: NoUpdateReleaseNotNewer},
		{name: "downgrade", currentVersion: "1.2.3", releaseTag: "v1.2.2", expectedReason: NoUpdateReleaseNotNewer},
		{name: "invalid release", currentVersion: "1.2.3", releaseTag: "latest", expectedReason: NoUpdateReleaseVersionInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReleaseFixture(t, []byte("new collector"), nil)
			fixture.tagName = test.releaseTag
			executablePath := writeCurrentExecutable(t, []byte("old collector"))
			server := newReleaseServer(t, fixture, http.StatusOK)
			manager := mustNewManagerForVersion(t, fixture, server.URL+"/latest", executablePath, nil, test.currentVersion)

			result, err := manager.Update(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if result.NoUpdateReason != test.expectedReason || result.Updated {
				t.Fatalf("result = %#v", result)
			}
			assertFileContent(t, executablePath, "old collector")
		})
	}
}

func TestManagerUpdateBindsArchiveNameToReleaseTag(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("old signed release"), nil)
	fixture.tagName = "v1.2.4"
	executablePath := writeCurrentExecutable(t, []byte("current collector"))
	server := newReleaseServer(t, fixture, http.StatusOK)
	manager := mustNewManager(t, fixture, server.URL+"/latest", executablePath, ValidatorFunc(
		func(_ context.Context, _ string) error { return nil },
	))

	_, err := manager.Update(context.Background())
	if !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("error = %v, want ErrAssetNotFound", err)
	}
	assertFileContent(t, executablePath, "current collector")
}

func TestManagerUpdateRejectsDraftAndPrereleaseMetadata(t *testing.T) {
	tests := []struct {
		name           string
		draft          bool
		prerelease     bool
		expectedReason NoUpdateReason
	}{
		{name: "draft", draft: true, expectedReason: NoUpdateReleaseIsDraft},
		{name: "prerelease", prerelease: true, expectedReason: NoUpdateReleaseIsPrerelease},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReleaseFixture(t, []byte("new collector"), nil)
			fixture.draft = test.draft
			fixture.prerelease = test.prerelease
			executablePath := writeCurrentExecutable(t, []byte("old collector"))
			server := newReleaseServer(t, fixture, http.StatusOK)
			manager := mustNewManager(t, fixture, server.URL+"/latest", executablePath, ValidatorFunc(
				func(_ context.Context, _ string) error { return nil },
			))

			result, err := manager.Update(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if result.NoUpdateReason != test.expectedReason || result.Updated {
				t.Fatalf("result = %#v", result)
			}
			assertFileContent(t, executablePath, "old collector")
		})
	}
}

func TestManagerUpdateRejectsNonSuccessAssetResponse(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("new collector"), nil)
	executablePath := writeCurrentExecutable(t, []byte("old collector"))
	server := newReleaseServer(t, fixture, http.StatusBadGateway)
	manager := mustNewManager(t, fixture, server.URL+"/latest", executablePath, nil)

	_, err := manager.Update(context.Background())
	if !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("error = %v, want ErrUnexpectedStatus", err)
	}
	assertFileContent(t, executablePath, "old collector")
}

func mustNewManager(t *testing.T, fixture releaseFixture, releaseURL string, executablePath string, validator Validator) *Manager {
	t.Helper()
	return mustNewManagerForVersion(t, fixture, releaseURL, executablePath, validator, "1.2.2")
}

func mustNewManagerForVersion(t *testing.T, fixture releaseFixture, releaseURL string, executablePath string, validator Validator, currentVersion string) *Manager {
	t.Helper()
	manager, err := New(Config{
		ReleaseURL:        releaseURL,
		PublicKeyPEM:      fixture.publicKeyPEM,
		CurrentVersion:    currentVersion,
		ExecutablePath:    executablePath,
		GOOS:              fixture.goos,
		GOARCH:            fixture.goarch,
		AllowLoopbackHTTP: true,
		Validator:         validator,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func newReleaseFixture(t *testing.T, binary []byte, signedBinary []byte) releaseFixture {
	t.Helper()
	return newReleaseFixtureForPlatform(t, binary, signedBinary, "darwin", "arm64", true)
}

func newReleaseFixtureForPlatform(t *testing.T, binary []byte, signedBinary []byte, goos string, goarch string, includeSignature bool) releaseFixture {
	t.Helper()
	privateKey := newSigningKey(t)
	if signedBinary == nil {
		signedBinary = binary
	}
	archiveName := "mitoriq-collector_1.2.3_" + goos + "_" + goarch + ".tar.gz"
	files := []tarFile{{name: "mitoriq-collector", content: binary, mode: 0o755}}
	if includeSignature {
		files = append(files, tarFile{name: "mitoriq-collector_" + goos + "_" + goarch + ".sig", content: signBlob(t, privateKey, signedBinary), mode: 0o644})
	}
	archive := makeArchive(t, files)
	digest := sha256.Sum256(archive)
	manifest := []byte(hex.EncodeToString(digest[:]) + "  " + archiveName + "\n")
	return releaseFixture{
		archive:      archive,
		archiveName:  archiveName,
		goarch:       goarch,
		goos:         goos,
		manifest:     manifest,
		manifestSig:  signBlob(t, privateKey, manifest),
		publicKeyPEM: marshalPublicKey(t, &privateKey.PublicKey),
		tagName:      "v1.2.3",
	}
}

func resignArchive(t *testing.T, fixture releaseFixture) releaseFixture {
	t.Helper()
	privateKey := newSigningKey(t)
	digest := sha256.Sum256(fixture.archive)
	fixture.manifest = []byte(hex.EncodeToString(digest[:]) + "  " + fixture.archiveName + "\n")
	fixture.manifestSig = signBlob(t, privateKey, fixture.manifest)
	fixture.publicKeyPEM = marshalPublicKey(t, &privateKey.PublicKey)
	return fixture
}

type tarFile struct {
	name    string
	content []byte
	mode    int64
}

func makeArchive(t *testing.T, files []tarFile) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, file := range files {
		if err := tarWriter.WriteHeader(&tar.Header{
			Name: file.name,
			Mode: file.mode,
			Size: int64(len(file.content)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(file.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func appendTarEntry(t *testing.T, archive []byte, name string, content []byte) []byte {
	t.Helper()
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tarReader := tar.NewReader(gzipReader)
	files := make([]tarFile, 0, 3)
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		fileContent := make([]byte, header.Size)
		if _, err := io.ReadFull(tarReader, fileContent); err != nil && len(fileContent) != 0 {
			t.Fatal(err)
		}
		files = append(files, tarFile{name: header.Name, content: fileContent, mode: header.Mode})
	}
	files = append(files, tarFile{name: name, content: content, mode: 0o644})
	return makeArchive(t, files)
}

func newReleaseServer(t *testing.T, fixture releaseFixture, assetStatus int) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/latest" {
			assets := []map[string]string{
				{"name": fixture.archiveName, "browser_download_url": server.URL + "/" + fixture.archiveName},
				{"name": "checksums.txt", "browser_download_url": server.URL + "/checksums.txt"},
				{"name": "checksums.txt.sig", "browser_download_url": server.URL + "/checksums.txt.sig"},
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"assets":     assets,
				"draft":      fixture.draft,
				"prerelease": fixture.prerelease,
				"tag_name":   fixture.tagName,
			})
			return
		}
		if assetStatus != http.StatusOK {
			writer.WriteHeader(assetStatus)
			return
		}
		switch request.URL.Path {
		case "/" + fixture.archiveName:
			_, _ = writer.Write(fixture.archive)
		case "/checksums.txt":
			_, _ = writer.Write(fixture.manifest)
		case "/checksums.txt.sig":
			_, _ = writer.Write(fixture.manifestSig)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func newSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}

func marshalPublicKey(t *testing.T, publicKey *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func signBlob(t *testing.T, privateKey *ecdsa.PrivateKey, content []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(content)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(signature)
	return []byte(encoded + "\n")
}

func writeCurrentExecutable(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mitoriq-collector")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertFileContent(t *testing.T, path string, expected string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(content)) != expected {
		t.Fatalf("content = %q, want %q", content, expected)
	}
}
