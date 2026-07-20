package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var errKeychainUnavailable = errors.New("keychain unavailable")

type fakeHTTPClient func(*http.Request) (*http.Response, error)

func (client fakeHTTPClient) Do(request *http.Request) (*http.Response, error) {
	return client(request)
}

type fakeCredentialStore struct {
	loadErr    error
	loadToken  string
	saveErr    error
	savedToken string
	service    string
}

func (store *fakeCredentialStore) Save(_ context.Context, service string, token string) error {
	store.service = service
	store.savedToken = token
	return store.saveErr
}

func (store *fakeCredentialStore) Load(_ context.Context, service string) (string, error) {
	store.service = service
	return store.loadToken, store.loadErr
}

func fakeEnrollmentToken() string {
	return strings.Join([]string{"mtq_e_tokenid", "secretvalue"}, "_")
}

func fixedTime() time.Time {
	return time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
}

func TestBuildEnrollRequestUsesMachineMetadata(t *testing.T) {
	request := BuildEnrollRequest(EnrollOptions{
		BootstrapCode:    "mtq_b_abcdefghijklmnopqrstuvwxyz",
		CollectorVersion: "0.1.0",
		DisplayName:      "Dev MacBook",
		LocalUUID:        "aaaaaaaa-7777-4aaa-8aaa-aaaaaaaaaaaa",
		OS:               "macos",
		Now:              fixedTime,
	})

	if request.BootstrapCode != "mtq_b_abcdefghijklmnopqrstuvwxyz" {
		t.Fatalf("BootstrapCode = %q", request.BootstrapCode)
	}
	if request.Machine.LocalUUID != "aaaaaaaa-7777-4aaa-8aaa-aaaaaaaaaaaa" {
		t.Fatalf("LocalUUID = %q", request.Machine.LocalUUID)
	}
	if request.Machine.LastSeenAt != "2026-07-04T00:00:00Z" {
		t.Fatalf("LastSeenAt = %q", request.Machine.LastSeenAt)
	}
}

func TestBuildEnrollRequestUsesCurrentTimeWhenNowMissing(t *testing.T) {
	request := BuildEnrollRequest(EnrollOptions{
		BootstrapCode: "mtq_b_bootstrap",
		DisplayName:   "Mitoriq Test",
		LocalUUID:     "local-1",
		OS:            "macos",
	})

	if _, err := time.Parse(time.RFC3339, request.Machine.LastSeenAt); err != nil {
		t.Fatalf("LastSeenAt = %q", request.Machine.LastSeenAt)
	}
}

func TestSaveEnrollmentTokenFallsBackTo0600FileWithoutPrintingToken(t *testing.T) {
	home := t.TempDir()
	token := fakeEnrollmentToken()
	var commands [][]string
	store := TokenStore{
		CommandRunner: func(_ context.Context, name string, args ...string) error {
			commands = append(commands, append([]string{name}, args...))
			return errKeychainUnavailable
		},
		GOOS: "darwin",
		Home: home,
	}

	result, err := store.Save(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}

	if result.Method != "file" {
		t.Fatalf("Method = %q", result.Method)
	}
	if strings.Contains(result.Warning, token) {
		t.Fatalf("warning leaked token: %q", result.Warning)
	}
	if len(commands) != 1 || commands[0][0] != "security" {
		t.Fatalf("commands = %#v", commands)
	}

	tokenPath := filepath.Join(home, ".config", "mitoriq", "enrollment-token")
	content, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != token+"\n" {
		t.Fatalf("stored token mismatch")
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
}

func TestSaveEnrollmentTokenAtomicallyReplacesFallbackFile(t *testing.T) {
	home := t.TempDir()
	store := TokenStore{GOOS: "linux", Home: home}
	record := EnrollmentTokenRecord{OrganizationID: "org-1", Token: "mtq_e_old_secret"}
	if _, err := store.SaveForEnrollment(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	record.Token = "mtq_e_new_secret"
	if _, err := store.SaveForEnrollment(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(home, ".config", "mitoriq", "enrollment-tokens", "org-1")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != record.Token+"\n" {
		t.Fatalf("stored token mismatch")
	}
	temporaryFiles, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".enrollment-token-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temporaryFiles) != 0 {
		t.Fatalf("temporary files = %v", temporaryFiles)
	}
}

func TestSaveEnrollmentTokenSyncsParentDirectoryAndSurfacesFailure(t *testing.T) {
	home := t.TempDir()
	directory := filepath.Join(home, ".config", "mitoriq")
	var syncedDirectory string
	store := TokenStore{
		GOOS: "linux",
		Home: home,
		syncParent: func(path string) error {
			syncedDirectory = path
			return errors.New("sync failed")
		},
	}

	_, err := store.Save(context.Background(), fakeEnrollmentToken())
	if err == nil {
		t.Fatal("parent directory sync failure was ignored")
	}
	if syncedDirectory != directory {
		t.Fatalf("synced directory = %q", syncedDirectory)
	}
}

func TestSaveEnrollmentTokenUsesKeychainWhenAvailable(t *testing.T) {
	token := fakeEnrollmentToken()
	var commandName string
	store := TokenStore{
		CommandRunner: func(_ context.Context, name string, _ ...string) error {
			commandName = name
			return nil
		},
		GOOS: "darwin",
		Home: t.TempDir(),
	}

	result, err := store.Save(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}

	if result.Method != "keychain" {
		t.Fatalf("Method = %q", result.Method)
	}
	if commandName != "security" {
		t.Fatalf("commandName = %q", commandName)
	}
}

func TestSaveEnrollmentTokenUsesWindowsCredentialManagerWhenAvailable(t *testing.T) {
	token := fakeEnrollmentToken()
	credentials := &fakeCredentialStore{}
	store := TokenStore{
		CredentialStore: credentials,
		GOOS:            "windows",
		Home:            t.TempDir(),
	}

	result, err := store.SaveForEnrollment(context.Background(), EnrollmentTokenRecord{
		OrganizationID: "org-1",
		Token:          token,
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Method != "credential-manager" {
		t.Fatalf("Method = %q", result.Method)
	}
	if credentials.savedToken != token {
		t.Fatalf("saved token mismatch")
	}
	if credentials.service != "mitoriq.enrollment-token.org-1" {
		t.Fatalf("service = %q", credentials.service)
	}
}

func TestSaveEnrollmentTokenUsesDefaultHomeDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	store := TokenStore{
		GOOS: "linux",
	}

	result, err := store.Save(context.Background(), fakeEnrollmentToken())
	if err != nil {
		t.Fatal(err)
	}

	if result.Path != filepath.Join(home, ".config", "mitoriq", "enrollment-token") {
		t.Fatalf("Path = %q", result.Path)
	}
}

func TestLoadEnrollmentTokenReadsFallbackFile(t *testing.T) {
	home := t.TempDir()
	tokenPath := filepath.Join(home, ".config", "mitoriq", "enrollment-token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte(fakeEnrollmentToken()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	token, err := (TokenStore{GOOS: "linux", Home: home}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token != fakeEnrollmentToken() {
		t.Fatalf("token = %q", token)
	}
}

func TestLoadEnrollmentTokenRejectsFileSwappedBetweenInspectionAndOpen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("inode identity semantics are required")
	}
	home := t.TempDir()
	tokenPath := filepath.Join(home, ".config", "mitoriq", "enrollment-token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatal(err)
	}
	originalToken := "mtq_e_original_secret"
	swappedToken := "mtq_e_swapped_secret"
	if err := os.WriteFile(tokenPath, []byte(originalToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	replacementPath := filepath.Join(home, "replacement-token")
	if err := os.WriteFile(replacementPath, []byte(swappedToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var swapErr error
	store := TokenStore{
		GOOS: "linux",
		Home: home,
		beforeTokenFileOpen: func() {
			swapErr = os.Rename(replacementPath, tokenPath)
		},
	}

	token, err := store.Load(context.Background())
	if swapErr != nil {
		t.Fatal(swapErr)
	}
	if err == nil {
		t.Fatalf("swapped token file returned %q", token)
	}
	if strings.Contains(err.Error(), home) || strings.Contains(err.Error(), originalToken) || strings.Contains(err.Error(), swappedToken) {
		t.Fatalf("error leaked sensitive data: %q", err)
	}
}

func TestLoadEnrollmentTokenRejectsOversizedFileWithoutLeakingPath(t *testing.T) {
	home := t.TempDir()
	tokenPath := filepath.Join(home, ".config", "mitoriq", "enrollment-token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, bytes.Repeat([]byte{'x'}, 17<<10), 0o600); err != nil {
		t.Fatal(err)
	}

	token, err := (TokenStore{GOOS: "linux", Home: home}).Load(context.Background())
	if err == nil {
		t.Fatalf("oversized token file returned %d bytes", len(token))
	}
	if strings.Contains(err.Error(), home) {
		t.Fatalf("error leaked token path: %q", err)
	}
}

func TestLoadEnrollmentTokenRejectsInsecureFileTypesAndModesWithoutLeakingSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file mode and symlink semantics are required")
	}
	tests := []struct {
		name   string
		create func(t *testing.T, path string)
	}{
		{
			name: "symlink",
			create: func(t *testing.T, path string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "token-target")
				if err := os.WriteFile(target, []byte("secret-token\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "non-regular",
			create: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Mkdir(path, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong-mode",
			create: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("secret-token\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".config", "mitoriq", "enrollment-token")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			test.create(t, path)

			var openAttempted atomic.Bool
			token, err := (TokenStore{
				GOOS: "linux",
				Home: home,
				beforeTokenFileOpen: func() {
					openAttempted.Store(true)
				},
			}).Load(context.Background())
			if err == nil {
				t.Fatalf("insecure token file returned %q", token)
			}
			if openAttempted.Load() {
				t.Fatal("insecure token file reached the open step")
			}
			if strings.Contains(err.Error(), home) || strings.Contains(err.Error(), "secret-token") {
				t.Fatalf("error leaked sensitive data: %q", err)
			}
		})
	}
}

func TestLoadEnrollmentTokenMissingErrorDoesNotLeakPath(t *testing.T) {
	home := t.TempDir()
	_, err := (TokenStore{GOOS: "linux", Home: home}).Load(context.Background())
	if !IsTokenNotFound(err) {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), home) {
		t.Fatalf("error leaked token path: %q", err)
	}
}

func TestEnrollmentTokenStoreSeparatesOrganizations(t *testing.T) {
	home := t.TempDir()
	store := TokenStore{GOOS: "linux", Home: home}
	orgAToken := "mtq_e_orgatoken_secretvalue"
	orgBToken := "mtq_e_orgbtoken_secretvalue"

	if _, err := store.SaveForEnrollment(context.Background(), EnrollmentTokenRecord{
		OrganizationID: "org-a",
		Token:          orgAToken,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveForEnrollment(context.Background(), EnrollmentTokenRecord{
		OrganizationID: "org-b",
		Token:          orgBToken,
	}); err != nil {
		t.Fatal(err)
	}

	actualOrgA, err := store.LoadForOrganization(context.Background(), "org-a")
	if err != nil {
		t.Fatal(err)
	}
	actualOrgB, err := store.LoadForOrganization(context.Background(), "org-b")
	if err != nil {
		t.Fatal(err)
	}

	if actualOrgA != orgAToken {
		t.Fatalf("org-a token = %q", actualOrgA)
	}
	if actualOrgB != orgBToken {
		t.Fatalf("org-b token = %q", actualOrgB)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "mitoriq", "enrollment-tokens", "org-a")); err != nil {
		t.Fatal(err)
	}
}

func TestLoadEnrollmentTokenUsesKeychainWhenAvailable(t *testing.T) {
	token := fakeEnrollmentToken()
	var commandName string
	store := TokenStore{
		CommandOutput: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			commandName = name
			return []byte(token + "\n"), nil
		},
		GOOS: "darwin",
		Home: t.TempDir(),
	}

	actual, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if actual != token {
		t.Fatalf("token = %q", actual)
	}
	if commandName != "security" {
		t.Fatalf("commandName = %q", commandName)
	}
}

func TestLoadEnrollmentTokenUsesWindowsCredentialManagerWhenAvailable(t *testing.T) {
	token := fakeEnrollmentToken()
	credentials := &fakeCredentialStore{loadToken: token}
	store := TokenStore{
		CredentialStore: credentials,
		GOOS:            "windows",
		Home:            t.TempDir(),
	}

	actual, err := store.LoadForOrganization(context.Background(), "org-1")
	if err != nil {
		t.Fatal(err)
	}

	if actual != token {
		t.Fatalf("token = %q", actual)
	}
	if credentials.service != "mitoriq.enrollment-token.org-1" {
		t.Fatalf("service = %q", credentials.service)
	}
}

func TestSaveEnrollmentTokenReturnsErrorWhenConfigParentIsFile(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home-file")
	if err := os.WriteFile(home, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := TokenStore{
		GOOS: "linux",
		Home: home,
	}

	_, err := store.Save(context.Background(), fakeEnrollmentToken())

	if err == nil {
		t.Fatal("expected config parent error")
	}
}

func TestNewLocalUUIDReturnsVersion4UUID(t *testing.T) {
	uuid, err := NewLocalUUID()
	if err != nil {
		t.Fatal(err)
	}

	if len(uuid) != 36 {
		t.Fatalf("uuid length = %d", len(uuid))
	}
	if uuid[14] != '4' {
		t.Fatalf("uuid version = %q", uuid[14])
	}
	if !strings.Contains("89ab", string(uuid[19])) {
		t.Fatalf("uuid variant = %q", uuid[19])
	}
}

func TestWriteEnrollResultDoesNotPrintEnrollmentToken(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	token := fakeEnrollmentToken()

	err := writeEnrollResult(
		&stdout,
		&stderr,
		EnrollResponse{
			EnrollmentToken:     token,
			MachineEnrollmentID: "enrollment-1",
			MachineID:           "machine-1",
			OrganizationID:      "org-1",
		},
		SaveResult{Method: "keychain"},
	)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(stdout.String(), token) {
		t.Fatalf("stdout leaked token: %q", stdout.String())
	}
	if strings.Contains(stderr.String(), token) {
		t.Fatalf("stderr leaked token: %q", stderr.String())
	}
}

func TestEnrollPostsRequestStoresTokenAndHidesSecret(t *testing.T) {
	token := fakeEnrollmentToken()
	var received EnrollRequest
	client := fakeHTTPClient(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/api/machines/enrollments" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body: io.NopCloser(strings.NewReader(`{
				"enrollmentToken":"` + token + `",
				"machineEnrollmentId":"enrollment-1",
				"machineId":"machine-1",
				"organizationId":"org-1",
				"tokenPrefix":"mtq_e_tokenid"
			}`)),
			Header: make(http.Header),
		}, nil
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, err := Enroll(context.Background(), client, TokenStore{GOOS: "linux", Home: t.TempDir()}, EnrollOptions{
		APIURL:           "https://collector.example.com/",
		BootstrapCode:    "mtq_b_bootstrap",
		CollectorVersion: "0.1.0",
		DisplayName:      "Mitoriq Test",
		LocalUUID:        "local-1",
		OS:               "macos",
		Stdout:           &stdout,
		Stderr:           &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}

	if received.BootstrapCode != "mtq_b_bootstrap" {
		t.Fatalf("received request = %#v", received)
	}
	if strings.Contains(stdout.String(), token) || strings.Contains(stderr.String(), token) {
		t.Fatalf("token leaked stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestEnrollReturnsErrorOnNonCreatedStatus(t *testing.T) {
	client := fakeHTTPClient(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(strings.NewReader(`{"code":"invalid"}`)),
			Header:     make(http.Header),
		}, nil
	})

	_, err := Enroll(context.Background(), client, TokenStore{GOOS: "linux", Home: t.TempDir()}, EnrollOptions{
		APIURL:        "https://collector.example.com",
		BootstrapCode: "mtq_b_bootstrap",
		DisplayName:   "Mitoriq Test",
		LocalUUID:     "local-1",
		OS:            "macos",
	})

	if err == nil {
		t.Fatal("expected enroll status error")
	}
}

func TestEnrollReturnsHTTPClientError(t *testing.T) {
	expectedErr := errors.New("network unavailable")
	client := fakeHTTPClient(func(_ *http.Request) (*http.Response, error) {
		return nil, expectedErr
	})

	_, err := Enroll(context.Background(), client, TokenStore{GOOS: "linux", Home: t.TempDir()}, EnrollOptions{
		APIURL:        "https://collector.example.com",
		BootstrapCode: "mtq_b_bootstrap",
		DisplayName:   "Mitoriq Test",
		LocalUUID:     "local-1",
		OS:            "macos",
	})

	if !errors.Is(err, expectedErr) {
		t.Fatalf("err = %v, want %v", err, expectedErr)
	}
}

func TestEnrollReturnsDecodeError(t *testing.T) {
	client := fakeHTTPClient(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader(`not json`)),
			Header:     make(http.Header),
		}, nil
	})

	_, err := Enroll(context.Background(), client, TokenStore{GOOS: "linux", Home: t.TempDir()}, EnrollOptions{
		APIURL:        "https://collector.example.com",
		BootstrapCode: "mtq_b_bootstrap",
		DisplayName:   "Mitoriq Test",
		LocalUUID:     "local-1",
		OS:            "macos",
	})

	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestEnrollReturnsInvalidURLError(t *testing.T) {
	client := fakeHTTPClient(func(_ *http.Request) (*http.Response, error) {
		t.Fatal("client should not be called")
		return nil, nil
	})

	_, err := Enroll(context.Background(), client, TokenStore{GOOS: "linux", Home: t.TempDir()}, EnrollOptions{
		APIURL:        "://bad",
		BootstrapCode: "mtq_b_bootstrap",
		DisplayName:   "Mitoriq Test",
		LocalUUID:     "local-1",
		OS:            "macos",
	})

	if err == nil {
		t.Fatal("expected invalid URL error")
	}
}
