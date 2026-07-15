package enroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type MachineRequest struct {
	DisplayName string `json:"displayName"`
	LastSeenAt  string `json:"lastSeenAt"`
	LocalUUID   string `json:"localUuid"`
	OS          string `json:"os"`
}

type EnrollRequest struct {
	BootstrapCode    string         `json:"bootstrapCode"`
	CollectorVersion string         `json:"collectorVersion,omitempty"`
	Machine          MachineRequest `json:"machine"`
}

type EnrollResponse struct {
	EnrollmentToken     string `json:"enrollmentToken"`
	MachineEnrollmentID string `json:"machineEnrollmentId"`
	MachineID           string `json:"machineId"`
	MemberID            string `json:"memberId"`
	OrganizationID      string `json:"organizationId"`
	TokenPrefix         string `json:"tokenPrefix"`
}

type EnrollOptions struct {
	APIURL           string
	BootstrapCode    string
	CollectorVersion string
	DisplayName      string
	Home             string
	LocalUUID        string
	OS               string
	Now              func() time.Time
	Stderr           io.Writer
	Stdout           io.Writer
}

type SaveResult struct {
	Method  string
	Path    string
	Warning string
}

var ErrTokenNotFound = errors.New("enrollment token not found")

type EnrollmentTokenRecord struct {
	OrganizationID string
	Token          string
}

type CredentialStore interface {
	Load(ctx context.Context, service string) (string, error)
	Save(ctx context.Context, service string, token string) error
}

func IsTokenNotFound(err error) bool {
	return errors.Is(err, ErrTokenNotFound)
}

type TokenStore struct {
	CredentialStore CredentialStore
	CommandOutput   func(context.Context, string, ...string) ([]byte, error)
	CommandRunner   func(context.Context, string, ...string) error
	GOOS            string
	Home            string
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func nowOrDefault(now func() time.Time) time.Time {
	if now == nil {
		return time.Now().UTC()
	}

	return now().UTC()
}

func BuildEnrollRequest(options EnrollOptions) EnrollRequest {
	return EnrollRequest{
		BootstrapCode:    options.BootstrapCode,
		CollectorVersion: options.CollectorVersion,
		Machine: MachineRequest{
			DisplayName: options.DisplayName,
			LastSeenAt:  nowOrDefault(options.Now).Format(time.RFC3339),
			LocalUUID:   options.LocalUUID,
			OS:          options.OS,
		},
	}
}

func (store TokenStore) Save(ctx context.Context, token string) (SaveResult, error) {
	return store.saveToken(ctx, EnrollmentTokenRecord{Token: token})
}

func (store TokenStore) SaveForEnrollment(ctx context.Context, record EnrollmentTokenRecord) (SaveResult, error) {
	return store.saveToken(ctx, record)
}

func (store TokenStore) saveToken(ctx context.Context, record EnrollmentTokenRecord) (SaveResult, error) {
	goos := store.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}

	if goos == "darwin" {
		if err := store.run(ctx, "security", "add-generic-password", "-a", "mitoriq-collector", "-s", tokenService(record.OrganizationID), "-w", record.Token, "-U"); err == nil {
			return SaveResult{Method: "keychain"}, nil
		}
	}
	if goos == "windows" {
		if credentials := store.credentialStore(); credentials != nil {
			if err := credentials.Save(ctx, tokenService(record.OrganizationID), record.Token); err == nil {
				return SaveResult{Method: "credential-manager"}, nil
			}
		}
	}

	path := tokenPath(store.Home, record.OrganizationID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return SaveResult{}, err
	}
	if err := os.WriteFile(path, []byte(record.Token+"\n"), 0o600); err != nil {
		return SaveResult{}, err
	}

	return SaveResult{
		Method:  "file",
		Path:    path,
		Warning: fallbackWarning(goos),
	}, nil
}

func (store TokenStore) Load(ctx context.Context) (string, error) {
	return store.loadToken(ctx, "")
}

func (store TokenStore) LoadForOrganization(ctx context.Context, organizationID string) (string, error) {
	return store.loadToken(ctx, organizationID)
}

func (store TokenStore) loadToken(ctx context.Context, organizationID string) (string, error) {
	goos := store.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}

	if goos == "darwin" {
		output, err := store.output(ctx, "security", "find-generic-password", "-a", "mitoriq-collector", "-s", tokenService(organizationID), "-w")
		if err == nil {
			token := strings.TrimSpace(string(output))
			if token != "" {
				return token, nil
			}
		}
	}
	if goos == "windows" {
		if credentials := store.credentialStore(); credentials != nil {
			token, err := credentials.Load(ctx, tokenService(organizationID))
			if err == nil && strings.TrimSpace(token) != "" {
				return strings.TrimSpace(token), nil
			}
		}
	}

	path := tokenPath(store.Home, organizationID)
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %s", ErrTokenNotFound, path)
		}

		return "", err
	}
	token := strings.TrimSpace(string(content))
	if token == "" {
		return "", fmt.Errorf("%w: %s", ErrTokenNotFound, path)
	}

	return token, nil
}

func (store TokenStore) credentialStore() CredentialStore {
	if store.CredentialStore != nil {
		return store.CredentialStore
	}

	return newWindowsCredentialStore()
}

func fallbackWarning(goos string) string {
	if goos == "windows" {
		return "Credential Manager を利用できないためローカルファイルへ保存しました。Windows のファイル ACL を確認してください。"
	}

	return "Keychain を利用できないため 0600 ファイルへ保存しました。"
}

func tokenPath(home string, organizationID string) string {
	if organizationID == "" {
		return filepath.Join(homeDir(home), ".config", "mitoriq", "enrollment-token")
	}

	return filepath.Join(homeDir(home), ".config", "mitoriq", "enrollment-tokens", organizationID)
}

func tokenService(organizationID string) string {
	if organizationID == "" {
		return "mitoriq.enrollment-token"
	}

	return "mitoriq.enrollment-token." + organizationID
}

func (store TokenStore) run(ctx context.Context, name string, args ...string) error {
	if store.CommandRunner != nil {
		return store.CommandRunner(ctx, name, args...)
	}

	return exec.CommandContext(ctx, name, args...).Run()
}

func (store TokenStore) output(ctx context.Context, name string, args ...string) ([]byte, error) {
	if store.CommandOutput != nil {
		return store.CommandOutput(ctx, name, args...)
	}

	return exec.CommandContext(ctx, name, args...).Output()
}

func homeDir(home string) string {
	if home != "" {
		return home
	}
	if value := os.Getenv("HOME"); value != "" {
		return value
	}

	if value, err := os.UserHomeDir(); err == nil {
		return value
	}

	return "."
}

func Enroll(
	ctx context.Context,
	client HTTPClient,
	store TokenStore,
	options EnrollOptions,
) (EnrollResponse, error) {
	requestBody, err := json.Marshal(BuildEnrollRequest(options))
	if err != nil {
		return EnrollResponse{}, err
	}

	url := strings.TrimRight(options.APIURL, "/") + "/api/machines/enrollments"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(requestBody))
	if err != nil {
		return EnrollResponse{}, err
	}
	request.Header.Set("content-type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return EnrollResponse{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		return EnrollResponse{}, fmt.Errorf("enroll request failed: status=%d", response.StatusCode)
	}

	var body EnrollResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return EnrollResponse{}, err
	}

	saveResult, err := store.SaveForEnrollment(ctx, EnrollmentTokenRecord{
		OrganizationID: body.OrganizationID,
		Token:          body.EnrollmentToken,
	})
	if err != nil {
		return EnrollResponse{}, err
	}

	return body, writeEnrollResult(options.Stdout, options.Stderr, body, saveResult)
}

func writeEnrollResult(
	stdout io.Writer,
	stderr io.Writer,
	body EnrollResponse,
	saveResult SaveResult,
) error {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	if saveResult.Warning != "" {
		if _, err := fmt.Fprintln(stderr, saveResult.Warning); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(
		stdout,
		"enrolled machine_id=%s machine_enrollment_id=%s organization_id=%s token_store=%s\n",
		body.MachineID,
		body.MachineEnrollmentID,
		body.OrganizationID,
		saveResult.Method,
	)

	return err
}

func NewLocalUUID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80

	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		bytes[0:4],
		bytes[4:6],
		bytes[6:8],
		bytes[8:10],
		bytes[10:16],
	), nil
}
