package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/deviceauth"
	"github.com/mitoriq/collector/internal/enroll"
	"github.com/mitoriq/collector/internal/localconfig"
	"github.com/mitoriq/collector/internal/version"
)

type fakeSetupHelper struct {
	url     string
	done    chan error
	retry   deviceauth.RetryFunc
	views   []deviceauth.HelperView
	onError func()
	mu      sync.Mutex
}

func (helper *fakeSetupHelper) URL() string        { return helper.url }
func (helper *fakeSetupHelper) Done() <-chan error { return helper.done }
func (helper *fakeSetupHelper) Update(view deviceauth.HelperView) error {
	helper.mu.Lock()
	helper.views = append(helper.views, view)
	onError := helper.onError
	helper.mu.Unlock()
	if view.State == deviceauth.HelperError && onError != nil {
		onError()
	}
	return nil
}

func TestSetupCommandAcceptsNoArgumentsAndRejectsWindowsBeforeSideEffects(t *testing.T) {
	if err := runSetupCommand([]string{"-h"}, io.Discard, io.Discard, setupCommandDependencies{}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help error = %v", err)
	}
	if err := runSetupCommand([]string{"unexpected"}, io.Discard, io.Discard, setupCommandDependencies{}); err == nil {
		t.Fatal("positional argument was accepted")
	}
	deps := setupCommandDependencies{GOOS: "windows", Origins: func() (version.ServiceOrigins, error) {
		t.Fatal("network configuration read")
		return version.ServiceOrigins{}, nil
	}}
	if err := runSetupCommand(nil, io.Discard, io.Discard, deps); !errors.Is(err, deviceauth.ErrUnsupportedPlatform) {
		t.Fatalf("windows error = %v", err)
	}
}

func TestTopLevelHelpGuidesToSetupWithoutAdvertisingLegacyEnroll(t *testing.T) {
	var stdout bytes.Buffer
	if code := run(nil, &stdout, io.Discard); code != 0 || !strings.Contains(stdout.String(), "setup") || strings.Contains(stdout.String(), "  enroll ") {
		t.Fatalf("code=%d help=%q", code, stdout.String())
	}
}

func TestResolveSetupOriginsAllowsOnlyDevelopmentHTTPSOverrides(t *testing.T) {
	embedded := func() (version.ServiceOrigins, error) {
		return version.ServiceOrigins{APIURL: "https://release-api.example", WebURL: "https://release.example"}, nil
	}
	getenv := func(name string) string {
		return map[string]string{"MITORIQ_API_ORIGIN": "https://dev-api.example", "MITORIQ_WEB_ORIGIN": "https://dev.example"}[name]
	}
	dev, err := resolveSetupOrigins(true, getenv, embedded)
	if err != nil || dev.APIURL != "https://dev-api.example" {
		t.Fatalf("development origins = %#v, %v", dev, err)
	}
	release, err := resolveSetupOrigins(false, getenv, embedded)
	if err != nil || release.APIURL != "https://release-api.example" {
		t.Fatalf("release origins = %#v, %v", release, err)
	}
	if _, err := resolveSetupOrigins(true, func(string) string { return "http://unsafe.example" }, embedded); err == nil {
		t.Fatal("unsafe development origins were accepted")
	}
}

func TestSetupCommandPersistsEnrollmentAndKeepsSecretsOutOfOutputAndURLs(t *testing.T) {
	home := t.TempDir()
	token := "mtq_e_token-secret-value"
	enrollment := map[string]string{"enrollmentToken": token, "machineEnrollmentId": "11111111-1111-4111-8111-111111111111", "machineId": "22222222-2222-4222-8222-222222222222", "memberId": "33333333-3333-4333-8333-333333333333", "organizationId": "44444444-4444-4444-8444-444444444444", "tokenPrefix": "mtq_e_token"}
	var commandEnvelope deviceauth.Envelope
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("content-type", "application/json")
		switch request.URL.Path {
		case "/api/machines/device-authorizations/start":
			var body deviceauth.StartRequest
			if json.NewDecoder(request.Body).Decode(&body) != nil || body.Preflight.Platform != "linux" {
				t.Fatal("invalid start request")
			}
			envelope := sealCommandEnvelope(t, body.PublicKey, enrollment)
			commandEnvelope = envelope
			_, _ = io.WriteString(writer, `{"deviceCode":"device-secret","userCode":"ABCD-EFGH","expiresIn":60,"interval":1}`)
		case "/api/machines/device-authorizations/poll":
			_ = json.NewEncoder(writer).Encode(deviceauth.PollResponse{Status: deviceauth.StatusAuthorized, Envelope: &commandEnvelope})
		case "/api/machines/device-authorizations/complete":
			_, _ = io.WriteString(writer, `{"status":"enrolled"}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	helper := newFakeSetupHelper("http://127.0.0.1:45678")
	var openedLocal, openedWeb string
	deps := setupCommandDependencies{
		GOOS: "linux", HomeDir: func() (string, error) { return home, nil }, HTTPClient: server.Client(),
		Origins: func() (version.ServiceOrigins, error) {
			return version.ServiceOrigins{APIURL: server.URL, WebURL: "https://web.example"}, nil
		},
		StartHelper: helper.starter(), OpenBrowser: func(_ context.Context, localURL, webURL string) error {
			openedLocal, openedWeb = localURL, webURL
			return nil
		},
		Sleep: func(context.Context, time.Duration) error { return nil }, Grace: 0,
	}
	var stdout, stderr bytes.Buffer
	if err := runSetupCommand(nil, &stdout, &stderr, deps); err != nil {
		t.Fatal(err)
	}
	config, err := (localconfig.Store{Path: filepath.Join(home, ".config", "mitoriq", "collector.json")}).Load()
	if err != nil || config.MachineID != enrollment["machineId"] {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	if config.MachineLocalUUID == "" {
		t.Fatal("stable machine local UUID was not persisted")
	}
	stored, err := os.ReadFile(filepath.Join(home, ".config", "mitoriq", "enrollment-tokens", enrollment["organizationId"]))
	if err != nil || strings.TrimSpace(string(stored)) != token {
		t.Fatal("enrollment credential was not persisted")
	}
	combined := stdout.String() + stderr.String() + openedLocal + openedWeb
	for _, forbidden := range []string{token, "device-secret", enrollment["machineId"], enrollment["organizationId"], "ABCD-EFGH"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("secret/internal value leaked: %q", forbidden)
		}
	}
	if openedLocal != helper.url || openedWeb != "https://web.example/now#collector-setup" || !strings.Contains(stdout.String(), "next=mitoriq-collector install") {
		t.Fatalf("stdout=%q local=%q web=%q", stdout.String(), openedLocal, openedWeb)
	}
}

func TestDarwinSetupCredentialStoreDoesNotUseKeychainCLIWithTokenArgv(t *testing.T) {
	home := t.TempDir()
	token, organizationID := "token-secret", "44444444-4444-4444-8444-444444444444"
	store := setupTokenStoreWithoutKeychainCLIArgv(home, "darwin")
	store.CommandRunner = func(context.Context, string, ...string) error {
		t.Fatal("credential command must not be used")
		return nil
	}
	if _, err := store.SaveForEnrollment(context.Background(), enroll.EnrollmentTokenRecord{OrganizationID: organizationID, Token: token}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(home, ".config", "mitoriq", "enrollment-tokens", organizationID))
	if err != nil || strings.TrimSpace(string(content)) != token {
		t.Fatal("0600 credential fallback was not used")
	}
}

func TestSetupCommandReusesPersistedMachineLocalUUIDWithoutJournal(t *testing.T) {
	const localUUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	home := t.TempDir()
	store := localconfig.Store{Path: filepath.Join(home, ".config", "mitoriq", "collector.json")}
	if err := store.Save(localconfig.Config{MachineLocalUUID: localUUID}); err != nil {
		t.Fatal(err)
	}

	var observed []string
	for range 2 {
		helper := newFakeSetupHelper("http://127.0.0.1:45678")
		deps := setupCommandDependencies{
			GOOS: "linux", Grace: 0, HomeDir: func() (string, error) { return home, nil },
			Origins: func() (version.ServiceOrigins, error) {
				return version.ServiceOrigins{APIURL: "https://api.example", WebURL: "https://web.example"}, nil
			},
			StartHelper: helper.starter(), OpenBrowser: func(context.Context, string, string) error { return nil },
			RunSetup: func(_ context.Context, setup deviceauth.Setup) error {
				observed = append(observed, setup.LocalUUID)
				return setup.Challenge("ABCD-EFGH", time.Now().Add(time.Minute))
			},
		}
		if err := runSetupCommand(nil, io.Discard, io.Discard, deps); err != nil {
			t.Fatal(err)
		}
	}
	if len(observed) != 2 || observed[0] != localUUID || observed[1] != localUUID {
		t.Fatalf("observed local UUIDs = %v", observed)
	}
}

func TestSetupCommandKeepsEnrolledViewVisibleForGracePeriod(t *testing.T) {
	helper := newFakeSetupHelper("http://127.0.0.1:45678")
	const grace = 35 * time.Millisecond
	deps := setupCommandDependencies{
		GOOS: "linux", Grace: grace, HomeDir: func() (string, error) { return t.TempDir(), nil },
		Origins: func() (version.ServiceOrigins, error) {
			return version.ServiceOrigins{APIURL: "https://api.example", WebURL: "https://web.example"}, nil
		},
		StartHelper: helper.starter(), OpenBrowser: func(context.Context, string, string) error { return nil },
		RunSetup: func(_ context.Context, setup deviceauth.Setup) error {
			return setup.Challenge("ABCD-EFGH", time.Now().Add(time.Minute))
		},
	}
	started := time.Now()
	if err := runSetupCommand(nil, io.Discard, io.Discard, deps); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < grace {
		t.Fatalf("helper closed after %v, before grace %v", elapsed, grace)
	}
	helper.mu.Lock()
	defer helper.mu.Unlock()
	if len(helper.views) == 0 || helper.views[len(helper.views)-1].State != deviceauth.Enrolled {
		t.Fatalf("final helper views = %#v", helper.views)
	}
}

func TestSetupCommandSerializesConcurrentProcessesForTheSameHome(t *testing.T) {
	home := t.TempDir()
	entered := make(chan int, 2)
	releaseFirst := make(chan struct{})
	results := make(chan error, 2)
	var invocation int
	var invocationMu sync.Mutex
	dependencies := setupCommandDependencies{
		GOOS: "linux", Grace: 0, HomeDir: func() (string, error) { return home, nil },
		Origins: func() (version.ServiceOrigins, error) {
			return version.ServiceOrigins{APIURL: "https://api.example", WebURL: "https://web.example"}, nil
		},
		OpenBrowser: func(context.Context, string, string) error { return nil },
		StartHelper: func(ctx context.Context, initial deviceauth.HelperView, retry deviceauth.RetryFunc) (setupCommandHelper, error) {
			helper := newFakeSetupHelper("http://127.0.0.1:45678")
			return helper.starter()(ctx, initial, retry)
		},
		RunSetup: func(_ context.Context, setup deviceauth.Setup) error {
			invocationMu.Lock()
			invocation++
			current := invocation
			invocationMu.Unlock()
			entered <- current
			if err := setup.Challenge("ABCD-EFGH", time.Now().Add(time.Minute)); err != nil {
				return err
			}
			if current == 1 {
				<-releaseFirst
			}
			return nil
		},
	}

	go func() { results <- runSetupCommand(nil, io.Discard, io.Discard, dependencies) }()
	if current := <-entered; current != 1 {
		t.Fatalf("first invocation = %d", current)
	}
	go func() { results <- runSetupCommand(nil, io.Discard, io.Discard, dependencies) }()
	select {
	case current := <-entered:
		t.Fatalf("concurrent setup entered critical section as invocation %d", current)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)
	if current := <-entered; current != 2 {
		t.Fatalf("second invocation = %d", current)
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestSetupCommandRetriesThroughHelperAndSanitizesEarlyErrors(t *testing.T) {
	helper := newFakeSetupHelper("http://127.0.0.1:45678")
	var attempts int
	deps := setupCommandDependencies{
		GOOS: "linux", HomeDir: func() (string, error) { return t.TempDir(), nil },
		Origins: func() (version.ServiceOrigins, error) {
			return version.ServiceOrigins{APIURL: "https://api.example", WebURL: "https://web.example"}, nil
		},
		StartHelper: helper.starter(), OpenBrowser: func(context.Context, string, string) error { return nil }, Grace: 0,
		RunSetup: func(ctx context.Context, setup deviceauth.Setup) error {
			attempts++
			if err := setup.Challenge("ABCD-EFGH", time.Now().Add(time.Minute)); err != nil {
				return err
			}
			if attempts == 1 {
				return errors.New("device-secret internal-id")
			}
			return nil
		},
	}
	var once sync.Once
	helper.onError = func() {
		once.Do(func() { go func() { view, _ := helper.retry(context.Background()); _ = helper.Update(view) }() })
	}
	var stdout bytes.Buffer
	if err := runSetupCommand(nil, &stdout, io.Discard, deps); err != nil || attempts != 2 {
		t.Fatalf("err=%v attempts=%d", err, attempts)
	}
	early := deps
	early.Origins = func() (version.ServiceOrigins, error) { return version.ServiceOrigins{}, errors.New("device-secret") }
	if err := runSetupCommand(nil, io.Discard, io.Discard, early); err == nil || strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "再実行") {
		t.Fatalf("early error = %v", err)
	}
}

type pollOnlyProtocol struct{ response deviceauth.PollResponse }

func (protocol pollOnlyProtocol) Start(context.Context, deviceauth.StartRequest) (deviceauth.StartResponse, error) {
	return deviceauth.StartResponse{}, nil
}
func (protocol pollOnlyProtocol) Poll(context.Context, deviceauth.PollRequest) (deviceauth.PollResponse, error) {
	return protocol.response, nil
}
func (protocol pollOnlyProtocol) Complete(context.Context, deviceauth.CompleteRequest) (deviceauth.CompleteResponse, error) {
	return deviceauth.CompleteResponse{}, nil
}

func TestSetupProtocolMapsPollStatesToHelper(t *testing.T) {
	for _, test := range []struct {
		status deviceauth.Status
		state  deviceauth.HelperState
	}{
		{deviceauth.StatusAuthorizationPending, deviceauth.HelperReady}, {deviceauth.StatusSlowDown, deviceauth.HelperReady},
		{deviceauth.StatusAuthorized, deviceauth.Authorized}, {deviceauth.StatusEnrolled, deviceauth.Enrolled},
		{deviceauth.StatusExpiredToken, deviceauth.Expired}, {deviceauth.StatusAccessDenied, deviceauth.HelperError},
	} {
		helper := newFakeSetupHelper("http://127.0.0.1:45678")
		protocol := &setupHelperProtocol{delegate: pollOnlyProtocol{response: deviceauth.PollResponse{Status: test.status}}, helper: helper, userCode: "ABCD-EFGH"}
		if _, err := protocol.Poll(context.Background(), deviceauth.PollRequest{}); err != nil {
			t.Fatal(err)
		}
		if helper.views[len(helper.views)-1].State != test.state {
			t.Fatalf("status=%q view=%#v", test.status, helper.views)
		}
	}
}

func newFakeSetupHelper(url string) *fakeSetupHelper {
	return &fakeSetupHelper{url: url, done: make(chan error)}
}
func (helper *fakeSetupHelper) starter() func(context.Context, deviceauth.HelperView, deviceauth.RetryFunc) (setupCommandHelper, error) {
	return func(ctx context.Context, initial deviceauth.HelperView, retry deviceauth.RetryFunc) (setupCommandHelper, error) {
		helper.retry, helper.views = retry, append(helper.views, initial)
		go func() { <-ctx.Done(); close(helper.done) }()
		return helper, nil
	}
}

func sealCommandEnvelope(t *testing.T, publicPEM string, value map[string]string) deviceauth.Envelope {
	t.Helper()
	block, _ := pem.Decode([]byte(publicPEM))
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := parsed.(*rsa.PublicKey)
	key, nonce := make([]byte, 32), make([]byte, 12)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nil, nonce, setupJSON(t, value), nil)
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	encode, tagAt := base64.StdEncoding.EncodeToString, len(sealed)-gcm.Overhead()
	return deviceauth.Envelope{Algorithm: "RSA-OAEP-256+A256GCM", EncryptedKey: encode(encryptedKey), IV: encode(nonce), Ciphertext: encode(sealed[:tagAt]), Tag: encode(sealed[tagAt:])}
}

func setupJSON(t *testing.T, value map[string]string) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
