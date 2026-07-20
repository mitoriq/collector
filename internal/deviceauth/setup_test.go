package deviceauth

import (
	"context"
	"crypto/rsa"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/enroll"
	"github.com/mitoriq/collector/internal/localconfig"
)

type fakeProtocol struct {
	startCount   int
	startRequest StartRequest
	polls        []PollResponse
	completeErr  error
	envelope     Envelope
}

func (fake *fakeProtocol) Start(_ context.Context, request StartRequest) (StartResponse, error) {
	fake.startRequest = request
	fake.startCount++
	return StartResponse{DeviceCode: "device-secret", UserCode: "ABCD", ExpiresIn: 60, Interval: 1}, nil
}
func (fake *fakeProtocol) Poll(context.Context, PollRequest) (PollResponse, error) {
	response := fake.polls[0]
	fake.polls = fake.polls[1:]
	return response, nil
}
func (fake *fakeProtocol) Complete(context.Context, CompleteRequest) (CompleteResponse, error) {
	if fake.completeErr != nil {
		return CompleteResponse{}, fake.completeErr
	}
	return CompleteResponse{Status: "enrolled"}, nil
}

type fakeTokens struct {
	token   string
	saveErr error
}

func (fake *fakeTokens) SaveForEnrollment(_ context.Context, record enroll.EnrollmentTokenRecord) (enroll.SaveResult, error) {
	if fake.saveErr == nil {
		fake.token = record.Token
	}
	return enroll.SaveResult{}, fake.saveErr
}
func (fake *fakeTokens) LoadForOrganization(context.Context, string) (string, error) {
	return fake.token, nil
}

type fakeConfig struct {
	value     localconfig.Config
	updateErr error
}

func (fake *fakeConfig) Update(update func(localconfig.Config) (localconfig.Config, error)) error {
	if fake.updateErr != nil {
		return fake.updateErr
	}
	next, err := update(fake.value)
	fake.value = next
	return err
}
func (fake *fakeConfig) Load() (localconfig.Config, error) { return fake.value, nil }

func TestSetupFailsWindowsBeforeSideEffects(t *testing.T) {
	protocol := &fakeProtocol{}
	setup := Setup{GOOS: "windows", Protocol: protocol, Preflight: func(context.Context, string) error { t.Fatal("preflight called"); return nil }}
	if err := setup.Run(context.Background()); !errors.Is(err, ErrUnsupportedPlatform) || protocol.startCount != 0 {
		t.Fatalf("err=%v starts=%d", err, protocol.startCount)
	}
}

func TestSetupMapsDarwinToMacOSBeforeNetwork(t *testing.T) {
	protocol := &fakeProtocol{polls: []PollResponse{{Status: StatusExpiredToken}}}
	setup := testSetup(t, protocol, &fakeTokens{}, &fakeConfig{})
	setup.GOOS = "darwin"
	var preflightPlatform string
	setup.Preflight = func(_ context.Context, platform string) error { preflightPlatform = platform; return nil }
	if err := setup.Run(context.Background()); err == nil {
		t.Fatal("terminal response was ignored")
	}
	if preflightPlatform != "macos" || protocol.startRequest.Preflight.Platform != "macos" || protocol.startRequest.Machine.OS != "macos" {
		t.Fatalf("preflight=%q request=%#v", preflightPlatform, protocol.startRequest)
	}
}

func TestSetupResumesSameEnrollmentAfterLocalAndACKFailures(t *testing.T) {
	const originalLocalUUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	for _, point := range []string{"token", "config", "ack"} {
		t.Run(point, func(t *testing.T) {
			privateKey, publicKey := generateKey(t)
			enrollment := enroll.EnrollResponse{EnrollmentToken: "token-secret", MachineEnrollmentID: "11111111-1111-4111-8111-111111111111", MachineID: "22222222-2222-4222-8222-222222222222", MemberID: "33333333-3333-4333-8333-333333333333", OrganizationID: "44444444-4444-4444-8444-444444444444", TokenPrefix: "prefix"}
			protocol := &fakeProtocol{polls: []PollResponse{{Status: StatusAuthorized, Envelope: ptrEnvelope(sealEnvelope(t, &privateKey.PublicKey, enrollment))}, {Status: StatusEnrolled}}}
			tokens, config := &fakeTokens{}, &fakeConfig{}
			setup := testSetup(t, protocol, tokens, config)
			setup.GenerateKey = func() (*rsa.PrivateKey, string, error) { return privateKey, publicKey, nil }
			switch point {
			case "token":
				tokens.saveErr = errors.New("fail")
			case "config":
				config.updateErr = errors.New("fail")
			case "ack":
				protocol.completeErr = errors.New("lost")
			}
			if err := setup.Run(context.Background()); err == nil {
				t.Fatal("failure was ignored")
			}
			setup.LocalUUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			tokens.saveErr, config.updateErr, protocol.completeErr = nil, nil, nil
			if err := setup.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if protocol.startCount != 1 || tokens.token != enrollment.EnrollmentToken || config.value.MachineID != enrollment.MachineID || config.value.MachineLocalUUID != originalLocalUUID {
				t.Fatal("same enrollment was not resumed")
			}
			if _, err := setup.Journal.Load(); !errors.Is(err, ErrJournalNotFound) {
				t.Fatal("journal remains")
			}
		})
	}
}

func TestSetupDiscardsACKGraceJournalBeforeStartingFreshAuthorization(t *testing.T) {
	for _, terminalStatus := range []Status{StatusExpiredToken, StatusAccessDenied} {
		t.Run(string(terminalStatus), func(t *testing.T) {
			privateKey, publicKey := generateKey(t)
			enrollment := enroll.EnrollResponse{EnrollmentToken: "token-secret", MachineEnrollmentID: "11111111-1111-4111-8111-111111111111", MachineID: "22222222-2222-4222-8222-222222222222", MemberID: "33333333-3333-4333-8333-333333333333", OrganizationID: "44444444-4444-4444-8444-444444444444", TokenPrefix: "prefix"}
			protocol := &fakeProtocol{
				polls:       []PollResponse{{Status: StatusAuthorized, Envelope: ptrEnvelope(sealEnvelope(t, &privateKey.PublicKey, enrollment))}, {Status: terminalStatus}, {Status: terminalStatus}},
				completeErr: errors.New("ack lost"),
			}
			setup := testSetup(t, protocol, &fakeTokens{}, &fakeConfig{})
			setup.GenerateKey = func() (*rsa.PrivateKey, string, error) { return privateKey, publicKey, nil }
			firstErr := setup.Run(context.Background())
			if firstErr == nil {
				t.Fatal("ACK failure was ignored")
			}
			state, err := setup.Journal.Load()
			if err != nil || state.Progress != ProgressConfig {
				t.Fatalf("first attempt did not reach ACK grace: runErr=%v state=%#v loadErr=%v", firstErr, state, err)
			}
			protocol.completeErr = nil
			if err := setup.Run(context.Background()); err == nil {
				t.Fatal("terminal ACK grace response was ignored")
			}
			if _, err := setup.Journal.Load(); !errors.Is(err, ErrJournalNotFound) {
				t.Fatalf("terminal ACK grace journal remains: %v", err)
			}
			if err := setup.Run(context.Background()); err == nil {
				t.Fatal("fresh terminal authorization response was ignored")
			}
			if protocol.startCount != 2 {
				t.Fatalf("start count = %d, want fresh authorization", protocol.startCount)
			}
		})
	}
}

func TestSetupRejectsUnsafeOrganizationIDBeforeCredentialPersistence(t *testing.T) {
	privateKey, publicKey := generateKey(t)
	enrollment := enroll.EnrollResponse{EnrollmentToken: "token-secret", MachineEnrollmentID: "11111111-1111-4111-8111-111111111111", MachineID: "22222222-2222-4222-8222-222222222222", MemberID: "33333333-3333-4333-8333-333333333333", OrganizationID: "../../escape", TokenPrefix: "prefix"}
	protocol := &fakeProtocol{polls: []PollResponse{{Status: StatusAuthorized, Envelope: ptrEnvelope(sealEnvelope(t, &privateKey.PublicKey, enrollment))}}}
	tokens := &fakeTokens{}
	setup := testSetup(t, protocol, tokens, &fakeConfig{})
	setup.GenerateKey = func() (*rsa.PrivateKey, string, error) { return privateKey, publicKey, nil }
	if err := setup.Run(context.Background()); err == nil || tokens.token != "" {
		t.Fatalf("err=%v token_saved=%t", err, tokens.token != "")
	}
}

func TestSetupHonorsSlowDownAndRemovesExpiredJournal(t *testing.T) {
	protocol := &fakeProtocol{polls: []PollResponse{{Status: StatusSlowDown}, {Status: StatusExpiredToken}}}
	setup := testSetup(t, protocol, &fakeTokens{}, &fakeConfig{})
	var sleeps []time.Duration
	setup.Sleep = func(_ context.Context, duration time.Duration) error { sleeps = append(sleeps, duration); return nil }
	if err := setup.Run(context.Background()); err == nil {
		t.Fatal("expiry was ignored")
	}
	if len(sleeps) != 2 || sleeps[0] != time.Second || sleeps[1] != 6*time.Second {
		t.Fatalf("sleeps=%v", sleeps)
	}
	if _, err := setup.Journal.Load(); !errors.Is(err, ErrJournalNotFound) {
		t.Fatal("expired journal remains")
	}
}

func testSetup(t *testing.T, protocol *fakeProtocol, tokens *fakeTokens, config *fakeConfig) Setup {
	t.Helper()
	return Setup{GOOS: "linux", APIURL: "https://api.example", DisplayName: "host", LocalUUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Protocol: protocol, Tokens: tokens, Config: config,
		Journal: JournalStore{Path: filepath.Join(t.TempDir(), "journal.json")}, Preflight: func(context.Context, string) error { return nil }, Sleep: func(context.Context, time.Duration) error { return nil }}
}
func ptrEnvelope(value Envelope) *Envelope { return &value }
