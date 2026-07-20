package deviceauth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"regexp"
	"runtime"
	"time"

	"github.com/mitoriq/collector/internal/enroll"
	"github.com/mitoriq/collector/internal/localconfig"
)

var ErrUnsupportedPlatform = errors.New("このOSではsetupを利用できません")

var canonicalUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Protocol interface {
	Start(context.Context, StartRequest) (StartResponse, error)
	Poll(context.Context, PollRequest) (PollResponse, error)
	Complete(context.Context, CompleteRequest) (CompleteResponse, error)
}
type TokenStore interface {
	SaveForEnrollment(context.Context, enroll.EnrollmentTokenRecord) (enroll.SaveResult, error)
	LoadForOrganization(context.Context, string) (string, error)
}
type ConfigStore interface {
	Update(func(localconfig.Config) (localconfig.Config, error)) error
	Load() (localconfig.Config, error)
}

type Setup struct {
	GOOS, APIURL, DisplayName, LocalUUID, CollectorVersion string
	Protocol                                               Protocol
	Tokens                                                 TokenStore
	Config                                                 ConfigStore
	Journal                                                JournalStore
	Preflight                                              func(context.Context, string) error
	Challenge                                              func(string, time.Time) error
	GenerateKey                                            func() (*rsa.PrivateKey, string, error)
	Now                                                    func() time.Time
	Sleep                                                  func(context.Context, time.Duration) error
}

func (setup Setup) Run(ctx context.Context) error {
	platform := setup.GOOS
	if platform == "" {
		platform = runtime.GOOS
	}
	if platform == "darwin" {
		platform = "macos"
	}
	if platform == "windows" {
		return ErrUnsupportedPlatform
	}
	if (platform != "macos" && platform != "linux") || setup.Protocol == nil || setup.Tokens == nil || setup.Config == nil || setup.Preflight == nil {
		return errors.New("setup configuration is invalid")
	}
	if setup.Preflight(ctx, platform) != nil {
		return errors.New("setup preflight failed")
	}
	state, privateKey, resumed, err := setup.loadOrStart(ctx, platform)
	if err != nil {
		return err
	}
	if setup.Challenge != nil && setup.Challenge(state.UserCode, time.Unix(state.ExpiresAt, 0)) != nil {
		return errors.New("setup challenge failed")
	}
	if resumed && state.Progress == ProgressConfig {
		response, pollErr := setup.Protocol.Poll(ctx, PollRequest{DeviceCode: state.DeviceCode, CollectorVersion: setup.CollectorVersion})
		if pollErr != nil {
			return errors.New("device authorization poll failed")
		}
		switch response.Status {
		case StatusEnrolled:
			if setup.verifyLocal(ctx, state, privateKey) != nil {
				return errors.New("local enrollment state is incomplete")
			}
			return setup.Journal.Remove()
		case StatusExpiredToken, StatusAccessDenied:
			if setup.Journal.Remove() != nil {
				return errors.New("remove ended setup progress failed")
			}
			return errors.New("device authorization ended")
		}
	}
	if state.Envelope == nil && setup.poll(ctx, &state) != nil {
		return errors.New("device authorization did not complete")
	}
	enrollment, err := DecryptEnrollmentEnvelope(privateKey, *state.Envelope)
	if err != nil || !validEnrollmentIdentifiers(enrollment) {
		return errors.New("invalid enrollment envelope")
	}
	if state.Progress == ProgressEnvelope {
		if _, err := setup.Tokens.SaveForEnrollment(ctx, enroll.EnrollmentTokenRecord{OrganizationID: enrollment.OrganizationID, Token: enrollment.EnrollmentToken}); err != nil {
			return errors.New("save enrollment credential failed")
		}
		state.Progress = ProgressToken
		if setup.Journal.Save(state) != nil {
			return errors.New("save setup progress failed")
		}
	}
	if state.Progress == ProgressToken {
		if setup.saveConfig(enrollment, state.LocalUUID) != nil {
			return errors.New("save collector configuration failed")
		}
		state.Progress = ProgressConfig
		if setup.Journal.Save(state) != nil {
			return errors.New("save setup progress failed")
		}
	}
	if _, err := setup.Protocol.Complete(ctx, CompleteRequest{DeviceCode: state.DeviceCode}); err != nil {
		return errors.New("complete device authorization failed")
	}
	return setup.Journal.Remove()
}

func (setup Setup) loadOrStart(ctx context.Context, platform string) (JournalState, *rsa.PrivateKey, bool, error) {
	state, err := setup.Journal.Load()
	if err == nil {
		key, keyErr := parsePrivateKey(state.PrivateKeyPEM)
		return state, key, true, keyErr
	}
	if !errors.Is(err, ErrJournalNotFound) {
		return JournalState{}, nil, false, errors.New("load setup progress failed")
	}
	if setup.LocalUUID == "" || !localconfig.ValidMachineLocalUUID(setup.LocalUUID) {
		return JournalState{}, nil, false, errors.New("machine local UUID is invalid")
	}
	generateKey := setup.GenerateKey
	if generateKey == nil {
		generateKey = GenerateEphemeralKey
	}
	key, publicKey, err := generateKey()
	if err != nil {
		return JournalState{}, nil, false, errors.New("generate setup key failed")
	}
	request := StartRequest{PublicKey: publicKey, Preflight: Preflight{ConfigWritable: true, CredentialWritable: true, JournalWritable: true, Platform: platform}, Machine: Machine{DisplayName: setup.DisplayName, LocalUUID: setup.LocalUUID, OS: platform}}
	started, err := setup.Protocol.Start(ctx, request)
	if err != nil {
		return JournalState{}, nil, false, errors.New("start device authorization failed")
	}
	state = JournalState{Version: journalVersion, DeviceCode: started.DeviceCode, UserCode: started.UserCode, PrivateKeyPEM: encodePrivateKey(key), LocalUUID: setup.LocalUUID, Progress: ProgressStarted, Interval: started.Interval, ExpiresAt: setup.now().Add(time.Duration(started.ExpiresIn) * time.Second).Unix()}
	if setup.Journal.Save(state) != nil {
		return JournalState{}, nil, false, errors.New("save setup progress failed")
	}
	return state, key, false, nil
}

func (setup Setup) poll(ctx context.Context, state *JournalState) error {
	for state.Envelope == nil {
		if !setup.now().Before(time.Unix(state.ExpiresAt, 0)) {
			_ = setup.Journal.Remove()
			return errors.New("device authorization expired")
		}
		if setup.sleep(ctx, time.Duration(state.Interval)*time.Second) != nil {
			return errors.New("device authorization interrupted")
		}
		response, err := setup.Protocol.Poll(ctx, PollRequest{DeviceCode: state.DeviceCode, CollectorVersion: setup.CollectorVersion})
		if err != nil {
			return errors.New("device authorization poll failed")
		}
		switch response.Status {
		case StatusAuthorizationPending:
			if response.Interval > 0 {
				state.Interval = response.Interval
			}
		case StatusSlowDown:
			if response.Interval > state.Interval {
				state.Interval = response.Interval
			} else {
				state.Interval += 5
			}
			if setup.Journal.Save(*state) != nil {
				return errors.New("save setup progress failed")
			}
		case StatusAuthorized:
			state.Envelope, state.Progress = response.Envelope, ProgressEnvelope
			return setup.Journal.Save(*state)
		case StatusExpiredToken, StatusAccessDenied:
			_ = setup.Journal.Remove()
			return errors.New("device authorization ended")
		default:
			return errors.New("unexpected device authorization state")
		}
	}
	return nil
}

func (setup Setup) saveConfig(value enroll.EnrollResponse, localUUID string) error {
	return setup.Config.Update(func(config localconfig.Config) (localconfig.Config, error) {
		config.APIURL, config.MachineEnrollmentID, config.MachineID = setup.APIURL, value.MachineEnrollmentID, value.MachineID
		config.MachineLocalUUID = localUUID
		config.MemberID, config.OrganizationID = value.MemberID, value.OrganizationID
		return config, nil
	})
}

func (setup Setup) verifyLocal(ctx context.Context, state JournalState, key *rsa.PrivateKey) error {
	value, err := DecryptEnrollmentEnvelope(key, *state.Envelope)
	if err != nil || !validEnrollmentIdentifiers(value) {
		return errors.New("invalid enrollment envelope")
	}
	token, tokenErr := setup.Tokens.LoadForOrganization(ctx, value.OrganizationID)
	config, configErr := setup.Config.Load()
	if tokenErr != nil || configErr != nil || token != value.EnrollmentToken || config.MachineID != value.MachineID || config.MachineEnrollmentID != value.MachineEnrollmentID || config.MachineLocalUUID != state.LocalUUID || config.OrganizationID != value.OrganizationID {
		return errors.New("local enrollment state mismatch")
	}
	return nil
}

func validEnrollmentIdentifiers(value enroll.EnrollResponse) bool {
	return canonicalUUIDPattern.MatchString(value.MachineEnrollmentID) && canonicalUUIDPattern.MatchString(value.MachineID) &&
		canonicalUUIDPattern.MatchString(value.MemberID) && canonicalUUIDPattern.MatchString(value.OrganizationID)
}

func (setup Setup) now() time.Time {
	if setup.Now != nil {
		return setup.Now()
	}
	return time.Now()
}
func (setup Setup) sleep(ctx context.Context, duration time.Duration) error {
	if setup.Sleep != nil {
		return setup.Sleep(ctx, duration)
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func encodePrivateKey(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}
func parsePrivateKey(value string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid setup key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid setup key")
	}
	return key, nil
}
