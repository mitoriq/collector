package deviceauth

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/mitoriq/collector/internal/localconfig"
)

const journalVersion = 1

var ErrJournalNotFound = errors.New("device authorization journal not found")

type Progress string

const (
	ProgressStarted  Progress = "started"
	ProgressEnvelope Progress = "envelope_saved"
	ProgressToken    Progress = "token_saved"
	ProgressConfig   Progress = "config_saved"
)

type JournalState struct {
	Version       int       `json:"version"`
	DeviceCode    string    `json:"deviceCode"`
	UserCode      string    `json:"userCode"`
	PrivateKeyPEM string    `json:"privateKeyPem"`
	LocalUUID     string    `json:"localUuid"`
	Progress      Progress  `json:"progress"`
	Interval      int       `json:"interval"`
	ExpiresAt     int64     `json:"expiresAt"`
	Envelope      *Envelope `json:"envelope,omitempty"`
}

type JournalStore struct {
	Path       string
	afterOpen  func()
	syncParent func(string) error
}

func (store JournalStore) Save(state JournalState) error {
	if !validJournal(state) || store.Path == "" {
		return errors.New("invalid device authorization journal")
	}
	if err := os.MkdirAll(filepath.Dir(store.Path), 0o700); err != nil {
		return errors.New("create device authorization journal directory")
	}
	body, err := json.Marshal(state)
	if err != nil {
		return errors.New("encode device authorization journal")
	}
	file, err := os.CreateTemp(filepath.Dir(store.Path), ".device-authorization-*")
	if err != nil {
		return errors.New("create device authorization journal")
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return errors.New("secure device authorization journal")
	}
	if writeSyncClose(file, body) != nil || os.Rename(temporaryPath, store.Path) != nil {
		return errors.New("save device authorization journal")
	}
	syncParent := store.syncParent
	if syncParent == nil {
		syncParent = syncParentDirectory
	}
	if syncParent(filepath.Dir(store.Path)) != nil {
		return errors.New("save device authorization journal")
	}
	return nil
}

func syncParentDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return err
	}
	return directory.Close()
}

func writeSyncClose(file *os.File, body []byte) error {
	if _, err := file.Write(body); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func (store JournalStore) Load() (JournalState, error) {
	file, err := openJournalFile(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return JournalState{}, ErrJournalNotFound
	}
	if err != nil {
		return JournalState{}, errors.New("open device authorization journal")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !isSecureJournalFileInfo(openedInfo) {
		return JournalState{}, errors.New("insecure device authorization journal")
	}
	if store.afterOpen != nil {
		store.afterOpen()
	}
	currentFile, err := openJournalFile(store.Path)
	if err != nil {
		return JournalState{}, errors.New("insecure device authorization journal")
	}
	currentInfo, statErr := currentFile.Stat()
	closeErr := currentFile.Close()
	if statErr != nil || closeErr != nil || !isSecureJournalFileInfo(currentInfo) || !os.SameFile(openedInfo, currentInfo) {
		return JournalState{}, errors.New("insecure device authorization journal")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var state JournalState
	if decoder.Decode(&state) != nil || !validJournal(state) {
		return JournalState{}, errors.New("invalid device authorization journal")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return JournalState{}, errors.New("invalid device authorization journal")
	}
	return state, nil
}

func isSecureJournalFileInfo(info os.FileInfo) bool {
	return info.Mode().IsRegular() && (runtime.GOOS == "windows" || info.Mode().Perm() == 0o600)
}

func (store JournalStore) Remove() error {
	if err := os.Remove(store.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("remove device authorization journal")
	}
	return nil
}

func validJournal(state JournalState) bool {
	validProgress := state.Progress == ProgressStarted || state.Progress == ProgressEnvelope || state.Progress == ProgressToken || state.Progress == ProgressConfig
	needsEnvelope := state.Progress != ProgressStarted
	return state.Version == journalVersion && state.DeviceCode != "" && state.UserCode != "" && state.PrivateKeyPEM != "" && state.LocalUUID != "" && localconfig.ValidMachineLocalUUID(state.LocalUUID) && state.Interval > 0 && state.ExpiresAt > 0 && validProgress && (!needsEnvelope || state.Envelope != nil)
}
