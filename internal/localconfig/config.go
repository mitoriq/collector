package localconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/mitoriq/collector/internal/filelock"
)

var ErrNotFound = errors.New("collector config not found")

var machineLocalUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const (
	UpdateChannelManual = "manual"
	UpdateChannelStable = "stable"
)

type RepoAllowlistEntry struct {
	Alias         string `json:"alias"`
	RemoteURLHash string `json:"remoteUrlHash"`
}

type Config struct {
	APIURL              string               `json:"apiUrl"`
	AllowInsecureHTTP   bool                 `json:"allowInsecureHttp"`
	AuditLogPath        string               `json:"auditLogPath,omitempty"`
	CursorHooksBeta     bool                 `json:"cursorHooksBeta,omitempty"`
	Deny                DenyRules            `json:"deny,omitempty"`
	MaxPrivacyLevel     string               `json:"maxPrivacyLevel,omitempty"`
	MachineEnrollmentID string               `json:"machineEnrollmentId"`
	MachineID           string               `json:"machineId"`
	MachineLocalUUID    string               `json:"machineLocalUuid,omitempty"`
	MemberID            string               `json:"memberId"`
	OrganizationID      string               `json:"organizationId"`
	RepoAllowlist       []RepoAllowlistEntry `json:"repoAllowlist,omitempty"`
	UnmappedRepoMode    string               `json:"unmappedRepoMode,omitempty"`
	UpdateChannel       string               `json:"updateChannel,omitempty"`
}

type Store struct {
	Home                string
	Path                string
	syncParentDirectory func(string) error
}

func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

func (store Store) Save(config Config) error {
	path := store.path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	return filelock.With(path+".lock", func() error {
		return saveUnlocked(path, config, store.directorySync())
	})
}

func (store Store) Update(update func(Config) (Config, error)) error {
	path := store.path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	return filelock.With(path+".lock", func() error {
		current, err := loadUnlocked(path)
		if err != nil {
			if !IsNotFound(err) {
				return err
			}
			current = Config{}
		}
		next, err := update(current)
		if err != nil {
			return err
		}

		return saveUnlocked(path, next, store.directorySync())
	})
}

func saveUnlocked(path string, config Config, syncDirectory func(string) error) error {
	if !ValidUpdateChannel(config.UpdateChannel) {
		return fmt.Errorf("updateChannel must be manual or stable")
	}
	if !ValidMachineLocalUUID(config.MachineLocalUUID) {
		return fmt.Errorf("machineLocalUuid must be a canonical UUID")
	}
	body, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	file, err := os.CreateTemp(filepath.Dir(path), ".collector-config-*")
	if err != nil {
		return fmt.Errorf("create collector config: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("secure collector config: %w", err)
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		return fmt.Errorf("write collector config: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync collector config: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close collector config: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace collector config: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync collector config directory: %w", err)
	}

	return nil
}

func (store Store) Load() (Config, error) {
	return loadUnlocked(store.path())
}

func loadUnlocked(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, fmt.Errorf("%w: %s", ErrNotFound, path)
		}

		return Config{}, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	if !ValidUpdateChannel(config.UpdateChannel) {
		return Config{}, fmt.Errorf("updateChannel must be manual or stable")
	}
	if !ValidMachineLocalUUID(config.MachineLocalUUID) {
		return Config{}, fmt.Errorf("machineLocalUuid must be a canonical UUID")
	}

	return config, nil
}

func ValidUpdateChannel(value string) bool {
	return value == "" || value == UpdateChannelManual || value == UpdateChannelStable
}

func ValidMachineLocalUUID(value string) bool {
	return value == "" || machineLocalUUIDPattern.MatchString(value)
}

func EffectiveUpdateChannel(value string) string {
	if value == "" {
		return UpdateChannelManual
	}

	return value
}

func (store Store) path() string {
	if store.Path != "" {
		return store.Path
	}

	return filepath.Join(homeDir(store.Home), ".config", "mitoriq", "collector.json")
}

func (store Store) directorySync() func(string) error {
	if store.syncParentDirectory != nil {
		return store.syncParentDirectory
	}
	return syncParentDirectory
}

func syncParentDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
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
