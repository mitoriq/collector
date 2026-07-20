package localconfig

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
)

func TestStoreRoundTripUses0600CollectorConfig(t *testing.T) {
	home := t.TempDir()
	store := Store{Home: home}
	expected := Config{
		APIURL:            "https://api.mitoriq.example",
		AllowInsecureHTTP: false,
		AuditLogPath:      filepath.Join(home, "audit.jsonl"),
		CursorHooksBeta:   true,
		Deny: DenyRules{
			PathGlobs:   []string{"secrets/**", "*.pem"},
			PathRegexes: []string{`(^|/)private/`},
			Repos: []RepoDenyEntry{
				{Alias: "sandbox", RemoteURLHash: "deny-hash"},
			},
		},
		MaxPrivacyLevel:     "L2",
		MachineEnrollmentID: "enrollment-1",
		MachineID:           "machine-1",
		MachineLocalUUID:    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		MemberID:            "member-1",
		OrganizationID:      "org-1",
		RepoAllowlist: []RepoAllowlistEntry{
			{Alias: "mitoriq", RemoteURLHash: "a"},
		},
		UnmappedRepoMode: "drop",
		UpdateChannel:    "stable",
	}

	if err := store.Save(expected); err != nil {
		t.Fatal(err)
	}
	actual, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("config = %#v, want %#v", actual, expected)
	}

	info, err := os.Stat(filepath.Join(home, ".config", "mitoriq", "collector.json"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
}

func TestStoreLoadsLegacyConfigWithoutMachineLocalUUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector.json")
	if err := os.WriteFile(path, []byte("{\"apiUrl\":\"https://api.example\",\"machineId\":\"machine-1\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := (Store{Path: path}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.MachineLocalUUID != "" || config.MachineID != "machine-1" {
		t.Fatalf("legacy config = %#v", config)
	}
}

func TestStoreRejectsInvalidMachineLocalUUID(t *testing.T) {
	store := Store{Home: t.TempDir()}
	if err := store.Save(Config{MachineLocalUUID: "not-a-uuid"}); err == nil {
		t.Fatal("invalid machine local UUID was saved")
	}

	path := filepath.Join(t.TempDir(), "collector.json")
	if err := os.WriteFile(path, []byte("{\"machineLocalUuid\":\"not-a-uuid\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Store{Path: path}).Load(); err == nil {
		t.Fatal("invalid machine local UUID was loaded")
	}
}

func TestStoreReportsParentDirectorySyncFailureAfterAtomicRename(t *testing.T) {
	want := errors.New("sync failed")
	store := Store{Home: t.TempDir(), syncParentDirectory: func(string) error { return want }}
	if err := store.Save(Config{}); !errors.Is(err, want) {
		t.Fatalf("Save() error = %v, want wrapped sync failure", err)
	}
	if _, err := os.Stat(store.path()); err != nil {
		t.Fatalf("atomic rename did not complete before directory sync: %v", err)
	}
}

func TestStoreLoadReturnsNotFoundForMissingConfig(t *testing.T) {
	_, err := Store{Home: t.TempDir()}.Load()

	if err == nil {
		t.Fatal("expected missing config error")
	}
	if !IsNotFound(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestStoreRejectsUnknownUpdateChannel(t *testing.T) {
	store := Store{Home: t.TempDir()}
	if err := store.Save(Config{UpdateChannel: "nightly"}); err == nil {
		t.Fatal("expected invalid update channel error")
	}
}

func TestEffectiveUpdateChannelDefaultsToManual(t *testing.T) {
	if channel := EffectiveUpdateChannel(""); channel != UpdateChannelManual {
		t.Fatalf("channel = %q, want %q", channel, UpdateChannelManual)
	}
}

func TestStoreUpdateSerializesConcurrentFieldChanges(t *testing.T) {
	store := Store{Home: t.TempDir()}
	if err := store.Save(Config{UpdateChannel: UpdateChannelStable}); err != nil {
		t.Fatal(err)
	}
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		if err := store.Update(func(config Config) (Config, error) {
			config.UpdateChannel = UpdateChannelManual
			return config, nil
		}); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		defer waitGroup.Done()
		if err := store.Update(func(config Config) (Config, error) {
			config.RepoAllowlist = []RepoAllowlistEntry{{Alias: "mitoriq", RemoteURLHash: "hash"}}
			return config, nil
		}); err != nil {
			t.Error(err)
		}
	}()
	waitGroup.Wait()

	config, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.UpdateChannel != UpdateChannelManual || len(config.RepoAllowlist) != 1 {
		t.Fatalf("config = %#v", config)
	}
}

func TestDenyPolicyMatchesRepoAndPathRules(t *testing.T) {
	policy := CompileDenyPolicy(DenyRules{
		PathGlobs:   []string{"secrets/**", "*.pem", "run-[0-9].log"},
		PathRegexes: []string{`(^|/)generated/`},
		Repos: []RepoDenyEntry{
			{Alias: "private", RemoteURLHash: "repo-hash"},
		},
	})

	if reasons := policy.InvalidReasons(); len(reasons) != 0 {
		t.Fatalf("invalid reasons = %#v", reasons)
	}
	for _, candidate := range []string{
		"repo-hash",
	} {
		if !policy.DeniesRepo(candidate) {
			t.Fatalf("repo %q should be denied", candidate)
		}
	}
	for _, candidate := range []string{
		"secrets",
		"secrets/token.txt",
		"apps/api/private-key.pem",
		"apps/generated/client.ts",
		"logs/run-7.log",
	} {
		if !policy.DeniesPath(candidate) {
			t.Fatalf("path %q should be denied", candidate)
		}
	}
	if policy.DeniesPath("apps/api/public.ts") {
		t.Fatal("public path should not be denied")
	}
}

func TestDenyPolicyFailsClosedForInvalidPatterns(t *testing.T) {
	policy := CompileDenyPolicy(DenyRules{
		PathGlobs:   []string{"["},
		PathRegexes: []string{"("},
		Repos:       []RepoDenyEntry{{}},
	})

	if !policy.DeniesAllL2() {
		t.Fatal("invalid deny policy should deny all L2+ payloads")
	}
	if !policy.DeniesRepo("any-repo") || !policy.DeniesPath("apps/api/public.ts") {
		t.Fatal("invalid deny policy should fail closed")
	}
	if reasons := policy.InvalidReasons(); len(reasons) != 3 {
		t.Fatalf("invalid reasons = %#v", reasons)
	}
}
