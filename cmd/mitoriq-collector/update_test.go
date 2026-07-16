package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitoriq/collector/internal/autoupdate"
	"github.com/mitoriq/collector/internal/localconfig"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestRunUpdatePersistsStableChannelWithoutReleaseCredentials(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "collector.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"update", "--config", configPath, "--set-channel", "stable"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	config, err := (localconfig.Store{Path: configPath}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.UpdateChannel != localconfig.UpdateChannelStable {
		t.Fatalf("channel = %q", config.UpdateChannel)
	}
	if !strings.Contains(stdout.String(), "update_channel=stable") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunUpdateRejectsUnknownChannel(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"update", "--config", filepath.Join(t.TempDir(), "collector.json"), "--set-channel", "nightly"}, &stdout, &stderr)

	if code == 0 || !strings.Contains(stderr.String(), "manual or stable") {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func TestPackageManagerManagedDetectsHomebrewInstallRoots(t *testing.T) {
	if !isPackageManagerManaged("/opt/homebrew/Cellar/mitoriq-collector/1.0.0/bin/mitoriq-collector") {
		t.Fatal("expected Homebrew Cellar path to be managed")
	}
	if !isPackageManagerManaged("/opt/homebrew/Caskroom/mitoriq-collector/1.0.0/mitoriq-collector") {
		t.Fatal("expected Homebrew Caskroom path to be managed")
	}
	if isPackageManagerManaged("/Users/dev/.local/bin/mitoriq-collector") {
		t.Fatal("direct install should not be package-manager managed")
	}
}

func TestStableRollbackDisablesAutomaticChannel(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "collector.json")
	store := localconfig.Store{Path: configPath}
	if err := store.Save(localconfig.Config{UpdateChannel: localconfig.UpdateChannelStable}); err != nil {
		t.Fatal(err)
	}
	updateErr := errors.New("new binary validation failed")
	if err := disableStableAfterRollback(store, true, updateErr); !errors.Is(err, updateErr) {
		t.Fatalf("err = %v", err)
	}
	config, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.UpdateChannel != localconfig.UpdateChannelManual {
		t.Fatalf("channel = %q, want manual", config.UpdateChannel)
	}
}

func TestRollbackFailureAlsoDisablesAutomaticChannel(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "collector.json")
	store := localconfig.Store{Path: configPath}
	if err := store.Save(localconfig.Config{UpdateChannel: localconfig.UpdateChannelStable}); err != nil {
		t.Fatal(err)
	}
	updateErr := fmt.Errorf("%w: restore failed", autoupdate.ErrRollbackFailed)
	if err := disableStableAfterRollback(store, true, updateErr); !errors.Is(err, autoupdate.ErrRollbackFailed) {
		t.Fatalf("err = %v", err)
	}
	config, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.UpdateChannel != localconfig.UpdateChannelManual {
		t.Fatalf("channel = %q, want manual", config.UpdateChannel)
	}
}

func TestStableUpdateStillRequestsRestartWhenStatusOutputFails(t *testing.T) {
	updated, err := reportStableUpdateResult(autoupdate.Result{
		Updated: true,
		TagName: "v1.2.3",
	}, failingWriter{})

	if !updated {
		t.Fatal("updated = false, want true")
	}
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("err = %v, want closed pipe", err)
	}
}
