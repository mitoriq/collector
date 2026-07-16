package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mitoriq/collector/internal/localaudit"
)

func setTestUserHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))

	return home
}

func TestSetTestUserHomeControlsOSUserHomeDirAndLaunchdPaths(t *testing.T) {
	home := setTestUserHome(t)

	resolvedHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(resolvedHome) != filepath.Clean(home) {
		t.Fatalf("resolved home = %q, want %q", resolvedHome, home)
	}
	expectedAuditPath := filepath.Join(home, ".local", "state", "mitoriq", "collector-audit.jsonl")
	if actual := (localaudit.Store{}).ResolvedPath(); actual != expectedAuditPath {
		t.Fatalf("audit path = %q, want %q", actual, expectedAuditPath)
	}
	expectedPlist := filepath.Join(home, "Library", "LaunchAgents", launchdServiceLabel+".plist")
	if actual := defaultLaunchdPath(); actual != expectedPlist {
		t.Fatalf("launchd path = %q, want %q", actual, expectedPlist)
	}
	expectedLock := filepath.Join(
		home,
		"Library",
		"Application Support",
		launchdLifecycleLockDirectory,
		launchdLifecycleLockFileName,
	)
	if actual := defaultLaunchdLifecycleLockPath(); actual != expectedLock {
		t.Fatalf("launchd lock path = %q, want %q", actual, expectedLock)
	}
}
