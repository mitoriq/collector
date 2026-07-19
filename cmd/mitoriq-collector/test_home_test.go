package main

import (
	"os"
	"path/filepath"
	"testing"
)

func setTestUserHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

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
	if actual := launchdLifecycleLockPath(defaultLaunchdPath()); actual != expectedLock {
		t.Fatalf("launchd lock path = %q, want %q", actual, expectedLock)
	}
}
