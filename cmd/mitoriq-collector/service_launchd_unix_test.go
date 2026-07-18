//go:build !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallLaunchdRefusesSymlinkPlistWithoutTouchingTarget(t *testing.T) {
	plan := launchdTestPlan(t)
	if err := os.MkdirAll(filepath.Dir(plan.LaunchdPath), 0o755); err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(t.TempDir(), "unrelated.plist")
	targetBody := []byte("unrelated")
	if err := os.WriteFile(targetPath, targetBody, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetPath, plan.LaunchdPath); err != nil {
		t.Fatal(err)
	}
	runner := &fakeLaunchdRunner{}

	err := installLaunchd(plan, false, &bytes.Buffer{}, runner, testLaunchdUID)

	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v", err)
	}
	body, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(body, targetBody) {
		t.Fatalf("symlink target changed: %q", body)
	}
	if countCommand(runner.calls, launchctlBinaryPath, "bootstrap") != 0 {
		t.Fatalf("service was mutated: %#v", runner.calls)
	}
}

func TestInstallLaunchdRejectsNonExecutableBinaryDuringPreflight(t *testing.T) {
	plan := launchdTestPlan(t)
	if err := os.Chmod(plan.BinaryPath, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeLaunchdRunner{}

	err := installLaunchd(plan, false, &bytes.Buffer{}, runner, testLaunchdUID)

	if err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("commands executed: %#v", runner.calls)
	}
}

func TestLaunchdPlistRejectsWindowsAbsolutePathOutsideWindowsTestHost(t *testing.T) {
	plan := installPlan{BinaryPath: `C:\Program Files\Mitoriq\mitoriq-collector.exe`}
	if _, err := plan.launchdPlist(); err == nil {
		t.Fatal("Windows absolute path accepted for a macOS LaunchAgent")
	}
}
