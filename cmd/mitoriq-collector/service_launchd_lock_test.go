//go:build !windows

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/filelock"
)

func TestInstallLaunchdWaitsForLifecycleLock(t *testing.T) {
	plan := launchdTestPlan(t)
	lockPath := launchdLifecycleLockPath(plan.LaunchdPath)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	holderReady := make(chan struct{})
	releaseHolder := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- filelock.With(lockPath, func() error {
			close(holderReady)
			<-releaseHolder
			return nil
		})
	}()
	select {
	case <-holderReady:
	case <-time.After(time.Second):
		t.Fatal("timed out acquiring launchd lifecycle lock")
	}

	runner := &fakeLaunchdRunner{}
	installDone := make(chan error, 1)
	go func() {
		installDone <- installLaunchd(plan, false, &bytes.Buffer{}, runner, testLaunchdUID)
	}()

	select {
	case err := <-installDone:
		t.Fatalf("install completed while lifecycle lock was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if len(runner.calls) != 0 {
		t.Fatalf("launchctl calls while lock was held: %#v", runner.calls)
	}
	if _, err := os.Stat(plan.LaunchdPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plist mutated while lock was held: %v", err)
	}

	close(releaseHolder)
	if err := <-holderDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-installDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("install did not continue after lifecycle lock was released")
	}
}

func TestInstallAndUninstallLaunchdSerializeLifecycle(t *testing.T) {
	plan := launchdTestPlan(t)
	lockPath := launchdLifecycleLockPath(plan.LaunchdPath)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	holderReady := make(chan struct{})
	releaseHolder := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- filelock.With(lockPath, func() error {
			close(holderReady)
			<-releaseHolder
			return nil
		})
	}()
	<-holderReady

	installRunner := &fakeLaunchdRunner{}
	uninstallRunner := &fakeLaunchdRunner{}
	installDone := make(chan error, 1)
	uninstallDone := make(chan error, 1)
	go func() {
		installDone <- installLaunchd(plan, false, &bytes.Buffer{}, installRunner, testLaunchdUID)
	}()
	go func() {
		uninstallDone <- uninstallLaunchd(plan.LaunchdPath, false, &bytes.Buffer{}, uninstallRunner, testLaunchdUID)
	}()

	select {
	case err := <-installDone:
		t.Fatalf("install completed while lifecycle lock was held: %v", err)
	case err := <-uninstallDone:
		t.Fatalf("uninstall completed while lifecycle lock was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if len(installRunner.calls) != 0 || len(uninstallRunner.calls) != 0 {
		t.Fatalf("lifecycle commands escaped lock: install=%#v uninstall=%#v", installRunner.calls, uninstallRunner.calls)
	}

	close(releaseHolder)
	if err := <-holderDone; err != nil {
		t.Fatal(err)
	}
	for completed := 0; completed < 2; completed++ {
		select {
		case err := <-installDone:
			if err != nil {
				t.Fatal(err)
			}
		case err := <-uninstallDone:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("serialized lifecycle operation did not complete")
		}
	}
}

func TestInstallLaunchdRejectsSymlinkLifecycleLockDirectory(t *testing.T) {
	plan := launchdTestPlan(t)
	lockDirectory := filepath.Dir(launchdLifecycleLockPath(plan.LaunchdPath))
	if err := os.MkdirAll(filepath.Dir(lockDirectory), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), lockDirectory); err != nil {
		t.Fatal(err)
	}
	runner := &fakeLaunchdRunner{}
	var stdout bytes.Buffer

	err := installLaunchd(plan, false, &stdout, runner, testLaunchdUID)

	if err == nil || !strings.Contains(err.Error(), "lock directory must not be a symlink") {
		t.Fatalf("err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("commands executed: %#v", runner.calls)
	}
	assertLaunchdFailurePhase(
		t,
		stdout.String(),
		"collector_service_phase=preflight status=failed reason=lifecycle_lock_failed next_action=retry_install",
	)
}

func TestInstallLaunchdRejectsSymlinkLifecycleLockFile(t *testing.T) {
	plan := launchdTestPlan(t)
	lockPath := launchdLifecycleLockPath(plan.LaunchdPath)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), lockPath); err != nil {
		t.Fatal(err)
	}
	runner := &fakeLaunchdRunner{}
	var stdout bytes.Buffer

	err := installLaunchd(plan, false, &stdout, runner, testLaunchdUID)

	if err == nil || !strings.Contains(err.Error(), "file lock") {
		t.Fatalf("err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("commands executed: %#v", runner.calls)
	}
	assertLaunchdFailurePhase(
		t,
		stdout.String(),
		"collector_service_phase=preflight status=failed reason=lifecycle_lock_failed next_action=retry_install",
	)
}
