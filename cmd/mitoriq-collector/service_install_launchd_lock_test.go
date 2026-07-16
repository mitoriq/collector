package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mitoriq/collector/internal/filelock"
)

type blockingCommandRunner struct {
	*recordingCommandRunner
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingCommandRunner(isLoaded bool) *blockingCommandRunner {
	return &blockingCommandRunner{
		recordingCommandRunner: &recordingCommandRunner{launchdNotLoaded: !isLoaded},
		entered:                make(chan struct{}),
		release:                make(chan struct{}),
	}
}

func (runner *blockingCommandRunner) Run(name string, args ...string) error {
	runner.once.Do(func() {
		close(runner.entered)
		<-runner.release
	})

	return runner.recordingCommandRunner.Run(name, args...)
}

type launchdVerificationRunner struct {
	mu              sync.Mutex
	calls           []recordedCommand
	verificationErr error
}

func (runner *launchdVerificationRunner) Run(name string, args ...string) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.calls = append(runner.calls, recordedCommand{name: name, args: append([]string(nil), args...)})
	if name != "launchctl" || len(args) == 0 {
		return nil
	}
	if args[0] == "print" && len(runner.calls) >= 3 && runner.verificationErr != nil {
		return runner.verificationErr
	}

	return nil
}

func TestRunInstallForDarwinWaitsForLifecycleLock(t *testing.T) {
	setTestUserHome(t)
	lockPath := defaultLaunchdLifecycleLockPath()
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

	runner := &recordingCommandRunner{launchdNotLoaded: true}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	installStarted := make(chan struct{})
	installDone := make(chan error, 1)
	go func() {
		close(installStarted)
		installDone <- runInstallForOS([]string{
			"--binary", "/opt/homebrew/bin/mitoriq-collector",
			"--tools", "claude",
		}, &stdout, &stderr, "darwin", runner, "501")
	}()
	<-installStarted

	select {
	case err := <-installDone:
		t.Fatalf("install completed while lifecycle lock was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if count := runner.callCount(); count != 0 {
		t.Fatalf("launchctl calls while lifecycle lock was held = %d, want 0", count)
	}
	if _, err := os.Stat(defaultLaunchdPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("launchd plist was mutated while lifecycle lock was held: %v", err)
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

func TestRunInstallAndUninstallForDarwinSerializeLifecycle(t *testing.T) {
	setTestUserHome(t)
	installRunner := newBlockingCommandRunner(false)
	uninstallRunner := &recordingCommandRunner{launchdNotLoaded: true}
	var installStdout bytes.Buffer
	var installStderr bytes.Buffer
	var uninstallStdout bytes.Buffer
	var uninstallStderr bytes.Buffer
	installDone := make(chan error, 1)
	go func() {
		installDone <- runInstallForOS([]string{
			"--binary", "/opt/homebrew/bin/mitoriq-collector",
			"--tools", "claude",
		}, &installStdout, &installStderr, "darwin", installRunner, "501")
	}()
	select {
	case <-installRunner.entered:
	case <-time.After(time.Second):
		t.Fatal("install did not enter launchd lifecycle")
	}

	uninstallStarted := make(chan struct{})
	uninstallDone := make(chan error, 1)
	go func() {
		close(uninstallStarted)
		uninstallDone <- runUninstallForOS(
			nil,
			&uninstallStdout,
			&uninstallStderr,
			"darwin",
			uninstallRunner,
			"501",
		)
	}()
	<-uninstallStarted
	select {
	case err := <-uninstallDone:
		t.Fatalf("uninstall completed while install lifecycle was active: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if count := uninstallRunner.callCount(); count != 0 {
		t.Fatalf("uninstall launchctl calls during install lifecycle = %d, want 0", count)
	}

	close(installRunner.release)
	if err := <-installDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-uninstallDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("uninstall did not continue after install lifecycle completed")
	}
	if _, err := os.Stat(defaultLaunchdPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final launchd plist should be absent after serialized uninstall: %v", err)
	}
}

func TestRunInstallForDarwinRejectsSymlinkLifecycleLockDirectory(t *testing.T) {
	setTestUserHome(t)
	lockDirectory := filepath.Dir(defaultLaunchdLifecycleLockPath())
	if err := os.MkdirAll(filepath.Dir(lockDirectory), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), lockDirectory); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{launchdNotLoaded: true}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runInstallForOS([]string{
		"--binary", "/opt/homebrew/bin/mitoriq-collector",
		"--tools", "claude",
	}, &stdout, &stderr, "darwin", runner, "501")

	if err == nil || !strings.Contains(err.Error(), "launchd lifecycle lock directory must not be a symlink") {
		t.Fatalf("err = %v", err)
	}
	if count := runner.callCount(); count != 0 {
		t.Fatalf("launchctl calls = %d, want 0", count)
	}
	if _, statErr := os.Stat(defaultLaunchdPath()); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("launchd plist should not be mutated: %v", statErr)
	}
}

func TestRunInstallForDarwinRejectsSymlinkLifecycleLockFile(t *testing.T) {
	setTestUserHome(t)
	lockPath := defaultLaunchdLifecycleLockPath()
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "lock-target"), lockPath); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{launchdNotLoaded: true}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runInstallForOS([]string{
		"--binary", "/opt/homebrew/bin/mitoriq-collector",
		"--tools", "claude",
	}, &stdout, &stderr, "darwin", runner, "501")

	if err == nil ||
		(!strings.Contains(err.Error(), "open file lock: too many levels of symbolic links") &&
			!strings.Contains(err.Error(), "file lock must not be a symlink")) {
		t.Fatalf("err = %v", err)
	}
	if count := runner.callCount(); count != 0 {
		t.Fatalf("launchctl calls = %d, want 0", count)
	}
	if _, statErr := os.Stat(defaultLaunchdPath()); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("launchd plist should not be mutated: %v", statErr)
	}
}

func TestRunUninstallForDarwinLeavesPlistWhenServiceRemainsLoadedAfterBootout(t *testing.T) {
	home := setTestUserHome(t)
	launchdPath := filepath.Join(home, "Library", "LaunchAgents", "com.mitoriq.collector.plist")
	if err := os.MkdirAll(filepath.Dir(launchdPath), 0o755); err != nil {
		t.Fatal(err)
	}
	previousPlist := []byte("owned plist\n")
	if err := os.WriteFile(launchdPath, previousPlist, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &launchdVerificationRunner{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runUninstallForOS(nil, &stdout, &stderr, "darwin", runner, "501")

	if err == nil || !strings.Contains(err.Error(), "launchd service remains loaded after bootout") {
		t.Fatalf("err = %v", err)
	}
	body, readErr := os.ReadFile(launchdPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(body, previousPlist) {
		t.Fatalf("plist = %q, want %q", body, previousPlist)
	}
	expectedCalls := []recordedCommand{
		{name: "launchctl", args: []string{"print", "gui/501/com.mitoriq.collector"}},
		{name: "launchctl", args: []string{"bootout", "gui/501/com.mitoriq.collector"}},
		{name: "launchctl", args: []string{"print", "gui/501/com.mitoriq.collector"}},
	}
	if !reflect.DeepEqual(runner.calls, expectedCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, expectedCalls)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunUninstallForDarwinLeavesPlistWhenPostBootoutInspectionFails(t *testing.T) {
	home := setTestUserHome(t)
	launchdPath := filepath.Join(home, "Library", "LaunchAgents", "com.mitoriq.collector.plist")
	if err := os.MkdirAll(filepath.Dir(launchdPath), 0o755); err != nil {
		t.Fatal(err)
	}
	previousPlist := []byte("owned plist\n")
	if err := os.WriteFile(launchdPath, previousPlist, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &launchdVerificationRunner{
		verificationErr: errors.New("launchctl: operation not permitted"),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runUninstallForOS(nil, &stdout, &stderr, "darwin", runner, "501")

	if err == nil || !strings.Contains(err.Error(), "verify launchd service unloaded after bootout") {
		t.Fatalf("err = %v", err)
	}
	body, readErr := os.ReadFile(launchdPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(body, previousPlist) {
		t.Fatalf("plist = %q, want %q", body, previousPlist)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
}
