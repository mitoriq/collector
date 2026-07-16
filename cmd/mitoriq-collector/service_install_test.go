package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestRunInstallPrintSettingsJSONForEachToolWithoutInstallingService(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	binaryPath := "/opt/mitoriq/bin/mitoriq-collector"
	tests := []struct {
		name     string
		tool     string
		expected []string
	}{
		{
			name: "claude",
			tool: "claude",
			expected: []string{
				`"SessionStart"`,
				`"PreToolUse"`,
				`"PostToolUse"`,
				`"matcher": "*"`,
				binaryPath + " claude-hook",
			},
		},
		{
			name: "codex",
			tool: "codex",
			expected: []string{
				`"UserPromptSubmit"`,
				`"PreToolUse"`,
				`"PostToolUse"`,
				`"Stop"`,
				`"matcher": "*"`,
				binaryPath + " codex-hook",
			},
		},
		{
			name: "cursor",
			tool: "cursor",
			expected: []string{
				`"version": 1`,
				`"sessionStart"`,
				`"preToolUse"`,
				`"postToolUse"`,
				`"matcher": "*"`,
				binaryPath + " cursor-hook --cursor-hooks-beta",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			runner := &recordingCommandRunner{}

			err := runInstallForOS([]string{
				"--binary", binaryPath,
				"--tools", test.tool,
				"--print-settings-json",
			}, &stdout, &stderr, "darwin", runner, "")

			if err != nil {
				t.Fatalf("error = %v, stderr = %s", err, stderr.String())
			}
			var settings map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &settings); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
			}
			for _, expected := range test.expected {
				if !strings.Contains(stdout.String(), expected) {
					t.Fatalf("stdout missing %q: %s", expected, stdout.String())
				}
			}
			if len(runner.calls) != 0 {
				t.Fatalf("service commands executed: %#v", runner.calls)
			}
			if _, err := os.Stat(defaultLaunchdPath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("launchd plist should not exist: %v", err)
			}
		})
	}
}

func TestRunInstallPrintSettingsJSONRequiresOneSupportedTool(t *testing.T) {
	for _, tools := range []string{"claude,codex", "claude,claude", "unknown"} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		err := runInstallForOS([]string{
			"--binary", "/opt/mitoriq/bin/mitoriq-collector",
			"--tools", tools,
			"--print-settings-json",
		}, &stdout, &stderr, "darwin", &recordingCommandRunner{}, "")

		if err == nil || !strings.Contains(err.Error(), "--print-settings-json requires exactly one supported tool") {
			t.Fatalf("tools = %q, err = %v", tools, err)
		}
		if stdout.Len() != 0 {
			t.Fatalf("tools = %q, stdout = %q", tools, stdout.String())
		}
	}
}

func TestRunInstallPrintSettingsJSONRejectsUnsafeBinaryPathWithoutOutput(t *testing.T) {
	for _, binaryPath := range []string{"/opt/mitoriq\ncollector", "/opt/mitoriq\rcollector", "/opt/mitoriq\x00collector"} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		err := runInstallForOS([]string{
			"--binary", binaryPath,
			"--tools", "claude",
			"--print-settings-json",
		}, &stdout, &stderr, "darwin", &recordingCommandRunner{}, "")

		if err == nil || !strings.Contains(err.Error(), "binary path contains unsupported characters") {
			t.Fatalf("binary path = %q, err = %v", binaryPath, err)
		}
		if stdout.Len() != 0 {
			t.Fatalf("binary path = %q, stdout = %q", binaryPath, stdout.String())
		}
	}
}

type recordedCommand struct {
	name string
	args []string
}

type recordingCommandRunner struct {
	mu                       sync.Mutex
	calls                    []recordedCommand
	failEnable               bool
	failLaunchdBootout       bool
	failLaunchdInspect       bool
	launchdNotLoaded         bool
	failNextLaunchdBootstrap bool
}

func (runner *recordingCommandRunner) Run(name string, args ...string) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.calls = append(runner.calls, recordedCommand{name: name, args: append([]string(nil), args...)})
	if runner.failEnable && name == "systemctl" && reflect.DeepEqual(args, []string{"--user", "enable", "--now", systemdServiceName}) {
		return errors.New("enable failed")
	}
	if runner.failLaunchdInspect && name == "launchctl" && len(args) > 0 && args[0] == "print" {
		return errors.New("launchctl: operation not permitted")
	}
	if runner.failLaunchdBootout && name == "launchctl" && len(args) > 0 && args[0] == "bootout" {
		return errors.New("bootout failed")
	}
	if runner.launchdNotLoaded && name == "launchctl" && len(args) > 0 && args[0] == "print" {
		return errors.New("launchctl: Could not find service in domain")
	}
	if name == "launchctl" && len(args) > 0 && args[0] == "bootout" {
		runner.launchdNotLoaded = true
	}
	if runner.failNextLaunchdBootstrap && name == "launchctl" && len(args) > 0 && args[0] == "bootstrap" {
		runner.failNextLaunchdBootstrap = false
		return errors.New("bootstrap failed")
	}
	if name == "launchctl" && len(args) > 0 && args[0] == "bootstrap" {
		runner.launchdNotLoaded = false
	}

	return nil
}

func (runner *recordingCommandRunner) callCount() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()

	return len(runner.calls)
}

func TestRunInstallForDarwinWritesLaunchdPlistAndBootstrapsNewService(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	runner := &recordingCommandRunner{launchdNotLoaded: true}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runInstallForOS([]string{
		"--binary", "/opt/homebrew/bin/mitoriq-collector",
		"--tools", "claude,codex",
	}, &stdout, &stderr, "darwin", runner, "501")

	if err != nil {
		t.Fatal(err)
	}
	launchdPath := filepath.Join(home, "Library", "LaunchAgents", "com.mitoriq.collector.plist")
	if _, err := os.Stat(launchdPath); err != nil {
		t.Fatal(err)
	}
	lockDirectory := filepath.Dir(defaultLaunchdLifecycleLockPath())
	lockDirectoryInfo, err := os.Lstat(lockDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if !lockDirectoryInfo.IsDir() || lockDirectoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("lock directory mode = %v, want directory 0700", lockDirectoryInfo.Mode())
	}
	lockInfo, err := os.Lstat(defaultLaunchdLifecycleLockPath())
	if err != nil {
		t.Fatal(err)
	}
	if !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("lock file mode = %v, want regular file 0600", lockInfo.Mode())
	}
	expectedCalls := []recordedCommand{
		{name: "launchctl", args: []string{"print", "gui/501/com.mitoriq.collector"}},
		{name: "launchctl", args: []string{"bootstrap", "gui/501", launchdPath}},
	}
	if !reflect.DeepEqual(runner.calls, expectedCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, expectedCalls)
	}
	if !strings.Contains(stdout.String(), "collector_install_status=written launchd_plist="+launchdPath) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunInstallForDarwinReplacesLoadedServiceBeforeBootstrap(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	launchdPath := filepath.Join(home, "Library", "LaunchAgents", "com.mitoriq.collector.plist")
	if err := os.MkdirAll(filepath.Dir(launchdPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launchdPath, []byte("old plist\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runInstallForOS([]string{
		"--binary", "/opt/homebrew/bin/mitoriq-collector",
		"--tools", "claude",
	}, &stdout, &stderr, "darwin", runner, "501")

	if err != nil {
		t.Fatal(err)
	}
	expectedCalls := []recordedCommand{
		{name: "launchctl", args: []string{"print", "gui/501/com.mitoriq.collector"}},
		{name: "launchctl", args: []string{"bootout", "gui/501/com.mitoriq.collector"}},
		{name: "launchctl", args: []string{"bootstrap", "gui/501", launchdPath}},
	}
	if !reflect.DeepEqual(runner.calls, expectedCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, expectedCalls)
	}
	body, err := os.ReadFile(launchdPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "old plist") || !strings.Contains(string(body), "/opt/homebrew/bin/mitoriq-collector") {
		t.Fatalf("plist = %q", body)
	}
}

func TestRunInstallForDarwinRestoresPreviousServiceWhenBootstrapFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	launchdPath := filepath.Join(home, "Library", "LaunchAgents", "com.mitoriq.collector.plist")
	if err := os.MkdirAll(filepath.Dir(launchdPath), 0o755); err != nil {
		t.Fatal(err)
	}
	previousPlist := []byte("old plist without trailing newline")
	if err := os.WriteFile(launchdPath, previousPlist, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{failNextLaunchdBootstrap: true}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runInstallForOS([]string{
		"--binary", "/opt/homebrew/bin/mitoriq-collector",
		"--tools", "claude",
	}, &stdout, &stderr, "darwin", runner, "501")

	if err == nil || !strings.Contains(err.Error(), "bootstrap launchd service") {
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
		{name: "launchctl", args: []string{"bootstrap", "gui/501", launchdPath}},
		{name: "launchctl", args: []string{"bootstrap", "gui/501", launchdPath}},
	}
	if !reflect.DeepEqual(runner.calls, expectedCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, expectedCalls)
	}
}

func TestRunInstallForDarwinRestoresPreviousPlistWhenBootoutFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	launchdPath := filepath.Join(home, "Library", "LaunchAgents", "com.mitoriq.collector.plist")
	if err := os.MkdirAll(filepath.Dir(launchdPath), 0o755); err != nil {
		t.Fatal(err)
	}
	previousPlist := []byte("old plist without trailing newline")
	if err := os.WriteFile(launchdPath, previousPlist, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{failLaunchdBootout: true}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runInstallForOS([]string{
		"--binary", "/opt/homebrew/bin/mitoriq-collector",
		"--tools", "claude",
	}, &stdout, &stderr, "darwin", runner, "501")

	if err == nil || !strings.Contains(err.Error(), "boot out existing launchd service") {
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
	}
	if !reflect.DeepEqual(runner.calls, expectedCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, expectedCalls)
	}
}

func TestRunInstallForDarwinRemovesNewPlistWhenInitialBootstrapFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	runner := &recordingCommandRunner{
		failNextLaunchdBootstrap: true,
		launchdNotLoaded:         true,
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runInstallForOS([]string{
		"--binary", "/opt/homebrew/bin/mitoriq-collector",
		"--tools", "claude",
	}, &stdout, &stderr, "darwin", runner, "501")

	if err == nil || !strings.Contains(err.Error(), "bootstrap launchd service") {
		t.Fatalf("err = %v", err)
	}
	launchdPath := filepath.Join(home, "Library", "LaunchAgents", "com.mitoriq.collector.plist")
	if _, statErr := os.Stat(launchdPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed new plist should be removed: %v", statErr)
	}
	expectedCalls := []recordedCommand{
		{name: "launchctl", args: []string{"print", "gui/501/com.mitoriq.collector"}},
		{name: "launchctl", args: []string{"bootstrap", "gui/501", launchdPath}},
	}
	if !reflect.DeepEqual(runner.calls, expectedCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, expectedCalls)
	}
}

func TestRunInstallForDarwinDoesNotMutatePlistWhenServiceInspectionFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	launchdPath := filepath.Join(home, "Library", "LaunchAgents", "com.mitoriq.collector.plist")
	if err := os.MkdirAll(filepath.Dir(launchdPath), 0o755); err != nil {
		t.Fatal(err)
	}
	previousPlist := []byte("old plist\n")
	if err := os.WriteFile(launchdPath, previousPlist, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{failLaunchdInspect: true}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runInstallForOS([]string{
		"--binary", "/opt/homebrew/bin/mitoriq-collector",
		"--tools", "claude",
	}, &stdout, &stderr, "darwin", runner, "501")

	if err == nil || !strings.Contains(err.Error(), "inspect launchd service") {
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
	}
	if !reflect.DeepEqual(runner.calls, expectedCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, expectedCalls)
	}
}

func TestWriteLaunchdPlistPreservesExistingFileWhenAtomicReplaceFails(t *testing.T) {
	tests := []struct {
		name      string
		configure func(launchdAtomicFileOps) launchdAtomicFileOps
	}{
		{
			name: "write",
			configure: func(ops launchdAtomicFileOps) launchdAtomicFileOps {
				ops.write = func(*os.File, []byte) error {
					return errors.New("write failed")
				}

				return ops
			},
		},
		{
			name: "rename",
			configure: func(ops launchdAtomicFileOps) launchdAtomicFileOps {
				ops.rename = func(string, string) error {
					return errors.New("rename failed")
				}

				return ops
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			launchdPath := filepath.Join(directory, "com.mitoriq.collector.plist")
			previousPlist := []byte("old plist\n")
			if err := os.WriteFile(launchdPath, previousPlist, 0o644); err != nil {
				t.Fatal(err)
			}

			err := writeLaunchdPlistWithOps(
				launchdPath,
				"new plist",
				test.configure(defaultLaunchdAtomicFileOps()),
			)
			if err == nil {
				t.Fatal("expected atomic replace failure")
			}
			body, readErr := os.ReadFile(launchdPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !reflect.DeepEqual(body, previousPlist) {
				t.Fatalf("plist = %q, want %q", body, previousPlist)
			}
			entries, readDirErr := os.ReadDir(directory)
			if readDirErr != nil {
				t.Fatal(readDirErr)
			}
			if len(entries) != 1 || entries[0].Name() != filepath.Base(launchdPath) {
				t.Fatalf("unexpected files after failed replace: %#v", entries)
			}
		})
	}
}

func TestRunInstallForLinuxWritesSystemdUserUnitAndEnablesService(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	runner := &recordingCommandRunner{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runInstallForOS([]string{
		"--binary", "/opt/mitoriq/bin/mitoriq-collector",
		"--tools", "claude,codex",
	}, &stdout, &stderr, "linux", runner, "dev")

	if err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(home, ".config", "systemd", "user", systemdServiceName)
	body, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	unit := string(body)
	for _, expected := range []string{
		`ExecStart="/opt/mitoriq/bin/mitoriq-collector" daemon`,
		"Restart=always",
		"WantedBy=default.target",
	} {
		if !strings.Contains(unit, expected) {
			t.Fatalf("unit missing %q: %s", expected, unit)
		}
	}
	expectedCalls := []recordedCommand{
		{name: "systemctl", args: []string{"--user", "daemon-reload"}},
		{name: "loginctl", args: []string{"enable-linger", "dev"}},
		{name: "systemctl", args: []string{"--user", "enable", "--now", systemdServiceName}},
	}
	if !reflect.DeepEqual(runner.calls, expectedCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, expectedCalls)
	}
	if !strings.Contains(stdout.String(), "collector_install_status=written systemd_unit="+unitPath) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunInstallForLinuxDryRunDoesNotWriteOrExecute(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	runner := &recordingCommandRunner{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runInstallForOS([]string{
		"--binary", "/opt/mitoriq/bin/mitoriq-collector",
		"--dry-run",
		"--tools", "claude",
	}, &stdout, &stderr, "linux", runner, "dev")

	if err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(home, ".config", "systemd", "user", systemdServiceName)
	if _, err := os.Stat(unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unit should not exist: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("calls = %#v", runner.calls)
	}
	if !strings.Contains(stdout.String(), "collector_install_status=planned systemd_unit="+unitPath) ||
		!strings.Contains(stdout.String(), "Restart=always") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunUninstallForLinuxDisablesServiceAndRemovesOwnedUnit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	unitPath := filepath.Join(home, ".config", "systemd", "user", systemdServiceName)
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("owned"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runUninstallForOS(nil, &stdout, &stderr, "linux", runner, "")

	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unit should be removed: %v", err)
	}
	expectedCalls := []recordedCommand{
		{name: "systemctl", args: []string{"--user", "disable", "--now", systemdServiceName}},
		{name: "systemctl", args: []string{"--user", "daemon-reload"}},
	}
	if !reflect.DeepEqual(runner.calls, expectedCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, expectedCalls)
	}
	if !strings.Contains(stdout.String(), "collector_uninstall_status=written systemd_unit="+unitPath) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunInstallForLinuxRollsBackUnitWhenEnableFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	runner := &recordingCommandRunner{failEnable: true}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runInstallForOS([]string{
		"--binary", "/opt/mitoriq/bin/mitoriq-collector",
		"--tools", "claude",
	}, &stdout, &stderr, "linux", runner, "dev")

	if err == nil || !strings.Contains(err.Error(), "enable systemd user service") {
		t.Fatalf("err = %v", err)
	}
	unitPath := filepath.Join(home, ".config", "systemd", "user", systemdServiceName)
	if _, statErr := os.Stat(unitPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unit should be rolled back: %v", statErr)
	}
	expectedTail := []recordedCommand{
		{name: "systemctl", args: []string{"--user", "disable", "--now", systemdServiceName}},
		{name: "systemctl", args: []string{"--user", "daemon-reload"}},
	}
	if !reflect.DeepEqual(runner.calls[len(runner.calls)-2:], expectedTail) {
		t.Fatalf("calls = %#v", runner.calls)
	}
}

func TestRunUninstallForDarwinBootsOutLoadedServiceBeforeRemovingPlist(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	launchdPath := filepath.Join(home, "Library", "LaunchAgents", "com.mitoriq.collector.plist")
	if err := os.MkdirAll(filepath.Dir(launchdPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launchdPath, []byte("owned plist\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runUninstallForOS(nil, &stdout, &stderr, "darwin", runner, "501")

	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(launchdPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("plist should be removed: %v", statErr)
	}
	expectedCalls := []recordedCommand{
		{name: "launchctl", args: []string{"print", "gui/501/com.mitoriq.collector"}},
		{name: "launchctl", args: []string{"bootout", "gui/501/com.mitoriq.collector"}},
		{name: "launchctl", args: []string{"print", "gui/501/com.mitoriq.collector"}},
	}
	if !reflect.DeepEqual(runner.calls, expectedCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, expectedCalls)
	}
}

func TestRunUninstallForDarwinRemovesPlistWhenServiceIsNotLoaded(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	launchdPath := filepath.Join(home, "Library", "LaunchAgents", "com.mitoriq.collector.plist")
	if err := os.MkdirAll(filepath.Dir(launchdPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launchdPath, []byte("owned plist\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{launchdNotLoaded: true}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runUninstallForOS(nil, &stdout, &stderr, "darwin", runner, "501")

	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(launchdPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("plist should be removed: %v", statErr)
	}
	expectedCalls := []recordedCommand{
		{name: "launchctl", args: []string{"print", "gui/501/com.mitoriq.collector"}},
	}
	if !reflect.DeepEqual(runner.calls, expectedCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, expectedCalls)
	}
}

func TestRunUninstallForDarwinLeavesPlistWhenInspectionOrBootoutFails(t *testing.T) {
	tests := []struct {
		name   string
		runner *recordingCommandRunner
	}{
		{
			name:   "inspect",
			runner: &recordingCommandRunner{failLaunchdInspect: true},
		},
		{
			name:   "bootout",
			runner: &recordingCommandRunner{failLaunchdBootout: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			launchdPath := filepath.Join(
				home,
				"Library",
				"LaunchAgents",
				"com.mitoriq.collector.plist",
			)
			if err := os.MkdirAll(filepath.Dir(launchdPath), 0o755); err != nil {
				t.Fatal(err)
			}
			previousPlist := []byte("owned plist\n")
			if err := os.WriteFile(launchdPath, previousPlist, 0o644); err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			err := runUninstallForOS(nil, &stdout, &stderr, "darwin", test.runner, "501")

			if err == nil {
				t.Fatal("expected uninstall failure")
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
		})
	}
}

func TestRunInstallAndUninstallRejectUnsupportedOS(t *testing.T) {
	runner := &recordingCommandRunner{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	installErr := runInstallForOS([]string{"--tools", "claude"}, &stdout, &stderr, "windows", runner, "dev")
	if installErr == nil || !strings.Contains(installErr.Error(), "unsupported operating system") {
		t.Fatalf("install error = %v", installErr)
	}
	settingsErr := runInstallForOS([]string{
		"--binary", "/opt/mitoriq/bin/mitoriq-collector",
		"--tools", "claude",
		"--print-settings-json",
	}, &stdout, &stderr, "windows", runner, "dev")
	if settingsErr == nil || !strings.Contains(settingsErr.Error(), "unsupported operating system") {
		t.Fatalf("print settings error = %v", settingsErr)
	}
	uninstallErr := runUninstallForOS(nil, &stdout, &stderr, "windows", runner, "")
	if uninstallErr == nil || !strings.Contains(uninstallErr.Error(), "unsupported operating system") {
		t.Fatalf("uninstall error = %v", uninstallErr)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("calls = %#v", runner.calls)
	}
}

func TestSystemdUserUnitEscapesExpansionAndRejectsRelativeBinary(t *testing.T) {
	unit, err := (installPlan{BinaryPath: `/opt/Mitoriq $HOME/%n/"collector"`}).systemdUserUnit()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(unit, `ExecStart="/opt/Mitoriq $$HOME/%%n/\"collector\"" daemon`) {
		t.Fatalf("unit = %q", unit)
	}
	if _, err := (installPlan{BinaryPath: "bin/mitoriq-collector"}).systemdUserUnit(); err == nil {
		t.Fatal("expected relative binary path to be rejected")
	}
}
