package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	calls      []recordedCommand
	failEnable bool
}

func (runner *recordingCommandRunner) Run(name string, args ...string) error {
	runner.calls = append(runner.calls, recordedCommand{name: name, args: append([]string(nil), args...)})
	if runner.failEnable && name == "systemctl" && reflect.DeepEqual(args, []string{"--user", "enable", "--now", systemdServiceName}) {
		return errors.New("enable failed")
	}

	return nil
}

func (runner *recordingCommandRunner) Output(name string, args ...string) (string, error) {
	return "", runner.Run(name, args...)
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
	}, &stdout, &stderr, "linux", runner, "ren")

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
		{name: "loginctl", args: []string{"enable-linger", "ren"}},
		{name: "systemctl", args: []string{"--user", "enable", "--now", systemdServiceName}},
	}
	if !reflect.DeepEqual(runner.calls, expectedCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, expectedCalls)
	}
	if !strings.Contains(stdout.String(), "collector_install_status=written systemd_unit="+unitPath) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunInstallForMacOSDoesNotRequireHookTools(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	binaryPath := writeExecutable(t, home, "mitoriq-collector")
	runner := &fakeLaunchdRunner{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runInstallForOS(
		[]string{"--binary", binaryPath},
		&stdout,
		&stderr,
		"darwin",
		runner,
		testLaunchdUID,
	)

	if err != nil {
		t.Fatalf("error = %v, stderr = %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "collector_install_status=running") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "_hook_command=") {
		t.Fatalf("unexpected hook output: %q", stdout.String())
	}
}

func TestRunServiceStatusForMacOSUsesStableContract(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	plan := installPlan{
		BinaryPath:  writeExecutable(t, home, "mitoriq-collector"),
		LaunchdPath: defaultLaunchdPath(),
	}
	body, err := plan.launchdPlist()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicLaunchdPlist(plan.LaunchdPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeLaunchdRunner{loaded: true, pid: 4242}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err = runServiceStatusForOS(nil, &stdout, &stderr, "darwin", runner, testLaunchdUID)

	if err != nil {
		t.Fatalf("error = %v, stderr = %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "collector_service_status=running") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunServiceStatusRejectsUnsupportedOS(t *testing.T) {
	err := runServiceStatusForOS(
		nil,
		&bytes.Buffer{},
		&bytes.Buffer{},
		"windows",
		&recordingCommandRunner{},
		"",
	)

	if err == nil || !strings.Contains(err.Error(), "unsupported operating system") {
		t.Fatalf("err = %v", err)
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
	}, &stdout, &stderr, "linux", runner, "ren")

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
	}, &stdout, &stderr, "linux", runner, "ren")

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

func TestRunInstallAndUninstallRejectUnsupportedOS(t *testing.T) {
	runner := &recordingCommandRunner{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	installErr := runInstallForOS([]string{"--tools", "claude"}, &stdout, &stderr, "windows", runner, "ren")
	if installErr == nil || !strings.Contains(installErr.Error(), "unsupported operating system") {
		t.Fatalf("install error = %v", installErr)
	}
	settingsErr := runInstallForOS([]string{
		"--binary", "/opt/mitoriq/bin/mitoriq-collector",
		"--tools", "claude",
		"--print-settings-json",
	}, &stdout, &stderr, "windows", runner, "ren")
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
