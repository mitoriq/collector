package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testLaunchdUID = "501"

type fakeLaunchdRunner struct {
	bootoutPending        bool
	bootoutVisibleQueries int
	calls                 []recordedCommand
	failures              map[string][]error
	loaded                bool
	missingPlistWhileLive bool
	observedPlistPath     string
	pid                   int
	serviceOutput         string
	serviceOutputs        []string
}

func (runner *fakeLaunchdRunner) Run(name string, args ...string) error {
	runner.record(name, args...)
	if err := runner.nextFailure(name, args...); err != nil {
		return err
	}
	if name != launchctlBinaryPath || len(args) == 0 {
		return nil
	}

	switch args[0] {
	case "bootstrap":
		if runner.loaded {
			return errors.New("service is already loaded")
		}
		runner.loaded = true
	case "bootout":
		if !runner.loaded {
			return errors.New("Could not find service")
		}
		if runner.bootoutVisibleQueries > 0 {
			runner.bootoutPending = true
		} else {
			runner.loaded = false
		}
	case "kickstart":
		if !runner.loaded {
			return errors.New("service is not loaded")
		}
		if runner.pid == 0 {
			runner.pid = 4242
		} else {
			runner.pid++
		}
	}

	return nil
}

func (runner *fakeLaunchdRunner) Output(name string, args ...string) (string, error) {
	runner.record(name, args...)
	if err := runner.nextFailure(name, args...); err != nil {
		return "", err
	}
	if name != launchctlBinaryPath || len(args) != 2 || args[0] != "print" {
		return "", nil
	}
	if args[1] == launchdDomainTarget(testLaunchdUID) {
		return "domain = gui/501\n", nil
	}
	if runner.bootoutPending {
		if runner.bootoutVisibleQueries > 0 {
			if runner.observedPlistPath != "" {
				if _, err := os.Stat(runner.observedPlistPath); errors.Is(err, os.ErrNotExist) {
					runner.missingPlistWhileLive = true
				}
			}
			runner.bootoutVisibleQueries--
		} else {
			runner.bootoutPending = false
			runner.loaded = false
		}
	}
	if !runner.loaded {
		return "", errors.New("Could not find service \"com.mitoriq.collector\" in domain for user gui: 501")
	}
	if len(runner.serviceOutputs) > 0 {
		output := runner.serviceOutputs[0]
		runner.serviceOutputs = append([]string(nil), runner.serviceOutputs[1:]...)

		return output, nil
	}
	if runner.serviceOutput != "" {
		return runner.serviceOutput, nil
	}
	if runner.pid == 0 {
		return "gui/501/com.mitoriq.collector = {\n\tstate = waiting\n}\n", nil
	}

	return fmt.Sprintf("gui/501/com.mitoriq.collector = {\n\tstate = running\n\tpid = %d\n}\n", runner.pid), nil
}

func (runner *fakeLaunchdRunner) record(name string, args ...string) {
	runner.calls = append(runner.calls, recordedCommand{name: name, args: append([]string(nil), args...)})
}

func (runner *fakeLaunchdRunner) nextFailure(name string, args ...string) error {
	key := commandKey(name, args...)
	failures := runner.failures[key]
	if len(failures) == 0 {
		return nil
	}
	runner.failures[key] = append([]error(nil), failures[1:]...)

	return failures[0]
}

func commandKey(name string, args ...string) string {
	return strings.Join(append([]string{name}, args...), "\x00")
}

func writeExecutable(t *testing.T, directory string, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	return path
}

func launchdTestPlan(t *testing.T) installPlan {
	t.Helper()
	home := t.TempDir()
	binaryPath := writeExecutable(t, home, "Mitoriq & Collector")

	return installPlan{
		BinaryPath:  binaryPath,
		LaunchdPath: filepath.Join(home, "Library", "LaunchAgents", launchdPlistName),
	}
}

func TestInstallLaunchdBootstrapsKickstartsAndReportsRunning(t *testing.T) {
	plan := launchdTestPlan(t)
	runner := &fakeLaunchdRunner{}
	var stdout bytes.Buffer

	err := installLaunchdWithWaitPolicy(
		plan,
		false,
		&stdout,
		runner,
		testLaunchdUID,
		newTestLaunchdWaitPolicy(3),
	)

	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(plan.LaunchdPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		launchdOwnershipMarker,
		"com.mitoriq.collector",
		"Mitoriq &amp; Collector",
		"<key>RunAtLoad</key>",
		"<key>KeepAlive</key>",
	} {
		if !strings.Contains(string(body), expected) {
			t.Fatalf("plist missing %q: %s", expected, body)
		}
	}
	expectedCalls := []recordedCommand{
		{name: launchctlBinaryPath, args: []string{"print", "gui/501"}},
		{name: launchctlBinaryPath, args: []string{"print", "gui/501/com.mitoriq.collector"}},
		{name: launchctlBinaryPath, args: []string{"bootstrap", "gui/501", plan.LaunchdPath}},
		{name: launchctlBinaryPath, args: []string{"print", "gui/501/com.mitoriq.collector"}},
		{name: launchctlBinaryPath, args: []string{"kickstart", "-p", "gui/501/com.mitoriq.collector"}},
		{name: launchctlBinaryPath, args: []string{"print", "gui/501/com.mitoriq.collector"}},
	}
	if !reflect.DeepEqual(runner.calls, expectedCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, expectedCalls)
	}
	for _, expected := range []string{
		"collector_service_phase=preflight status=complete",
		"collector_service_phase=installed status=complete",
		"collector_service_phase=loaded status=complete",
		"collector_service_phase=running status=complete state=running pid=4242",
		"collector_service_phase=heartbeat_seen status=pending next_action=wait_for_heartbeat",
		"collector_install_status=running",
		"heartbeat_status=not_checked",
		"next_action=wait_for_heartbeat",
		"reboot_recovery=enabled",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("stdout missing %q: %s", expected, stdout.String())
		}
	}
	for _, phase := range []string{"preflight", "installed", "loaded", "running", "heartbeat_seen"} {
		if count := strings.Count(stdout.String(), "collector_service_phase="+phase+" "); count != 1 {
			t.Fatalf("phase %q count = %d, stdout = %q", phase, count, stdout.String())
		}
	}
}

func TestInstallLaunchdWaitsForTransientPostBootstrapAbsence(t *testing.T) {
	plan := launchdTestPlan(t)
	serviceQueryKey := commandKey(
		launchctlBinaryPath,
		"print",
		launchdServiceTarget(testLaunchdUID),
	)
	runner := &fakeLaunchdRunner{failures: map[string][]error{
		serviceQueryKey: {
			nil,
			errors.New("Could not find service \"com.mitoriq.collector\" in domain for user gui: 501"),
		},
	}}
	var stdout bytes.Buffer

	err := installLaunchdWithWaitPolicy(
		plan,
		false,
		&stdout,
		runner,
		testLaunchdUID,
		newTestLaunchdWaitPolicy(3),
	)

	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "collector_install_status=running") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "status=failed") {
		t.Fatalf("transient absence emitted a failure phase: %q", stdout.String())
	}
	serviceQueryCount := 0
	for _, call := range runner.calls {
		if call.name == launchctlBinaryPath && reflect.DeepEqual(
			call.args,
			[]string{"print", launchdServiceTarget(testLaunchdUID)},
		) {
			serviceQueryCount++
		}
	}
	if serviceQueryCount != 4 {
		t.Fatalf("service status query count = %d, calls = %#v", serviceQueryCount, runner.calls)
	}
	if countCommand(runner.calls, launchctlBinaryPath, "bootout") != 0 {
		t.Fatalf("transient absence triggered rollback: %#v", runner.calls)
	}
}

func TestInstallLaunchdIsDuplicateSafe(t *testing.T) {
	plan := launchdTestPlan(t)
	runner := &fakeLaunchdRunner{}
	var firstOutput bytes.Buffer
	if err := installLaunchd(plan, false, &firstOutput, runner, testLaunchdUID); err != nil {
		t.Fatal(err)
	}
	firstBody, err := os.ReadFile(plan.LaunchdPath)
	if err != nil {
		t.Fatal(err)
	}

	var secondOutput bytes.Buffer
	if err := installLaunchd(plan, false, &secondOutput, runner, testLaunchdUID); err != nil {
		t.Fatal(err)
	}
	secondBody, err := os.ReadFile(plan.LaunchdPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBody, secondBody) {
		t.Fatalf("duplicate install changed plist\nfirst=%s\nsecond=%s", firstBody, secondBody)
	}
	if countCommand(runner.calls, launchctlBinaryPath, "bootstrap") != 1 {
		t.Fatalf("bootstrap calls = %#v", runner.calls)
	}
	if countCommand(runner.calls, launchctlBinaryPath, "kickstart") != 1 {
		t.Fatalf("kickstart calls = %#v", runner.calls)
	}
	if !runner.loaded {
		t.Fatal("service should remain loaded")
	}
}

func TestInstallLaunchdMigratesLegacyOwnedPlist(t *testing.T) {
	plan := launchdTestPlan(t)
	body, err := plan.launchdPlist()
	if err != nil {
		t.Fatal(err)
	}
	markerBlock := "  <key>EnvironmentVariables</key>\n" +
		"  <dict>\n" +
		"    <key>" + launchdOwnershipMarker + "</key>\n" +
		"    <string>" + launchdOwnershipValue + "</string>\n" +
		"  </dict>\n"
	legacyBody := strings.Replace(body, markerBlock, "", 1)
	if legacyBody == body {
		t.Fatal("test fixture did not remove the ownership marker")
	}
	if err := writeAtomicLaunchdPlist(plan.LaunchdPath, legacyBody, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeLaunchdRunner{loaded: true, pid: 4100}

	if err := installLaunchd(plan, false, &bytes.Buffer{}, runner, testLaunchdUID); err != nil {
		t.Fatal(err)
	}
	migratedBody, err := os.ReadFile(plan.LaunchdPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migratedBody), launchdOwnershipMarker) {
		t.Fatalf("legacy plist was not marked as owned: %s", migratedBody)
	}
}

func TestInstallLaunchdRollsBackNewInstallWhenActivationFails(t *testing.T) {
	plan := launchdTestPlan(t)
	kickstartKey := commandKey(launchctlBinaryPath, "kickstart", "-p", "gui/501/com.mitoriq.collector")
	runner := &fakeLaunchdRunner{failures: map[string][]error{
		kickstartKey: {errors.New("kickstart denied")},
	}}
	var stdout bytes.Buffer

	err := installLaunchd(plan, false, &stdout, runner, testLaunchdUID)

	if err == nil || !strings.Contains(err.Error(), "kickstart") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(plan.LaunchdPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("new plist should be removed: %v", statErr)
	}
	if runner.loaded {
		t.Fatal("partially activated service should be booted out")
	}
	if !strings.Contains(stdout.String(), "collector_service_phase=rollback status=complete") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(
		stdout.String(),
		"collector_service_phase=running status=failed reason=kickstart_failed next_action=retry_install",
	) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestInstallLaunchdRestoresPreviousOwnedServiceWhenReplacementFails(t *testing.T) {
	plan := launchdTestPlan(t)
	previousPlan := plan
	previousPlan.BinaryPath = writeExecutable(t, filepath.Dir(plan.BinaryPath), "previous-collector")
	previousBody, err := previousPlan.launchdPlist()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicLaunchdPlist(plan.LaunchdPath, previousBody, 0o644); err != nil {
		t.Fatal(err)
	}
	kickstartKey := commandKey(launchctlBinaryPath, "kickstart", "-p", "gui/501/com.mitoriq.collector")
	serviceQueryKey := commandKey(
		launchctlBinaryPath,
		"print",
		launchdServiceTarget(testLaunchdUID),
	)
	notFound := errors.New("Could not find service \"com.mitoriq.collector\" in domain for user gui: 501")
	runner := &fakeLaunchdRunner{
		failures: map[string][]error{
			kickstartKey:    {errors.New("replacement failed")},
			serviceQueryKey: {nil, nil, nil, notFound},
		},
		loaded: true,
		pid:    4100,
	}
	var stdout bytes.Buffer

	err = installLaunchd(plan, false, &stdout, runner, testLaunchdUID)

	if err == nil || !strings.Contains(err.Error(), "kickstart launchd service failed") {
		t.Fatalf("err = %v", err)
	}
	restoredBody, readErr := os.ReadFile(plan.LaunchdPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(restoredBody) != previousBody+"\n" {
		t.Fatalf("previous plist was not restored\nwant=%s\ngot=%s", previousBody, restoredBody)
	}
	if !runner.loaded {
		t.Fatal("previous service should be restored and running")
	}
	if countCommand(runner.calls, launchctlBinaryPath, "bootout") != 2 ||
		countCommand(runner.calls, launchctlBinaryPath, "bootstrap") != 2 {
		t.Fatalf("rollback command sequence = %#v", runner.calls)
	}
}

func TestInstallLaunchdReportsRollbackFailureWhenPreviousServiceDoesNotRecover(t *testing.T) {
	plan := launchdTestPlan(t)
	previousPlan := plan
	previousPlan.BinaryPath = writeExecutable(t, filepath.Dir(plan.BinaryPath), "previous-collector")
	previousBody, err := previousPlan.launchdPlist()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicLaunchdPlist(plan.LaunchdPath, previousBody, 0o644); err != nil {
		t.Fatal(err)
	}
	kickstartKey := commandKey(launchctlBinaryPath, "kickstart", "-p", "gui/501/com.mitoriq.collector")
	runner := &fakeLaunchdRunner{
		failures: map[string][]error{kickstartKey: {errors.New("replacement failed")}},
		loaded:   true,
		pid:      4100,
		serviceOutputs: []string{
			"gui/501/com.mitoriq.collector = {\n\tstate = running\n\tpid = 4100\n}\n",
			"gui/501/com.mitoriq.collector = {\n\tstate = running\n\tpid = 4101\n}\n",
		},
		serviceOutput: "gui/501/com.mitoriq.collector = {\n\tstate = waiting\n}\n",
	}
	var stdout bytes.Buffer

	err = installLaunchdWithWaitPolicy(
		plan,
		false,
		&stdout,
		runner,
		testLaunchdUID,
		newTestLaunchdWaitPolicy(3),
	)

	if err == nil || !strings.Contains(err.Error(), "previous launchd service did not return to running state") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(stdout.String(), "collector_service_phase=rollback status=failed") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestInstallAndUninstallRefuseUnownedLaunchdPlist(t *testing.T) {
	plan := launchdTestPlan(t)
	if err := os.MkdirAll(filepath.Dir(plan.LaunchdPath), 0o755); err != nil {
		t.Fatal(err)
	}
	unowned := "<?xml version=\"1.0\"?><plist><dict><key>Label</key><string>example.unrelated</string></dict></plist>"
	if err := os.WriteFile(plan.LaunchdPath, []byte(unowned), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeLaunchdRunner{loaded: true, pid: 4000}

	installErr := installLaunchd(plan, false, &bytes.Buffer{}, runner, testLaunchdUID)
	uninstallErr := uninstallLaunchd(plan.LaunchdPath, false, &bytes.Buffer{}, runner, testLaunchdUID)

	if installErr == nil || !strings.Contains(installErr.Error(), "owned") {
		t.Fatalf("install err = %v", installErr)
	}
	if uninstallErr == nil || !strings.Contains(uninstallErr.Error(), "owned") {
		t.Fatalf("uninstall err = %v", uninstallErr)
	}
	body, err := os.ReadFile(plan.LaunchdPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != unowned {
		t.Fatalf("unowned plist changed: %s", body)
	}
	if countCommand(runner.calls, launchctlBinaryPath, "bootout") != 0 {
		t.Fatalf("unowned service was touched: %#v", runner.calls)
	}
}

func TestLaunchdOwnershipRequiresExactStructuredPlist(t *testing.T) {
	plan := launchdTestPlan(t)
	ownedBody, err := plan.launchdPlist()
	if err != nil {
		t.Fatal(err)
	}
	marker := "    <key>" + launchdOwnershipMarker + "</key>\n" +
		"    <string>" + launchdOwnershipValue + "</string>"
	tests := []struct {
		name string
		body string
	}{
		{
			name: "marker only in comment",
			body: strings.Replace(ownedBody, marker, "    <!-- "+marker+" -->", 1),
		},
		{
			name: "run at load false",
			body: strings.Replace(ownedBody, "<key>RunAtLoad</key>\n  <true/>", "<key>RunAtLoad</key>\n  <false/>", 1),
		},
		{
			name: "extra program argument",
			body: strings.Replace(ownedBody, "    <string>daemon</string>", "    <string>daemon</string>\n    <string>unrelated</string>", 1),
		},
		{
			name: "extra top level key",
			body: strings.Replace(ownedBody, "  <key>RunAtLoad</key>", "  <key>Unrelated</key>\n  <string>value</string>\n  <key>RunAtLoad</key>", 1),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if isOwnedLaunchdPlist([]byte(test.body)) {
				t.Fatalf("non-owned plist accepted:\n%s", test.body)
			}
		})
	}
}

func TestWriteAtomicLaunchdPlistPreservesExistingFileOnReplaceFailure(t *testing.T) {
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
			launchdPath := filepath.Join(directory, launchdPlistName)
			previousBody := []byte("previous plist\n")
			if err := os.WriteFile(launchdPath, previousBody, 0o644); err != nil {
				t.Fatal(err)
			}

			err := writeAtomicLaunchdPlistWithOps(
				launchdPath,
				"replacement plist",
				0o644,
				test.configure(defaultLaunchdAtomicFileOps()),
			)

			if err == nil {
				t.Fatal("expected atomic replace failure")
			}
			body, readErr := os.ReadFile(launchdPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !bytes.Equal(body, previousBody) {
				t.Fatalf("body = %q, want %q", body, previousBody)
			}
			entries, readDirErr := os.ReadDir(directory)
			if readDirErr != nil {
				t.Fatal(readDirErr)
			}
			if len(entries) != 1 || entries[0].Name() != launchdPlistName {
				t.Fatalf("unexpected files after failed replace: %#v", entries)
			}
		})
	}
}

func TestUninstallLaunchdStopsServiceBeforeRemovingOwnedPlist(t *testing.T) {
	plan := launchdTestPlan(t)
	body, err := plan.launchdPlist()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicLaunchdPlist(plan.LaunchdPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeLaunchdRunner{loaded: true, pid: 4242}
	var stdout bytes.Buffer

	err = uninstallLaunchd(plan.LaunchdPath, false, &stdout, runner, testLaunchdUID)

	if err != nil {
		t.Fatal(err)
	}
	if runner.loaded {
		t.Fatal("service should be stopped")
	}
	if _, statErr := os.Stat(plan.LaunchdPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("plist should be removed: %v", statErr)
	}
	if !strings.Contains(stdout.String(), "collector_uninstall_status=removed") ||
		!strings.Contains(stdout.String(), "service_state=stopped") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestInstallLaunchdDryRunDoesNotWriteOrExecute(t *testing.T) {
	plan := launchdTestPlan(t)
	runner := &fakeLaunchdRunner{}
	var stdout bytes.Buffer

	err := installLaunchd(plan, true, &stdout, runner, "")

	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(plan.LaunchdPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("dry run wrote plist: %v", statErr)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("dry run executed commands: %#v", runner.calls)
	}
	if !strings.Contains(stdout.String(), "collector_install_status=planned") ||
		!strings.Contains(stdout.String(), launchdOwnershipMarker) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestLaunchdPlistRejectsUnsafeBinaryPaths(t *testing.T) {
	for _, binaryPath := range []string{"relative/mitoriq-collector", "/opt/mitoriq\ncollector", "/opt/mitoriq\x00collector"} {
		plan := installPlan{BinaryPath: binaryPath}

		if _, err := plan.launchdPlist(); err == nil {
			t.Fatalf("binary path %q should be rejected", binaryPath)
		}
	}
}

func TestLaunchdPlistUsesMacOSAbsolutePathSemantics(t *testing.T) {
	plan := installPlan{BinaryPath: "/opt/mitoriq/bin/mitoriq-collector"}
	if _, err := plan.launchdPlist(); err != nil {
		t.Fatalf("POSIX absolute path rejected: %v", err)
	}
}

func TestInstallLaunchdRejectsRootBeforeChangingState(t *testing.T) {
	plan := launchdTestPlan(t)
	runner := &fakeLaunchdRunner{}

	err := installLaunchd(plan, false, &bytes.Buffer{}, runner, "0")

	if err == nil || !strings.Contains(err.Error(), "non-root") {
		t.Fatalf("err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("commands executed for root: %#v", runner.calls)
	}
	if _, statErr := os.Stat(plan.LaunchdPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("root install wrote plist: %v", statErr)
	}
}

func TestUninstallLaunchdKeepsOwnedPlistWhenBootoutFails(t *testing.T) {
	plan := launchdTestPlan(t)
	body, err := plan.launchdPlist()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicLaunchdPlist(plan.LaunchdPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	bootoutKey := commandKey(launchctlBinaryPath, "bootout", "gui/501/com.mitoriq.collector")
	runner := &fakeLaunchdRunner{
		failures: map[string][]error{bootoutKey: {errors.New("bootout denied")}},
		loaded:   true,
		pid:      4242,
	}

	err = uninstallLaunchd(plan.LaunchdPath, false, &bytes.Buffer{}, runner, testLaunchdUID)

	if err == nil || !strings.Contains(err.Error(), "stop launchd service failed") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(plan.LaunchdPath); statErr != nil {
		t.Fatalf("plist should remain for retry: %v", statErr)
	}
}

type stickyLoadedLaunchdRunner struct{}

func (stickyLoadedLaunchdRunner) Run(string, ...string) error {
	return nil
}

func (stickyLoadedLaunchdRunner) Output(_ string, args ...string) (string, error) {
	if len(args) == 2 && args[0] == "print" && args[1] == launchdDomainTarget(testLaunchdUID) {
		return "domain = gui/501\n", nil
	}

	return "gui/501/com.mitoriq.collector = {\n\tstate = running\n\tpid = 4242\n}\n", nil
}

func TestUninstallLaunchdKeepsOwnedPlistWhenServiceRemainsLoaded(t *testing.T) {
	plan := launchdTestPlan(t)
	body, err := plan.launchdPlist()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicLaunchdPlist(plan.LaunchdPath, body, 0o644); err != nil {
		t.Fatal(err)
	}

	err = uninstallLaunchd(
		plan.LaunchdPath,
		false,
		&bytes.Buffer{},
		stickyLoadedLaunchdRunner{},
		testLaunchdUID,
	)

	if err == nil || !strings.Contains(err.Error(), "remained loaded") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(plan.LaunchdPath); statErr != nil {
		t.Fatalf("plist should remain for recovery: %v", statErr)
	}
}

func countCommand(calls []recordedCommand, name string, subcommand string) int {
	count := 0
	for _, call := range calls {
		if call.name == name && len(call.args) > 0 && call.args[0] == subcommand {
			count++
		}
	}

	return count
}
