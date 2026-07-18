package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestLaunchdWaitPolicy(maxProbes int) launchdWaitPolicy {
	current := time.Unix(0, 0)
	interval := time.Millisecond

	return launchdWaitPolicy{
		timeout:  time.Duration(maxProbes) * interval,
		interval: interval,
		now: func() time.Time {
			return current
		},
		sleep: func(delay time.Duration) {
			current = current.Add(delay)
		},
	}
}

func TestInstallLaunchdWaitsForPostKickstartRunningState(t *testing.T) {
	plan := launchdTestPlan(t)
	runner := &fakeLaunchdRunner{serviceOutputs: []string{
		"gui/501/com.mitoriq.collector = {\n\tstate = waiting\n}\n",
		"gui/501/com.mitoriq.collector = {\n\tstate = waiting\n}\n",
		"gui/501/com.mitoriq.collector = {\n\tstate = running\n\tpid = 4242\n}\n",
	}}
	var stdout bytes.Buffer

	err := installLaunchdWithWaitPolicy(
		plan,
		false,
		&stdout,
		runner,
		testLaunchdUID,
		newTestLaunchdWaitPolicy(4),
	)

	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "collector_install_status=running") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if countCommand(runner.calls, launchctlBinaryPath, "bootout") != 0 {
		t.Fatalf("running transition triggered rollback: %#v", runner.calls)
	}
}

func TestInstallLaunchdExistingStoppedServiceWaitsForTransientStatus(t *testing.T) {
	plan := launchdTestPlan(t)
	body, err := plan.launchdPlist()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicLaunchdPlist(plan.LaunchdPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	serviceQueryKey := commandKey(
		launchctlBinaryPath,
		"print",
		launchdServiceTarget(testLaunchdUID),
	)
	runner := &fakeLaunchdRunner{
		loaded: true,
		failures: map[string][]error{
			serviceQueryKey: {
				nil,
				errors.New("Could not find service \"com.mitoriq.collector\" in domain for user gui: 501"),
			},
		},
		serviceOutputs: []string{
			"gui/501/com.mitoriq.collector = {\n\tstate = waiting\n}\n",
			"gui/501/com.mitoriq.collector = {\n\tstate = running\n\tpid = 4242\n}\n",
		},
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

	if err != nil {
		t.Fatal(err)
	}
	if countCommand(runner.calls, launchctlBinaryPath, "bootstrap") != 0 {
		t.Fatalf("existing service was bootstrapped again: %#v", runner.calls)
	}
	if countCommand(runner.calls, launchctlBinaryPath, "kickstart") != 1 {
		t.Fatalf("kickstart calls = %#v", runner.calls)
	}
}

func TestInstallLaunchdLoadedTimeoutRollsBackNewInstall(t *testing.T) {
	plan := launchdTestPlan(t)
	serviceQueryKey := commandKey(
		launchctlBinaryPath,
		"print",
		launchdServiceTarget(testLaunchdUID),
	)
	notFound := errors.New("Could not find service \"com.mitoriq.collector\" in domain for user gui: 501")
	runner := &fakeLaunchdRunner{failures: map[string][]error{
		serviceQueryKey: {nil, notFound, notFound, notFound},
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

	if err == nil || !strings.Contains(err.Error(), "did not reach loaded state") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(
		stdout.String(),
		"collector_service_phase=loaded status=failed reason=not_loaded next_action=retry_install",
	) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if _, statErr := os.Stat(plan.LaunchdPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("new plist should be removed: %v", statErr)
	}
	if runner.loaded {
		t.Fatal("partially loaded service should be booted out")
	}
	if countCommand(runner.calls, launchctlBinaryPath, "bootout") != 1 {
		t.Fatalf("rollback calls = %#v", runner.calls)
	}
}

func TestInstallLaunchdStopsPollingOnHardStatusError(t *testing.T) {
	plan := launchdTestPlan(t)
	serviceQueryKey := commandKey(
		launchctlBinaryPath,
		"print",
		launchdServiceTarget(testLaunchdUID),
	)
	secret := "secret-in-launchctl-output"
	runner := &fakeLaunchdRunner{failures: map[string][]error{
		serviceQueryKey: {
			nil,
			errors.New("Could not find service \"com.mitoriq.collector\" in domain for user gui: 501"),
			errors.New(secret),
		},
	}}
	var stdout bytes.Buffer

	err := installLaunchdWithWaitPolicy(
		plan,
		false,
		&stdout,
		runner,
		testLaunchdUID,
		newTestLaunchdWaitPolicy(5),
	)

	if err == nil || !strings.Contains(err.Error(), "read launchd status after bootstrap") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(stdout.String(), secret) {
		t.Fatalf("launchctl output leaked: err=%v stdout=%q", err, stdout.String())
	}
	if !strings.Contains(
		stdout.String(),
		"collector_service_phase=loaded status=failed reason=status_query_failed next_action=retry_install",
	) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestWaitForLaunchdStateStopsAtDeadline(t *testing.T) {
	runner := &fakeLaunchdRunner{
		loaded:        true,
		serviceOutput: "gui/501/com.mitoriq.collector = {\n\tstate = waiting\n}\n",
	}

	_, loaded, err := waitForLaunchdRunning(
		runner,
		testLaunchdUID,
		newTestLaunchdWaitPolicy(3),
	)

	if err != nil {
		t.Fatal(err)
	}
	if !loaded {
		t.Fatal("service should remain loaded while waiting")
	}
	if count := countCommand(runner.calls, launchctlBinaryPath, "print"); count != 3 {
		t.Fatalf("status query count = %d, calls = %#v", count, runner.calls)
	}
}

func TestRollbackKeepsOwnedPlistWhenPartialStatusIsUnknown(t *testing.T) {
	plan := launchdTestPlan(t)
	serviceQueryKey := commandKey(
		launchctlBinaryPath,
		"print",
		launchdServiceTarget(testLaunchdUID),
	)
	runner := &fakeLaunchdRunner{failures: map[string][]error{
		serviceQueryKey: {
			nil,
			nil,
			errors.New("activation status unavailable"),
			errors.New("rollback status unavailable"),
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

	if err == nil || !strings.Contains(err.Error(), "inspect partial launchd service") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(plan.LaunchdPath); statErr != nil {
		t.Fatalf("owned plist should remain while service state is unknown: %v", statErr)
	}
	if !runner.loaded {
		t.Fatal("test must retain the partially loaded service state")
	}
	if !strings.Contains(stdout.String(), "collector_service_phase=rollback status=failed") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRollbackKeepsOwnedPlistWhenPartialBootoutFails(t *testing.T) {
	plan := launchdTestPlan(t)
	kickstartKey := commandKey(
		launchctlBinaryPath,
		"kickstart",
		"-p",
		launchdServiceTarget(testLaunchdUID),
	)
	bootoutKey := commandKey(launchctlBinaryPath, "bootout", launchdServiceTarget(testLaunchdUID))
	runner := &fakeLaunchdRunner{failures: map[string][]error{
		kickstartKey: {errors.New("kickstart denied")},
		bootoutKey:   {errors.New("bootout denied")},
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

	if err == nil || !strings.Contains(err.Error(), "bootout partial launchd service") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(plan.LaunchdPath); statErr != nil {
		t.Fatalf("owned plist should remain after bootout failure: %v", statErr)
	}
	if !runner.loaded {
		t.Fatal("bootout failure must leave service loaded")
	}
	if !strings.Contains(stdout.String(), "collector_service_phase=rollback status=failed") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRollbackKeepsOwnedPlistWhenPartialServiceRemainsLoaded(t *testing.T) {
	plan := launchdTestPlan(t)
	kickstartKey := commandKey(
		launchctlBinaryPath,
		"kickstart",
		"-p",
		launchdServiceTarget(testLaunchdUID),
	)
	runner := &fakeLaunchdRunner{
		bootoutVisibleQueries: 10,
		failures: map[string][]error{
			kickstartKey: {errors.New("kickstart denied")},
		},
	}
	var stdout bytes.Buffer

	err := installLaunchdWithWaitPolicy(
		plan,
		false,
		&stdout,
		runner,
		testLaunchdUID,
		newTestLaunchdWaitPolicy(3),
	)

	if err == nil || !strings.Contains(err.Error(), "remained loaded after bootout") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(plan.LaunchdPath); statErr != nil {
		t.Fatalf("owned plist should remain while service is loaded: %v", statErr)
	}
	if !runner.loaded {
		t.Fatal("test must retain the partially loaded service state")
	}
	if !strings.Contains(stdout.String(), "collector_service_phase=rollback status=failed") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRollbackWaitsForPartialServiceToBecomeAbsentBeforeRemovingPlist(t *testing.T) {
	plan := launchdTestPlan(t)
	kickstartKey := commandKey(
		launchctlBinaryPath,
		"kickstart",
		"-p",
		launchdServiceTarget(testLaunchdUID),
	)
	runner := &fakeLaunchdRunner{
		bootoutVisibleQueries: 2,
		failures: map[string][]error{
			kickstartKey: {errors.New("kickstart denied")},
		},
		observedPlistPath: plan.LaunchdPath,
	}
	var stdout bytes.Buffer

	err := installLaunchdWithWaitPolicy(
		plan,
		false,
		&stdout,
		runner,
		testLaunchdUID,
		newTestLaunchdWaitPolicy(4),
	)

	if err == nil || !strings.Contains(err.Error(), "kickstart launchd service") {
		t.Fatalf("err = %v", err)
	}
	if runner.missingPlistWhileLive {
		t.Fatal("rollback removed owned plist before launchd became absent")
	}
	if _, statErr := os.Stat(plan.LaunchdPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rolled back plist should be absent: %v", statErr)
	}
	if !strings.Contains(stdout.String(), "collector_service_phase=rollback status=complete") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestInstallLaunchdWaitsForPreviousServiceToBecomeAbsentBeforeReplacement(t *testing.T) {
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
	runner := &fakeLaunchdRunner{
		bootoutVisibleQueries: 2,
		loaded:                true,
		pid:                   4100,
	}

	err = installLaunchdWithWaitPolicy(
		plan,
		false,
		&bytes.Buffer{},
		runner,
		testLaunchdUID,
		newTestLaunchdWaitPolicy(4),
	)

	if err != nil {
		t.Fatal(err)
	}
	body, readErr := os.ReadFile(plan.LaunchdPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	expected, expectedErr := plan.launchdPlist()
	if expectedErr != nil {
		t.Fatal(expectedErr)
	}
	if string(body) != expected+"\n" {
		t.Fatalf("replacement plist mismatch: %s", body)
	}
}

func TestWaitForLaunchdStateStopsImmediatelyOnHardError(t *testing.T) {
	secret := "secret-in-hard-launchctl-error"
	serviceQueryKey := commandKey(
		launchctlBinaryPath,
		"print",
		launchdServiceTarget(testLaunchdUID),
	)
	runner := &fakeLaunchdRunner{
		loaded: true,
		failures: map[string][]error{
			serviceQueryKey: {errors.New(secret)},
		},
	}

	_, _, err := waitForLaunchdRunning(runner, testLaunchdUID, newTestLaunchdWaitPolicy(5))

	if err == nil {
		t.Fatal("expected hard status error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("launchctl output leaked: %v", err)
	}
	if count := countCommand(runner.calls, launchctlBinaryPath, "print"); count != 1 {
		t.Fatalf("hard error was retried: calls = %#v", runner.calls)
	}
}
