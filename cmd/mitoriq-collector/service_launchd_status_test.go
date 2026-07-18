package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestLaunchdStatusReportsAbsentInstalledAndLoadedStates(t *testing.T) {
	testCases := []struct {
		name       string
		hasPlist   bool
		runner     *fakeLaunchdRunner
		expected   string
		state      string
		recovery   string
		nextAction string
	}{
		{
			name:       "absent",
			runner:     &fakeLaunchdRunner{},
			expected:   "collector_service_status=absent",
			state:      "state=not_installed",
			recovery:   "reboot_recovery=disabled",
			nextAction: "next_action=install",
		},
		{
			name:       "installed",
			hasPlist:   true,
			runner:     &fakeLaunchdRunner{},
			expected:   "collector_service_status=installed",
			state:      "state=not_loaded",
			recovery:   "reboot_recovery=enabled",
			nextAction: "next_action=install",
		},
		{
			name:     "loaded",
			hasPlist: true,
			runner: &fakeLaunchdRunner{
				loaded:        true,
				serviceOutput: "gui/501/com.mitoriq.collector = {\n\tstate = waiting\n}\n",
			},
			expected:   "collector_service_status=loaded",
			state:      "state=waiting",
			recovery:   "reboot_recovery=enabled",
			nextAction: "next_action=install",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			plan := launchdTestPlan(t)
			if testCase.hasPlist {
				body, err := plan.launchdPlist()
				if err != nil {
					t.Fatal(err)
				}
				if err := writeAtomicLaunchdPlist(plan.LaunchdPath, body, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var stdout bytes.Buffer

			if err := statusLaunchd(plan.LaunchdPath, &stdout, testCase.runner, testLaunchdUID); err != nil {
				t.Fatal(err)
			}
			for _, expected := range []string{
				testCase.expected,
				testCase.state,
				testCase.recovery,
				"heartbeat_status=not_checked",
				testCase.nextAction,
			} {
				if !strings.Contains(stdout.String(), expected) {
					t.Fatalf("stdout missing %q: %s", expected, stdout.String())
				}
			}
		})
	}
}

func TestLaunchdStatusReportsRunningAndRebootRecovery(t *testing.T) {
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

	err = statusLaunchd(plan.LaunchdPath, &stdout, runner, testLaunchdUID)

	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"collector_service_status=running",
		"state=running",
		"pid=4242",
		"reboot_recovery=enabled",
		"heartbeat_status=not_checked",
		"next_action=check_heartbeat",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("stdout missing %q: %s", expected, stdout.String())
		}
	}
}

func TestParseLaunchdStatusUsesOnlyTopLevelServiceFields(t *testing.T) {
	status, err := parseLaunchdStatus(`gui/501/com.mitoriq.collector = {
	state = running
	pid = 4242
	spawn type = daemon (3)
	properties = {
		state = waiting
		pid = 99
	}
}`)

	if err != nil {
		t.Fatal(err)
	}
	if status.state != "running" || status.pid != 4242 {
		t.Fatalf("status = %#v", status)
	}
}

func TestParseLaunchdStatusIgnoresBracesInScalarValues(t *testing.T) {
	status, err := parseLaunchdStatus(`gui/501/com.mitoriq.collector = {
	state = running
	pid = 4242
	program = /Applications/Mitoriq {Beta/mitoriq-collector
}`)

	if err != nil {
		t.Fatal(err)
	}
	if status.state != "running" || status.pid != 4242 {
		t.Fatalf("status = %#v", status)
	}
}

func TestParseLaunchdStatusRejectsRunningStateWithoutPID(t *testing.T) {
	_, err := parseLaunchdStatus(`gui/501/com.mitoriq.collector = {
	state = running
}`)

	if err == nil || !strings.Contains(err.Error(), "running state without a process ID") {
		t.Fatalf("err = %v", err)
	}
}

func TestLaunchdPlistCanBootstrapAgainAfterSimulatedReboot(t *testing.T) {
	plan := launchdTestPlan(t)
	runner := &fakeLaunchdRunner{}
	if err := installLaunchd(plan, false, &bytes.Buffer{}, runner, testLaunchdUID); err != nil {
		t.Fatal(err)
	}
	runner.loaded = false
	runner.pid = 0
	runner.calls = nil

	if err := runner.Run(launchctlBinaryPath, "bootstrap", launchdDomainTarget(testLaunchdUID), plan.LaunchdPath); err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(launchctlBinaryPath, "kickstart", "-p", launchdServiceTarget(testLaunchdUID)); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := statusLaunchd(plan.LaunchdPath, &stdout, runner, testLaunchdUID); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "collector_service_status=running") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestStatusLaunchdDoesNotLeakRawPrintOutput(t *testing.T) {
	plan := launchdTestPlan(t)
	body, err := plan.launchdPlist()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicLaunchdPlist(plan.LaunchdPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	secret := "mtq_e_must_not_escape"
	runner := &fakeLaunchdRunner{
		loaded: true,
		pid:    4242,
		serviceOutput: "gui/501/com.mitoriq.collector = {\n" +
			"\tstate = running\n\tpid = 4242\n\tenvironment = { TOKEN => " + secret + " }\n}\n",
	}
	var stdout bytes.Buffer

	err = statusLaunchd(plan.LaunchdPath, &stdout, runner, testLaunchdUID)

	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), secret) || !strings.Contains(stdout.String(), "pid=4242") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

type failingOutputLaunchdRunner struct {
	secret string
}

func (runner failingOutputLaunchdRunner) Run(string, ...string) error {
	return errors.New("command failed: " + runner.secret)
}

func (runner failingOutputLaunchdRunner) Output(_ string, args ...string) (string, error) {
	if len(args) == 2 && args[0] == "print" && args[1] == launchdDomainTarget(testLaunchdUID) {
		return "domain = gui/501\n", nil
	}

	return "environment = { TOKEN => " + runner.secret + " }\n", errors.New("command failed: " + runner.secret)
}

func TestStatusLaunchdDoesNotLeakFailedLaunchctlOutput(t *testing.T) {
	plan := launchdTestPlan(t)
	body, err := plan.launchdPlist()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicLaunchdPlist(plan.LaunchdPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	secret := "mtq_e_must_not_escape_from_failure"

	err = statusLaunchd(
		plan.LaunchdPath,
		&bytes.Buffer{},
		failingOutputLaunchdRunner{secret: secret},
		testLaunchdUID,
	)

	if err == nil {
		t.Fatal("expected status failure")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("secret leaked in error: %v", err)
	}
}
