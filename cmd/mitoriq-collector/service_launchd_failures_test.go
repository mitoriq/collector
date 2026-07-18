package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestInstallLaunchdReportsInvalidPlanFailurePhase(t *testing.T) {
	plan := launchdTestPlan(t)
	plan.BinaryPath = "relative/mitoriq-collector"
	var stdout bytes.Buffer

	err := installLaunchd(plan, false, &stdout, &fakeLaunchdRunner{}, testLaunchdUID)

	if err == nil {
		t.Fatal("expected invalid plan failure")
	}
	assertLaunchdFailurePhase(
		t,
		stdout.String(),
		"collector_service_phase=preflight status=failed reason=invalid_plan next_action=fix_preflight",
	)
}

func TestInstallLaunchdReportsStaticPreflightFailurePhase(t *testing.T) {
	plan := launchdTestPlan(t)
	var stdout bytes.Buffer

	err := installLaunchd(plan, false, &stdout, &fakeLaunchdRunner{}, "0")

	if err == nil {
		t.Fatal("expected preflight failure")
	}
	assertLaunchdFailurePhase(
		t,
		stdout.String(),
		"collector_service_phase=preflight status=failed reason=static_preflight_failed next_action=fix_preflight",
	)
}

func TestInstallLaunchdReportsDomainPreflightFailurePhase(t *testing.T) {
	plan := launchdTestPlan(t)
	runner := &fakeLaunchdRunner{failures: map[string][]error{
		commandKey(launchctlBinaryPath, "print", launchdDomainTarget(testLaunchdUID)): {
			errors.New("domain unavailable"),
		},
	}}
	var stdout bytes.Buffer

	err := installLaunchd(plan, false, &stdout, runner, testLaunchdUID)

	if err == nil {
		t.Fatal("expected domain preflight failure")
	}
	assertLaunchdFailurePhase(
		t,
		stdout.String(),
		"collector_service_phase=preflight status=failed reason=domain_unavailable next_action=login_to_gui_session",
	)
}

func TestInstallLaunchdReportsExistingServiceKickstartFailurePhase(t *testing.T) {
	plan := launchdTestPlan(t)
	body, err := plan.launchdPlist()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicLaunchdPlist(plan.LaunchdPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeLaunchdRunner{
		loaded:        true,
		serviceOutput: "gui/501/com.mitoriq.collector = {\n\tstate = waiting\n}\n",
		failures: map[string][]error{
			commandKey(launchctlBinaryPath, "kickstart", "-p", launchdServiceTarget(testLaunchdUID)): {
				errors.New("kickstart failed"),
			},
		},
	}
	var stdout bytes.Buffer

	err = installLaunchd(plan, false, &stdout, runner, testLaunchdUID)

	if err == nil {
		t.Fatal("expected kickstart failure")
	}
	assertLaunchdFailurePhase(
		t,
		stdout.String(),
		"collector_service_phase=running status=failed reason=kickstart_failed next_action=retry_install",
	)
}

func TestInstallLaunchdReportsPostActivationStatusFailurePhase(t *testing.T) {
	plan := launchdTestPlan(t)
	runner := &fakeLaunchdRunner{failures: map[string][]error{
		commandKey(launchctlBinaryPath, "print", launchdServiceTarget(testLaunchdUID)): {
			nil,
			errors.New("status unavailable"),
		},
	}}
	var stdout bytes.Buffer

	err := installLaunchd(plan, false, &stdout, runner, testLaunchdUID)

	if err == nil {
		t.Fatal("expected status failure")
	}
	assertLaunchdFailurePhase(
		t,
		stdout.String(),
		"collector_service_phase=running status=failed reason=status_query_failed next_action=retry_install",
	)
}

func TestInstallLaunchdReportsNotRunningAfterActivationPhase(t *testing.T) {
	plan := launchdTestPlan(t)
	runner := &fakeLaunchdRunner{
		serviceOutput: "gui/501/com.mitoriq.collector = {\n\tstate = waiting\n}\n",
	}
	var stdout bytes.Buffer

	err := installLaunchd(plan, false, &stdout, runner, testLaunchdUID)

	if err == nil {
		t.Fatal("expected activation verification failure")
	}
	assertLaunchdFailurePhase(
		t,
		stdout.String(),
		"collector_service_phase=running status=failed reason=not_running next_action=retry_install",
	)
}

func assertLaunchdFailurePhase(t *testing.T, output string, expected string) {
	t.Helper()
	if !strings.Contains(output, expected) {
		t.Fatalf("stdout missing %q: %s", expected, output)
	}
}
