package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	launchctlBinaryPath    = "/bin/launchctl"
	launchdOwnershipMarker = "MITORIQ_MANAGED_LAUNCH_AGENT"
	launchdOwnershipValue  = "v1"
	launchdPlistName       = "com.mitoriq.collector.plist"
	launchdServiceLabel    = "com.mitoriq.collector"
)

type launchdPlistSnapshot struct {
	body   []byte
	exists bool
	mode   os.FileMode
}

type launchdProcessStatus struct {
	pid   int
	state string
}

func installLaunchd(
	plan installPlan,
	dryRun bool,
	stdout io.Writer,
	runner commandRunner,
	userID string,
) error {
	return installLaunchdWithWaitPolicy(
		plan,
		dryRun,
		stdout,
		runner,
		userID,
		defaultLaunchdWaitPolicy(),
	)
}

func installLaunchdWithWaitPolicy(
	plan installPlan,
	dryRun bool,
	stdout io.Writer,
	runner commandRunner,
	userID string,
	waitPolicy launchdWaitPolicy,
) error {
	plist, err := plan.launchdPlist()
	if err != nil {
		phaseErr := writeLaunchdFailurePhase(stdout, "preflight", "invalid_plan", "fix_preflight")

		return errors.Join(err, phaseErr)
	}
	if dryRun {
		if _, err := fmt.Fprintf(
			stdout,
			"collector_install_status=planned launchd_plist=%s service=%s\n",
			plan.LaunchdPath,
			launchdServiceLabel,
		); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(stdout, plist); err != nil {
			return err
		}

		return writeHookSnippets(stdout, plan)
	}
	if err := validateLaunchdStaticPreflight(plan, userID); err != nil {
		phaseErr := writeLaunchdFailurePhase(
			stdout,
			"preflight",
			"static_preflight_failed",
			"fix_preflight",
		)

		return errors.Join(fmt.Errorf("launchd preflight: %w", err), phaseErr)
	}

	err = withLaunchdLifecycleLock(plan.LaunchdPath, func() error {
		return installLaunchdLocked(plan, plist, stdout, runner, userID, waitPolicy)
	})
	var lockErr *launchdLifecycleLockError
	if errors.As(err, &lockErr) {
		phaseErr := writeLaunchdFailurePhase(
			stdout,
			"preflight",
			"lifecycle_lock_failed",
			"retry_install",
		)

		return errors.Join(err, phaseErr)
	}

	return err
}

func installLaunchdLocked(
	plan installPlan,
	plist string,
	stdout io.Writer,
	runner commandRunner,
	userID string,
	waitPolicy launchdWaitPolicy,
) error {
	if err := validateLaunchdDomainPreflight(runner, userID); err != nil {
		phaseErr := writeLaunchdFailurePhase(
			stdout,
			"preflight",
			"domain_unavailable",
			"login_to_gui_session",
		)

		return errors.Join(fmt.Errorf("launchd preflight: %w", err), phaseErr)
	}
	if err := writeLaunchdPhase(stdout, "preflight", "complete", launchdProcessStatus{}); err != nil {
		return err
	}
	snapshot, err := readOwnedLaunchdPlist(plan.LaunchdPath)
	if err != nil {
		phaseErr := writeLaunchdFailurePhase(
			stdout,
			"installed",
			"ownership_validation_failed",
			"inspect_plist",
		)

		return errors.Join(err, phaseErr)
	}
	baselineStatus, baselineLoaded, err := queryLaunchdStatus(runner, userID)
	if err != nil {
		phaseErr := writeLaunchdFailurePhase(
			stdout,
			"loaded",
			"status_query_failed",
			"retry_install",
		)

		return errors.Join(fmt.Errorf("inspect existing launchd service: %w", err), phaseErr)
	}
	if !snapshot.exists && baselineLoaded {
		phaseErr := writeLaunchdFailurePhase(
			stdout,
			"installed",
			"ownership_conflict",
			"inspect_plist",
		)

		return errors.Join(
			fmt.Errorf("refusing to replace loaded launchd service without an owned plist"),
			phaseErr,
		)
	}
	restoreBaseline := func(activationAttempted bool) error {
		return restoreLaunchdBaseline(
			plan.LaunchdPath,
			snapshot,
			baselineStatus,
			baselineLoaded,
			runner,
			userID,
			waitPolicy,
			activationAttempted,
		)
	}

	desiredBody := []byte(plist + "\n")
	isSamePlist := snapshot.exists && bytes.Equal(snapshot.body, desiredBody)
	if isSamePlist && baselineLoaded && isRunningLaunchdStatus(baselineStatus) {
		if err := writeLaunchdPhase(stdout, "installed", "complete", launchdProcessStatus{}); err != nil {
			return err
		}
		if err := writeLaunchdPhase(stdout, "loaded", "complete", launchdProcessStatus{}); err != nil {
			return err
		}
		return reportLaunchdInstall(stdout, plan, baselineStatus)
	}
	if isSamePlist && baselineLoaded {
		if err := writeLaunchdPhase(stdout, "installed", "complete", launchdProcessStatus{}); err != nil {
			return err
		}
		if err := writeLaunchdPhase(stdout, "loaded", "complete", launchdProcessStatus{}); err != nil {
			return err
		}
		if err := runner.Run(launchctlBinaryPath, "kickstart", "-p", launchdServiceTarget(userID)); err != nil {
			phaseErr := writeLaunchdFailurePhase(stdout, "running", "kickstart_failed", "retry_install")

			return errors.Join(safeLaunchdCommandError("kickstart existing launchd service", err), phaseErr)
		}
		status, loaded, err := waitForLaunchdRunning(runner, userID, waitPolicy)
		if err != nil {
			phaseErr := writeLaunchdFailurePhase(stdout, "running", "status_query_failed", "retry_install")

			return errors.Join(fmt.Errorf("read launchd status after kickstart: %w", err), phaseErr)
		}
		if !loaded || !isRunningLaunchdStatus(status) {
			phaseErr := writeLaunchdFailurePhase(stdout, "running", "not_running", "retry_install")

			return errors.Join(fmt.Errorf("launchd service did not reach running state"), phaseErr)
		}

		return reportLaunchdInstall(stdout, plan, status)
	}

	if snapshot.exists && baselineLoaded {
		if err := runner.Run(launchctlBinaryPath, "bootout", launchdServiceTarget(userID)); err != nil {
			phaseErr := writeLaunchdFailurePhase(stdout, "loaded", "bootout_failed", "retry_install")

			return errors.Join(
				safeLaunchdCommandError("stop existing launchd service before replacement", err),
				phaseErr,
			)
		}
		_, stillLoaded, err := waitForLaunchdAbsent(runner, userID, waitPolicy)
		if err != nil {
			phaseErr := writeLaunchdFailurePhase(stdout, "loaded", "status_query_failed", "retry_install")

			return errors.Join(fmt.Errorf("confirm existing launchd service stopped: %w", err), phaseErr)
		}
		if stillLoaded {
			phaseErr := writeLaunchdFailurePhase(stdout, "loaded", "bootout_incomplete", "retry_install")

			return errors.Join(fmt.Errorf("existing launchd service remained loaded after bootout"), phaseErr)
		}
	}
	if !isSamePlist {
		if err := writeAtomicLaunchdPlist(plan.LaunchdPath, plist, 0o644); err != nil {
			rollbackErr := restoreBaseline(false)
			phaseErr := writeLaunchdFailurePhase(stdout, "installed", "plist_write_failed", "retry_install")
			writeLaunchdRollbackPhase(stdout, rollbackErr)

			return errors.Join(fmt.Errorf("write launchd plist: %w", err), rollbackErr, phaseErr)
		}
	}
	if err := writeLaunchdPhase(stdout, "installed", "complete", launchdProcessStatus{}); err != nil {
		rollbackErr := restoreBaseline(false)
		return errors.Join(err, rollbackErr)
	}
	if err := runner.Run(launchctlBinaryPath, "bootstrap", launchdDomainTarget(userID), plan.LaunchdPath); err != nil {
		rollbackErr := restoreBaseline(true)
		phaseErr := writeLaunchdFailurePhase(stdout, "loaded", "bootstrap_failed", "retry_install")
		writeLaunchdRollbackPhase(stdout, rollbackErr)
		return errors.Join(
			safeLaunchdCommandError("bootstrap launchd service", err),
			rollbackErr,
			phaseErr,
		)
	}
	_, loaded, err := waitForLaunchdLoaded(runner, userID, waitPolicy)
	if err != nil {
		rollbackErr := restoreBaseline(true)
		phaseErr := writeLaunchdFailurePhase(stdout, "loaded", "status_query_failed", "retry_install")
		writeLaunchdRollbackPhase(stdout, rollbackErr)

		return errors.Join(fmt.Errorf("read launchd status after bootstrap: %w", err), rollbackErr, phaseErr)
	}
	if !loaded {
		rollbackErr := restoreBaseline(true)
		phaseErr := writeLaunchdFailurePhase(stdout, "loaded", "not_loaded", "retry_install")
		writeLaunchdRollbackPhase(stdout, rollbackErr)

		return errors.Join(fmt.Errorf("launchd service did not reach loaded state"), rollbackErr, phaseErr)
	}
	if err := writeLaunchdPhase(stdout, "loaded", "complete", launchdProcessStatus{}); err != nil {
		rollbackErr := restoreBaseline(true)
		return errors.Join(err, rollbackErr)
	}
	if err := runner.Run(launchctlBinaryPath, "kickstart", "-p", launchdServiceTarget(userID)); err != nil {
		rollbackErr := restoreBaseline(true)
		phaseErr := writeLaunchdFailurePhase(stdout, "running", "kickstart_failed", "retry_install")
		writeLaunchdRollbackPhase(stdout, rollbackErr)
		return errors.Join(
			safeLaunchdCommandError("kickstart launchd service", err),
			rollbackErr,
			phaseErr,
		)
	}
	status, loaded, err := waitForLaunchdRunning(runner, userID, waitPolicy)
	if err != nil {
		rollbackErr := restoreBaseline(true)
		phaseErr := writeLaunchdFailurePhase(stdout, "running", "status_query_failed", "retry_install")
		writeLaunchdRollbackPhase(stdout, rollbackErr)

		return errors.Join(fmt.Errorf("read launchd status after activation: %w", err), rollbackErr, phaseErr)
	}
	if !loaded || !isRunningLaunchdStatus(status) {
		rollbackErr := restoreBaseline(true)
		phaseErr := writeLaunchdFailurePhase(stdout, "running", "not_running", "retry_install")
		writeLaunchdRollbackPhase(stdout, rollbackErr)

		return errors.Join(fmt.Errorf("launchd service did not reach running state"), rollbackErr, phaseErr)
	}

	return reportLaunchdInstall(stdout, plan, status)
}

func reportLaunchdInstall(stdout io.Writer, plan installPlan, status launchdProcessStatus) error {
	if err := writeLaunchdPhase(stdout, "running", "complete", status); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(
		stdout,
		"collector_service_phase=heartbeat_seen status=pending next_action=wait_for_heartbeat",
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(
		stdout,
		"collector_install_status=running launchd_plist=%s service=%s state=%s pid=%d reboot_recovery=enabled heartbeat_status=not_checked next_action=wait_for_heartbeat\n",
		plan.LaunchdPath,
		launchdServiceLabel,
		status.state,
		status.pid,
	); err != nil {
		return err
	}

	return writeHookSnippets(stdout, plan)
}

func uninstallLaunchd(
	launchdPath string,
	dryRun bool,
	stdout io.Writer,
	runner commandRunner,
	userID string,
) error {
	if dryRun {
		_, err := fmt.Fprintf(
			stdout,
			"collector_uninstall_status=planned launchd_plist=%s service=%s\n",
			launchdPath,
			launchdServiceLabel,
		)

		return err
	}
	if err := validateLaunchdUserID(userID); err != nil {
		return err
	}

	return withLaunchdLifecycleLock(launchdPath, func() error {
		return uninstallLaunchdLocked(launchdPath, stdout, runner, userID)
	})
}

func uninstallLaunchdLocked(
	launchdPath string,
	stdout io.Writer,
	runner commandRunner,
	userID string,
) error {
	snapshot, err := readOwnedLaunchdPlist(launchdPath)
	if err != nil {
		return err
	}
	_, loaded, err := queryLaunchdStatus(runner, userID)
	if err != nil {
		return fmt.Errorf("inspect launchd service before uninstall: %w", err)
	}
	if !snapshot.exists {
		if loaded {
			return fmt.Errorf("refusing to stop loaded launchd service without an owned plist")
		}
		_, err := fmt.Fprintf(
			stdout,
			"collector_uninstall_status=absent launchd_plist=%s service=%s service_state=stopped\n",
			launchdPath,
			launchdServiceLabel,
		)

		return err
	}
	if loaded {
		if err := runner.Run(launchctlBinaryPath, "bootout", launchdServiceTarget(userID)); err != nil {
			return safeLaunchdCommandError("stop launchd service", err)
		}
		if _, stillLoaded, err := queryLaunchdStatus(runner, userID); err != nil {
			return fmt.Errorf("confirm launchd service stopped: %w", err)
		} else if stillLoaded {
			return fmt.Errorf("launchd service remained loaded after bootout")
		}
	}
	if err := os.Remove(launchdPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove owned launchd plist: %w", err)
	}
	_, err = fmt.Fprintf(
		stdout,
		"collector_uninstall_status=removed launchd_plist=%s service=%s service_state=stopped\n",
		launchdPath,
		launchdServiceLabel,
	)

	return err
}

func statusLaunchd(
	launchdPath string,
	stdout io.Writer,
	runner commandRunner,
	userID string,
) error {
	if err := validateLaunchdUserID(userID); err != nil {
		return err
	}

	return withLaunchdLifecycleLock(launchdPath, func() error {
		return statusLaunchdLocked(launchdPath, stdout, runner, userID)
	})
}

func statusLaunchdLocked(
	launchdPath string,
	stdout io.Writer,
	runner commandRunner,
	userID string,
) error {
	snapshot, err := readOwnedLaunchdPlist(launchdPath)
	if err != nil {
		return err
	}
	status, loaded, err := queryLaunchdStatus(runner, userID)
	if err != nil {
		return fmt.Errorf("read launchd service status: %w", err)
	}
	if !snapshot.exists {
		if loaded {
			return fmt.Errorf("loaded launchd service has no owned plist")
		}
		_, err := fmt.Fprintf(
			stdout,
			"collector_service_status=absent service=%s state=not_installed pid=0 reboot_recovery=disabled heartbeat_status=not_checked next_action=install\n",
			launchdServiceLabel,
		)

		return err
	}
	if !loaded {
		_, err := fmt.Fprintf(
			stdout,
			"collector_service_status=installed service=%s state=not_loaded pid=0 reboot_recovery=enabled heartbeat_status=not_checked next_action=install\n",
			launchdServiceLabel,
		)

		return err
	}
	serviceStatus := "loaded"
	if isRunningLaunchdStatus(status) {
		serviceStatus = "running"
	}
	_, err = fmt.Fprintf(
		stdout,
		"collector_service_status=%s service=%s state=%s pid=%d reboot_recovery=enabled heartbeat_status=not_checked next_action=%s\n",
		serviceStatus,
		launchdServiceLabel,
		status.state,
		status.pid,
		launchdStatusNextAction(serviceStatus),
	)

	return err
}

func validateLaunchdStaticPreflight(plan installPlan, userID string) error {
	if err := validateLaunchdUserID(userID); err != nil {
		return err
	}
	if filepath.Base(plan.LaunchdPath) != launchdPlistName ||
		filepath.Base(filepath.Dir(plan.LaunchdPath)) != "LaunchAgents" ||
		filepath.Base(filepath.Dir(filepath.Dir(plan.LaunchdPath))) != "Library" {
		return fmt.Errorf("launchd plist path must be the user LaunchAgents path")
	}
	info, err := os.Stat(plan.BinaryPath)
	if err != nil {
		return fmt.Errorf("stat collector binary: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("collector binary is not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("collector binary is not executable")
	}

	return nil
}

func validateLaunchdDomainPreflight(runner commandRunner, userID string) error {
	if _, err := runner.Output(launchctlBinaryPath, "print", launchdDomainTarget(userID)); err != nil {
		return safeLaunchdCommandError("GUI launchd domain is unavailable", err)
	}

	return nil
}

func validateLaunchdUserID(userID string) error {
	value, err := strconv.Atoi(userID)
	if err != nil || value <= 0 {
		return fmt.Errorf("a non-root numeric GUI user ID is required")
	}

	return nil
}

func queryLaunchdStatus(
	runner commandRunner,
	userID string,
) (launchdProcessStatus, bool, error) {
	output, err := runner.Output(launchctlBinaryPath, "print", launchdServiceTarget(userID))
	if err != nil {
		if isLaunchdServiceNotFound(output, err) {
			return launchdProcessStatus{}, false, nil
		}

		return launchdProcessStatus{}, false, fmt.Errorf("launchd service query failed")
	}
	status, err := parseLaunchdStatus(output)
	if err != nil {
		return launchdProcessStatus{}, false, err
	}

	return status, true, nil
}

func parseLaunchdStatus(output string) (launchdProcessStatus, error) {
	status := launchdProcessStatus{state: "loaded"}
	depth := 0
	hasRootDictionary := false
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		isDictionaryOpen := strings.HasSuffix(trimmed, " = {")
		isDictionaryClose := trimmed == "}"
		if hasRootDictionary && depth == 1 {
			switch {
			case strings.HasPrefix(trimmed, "state = "):
				status.state = strings.TrimSpace(strings.TrimPrefix(trimmed, "state = "))
			case strings.HasPrefix(trimmed, "pid = "):
				pid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(trimmed, "pid = ")))
				if err != nil || pid <= 0 {
					return launchdProcessStatus{}, fmt.Errorf("launchd returned an invalid process ID")
				}
				status.pid = pid
			}
		}
		if isDictionaryOpen {
			depth++
			hasRootDictionary = true
		}
		if isDictionaryClose {
			depth--
		}
		if depth < 0 {
			return launchdProcessStatus{}, fmt.Errorf("launchd returned malformed service output")
		}
	}
	if !hasRootDictionary || depth != 0 {
		return launchdProcessStatus{}, fmt.Errorf("launchd returned malformed service output")
	}
	if strings.TrimSpace(status.state) == "" {
		return launchdProcessStatus{}, fmt.Errorf("launchd returned an empty service state")
	}
	if status.state == "running" && status.pid <= 0 {
		return launchdProcessStatus{}, fmt.Errorf("launchd returned running state without a process ID")
	}

	return status, nil
}

func isRunningLaunchdStatus(status launchdProcessStatus) bool {
	return status.state == "running" && status.pid > 0
}

func isLaunchdServiceNotFound(output string, err error) bool {
	message := strings.ToLower(output + "\n" + err.Error())

	return strings.Contains(message, "could not find service") ||
		strings.Contains(message, "service not found") ||
		strings.Contains(message, "no such process")
}

func safeLaunchdCommandError(action string, err error) error {
	var executionError *commandExecutionError
	if errors.As(err, &executionError) {
		return fmt.Errorf("%s: %w", action, executionError)
	}

	return fmt.Errorf("%s failed", action)
}

func writeLaunchdRollbackPhase(stdout io.Writer, rollbackErr error) {
	status := "complete"
	if rollbackErr != nil {
		status = "failed"
	}
	_, _ = fmt.Fprintf(stdout, "collector_service_phase=rollback status=%s\n", status)
}

func writeLaunchdPhase(
	stdout io.Writer,
	phase string,
	status string,
	process launchdProcessStatus,
) error {
	if process.state != "" {
		_, err := fmt.Fprintf(
			stdout,
			"collector_service_phase=%s status=%s state=%s pid=%d\n",
			phase,
			status,
			process.state,
			process.pid,
		)

		return err
	}
	_, err := fmt.Fprintf(stdout, "collector_service_phase=%s status=%s\n", phase, status)

	return err
}

func writeLaunchdFailurePhase(
	stdout io.Writer,
	phase string,
	reason string,
	nextAction string,
) error {
	_, err := fmt.Fprintf(
		stdout,
		"collector_service_phase=%s status=failed reason=%s next_action=%s\n",
		phase,
		reason,
		nextAction,
	)

	return err
}

func launchdStatusNextAction(serviceStatus string) string {
	if serviceStatus == "running" {
		return "check_heartbeat"
	}

	return "install"
}

func readOwnedLaunchdPlist(path string) (launchdPlistSnapshot, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return launchdPlistSnapshot{}, nil
	}
	if err != nil {
		return launchdPlistSnapshot{}, fmt.Errorf("stat launchd plist: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return launchdPlistSnapshot{}, fmt.Errorf("launchd plist must be an owned regular file, not a symlink")
	}
	if !info.Mode().IsRegular() {
		return launchdPlistSnapshot{}, fmt.Errorf("launchd plist must be an owned regular file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return launchdPlistSnapshot{}, fmt.Errorf("read launchd plist: %w", err)
	}
	if !isOwnedLaunchdPlist(body) {
		return launchdPlistSnapshot{}, fmt.Errorf("existing launchd plist is not Mitoriq-owned")
	}

	return launchdPlistSnapshot{body: body, exists: true, mode: info.Mode()}, nil
}

func (plan installPlan) launchdPlist() (string, error) {
	if plan.BinaryPath == "" || strings.ContainsAny(plan.BinaryPath, "\x00\r\n") {
		return "", fmt.Errorf("binary path contains unsupported characters")
	}
	if !isAbsoluteLaunchdBinaryPath(plan.BinaryPath) {
		return "", fmt.Errorf("macOS service binary path must be absolute")
	}
	var escapedBinary strings.Builder
	if err := xml.EscapeText(&escapedBinary, []byte(plan.BinaryPath)); err != nil {
		return "", fmt.Errorf("escape collector binary path: %w", err)
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>daemon</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>%s</key>
    <string>%s</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>`, launchdServiceLabel, escapedBinary.String(), launchdOwnershipMarker, launchdOwnershipValue), nil
}

func isAbsoluteLaunchdBinaryPath(binaryPath string) bool {
	if path.IsAbs(binaryPath) {
		return true
	}

	return runtime.GOOS == "windows" && filepath.IsAbs(binaryPath)
}

func launchdDomainTarget(userID string) string {
	return "gui/" + userID
}

func launchdServiceTarget(userID string) string {
	return launchdDomainTarget(userID) + "/" + launchdServiceLabel
}

func defaultLaunchdPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}

	return filepath.Join(home, "Library", "LaunchAgents", launchdPlistName)
}
