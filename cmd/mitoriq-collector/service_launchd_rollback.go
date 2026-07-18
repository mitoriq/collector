package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

func stopPartialLaunchdService(
	runner commandRunner,
	userID string,
	waitPolicy launchdWaitPolicy,
	activationAttempted bool,
) error {
	var loaded bool
	var err error
	if activationAttempted {
		_, loaded, err = waitForLaunchdLoaded(runner, userID, waitPolicy)
	} else {
		_, loaded, err = queryLaunchdStatus(runner, userID)
	}
	if err != nil {
		return fmt.Errorf("inspect partial launchd service: %w", err)
	}
	if !loaded {
		return nil
	}
	if err := runner.Run(launchctlBinaryPath, "bootout", launchdServiceTarget(userID)); err != nil {
		return safeLaunchdCommandError("bootout partial launchd service", err)
	}
	_, stillLoaded, err := waitForLaunchdAbsent(runner, userID, waitPolicy)
	if err != nil {
		return fmt.Errorf("confirm partial launchd service stopped: %w", err)
	}
	if stillLoaded {
		return fmt.Errorf("partial launchd service remained loaded after bootout")
	}

	return nil
}

func restoreLaunchdBaseline(
	launchdPath string,
	snapshot launchdPlistSnapshot,
	baselineStatus launchdProcessStatus,
	baselineLoaded bool,
	runner commandRunner,
	userID string,
	waitPolicy launchdWaitPolicy,
	activationAttempted bool,
) error {
	var rollbackErrors []error
	if err := stopPartialLaunchdService(runner, userID, waitPolicy, activationAttempted); err != nil {
		return err
	}
	plistRestored := false
	if snapshot.exists {
		mode := snapshot.mode.Perm()
		if mode == 0 {
			mode = 0o644
		}
		if err := writeAtomicLaunchdPlistBytes(launchdPath, snapshot.body, mode); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restore previous launchd plist: %w", err))
		} else {
			plistRestored = true
		}
	} else if err := os.Remove(launchdPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("remove partial launchd plist: %w", err))
	} else {
		plistRestored = true
	}
	if plistRestored && baselineLoaded {
		if err := runner.Run(launchctlBinaryPath, "bootstrap", launchdDomainTarget(userID), launchdPath); err != nil {
			rollbackErrors = append(
				rollbackErrors,
				safeLaunchdCommandError("reload previous launchd service", err),
			)
		} else {
			_, restoredLoaded, waitErr := waitForLaunchdLoaded(runner, userID, waitPolicy)
			if waitErr != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("wait for previous launchd service: %w", waitErr))
			} else if !restoredLoaded {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("previous launchd loaded state was not restored"))
			} else if isRunningLaunchdStatus(baselineStatus) {
				if err := runner.Run(launchctlBinaryPath, "kickstart", "-p", launchdServiceTarget(userID)); err != nil {
					rollbackErrors = append(
						rollbackErrors,
						safeLaunchdCommandError("restart previous launchd service", err),
					)
				}
			}
		}
	}
	if plistRestored {
		if err := verifyLaunchdPlistBaseline(launchdPath, snapshot); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	status, loaded, err := waitForLaunchdBaseline(
		runner,
		userID,
		waitPolicy,
		baselineStatus,
		baselineLoaded,
	)
	if err != nil {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("verify restored launchd service: %w", err))
	} else if loaded != baselineLoaded {
		rollbackErrors = append(
			rollbackErrors,
			fmt.Errorf("previous launchd loaded state was not restored"),
		)
	} else if baselineLoaded && isRunningLaunchdStatus(baselineStatus) && !isRunningLaunchdStatus(status) {
		rollbackErrors = append(
			rollbackErrors,
			fmt.Errorf("previous launchd service did not return to running state"),
		)
	}

	return errors.Join(rollbackErrors...)
}

func verifyLaunchdPlistBaseline(path string, snapshot launchdPlistSnapshot) error {
	body, err := os.ReadFile(path)
	if snapshot.exists {
		if err != nil {
			return fmt.Errorf("verify restored launchd plist: %w", err)
		}
		if !bytes.Equal(body, snapshot.body) {
			return fmt.Errorf("previous launchd plist bytes were not restored")
		}

		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("verify partial launchd plist removal: %w", err)
	}

	return fmt.Errorf("partial launchd plist remained after rollback")
}
