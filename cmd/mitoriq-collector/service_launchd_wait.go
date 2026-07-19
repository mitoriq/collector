package main

import "time"

const (
	launchdStateWaitTimeout  = 5 * time.Second
	launchdStatePollInterval = 100 * time.Millisecond
)

type launchdWaitPolicy struct {
	timeout  time.Duration
	interval time.Duration
	now      func() time.Time
	sleep    func(time.Duration)
}

type launchdStatePredicate func(launchdProcessStatus, bool) bool

func defaultLaunchdWaitPolicy() launchdWaitPolicy {
	return launchdWaitPolicy{
		timeout:  launchdStateWaitTimeout,
		interval: launchdStatePollInterval,
		now:      time.Now,
		sleep:    time.Sleep,
	}
}

func waitForLaunchdState(
	runner commandRunner,
	userID string,
	policy launchdWaitPolicy,
	predicate launchdStatePredicate,
) (launchdProcessStatus, bool, error) {
	deadline := policy.now().Add(policy.timeout)
	var lastStatus launchdProcessStatus
	lastLoaded := false
	for isFirstProbe := true; ; isFirstProbe = false {
		if !isFirstProbe && !policy.now().Before(deadline) {
			return lastStatus, lastLoaded, nil
		}
		status, loaded, err := queryLaunchdStatus(runner, userID)
		if err != nil {
			return launchdProcessStatus{}, false, err
		}
		lastStatus = status
		lastLoaded = loaded
		if predicate(status, loaded) {
			return status, loaded, nil
		}

		remaining := deadline.Sub(policy.now())
		if remaining <= 0 {
			return lastStatus, lastLoaded, nil
		}
		delay := policy.interval
		if delay > remaining {
			delay = remaining
		}
		policy.sleep(delay)
	}
}

func waitForLaunchdLoaded(
	runner commandRunner,
	userID string,
	policy launchdWaitPolicy,
) (launchdProcessStatus, bool, error) {
	return waitForLaunchdState(runner, userID, policy, func(_ launchdProcessStatus, loaded bool) bool {
		return loaded
	})
}

func waitForLaunchdRunning(
	runner commandRunner,
	userID string,
	policy launchdWaitPolicy,
) (launchdProcessStatus, bool, error) {
	return waitForLaunchdState(runner, userID, policy, func(status launchdProcessStatus, loaded bool) bool {
		return loaded && isRunningLaunchdStatus(status)
	})
}

func waitForLaunchdAbsent(
	runner commandRunner,
	userID string,
	policy launchdWaitPolicy,
) (launchdProcessStatus, bool, error) {
	return waitForLaunchdState(runner, userID, policy, func(_ launchdProcessStatus, loaded bool) bool {
		return !loaded
	})
}

func waitForLaunchdBaseline(
	runner commandRunner,
	userID string,
	policy launchdWaitPolicy,
	baselineStatus launchdProcessStatus,
	baselineLoaded bool,
) (launchdProcessStatus, bool, error) {
	return waitForLaunchdState(runner, userID, policy, func(status launchdProcessStatus, loaded bool) bool {
		if !baselineLoaded {
			return !loaded
		}
		if isRunningLaunchdStatus(baselineStatus) {
			return loaded && isRunningLaunchdStatus(status)
		}
		return loaded
	})
}
