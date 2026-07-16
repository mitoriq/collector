package filelock

import (
	"context"
	"time"
)

const retryInterval = 10 * time.Millisecond

func acquireWithRetry(
	ctx context.Context,
	tryLock func() error,
	isContended func(error) bool,
) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := tryLock()
		if err == nil {
			return nil
		}
		if !isContended(err) {
			return err
		}
		if err := waitForRetry(ctx); err != nil {
			return err
		}
	}
}

func waitForRetry(ctx context.Context) error {
	timer := time.NewTimer(retryInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
