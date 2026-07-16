package filelock

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type heldLock struct {
	done    chan error
	release chan struct{}
	once    sync.Once
}

func acquireHeldLock(t *testing.T, path string) *heldLock {
	t.Helper()
	locked := make(chan struct{})
	holder := &heldLock{
		done:    make(chan error, 1),
		release: make(chan struct{}),
	}
	go func() {
		holder.done <- With(path, func() error {
			close(locked)
			<-holder.release
			return nil
		})
	}()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("timed out acquiring holder lock")
	}
	t.Cleanup(func() {
		holder.Release(t)
	})

	return holder
}

func (holder *heldLock) Release(t *testing.T) {
	t.Helper()
	holder.once.Do(func() {
		close(holder.release)
		if err := <-holder.done; err != nil {
			t.Errorf("release holder lock: %v", err)
		}
	})
}

func TestWithContextStopsWaitingWhenContextCanceled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector.lock")
	acquireHeldLock(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	var callbackCalls atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- WithContext(ctx, path, func() error {
			callbackCalls.Add(1)
			return nil
		})
	}()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not stop lock wait")
	}
	if calls := callbackCalls.Load(); calls != 0 {
		t.Fatalf("callback calls = %d, want 0", calls)
	}
}

func TestWithContextAcquiresLockAfterContentionClears(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector.lock")
	holder := acquireHeldLock(t, path)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var callbackCalls atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- WithContext(ctx, path, func() error {
			callbackCalls.Add(1)
			return nil
		})
	}()
	holder.Release(t)

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("lock was not acquired after contention cleared")
	}
	if calls := callbackCalls.Load(); calls != 1 {
		t.Fatalf("callback calls = %d, want 1", calls)
	}
}

func TestAcquireWithRetryStopsAfterContentionWhenContextCanceled(t *testing.T) {
	contentionErr := errors.New("lock contended")
	firstAttempt := make(chan struct{})
	var signalOnce sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- acquireWithRetry(ctx, func() error {
			signalOnce.Do(func() {
				close(firstAttempt)
			})
			return contentionErr
		}, func(err error) bool {
			return errors.Is(err, contentionErr)
		})
	}()
	<-firstAttempt
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not stop retry wait")
	}
}

func TestAcquireWithRetrySucceedsAfterContentionClears(t *testing.T) {
	contentionErr := errors.New("lock contended")
	firstAttempt := make(chan struct{})
	var attempts atomic.Int32
	var canAcquire atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- acquireWithRetry(context.Background(), func() error {
			if attempts.Add(1) == 1 {
				close(firstAttempt)
				return contentionErr
			}
			if canAcquire.Load() {
				return nil
			}
			return contentionErr
		}, func(err error) bool {
			return errors.Is(err, contentionErr)
		})
	}()
	<-firstAttempt
	canAcquire.Store(true)

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("lock was not acquired after contention cleared")
	}
	if count := attempts.Load(); count < 2 {
		t.Fatalf("lock attempts = %d, want at least 2", count)
	}
}
