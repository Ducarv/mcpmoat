//go:build unix

package inspect_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

// stopGrace mirrors the unexported constant inspect.stopGrace (sdk.go). The
// SDK command transport waits this long after it closes stdin and again after
// SIGTERM, then sends SIGKILL and waits once more. So a normal stop takes at
// most 3*stopGrace. Keep the two values the same.
const stopGrace = 2 * time.Second

// reapLag is how long the test polls for the process to go away when the
// first check finds it. Any lag at all violates the stop contract, so the
// test fails in that case too; the poll only measures the lag for the report.
const reapLag = 100 * time.Millisecond

// TestInspectStopsChild checks the stop guarantee of Inspect (issue #25): when
// Inspect returns, on success and on every error, the child process was
// stopped and reaped. kill(pid, 0) answers for a running process and also for
// a zombie (a process that exited but was not reaped by Wait), so ESRCH right
// after Inspect returns proves that the process is gone and reaped.
func TestInspectStopsChild(t *testing.T) {
	t.Parallel()

	// cancelOnStart is the sentinel timeout for the cases that cancel ctx
	// explicitly as soon as the child has written its pidfile.
	const cancelOnStart = time.Duration(0)

	tests := []struct {
		name    string
		mode    string
		timeout time.Duration // cancelOnStart: cancel explicitly instead
		wantErr error         // nil: Inspect must succeed; errAny: any error
		maxTime time.Duration // upper bound for the elapsed time of Inspect
	}{
		{name: "ok", mode: "ok", timeout: 10 * time.Second, wantErr: nil, maxTime: 5 * time.Second},
		{name: "crash", mode: "crash", timeout: 10 * time.Second, wantErr: errAny, maxTime: 5 * time.Second},
		{name: "hang-init deadline", mode: "hang-init", timeout: time.Second, wantErr: context.DeadlineExceeded, maxTime: time.Second + 3*stopGrace + time.Second},
		{name: "hang-list deadline", mode: "hang-list", timeout: time.Second, wantErr: context.DeadlineExceeded, maxTime: time.Second + 3*stopGrace + time.Second},
		// For the cancel cases, maxTime bounds the time from the cancel to
		// the return of Inspect.
		{name: "hang-init cancel", mode: "hang-init", timeout: cancelOnStart, wantErr: context.Canceled, maxTime: 3*stopGrace + time.Second},
		{name: "hang-list cancel", mode: "hang-list", timeout: cancelOnStart, wantErr: context.Canceled, maxTime: 3*stopGrace + time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pidfile := filepath.Join(t.TempDir(), "pid")
			server := discover.Server{
				Name:      "benign-" + tt.mode,
				Transport: discover.TransportStdio,
				Command:   inspecttest.Fixture(t, "benign"),
				Args:      discover.NewArgs([]string{"-mode", tt.mode, "-pidfile", pidfile}),
			}

			var (
				ctx      context.Context
				cancel   context.CancelFunc
				canceled <-chan time.Time // time of the explicit cancel
			)
			if tt.timeout == cancelOnStart {
				// The outer timeout only keeps a broken test from
				// hanging; the case wants context.Canceled, so hitting
				// this deadline fails the test.
				outer, outerCancel := context.WithTimeout(t.Context(), 10*time.Second)
				t.Cleanup(outerCancel)
				ctx, cancel = context.WithCancel(outer)
				canceled = cancelWhenStarted(ctx, cancel, pidfile)
			} else {
				ctx, cancel = context.WithTimeout(t.Context(), tt.timeout)
			}
			defer cancel()

			start := time.Now()
			_, err := inspect.New(inspect.Options{}).Inspect(ctx, server)
			end := time.Now()

			// Check the process first, before anything else can give it
			// time to go away: the contract is "stopped before Inspect
			// returns".
			pid := sdkReadPID(t, pidfile)
			assertGone(t, pid, end)

			elapsed := end.Sub(start)
			measured := elapsed
			if canceled != nil {
				select {
				case at := <-canceled:
					measured = end.Sub(at)
					t.Logf("mode %s: Inspect returned %v after the cancel (%v in total)", tt.mode, measured, elapsed)
				default:
					t.Errorf("Inspect returned before the explicit cancel (after %v)", elapsed)
				}
			} else {
				t.Logf("mode %s: Inspect returned after %v (timeout %v)", tt.mode, elapsed, tt.timeout)
			}
			if measured > tt.maxTime {
				t.Errorf("Inspect took %v, want at most %v", measured, tt.maxTime)
			}

			switch {
			case tt.wantErr == nil:
				if err != nil {
					t.Errorf("Inspect() error = %v, want nil", err)
				}
			case errors.Is(tt.wantErr, errAny):
				if err == nil {
					t.Error("Inspect() error = nil, want an error")
				}
			default:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Inspect() error = %v, want errors.Is(err, %v)", err, tt.wantErr)
				}
			}
		})
	}
}

// errAny is a marker for test cases that accept any non-nil error.
var errAny = errors.New("any error")

// cancelWhenStarted polls pidfile until the child has written its PID, then
// calls cancel. It sends the time of the cancel on the returned channel. If
// ctx ends first, or the child does not write the file within 10s, it stops
// without a cancel and sends nothing.
func cancelWhenStarted(ctx context.Context, cancel context.CancelFunc, pidfile string) <-chan time.Time {
	done := make(chan time.Time, 1)
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-deadline.C:
				return
			case <-ticker.C:
				// The child writes "<pid>\n" in one WriteFile call. The
				// newline shows that the write is complete.
				data, err := os.ReadFile(pidfile) //nolint:gosec // G304: pidfile is a path in t.TempDir() that the test made
				if err != nil || !strings.HasSuffix(string(data), "\n") {
					continue
				}
				at := time.Now()
				cancel()
				done <- at
				return
			}
		}
	}()
	return done
}

// assertGone checks that the process pid no longer exists, also not as a
// zombie. returned is the time when Inspect returned. If the first check
// finds the process, assertGone polls for at most reapLag to measure the lag,
// and fails in both cases: the contract is that the process is stopped and
// reaped before Inspect returns.
func assertGone(t *testing.T, pid int, returned time.Time) {
	t.Helper()
	err := syscall.Kill(pid, 0)
	if errors.Is(err, syscall.ESRCH) {
		return
	}
	first := err

	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(reapLag)
	defer deadline.Stop()
	for {
		select {
		case <-ticker.C:
			if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
				t.Errorf("stop contract violated: process %d still existed when Inspect returned (kill 0: %v); it was gone %v later",
					pid, first, time.Since(returned))
				return
			}
		case <-deadline.C:
			t.Errorf("stop contract violated: process %d still exists %v after Inspect returned (kill 0: %v)",
				pid, time.Since(returned), first)
			// Do not leave the process behind after the failure.
			_ = syscall.Kill(pid, syscall.SIGKILL)
			return
		}
	}
}
