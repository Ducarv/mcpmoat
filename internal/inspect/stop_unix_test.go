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

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// stopGrace is inspect.stopGrace. A normal stop closes stdin, waits at most
// this long for the server to exit, and then kills the process group. The
// time bounds below allow 3*stopGrace, to leave slack for a slow machine.
const stopGrace = inspect.StopGrace

// reapLag is how long the test polls for the process to go away when the
// first check finds it. Any lag at all violates the stop contract, so the
// test fails in that case too; the poll only measures the lag for the report.
const reapLag = 100 * time.Millisecond

// TestSDKInspectStopsChild checks the stop guarantee of Inspect (issue #25): when
// Inspect returns, on success and on every error, the child process was
// stopped and reaped. kill(pid, 0) answers for a running process and also for
// a zombie (a process that exited but was not reaped by Wait), so ESRCH right
// after Inspect returns proves that the process is gone and reaped.
func TestSDKInspectStopsChild(t *testing.T) {
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
			server := sdkBenign(t, "-mode", tt.mode, "-pidfile", pidfile)

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
			_, err := sdkNew(t, inspect.SDKOptions{}).Inspect(ctx, server)
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

// TestSDKInspectKillsProcessGroup checks that Inspect also stops a process
// that the server started and that stayed in its process group, on a normal
// stop and on a ctx deadline. The fixture starts a copy of itself that never
// exits (-spawn). Without the process group kill, that copy keeps running
// after Inspect returns.
func TestSDKInspectKillsProcessGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mode    string
		timeout time.Duration
	}{
		{name: "normal stop", mode: "ok", timeout: 10 * time.Second},
		{name: "ctx deadline", mode: "hang-list", timeout: time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spawnfile := filepath.Join(t.TempDir(), "spawn")
			server := sdkBenign(t, "-mode", tt.mode, "-spawn", spawnfile)
			ctx, cancel := context.WithTimeout(t.Context(), tt.timeout)
			defer cancel()

			_, _ = sdkNew(t, inspect.SDKOptions{}).Inspect(ctx, server)

			pid := sdkReadPID(t, spawnfile)
			// The spawned process is not a child of mcpmoat. After the
			// SIGKILL, init (or launchd) reaps it, which can take a moment,
			// so poll for a short time.
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			deadline := time.After(5 * time.Second)
			for {
				err := syscall.Kill(pid, 0)
				if errors.Is(err, syscall.ESRCH) {
					return
				}
				select {
				case <-ticker.C:
				case <-deadline:
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("process %d that the server started still runs after Inspect returned (kill 0: %v)", pid, err)
				}
			}
		})
	}
}

// TestSDKInspectFloodWithoutReads checks that Inspect returns soon after a
// successful list, also when the server floods ping requests and then never
// reads its stdin. The replies of the client fill the pipe and block.
// Inspect must stop the child, which closes its stdin, before it closes the
// MCP session, because the close of the session waits for those writes.
// With the wrong order, Inspect returns only when ctx ends.
//
// The test checks ctx, not a wall-clock bound: a loaded CI runner with -race
// can take 20s or more for the pings, while the wrong order always waits for
// the end of ctx.
func TestSDKInspectFloodWithoutReads(t *testing.T) {
	t.Parallel()

	// Build the fixture before ctx starts, so a cold build cache does not
	// count against it.
	server := sdkBenign(t, "-mode", "flood-list")
	inspector := sdkNew(t, inspect.SDKOptions{})
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	start := time.Now()
	res, err := inspector.Inspect(ctx, server)
	elapsed := time.Since(start)
	ctxErr := ctx.Err()

	if err != nil {
		t.Fatalf("Inspect() error = %v, want nil", err)
	}
	if res.Tools == nil || len(res.Tools) != 0 {
		t.Errorf("Inspect() Tools = %#v, want an empty, non-nil slice", res.Tools)
	}
	if ctxErr != nil {
		t.Errorf("Inspect returned after %v, when ctx had ended (%v); want a return before the end of ctx", elapsed, ctxErr)
	}
	t.Logf("Inspect returned after %v", elapsed)
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
				// Send before cancel: once cancel runs, Inspect can
				// return and the test can read done before a later
				// send. done has room for one value, so this never
				// blocks.
				done <- time.Now()
				cancel()
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
