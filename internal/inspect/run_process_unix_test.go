//go:build unix

package inspect_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// These tests run Run against real child processes (the helper modes of
// helperprocess_unix_test.go). They do not call t.Parallel;
// helperprocess_unix_test.go explains why, and holds the time constants.
//
// The order of the outcomes is checked with fakes in run_test.go
// (TestRunOrder), which covers every tie-breaker and many input orders.

// namedMode is a fixture server: a unique name and a helper mode.
type namedMode struct{ name, mode string }

// helperServers returns one helper server per entry.
func helperServers(t *testing.T, modes ...namedMode) []discover.Server {
	t.Helper()
	servers := make([]discover.Server, 0, len(modes))
	for _, m := range modes {
		servers = append(servers, helperServer(t, m.name, m.mode))
	}
	return servers
}

// runModes runs one helper server per entry through inspect.Run and returns
// the outcomes indexed by server name. Names must be unique.
func runModes(t *testing.T, opts inspect.Options, insp inspect.Inspector, modes ...namedMode) map[string]inspect.Outcome {
	t.Helper()
	return byName(t, mustRun(t.Context(), t, helperServers(t, modes...), opts, insp))
}

// mustRunWithin is mustRun with a time limit: it fails the test if Run does
// not return within limit. Run runs in its own goroutine, and the checks stay
// in the test goroutine, because t.Fatal must not be called from another
// goroutine. If Run hangs, its goroutine is left behind until the test binary
// exits; the test has failed by then.
func mustRunWithin(t *testing.T, limit time.Duration, servers []discover.Server, opts inspect.Options, insp inspect.Inspector) []inspect.Outcome {
	t.Helper()
	type result struct {
		outcomes []inspect.Outcome
		err      error
	}
	done := make(chan result, 1)
	go func() {
		outcomes, err := inspect.Run(t.Context(), servers, opts, insp)
		done <- result{outcomes: outcomes, err: err}
	}()

	var res result
	select {
	case res = <-done:
	case <-time.After(limit):
		t.Fatalf("Run() did not return within %s", limit)
	}
	if res.err != nil {
		t.Fatalf("Run() error = %v, want nil", res.err)
	}
	if len(res.outcomes) != len(servers) {
		t.Fatalf("Run() returned %d outcomes, want %d", len(res.outcomes), len(servers))
	}
	return res.outcomes
}

// byName indexes outcomes by server name. It fails the test if two outcomes
// have the same name.
func byName(t *testing.T, outcomes []inspect.Outcome) map[string]inspect.Outcome {
	t.Helper()
	m := make(map[string]inspect.Outcome, len(outcomes))
	for _, o := range outcomes {
		if _, dup := m[o.Server.Name]; dup {
			t.Fatalf("duplicate outcome for server %q", o.Server.Name)
		}
		m[o.Server.Name] = o
	}
	return m
}

// TestRunTenSlowServersConcurrently is the integration test for NFR-03: ten
// servers that each need 1s to start must finish in well under 15s.
func TestRunTenSlowServersConcurrently(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the wall-time test in short mode")
	}

	const count = 10
	modes := make([]namedMode, 0, count)
	for i := range count {
		modes = append(modes, namedMode{fmt.Sprintf("slow-%02d", i), "slow"})
	}
	opts := inspect.Options{Timeout: 10 * time.Second, Concurrency: 4}

	start := time.Now()
	got := runModes(t, opts, execInspector{}, modes...)
	elapsed := time.Since(start)
	t.Logf("%d slow servers, concurrency %d: elapsed %s", count, opts.Concurrency, elapsed)

	for _, o := range got {
		checkStatus(t, o, inspect.StatusOK)
	}

	// Hard limit from NFR-03.
	if elapsed >= 15*time.Second {
		t.Fatalf("elapsed = %s, want < 15s (NFR-03)", elapsed)
	}
	// With 4 workers, 10 servers of 1s run in 3 rounds (4 + 4 + 2), so about 3s
	// plus the start cost of the processes, which is higher under -race. A
	// serial run needs at least 10s, so a result below 9s proves the pool runs
	// servers in parallel.
	if elapsed >= 9*time.Second {
		t.Errorf("elapsed = %s, want < 9s: expected about 3s plus start cost under -race; a serial run takes >= 10s", elapsed)
	}
}

// TestRunHangTimesOut checks that a server that never answers ends with
// StatusTimeout after about opts.Timeout, and that Run returns by itself.
func TestRunHangTimesOut(t *testing.T) {
	opts := inspect.Options{Timeout: time.Second, Concurrency: 1}

	start := time.Now()
	got := runModes(t, opts, execInspector{}, namedMode{"hang", "hang"})
	elapsed := time.Since(start)

	o := got["hang"]
	checkStatus(t, o, inspect.StatusTimeout)
	if !errors.Is(o.Err, context.DeadlineExceeded) {
		t.Errorf("errors.Is(Err, context.DeadlineExceeded) = false, Err = %v", o.Err)
	}
	if elapsed < opts.Timeout {
		t.Errorf("Run took %s, want at least the timeout %s", elapsed, opts.Timeout)
	}
	if limit := opts.Timeout + inspect.KillWaitDelay + processTreeSlack; elapsed > limit {
		t.Errorf("Run took %s, want at most %s", elapsed, limit)
	}
}

// TestRunMixedIsolation checks that a hung server and a crashed server do not
// change the outcome of the healthy servers (FR-06), and that Run returns.
func TestRunMixedIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the wall-time test in short mode")
	}

	servers := map[string]struct {
		mode string
		want inspect.Status
	}{
		"hang":   {mode: "hang", want: inspect.StatusTimeout},
		"crash":  {mode: "crash", want: inspect.StatusFailed},
		"slow-1": {mode: "slow", want: inspect.StatusOK},
		"slow-2": {mode: "slow", want: inspect.StatusOK},
		"slow-3": {mode: "slow", want: inspect.StatusOK},
	}
	modes := make([]namedMode, 0, len(servers))
	for name, s := range servers {
		modes = append(modes, namedMode{name, s.mode})
	}

	// A slow server needs 1s of work plus the start cost of the test binary,
	// which is high under -race and on a busy machine (a 2s timeout was too
	// tight there). The hang server still ends at the timeout.
	const timeout = 5 * time.Second
	opts := inspect.Options{Timeout: timeout, Concurrency: 5}

	// Run must not hang. The bound is the timeout, the WaitDelay of the
	// process-group kill and the slack.
	limit := timeout + inspect.KillWaitDelay + processTreeSlack

	got := byName(t, mustRunWithin(t, limit, helperServers(t, modes...), opts, execInspector{}))

	for name, s := range servers {
		o, ok := got[name]
		if !ok {
			t.Errorf("no outcome for server %q", name)
			continue
		}
		checkStatus(t, o, s.want)
		timedOut := errors.Is(o.Err, context.DeadlineExceeded)
		if s.want == inspect.StatusTimeout && !timedOut {
			t.Errorf("server %q: Err = %v, want it to wrap context.DeadlineExceeded", name, o.Err)
		}
		if s.want == inspect.StatusFailed && timedOut {
			t.Errorf("server %q: Err = %v wraps DeadlineExceeded, want a plain failure", name, o.Err)
		}
	}
}

// TestRunNoGoroutineLeak checks that Run leaves no goroutine behind after a
// mix of a hang, a crash and a slow server.
func TestRunNoGoroutineLeak(t *testing.T) {
	baseline := runtime.NumGoroutine()

	opts := inspect.Options{Timeout: time.Second, Concurrency: 3}
	got := runModes(t, opts, execInspector{},
		namedMode{"hang", "hang"},
		namedMode{"crash", "crash"},
		namedMode{"slow", "slow"},
	)
	// Make sure the run did what the test needs: all three paths ran.
	checkStatus(t, got["hang"], inspect.StatusTimeout)
	checkStatus(t, got["crash"], inspect.StatusFailed)
	// "slow" needs about 1s plus start-up time, so under -race it can hit the
	// 1s timeout. Either result is fine for a leak check.
	if s := got["slow"].Status; s != inspect.StatusOK && s != inspect.StatusTimeout {
		t.Errorf("slow: Status = %q, want ok or timeout", s)
	}

	// The exec package and the runtime stop their own goroutines (pipe copiers,
	// the context watcher) a moment after Wait returns. A bounded poll is the
	// only way to see that. This is a leak check, not synchronisation.
	deadline := time.Now().Add(reapLimit)
	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines = %d, want at most the baseline %d\n%s", runtime.NumGoroutine(), baseline, trimStacks(string(buf)))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// trimStacks keeps a goroutine dump short enough for a test log.
func trimStacks(s string) string {
	const limit = 6000
	if len(s) > limit {
		return strings.TrimSpace(s[:limit]) + "\n... (truncated)"
	}
	return s
}
