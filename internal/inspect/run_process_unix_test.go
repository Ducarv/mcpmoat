//go:build unix

package inspect_test

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// These tests run Run against real child processes (the helper modes of
// helperprocess_unix_test.go). They measure wall time, so none of them calls
// t.Parallel: other tests in the process would slow them down and skew the
// numbers.

// TestRunTenSlowServersConcurrently is the integration test for NFR-03: ten
// servers that each need 1s to start must finish in well under 15s.
func TestRunTenSlowServersConcurrently(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the wall-time test in short mode")
	}

	const count = 10
	servers := make([]discover.Server, 0, count)
	for i := range count {
		servers = append(servers, helperServer(t, fmt.Sprintf("slow-%02d", i), "slow"))
	}
	opts := inspect.Options{Timeout: 10 * time.Second, Concurrency: 4}

	start := time.Now()
	outcomes, err := inspect.Run(t.Context(), servers, opts, execInspector{})
	elapsed := time.Since(start)
	t.Logf("%d slow servers, concurrency %d: elapsed %s", count, opts.Concurrency, elapsed)
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	if len(outcomes) != count {
		t.Fatalf("len(outcomes) = %d, want %d", len(outcomes), count)
	}
	for _, o := range outcomes {
		if o.Status != inspect.StatusOK || o.Err != nil {
			t.Errorf("server %q: Status = %q, Err = %v, want %q and nil error", o.Server.Name, o.Status, o.Err, inspect.StatusOK)
		}
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

// procOrderKey is the part of a server that the sort order is defined on.
type procOrderKey struct {
	client discover.Client
	source string
	name   string
}

func compareProcOrderKeys(a, b procOrderKey) int {
	return cmp.Or(
		cmp.Compare(a.client, b.client),
		cmp.Compare(a.source, b.source),
		cmp.Compare(a.name, b.name),
	)
}

// TestRunOrderStableAcrossRuns checks that the order of the outcomes does not
// depend on the order of the input servers.
func TestRunOrderStableAcrossRuns(t *testing.T) {
	// "crash" exits at once, so this test is fast. Every server ends with
	// StatusFailed, but this test checks only the order.
	mk := func(client discover.Client, source, name string) discover.Server {
		s := helperServer(t, name, "crash")
		s.Client = client
		s.Source = source
		return s
	}
	servers := []discover.Server{
		mk(discover.ClientCursor, "/home/u/.cursor/mcp.json", "zeta"),
		mk(discover.ClientClaudeCode, "/proj/b/.mcp.json", "alpha"),
		mk(discover.ClientCursor, "/home/u/.cursor/mcp.json", "alpha"),
		mk(discover.ClientClaudeCode, "/proj/a/.mcp.json", "mid"),
		mk(discover.ClientClaudeCode, "/proj/a/.mcp.json", "alpha"),
		mk(discover.ClientCursor, "/proj/c/.cursor/mcp.json", "beta"),
		mk(discover.ClientClaudeCode, "/proj/b/.mcp.json", "beta"),
		mk(discover.ClientCursor, "/home/u/.cursor/mcp.json", "mid"),
	}

	// Fixed permutations of the indexes 0..7: no random numbers, so the test
	// is the same on every run.
	permutations := [][]int{
		{0, 1, 2, 3, 4, 5, 6, 7},
		{7, 6, 5, 4, 3, 2, 1, 0},
		{3, 0, 6, 1, 7, 4, 2, 5},
	}

	opts := inspect.Options{Timeout: 10 * time.Second, Concurrency: 4}
	var first []procOrderKey
	for i, perm := range permutations {
		input := make([]discover.Server, 0, len(perm))
		for _, idx := range perm {
			input = append(input, servers[idx])
		}

		outcomes, err := inspect.Run(t.Context(), input, opts, execInspector{})
		if err != nil {
			t.Fatalf("permutation %d: Run() error = %v, want nil", i, err)
		}
		if len(outcomes) != len(servers) {
			t.Fatalf("permutation %d: len(outcomes) = %d, want %d", i, len(outcomes), len(servers))
		}

		keys := make([]procOrderKey, 0, len(outcomes))
		for _, o := range outcomes {
			keys = append(keys, procOrderKey{client: o.Server.Client, source: o.Server.Source, name: o.Server.Name})
		}

		if !slices.IsSortedFunc(keys, compareProcOrderKeys) {
			t.Errorf("permutation %d: outcomes are not sorted by Client, Source, Name: %v", i, keys)
		}
		if first == nil {
			first = keys
			continue
		}
		if !slices.Equal(keys, first) {
			t.Errorf("permutation %d: order = %v, want the same as permutation 0: %v", i, keys, first)
		}
	}
}

// TestRunMixedIsolation checks that a hung server and a crashed server do not
// change the outcome of the healthy servers (FR-06), and that Run returns.
func TestRunMixedIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the wall-time test in short mode")
	}

	want := map[string]inspect.Status{
		"hang":   inspect.StatusTimeout,
		"crash":  inspect.StatusFailed,
		"slow-1": inspect.StatusOK,
		"slow-2": inspect.StatusOK,
		"slow-3": inspect.StatusOK,
	}
	modes := map[string]string{
		"hang":   "hang",
		"crash":  "crash",
		"slow-1": "slow",
		"slow-2": "slow",
		"slow-3": "slow",
	}
	servers := make([]discover.Server, 0, len(modes))
	for name, mode := range modes {
		servers = append(servers, helperServer(t, name, mode))
	}

	// A slow server needs 1s of work plus the start cost of the test binary,
	// which is high under -race and on a busy machine (a 2s timeout was too
	// tight there). The hang server still ends at the timeout.
	const timeout = 5 * time.Second
	opts := inspect.Options{Timeout: timeout, Concurrency: 5}

	// Run must not hang. The bound is the timeout, the 2s WaitDelay of the
	// process-group kill and 5s of slack.
	limit := timeout + 2*time.Second + 5*time.Second

	type result struct {
		outcomes []inspect.Outcome
		err      error
		elapsed  time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		outcomes, err := inspect.Run(t.Context(), servers, opts, execInspector{})
		done <- result{outcomes: outcomes, err: err, elapsed: time.Since(start)}
	}()

	var res result
	select {
	case res = <-done:
	case <-time.After(limit):
		t.Fatalf("Run() did not return within %s", limit)
	}
	t.Logf("mixed run: elapsed %s", res.elapsed)

	if res.err != nil {
		t.Fatalf("Run() error = %v, want nil", res.err)
	}
	if len(res.outcomes) != len(want) {
		t.Fatalf("len(outcomes) = %d, want %d", len(res.outcomes), len(want))
	}

	seen := make(map[string]bool, len(want))
	for _, o := range res.outcomes {
		name := o.Server.Name
		wantStatus, ok := want[name]
		if !ok {
			t.Errorf("unexpected outcome for server %q", name)
			continue
		}
		if seen[name] {
			t.Errorf("duplicate outcome for server %q", name)
		}
		seen[name] = true

		if o.Status != wantStatus {
			t.Errorf("server %q: Status = %q, want %q (Err = %v)", name, o.Status, wantStatus, o.Err)
		}
		if (wantStatus == inspect.StatusOK) != (o.Err == nil) {
			t.Errorf("server %q: Err = %v, want nil only for %q", name, o.Err, inspect.StatusOK)
		}
		if wantStatus == inspect.StatusTimeout && !errors.Is(o.Err, context.DeadlineExceeded) {
			t.Errorf("server %q: Err = %v, want it to wrap context.DeadlineExceeded", name, o.Err)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("no outcome for server %q", name)
		}
	}
}
