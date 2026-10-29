package main

// In-process tests of the time limit of the whole tool rule step of "mcpmoat
// scan" (issue #210, toolRulesStepBudget, see checkTools and serverShare). The
// per-server budget, the caps and the helpers that the tests share are in
// scan_tools_test.go. Most tests here call checkTools with a fake toolChecker
// (blockingChecker), so a check takes a known time without a hostile regex.
// They compare deadlines, not the wall clock, so a busy machine cannot make
// them fail.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// TestScanToolsServerShare checks serverShare: each server gets the time left
// split evenly among the servers left, but never more than the per-server
// budget. Zero servers must not divide by zero.
func TestScanToolsServerShare(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		perServer, left time.Duration
		servers         int
		want            time.Duration
	}{
		{name: "the share is less than the per-server budget", perServer: 5 * time.Second, left: 30 * time.Second, servers: 20, want: 1500 * time.Millisecond},
		{name: "the share is more than the per-server budget", perServer: 5 * time.Second, left: 30 * time.Second, servers: 2, want: 5 * time.Second},
		{name: "the share is the per-server budget", perServer: 5 * time.Second, left: 10 * time.Second, servers: 2, want: 5 * time.Second},
		{name: "one server gets all the time left", perServer: time.Hour, left: 100 * time.Millisecond, servers: 1, want: 100 * time.Millisecond},
		{name: "one server gets at most the per-server budget", perServer: 5 * time.Second, left: 30 * time.Second, servers: 1, want: 5 * time.Second},
		{name: "the division rounds down to the nanosecond", perServer: time.Hour, left: 10 * time.Nanosecond, servers: 3, want: 3 * time.Nanosecond},
		{name: "no time left", perServer: 5 * time.Second, left: 0, servers: 3, want: 0},
		{name: "the time left is negative", perServer: 5 * time.Second, left: -3 * time.Second, servers: 3, want: -time.Second},
		{name: "a used-up per-server budget", perServer: usedUpBudget, left: 30 * time.Second, servers: 3, want: usedUpBudget},
		{name: "zero servers count as one", perServer: 5 * time.Second, left: 2 * time.Second, servers: 0, want: 2 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := serverShare(tt.perServer, tt.left, tt.servers); got != tt.want {
				t.Errorf("serverShare(%s, %s, %d) = %s, want %s", tt.perServer, tt.left, tt.servers, got, tt.want)
			}
		})
	}
}

// lateWarning is the stderr line for the servers that the tool rule step did
// not check, because its time limit left too little time. limit is the limit as the line
// prints it. The words are written out here, not taken from lateServersText, so
// a change of the words fails the test.
func lateWarning(limit string, late int) string {
	if late == 1 {
		return scanWarnPrefix + "the " + limit + " time limit of the rule analysis left too little time; 1 server was not checked"
	}
	return fmt.Sprintf("%sthe %s time limit of the rule analysis left too little time; %d servers were not checked", scanWarnPrefix, limit, late)
}

// TestScanToolsLateServersText checks the text of the warning for the servers
// that were not checked, with the limit of a real scan (30 s) and with the
// singular and plural forms.
func TestScanToolsLateServersText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		limit time.Duration
		late  int
		want  string
	}{
		{limit: toolRulesStepBudget, late: 1, want: lateWarning("30s", 1)},
		{limit: toolRulesStepBudget, late: 2, want: lateWarning("30s", 2)},
		{limit: 100 * time.Millisecond, late: 20, want: lateWarning("100ms", 20)},
	}
	for _, tt := range tests {
		if got := scanWarnPrefix + lateServersText(tt.limit, tt.late); got != tt.want {
			t.Errorf("lateServersText(%s, %d) = %q, want %q", tt.limit, tt.late, got, tt.want)
		}
	}
}

// checkCall records one call of blockingChecker.CheckTool.
type checkCall struct {
	tool string
	// now is the time of the call. deadline is the deadline of the context of
	// the call. hasDeadline is false when the context has none.
	now         time.Time
	deadline    time.Time
	hasDeadline bool
}

// blockTimeout is the time after which a blockingChecker call fails the test.
// It only stops a broken test from hanging: no test waits for it.
const blockTimeout = 30 * time.Second

// blockingChecker is a fake toolChecker. Its CheckTool finds nothing and
// blocks until its context ends, like the analyzer on a hostile text. It
// records each call. onCall, when not nil, runs at the start of each call, for
// example to simulate a signal. When the context does not end within
// blockTimeout, the call fails the test and returns an error that is not a
// context error.
type blockingChecker struct {
	t      *testing.T
	onCall func()
	mu     sync.Mutex
	calls  []checkCall
}

// CheckTool records the call, runs onCall and blocks until ctx ends.
func (b *blockingChecker) CheckTool(ctx context.Context, tl inspect.Tool) ([]rules.TextFinding, error) {
	b.record(ctx, tl)
	if b.onCall != nil {
		b.onCall()
	}
	timer := time.NewTimer(blockTimeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("fake check of a tool: %w", ctx.Err())
	case <-timer.C:
		b.t.Errorf("CheckTool: the context did not end within %s", blockTimeout)
		return nil, errors.New("fake check: the context did not end")
	}
}

// record adds one call to the calls, with the time and the deadline of ctx. It
// returns the deadline and whether ctx has one.
func (b *blockingChecker) record(ctx context.Context, tl inspect.Tool) (deadline time.Time, ok bool) {
	now := time.Now()
	deadline, ok = ctx.Deadline()
	b.mu.Lock()
	b.calls = append(b.calls, checkCall{tool: tl.Name, now: now, deadline: deadline, hasDeadline: ok})
	b.mu.Unlock()
	return deadline, ok
}

// MaxSeverity returns high, the highest severity of the built-in rules.
func (b *blockingChecker) MaxSeverity() rules.Severity { return rules.SeverityHigh }

// recorded returns a copy of the calls so far.
func (b *blockingChecker) recorded() []checkCall {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.calls)
}

// stepOutcomes returns the outcomes of n inspected servers, srv-01 to srv-NN,
// each with the tools tool_a and tool_b, and their names in the order of the
// servers. The outcomes are in reverse order on purpose: inspect.Run sorts
// them, so checkTools must use Index, not the position.
func stepOutcomes(n int) ([]inspect.Outcome, []string) {
	outcomes := make([]inspect.Outcome, n)
	names := make([]string, n)
	for i := range n {
		names[i] = fmt.Sprintf("srv-%02d", i+1)
		outcomes[n-1-i] = inspect.Outcome{
			Index:  i,
			Server: discover.Server{Name: names[i], Command: "npx"},
			Status: inspect.StatusOK,
			Result: inspect.Result{ServerName: names[i], Tools: []inspect.Tool{mkTool("tool_a", "A."), mkTool("tool_b", "B.")}},
		}
	}
	return outcomes, names
}

// stepSetup returns the scan setup of the tool rule step with the per-server
// budget perServer and the step limit step. It has no rule set: the fakes find
// nothing, so no row needs the texts of a rule.
func stepSetup(perServer, step time.Duration) scanSetup {
	return scanSetup{toolBudget: perServer, toolStepBudget: step, maxToolRows: maxToolRowsPerServer}
}

// assertStepBudgetRows fails the test unless rows are exactly one high
// MOAT-T1-023 row for each server of names, in that order, with both tools not
// fully checked.
func assertStepBudgetRows(t *testing.T, rows []report.FindingRow, names []string) {
	t.Helper()
	if len(rows) != len(names) {
		t.Fatalf("rows = %d, want %d (one budget row for each server)\nrows: %+v", len(rows), len(names), rows)
	}
	for i, r := range rows {
		if r.RuleID != rules.RuleAnalysisBudget || r.Name != names[i] || r.Severity != "high" ||
			r.Key != "" || r.Related != budgetReason(2, 2) {
			t.Errorf("row %d = %s %s %s key %q related %q, want %s high for %s with %q",
				i, r.RuleID, r.Name, r.Severity, r.Key, r.Related, rules.RuleAnalysisBudget, names[i], budgetReason(2, 2))
		}
	}
}

// TestScanToolsStepBudgetFairShare checks the fair share of the step limit:
// 20 servers whose check blocks until its context ends, a per-server budget of
// one hour and a step limit of 100 ms. Each server gets a share of the time
// left, so the first server is cut after at most 5 ms, not after the whole
// step. Every server ends with a MOAT-T1-023 row.
//
// The test does not time the step. It compares deadlines: the deadline of each
// call is not after the step deadline. The step deadline is at most the time
// of the first call plus 100 ms, because checkTools sets it before that call.
//
// Most servers are cut while they run and get their own warning, with the
// budget that they got. That budget is at least minServerShare (1 ms), so the
// warning never shows "0s". On a busy machine the overshoot of each cut eats
// into the time of the servers after it. Then the step limit can pass before
// the last servers start, or their share can drop under 1 ms. Those servers
// are not checked, and one summary line counts them. They are always the last
// servers. So the test accepts any split between the two, but each server must
// be in exactly one of them, in order.
func TestScanToolsStepBudgetFairShare(t *testing.T) {
	t.Parallel()

	const (
		servers = 20
		step    = 100 * time.Millisecond
	)
	c, _, stderr := newTestCLI(fakeGetenv(nil), testBuild)
	checker := &blockingChecker{t: t}
	outcomes, names := stepOutcomes(servers)
	counts := make([]int, servers)

	res, err := c.checkTools(t.Context(), checker, stepSetup(time.Hour, step), outcomes, &scanIgnores{}, counts)

	if err != nil {
		t.Fatalf("checkTools error = %v, want nil\nstderr:\n%s", err, stderr)
	}
	assertStepBudgetRows(t, res.rows, names)
	if res.ignored != nil {
		t.Errorf("ignored = %v, want nil", res.ignored)
	}
	for i, n := range counts {
		if n != 1 {
			t.Errorf("counts[%d] = %d, want 1 (the budget row)", i, n)
		}
	}

	calls := checker.recorded()
	if len(calls) == 0 {
		t.Fatalf("CheckTool was not called, want a call for at least the first server\nstderr:\n%s", stderr)
	}
	late := servers - len(calls)
	t.Logf("%d servers were cut while they ran, %d were late", len(calls), late)
	stepUpper := calls[0].now.Add(step)
	for i, call := range calls {
		// The cut comes in the first tool of each server.
		if call.tool != "tool_a" || !call.hasDeadline {
			t.Errorf("call %d: tool %q, has deadline %v, want tool_a with a deadline", i, call.tool, call.hasDeadline)
			continue
		}
		if call.deadline.After(stepUpper) {
			t.Errorf("call %d: deadline is %s after the step deadline, want no later", i, call.deadline.Sub(stepUpper))
		}
		if call.deadline.After(call.now.Add(time.Hour)) {
			t.Errorf("call %d: deadline is more than the per-server budget after the call", i)
		}
	}
	// Without the fair share, the first server could use the whole step.
	if got, limit := calls[0].deadline.Sub(calls[0].now), step/servers; got > limit {
		t.Errorf("the first server had %s left at its call, want at most %s (a fair share)", got, limit)
	}

	lines := strings.Split(strings.TrimSuffix(stderr.String(), "\n"), "\n")
	wantLines := len(calls)
	if late > 0 {
		wantLines++
	}
	if len(lines) != wantLines {
		t.Fatalf("stderr has %d lines, want %d (one warning for each cut server and one for the late ones)\nstderr:\n%s", len(lines), wantLines, stderr)
	}
	const tail = "; 2 of 2 tools not fully checked"
	for i := range calls {
		head := scanWarnPrefix + "server " + names[i] + ": the rule analysis stopped after "
		line := lines[i]
		if !strings.HasPrefix(line, head) || !strings.HasSuffix(line, tail) {
			t.Errorf("stderr line %d = %q, want %q<budget>%q", i+1, line, head, tail)
			continue
		}
		got, err := time.ParseDuration(strings.TrimSuffix(strings.TrimPrefix(line, head), tail))
		// A cut server had a share of at least 1 ms, and the warning rounds
		// the budget to milliseconds, so it shows at least 1ms.
		if err != nil || got < time.Millisecond || got > step {
			t.Errorf("stderr line %d: budget %q (error %v), want a duration from 1ms to %s", i+1, line, err, step)
			continue
		}
		// The first server starts with almost the whole step left, so its
		// share is at most step/servers.
		if i == 0 && got > step/servers {
			t.Errorf("stderr line 1: budget %s, want at most %s", got, step/servers)
		}
	}
	if late > 0 {
		if got, want := lines[len(lines)-1], lateWarning("100ms", late); got != want {
			t.Errorf("last stderr line = %q, want %q", got, want)
		}
	}
}

// TestScanToolsStepBudgetUsedUp checks a step limit that is used up at once
// (usedUpBudget): checkTools calls CheckTool for no server, gives each
// inspected server with tools a MOAT-T1-023 row for all its tools, and prints
// exactly one summary line with their count, and no warning for each server.
// A server that was not inspected, or that lists no tools, is skipped: it gets
// no row and does not count.
//
// The line shows the limit as checkTools got it, so here "-1ns". A real scan
// shows "30s" (see TestScanToolsLateServersText).
func TestScanToolsStepBudgetUsedUp(t *testing.T) {
	t.Parallel()

	for _, servers := range []int{1, 3} {
		t.Run(fmt.Sprintf("%d servers", servers), func(t *testing.T) {
			t.Parallel()

			c, _, stderr := newTestCLI(fakeGetenv(nil), testBuild)
			checker := &blockingChecker{t: t}
			outcomes, names := stepOutcomes(servers)
			// Two servers that the step skips, after the others.
			outcomes = append(outcomes,
				inspect.Outcome{Index: servers, Server: discover.Server{Name: "failed"}, Status: inspect.StatusFailed, Err: errors.New("boom")},
				inspect.Outcome{Index: servers + 1, Server: discover.Server{Name: "empty"}, Status: inspect.StatusOK},
			)
			counts := make([]int, servers+2)

			res, err := c.checkTools(t.Context(), checker, stepSetup(time.Hour, usedUpBudget), outcomes, &scanIgnores{}, counts)

			if err != nil {
				t.Fatalf("checkTools error = %v, want nil\nstderr:\n%s", err, stderr)
			}
			if calls := checker.recorded(); len(calls) != 0 {
				t.Errorf("CheckTool calls = %d, want 0 after the step limit", len(calls))
			}
			assertStepBudgetRows(t, res.rows, names)
			for i, n := range counts {
				want := 1
				if i >= servers {
					want = 0
				}
				if n != want {
					t.Errorf("counts[%d] = %d, want %d", i, n, want)
				}
			}
			assertStderrLines(t, stderr.String(), []lineWant{exactLine(lateWarning("-1ns", servers))})
		})
	}
}

// TestScanToolsStepBudgetShareTooSmall checks a step limit that has time left
// but gives each server a share under minServerShare (1 ms): checkTools calls
// CheckTool for no server, gives each server a MOAT-T1-023 row for all its
// tools, and prints exactly one summary line with their count, and no warning
// for each server. The line shows the step limit.
//
// The time left is never more than the step limit, so the share of the first
// server is under 1 ms on any machine. The case with 20 servers and 10 ms also
// checks that a late server stays late for the rest of the step: the 12th
// server has only 9 servers left with it, so its own share would be about
// 1.1 ms. Without that rule, CheckTool would get calls for the last servers.
func TestScanToolsStepBudgetShareTooSmall(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		servers int
		step    time.Duration
		limit   string // the step limit as the summary line prints it
	}{
		{name: "20 servers and 10 ms", servers: 20, step: 10 * time.Millisecond, limit: "10ms"},
		{name: "2 servers and 1 ms", servers: 2, step: time.Millisecond, limit: "1ms"},
		{name: "1 server and 999 µs", servers: 1, step: 999 * time.Microsecond, limit: "999µs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, _, stderr := newTestCLI(fakeGetenv(nil), testBuild)
			checker := &blockingChecker{t: t}
			outcomes, names := stepOutcomes(tt.servers)
			counts := make([]int, tt.servers)

			res, err := c.checkTools(t.Context(), checker, stepSetup(time.Hour, tt.step), outcomes, &scanIgnores{}, counts)

			if err != nil {
				t.Fatalf("checkTools error = %v, want nil\nstderr:\n%s", err, stderr)
			}
			if calls := checker.recorded(); len(calls) != 0 {
				t.Errorf("CheckTool calls = %d, want 0 (each share is under 1 ms)", len(calls))
			}
			assertStepBudgetRows(t, res.rows, names)
			if res.ignored != nil {
				t.Errorf("ignored = %v, want nil", res.ignored)
			}
			for i, n := range counts {
				if n != 1 {
					t.Errorf("counts[%d] = %d, want 1 (the budget row)", i, n)
				}
			}
			assertStderrLines(t, stderr.String(), []lineWant{exactLine(lateWarning(tt.limit, tt.servers))})
		})
	}
}

// overrunChecker is a fake toolChecker. Its first CheckTool call finds
// nothing and returns only overrun after the deadline of its context, like an
// analyzer that cannot stop at once (issue #146). So the first server uses
// time of the servers after it. The later calls act like the calls of
// blockingChecker.
type overrunChecker struct {
	blockingChecker
	overrun time.Duration
}

// CheckTool records the call. On the first call it returns overrun after the
// deadline of ctx. On a later call it blocks until ctx ends.
func (o *overrunChecker) CheckTool(ctx context.Context, tl inspect.Tool) ([]rules.TextFinding, error) {
	if len(o.recorded()) > 0 {
		return o.blockingChecker.CheckTool(ctx, tl)
	}
	deadline, ok := o.record(ctx, tl)
	if !ok {
		o.t.Errorf("CheckTool: the context has no deadline")
		return nil, errors.New("fake check: the context has no deadline")
	}
	// The timer stands for the work of the analyzer after the deadline. It
	// is not a wait for another goroutine: ctx.Done below is that wait.
	timer := time.NewTimer(time.Until(deadline.Add(o.overrun)))
	defer timer.Stop()
	<-timer.C
	<-ctx.Done()
	return nil, fmt.Errorf("fake check of a tool: %w", ctx.Err())
}

// TestScanToolsStepBudgetLateSticky checks that once a server is late, every
// server after it is late too, also when the share of a later server alone
// would be 1 ms or more. 10 servers, a step limit of 100 ms, one hour for each
// server. The first server gets at most 10 ms and its check runs on after its
// deadline (overrunChecker), so that at most 4 ms of the step are left after
// it:
//
//   - The deadline of the first server is at most 90 ms before the step
//     deadline (9 shares of at most 10 ms), so 86 ms after it leaves at most
//     4 ms. The second server has 9 servers left with it, so its share is at
//     most 0.45 ms: it is late.
//   - On a normal machine about 4 ms are left, so the 8th server, with 3
//     servers left, would have a share of about 1.3 ms. Without the rule that
//     a late server stays late, CheckTool would get a call for it.
//
// The test asserts on the rows, the calls and the stderr lines, not on time:
// one call (the first server, cut on tool_a, with its own warning), then one
// summary line for the 9 late servers.
func TestScanToolsStepBudgetLateSticky(t *testing.T) {
	t.Parallel()

	const (
		servers = 10
		step    = 100 * time.Millisecond
		// overrun leaves at most 4 ms after the first server: its deadline is
		// at most step*(servers-1)/servers before the step deadline.
		overrun = step*(servers-1)/servers - 4*time.Millisecond
	)
	c, _, stderr := newTestCLI(fakeGetenv(nil), testBuild)
	checker := &overrunChecker{blockingChecker: blockingChecker{t: t}, overrun: overrun}
	outcomes, names := stepOutcomes(servers)
	counts := make([]int, servers)

	res, err := c.checkTools(t.Context(), checker, stepSetup(time.Hour, step), outcomes, &scanIgnores{}, counts)

	if err != nil {
		t.Fatalf("checkTools error = %v, want nil\nstderr:\n%s", err, stderr)
	}
	calls := checker.recorded()
	if len(calls) != 1 || calls[0].tool != "tool_a" {
		tools := make([]string, len(calls))
		for i, call := range calls {
			tools[i] = call.tool
		}
		t.Fatalf("CheckTool calls = %d %v, want one call for tool_a of the first server\nstderr:\n%s", len(calls), tools, stderr)
	}
	// The first server was cut on tool_a, so its row also counts both tools.
	assertStepBudgetRows(t, res.rows, names)
	if res.ignored != nil {
		t.Errorf("ignored = %v, want nil", res.ignored)
	}
	for i, n := range counts {
		if n != 1 {
			t.Errorf("counts[%d] = %d, want 1 (the budget row)", i, n)
		}
	}
	assertStderrLines(t, stderr.String(), []lineWant{
		prefixLine(scanWarnPrefix + "server " + names[0] + ": the rule analysis stopped after "),
		exactLine(lateWarning("100ms", servers-1)),
	})
	const tail = "; 2 of 2 tools not fully checked"
	if first := nonEmptyLines(stderr.String())[0]; !strings.HasSuffix(first, tail) {
		t.Errorf("stderr line 1 = %q, want it to end with %q", first, tail)
	}
}

// TestScanToolsStepBudgetScan checks a full scan whose step limit is used up
// (issue #210): each server gets the normal MOAT-T1-023 row for all its tools,
// stderr has one summary line and no warning for each server, and the --json
// document stays complete. The row is high with the built-in rules, so the exit
// code follows --fail-on: 1 by default, 0 with --fail-on critical. With a
// critical rule from --rules, the row is critical and --fail-on critical gives
// 1 (see failClosedSeverity).
func TestScanToolsStepBudgetScan(t *testing.T) {
	t.Parallel()

	insp := func() *inspecttest.Fake {
		return fakeServers(map[string][]inspect.Tool{
			"srv-a": {poisonedTool("read_file"), schemaTool("write_file"), mkTool("add_numbers", "Add.")},
			"srv-b": {poisonedTool("fetch_url"), mkTool("echo_text", "Echo.")},
		})
	}
	tests := []struct {
		name     string
		critical bool // add the critical rule with --rules
		failOn   string
		severity string
		code     int
	}{
		{name: "default --fail-on", severity: "high", code: exitFindings},
		{name: "--fail-on critical", failOn: "critical", severity: "high", code: exitOK},
		{name: "critical rule, --fail-on critical", critical: true, failOn: "critical", severity: "critical", code: exitFindings},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var flags []string
			if tt.critical {
				flags = append(flags, "--rules", criticalRulesDir(t))
			}
			if tt.failOn != "" {
				flags = append(flags, "--fail-on", tt.failOn)
			}
			e := newPinEnv(t, twoServers())
			var wantStderr []string
			if tt.failOn == "critical" {
				wantStderr = append(wantStderr, failOnCriticalNotice)
			}
			wantStderr = append(wantStderr, lateWarning("-1ns", 2), newPinsLine(e), pinnedLine("srv-a", 3), pinnedLine("srv-b", 2))

			opts := scanOpts{budget: time.Hour, step: usedUpBudget}
			got := scanWith(e, insp(), opts, flags...)

			assertScanRun(t, got, scanWant{code: tt.code, stdout: []string{"MOAT-T1-023  " + budgetTitle + "\n"}, stderr: wantStderr})
			assertToolFindings(t, got.stdout,
				toolFinding{rules.RuleAnalysisBudget, tt.severity, "srv-a", "", quotedCell(budgetReason(3, 3))},
				toolFinding{rules.RuleAnalysisBudget, tt.severity, "srv-b", "", quotedCell(budgetReason(2, 2))},
			)
			assertStderrLines(t, got.stderr, exactLines(wantStderr))
			assertContainsNone(t, "stderr", got.stderr, []string{"rule analysis stopped"})
			assertNoToolText(t, got.stderr, "read_file", "write_file", "add_numbers", "fetch_url", "echo_text")

			// The servers are pinned now. jsonFindings checks that complete
			// is true.
			jsonRun := scanWith(e, insp(), opts, append(slices.Clone(flags), "--json")...)

			wantJSONStderr := slices.DeleteFunc(slices.Clone(wantStderr), func(l string) bool {
				return strings.HasPrefix(l, scanPrefix+"pinned ") || l == newPinsLine(e)
			})
			assertScanRun(t, jsonRun, scanWant{code: tt.code, stderr: wantJSONStderr})
			assertStderrLines(t, jsonRun.stderr, exactLines(wantJSONStderr))
			want := []report.JSONFinding{budgetJSONRow("srv-a", tt.severity, 3, 3), atServer(budgetJSONRow("srv-b", tt.severity, 2, 2), 1)}
			if rows := jsonFindings(t, jsonRun.stdout); !slices.Equal(rows, want) {
				t.Errorf("JSON findings = %+v\nwant            %+v", rows, want)
			}
		})
	}
}

// TestScanToolsStepInterrupted checks that a signal (the parent context ends)
// during the tool rule step returns errInterrupted with an empty result and the
// interruptedText line, also when the budget of the server or the step limit
// has passed too. The end of the step limit alone is not a signal (see
// TestScanToolsStepBudgetUsedUp), but a signal is never taken for a step
// timeout: there is no MOAT-T1-023 row and no budget warning.
func TestScanToolsStepInterrupted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		perServer, step time.Duration
		// cancelBefore cancels the parent context before checkTools runs.
		// Otherwise the first CheckTool call cancels it.
		cancelBefore bool
		calls        int
	}{
		{name: "signal while a server runs", perServer: time.Hour, step: time.Hour, calls: 1},
		{name: "signal when the server budget is used up", perServer: usedUpBudget, step: time.Hour, calls: 1},
		{name: "signal after the step limit", perServer: time.Hour, step: usedUpBudget, cancelBefore: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			c, _, stderr := newTestCLI(fakeGetenv(nil), testBuild)
			checker := &blockingChecker{t: t}
			if tt.cancelBefore {
				cancel()
			} else {
				checker.onCall = cancel
			}
			outcomes, _ := stepOutcomes(3)

			res, err := c.checkTools(ctx, checker, stepSetup(tt.perServer, tt.step), outcomes, &scanIgnores{}, make([]int, 3))

			if !errors.Is(err, errInterrupted) {
				t.Errorf("checkTools error = %v, want errInterrupted", err)
			}
			if res.rows != nil || res.ignored != nil {
				t.Errorf("result = %+v, want empty", res)
			}
			if calls := checker.recorded(); len(calls) != tt.calls {
				t.Errorf("CheckTool calls = %d, want %d", len(calls), tt.calls)
			}
			assertStderrLines(t, stderr.String(), []lineWant{exactLine(scanPrefix + interruptedText)})
		})
	}
}

// TestScanToolsNilAnalyzer checks that toolRulesStep with a nil analyzer
// checks nothing: no row, no count, no line on stderr and no panic. A nil
// *rules.Analyzer in a toolChecker interface is not == nil, so checkTools could
// not see it (a typed nil). toolRulesStep must check the pointer first. With a
// used-up step limit, the step also gives no late-server row: there is nothing
// to check.
func TestScanToolsNilAnalyzer(t *testing.T) {
	t.Parallel()

	// Only the used-up step limit finds a missing nil guard: a nil
	// *rules.Analyzer is safe on both methods (CheckTool and MaxSeverity), so
	// with one hour the step would find nothing without the guard too. That
	// subtest shows the normal path. With a used-up limit and no guard, the
	// step would add a late-server row for each server.
	for _, step := range []time.Duration{time.Hour, usedUpBudget} {
		t.Run(fmt.Sprintf("step limit %s", step), func(t *testing.T) {
			t.Parallel()

			c, _, stderr := newTestCLI(fakeGetenv(nil), testBuild)
			outcomes, _ := stepOutcomes(2)
			for i := range outcomes {
				outcomes[i].Result.Tools = []inspect.Tool{poisonedTool("read_file")}
			}
			counts := make([]int, 2)
			setup := stepSetup(time.Hour, step)
			setup.analyzer = nil

			res, err := c.toolRulesStep(t.Context(), setup, outcomes, &scanIgnores{}, counts)

			if err != nil {
				t.Errorf("toolRulesStep error = %v, want nil", err)
			}
			if len(res.rows) != 0 || res.ignored != nil {
				t.Errorf("result = %+v, want empty", res)
			}
			if !slices.Equal(counts, []int{0, 0}) {
				t.Errorf("counts = %v, want [0 0]", counts)
			}
			assertCleanStderr(t, stderr.String())
		})
	}
}
