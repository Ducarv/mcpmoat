package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/llm"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// This file tests the time limit of the whole LLM step of "mcpmoat scan
// --llm" (FR-17, FR-16, issue #188), and the retries of the real client at
// scan level:
//
//   - When the time limit (defaultLLMStepTimeout, or cli.llmStepTimeout in a test)
//     is reached, scan exits with 2, the JSON report has complete false, the
//     rows of the tools that got an answer stay, and stderr has the line
//     "the LLM step stopped after <time>; N tools were not classified".
//   - A signal wins over the deadline, and a provider failure that came
//     first wins over it too.
//   - The real client tries HTTP 429, 502, 503, 504 and 529 again
//     (llmRetryCodes), llm.RetryMaxTries requests in total for one tool. It
//     honours Retry-After up to 30 seconds; a longer Retry-After means no
//     retry. A Retry-After whose wait would end after the step deadline also
//     means no retry: the client fails at once with the provider error, and
//     the step does not sleep until the deadline.
//
// The fake provider (fakeProvider) sends "Retry-After: 0" with every retryable
// status: cmd/mcpmoat cannot change the backoff waits of package llm (about
// 0.5 s and more), and the wait of 0 s keeps the tests fast.
//
// The step deadline is a real timer in runLLMJobs, and a test cannot fire it
// early. So no test here needs work to finish inside a short time: each
// deadline test uses llmTestStepLimit, seconds more than the work that must
// come before the deadline, and its slow requests end only at the deadline.

// llmDeadlineGuard is the longest time that a fake waits for the end of its
// context. The step deadline of a test is much shorter, so the guard ends a
// wait only when the code under test is broken (for example, no deadline).
// The test then fails with an internal error line instead of a hang.
const llmDeadlineGuard = 20 * time.Second

// llmTestStepLimit is the time limit of the LLM step (cli.llmStepTimeout) in
// the tests that need the deadline to end the step. Before the deadline, such
// a test needs only some milliseconds of work: the fast tools get their
// answers, and the first requests start (with the real client, they reach the
// fake provider). The limit gives that work a margin of seconds, also under
// -race with many parallel tests, so the order of the work and the deadline
// does not depend on the speed of the machine. The cost is test time only:
// the slow requests of a test end at the deadline.
const llmTestStepLimit = 3 * time.Second

// llmTestStepLimitText is llmTestStepLimit as durationText gives it in the
// deadline line. It is a copy, so a change of the text fails the tests.
const llmTestStepLimitText = "3 seconds"

// errDeadlineGuard is the error of a fake whose context never ended. It is
// not a provider error, so the step fails with llmInternalText.
var errDeadlineGuard = errors.New("test: the context of the request never ended")

// waitForStop blocks until ctx ends and returns its error, wrapped like the
// real client does (see llm.Classify). After llmDeadlineGuard it returns
// errDeadlineGuard.
func waitForStop(ctx context.Context) error {
	guard := time.NewTimer(llmDeadlineGuard)
	defer guard.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("test: LLM request stopped: %w", ctx.Err())
	case <-guard.C:
		return errDeadlineGuard
	}
}

// llmDeadlineLine returns the exact stderr line of an LLM step that its time
// limit stopped. timeText is the time as durationText gives it. It is a
// copy of the text of printLLMProblems, so a change of it fails the tests.
func llmDeadlineLine(timeText string, n int) string {
	return scanPrefix + "the LLM step stopped after " + timeText + "; " + notClassifiedText(n) + "\n"
}

// llmStepLines returns the lines of stderr that say why the LLM step is
// incomplete: a provider failure, an internal error or the time limit.
func llmStepLines(stderr string) []string {
	var out []string
	for line := range strings.Lines(stderr) {
		if strings.HasPrefix(line, scanPrefix+"the LLM provider failed") ||
			strings.HasPrefix(line, scanPrefix+"the LLM step ") {
			out = append(out, line)
		}
	}
	return out
}

// llmDeadlineRun runs "mcpmoat scan --llm" on one server "srv" with tools and
// the classifier cl, with the process context ctx (see cli.ctx) and the
// time limit timeout for the LLM step (see cli.llmStepTimeout). It
// returns the result and the world, so that the test can read pins.json.
func llmDeadlineRun(ctx context.Context, t *testing.T, tools []inspect.Tool, cl toolClassifier, timeout time.Duration, jsonOut bool) (pinRunResult, *pinEnv) {
	t.Helper()
	servers := map[string][]inspect.Tool{"srv": tools}
	e := llmEnv(t, servers)
	c, stdout, stderr := llmCLI(e, fakeServers(servers), &llmFactory{t: t, cl: cl})
	c.llmStepTimeout = timeout
	c.ctx = ctx
	args := []string{"--llm"}
	if jsonOut {
		args = append(args, "--json")
	}
	return llmRun(t, e, c, stdout, stderr, args...), e
}

// llmDeadlineRows returns the LLM rows of the terminal report or the JSON
// document, and checks that the report printed: the SUMMARY block, or one
// server in the JSON document. For --json it also checks the complete field.
func llmDeadlineRows(t *testing.T, stdout string, jsonOut, wantComplete bool) []llmHit {
	t.Helper()
	if jsonOut {
		doc := decodeScanJSON(t, stdout)
		if doc.Complete != wantComplete {
			t.Errorf("complete = %v, want %v", doc.Complete, wantComplete)
		}
		if len(doc.Servers) != 1 {
			t.Errorf("JSON has %d servers, want 1: the report must still print", len(doc.Servers))
		}
		return llmJSONRows(t, doc)
	}
	if !strings.Contains(stdout, summaryHeading) {
		t.Errorf("stdout has no SUMMARY block: the report must still print\nstdout:\n%s", stdout)
	}
	return llmRowsOf(t, parseFindings(t, stdout))
}

// llmOutputs is the two report formats of a test: terminal and --json.
var llmOutputs = []struct {
	name string
	json bool
}{{"terminal", false}, {"json", true}}

// TestScanLLMStepDeadline runs scan --llm with a fake classifier and a short
// time limit for the LLM step. The "fast" tools answer at once, also when
// the context has ended. The "slow" tools wait until their context ends:
// only the deadline ends it. So the deadline stops the step: exit 2,
// complete false, the exact deadline line with the number of slow tools,
// and the rows of the fast tools stay. The slow tools have the high marker,
// so a slow tool that got a row would show. With more slow tools than
// workers, some slow tools are never sent; they count as not classified
// too.
//
// The fast tools come first in the job order, so they start before the
// slow ones take the workers. They answer in microseconds, and the deadline
// is llmTestStepLimit (seconds) away, so they get their rows and the first
// slow requests start before it.
func TestScanLLMStepDeadline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fast     []inspect.Tool
		slow     int
		wantRows []llmHit
	}{
		{
			name:     "two fast tools and six slow tools",
			fast:     []inspect.Tool{mkTool("fast1", "Read keys. "+llmMarkHigh), mkTool("fast2", "Odd. "+llmMarkMedium), mkTool("fast3", "Add.")},
			slow:     6,
			wantRows: []llmHit{{llm.RuleID, "high", "srv", "fast1"}, {llm.RuleID, "medium", "srv", "fast2"}},
		},
		{
			// The singular form of the line.
			name:     "one slow tool",
			fast:     []inspect.Tool{mkTool("fast1", "Read keys. "+llmMarkHigh)},
			slow:     1,
			wantRows: []llmHit{{llm.RuleID, "high", "srv", "fast1"}},
		},
		{
			name: "only slow tools",
			slow: 2,
		},
	}
	for _, tt := range tests {
		for _, out := range llmOutputs {
			t.Run(tt.name+"/"+out.name, func(t *testing.T) {
				t.Parallel()
				tools := slices.Clone(tt.fast)
				for i := range tt.slow {
					tools = append(tools, mkTool(fmt.Sprintf("slow%d", i+1), "Read keys. "+llmMarkHigh))
				}
				var started, stopped, noDeadline atomic.Int32
				cl := &llmFake{answer: func(ctx context.Context, in llm.Input) (llm.Verdict, error) {
					if strings.HasPrefix(in.ToolName, "fast") {
						return llmAnswerFor(in)
					}
					started.Add(1)
					if _, ok := ctx.Deadline(); !ok {
						noDeadline.Add(1)
					}
					err := waitForStop(ctx)
					if errors.Is(err, context.DeadlineExceeded) {
						stopped.Add(1)
					}
					return llm.Verdict{}, err
				}}

				r, e := llmDeadlineRun(t.Context(), t, tools, cl, llmTestStepLimit, out.json)

				if r.code != exitError {
					t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, exitError, r.stdout, r.stderr)
				}
				want := []string{llmDeadlineLine(llmTestStepLimitText, tt.slow)}
				if got := llmStepLines(r.stderr); !slices.Equal(got, want) {
					t.Errorf("LLM step lines = %q, want %q\nstderr:\n%s", got, want, r.stderr)
				}
				if strings.Contains(r.stderr, interruptedText) {
					t.Errorf("stderr reports a signal for the step deadline:\n%s", r.stderr)
				}
				if got := llmDeadlineRows(t, r.stdout, out.json, false); !slices.Equal(got, tt.wantRows) {
					t.Errorf("LLM findings = %+v, want %+v\nstdout:\n%s", got, tt.wantRows, r.stdout)
				}
				// Each slow request that started saw the deadline of its
				// context: the step has one, and it ended the request.
				if n := noDeadline.Load(); n != 0 {
					t.Errorf("%d requests had a context without a deadline", n)
				}
				if s, d := started.Load(), stopped.Load(); s != d || s < 1 || s > llmWantWorkers {
					t.Errorf("slow requests: %d started, %d stopped by the deadline; want the same number, 1 to %d", s, d, llmWantWorkers)
				}
				// The deadline is not a signal: the first-run pins are
				// saved, as after a provider failure.
				if _, ok := e.readPins().tools("srv"); !ok {
					t.Errorf("pins.json has no entry for srv, want the first-run pins")
				}
			})
		}
	}
}

// TestScanLLMStepDeadlineUsedUp runs scan --llm with a negative time limit:
// it is used up before the first job, so no request starts and every tool
// is not classified. The notice before the requests still prints (it comes
// before the step), and the line names the time as Go prints it.
func TestScanLLMStepDeadlineUsedUp(t *testing.T) {
	t.Parallel()

	for _, out := range llmOutputs {
		t.Run(out.name, func(t *testing.T) {
			t.Parallel()
			fake := &llmFake{}
			tools := []inspect.Tool{mkTool("t1", "Read keys. "+llmMarkHigh), mkTool("t2", "Add."), mkTool("t3", llmMark503)}

			r, _ := llmDeadlineRun(t.Context(), t, tools, fake, -time.Nanosecond, out.json)

			if r.code != exitError {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitError, r.stderr)
			}
			if n := fake.calls.Load(); n != 0 {
				t.Errorf("Classify calls = %d, want 0: no request may start", n)
			}
			want := []string{llmDeadlineLine("-1ns", 3)}
			if got := llmStepLines(r.stderr); !slices.Equal(got, want) {
				t.Errorf("LLM step lines = %q, want %q\nstderr:\n%s", got, want, r.stderr)
			}
			if got := llmDeadlineRows(t, r.stdout, out.json, false); len(got) != 0 {
				t.Errorf("LLM findings = %+v, want none", got)
			}
		})
	}
}

// TestScanLLMStepDeadlineSignal checks that a signal wins over the step
// deadline. The signal is the end of the process context (cli.ctx). scan
// then prints interruptedText, exits with 2, prints no report and saves no
// pins, as without the deadline; stderr has no deadline line.
//
//   - "signal first": the deadline is far away; the first request cancels
//     the process context.
//   - "deadline first": the deadline ends the requests, and then a request
//     cancels the process context before the step returns. The signal still
//     wins: the step checks the process context after its requests.
func TestScanLLMStepDeadlineSignal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		timeout       time.Duration
		deadlineFirst bool
	}{
		{name: "signal first", timeout: time.Hour},
		{name: "deadline first", timeout: llmTestStepLimit, deadlineFirst: true},
	}
	for _, tt := range tests {
		for _, out := range llmOutputs {
			t.Run(tt.name+"/"+out.name, func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var sawDeadline atomic.Int32
				cl := &llmFake{answer: func(callCtx context.Context, _ llm.Input) (llm.Verdict, error) {
					if !tt.deadlineFirst {
						cancel()
					}
					err := waitForStop(callCtx)
					if errors.Is(context.Cause(callCtx), errLLMStepDeadline) {
						sawDeadline.Add(1)
					}
					if tt.deadlineFirst {
						cancel()
					}
					return llm.Verdict{}, err
				}}
				tools := []inspect.Tool{mkTool("t1", "Read keys. "+llmMarkHigh), mkTool("t2", "Add.")}

				r, e := llmDeadlineRun(ctx, t, tools, cl, tt.timeout, out.json)

				if r.code != exitError {
					t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitError, r.stderr)
				}
				assertEmptyStdout(t, r.stdout)
				assertContainsAll(t, "stderr", r.stderr, []string{scanPrefix + interruptedText + "\n"})
				if got := llmStepLines(r.stderr); len(got) != 0 {
					t.Errorf("stderr reports a failure of the LLM step for a signal: %q\nstderr:\n%s", got, r.stderr)
				}
				e.assertNoPinsFile(t, "a signal during the LLM step")
				// The fake checks which cause ended its request, so the test
				// knows that it reached the order that it names.
				if got := sawDeadline.Load() > 0; got != tt.deadlineFirst {
					t.Errorf("a request saw the step deadline = %v, want %v", got, tt.deadlineFirst)
				}
			})
		}
	}
}

// TestScanLLMStepDeadlineProviderFirst checks the order of a provider
// failure and the step deadline: the first cause wins.
//
//   - "failure first": t1 fails with HTTP 503 at once, the other tools wait
//     until the failure cancels them. The deadline is far away. The line is
//     the provider line, and every tool is not classified.
//   - "failure first, deadline passes later": the same, with a short
//     deadline that passes while the stopped requests still run (they wait
//     until after the deadline of their context). The provider line still
//     wins.
//   - "failure after the deadline": every tool waits until its context ends
//     and then returns HTTP 503. Those failures are a result of the
//     deadline, so the deadline line wins.
func TestScanLLMStepDeadlineProviderFirst(t *testing.T) {
	t.Parallel()

	status503 := &llm.StatusError{Code: http.StatusServiceUnavailable}
	tests := []struct {
		name    string
		timeout time.Duration
		// failAtOnce makes t1 fail with HTTP 503 at once.
		failAtOnce bool
		// outlive makes a stopped request wait until the deadline of its
		// context has passed, before it returns.
		outlive bool
		// failAfterStop makes a stopped request return HTTP 503, not the
		// error of its context.
		failAfterStop bool
		wantLine      string
	}{
		{
			name:       "failure first",
			timeout:    time.Hour,
			failAtOnce: true,
			wantLine:   scanPrefix + "the LLM provider failed (HTTP 503); 3 tools were not classified\n",
		},
		{
			name:       "failure first, deadline passes later",
			timeout:    llmTestStepLimit,
			failAtOnce: true,
			outlive:    true,
			wantLine:   scanPrefix + "the LLM provider failed (HTTP 503); 3 tools were not classified\n",
		},
		{
			name:          "failure after the deadline",
			timeout:       llmTestStepLimit,
			failAfterStop: true,
			wantLine:      llmDeadlineLine(llmTestStepLimitText, 3),
		},
	}
	for _, tt := range tests {
		for _, out := range llmOutputs {
			t.Run(tt.name+"/"+out.name, func(t *testing.T) {
				t.Parallel()
				cl := &llmFake{answer: func(ctx context.Context, in llm.Input) (llm.Verdict, error) {
					if tt.failAtOnce && in.ToolName == "t1" {
						return llm.Verdict{}, status503
					}
					err := waitForStop(ctx)
					if tt.outlive {
						// Let the step deadline pass. This is not a
						// synchronisation: the result is the same when the
						// deadline has not passed yet.
						if dl, ok := ctx.Deadline(); ok {
							timer := time.NewTimer(time.Until(dl) + 100*time.Millisecond)
							<-timer.C
						}
					}
					if tt.failAfterStop && !errors.Is(err, errDeadlineGuard) {
						return llm.Verdict{}, status503
					}
					return llm.Verdict{}, err
				}}
				tools := []inspect.Tool{mkTool("t1", "Add."), mkTool("t2", "Read keys. "+llmMarkHigh), mkTool("t3", "Sub.")}

				r, _ := llmDeadlineRun(t.Context(), t, tools, cl, tt.timeout, out.json)

				if r.code != exitError {
					t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitError, r.stderr)
				}
				if got := llmStepLines(r.stderr); !slices.Equal(got, []string{tt.wantLine}) {
					t.Errorf("LLM step lines = %q, want %q\nstderr:\n%s", got, []string{tt.wantLine}, r.stderr)
				}
				if got := llmDeadlineRows(t, r.stdout, out.json, false); len(got) != 0 {
					t.Errorf("LLM findings = %+v, want none", got)
				}
			})
		}
	}
}

// TestRunLLMJobsDeadline checks runLLMJobs directly. A deadline that comes
// after every job got an answer changes nothing: the fake answers each tool
// only after its context ended, with a verdict, so every job is answered and
// there is no failure. A deadline before an answer gives answerDeadline for
// the stopped job and the failure answerDeadline with the time limit. The
// one job starts at once; the deadline is llmTestStepLimit away.
func TestRunLLMJobsDeadline(t *testing.T) {
	t.Parallel()

	const timeout = llmTestStepLimit
	jobs := planLLMJobs(rejectOutcomes(mkTool("t1", "Add."))).jobs

	t.Run("answered after the deadline", func(t *testing.T) {
		t.Parallel()
		cl := &llmFake{answer: func(ctx context.Context, _ llm.Input) (llm.Verdict, error) {
			if err := waitForStop(ctx); errors.Is(err, errDeadlineGuard) {
				return llm.Verdict{}, err
			}
			return llm.Verdict{Risk: llm.RiskHigh, Category: llm.CategoryCredentialAccess}, nil
		}}
		answers, failure := runLLMJobs(t.Context(), jobs, cl, timeout)
		if failure != nil {
			t.Errorf("failure = %+v, want nil: every job got an answer", failure)
		}
		if len(answers) != 1 || answers[0].kind != answerVerdict {
			t.Errorf("answers = %+v, want one answerVerdict", answers)
		}
	})
	t.Run("stopped by the deadline", func(t *testing.T) {
		t.Parallel()
		cl := &llmFake{answer: func(ctx context.Context, _ llm.Input) (llm.Verdict, error) {
			return llm.Verdict{}, waitForStop(ctx)
		}}
		answers, failure := runLLMJobs(t.Context(), jobs, cl, timeout)
		if failure == nil || failure.kind != answerDeadline || failure.timeout != timeout || failure.err != nil {
			t.Errorf("failure = %+v, want answerDeadline with the timeout %v and no error", failure, timeout)
		}
		if len(answers) != 1 || answers[0].kind != answerDeadline {
			t.Errorf("answers = %+v, want one answerDeadline", answers)
		}
	})
}

// TestEndedByDeadline checks endedByDeadline for each way the context of
// the requests can end.
func TestEndedByDeadline(t *testing.T) {
	t.Parallel()

	alive := t.Context()
	signalled, signal := context.WithCancel(t.Context())
	signal()
	// expired is a step context whose time limit is used up.
	expired := func(parent context.Context) context.Context {
		ctx, stop := context.WithTimeoutCause(parent, -time.Nanosecond, errLLMStepDeadline)
		t.Cleanup(stop)
		return ctx
	}
	cancelled := func(parent context.Context) context.Context {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx
	}
	// A deadline with another cause is not the deadline of the step.
	otherDeadline, stop := context.WithTimeout(alive, -time.Nanosecond)
	defer stop()

	tests := []struct {
		name        string
		ctx, runCtx context.Context
		want        bool
	}{
		{"alive", alive, alive, false},
		{"step deadline", alive, expired(alive), true},
		{"step deadline, then a cancel", alive, cancelled(expired(alive)), true},
		{"cancel after a failure", alive, cancelled(alive), false},
		{"cancel, then the step deadline", alive, expired(cancelled(alive)), false},
		{"another deadline", alive, otherDeadline, false},
		{"signal", signalled, signalled, false},
		{"signal and the step deadline", signalled, expired(signalled), false},
		{"step deadline, then a signal", signalled, expired(alive), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := endedByDeadline(tt.ctx, tt.runCtx); got != tt.want {
				t.Errorf("endedByDeadline() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDurationText checks the time text of the deadline line and of the
// help.
func TestDurationText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		d    time.Duration
		want string
	}{
		{10 * time.Minute, "10 minutes"},
		{time.Minute, "1 minute"},
		{2 * time.Hour, "120 minutes"},
		{90 * time.Second, "90 seconds"},
		{30 * time.Second, "30 seconds"},
		{time.Second, "1 second"},
		{61 * time.Second, "61 seconds"},
		{50 * time.Millisecond, "50ms"},
		{1400 * time.Millisecond, "1.4s"},
		{time.Minute + 500*time.Millisecond, "1m0.5s"},
		{-time.Nanosecond, "-1ns"},
		{0, "0s"},
	}
	for _, tt := range tests {
		if got := durationText(tt.d); got != tt.want {
			t.Errorf("durationText(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
	// The production time limit is 10 minutes (issue #188).
	if got := durationText(defaultLLMStepTimeout); got != "10 minutes" {
		t.Errorf("durationText(defaultLLMStepTimeout) = %q, want \"10 minutes\"", got)
	}
}

// TestLLMStepTimeoutOrDefault checks that a zero cli.llmStepTimeout (a real
// scan) gives the constant, and that a test value is used as it is.
func TestLLMStepTimeoutOrDefault(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ field, want time.Duration }{
		{0, 10 * time.Minute},
		{50 * time.Millisecond, 50 * time.Millisecond},
		{-time.Nanosecond, -time.Nanosecond},
	} {
		c := &cli{llmStepTimeout: tt.field}
		if got := c.llmStepTimeoutOrDefault(); got != tt.want {
			t.Errorf("llmStepTimeoutOrDefault() with the field %v = %v, want %v", tt.field, got, tt.want)
		}
	}
}

// TestPrintLLMProblemsDeadline checks the stderr lines of printLLMProblems
// for the step deadline: the time, the singular and the plural, and the cap
// line after it. The rows of the result hold a tool name and a description
// canary: printLLMProblems prints no tool text.
func TestPrintLLMProblemsDeadline(t *testing.T) {
	t.Parallel()

	const canary = "deadline-tool-canary-Wm3Rt8"
	rows := []report.FindingRow{{RuleID: llm.RuleID, Key: canary, Title: canary, Risk: canary}}
	deadline := func(d time.Duration) *llmFailure { return &llmFailure{kind: answerDeadline, timeout: d} }
	tests := []struct {
		name string
		r    llmResult
		want string
	}{
		{"one tool", llmResult{failure: deadline(10 * time.Minute), skipped: 1, rows: rows},
			scanPrefix + "the LLM step stopped after 10 minutes; 1 tool was not classified\n"},
		{"many tools", llmResult{failure: deadline(50 * time.Millisecond), skipped: 7, rows: rows},
			scanPrefix + "the LLM step stopped after 50ms; 7 tools were not classified\n"},
		{"and the cap", llmResult{failure: deadline(time.Minute), skipped: 2, overCap: 3, rows: rows},
			scanPrefix + "the LLM step stopped after 1 minute; 2 tools were not classified\n" +
				scanPrefix + fmt.Sprintf("--llm classifies at most %d tools in one scan; 3 tools were not classified\n", llmWantCap)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr strings.Builder
			c := &cli{stdout: &stdout, stderr: &stderr}
			c.printLLMProblems(tt.r)
			if stderr.String() != tt.want {
				t.Errorf("stderr = %q, want %q", stderr.String(), tt.want)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			if strings.Contains(stderr.String(), canary) {
				t.Errorf("stderr holds tool text: %q", stderr.String())
			}
		})
	}
}

// llmRetryScan runs "mcpmoat scan --llm" on one server "srv" with tools, with
// the real client against api and the time limit timeout for the LLM step
// (0: the default).
func llmRetryScan(t *testing.T, api *fakeProvider, tools []inspect.Tool, timeout time.Duration, jsonOut bool) pinRunResult {
	t.Helper()
	servers := map[string][]inspect.Tool{"srv": tools}
	return llmRealScan(t, api, llmEnv(t, servers), fakeServers(servers), timeout, jsonOut)
}

// TestScanLLMStepDeadlineRealClient runs scan --llm with the real client
// against a provider that never answers: it holds each request until the
// client closes it. The step deadline ends the step: exit 2, complete false,
// the deadline line, no retry (a stopped request is not tried again), and
// the provider sees each request closed. The request timeout of package llm
// (30 s) is not reached, so its text is not on stderr. The requests reach the
// loopback fake in milliseconds; the deadline is llmTestStepLimit away.
func TestScanLLMStepDeadlineRealClient(t *testing.T) {
	t.Parallel()

	const timeout = llmTestStepLimit
	for _, out := range llmOutputs {
		t.Run(out.name, func(t *testing.T) {
			t.Parallel()
			api := newFakeProvider(t, llm.ProviderAnthropic)
			api.hold = true
			tools := []inspect.Tool{mkTool("t1", "Read keys. "+llmMarkHigh), mkTool("t2", "Add.")}

			r := llmRetryScan(t, api, tools, timeout, out.json)

			if r.code != exitError {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitError, r.stderr)
			}
			want := []string{llmDeadlineLine(llmTestStepLimitText, 2)}
			if got := llmStepLines(r.stderr); !slices.Equal(got, want) {
				t.Errorf("LLM step lines = %q, want %q\nstderr:\n%s", got, want, r.stderr)
			}
			if strings.Contains(r.stderr, "timed out") || strings.Contains(r.stderr, interruptedText) {
				t.Errorf("stderr names a request timeout or a signal for the step deadline:\n%s", r.stderr)
			}
			if got := llmDeadlineRows(t, r.stdout, out.json, false); len(got) != 0 {
				t.Errorf("LLM findings = %+v, want none", got)
			}
			if n := api.bad.Load(); n != 0 {
				t.Errorf("the fake provider could not read %d requests", n)
			}
			n := int(api.requests.Load())
			if n < 1 {
				t.Fatalf("the provider got no request before the deadline of %v", timeout)
			}
			for name, got := range api.perTool() {
				if got != 1 {
					t.Errorf("the provider got %d requests for %s, want 1: a stopped request is not tried again", got, name)
				}
			}
			// The client closes each request that the deadline stopped. The
			// fake sees the close a little after the scan returns, so wait
			// for it, with a guard.
			guard := time.NewTimer(llmDeadlineGuard)
			defer guard.Stop()
			for i := range n {
				select {
				case <-api.closed:
				case <-guard.C:
					t.Fatalf("the provider saw %d of %d requests closed, want all", i, n)
				}
			}
		})
	}
}

// TestScanLLMRetry runs scan --llm with the real client against a provider
// that answers some requests with an error, and checks the retries at scan
// level: the number of requests for each tool, the exit code, the complete
// field and the failure line.
//
// The step limit of most cases is retryStep (10 s). It only bounds a broken
// client: a client that waited for a Retry-After above the cap of 30 s, or
// above the time left, would wait until that limit, and the line would be the
// deadline line, not the provider line. A Retry-After of 30 s is not honoured
// in a 10 s step, so that case gets the provider line after one request. The
// case with a 2 s Retry-After in a 4 s step waits for the retry, and the
// retry is held, so the deadline line shows after two requests.
//
// This test does not prove that the client honours "Retry-After: 0" (no
// backoff wait). At scan level that proof needs a step limit just under the
// backoff of 3 tries (at least 1.5 s), and a slow run under -race can then
// reach the limit. The proof is in internal/llm: TestClassifyRetryAfter
// ("zero seconds") gets its retry at once with a backoff of one hour, so it
// has no timing margin to lose.
func TestScanLLMRetry(t *testing.T) {
	t.Parallel()

	const retryStep = 10 * time.Second
	ra0 := func(code int) providerStep { return providerStep{code: code, retryAfter: "0"} }
	t1 := mkTool("t1", "Read keys. "+llmMarkHigh)
	t2 := mkTool("t2", "Add.")
	highT1 := []llmHit{{llm.RuleID, "high", "srv", "t1"}}

	type retryCase struct {
		name     string
		tools    []inspect.Tool
		script   map[string][]providerStep
		timeout  time.Duration
		wantCode int
		// wantTries is the exact number of requests for each tool.
		wantTries map[string]int
		wantRows  []llmHit
		// wantLine is the exact LLM step line; "" means none, and the step
		// is complete.
		wantLine string
	}
	var tests []retryCase
	// One busy answer, then the verdict: the retry succeeds.
	for _, code := range llmRetryCodes {
		tests = append(tests, retryCase{
			name:      fmt.Sprintf("HTTP %d once, then 200", code),
			tools:     []inspect.Tool{t1, t2},
			script:    map[string][]providerStep{"t1": {ra0(code)}},
			timeout:   retryStep,
			wantCode:  exitFindings,
			wantTries: map[string]int{"t1": 2, "t2": 1},
			wantRows:  highT1,
		})
	}
	tests = append(tests,
		retryCase{
			// The third request is the last one, and it succeeds.
			name:      "HTTP 429 and 503, then 200",
			tools:     []inspect.Tool{t1, t2},
			script:    map[string][]providerStep{"t1": {ra0(429), ra0(503)}},
			timeout:   retryStep,
			wantCode:  exitFindings,
			wantTries: map[string]int{"t1": llm.RetryMaxTries, "t2": 1},
			wantRows:  highT1,
		},
		retryCase{
			name:      "HTTP 429 every time",
			tools:     []inspect.Tool{t1},
			script:    map[string][]providerStep{"t1": slices.Repeat([]providerStep{ra0(429)}, 10)},
			timeout:   retryStep,
			wantCode:  exitError,
			wantTries: map[string]int{"t1": llm.RetryMaxTries},
			wantLine:  scanPrefix + "the LLM provider failed (HTTP 429); 1 tool was not classified\n",
		},
		retryCase{
			name:      "HTTP 529 every time",
			tools:     []inspect.Tool{t1},
			script:    map[string][]providerStep{"t1": slices.Repeat([]providerStep{ra0(529)}, 10)},
			timeout:   retryStep,
			wantCode:  exitError,
			wantTries: map[string]int{"t1": llm.RetryMaxTries},
			wantLine:  scanPrefix + "the LLM provider failed (HTTP 529); 1 tool was not classified\n",
		},
		retryCase{
			// A Retry-After above the cap: no retry, the failure at once.
			name:      "HTTP 429 with Retry-After 3600",
			tools:     []inspect.Tool{t1},
			script:    map[string][]providerStep{"t1": slices.Repeat([]providerStep{{code: 429, retryAfter: "3600"}}, 10)},
			timeout:   retryStep,
			wantCode:  exitError,
			wantTries: map[string]int{"t1": 1},
			wantLine:  scanPrefix + "the LLM provider failed (HTTP 429); 1 tool was not classified\n",
		},
		retryCase{
			// Just above the cap of 30 seconds.
			name:      "HTTP 503 with Retry-After 31",
			tools:     []inspect.Tool{t1},
			script:    map[string][]providerStep{"t1": slices.Repeat([]providerStep{{code: 503, retryAfter: "31"}}, 10)},
			timeout:   retryStep,
			wantCode:  exitError,
			wantTries: map[string]int{"t1": 1},
			wantLine:  scanPrefix + "the LLM provider failed (HTTP 503); 1 tool was not classified\n",
		},
		retryCase{
			// At the cap, but the step has 10 s left: the 30 s wait would end
			// after the step deadline, so the client fails at once with the
			// provider error. The step does not sleep until the deadline, so
			// the line is the provider line, after one request.
			name:      "HTTP 429 with Retry-After 30 and 10 s left: no wait",
			tools:     []inspect.Tool{t1},
			script:    map[string][]providerStep{"t1": slices.Repeat([]providerStep{{code: 429, retryAfter: "30"}}, 10)},
			timeout:   retryStep,
			wantCode:  exitError,
			wantTries: map[string]int{"t1": 1},
			wantLine:  scanPrefix + "the LLM provider failed (HTTP 429); 1 tool was not classified\n",
		},
		retryCase{
			// A 2 s wait fits before the step deadline of 4 s, so the client
			// waits and sends the retry. The retry is held, so the deadline
			// stops it: the deadline line, after two requests. The deadline
			// hits during a request that came after a wait. A Retry-After
			// wait that the client takes always ends before the deadline, so
			// the deadline cannot hit during such a wait itself.
			name:  "HTTP 503 with Retry-After 2, then a request that the deadline stops",
			tools: []inspect.Tool{t1, t2},
			script: map[string][]providerStep{"t1": {
				{code: 503, retryAfter: "2"},
				{hold: true},
			}},
			timeout:   4 * time.Second,
			wantCode:  exitError,
			wantTries: map[string]int{"t1": 2, "t2": 1},
			wantLine:  llmDeadlineLine("4 seconds", 1),
		},
		retryCase{
			// A refusal is never tried again, also with Retry-After.
			name:      "HTTP 400 with Retry-After 0",
			tools:     []inspect.Tool{mkTool("t1", "Read a file."), t2},
			script:    map[string][]providerStep{"t1": slices.Repeat([]providerStep{ra0(400)}, 10)},
			wantCode:  exitOK,
			wantTries: map[string]int{"t1": 1, "t2": 1},
			wantRows:  []llmHit{{llm.RuleIDInvalid, "medium", "srv", "t1"}},
		},
	)
	// Other codes are never tried again, also with Retry-After.
	for _, tc := range []struct {
		code   int
		reason string
	}{
		{401, "HTTP 401 (the API key was refused)"},
		{404, "HTTP 404"},
		{500, "HTTP 500"},
	} {
		tests = append(tests, retryCase{
			name:      fmt.Sprintf("HTTP %d with Retry-After 0", tc.code),
			tools:     []inspect.Tool{t1},
			script:    map[string][]providerStep{"t1": slices.Repeat([]providerStep{ra0(tc.code)}, 10)},
			wantCode:  exitError,
			wantTries: map[string]int{"t1": 1},
			wantLine:  scanPrefix + "the LLM provider failed (" + tc.reason + "); 1 tool was not classified\n",
		})
	}

	for _, tt := range tests {
		for _, out := range llmOutputs {
			t.Run(tt.name+"/"+out.name, func(t *testing.T) {
				t.Parallel()
				api := newFakeProvider(t, llm.ProviderAnthropic)
				api.script = tt.script

				r := llmRetryScan(t, api, tt.tools, tt.timeout, out.json)

				if r.code != tt.wantCode {
					t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, tt.wantCode, r.stdout, r.stderr)
				}
				if n := api.bad.Load(); n != 0 {
					t.Errorf("the fake provider could not read %d requests", n)
				}
				if got := api.perTool(); !maps.Equal(got, tt.wantTries) {
					t.Errorf("requests for each tool = %v, want %v", got, tt.wantTries)
				}
				var wantLines []string
				if tt.wantLine != "" {
					wantLines = []string{tt.wantLine}
				}
				if got := llmStepLines(r.stderr); !slices.Equal(got, wantLines) {
					t.Errorf("LLM step lines = %q, want %q\nstderr:\n%s", got, wantLines, r.stderr)
				}
				// The rows hold only rule IDs, severities and names, so the
				// risk text of MOAT-LLM-002 is not compared here; llmRowsOf
				// wants llm.InvalidText, so the refusal case reads the JSON
				// rows or the rule IDs only.
				var got []llmHit
				if out.json || tt.wantRows == nil || tt.wantRows[0].rule == llm.RuleID {
					got = llmDeadlineRows(t, r.stdout, out.json, tt.wantLine == "")
				} else {
					for _, row := range llmRejectRows(t, r.stdout, false) {
						got = append(got, llmHit{row.rule, row.severity, row.server, row.tool})
					}
				}
				if !slices.Equal(got, tt.wantRows) {
					t.Errorf("LLM findings = %+v, want %+v\nstdout:\n%s", got, tt.wantRows, r.stdout)
				}
			})
		}
	}
}

// TestScanLLMOpenAICustomBaseURL checks that a request to an
// OpenAI-compatible server at a base URL that is not the default one has no
// output-token cap: no max_completion_tokens (many such servers refuse it
// with HTTP 400) and no max_tokens. The model is the one of --llm-model.
func TestScanLLMOpenAICustomBaseURL(t *testing.T) {
	t.Parallel()

	api := newFakeProvider(t, llm.ProviderOpenAI)
	tools := []inspect.Tool{mkTool("t1", "Read keys. "+llmMarkHigh), mkTool("t2", "Add.")}

	r := llmRetryScan(t, api, tools, 0, true)

	if r.code != exitFindings {
		t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitFindings, r.stderr)
	}
	if got, want := llmDeadlineRows(t, r.stdout, true, true), []llmHit{{llm.RuleID, "high", "srv", "t1"}}; !slices.Equal(got, want) {
		t.Errorf("LLM findings = %+v, want %+v", got, want)
	}
	reqs := api.snapshot()
	if len(reqs) != 2 {
		t.Fatalf("the provider got %d requests, want 2", len(reqs))
	}
	for i, sent := range reqs {
		var req map[string]json.RawMessage
		if err := json.Unmarshal(sent.body, &req); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		for _, key := range []string{"max_completion_tokens", "max_tokens"} {
			if _, ok := req[key]; ok {
				t.Errorf("request %d has the key %q, want none for a custom base URL\nbody: %s", i, key, sent.body)
			}
		}
		if string(req["model"]) != `"m1"` {
			t.Errorf("request %d model = %s, want \"m1\"", i, req["model"])
		}
	}
}
