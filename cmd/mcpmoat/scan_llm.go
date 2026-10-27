package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/llm"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// This file holds the optional LLM step of scan (--llm, FR-17). Without
// --llm, runScan reads no LLM flag value, reads no API key and never calls
// cli.newClassifier, so no request is made (NFR-01).

// Limits of the LLM step.
const (
	// llmWorkers is the number of requests that run at the same time.
	llmWorkers = llm.MaxConcurrentRequests
	// llmStepTimeout is the time limit of the whole LLM step of one scan. It
	// is fixed: no flag changes it. A test sets cli.llmStepTimeout instead.
	//
	// Each request has a limit of 30 seconds in package llm, but without
	// this limit the step has none. The client of package llm tries a
	// request again after HTTP 429, 502, 503, 504 and 529: 3 requests in
	// total for one tool. Before a retry it waits for a backoff of 1 to 8
	// seconds, or for the Retry-After time of the answer, up to 30 seconds.
	// So in the worst case one tool takes 3 requests of 30 seconds and 2
	// waits of 30 seconds: about 150 seconds. maxLLMTools (500) tools with
	// llmWorkers (4) tools at the same time take 125 rounds of 150 seconds:
	// about 5 hours. This limit stops the step after 10 minutes.
	//
	// When the limit is reached, the step stops as after a provider failure
	// (see runLLMJobs): scan exits with 2, the JSON report has complete set
	// to false, and the rows of the tools that got an answer stay.
	llmStepTimeout = 10 * time.Minute
)

// errLLMStepDeadline is the cause of the context of the LLM step when
// llmStepTimeout (or cli.llmStepTimeout) is reached (see runLLMJobs). It has
// fixed text, and scan never prints it.
var errLLMStepDeadline = errors.New("the LLM step reached its time limit")

// llmStepTimeoutOrDefault returns c.llmStepTimeout, or llmStepTimeout when
// the field is zero (a real scan).
func (c *cli) llmStepTimeoutOrDefault() time.Duration {
	if c.llmStepTimeout == 0 {
		return llmStepTimeout
	}
	return c.llmStepTimeout
}

// stepTimeoutText returns the time limit d of the LLM step as text for the
// stderr line and the help. The help also gives llm.RetryAfterCap with it.
// The text is "10 minutes" for whole minutes, "30 seconds" for
// whole seconds, else the Go form of d, such as "50ms" (a value that a test
// sets). It holds only a number and a fixed unit.
func stepTimeoutText(d time.Duration) string {
	switch {
	case d >= time.Minute && d%time.Minute == 0:
		n := d / time.Minute
		if n == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", n)
	case d >= time.Second && d%time.Second == 0:
		n := d / time.Second
		if n == 1 {
			return "1 second"
		}
		return fmt.Sprintf("%d seconds", n)
	default:
		return d.String()
	}
}

// toolClassifier rates one tool. *llm.Client implements it. Tests use a fake,
// so they send no request.
type toolClassifier interface {
	Classify(ctx context.Context, in llm.Input) (llm.Verdict, error)
}

// answerKind sorts the result of one Classify call. sortAnswer is the only
// place that sorts the errors of Classify. runLLMJobs only turns an
// answerStopped into an answerDeadline when the step deadline stopped the
// request.
type answerKind int

const (
	// answerNotRun means that the job did not run. It is the zero value.
	answerNotRun answerKind = iota
	// answerVerdict means that Classify returned a verdict.
	answerVerdict
	// answerUnusable means that the provider answered, but the model output
	// is not a valid verdict (llm.ErrInvalidOutput). The tool gets an
	// llm.RuleIDInvalid row.
	answerUnusable
	// answerRejected means that the provider refused this one tool
	// (llm.ErrRejected: HTTP 400, 413 or 422). It does not stop the step:
	// the tool gets an llm.RuleIDInvalid row with llm.RejectedText, and the
	// other requests go on. The refusals can still fail the step: see
	// rejectedFailure for the rule. As an llmFailure kind it is that failure.
	answerRejected
	// answerStopped means that the context of the request ended: a signal,
	// or the cancel after the first failure of the step. A request that the
	// step deadline stopped is answerDeadline instead.
	answerStopped
	// answerProviderFailed means that the request to the provider failed
	// (llm.ErrProvider). It stops the LLM step.
	answerProviderFailed
	// answerInternalFailed means any other error: a local error, or an error
	// that sortAnswer does not know. It stops the LLM step, like a provider
	// failure. Its text is never printed, because it can hold anything.
	answerInternalFailed
	// answerDeadline means that the time limit of the whole LLM step
	// (llmStepTimeout) stopped the request, while the process got no
	// signal (see runLLMJobs). It stops the LLM step, like a provider
	// failure. sortAnswer never returns it.
	answerDeadline
)

// String returns the name of the kind, so a test failure or a debug print
// shows a name and not a number. Every kind has a name.
func (k answerKind) String() string {
	switch k {
	case answerNotRun:
		return "answerNotRun"
	case answerVerdict:
		return "answerVerdict"
	case answerUnusable:
		return "answerUnusable"
	case answerRejected:
		return "answerRejected"
	case answerStopped:
		return "answerStopped"
	case answerProviderFailed:
		return "answerProviderFailed"
	case answerInternalFailed:
		return "answerInternalFailed"
	case answerDeadline:
		return "answerDeadline"
	default:
		return fmt.Sprintf("answerKind(%d)", int(k))
	}
}

// stepFails reports whether an answer of kind k stops the LLM step at once.
// answerRejected does not: only the check after all the answers can make it
// fail the step (see rejectedFailure).
func (k answerKind) stepFails() bool {
	return k == answerProviderFailed || k == answerInternalFailed || k == answerDeadline
}

// answered reports whether the provider answered the job of an answer of
// kind k: with a verdict, with an answer that cannot be used, or with a
// refusal of this one tool. For the other kinds, the tool was not classified
// (see llmResult.skipped).
func (k answerKind) answered() bool {
	return k == answerVerdict || k == answerUnusable || k == answerRejected
}

// got2xx reports whether the provider answered the job of an answer of kind
// k with a 2xx status: with a verdict, or with model output that cannot be
// used (llm.ErrInvalidOutput comes only from a 2xx body).
func (k answerKind) got2xx() bool {
	return k == answerVerdict || k == answerUnusable
}

// sortAnswer returns the kind of the result of Classify with the error err.
//
// It fails closed. Only llm.ErrInvalidOutput (answerUnusable) and
// llm.ErrRejected (answerRejected) give an llm.RuleIDInvalid row: the
// provider answered, but there is no usable rating. Any error that
// sortAnswer does not know (for example a request that is too large, a nil
// client, or a future error path that does not wrap llm.ErrProvider) stops
// the step (answerInternalFailed). So a new error can never make a failed
// step look like a complete scan with medium findings.
//
// llm.ErrRejected wraps llm.ErrProvider, so its case must come before the
// llm.ErrProvider case: a switch takes the first case that is true. Every
// other provider error (401, 403, 404, 3xx, other codes, transport errors)
// stays a global failure (answerProviderFailed) that stops the step.
//
// A refusal alone does not stop the step. The refusals can still fail the
// step after all the requests end: see rejectedFailure for the rule.
func sortAnswer(err error) answerKind {
	switch {
	case err == nil:
		return answerVerdict
	case errors.Is(err, llm.ErrInvalidOutput):
		return answerUnusable
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return answerStopped
	case errors.Is(err, llm.ErrRejected):
		// Before the llm.ErrProvider case: ErrRejected wraps it.
		return answerRejected
	case errors.Is(err, llm.ErrProvider):
		return answerProviderFailed
	default:
		return answerInternalFailed
	}
}

// llmFailure is the first failure of the LLM step.
type llmFailure struct {
	// kind is answerProviderFailed or answerInternalFailed for the first
	// request that stopped the step, answerDeadline when the time limit of
	// the step stopped it first (see runLLMJobs), or answerRejected when the
	// refusals fail the step (see rejectedFailure for the rule).
	// answerRejected and answerDeadline are provider failures too: exit 2
	// and complete false, and the rows of the answered tools stay.
	kind answerKind
	// err is the error of the provider (llm.ErrProvider), whose text is
	// fixed (see llmFailureText). For answerRejected it is the error of the
	// first refused tool (llm.ErrRejected). It is nil for
	// answerInternalFailed: that error text is never kept, so it can never
	// be printed. It is nil for answerDeadline too.
	err error
	// timeout is the time limit of the step for answerDeadline, so that the
	// stderr line names it (see llmFailureLine). It is zero for the other
	// kinds.
	timeout time.Duration
}

// rejectedHintText is the fixed hint of the reason of an answerRejected
// failure (see rejectedReason). Every answered tool was refused, so it says
// "every tool", not "this tool" as llm.Reason does.
const rejectedHintText = "the provider refused every tool"

// llmInternalText is the text after the prefix of the stderr line when the
// LLM step failed for a reason that is not the provider. It is fixed text.
const llmInternalText = "the LLM step failed (internal error)"

// llmNoToolText is the text after the prefix of the stderr line when --llm
// is given but the step has no tool to classify: the config has no server, no
// server was inspected successfully, or the inspected servers list no tools.
// It is fixed text. It is a notice: it changes neither the exit code nor the
// JSON report.
const llmNoToolText = "--llm had no tool to classify"

// llmAnswer is the result of one job.
type llmAnswer struct {
	kind answerKind
	// verdict is the whole verdict for answerVerdict. For answerUnusable
	// and answerRejected, only verdict.Truncated is set (see
	// llm.Client.Classify), so that llmRow can rate a cut tool. For the
	// other kinds it is zero.
	verdict llm.Verdict
	// err is the error of Classify for answerRejected (it wraps
	// llm.ErrRejected and has fixed text), so that rejectedFailure can give
	// its reason. For the other kinds it is nil. newLLMAnswer sets it.
	err error
}

// newLLMAnswer returns the answer of kind k for the verdict v and the error
// err that Classify returned. It keeps of v only what llmAnswer.verdict
// documents, so a classifier that returns more with an error changes no row.
// It keeps err only for answerRejected, as llmAnswer.err documents: for the
// other kinds it drops err, so its text can never be printed.
func newLLMAnswer(k answerKind, v llm.Verdict, err error) llmAnswer {
	switch k {
	case answerVerdict:
		return llmAnswer{kind: k, verdict: v}
	case answerUnusable:
		return llmAnswer{kind: k, verdict: llm.Verdict{Truncated: v.Truncated}}
	case answerRejected:
		// Keep the error for the reason of rejectedFailure. Its text is
		// fixed.
		return llmAnswer{kind: k, verdict: llm.Verdict{Truncated: v.Truncated}, err: err}
	default:
		return llmAnswer{kind: k}
	}
}

// llmResult is the result of the LLM step.
type llmResult struct {
	// rows are the LLM findings that the ignore list does not drop, in the
	// order of the servers (inspect.Outcome.Index), then of the tools.
	rows []report.FindingRow
	// ignored counts the LLM findings that the ignore list dropped, by rule
	// ID. It is nil when the list dropped nothing.
	ignored map[string]int
	// fileBlocked lists the LLM rule IDs that have a .mcpmoat-ignore entry
	// that matches a kept row but is not applied (see scanIgnores). Each ID is
	// in it once, in the order of the first row that it matched. llmStep
	// prints one warning for each.
	fileBlocked []string
	// counts holds the number of rows of each server, by the index of the
	// server in the servers of the scan (see addLLMCounts).
	counts map[int]int
	// overCap is the number of tools over the share of their server of the
	// maxLLMTools cap (see fairShare), for all the servers together. They
	// were not sent.
	overCap int
	// failure is the first failure of the step: a provider failure, an
	// internal error, the time limit of the step, or the refusal of every
	// answered tool (see rejectedFailure). It is nil when no request failed.
	failure *llmFailure
	// skipped is the number of tools inside the shares that got no verdict:
	// the tool whose request failed, and the tools that were not sent after
	// it. After the step deadline, it is the tools whose request the
	// deadline stopped and the tools that were not sent. When every answered
	// tool was refused, it is every tool inside the shares.
	skipped int
	// tools is the number of tools that the step had to classify: every tool
	// of the inspected servers, also the ones over the cap. With 0, llmStep
	// prints llmNoToolText.
	tools int
}

// incomplete reports whether the LLM step missed tools. scan then exits
// with 2, and the JSON report has complete set to false.
func (r llmResult) incomplete() bool {
	return r.overCap > 0 || r.failure != nil || r.skipped > 0
}

// llmStep runs the LLM step of scan (see planLLMJobs and classifyPlan) on
// the tools of the inspected servers in outcomes. It prints on stderr one
// warning for each LLM rule that .mcpmoat-ignore cannot ignore (see
// llmResult.fileBlocked), then the problems of the step (see
// printLLMProblems). It returns an empty result and true when cl is nil (no
// --llm): then it sends nothing and prints nothing.
//
// With --llm and no tool to classify (outcomes is empty, no server was
// inspected, or the inspected servers list no tools), it sends nothing and
// prints one llmNoToolText line, so the user knows that no tool was rated.
// The line changes neither the exit code nor the JSON report.
//
// With at least one tool to send, it prints one notice line before the first
// request: the number of tools that it sends and the size of their text (see
// llmPlan.sendingNotice).
//
// It returns false when the process got a signal during a step that had a tool
// to classify. It has written interruptedText then (see interrupted), and scan
// must print no report and save no pins. With no tool to classify, a signal
// is not an error of the step, as without --llm. It returns false too, with
// one llmInternalText line, when classifyPlan fails while ctx is still alive
// (see llmStepStopped).
func (c *cli) llmStep(ctx context.Context, cl toolClassifier, outcomes []inspect.Outcome, ignore *scanIgnores) (llmResult, bool) {
	if cl == nil {
		return llmResult{}, true
	}
	plan := planLLMJobs(outcomes)
	// The notice comes here, between the two other groups of --llm lines on
	// stderr. The setup warning (see setupLLM) comes before the inspection:
	// it names the provider, but the tools are not known yet. The lines of
	// the result (llmNoToolText, the ignore warnings and printLLMProblems)
	// come after the requests. Only here are the tools known and no tool text
	// sent yet, so the notice tells the user how much data leaves the machine
	// before it leaves. With no job it is not printed: llmNoToolText says
	// that then. It goes to stderr also with --json, so stdout stays pure
	// JSON.
	if len(plan.jobs) > 0 {
		c.cmdPrintf("scan", "%s", plan.sendingNotice())
	}
	lr, err := classifyPlan(ctx, plan, cl, ignore, c.llmStepTimeoutOrDefault())
	if c.llmStepStopped(ctx, err) {
		return llmResult{}, false
	}
	if lr.tools == 0 {
		c.cmdPrintf("scan", "%s", llmNoToolText)
	}
	for _, id := range lr.fileBlocked {
		c.warnFileCannotIgnore(id)
	}
	c.printLLMProblems(lr)
	return lr, true
}

// llmStepStopped reports whether scan must stop after classifyPlan returned
// err, and writes the reason on stderr. With no error, the step is done, also
// when ctx ended: classifyPlan returns no error when it had no tool to
// classify, and then scan behaves as without --llm. When ctx ended (a signal)
// and err is not nil, it writes interruptedText (see interrupted).
// classifyPlan fails only when ctx ended, so the other case is a guard: an
// error while ctx is alive writes llmInternalText, never the text of err.
func (c *cli) llmStepStopped(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if c.interrupted(ctx, "scan") {
		return true
	}
	c.cmdPrintf("scan", "%s", llmInternalText)
	return true
}

// classifyPlan runs the jobs of plan, with the time limit timeout for all of
// them together, and returns the LLM findings. llmStep builds plan with
// planLLMJobs and then calls classifyPlan, so that it can print the notice
// between the two. It gives c.llmStepTimeoutOrDefault() as timeout:
// llmStepTimeout in a real scan, and the value that a test sets in
// cli.llmStepTimeout.
//
// The jobs send the name and the description of each tool of each inspected
// server (inspect.StatusOK) to cl. Nothing else of the tool and nothing of
// the server is sent. Each request also carries the secret values of the
// server (see llmServerJobs), so that cl removes them from the name and the
// description before it sends them.
//
// The tools go in the order of the servers (inspect.Outcome.Index), then in
// the order that the server lists them. At most maxLLMTools tools are sent,
// shared fairly between the servers (see planLLMJobs and fairShare): each
// server sends its first tools, up to its share. llmWorkers requests run at
// the same time. The rows keep the order of the tools, whatever the order in
// which the requests end.
//
// Each answered tool gives at most one report.SourceLLM row with fixed texts
// from package llm, so no model output reaches it: see llmRow. Only the
// --ignore entries drop rows, as for the pin rules: .mcpmoat-ignore cannot
// ignore the LLM rules (see scanIgnores). A file entry that matches a kept
// row is recorded in llmResult.fileBlocked.
//
// The first request that fails (a provider failure or an internal error, see
// sortAnswer) stops the step: the requests that run end and no new one
// starts. A request that package llm tries again fails only when its last
// try fails. The result then holds the failure (see llmResult.failure), and
// the tools without a verdict get no row.
//
// A tool that the provider refused (llm.ErrRejected) does not stop the step:
// it gets an llm.RuleIDInvalid row with llm.RejectedText. The refusals can
// still fail the step with no LLM row: see rejectedFailure for the rule.
//
// The whole step has the time limit timeout. When it is reached, the step
// stops like after a provider failure (see runLLMJobs): the failure is
// answerDeadline, the tools that got an answer keep their rows, and the
// other tools count as not classified. It is not a signal.
//
// The error is not nil only when ctx ended (the process got a signal) and at
// least one tool was to be classified. The caller then handles it like a
// signal during the inspection. With no tool, the result is empty and the
// error is nil.
func classifyPlan(ctx context.Context, plan llmPlan, cl toolClassifier, ignore *scanIgnores, timeout time.Duration) (llmResult, error) {
	res := llmResult{tools: plan.tools, overCap: plan.overCap}
	jobs := plan.jobs

	answers, failure := runLLMJobs(ctx, jobs, cl, timeout)
	// With no job, the step did nothing, so a signal that comes now is not
	// an LLM error. The caller handles it later, as without --llm.
	if err := ctx.Err(); err != nil && len(jobs) > 0 {
		return llmResult{}, err
	}
	if failure == nil {
		// A global failure wins. Without one, check the refusals.
		failure = rejectedFailure(answers)
	}
	res.failure = failure
	if failure != nil && failure.kind == answerRejected {
		// Fail closed: no tool was classified, so no tool gets a row.
		res.skipped = len(jobs)
		return res, nil
	}

	for i, job := range jobs {
		if !answers[i].kind.answered() {
			res.skipped++
			continue
		}
		row, ok := llmRow(job, answers[i])
		if !ok {
			continue // risk none: no finding
		}
		key := rules.FindingKey{RuleID: row.RuleID, Server: job.ref.Name, Tool: job.in.ToolName}
		// Only --ignore drops an LLM row. An entry of .mcpmoat-ignore that
		// matches is not applied (see scanIgnores).
		drop, fileBlocked := ignore.ignored(key)
		if drop {
			res.ignored = addIgnored(res.ignored, row.RuleID, 1)
			continue
		}
		if fileBlocked && !slices.Contains(res.fileBlocked, row.RuleID) {
			res.fileBlocked = append(res.fileBlocked, row.RuleID)
		}
		res.rows = append(res.rows, row)
		if res.counts == nil {
			res.counts = make(map[int]int)
		}
		res.counts[job.index]++
	}
	return res, nil
}

// rejectedFailure returns the failure of the step when at least one answer
// in answers is a refusal (answerRejected) and no answered job got a 2xx
// answer (see answerKind.got2xx). It returns nil in all other cases, also
// when answers is empty. Jobs without an answer (answerNotRun, answerStopped,
// a failed request) do not count.
//
// This is the one full statement of the rule for refusals (llm.ErrRejected).
// A refusal alone is per tool: the tool gets an llm.RuleIDInvalid row and
// the other requests go on. But the step fails closed when no tool got a
// 2xx answer. After all the requests end, classifyPlan applies this rule:
//
//   - A global failure (answerProviderFailed, answerInternalFailed or the
//     step deadline answerDeadline) or a signal wins: it is the failure of
//     the step, as without refusals, and classifyPlan does not call
//     rejectedFailure. The refused tools that were answered before it keep
//     their rows.
//   - Else, when at least one tool was refused and no answered tool got a
//     2xx answer (answerVerdict or answerUnusable), the step is a provider
//     failure with the reason of the refused tool with the lowest job index.
//     The refused tools then get no row: they count as not classified. So a
//     wrong model name or API shape that gives 400 for every tool exits
//     with 2 and complete false, not with one medium row for each tool.
//   - Else, the refused tools get their rows and the step is complete.
//
// Only answered jobs count. Without a global failure, a step deadline or a
// signal, no request is cancelled, so every job inside the shares of the cap
// (see fairShare) is answered.
//
// The failure holds the error of the refusal with the lowest index in
// answers. answers is in the order of the jobs, whatever the order in which
// the requests ended, so the reason is always the same for the same
// answers.
func rejectedFailure(answers []llmAnswer) *llmFailure {
	var first *llmFailure
	for _, a := range answers {
		if a.kind.got2xx() {
			return nil
		}
		if a.kind == answerRejected && first == nil {
			first = &llmFailure{kind: answerRejected, err: a.err}
		}
	}
	return first
}

// runLLMJobs runs the jobs with llmWorkers requests at the same time, and
// returns one answer for each job, in the order of jobs. A job that did not
// run has the kind answerNotRun.
//
// The first answer that stops the step (see answerKind.stepFails) is the
// failure: it stops the requests that run (it cancels their context) and no
// new job starts. When ctx ends, no new job starts either; the caller checks
// ctx. A refused tool (answerRejected) stops nothing: the caller checks the
// refusals after all the jobs (see rejectedFailure).
//
// All the jobs together have the time limit timeout. When it is reached, the
// context of the requests ends: the requests that run stop and no new job
// starts. The step ended by the deadline when the cause of that context is
// errLLMStepDeadline and ctx has not ended (see endedByDeadline). Then:
//
//   - A request that the deadline stopped is answerDeadline, not
//     answerStopped: it is not a signal and not the cancel after a failure.
//   - The failure is answerDeadline, when at least one job has no answer.
//     It replaces a failure that came after the deadline: such a failure
//     can be a result of the deadline. A failure that came first cancelled
//     the context first, so the cause is not errLLMStepDeadline and that
//     failure stays. So the first cause wins. The order is the order in
//     which the failures are recorded, not the order in which the workers
//     got them: a provider failure that a worker got just before the
//     deadline, but recorded just after it, can be reported as the deadline.
//     The exit code 2 and complete false do not change, only the reason on
//     stderr.
//   - When every job got an answer, the deadline came too late to change
//     anything, and the result is as without it.
//
// When ctx ends (a signal), the signal wins, also when the deadline is
// reached at the same time. The reason is not the cause of the context:
// when the deadline came first, the cause stays errLLMStepDeadline. The
// signal wins because endedByDeadline checks ctx.Err() first, and
// classifyPlan checks ctx.Err() after runLLMJobs returns. So the caller
// handles the signal, as without the deadline.
//
// runLLMJobs returns only after every request has ended: a deadline does
// not leave a goroutine behind.
func runLLMJobs(ctx context.Context, jobs []llmJob, cl toolClassifier, timeout time.Duration) ([]llmAnswer, *llmFailure) {
	answers := make([]llmAnswer, len(jobs))
	// WithTimeoutCause is WithTimeout with a cause: when timeout is
	// reached, stepCtx ends, stepCtx.Err() is context.DeadlineExceeded as
	// usual, and context.Cause(stepCtx) returns errLLMStepDeadline. The
	// cause lets the step tell its own deadline from the cancel after a
	// failure, and from a signal (the end of ctx) that came first. A signal
	// that comes after the deadline does not change the cause, so
	// endedByDeadline also checks ctx.Err(). stopTimer releases the timer
	// when the step ends before the deadline.
	stepCtx, stopTimer := context.WithTimeoutCause(ctx, timeout, errLLMStepDeadline)
	defer stopTimer()
	// runCtx is the context of the requests. cancel stops them after the
	// first failure. When stepCtx ends first, runCtx ends too, with the
	// same cause. When cancel comes first, the cause is context.Canceled.
	runCtx, cancel := context.WithCancel(stepCtx)
	defer cancel()

	var (
		mu      sync.Mutex
		failure *llmFailure
		wg      sync.WaitGroup
	)
	// sem holds one slot for each request that runs. A job waits for a free
	// slot before it starts.
	sem := make(chan struct{}, llmWorkers)

	for i, job := range jobs {
		select {
		case sem <- struct{}{}:
		case <-runCtx.Done():
		}
		if runCtx.Err() != nil {
			// A failure, the deadline or a signal: start no new job. A slot
			// that this iteration took stays taken, which does no harm.
			break
		}
		wg.Go(func() {
			defer func() { <-sem }()
			a, f := runLLMJob(ctx, runCtx, job, cl, timeout)
			// Each goroutine writes only its own element, so this needs no
			// lock.
			answers[i] = a
			if f == nil {
				return
			}
			mu.Lock()
			if failure == nil {
				failure = f
				cancel()
			}
			mu.Unlock()
		})
	}
	wg.Wait()
	// Check the deadline here too: it can end the step while no request
	// runs (between two jobs), and a failure that came after it must not
	// win. Every goroutine has ended, so failure needs no lock now.
	if endedByDeadline(ctx, runCtx) && !allAnswered(answers) {
		failure = &llmFailure{kind: answerDeadline, timeout: timeout}
	}
	return answers, failure
}

// runLLMJob runs one job of runLLMJobs: it sends the request with runCtx,
// the context of the requests, and returns the answer for the job. It also
// returns the failure of the job when the answer stops the step (see
// answerKind.stepFails), else nil. ctx is the context of the process, and
// timeout the time limit of the step (see runLLMJobs). runLLMJob only reads
// them: runLLMJobs keeps the first failure and cancels the other requests.
func runLLMJob(ctx, runCtx context.Context, job llmJob, cl toolClassifier, timeout time.Duration) (llmAnswer, *llmFailure) {
	v, err := cl.Classify(runCtx, job.in)
	kind := sortAnswer(err)
	if kind == answerStopped && endedByDeadline(ctx, runCtx) {
		// The deadline of the step stopped this request, not a signal and
		// not the cancel after a failure.
		kind = answerDeadline
	}
	a := newLLMAnswer(kind, v, err)
	if !kind.stepFails() {
		return a, nil
	}
	f := &llmFailure{kind: kind}
	switch kind {
	case answerProviderFailed:
		// Only a provider error is kept: its text is fixed.
		f.err = err
	case answerDeadline:
		f.timeout = timeout
	}
	return a, f
}

// endedByDeadline reports whether runCtx, the context of the requests of the
// LLM step, ended because the time limit of the step was reached, while ctx,
// the context of the process, is still alive (no signal).
//
// context.Cause returns the cause of the first reason that ended runCtx:
// errLLMStepDeadline for the deadline (see runLLMJobs), context.Canceled for
// the cancel after a failure, and the cause of ctx for a signal. It returns
// nil while runCtx is alive. errors.Is is used and not ==, as the errorlint
// gate asks; nothing wraps errLLMStepDeadline, so the two give the same
// result.
func endedByDeadline(ctx, runCtx context.Context) bool {
	return ctx.Err() == nil && errors.Is(context.Cause(runCtx), errLLMStepDeadline)
}

// allAnswered reports whether every answer in answers is an answer of the
// provider (see answerKind.answered). It is true for no answers.
func allAnswered(answers []llmAnswer) bool {
	for _, a := range answers {
		if !a.kind.answered() {
			return false
		}
	}
	return true
}

// printLLMProblems writes on stderr why the LLM step is incomplete: one line
// for a failed request or the step deadline, and one line for the tools over
// the cap. The cap line gives the total of the tools over the shares of all
// the servers (see fairShare), so it is one line also when several servers
// were cut. All the text is fixed, apart from numbers and the reason of a
// provider failure (see llmFailureText).
func (c *cli) printLLMProblems(r llmResult) {
	if r.failure != nil || r.skipped > 0 {
		c.cmdPrintf("scan", "%s; %d %s not classified",
			llmFailureLine(r.failure), r.skipped, plural(r.skipped, "tool was", "tools were"))
	}
	if r.overCap > 0 {
		c.cmdPrintf("scan", "--llm classifies at most %d tools in one scan; %d %s not classified",
			maxLLMTools, r.overCap, plural(r.overCap, "tool was", "tools were"))
	}
}

// llmFailureLine returns the start of the stderr line for the failure f of
// the LLM step: "the LLM provider failed (<reason>)" for a provider failure
// (see llmFailureText) and for the refusal of every answered tool (see
// rejectedReason), "the LLM step stopped after <time>" for the step deadline
// (see stepTimeoutText), else llmInternalText. A nil f with skipped tools
// cannot happen; it gives llmInternalText too, so it never blames the
// provider. A provider failure or a refusal without an error gives
// llmInternalText too.
func llmFailureLine(f *llmFailure) string {
	if f == nil {
		return llmInternalText
	}
	switch {
	case f.kind == answerDeadline:
		// The deadline line holds only a number and a fixed unit.
		return "the LLM step stopped after " + stepTimeoutText(f.timeout)
	case f.err == nil:
		return llmInternalText
	case f.kind == answerProviderFailed:
		return fmt.Sprintf("the LLM provider failed (%s)", llmFailureText(f.err))
	case f.kind == answerRejected:
		return fmt.Sprintf("the LLM provider failed (%s)", rejectedReason(f.err))
	default:
		return llmInternalText
	}
}

// rejectedReason returns the reason of an answerRejected failure: "HTTP
// <code>, the provider refused every tool" when err is an *llm.StatusError,
// else rejectedHintText. It does not use llm.Reason, whose hint is in
// parentheses and would give nested parentheses in the line. The code is an
// int and the hint is fixed, so the text holds no server data. termsafe.Quote
// still escapes it, as in llmFailureText.
func rejectedReason(err error) string {
	// errors.As finds an *llm.StatusError in the chain of err and stores it
	// in status. A typed nil in the chain gives a nil status, so check it.
	var status *llm.StatusError
	if errors.As(err, &status) && status != nil {
		return termsafe.Quote(fmt.Sprintf("HTTP %d, %s", status.Code, rejectedHintText))
	}
	return termsafe.Quote(rejectedHintText)
}

// llmFailureText returns the reason of a failed request to the provider: the
// fixed text of llm.Reason. For a status code it is "HTTP <code>", with a
// fixed hint for some codes: "HTTP 401 (the API key was refused)" for 401 and
// 403, and "HTTP 302 (redirect refused)" for a 3xx. For another provider
// error it is the fixed text of that error, for example "network error", and
// for an unknown error it is "unknown error". The text of llm.ErrProvider at
// the start is not in it, because the line already says "the LLM provider
// failed". llm.Reason never uses the text of an unknown error, so the reason
// never holds the key, the URL or a response body. termsafe.Quote still
// escapes the text as a second guard.
func llmFailureText(err error) string {
	return termsafe.Quote(llm.Reason(err))
}
