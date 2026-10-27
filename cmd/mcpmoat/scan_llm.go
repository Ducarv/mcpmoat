package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
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
	// maxLLMTools is the largest number of tools that one scan sends to the
	// provider. It bounds the cost of a scan, and llmStepTimeout bounds its
	// time. The client of package llm sends at most 3 requests for one tool
	// (the first request and 2 retries), so one scan sends at most 1500
	// requests. The servers share the cap fairly (see fairShare), so one
	// server with many tools cannot use it all and leave the other servers
	// without a rating.
	maxLLMTools = 500
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
// stderr line and the help: "10 minutes" for whole minutes, "30 seconds" for
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

// noLLMClientText is the text after the prefix of the error line that scan
// prints when it has no LLM client. This is a bug in mcpmoat, not a user
// error. It is fixed text.
const noLLMClientText = "internal error: no LLM client"

// noToolNameKey is the Key of an LLM finding row or a tool rule row (see
// toolKey) for a tool with an empty name. A hostile server can list such a
// tool. The report writers treat a row with an empty Key as a row about the
// whole server, so the row gets this fixed text instead. The request to the
// provider still has the real (empty) name.
const noToolNameKey = "(no name)"

// toolClassifier rates one tool. *llm.Client implements it. Tests use a fake,
// so they send no request.
type toolClassifier interface {
	Classify(ctx context.Context, in llm.Input) (llm.Verdict, error)
}

// newLLMClassifier is the real value of cli.newClassifier: it wraps llm.New.
// It sends no request.
func newLLMClassifier(cfg llm.Config) (toolClassifier, error) {
	client, err := llm.New(cfg)
	if err != nil {
		// Return a plain nil. A nil *llm.Client in the interface would not
		// compare equal to nil.
		return nil, err
	}
	return client, nil
}

// The names of the LLM flags of scan (FR-17), without the dashes.
const (
	flagLLM         = "llm"
	flagLLMProvider = "llm-provider"
	flagLLMModel    = "llm-model"
	flagLLMBaseURL  = "llm-base-url"
)

// addLLMFlags adds the four LLM flags of scan (FR-17) to fs. They store
// their values in f. --llm is off by default. The other three refuse an
// empty value (see onceStringFlag), so an empty value in f means that the
// flag was not given. checkLLMFlags checks them all.
//
// The base URL can hold a user:password, so the errors of its flag never
// hold the value. addLLMFlags returns that flag: when Parse fails, the
// caller prints its problem in place of the Parse error (see
// secretStringFlag).
func addLLMFlags(fs *flag.FlagSet, f *llmFlags) *secretFlag {
	fs.BoolVar(&f.on, flagLLM, false, "")
	onceStringFlag(fs, flagLLMProvider, "a provider name", &f.provider)
	onceStringFlag(fs, flagLLMModel, "a model name", &f.model)
	return secretStringFlag(fs, flagLLMBaseURL, "a URL", &f.baseURL)
}

// setupLLM checks the LLM flags (see checkLLMFlags) and, with --llm, prints
// the warning on stderr and builds the classifier (see buildClassifier).
// runScan calls it before it reads a config file. The warning comes before
// the client is built and before any request, also with --json (FR-17).
//
// It returns a nil classifier and true without --llm: then it reads no API
// key and builds no client. On a problem it has printed the error and
// returns false, and scan exits with 2.
func (c *cli) setupLLM(f llmFlags, noConnect bool) (toolClassifier, bool) {
	setup, ok := c.checkLLMFlags(f, noConnect)
	if !ok || setup == nil {
		return nil, ok
	}
	c.scanWarnf("%s", setup.warningText())
	return c.buildClassifier(setup.cfg)
}

// buildClassifier gets the classifier for cfg from c.newClassifier. This is
// the only place that calls it, and runScan calls it only with --llm. On an
// error it prints one line on stderr and returns false. The errors of llm.New
// have fixed text; termsafe.Quote still escapes the text, because a test can
// set any factory.
func (c *cli) buildClassifier(cfg llm.Config) (toolClassifier, bool) {
	if c.newClassifier == nil {
		c.cmdPrintf("scan", "%s", noLLMClientText)
		return nil, false
	}
	cl, err := c.newClassifier(cfg)
	if err != nil {
		c.cmdErr("scan", "cannot set up the LLM client", err)
		return nil, false
	}
	if cl == nil {
		c.cmdPrintf("scan", "%s", noLLMClientText)
		return nil, false
	}
	return cl, true
}

// closeClassifier closes the idle connections of cl, when cl has such a
// method (*llm.Client has one). A fake from a test usually has none. cl can
// be nil (no --llm): the type assertion is then false, and it does nothing.
func closeClassifier(cl toolClassifier) {
	if closer, ok := cl.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// llmFlags holds the values of the LLM flags as the user gave them. An empty
// string means that the flag was not given.
type llmFlags struct {
	on       bool   // --llm
	provider string // --llm-provider
	model    string // --llm-model
	baseURL  string // --llm-base-url
}

// strayLLMFlag returns the name of the first LLM flag in f that needs --llm,
// for example "--llm-model", or "" when f has none.
func strayLLMFlag(f llmFlags) string {
	for _, given := range []struct{ name, value string }{
		{"--" + flagLLMProvider, f.provider},
		{"--" + flagLLMModel, f.model},
		{"--" + flagLLMBaseURL, f.baseURL},
	} {
		if given.value != "" {
			return given.name
		}
	}
	return ""
}

// llmSetup is the checked LLM config of one scan.
type llmSetup struct {
	// cfg is the resolved config, with the defaults filled in and the API key
	// from the environment. cfg.APIKey prints as a mask.
	cfg llm.Config
	// host is the host of cfg.BaseURL, with the port if it has one. The
	// warning names it.
	host string
}

// newLLMSetup returns the llmSetup of cfg, a config that Resolve returned.
// Resolve checked cfg.BaseURL with llm.ValidateBaseURL, so the URL parses
// and has a host: the error is only a guard. It is llm.ErrInvalidBaseURL
// and never the url.Parse error, because that text quotes the URL, which
// can hold a secret.
func newLLMSetup(cfg llm.Config) (*llmSetup, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		return nil, llm.ErrInvalidBaseURL
	}
	return &llmSetup{cfg: cfg, host: u.Host}, nil
}

// warningText returns the text of the warning that scan prints on stderr
// before it builds the client and before any request (FR-17). The provider
// name is one of the fixed llm.Provider values. The host comes from the user,
// so termsafe.Quote escapes it.
func (s *llmSetup) warningText() string {
	return fmt.Sprintf("--llm sends the name and description of every tool to the LLM provider %s at %s. This data leaves your machine.",
		s.cfg.Provider, termsafe.Quote(s.host))
}

// checkLLMFlags checks the LLM flags and returns the LLM config of the scan.
// It returns nil and true when --llm is not set: then it reads no API key.
// On a problem it prints one usage error on stderr and returns false, and
// scan exits with 2.
//
// The API key comes only from the environment variable llm.KeyEnv, read
// through c.getenv. No message holds the key: the texts come from the llm
// errors, which are fixed and never hold the key, the model name or the URL.
func (c *cli) checkLLMFlags(f llmFlags, noConnect bool) (*llmSetup, bool) {
	if !f.on {
		// An LLM flag without --llm would do nothing. Say so, or the user
		// could think that the scan used the LLM.
		if name := strayLLMFlag(f); name != "" {
			c.usageError("scan", "%s needs --llm", name)
			return nil, false
		}
		return nil, true
	}
	if noConnect {
		c.usageError("scan", "--llm cannot be used with --no-connect: the LLM needs a connection to each server to get its tools")
		return nil, false
	}

	name := f.provider
	if name == "" {
		name = string(llm.ProviderAnthropic)
	}
	provider, err := llm.ParseProvider(name)
	if err != nil {
		c.usageError("scan", "--llm-provider: %v", err)
		return nil, false
	}
	if f.model == "" && provider.DefaultModel() == "" {
		c.usageError("scan", "--llm-provider %s needs --llm-model", provider)
		return nil, false
	}
	if f.baseURL != "" {
		if err := llm.ValidateBaseURL(f.baseURL); err != nil {
			c.usageError("scan", "--llm-base-url: %v", err)
			return nil, false
		}
	}
	key := c.getenv(llm.KeyEnv)
	if err := llm.ValidateKey(key); err != nil {
		// The error text names llm.KeyEnv and never holds the key.
		c.usageError("scan", "--llm: %v", err)
		return nil, false
	}

	cfg, err := llm.Config{
		Provider: provider,
		Model:    f.model,
		BaseURL:  f.baseURL,
		APIKey:   discover.NewSecret(key),
	}.Resolve()
	if err != nil {
		if errors.Is(err, llm.ErrInvalidModel) {
			c.usageError("scan", "--llm-model: %v", err)
		} else {
			c.usageError("scan", "--llm: %v", err)
		}
		return nil, false
	}
	setup, err := newLLMSetup(cfg)
	if err != nil {
		c.usageError("scan", "--llm-base-url: %v", err)
		return nil, false
	}
	return setup, true
}

// llmJob is one tool to classify.
type llmJob struct {
	// index is the index of the server in the servers of the scan
	// (inspect.Outcome.Index).
	index int
	// ref is the server of the finding row. ref.Name is the server name
	// from the config file. It is untrusted.
	ref report.ServerRef
	// in is what the classifier gets: the tool name and description, and the
	// secret values of the server (inspect.Result.Secrets). The classifier
	// sends only the name and the description, after it replaces each secret
	// value in them with discover.Mask (FR-17). The jobs of one server share
	// one Secrets slice: it is read only.
	in llm.Input
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
	// other requests go on. When no answered tool got a 2xx answer, the step
	// fails closed (see rejectedFailure). As an llmFailure kind it is that
	// failure.
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
// A refusal alone is per tool, but the step fails closed when no tool got a
// 2xx answer. After all the requests end, classifyTools applies this rule
// (see rejectedFailure):
//
//   - A global failure (answerProviderFailed, answerInternalFailed or the
//     step deadline answerDeadline) or a signal wins: it is the failure of
//     the step, as without refusals. The refused tools that were answered
//     before it keep their rows.
//   - Else, when at least one tool was refused and no answered tool got a
//     2xx answer (answerVerdict or answerUnusable), the step is a provider
//     failure with the reason of the refused tool with the lowest job index.
//     The refused tools then get no row: they count as not classified. So a
//     wrong model name or API shape that gives 400 for every tool exits
//     with 2 and complete false, not with one medium row for each tool.
//   - Else, the refused tools get their rows and the step is complete.
//
// Only answered jobs count. Without a global failure, a step deadline and a
// signal, no request is cancelled, so every job inside the shares of the cap
// (see fairShare) is answered.
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
	// the step stopped it first (see runLLMJobs), or answerRejected when no
	// answered tool got a 2xx answer and at least one was refused (see
	// rejectedFailure). answerRejected and answerDeadline are provider
	// failures too: exit 2 and complete false, and the rows of the answered
	// tools stay.
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
	// its reason. For the other kinds it is nil. runLLMJobs sets it.
	err error
}

// newLLMAnswer returns the answer of kind k for the verdict v that Classify
// returned. It keeps of v only what llmAnswer.verdict documents, so a
// classifier that returns more with an error changes no row.
func newLLMAnswer(k answerKind, v llm.Verdict) llmAnswer {
	switch k {
	case answerVerdict:
		return llmAnswer{kind: k, verdict: v}
	case answerUnusable, answerRejected:
		return llmAnswer{kind: k, verdict: llm.Verdict{Truncated: v.Truncated}}
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

// llmStep runs the LLM step of scan (see classifyTools) on the tools of the
// inspected servers in outcomes. It prints on stderr one warning for each LLM
// rule that .mcpmoat-ignore cannot ignore (see llmResult.fileBlocked), then
// the problems of the step (see printLLMProblems). It returns an empty result
// and true when cl is nil (no --llm): then it sends nothing and prints
// nothing.
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
// one llmInternalText line, when classifyTools fails while ctx is still alive
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

// llmStepStopped reports whether scan must stop after classifyTools returned
// err, and writes the reason on stderr. With no error, the step is done, also
// when ctx ended: classifyTools returns no error when it had no tool to
// classify, and then scan behaves as without --llm. When ctx ended (a signal)
// and err is not nil, it writes interruptedText (see interrupted).
// classifyTools fails only when ctx ended, so the other case is a guard: an
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

// classifyTools sends the name and the description of each tool of each
// inspected server (inspect.StatusOK) to cl, and returns the LLM findings.
// It sends nothing else of the tool and nothing of the server. Each request
// also carries the secret values of the server (see llmJobs), so that cl
// removes them from the name and the description before it sends them.
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
// it gets an llm.RuleIDInvalid row with llm.RejectedText. But when no
// answered tool got a 2xx answer, the step fails closed with no LLM row (see
// sortAnswer for the rule and rejectedFailure).
//
// The whole step has the time limit llmStepTimeout. When it is reached, the
// step stops like after a provider failure (see runLLMJobs): the failure is
// answerDeadline, the tools that got an answer keep their rows, and the
// other tools count as not classified. It is not a signal.
//
// The error is not nil only when ctx ended (the process got a signal) and at
// least one tool was to be classified. The caller then handles it like a
// signal during the inspection. With no tool, the result is empty and the
// error is nil.
//
// classifyTools is planLLMJobs and then classifyPlan, with the time limit
// llmStepTimeout. llmStep calls the two itself, so that it can print the
// notice between them, and so that a test can set the time limit (see
// cli.llmStepTimeout).
func classifyTools(ctx context.Context, outcomes []inspect.Outcome, cl toolClassifier, ignore *scanIgnores) (llmResult, error) {
	return classifyPlan(ctx, planLLMJobs(outcomes), cl, ignore, llmStepTimeout)
}

// classifyPlan runs the jobs of plan, with the time limit timeout for all of
// them together, and returns the LLM findings. It is the part of
// classifyTools after the jobs are built: see classifyTools for the whole
// behaviour.
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
// a failed request) do not count. The caller calls it only when the step
// has no global failure (see sortAnswer for the whole rule).
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

// llmPlan is the work of the LLM step, before the first request.
type llmPlan struct {
	// jobs are the tools to send, in the order of the servers
	// (inspect.Outcome.Index), then of the tools. Each server has at most its
	// share of maxLLMTools (see fairShare).
	jobs []llmJob
	// tools is the number of tools of the inspected servers, also the ones
	// over the shares.
	tools int
	// overCap is tools minus len(jobs): the tools over the shares, for all
	// the servers together. They are not sent.
	overCap int
}

// planLLMJobs returns the plan of the LLM step for the inspected servers in
// outcomes (see llmServerJobs). It splits maxLLMTools between the servers
// with fairShare, and keeps the first tools of each server up to its share,
// in the order that the server lists them. So a server with many tools
// cannot take the whole cap: a hostile server that lists thousands of tools
// still leaves a share to each other server.
func planLLMJobs(outcomes []inspect.Outcome) llmPlan {
	servers := llmServerJobs(outcomes)
	counts := make([]int, len(servers))
	for i, jobs := range servers {
		counts[i] = len(jobs)
	}
	shares := fairShare(counts, maxLLMTools)

	var plan llmPlan
	for i, jobs := range servers {
		plan.tools += len(jobs)
		plan.jobs = append(plan.jobs, jobs[:shares[i]]...)
	}
	plan.overCap = plan.tools - len(plan.jobs)
	return plan
}

// sendingNotice returns the text of the notice that llmStep prints on stderr
// before the first request: the number of jobs, and the size of the tool
// text that they send, in KiB rounded up. It holds numbers only: no tool
// text, no server name and nothing from the provider.
//
// The size is the sum of the bytes of each tool name and description after
// the cuts of package llm (llm.MaxToolNameBytes and llm.MaxDescriptionBytes).
// It is approximate ("about"): the masks of the secret values, the JSON
// escapes and the prompt change the real size of a request a little.
func (p llmPlan) sendingNotice() string {
	size := 0
	for _, job := range p.jobs {
		// min is a built-in function since Go 1.21.
		size += min(len(job.in.ToolName), llm.MaxToolNameBytes)
		size += min(len(job.in.Description), llm.MaxDescriptionBytes)
	}
	// Integer division rounds down. Adding 1023 first makes it round up, so
	// 1 byte shows as 1 KiB and not as 0 KiB.
	kib := (size + 1023) / 1024
	n := len(p.jobs)
	return fmt.Sprintf("sending %d %s (about %d KiB of text) to the LLM provider", n, plural(n, "tool", "tools"), kib)
}

// fairShare splits budget between servers that have counts[i] tools each,
// with a max-min fair share, and returns the share of each server, in the
// order of counts. A server never gets more than its count. A server with
// fewer tools than an equal part keeps all of them, and the part that it does
// not use goes to the other servers. The sum of the shares is the smaller of
// budget and the sum of counts.
//
// When the parts cannot be equal, the remainder goes to the servers that come
// first in counts, one tool each, so the result is always the same for the
// same input. For example, counts {3, 1000, 1000} with budget 500 give
// {3, 249, 248}. A count or a budget below 0 counts as 0.
func fairShare(counts []int, budget int) []int {
	shares := make([]int, len(counts))
	// order holds the indexes of counts, the smallest count first. The sort
	// is stable: servers with the same count keep the order of counts.
	order := make([]int, len(counts))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int {
		return cmp.Compare(max(counts[a], 0), max(counts[b], 0))
	})

	// This is "water-filling". Go from the smallest server to the largest.
	// While a server has no more tools than an equal part of what is left,
	// it gets all its tools. The first server with more tools than that part
	// stops the loop: all the servers after it are at least as large, so they
	// all get an equal part of what is left.
	left := max(budget, 0)
	for k, i := range order {
		n := len(order) - k // the servers that have no share yet
		count := max(counts[i], 0)
		if count <= left/n {
			shares[i] = count
			left -= count
			continue
		}
		// Each of the n servers gets left/n tools, and the first left%n of
		// them in the order of counts get one tool more. Each one has more
		// than left/n tools, so it has the tool for the extra one.
		rest := slices.Sorted(slices.Values(order[k:]))
		for j, idx := range rest {
			shares[idx] = left / n
			if j < left%n {
				shares[idx]++
			}
		}
		break
	}
	return shares
}

// llmServerJobs returns, for each inspected server with at least one tool,
// one job for each of its tools, in the order of the tools. The servers are
// in their order in the scan (inspect.Outcome.Index). inspect.Run sorts the
// outcomes, so their order is not the order of the servers.
//
// Every job of a server gets the secret values of that server
// (inspect.Result.Secrets) in llm.Input.Secrets, so that llm removes them
// from the tool text before the request (FR-17). A server that got a token
// can put it in a tool name or description. The jobs share the slice of the
// outcome and never change it.
func llmServerJobs(outcomes []inspect.Outcome) [][]llmJob {
	sorted := slices.SortedStableFunc(slices.Values(outcomes), func(a, b inspect.Outcome) int {
		return cmp.Compare(a.Index, b.Index)
	})
	var servers [][]llmJob
	for _, o := range sorted {
		if o.Status != inspect.StatusOK || len(o.Result.Tools) == 0 {
			continue
		}
		ref := report.NewServerRef(o.Server)
		jobs := make([]llmJob, 0, len(o.Result.Tools))
		for _, t := range o.Result.Tools {
			jobs = append(jobs, llmJob{
				index: o.Index,
				ref:   ref,
				in: llm.Input{
					ToolName:    t.Name,
					Description: t.Description,
					Secrets:     o.Result.Secrets,
				},
			})
		}
		servers = append(servers, jobs)
	}
	return servers
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
//     failure stays. So the first cause wins.
//   - When every job got an answer, the deadline came too late to change
//     anything, and the result is as without it.
//
// When ctx ends (a signal), the cause is not errLLMStepDeadline, also when
// the deadline is reached at the same time: the caller sees ctx.Err() and
// handles the signal, as without the deadline.
//
// runLLMJobs returns only after every request has ended: a deadline does
// not leave a goroutine behind.
func runLLMJobs(ctx context.Context, jobs []llmJob, cl toolClassifier, timeout time.Duration) ([]llmAnswer, *llmFailure) {
	answers := make([]llmAnswer, len(jobs))
	// WithTimeoutCause is WithTimeout with a cause: when timeout is
	// reached, stepCtx ends, stepCtx.Err() is context.DeadlineExceeded as
	// usual, and context.Cause(stepCtx) returns errLLMStepDeadline. The
	// cause lets the step tell its own deadline from a signal (the end of
	// ctx). stopTimer releases the timer when the step ends before the
	// deadline.
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
			v, err := cl.Classify(runCtx, job.in)
			kind := sortAnswer(err)
			if kind == answerStopped && endedByDeadline(ctx, runCtx) {
				// The deadline of the step stopped this request, not a
				// signal and not the cancel after a failure.
				kind = answerDeadline
			}
			// Each goroutine writes only its own element, so this needs no
			// lock.
			answers[i] = newLLMAnswer(kind, v)
			if kind == answerRejected {
				// Keep the error for the reason of rejectedFailure. Its
				// text is fixed.
				answers[i].err = err
			}
			if !kind.stepFails() {
				return
			}
			f := &llmFailure{kind: kind}
			switch kind {
			case answerProviderFailed:
				// Only a provider error is kept: its text is fixed.
				f.err = err
			case answerDeadline:
				f.timeout = timeout
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

// llmRow returns the finding row that the answer a of job gives, and true. It
// returns false when a gives no row: a verdict with risk none (and no cut
// text), or a job without an answer (see answerKind.answered).
//
// A verdict whose risk or category is not valid counts as an answer that
// cannot be used, so it fails closed. parseVerdict never returns one, but a
// classifier in a test can. A cut tool text (llm.Verdict.Truncated) gets the
// floor row (see truncatedRow) when the model rated it none or low, or gave
// no usable answer, or the provider refused it. So a cut tool always gets an
// llm.RuleID row of at least medium, and never an llm.RuleIDInvalid row.
//
// The Key is toolKey(job.in.ToolName), as in a tool rule row: the name cut to
// maxToolKeyRunes runes, or noToolNameKey for an empty name. All the rows
// below start from this row, so they all get the same Key. The ignore lookup
// in classifyTools uses the real tool name, not the Key.
func llmRow(job llmJob, a llmAnswer) (report.FindingRow, bool) {
	row := report.FindingRow{
		ServerRef: job.ref,
		Source:    report.SourceLLM,
		Field:     rules.FieldTool,
		Key:       toolKey(job.in.ToolName),
	}
	switch a.kind {
	case answerVerdict:
		v := a.verdict
		if !v.Risk.Valid() || !v.Category.Valid() {
			return unusableRow(row, v.Truncated), true
		}
		if v.Truncated && belowMedium(v.Risk) {
			return truncatedRow(row), true
		}
		severity, hasRisk := llmSeverity(v.Risk)
		if !hasRisk {
			return report.FindingRow{}, false // risk none
		}
		row = llmRuleRow(row)
		row.Severity = string(severity)
		row.Risk = v.Category.Text()
		row.Related = string(v.Category)
		return row, true
	case answerUnusable:
		return unusableRow(row, a.verdict.Truncated), true
	case answerRejected:
		return rejectedRow(row, a.verdict.Truncated), true
	default:
		// answerNotRun, answerStopped, answerProviderFailed,
		// answerInternalFailed and answerDeadline: the tool got no answer.
		return report.FindingRow{}, false
	}
}

// llmSeverity returns the severity of a finding for the LLM risk r, and true.
// It is the one place that maps an llm.Risk to a rules.Severity: low, medium
// and high map to the severity with the same name. The cap is high, never
// critical: the model alone can never give the highest severity. For
// llm.RiskNone and for a risk that is not valid, it returns false and there
// is no finding.
func llmSeverity(r llm.Risk) (rules.Severity, bool) {
	switch r {
	case llm.RiskLow:
		return rules.SeverityLow, true
	case llm.RiskMedium:
		return rules.SeverityMedium, true
	case llm.RiskHigh:
		return rules.SeverityHigh, true
	default:
		return "", false
	}
}

// belowMedium reports whether the valid risk r of a verdict for a cut tool
// text asks for the floor row: r is none or low.
func belowMedium(r llm.Risk) bool {
	return r == llm.RiskNone || r == llm.RiskLow
}

// llmRuleRow fills the fixed texts of an llm.RuleID row into row: the rule
// ID, the title and the remediation.
func llmRuleRow(row report.FindingRow) report.FindingRow {
	row.RuleID = llm.RuleID
	row.Title = llm.Title
	row.Remediation = llm.Remediation
	return row
}

// unusableRow fills row for an answer that cannot be used: the floor row
// (see truncatedRow) when the tool text was cut, else an llm.RuleIDInvalid
// row with severity medium and the fixed texts of package llm.
func unusableRow(row report.FindingRow, truncated bool) report.FindingRow {
	return invalidRow(row, truncated, llm.InvalidText)
}

// rejectedRow fills row for a tool that the provider refused
// (answerRejected): the same row as unusableRow, but with the risk text
// llm.RejectedText. A cut tool gets the floor row (see truncatedRow).
func rejectedRow(row report.FindingRow, truncated bool) report.FindingRow {
	return invalidRow(row, truncated, llm.RejectedText)
}

// invalidRow fills row for a tool without a usable rating: the floor row
// (see truncatedRow) when the tool text was cut, else an llm.RuleIDInvalid
// row with severity medium, the fixed risk text risk and the other fixed
// texts of package llm. risk is one of the fixed texts of package llm.
func invalidRow(row report.FindingRow, truncated bool, risk string) report.FindingRow {
	if truncated {
		return truncatedRow(row)
	}
	row.RuleID = llm.RuleIDInvalid
	row.Title = llm.InvalidTitle
	row.Severity = string(rules.SeverityMedium)
	row.Risk = risk
	row.Remediation = llm.InvalidRemediation
	return row
}

// truncatedRow fills row, an LLM row of a tool whose text was cut, as the
// floor row: llm.RuleID, severity medium, the fixed text llm.TruncatedText
// and the category other, whatever the model answered. The part after the
// cut was not rated, and a prompt injection before the cut can ask for a low
// rating or make the model refuse.
func truncatedRow(row report.FindingRow) report.FindingRow {
	row = llmRuleRow(row)
	row.Severity = string(rules.SeverityMedium)
	row.Risk = llm.TruncatedText
	row.Related = string(llm.CategoryOther)
	return row
}

// addLLMCounts adds the LLM row counts of each server to counts, the
// finding counts by server index that serverStatuses gets. An index outside
// counts cannot happen; it is skipped rather than panic.
func addLLMCounts(counts []int, llmCounts map[int]int) {
	for i, n := range llmCounts {
		if i >= 0 && i < len(counts) {
			counts[i] += n
		}
	}
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
