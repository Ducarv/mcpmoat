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
	// provider. It bounds the cost and the time of a scan.
	maxLLMTools = 500
	// llmWorkers is the number of requests that run at the same time.
	llmWorkers = llm.MaxConcurrentRequests
)

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
// place that sorts the errors of Classify.
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
	// answerStopped means that the context of the request ended: a signal,
	// or the cancel after the first failure of the step.
	answerStopped
	// answerProviderFailed means that the request to the provider failed
	// (llm.ErrProvider). It stops the LLM step.
	answerProviderFailed
	// answerInternalFailed means any other error: a local error, or an error
	// that sortAnswer does not know. It stops the LLM step, like a provider
	// failure. Its text is never printed, because it can hold anything.
	answerInternalFailed
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
	case answerStopped:
		return "answerStopped"
	case answerProviderFailed:
		return "answerProviderFailed"
	case answerInternalFailed:
		return "answerInternalFailed"
	default:
		return fmt.Sprintf("answerKind(%d)", int(k))
	}
}

// stepFails reports whether an answer of kind k stops the LLM step.
func (k answerKind) stepFails() bool {
	return k == answerProviderFailed || k == answerInternalFailed
}

// answered reports whether the provider answered the job of an answer of
// kind k: with a verdict, or with an answer that cannot be used. For the
// other kinds, the tool was not classified (see llmResult.skipped).
func (k answerKind) answered() bool {
	return k == answerVerdict || k == answerUnusable
}

// sortAnswer returns the kind of the result of Classify with the error err.
//
// It fails closed. Only llm.ErrInvalidOutput gives an llm.RuleIDInvalid row
// (answerUnusable): the model answered, but its answer cannot be used. Any
// error that sortAnswer does not know (for example a request that is too
// large, a nil client, or a future error path that does not wrap
// llm.ErrProvider) stops the step (answerInternalFailed). So a new error can
// never make a failed step look like a complete scan with medium findings.
func sortAnswer(err error) answerKind {
	switch {
	case err == nil:
		return answerVerdict
	case errors.Is(err, llm.ErrInvalidOutput):
		return answerUnusable
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return answerStopped
	case errors.Is(err, llm.ErrProvider):
		return answerProviderFailed
	default:
		return answerInternalFailed
	}
}

// llmFailure is the first failure of the LLM step.
type llmFailure struct {
	// kind is answerProviderFailed or answerInternalFailed.
	kind answerKind
	// err is the error of the provider (llm.ErrProvider), whose text is
	// fixed (see llmFailureText). It is nil for answerInternalFailed: that
	// error text is never kept, so it can never be printed.
	err error
}

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
	// verdict is the whole verdict for answerVerdict. For answerUnusable,
	// only verdict.Truncated is set (see llm.Client.Classify), so that
	// llmRow can rate a cut tool. For the other kinds it is zero.
	verdict llm.Verdict
}

// newLLMAnswer returns the answer of kind k for the verdict v that Classify
// returned. It keeps of v only what llmAnswer.verdict documents, so a
// classifier that returns more with an error changes no row.
func newLLMAnswer(k answerKind, v llm.Verdict) llmAnswer {
	switch k {
	case answerVerdict:
		return llmAnswer{kind: k, verdict: v}
	case answerUnusable:
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
	// overCap is the number of tools after the first maxLLMTools. They were
	// not sent.
	overCap int
	// failure is the first failure of the step: a provider failure or an
	// internal error. It is nil when no request failed.
	failure *llmFailure
	// skipped is the number of tools under the cap that got no verdict: the
	// tool whose request failed, and the tools that were not sent after it.
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
	lr, err := classifyTools(ctx, outcomes, cl, ignore)
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
// the order that the server lists them. Only the first maxLLMTools tools are
// sent. llmWorkers requests run at the same time. The rows keep the order of
// the tools, whatever the order in which the requests end.
//
// Each answered tool gives at most one report.SourceLLM row with fixed texts
// from package llm, so no model output reaches it: see llmRow. Only the
// --ignore entries drop rows, as for the pin rules: .mcpmoat-ignore cannot
// ignore the LLM rules (see scanIgnores). A file entry that matches a kept
// row is recorded in llmResult.fileBlocked.
//
// The first request that fails (a provider failure or an internal error, see
// sortAnswer) stops the step: the requests that run end and no new one
// starts. The result then holds the failure (see llmResult.failure), and the
// tools without a verdict get no row.
//
// The error is not nil only when ctx ended (the process got a signal) and at
// least one tool was to be classified. The caller then handles it like a
// signal during the inspection. With no tool, the result is empty and the
// error is nil.
func classifyTools(ctx context.Context, outcomes []inspect.Outcome, cl toolClassifier, ignore *scanIgnores) (llmResult, error) {
	var res llmResult
	jobs := llmJobs(outcomes)
	res.tools = len(jobs)
	if len(jobs) > maxLLMTools {
		res.overCap = len(jobs) - maxLLMTools
		jobs = jobs[:maxLLMTools]
	}

	answers, failure := runLLMJobs(ctx, jobs, cl)
	// With no job, the step did nothing, so a signal that comes now is not
	// an LLM error. The caller handles it later, as without --llm.
	if err := ctx.Err(); err != nil && len(jobs) > 0 {
		return llmResult{}, err
	}
	res.failure = failure

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

// llmJobs returns one job for each tool of each inspected server, in the order
// of the servers (inspect.Outcome.Index), then of the tools. inspect.Run sorts
// the outcomes, so their order is not the order of the servers.
//
// Every job of a server gets the secret values of that server
// (inspect.Result.Secrets) in llm.Input.Secrets, so that llm removes them
// from the tool text before the request (FR-17). A server that got a token
// can put it in a tool name or description. The jobs share the slice of the
// outcome and never change it.
func llmJobs(outcomes []inspect.Outcome) []llmJob {
	sorted := slices.SortedStableFunc(slices.Values(outcomes), func(a, b inspect.Outcome) int {
		return cmp.Compare(a.Index, b.Index)
	})
	var jobs []llmJob
	for _, o := range sorted {
		if o.Status != inspect.StatusOK {
			continue
		}
		ref := report.NewServerRef(o.Server)
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
	}
	return jobs
}

// runLLMJobs runs the jobs with llmWorkers requests at the same time, and
// returns one answer for each job, in the order of jobs. A job that did not
// run has the kind answerNotRun.
//
// The first answer that stops the step (see answerKind.stepFails) is the
// failure: it stops the requests that run (it cancels their context) and no
// new job starts. When ctx ends, no new job starts either; the caller checks
// ctx.
func runLLMJobs(ctx context.Context, jobs []llmJob, cl toolClassifier) ([]llmAnswer, *llmFailure) {
	answers := make([]llmAnswer, len(jobs))
	runCtx, cancel := context.WithCancel(ctx)
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
			// A failure or a signal: start no new job. A slot that this
			// iteration took stays taken, which does no harm.
			break
		}
		wg.Go(func() {
			defer func() { <-sem }()
			v, err := cl.Classify(runCtx, job.in)
			kind := sortAnswer(err)
			// Each goroutine writes only its own element, so this needs no
			// lock.
			answers[i] = newLLMAnswer(kind, v)
			if !kind.stepFails() {
				return
			}
			f := &llmFailure{kind: kind}
			if kind == answerProviderFailed {
				// Only a provider error is kept: its text is fixed.
				f.err = err
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
	return answers, failure
}

// llmRow returns the finding row that the answer a of job gives, and true. It
// returns false when a gives no row: a verdict with risk none (and no cut
// text), or a job without an answer (see answerKind.answered).
//
// A verdict whose risk or category is not valid counts as an answer that
// cannot be used, so it fails closed. parseVerdict never returns one, but a
// classifier in a test can. A cut tool text (llm.Verdict.Truncated) gets the
// floor row (see truncatedRow) when the model rated it none or low, or gave
// no usable answer. So a cut tool always gets an llm.RuleID row of at least
// medium, and never an llm.RuleIDInvalid row.
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
	default:
		// answerNotRun, answerStopped, answerProviderFailed and
		// answerInternalFailed: the tool got no answer.
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
	if truncated {
		return truncatedRow(row)
	}
	row.RuleID = llm.RuleIDInvalid
	row.Title = llm.InvalidTitle
	row.Severity = string(rules.SeverityMedium)
	row.Risk = llm.InvalidText
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
// for a failed request and one line for the tools over the cap. All the text
// is fixed, apart from numbers and the reason of a provider failure (see
// llmFailureText).
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
// the LLM step: "the LLM provider failed (<reason>)" for a provider failure,
// else llmInternalText. A nil f with skipped tools cannot happen; it gives
// llmInternalText too, so it never blames the provider.
func llmFailureLine(f *llmFailure) string {
	if f == nil || f.kind != answerProviderFailed || f.err == nil {
		return llmInternalText
	}
	return fmt.Sprintf("the LLM provider failed (%s)", llmFailureText(f.err))
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
