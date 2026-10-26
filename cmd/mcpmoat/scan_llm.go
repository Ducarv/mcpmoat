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
	llmWorkers = 4
)

// noLLMClientText is the text after the prefix of the error line that scan
// prints when it has no LLM client. This is a bug in mcpmoat, not a user
// error. It is fixed text.
const noLLMClientText = "internal error: no LLM client"

// noToolNameKey is the Key of an LLM finding row for a tool with an empty
// name. A hostile server can list such a tool. The report writers treat a
// row with an empty Key as a row about the whole server, so the row gets
// this fixed text instead. The request to the provider still has the real
// (empty) name.
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

// addLLMFlags adds the four LLM flags of scan (FR-17) to fs. They store
// their values in f. --llm is off by default. The other three refuse an
// empty value (see pathFlag), so an empty value in f means that the flag was
// not given. checkLLMFlags checks them all.
//
// The base URL can hold a user:password, so the errors of its flag never
// hold the value. addLLMFlags returns that flag: when Parse fails, the
// caller prints its problem in place of the Parse error (see secretPathFlag).
func addLLMFlags(fs *flag.FlagSet, f *llmFlags) *secretFlag {
	fs.BoolVar(&f.on, "llm", false, "")
	pathFlag(fs, "llm-provider", "a provider name", &f.provider)
	pathFlag(fs, "llm-model", "a model name", &f.model)
	return secretPathFlag(fs, "llm-base-url", "a URL", &f.baseURL)
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
// method (*llm.Client has one). A fake from a test usually has none.
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
		{"--llm-provider", f.provider},
		{"--llm-model", f.model},
		{"--llm-base-url", f.baseURL},
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
	if err := llm.ValidKey(key); err != nil {
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
	// in is what the classifier gets: the tool name and description only.
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
	// answerUnusable means that the answer for this tool cannot be used: the
	// model output is not a valid verdict, or another error about this tool
	// or the client. The tool gets an llm.RuleIDInvalid row.
	answerUnusable
	// answerStopped means that the context of the request ended: a signal,
	// or the cancel after the first provider failure.
	answerStopped
	// answerProviderFailed means that the request to the provider failed
	// (llm.ErrProvider). It stops the LLM step.
	answerProviderFailed
)

// sortAnswer returns the kind of the result of Classify with the error err.
//
// Only an llm.ErrProvider error is a provider failure. Any other error (for
// example a request that is too large, a nil client or an encode error) is
// about one tool or about the client, not about the provider. Such an error
// must not stop the other tools or be reported as a failed provider, so the
// tool gets an llm.RuleIDInvalid row (its answer could not be used), like
// invalid model output.
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
		return answerUnusable
	}
}

// llmAnswer is the result of one job.
type llmAnswer struct {
	kind    answerKind
	verdict llm.Verdict // set only for answerVerdict
}

// llmResult is the result of the LLM step.
type llmResult struct {
	// rows are the LLM findings that the ignore list does not drop, in the
	// order of the servers (inspect.Outcome.Index), then of the tools.
	rows []report.FindingRow
	// ignored counts the LLM findings that the ignore list dropped, by rule
	// ID. It is nil when the list dropped nothing.
	ignored map[string]int
	// counts holds the number of rows of each server, by the index of the
	// server in the servers of the scan (see addLLMCounts).
	counts map[int]int
	// overCap is the number of tools after the first maxLLMTools. They were
	// not sent.
	overCap int
	// failure is the first error of the provider (llm.ErrProvider). It is
	// nil when no request to the provider failed. Its text is fixed (see
	// llmFailureText).
	failure error
	// skipped is the number of tools under the cap that got no verdict: the
	// tool whose request failed, and the tools that were not sent after it.
	skipped int
}

// incomplete reports whether the LLM step missed tools. scan then exits
// with 2, and the JSON report has complete set to false.
func (r llmResult) incomplete() bool {
	return r.overCap > 0 || r.failure != nil || r.skipped > 0
}

// llmStep runs the LLM step of scan (see classifyTools) on the tools of the
// inspected servers in outcomes, and prints its problems on stderr (see
// printLLMProblems). It returns an empty result and true when cl is nil
// (no --llm) or when no server was inspected: then it sends nothing.
//
// It returns false when the process got a signal during the step. It has
// written interruptedText then (see interrupted), and scan must print no
// report and save no pins.
func (c *cli) llmStep(ctx context.Context, cl toolClassifier, outcomes []inspect.Outcome, ignore *scanIgnores) (llmResult, bool) {
	if cl == nil || len(outcomes) == 0 {
		return llmResult{}, true
	}
	lr, err := classifyTools(ctx, outcomes, cl, ignore)
	// classifyTools fails only when ctx ended, so interrupted is true then
	// and writes the line. The check of err is only a guard.
	if c.interrupted(ctx, "scan") || err != nil {
		return llmResult{}, false
	}
	c.printLLMProblems(lr)
	return lr, true
}

// classifyTools sends the name and the description of each tool of each
// inspected server (inspect.StatusOK) to cl, and returns the LLM findings.
// It sends nothing else of the tool and nothing of the server.
//
// The tools go in the order of the servers (inspect.Outcome.Index), then in
// the order that the server lists them. Only the first maxLLMTools tools are
// sent. llmWorkers requests run at the same time. The rows keep the order of
// the tools, whatever the order in which the requests end.
//
// A verdict with risk none gives no row. A verdict with risk low, medium or
// high gives one llm.RuleID row with that severity (never critical). An
// answer that cannot be used (see answerUnusable) gives one
// llm.RuleIDInvalid row with severity medium. Every row is a
// report.SourceLLM row with fixed texts from package llm: no model output
// reaches it. The ignore list drops rows like the findings of the config
// rules (see scanIgnores).
//
// The first request to the provider that fails (see sortAnswer) stops the
// step: the requests that run end and no new one starts. The result then
// holds the error (see llmResult.failure), and the tools without a verdict
// get no row.
//
// The error is not nil only when ctx ended (the process got a signal). The
// caller then handles it like a signal during the inspection.
func classifyTools(ctx context.Context, outcomes []inspect.Outcome, cl toolClassifier, ignore *scanIgnores) (llmResult, error) {
	var res llmResult
	jobs := llmJobs(outcomes)
	if len(jobs) > maxLLMTools {
		res.overCap = len(jobs) - maxLLMTools
		jobs = jobs[:maxLLMTools]
	}

	answers, failure := runLLMJobs(ctx, jobs, cl)
	if err := ctx.Err(); err != nil {
		return llmResult{}, err
	}
	res.failure = failure

	for i, job := range jobs {
		outcome, row := llmRow(job, answers[i])
		switch outcome {
		case llmNoVerdict:
			res.skipped++
			continue
		case llmNoRisk:
			continue // risk none: no finding
		}
		key := rules.FindingKey{RuleID: row.RuleID, Server: job.ref.Name, Tool: job.in.ToolName}
		// The LLM rule IDs are not pin rules, so the entries of
		// .mcpmoat-ignore and of --ignore both apply, as for the config
		// rules.
		if ignore.all.Ignored(key) {
			res.ignored = addIgnored(res.ignored, row.RuleID, 1)
			continue
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
				in:    llm.Input{ToolName: t.Name, Description: t.Description},
			})
		}
	}
	return jobs
}

// runLLMJobs runs the jobs with llmWorkers requests at the same time, and
// returns one answer for each job, in the order of jobs. A job that did not
// run has the kind answerNotRun.
//
// The first provider failure (answerProviderFailed) is the failure: it stops
// the requests that run (it cancels their context) and no new job starts.
// When ctx ends, no new job starts either; the caller checks ctx.
func runLLMJobs(ctx context.Context, jobs []llmJob, cl toolClassifier) ([]llmAnswer, error) {
	answers := make([]llmAnswer, len(jobs))
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu      sync.Mutex
		failure error
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
			answers[i] = llmAnswer{kind: kind, verdict: v}
			if kind != answerProviderFailed {
				return
			}
			mu.Lock()
			if failure == nil {
				failure = err
				cancel()
			}
			mu.Unlock()
		})
	}
	wg.Wait()
	return answers, failure
}

// llmOutcome is what one answer gives to the report.
type llmOutcome int

const (
	// llmNoVerdict means that the tool got no verdict: the job did not run,
	// it was stopped, or the request to the provider failed. It gives no row.
	llmNoVerdict llmOutcome = iota
	// llmNoRisk means a verdict with risk none. It gives no row.
	llmNoRisk
	// llmFinding means one finding row.
	llmFinding
)

// llmRow returns what the answer a of job gives. The row is set only for
// llmFinding.
func llmRow(job llmJob, a llmAnswer) (llmOutcome, report.FindingRow) {
	key := job.in.ToolName
	if key == "" {
		key = noToolNameKey
	}
	row := report.FindingRow{
		ServerRef: job.ref,
		Source:    report.SourceLLM,
		Field:     rules.FieldTool,
		Key:       key,
	}
	switch a.kind {
	case answerVerdict:
		severity, hasRisk := a.verdict.Risk.Severity()
		if !hasRisk {
			return llmNoRisk, report.FindingRow{}
		}
		row.RuleID = llm.RuleID
		row.Title = llm.Title
		row.Severity = severity
		row.Risk = a.verdict.Category.Text()
		row.Remediation = llm.Remediation
		// The category is one of the fixed llm.Category values: parseVerdict
		// refuses any other.
		row.Related = string(a.verdict.Category)
		return llmFinding, row
	case answerUnusable:
		row.RuleID = llm.RuleIDInvalid
		row.Title = llm.InvalidTitle
		row.Severity = string(rules.SeverityMedium)
		row.Risk = llm.InvalidText
		row.Remediation = llm.InvalidRemediation
		return llmFinding, row
	case answerNotRun, answerStopped, answerProviderFailed:
		return llmNoVerdict, report.FindingRow{}
	}
	// Not reached: the cases above name every answerKind.
	return llmNoVerdict, report.FindingRow{}
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
// is fixed, apart from numbers.
func (c *cli) printLLMProblems(r llmResult) {
	if r.failure != nil || r.skipped > 0 {
		c.cmdPrintf("scan", "the LLM provider failed (%s); %d %s not classified",
			llmFailureText(r.failure), r.skipped, plural(r.skipped, "tool was", "tools were"))
	}
	if r.overCap > 0 {
		c.cmdPrintf("scan", "--llm classifies at most %d tools in one scan; %d %s not classified",
			maxLLMTools, r.overCap, plural(r.overCap, "tool was", "tools were"))
	}
}

// llmFailureText returns the reason of a failed request: "HTTP <code>" for a
// status code, else the error text. The errors of package llm have fixed
// text. termsafe.Quote still escapes the text, because a classifier in a test
// can return any error.
func llmFailureText(err error) string {
	if err == nil {
		return "no answer"
	}
	var status *llm.StatusError
	if errors.As(err, &status) {
		return fmt.Sprintf("HTTP %d", status.Code)
	}
	return termsafe.Quote(err.Error())
}
