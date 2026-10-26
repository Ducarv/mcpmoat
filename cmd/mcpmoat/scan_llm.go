package main

import (
	"cmp"
	"context"
	"errors"
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

// buildClassifier gets the classifier for cfg from c.newClassifier. This is
// the only place that calls it, and runScan calls it only with --llm. On an
// error it prints one line on stderr and returns false. The errors of llm.New
// have fixed text; termsafe.Quote still escapes the text, because a test can
// set any factory.
func (c *cli) buildClassifier(cfg llm.Config) (toolClassifier, bool) {
	if c.newClassifier == nil {
		fprintf(c.stderr, "mcpmoat scan: internal error: no LLM client\n")
		return nil, false
	}
	cl, err := c.newClassifier(cfg)
	if err != nil {
		c.cmdErr("scan", "cannot set up the LLM client", err)
		return nil, false
	}
	if cl == nil {
		fprintf(c.stderr, "mcpmoat scan: internal error: no LLM client\n")
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

// llmSetup is the checked LLM config of one scan.
type llmSetup struct {
	// cfg is the resolved config, with the defaults filled in and the API key
	// from the environment. cfg.APIKey prints as a mask.
	cfg llm.Config
	// host is the host of cfg.BaseURL, with the port if it has one. The
	// warning names it.
	host string
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
		for _, given := range []struct{ name, value string }{
			{"--llm-provider", f.provider},
			{"--llm-model", f.model},
			{"--llm-base-url", f.baseURL},
		} {
			if given.value != "" {
				c.usageError("scan", "%s needs --llm", given.name)
				return nil, false
			}
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
	// Resolve checked the URL with ValidateBaseURL, so it parses and has a
	// host. The error text of url.Parse quotes the URL, so it is not printed.
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		c.usageError("scan", "--llm-base-url: %v", llm.ErrInvalidBaseURL)
		return nil, false
	}
	return &llmSetup{cfg: cfg, host: u.Host}, true
}

// llmJob is one tool to classify.
type llmJob struct {
	// index is the index of the server in the servers of the scan
	// (inspect.Outcome.Index).
	index int
	// server is the server name from the config file. It is untrusted.
	server string
	// ref is the server of the finding row.
	ref report.ServerRef
	// in is what the classifier gets: the tool name and description only.
	in llm.Input
}

// llmAnswer is the result of one job.
type llmAnswer struct {
	done    bool // true when Classify returned
	verdict llm.Verdict
	err     error
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
	// failure is the first error of the provider. It is nil when no request
	// failed. Its text is fixed (see llmFailureText).
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
// high gives one llm.RuleID row with that severity (never critical). Output
// that is not a valid verdict gives one llm.RuleIDInvalid row with severity
// medium. Every row is a report.SourceLLM row with fixed texts from package
// llm: no model output reaches it. The ignore list drops rows like the
// findings of the config rules (see scanIgnores).
//
// The first request that fails stops the step: the requests that run end and
// no new one starts. The result then holds the error (see
// llmResult.failure), and the tools without a verdict get no row.
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
		a := answers[i]
		row, ok, counted := llmRow(job, a)
		if !counted {
			res.skipped++
			continue
		}
		if !ok {
			continue // risk none: no finding
		}
		key := rules.FindingKey{RuleID: row.RuleID, Server: job.server, Tool: job.in.ToolName}
		// The LLM rule IDs are not pin rules, so the entries of
		// .mcpmoat-ignore and of --ignore both apply.
		if drop, _ := ignore.ignored(key); drop {
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
				index:  o.Index,
				server: o.Server.Name,
				ref:    ref,
				in:     llm.Input{ToolName: t.Name, Description: t.Description},
			})
		}
	}
	return jobs
}

// runLLMJobs runs the jobs with llmWorkers requests at the same time, and
// returns one answer for each job, in the order of jobs. A job that did not
// run has done set to false.
//
// The first error that is not a stop of the context is the failure: it stops
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
			// Each goroutine writes only its own element, so this needs no
			// lock.
			answers[i] = llmAnswer{done: true, verdict: v, err: err}
			if err == nil || errors.Is(err, llm.ErrInvalidOutput) || stoppedByContext(err) {
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

// stoppedByContext reports whether err means that the context of the request
// ended: a signal, or the cancel after the first failure.
func stoppedByContext(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// llmRow returns the finding row of one answer. ok is false when the answer
// gives no row (risk none). counted is false when the tool got no verdict:
// the job did not run, it was stopped, or its request failed.
func llmRow(job llmJob, a llmAnswer) (row report.FindingRow, ok, counted bool) {
	row = report.FindingRow{
		ServerRef: job.ref,
		Source:    report.SourceLLM,
		Field:     rules.FieldTool,
		Key:       job.in.ToolName,
	}
	switch {
	case !a.done:
		return report.FindingRow{}, false, false
	case a.err == nil:
		severity, hasRisk := a.verdict.Risk.Severity()
		if !hasRisk {
			return report.FindingRow{}, false, true
		}
		row.RuleID = llm.RuleID
		row.Title = llm.Title
		row.Severity = severity
		row.Risk = a.verdict.Category.Text()
		row.Remediation = llm.Remediation
		// The category is one of the fixed llm.Category values: parseVerdict
		// refuses any other.
		row.Related = string(a.verdict.Category)
		return row, true, true
	case errors.Is(a.err, llm.ErrInvalidOutput):
		row.RuleID = llm.RuleIDInvalid
		row.Title = llm.InvalidTitle
		row.Severity = string(rules.SeverityMedium)
		row.Risk = llm.InvalidText
		row.Remediation = llm.InvalidRemediation
		return row, true, true
	default:
		return report.FindingRow{}, false, false
	}
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
