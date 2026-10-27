package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// runScan implements "mcpmoat scan": it reads the client configs, runs the
// built-in config rules (T4 and T5) on every server and, unless --no-connect
// is given, inspects the servers, checks their tools against pins.json and
// applies the description and schema rules (T1 and T3, built-in and from
// --rules) to their tools (see scan_tools.go). --fail-on sets the lowest
// severity that gives exit code 1. Like --timeout, it is checked in both
// modes. With --llm (FR-17), it also asks an LLM to rate the description of
// each tool (see scan_llm.go).
//
// docs/ARCHITECTURE.md describes the data flow. The usage text (scanUsage and
// usage in cli.go) lists the flags. docs/exit-codes.md is the exit-code
// contract (FR-16), and the usage text summarises it.
func (c *cli) runScan(opts options, args []string) int {
	a, code, ok := c.parseScanArgs(args)
	if !ok {
		return code
	}

	// Check the LLM flags and the API key before scan reads a config file
	// (see setupLLM). Without --llm, classifier is nil: no key is read and no
	// client is built.
	classifier, ok := c.setupLLM(a.llmOpts, a.noConnect)
	if !ok {
		return exitError
	}
	defer closeClassifier(classifier)

	// Load and check the rules in both modes, so a bad rule file gives exit
	// code 2 also with --no-connect. The set gives the severity and the texts
	// of the findings. The analyzer applies the description and schema rules
	// to the tools when scan connects to the servers.
	loaded, ok := c.loadRules(a.rulesDir)
	if !ok {
		return exitError
	}

	setup, ok := c.buildScanSetup(opts, a, loaded, classifier)
	if !ok {
		return exitError
	}

	// The context ends when the process gets SIGINT, SIGTERM or SIGHUP (see
	// main). scan starts stdio servers in their own session, so the terminal
	// does not reach them: only this context stops them.
	return c.scanConfigs(c.ctxOrBackground(), a.configPath, a.ignoreIDs, setup)
}

// scanArgs holds the checked flags of "scan".
type scanArgs struct {
	noConnect bool // --no-connect: static analysis only
	noColor   bool // --no-color after "scan"
	jsonOut   bool // --json
	// configPath is the --config value, or empty for auto-discovery.
	configPath string
	// rulesDir is the --rules folder, or empty.
	rulesDir string
	// ignoreIDs holds the --ignore rule IDs, in the order given. Each one is a
	// valid rule ID.
	ignoreIDs []string
	// failOn is the --fail-on value, or high when the flag is not given.
	failOn rules.Severity
	// llmOpts holds the LLM flags (FR-17), see addLLMFlags.
	llmOpts llmFlags
	// connOpts are the checked --timeout and --concurrency values. They are
	// checked in both modes, also when --no-connect starts no server.
	connOpts inspect.Options
}

// parseScanArgs parses and checks the flags of "scan". When ok is false, it has
// printed the message (or the help text) and code is the exit code.
func (c *cli) parseScanArgs(args []string) (a scanArgs, code int, ok bool) {
	fs := flag.NewFlagSet("mcpmoat scan", flag.ContinueOnError)
	// We print our own messages and scanUsage prints the help, so the flag
	// package prints nothing and the flags have no usage text.
	fs.SetOutput(io.Discard)
	fs.BoolVar(&a.noConnect, "no-connect", false, "")
	fs.BoolVar(&a.noColor, "no-color", false, "")
	fs.BoolVar(&a.jsonOut, "json", false, "")
	timeout := fs.Duration("timeout", inspect.DefaultTimeout, "")
	concurrency := fs.Int("concurrency", inspect.DefaultConcurrency, "")

	// onceStringFlag refuses an empty value, so a result that is not ""
	// means the flag was given.
	onceStringFlag(fs, "config", "a file name", &a.configPath)
	onceStringFlag(fs, "rules", "a folder name", &a.rulesDir)

	// fs.Func calls the function once for each --ignore, so the user can
	// give the flag more than once. ValidRuleID also refuses an empty value
	// and a flag name such as "--no-connect" that the flag package took as
	// the value: a rule ID starts with a letter. The flag error already holds
	// the value, so the message does not repeat it.
	fs.Func("ignore", "", func(value string) error {
		if !rules.ValidRuleID(value) {
			return errors.New("--ignore needs a rule ID")
		}
		a.ignoreIDs = append(a.ignoreIDs, value)
		return nil
	})

	// severityFlag refuses an empty value, so an empty result means the flag
	// was not given: then the default is high.
	severityFlag(fs, "fail-on", &a.failOn)

	// The LLM flags (FR-17), see addLLMFlags.
	baseURLFlag := addLLMFlags(fs, &a.llmOpts)

	// The error of another flag, or the list of unexpected arguments, can
	// hold a base URL value too: for example "--timeout --llm-base-url=URL"
	// and "--timeout=--llm-base-url=URL" make the flag package quote the
	// whole value. hider.errorText removes every base URL value of args (see
	// newBaseURLHider) and the user info of any URL from the flag error, and
	// rejectArgs does the same with it for the list, as for the other
	// commands (see argscrub.go).
	hider := newBaseURLHider(args)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			scanUsage(c.stdout)
			return scanArgs{}, exitOK, false
		}
		// The flag package puts the value into err. Print the problem that
		// the flag recorded instead: its text holds no value.
		if baseURLFlag.problem != nil {
			return scanArgs{}, c.usageError("scan", "%v", baseURLFlag.problem), false
		}
		// The flag error holds untrusted argv inside its own text, so
		// termsafe.Quote escapes the whole message, and quotes it only when
		// it holds an unsafe rune. See dispatch in cli.go for why this
		// differs from quoteArg.
		return scanArgs{}, c.usageError("scan", "%s", termsafe.Quote(hider.errorText(err.Error()))), false
	}
	if c.rejectArgs("scan", hider, fs.Args()) {
		return scanArgs{}, exitError, false
	}
	if a.failOn == "" {
		a.failOn = rules.SeverityHigh
	}

	// Check the values in both modes, so a bad value is a usage error even
	// when --no-connect starts no server. The options go to inspect.Run.
	connOpts, err := connectOptions(*timeout, *concurrency)
	if err != nil {
		return scanArgs{}, c.usageError("scan", "%v", err), false
	}
	a.connOpts = connOpts
	return a, exitOK, true
}

// buildScanSetup prints the notices on stderr and builds the scanSetup from
// the checked flags a, the loaded rules and the classifier (nil without
// --llm). When ok is false, it has printed the message and scan must exit with
// code 2.
func (c *cli) buildScanSetup(opts options, a scanArgs, loaded loadedRules, classifier toolClassifier) (setup scanSetup, ok bool) {
	var connect *inspect.Options // nil with --no-connect
	if !a.noConnect {
		connect = &a.connOpts
	}
	// Scan does not apply a rule from --rules with the target config, and it
	// applies no description or schema rule with --no-connect. Say so, or such
	// a rule would pass in silence. Each notice is fixed text.
	for _, n := range loaded.external.notices(a.noConnect) {
		fprintf(c.stderr, "%s\n", n)
	}
	// No built-in rule is critical, so --fail-on critical gives exit code 0
	// for every built-in finding. Say so, or a CI log shows no sign that the
	// gate cannot fail.
	if a.failOn == rules.SeverityCritical {
		fprintf(c.stderr, "%s\n", failOnCriticalNotice)
	}

	// The typosquat check is built once and used for every server. An error
	// means a bug in mcpmoat (the list is part of the binary), so the message
	// is fixed text.
	typo, err := rules.NewBuiltinTyposquat()
	if err != nil {
		fprintf(c.stderr, "mcpmoat scan: internal error: built-in typosquat list is invalid\n")
		return scanSetup{}, false
	}
	// Colour is on only when stdout is a terminal, --no-color is not set and
	// NO_COLOR is empty (FR-14). opts.noColor holds the combined result of the
	// global flag (before "scan") and the environment variable. The scan flag
	// --no-color (after "scan") is read here, so both positions work.
	style := report.Style{Color: !opts.noColor && !a.noColor && c.stdoutIsTTY}
	return scanSetup{
		checks:      configChecks{set: loaded.set, typo: typo},
		analyzer:    loaded.analyzer,
		toolBudget:  c.toolBudgetOrDefault(),
		maxToolRows: c.maxToolRowsOrDefault(),
		connect:     connect,
		style:       style,
		failOn:      a.failOn,
		jsonOut:     a.jsonOut,
		classifier:  classifier,
	}, true
}

// scanSetup holds what scan has built before it reads the config files.
type scanSetup struct {
	// checks are the config rules (T4 and T5). Its rule set also gives the
	// severity and the texts of the tool rule findings (see toolRulesStep).
	checks configChecks
	// analyzer applies the description and schema rules (T1 and T3) to the
	// tools of the inspected servers (see toolRulesStep).
	analyzer *rules.Analyzer
	// toolBudget is the time that the tool rule step can use for the tools
	// of one server (toolRulesBudget in a real scan).
	toolBudget time.Duration
	// maxToolRows is the largest number of tool rows that the tool rule step
	// keeps for one server (maxToolRowsPerServer in a real scan).
	maxToolRows int
	// connect is nil with --no-connect. Otherwise it holds the options for
	// inspect.Run, and scan inspects the servers, checks their pins and
	// applies the tool rules to their tools.
	connect *inspect.Options
	// style tells the report writers whether to use colour.
	style report.Style
	// failOn is the --fail-on value: a finding at or above it gives exit
	// code 1 (see scanExitCode).
	failOn rules.Severity
	// jsonOut is true with --json: scan writes one JSON document on stdout
	// and none of the terminal tables.
	jsonOut bool
	// classifier rates the tools with an LLM (--llm, see llmStep). It
	// is nil without --llm, and then scan runs no LLM code.
	classifier toolClassifier
}

// toolBudgetOrDefault returns c.toolBudget, or toolRulesBudget when the field
// is zero (a real scan).
func (c *cli) toolBudgetOrDefault() time.Duration {
	if c.toolBudget == 0 {
		return toolRulesBudget
	}
	return c.toolBudget
}

// maxToolRowsOrDefault returns c.maxToolRows, or maxToolRowsPerServer when the
// field is zero (or negative).
func (c *cli) maxToolRowsOrDefault() int {
	if c.maxToolRows > 0 {
		return c.maxToolRows
	}
	return maxToolRowsPerServer
}

// failOnCriticalNotice is the line that buildScanSetup prints on stderr for
// --fail-on critical. TestNoBuiltinCriticalSeverity keeps it true.
const failOnCriticalNotice = "mcpmoat scan: note: no built-in rule is critical yet, so with --fail-on critical no built-in finding gives exit code 1"

// connectOptions builds the inspect options from the --timeout and
// --concurrency flags. inspect.Options.Validate holds the rules. Its messages
// name no flag and repeat the value, so connectOptions maps each error to a
// message that names the flag and does not repeat the value.
func connectOptions(timeout time.Duration, concurrency int) (inspect.Options, error) {
	opts := inspect.Options{Timeout: timeout, Concurrency: concurrency}
	err := opts.Validate()
	switch {
	case err == nil:
		return opts, nil
	case errors.Is(err, inspect.ErrInvalidTimeout):
		return inspect.Options{}, errors.New("--timeout must be greater than 0")
	case errors.Is(err, inspect.ErrInvalidConcurrency):
		return inspect.Options{}, errors.New("--concurrency must be at least 1")
	default:
		// A rule that Validate gets later. Its text holds only our own words
		// and numbers.
		return inspect.Options{}, err
	}
}

// onceStringFlag adds a flag to fs that takes one non-empty value and stores
// it in *dest. The flag can be given once. An empty value, or a value that
// looks like another flag (see isFlagOf), is refused. what names the missing
// value in the error message, for example "a file name".
func onceStringFlag(fs *flag.FlagSet, name, what string, dest *string) {
	fs.Func(name, "", func(value string) error {
		return setOnce(fs, name, what, dest, value)
	})
}

// setOnce does the checks of onceStringFlag and stores value in *dest. The
// error text holds only the flag name and what, never the value.
func setOnce(fs *flag.FlagSet, name, what string, dest *string, value string) error {
	if *dest != "" {
		return fmt.Errorf("--%s given more than once", name)
	}
	if value == "" || isFlagOf(fs, value) {
		return fmt.Errorf("--%s needs %s", name, what)
	}
	*dest = value
	return nil
}

// secretFlag is a flag.Value for a onceStringFlag whose value can hold a
// secret, for example a URL with a user:password. On a Set error, the flag
// package returns `invalid value "<value>" for flag ...`, so that error must
// not be printed. Set records the problem in problem, and the caller prints
// problem when Parse fails. Set still returns an error, so Parse stops at the
// same argument as for the other flags.
type secretFlag struct {
	fs      *flag.FlagSet
	name    string
	what    string
	dest    *string
	problem error
}

// secretStringFlag adds a flag to fs like onceStringFlag, but returns the flag
// so that the caller can print its problem in place of the Parse error.
func secretStringFlag(fs *flag.FlagSet, name, what string, dest *string) *secretFlag {
	f := &secretFlag{fs: fs, name: name, what: what, dest: dest}
	fs.Var(f, name, "")
	return f
}

// String returns "" so that no output of the flag package shows the value.
// The flag package can call it on a zero secretFlag.
func (f *secretFlag) String() string { return "" }

// Set checks value like onceStringFlag and stores it.
func (f *secretFlag) Set(value string) error {
	if err := setOnce(f.fs, f.name, f.what, f.dest, value); err != nil {
		f.problem = err
		return err
	}
	return nil
}

// severityFlag adds a flag to fs that takes one severity word and stores it in
// *dest. The flag can be given once. Valid refuses an empty value, another
// case ("HIGH") and a flag name that the flag package took as the value. The
// flag error already holds the value, so the message does not repeat it.
func severityFlag(fs *flag.FlagSet, name string, dest *rules.Severity) {
	fs.Func(name, "", func(value string) error {
		if *dest != "" {
			return fmt.Errorf("--%s given more than once", name)
		}
		if !rules.Severity(value).Valid() {
			return fmt.Errorf("--%s needs low, medium, high or critical", name)
		}
		*dest = rules.Severity(value)
		return nil
	})
}

// isFlagOf reports whether value looks like a flag of fs, in any form that
// the flag package accepts: "-name", "--name", "-name=x" or "--name=x". -h and
// -help count too, because the flag package treats them as a help request.
// The flag package takes the next argument as the value of --config and
// --rules, so "scan --config --no-connect" would use "--no-connect" as a file
// name. We reject that case. The names come from fs, so a new scan flag is
// covered without a second edit. A real file name that starts with "-" can be
// given as ./-name.
func isFlagOf(fs *flag.FlagSet, value string) bool {
	name, ok := strings.CutPrefix(value, "-")
	if !ok {
		return false
	}
	name = strings.TrimPrefix(name, "-")
	name, _, _ = strings.Cut(name, "=")
	return fs.Lookup(name) != nil || name == "h" || name == "help"
}

// scanConfigs loads the config files (see loadConfigs), builds the ignore
// list and runs the scan (see reportScan). configPath is the --config value, or
// empty for auto-discovery.
//
// The working directory is where .mcpmoat-ignore is. With --config, an unknown
// working directory is a warning, and scan reads no ignore file.
func (c *cli) scanConfigs(ctx context.Context, configPath string, ignoreIDs []string, setup scanSetup) int {
	res, wd, ok := c.loadConfigs(ctx, "scan", configPath)
	if !ok {
		return exitError
	}
	if wd == "" {
		c.scanWarnf("cannot read the working directory; %s is not read", rules.IgnoreFileName)
	}
	ignore := c.loadIgnore(wd, ignoreIDs)

	// A file that failed to load and gave no servers is a plain error. The
	// "No MCP servers found." line would be wrong and misleading here, so we
	// skip the table and print only the errors.
	if configPath != "" && loadFailed(res) {
		c.printFileErrors("scan", res.Errors)
		return exitError
	}
	return c.reportScan(ctx, res, configPath, setup, ignore)
}

// scanWarnf prints one scan warning line on stderr.
func (c *cli) scanWarnf(format string, a ...any) {
	c.warnf("scan", format, a...)
}

// loadIgnore builds the ignore lists (see scanIgnores). The list for the
// config rules holds the entries of .mcpmoat-ignore in the directory wd, then
// one entry for each --ignore ID in ids. The list for the pin rules, the LLM
// rules, the budget rule (MOAT-T1-023) and the tool findings cap rule
// (MOAT-T1-024) holds only the --ignore entries, because the file is untrusted
// (see scanIgnores). ids holds only valid rule IDs: the --ignore flag checks
// them. An empty wd means that the working directory is not known, so
// loadIgnore reads no file.
//
// Every problem with the file is a warning on stderr, not an error: the scan
// goes on. A file that loadIgnore cannot read gives no entries. The warnings
// and the read error never hold file content. The error holds the path, so
// termsafe.Quote escapes it. When the file gives one or more entries,
// loadIgnore prints their number, because the file is untrusted and can hide
// findings. The --ignore IDs come from the user, so they give no notice.
//
// An entry of the file for a pin rule (MOAT-T2-*), an LLM rule
// (MOAT-LLM-001 or MOAT-LLM-002), the budget rule (MOAT-T1-023) or the tool
// findings cap rule (MOAT-T1-024) is not applied (see fileCannotIgnore): scan
// warns when such an entry matches a finding (see pinOutcomes, toolRulesStep
// and llmStep).
func (c *cli) loadIgnore(wd string, ids []string) *scanIgnores {
	var ign scanIgnores
	if wd != "" {
		fromFile, warnings, err := rules.ReadIgnoreFile(wd)
		if err != nil {
			// The error text already starts with "read ignore file <path>",
			// so the line does not name the file again.
			c.scanWarnf("%s; mcpmoat uses no entries from it", termsafe.Quote(err.Error()))
		}
		for _, w := range warnings {
			c.scanWarnf("%s", w)
		}
		if n := fromFile.Len(); n > 0 {
			c.cmdPrintf("scan", "using %d %s from %s", n, plural(n, "entry", "entries"), rules.IgnoreFileName)
		}
		ign.all = fromFile
		ign.fileEntries = fromFile.Len()
	}
	for _, id := range ids {
		entry := rules.IgnoreEntry{RuleID: id}
		ign.all.Add(entry)
		ign.flags.Add(entry)
	}
	return &ign
}

// configErrorHint is the line that reportScan prints after the file
// problems, when it printed the report (the table or the --json document). It
// is fixed text: it holds no path and no config text.
const configErrorHint = "mcpmoat scan: a config file has a problem; " +
	"the report can miss servers that the client loads"

// reportScan runs the steps of the scan (see runScanSteps), writes the report
// (see writeScanOutput) and returns the exit code. res holds the servers, setup
// the settings of the scan, ignore the ignore list and configPath the --config
// value, or empty.
//
// The report goes on stdout, the file problems and warnings on stderr. After
// the report, reportScan prints one line on stderr with the rule IDs and counts
// of the findings that the ignore list dropped (see printIgnored), and saves
// the new pins (see savePinned). A save error never hides the report. The
// "pinned N tools" notices come after a successful save.
//
// The exit code comes from scanExitCode (docs/exit-codes.md is the contract,
// and the usage text in cli.go summarises it). A config file problem, a pin
// error or an incomplete LLM step gives exit code 2, also when there are
// findings at or above setup.failOn: the report is already printed, so the
// user still sees them. A signal during the steps, or a failed write of the
// report, returns exit code 2 without a full report.
func (c *cli) reportScan(ctx context.Context, res discover.Result, configPath string, setup scanSetup, ignore *scanIgnores) int {
	steps, ok := c.runScanSteps(ctx, res, setup, ignore)
	if !ok {
		return exitError
	}
	pinFailed := steps.pinFailed

	configProblem := len(res.Errors) > 0
	if writeErr := c.writeScanOutput(res, steps, setup, ignore.fileEntries, configPath, configProblem); writeErr != nil {
		c.cmdPrintf("scan", "cannot write output")
		// stderr can still work. The file problems are the reason for a
		// failed scan, so the user must still see them. New pins are not
		// saved: the user did not see the report.
		c.printFileErrors("scan", res.Errors)
		return exitError
	}
	c.printIgnored(steps.ignored)

	if !c.savePinned(ctx, steps.pr) {
		pinFailed = true
	}

	if configProblem {
		// Print the problems in the order of the result, then the hint.
		c.printFileErrors("scan", res.Errors)
		fprintf(c.stderr, "%s\n", configErrorHint)
	}
	return scanExitCode(configProblem || pinFailed || steps.llmIncomplete, steps.rows, setup.failOn)
}

// scanStepsResult holds what the steps of a scan produce (see runScanSteps).
// reportScan writes the report from it.
type scanStepsResult struct {
	// rows holds the findings of all steps: the config rules, the pins, the
	// tool rules and, with --llm, the LLM step.
	rows []report.FindingRow
	// ignored holds, for each rule ID, the number of findings that the ignore
	// list dropped (see printIgnored).
	ignored map[string]int
	// counts holds the number of findings of each server, in the order of the
	// servers, for the summary.
	counts []int
	// pr is the report of the pin step. It is the zero value when the pin step
	// did not run.
	pr pinReport
	// pinFailed is true when the pin step failed. The error is already on
	// stderr.
	pinFailed bool
	// llmIncomplete is true when a request failed or the tool cap was hit in
	// the LLM step: the report still prints, and scan exits with 2.
	llmIncomplete bool
}

// runScanSteps runs the steps of a scan on the servers of res: the config
// rules, then, when setup.connect is not nil, the pin step (see inspectAndPin),
// the tool rule step (see toolRulesStep) and the LLM step (see llmStep). It
// merges their rows, ignored counts and per-server counts. When ok is false, the
// scan must exit with 2 and print no report: the user stopped the scan, or the
// guard of a step caught an error. The step already wrote the line on stderr.
func (c *cli) runScanSteps(ctx context.Context, res discover.Result, setup scanSetup, ignore *scanIgnores) (steps scanStepsResult, ok bool) {
	// counts holds the findings of each server for the summary. It starts
	// with the config findings, and the tool rule step and the LLM step add
	// their own.
	rows, ignored, counts := setup.checks.findings(&ignore.all, res.Servers)

	var pr pinReport
	var pinFailed bool
	var outcomes []inspect.Outcome
	// With no server there is nothing to inspect and nothing to pin, so scan
	// does not read pins.json.
	if setup.connect != nil && len(res.Servers) > 0 {
		var err error
		pr, outcomes, err = c.inspectAndPin(ctx, res.Servers, *setup.connect, ignore, setup.jsonOut)
		if errors.Is(err, errInterrupted) {
			// Nothing is saved and no report is printed: the user stopped
			// the scan, so the result would be partial.
			return scanStepsResult{}, false
		}
		// Any other error is already on stderr. The report of the config
		// rules still prints, and scan exits with 2.
		pinFailed = err != nil
		rows = append(rows, pr.rows...)
		ignored = mergeIgnored(ignored, pr.ignored)
	}

	// The tool rule step and the LLM step (--llm) run after the pin step. When
	// the pin step failed (pins.json cannot be read, or inspect.Run failed), no
	// server was inspected and the error is already on stderr, so the steps do
	// not run: the llmNoToolText notice would give the wrong cause.
	var tr toolRulesResult
	var lr llmResult
	if !pinFailed {
		var stepsOK bool
		tr, lr, stepsOK = c.runToolAndLLMSteps(ctx, setup, outcomes, ignore, counts)
		if !stepsOK {
			return scanStepsResult{}, false
		}
	}
	rows = append(rows, tr.rows...)
	ignored = mergeIgnored(ignored, tr.ignored)
	rows = append(rows, lr.rows...)
	ignored = mergeIgnored(ignored, lr.ignored)
	addLLMCounts(counts, lr.counts)

	return scanStepsResult{
		rows:      rows,
		ignored:   ignored,
		counts:    counts,
		pr:        pr,
		pinFailed: pinFailed,
		// A failed request or the tool cap makes the result incomplete: the
		// report still prints, and scan exits with 2.
		llmIncomplete: lr.incomplete(),
	}, true
}

// runToolAndLLMSteps runs the tool rule step (see toolRulesStep) and then the
// LLM step (see llmStep) on the tools of the servers that scan inspected. With
// --no-connect, or with no server, there are no outcomes, so both steps check
// nothing. The tool rule step applies the description and schema rules (T1 and
// T3) and adds its rows to counts. A server that uses up its time budget gets a
// MOAT-T1-023 row, not exit 2. The LLM step only adds rows: it never changes or
// drops a rule row, and it never touches pins, diffs or hints.
//
// When ok is false, the user stopped the scan, as for a signal during the
// inspection, or the guard of a step caught an error: the scan must print no
// report and save no pins. The step already wrote the line on stderr.
func (c *cli) runToolAndLLMSteps(ctx context.Context, setup scanSetup, outcomes []inspect.Outcome, ignore *scanIgnores, counts []int) (tr toolRulesResult, lr llmResult, ok bool) {
	tr, err := c.toolRulesStep(ctx, setup, outcomes, ignore, counts)
	if err != nil {
		return toolRulesResult{}, llmResult{}, false
	}
	lr, ok = c.llmStep(ctx, setup.classifier, outcomes, ignore)
	if !ok {
		return toolRulesResult{}, llmResult{}, false
	}
	return tr, lr, true
}

// writeScanOutput writes the report on c.stdout: the JSON document with --json,
// or the terminal report (see writeScanReport). It returns the first write
// error. fileEntries is the number of entries that scan read from
// .mcpmoat-ignore: the JSON report holds it. configPath is the --config value,
// or empty. configProblem is true when a config file has a problem.
func (c *cli) writeScanOutput(res discover.Result, steps scanStepsResult, setup scanSetup, fileEntries int, configPath string, configProblem bool) error {
	if setup.jsonOut {
		mode := report.ModeNoConnect
		if setup.connect != nil {
			mode = report.ModeConnect
		}
		complete := !steps.pinFailed && !configProblem && !steps.llmIncomplete
		return c.writeScanJSON(scanJSONInput{
			version:       c.build.version,
			mode:          mode,
			complete:      complete,
			res:           res,
			rows:          steps.rows,
			pr:            steps.pr,
			ignored:       steps.ignored,
			fileEntries:   fileEntries,
			configPath:    configPath,
			configProblem: configProblem,
		})
	}
	statuses := steps.pr.serverStatuses(res.Servers, steps.counts)
	if steps.pinFailed {
		// The pin step stopped before any server was inspected. Say so, or
		// each line would look like a refused server. The error is on stderr.
		for i := range statuses {
			statuses[i].Reason = reasonPinStepFailed
		}
	}
	return c.writeScanReport(res.Servers, statuses, steps.rows, steps.pr, setup.style, configPath, configProblem)
}

// writeScanReport writes the report on c.stdout, in this order: the server
// table, the summary of each server (statuses, in the order of servers), the
// findings, the diffs of the changed and new tools, then the "To accept" lines.
// st sets the colour of the summary and the findings. It returns the first
// write error. Do not use fprintf for it: a write error (a closed pipe, for
// example) must give exit code 2. configPath is the --config value, or empty,
// and configProblem is true when a config file has a problem: the "To accept"
// lines depend on both (see writeAcceptHints).
func (c *cli) writeScanReport(servers []discover.Server, statuses []report.ServerStatus, rows []report.FindingRow, pr pinReport, st report.Style, configPath string, configProblem bool) error {
	if err := report.WriteServers(c.stdout, servers); err != nil {
		return err
	}
	if err := report.WriteSummary(c.stdout, statuses, st); err != nil {
		return err
	}
	if err := report.WriteFindings(c.stdout, rows, st); err != nil {
		return err
	}
	if err := report.WriteDiffs(c.stdout, pr.diffs); err != nil {
		return err
	}
	return writeAcceptHints(c.stdout, pr.hints, configPath, configProblem)
}

// savePinned saves the first-run pins of the pin step and, only when the save
// worked, prints the "pinned N tools" notices. Before them, it prints a notice
// when the save created a new pins file (see printNewPinsFile). It returns
// false when ctx ended (the user stopped the scan while the report printed),
// when the store cannot be read again or saved, or when a server did not fit
// in the pins file (see below). The report is already out, so an error here
// cannot hide it. It writes nothing when no server was pinned, so a scan of
// pinned servers never writes pins.json (only "pin --accept" re-pins).
//
// The scan took a long time since it read pins.json first (it connected to the
// servers), and another scan or "pin --accept" may have changed the file. So
// savePinned reads the file again, with the lock on the pins directory (see
// readPinsLocked), and holds the lock until the save is done. No other run
// that locks can read or save between this read and this save, so no update is
// lost. Only a file system that cannot lock leaves that window open, and
// readPinsLocked warns about it. savePinned adds each server only if the
// locked store has no entry for it. It never overwrites an entry that another
// run wrote, and it prints no notice for it.
//
// savePinned writes nothing on stdout or stderr while it holds the lock, so a
// blocked stdout or stderr never holds the lock. The locked work is in
// setNewPins: it collects the warnings in a list of lines and keeps the error
// of Set or Save. savePinned releases the lock right after it, or right after
// the step that failed, and only then prints with printPinSave, in this order:
// the warnings, the error, and on success the new pins file notice and the
// "pinned" lines.
//
// When the first read found pins.json (pr.storeExisted) but the locked read
// does not, the file was removed while scan ran. A save would drop every older
// pin, so savePinned saves nothing, prints pinsRemovedText after the release
// and returns false (see pinsRemovedWhileRunning).
//
// Another run can also have made the file larger after the report, so a
// server that fitted then may not fit now (pins.ErrStoreFull from Set). That
// server is not pinned and gets a warning on stderr. The other servers are
// still saved, and savePinned returns false, so scan exits with 2 and the
// refusal is never silent.
func (c *cli) savePinned(ctx context.Context, pr pinReport) bool {
	if len(pr.pinned) == 0 {
		return true
	}
	// A signal while the report printed means the user stopped the scan: save
	// nothing.
	if c.interrupted(ctx, "scan") {
		return false
	}
	store, release, ok := c.readPinsLocked(ctx, "scan")
	// release is never nil. Each path below calls release before it prints.
	// The deferred call is a safety net: a second call does nothing.
	defer release()
	if !ok {
		// readPinsLocked holds no lock after an error, and it printed the
		// message.
		return false
	}
	if pinsRemovedWhileRunning(pr.storeExisted, store) {
		release()
		c.cmdPrintf("scan", "%s", pinsRemovedText)
		return false
	}
	res := setNewPins(store, pr.pinned)
	// The last step that needs the lock is done. Free the lock before the
	// output: a blocked pipe must not keep other runs from the pins file.
	release()
	return c.printPinSave(store, res)
}

// pinSave is what setNewPins did while it held the lock. printPinSave prints
// it after the release.
type pinSave struct {
	// saved are the servers that the save pinned, in the order of the scan.
	saved []pinnedServer
	// warnings holds the text of each warning, without the prefix.
	warnings []string
	// full is true when Set refused at least one server with
	// pins.ErrStoreFull.
	full bool
	// fail is the error of Set or Save, if any.
	fail saveFailure
}

// setNewPins adds each server of pinned to store, unless store already has an
// entry for it, and saves store when it added at least one server. It does not
// print: savePinned calls it with the lock held.
func setNewPins(store *pins.Store, pinned []pinnedServer) pinSave {
	var res pinSave
	for _, ps := range pinned {
		if other, found := store.Get(ps.id); found {
			// Another run pinned the server meanwhile. Its pins stay, but
			// this scan did not compare them with the tools that it saw.
			if !maps.Equal(other, ps.snap) {
				res.warnings = append(res.warnings, fmt.Sprintf("server %s was pinned by another run with other tools during this scan; run scan again", cutName(ps.name)))
			}
			continue
		}
		err := store.Set(ps.id, ps.snap)
		if errors.Is(err, pins.ErrStoreFull) {
			// The store did not change, so the other servers can still be
			// saved. This one is not pinned: say so, and exit with 2.
			res.warnings = append(res.warnings, fmt.Sprintf("server %s not pinned: %s", cutName(ps.name), pinsFullText))
			res.full = true
			continue
		}
		// pinOutcomes checked the pins with the same rules, so any other error
		// is not expected. Stop the loop and save nothing.
		if err != nil {
			res.fail = saveFailure{what: "cannot set the pins of a server", err: err}
			break
		}
		res.saved = append(res.saved, ps)
	}
	if !res.fail.failed() && len(res.saved) > 0 {
		if err := store.Save(); err != nil {
			res.fail = saveFailure{what: "cannot save the pins file", err: err}
		}
	}
	return res
}

// printPinSave prints the result of setNewPins after the release of the lock:
// the warnings, the error, and on success the new pins file notice and the
// "pinned" lines. It returns the result of savePinned.
func (c *cli) printPinSave(store *pins.Store, res pinSave) bool {
	for _, w := range res.warnings {
		c.scanWarnf("%s", w)
	}
	if res.fail.failed() {
		c.cmdErr("scan", res.fail.what, res.fail.err)
		return false
	}
	if len(res.saved) == 0 {
		return !res.full
	}
	if !store.Existed() {
		c.printNewPinsFile("scan", store.Path())
	}
	c.printPinned(res.saved)
	return !res.full
}

// inspectAndPin reads the pins store, inspects the servers with c.inspector,
// and checks the tools against the pins (see pinOutcomes). Without --json it
// writes no warning for a server that was not inspected, and none for the
// warnings of an inspection: the pin report holds them, and the summary on
// stdout shows them (see serverStatuses). With --json (jsonOut) there is no
// summary, so it writes them on stderr (see warnNotInspected).
//
// The store is read first, before inspect.Run starts any server, so a corrupt
// or newer pins.json gives exit code 2 before a stdio server runs. savePinned
// reads it again before it saves. It returns an error when scan must exit with
// 2: the store could not be read, or inspect.Run refused its input (no
// inspector, or bad options; the flags are already checked, so this is a bug).
// The message is already written on stderr.
//
// The error is errInterrupted when ctx ended during the inspection (the process
// got a signal). It has written interruptedText then (see interrupted).
// Nothing is saved: inspectAndPin never saves.
//
// It also returns the outcomes of inspect.Run, for the tool rule step (see
// toolRulesStep) and the LLM step (see llmStep). They are nil when it
// returns an error.
func (c *cli) inspectAndPin(ctx context.Context, servers []discover.Server, opts inspect.Options, ignore *scanIgnores, jsonOut bool) (pinReport, []inspect.Outcome, error) {
	store, ok := c.readPins("scan")
	if !ok {
		return pinReport{}, nil, errPinsUnreadable
	}

	outcomes, err := inspect.Run(ctx, servers, opts, c.inspector)
	if c.interrupted(ctx, "scan") {
		return pinReport{}, nil, errInterrupted
	}
	if err != nil {
		// The text of an inspect.Run error holds only our own words.
		c.cmdErr("scan", "cannot inspect the servers", err)
		return pinReport{}, nil, err
	}
	if jsonOut {
		c.warnNotInspected(outcomes)
	}
	return c.pinOutcomes(store, outcomes, ignore), outcomes, nil
}

// warnNotInspected writes on stderr, for --json, what the summary shows
// without it: one line for each outcome that is not inspect.StatusOK (see
// notInspectedText), and one line for each warning of an inspection (see
// outcomeWarnings). It never changes the exit code (FR-06, FR-16).
func (c *cli) warnNotInspected(outcomes []inspect.Outcome) {
	for _, o := range outcomes {
		if o.Status != inspect.StatusOK {
			c.scanWarnf("%s", notInspectedText(o))
		}
		for _, w := range outcomeWarnings(o) {
			c.scanWarnf("%s", warningText(o.Server.Name, w))
		}
	}
}

// The errors of inspectAndPin that have no other error to return. Their text
// is never printed.
var (
	// errInterrupted means that the process got a signal during the
	// inspection or the tool rule step.
	errInterrupted = errors.New("interrupted")
	// errPinsUnreadable means that readPins failed and wrote the message.
	errPinsUnreadable = errors.New("cannot read the pins file")
)

// reasonPinStepFailed is the summary reason of every server when inspectAndPin
// failed before it inspected any server (pinFailed in reportScan).
const reasonPinStepFailed = "scan stopped before it inspected the servers, see the error on stderr"

// printIgnored writes one line on stderr that counts the findings which the
// ignore list dropped, for example
// "mcpmoat scan: 3 findings ignored: MOAT-T4-002 (2), MOAT-T4-003 (1)". The
// rule IDs are sorted. It writes nothing when the map is empty. The line holds
// only rule IDs from the built-in rules and counts: no server name, key or
// config text. FR-10 asks for this count, and an untrusted ignore file must not
// hide findings in silence.
func (c *cli) printIgnored(ignored map[string]int) {
	if len(ignored) == 0 {
		return
	}
	ids := slices.Sorted(maps.Keys(ignored))
	parts := make([]string, len(ids))
	total := 0
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%s (%d)", id, ignored[id])
		total += ignored[id]
	}
	c.cmdPrintf("scan", "%d %s ignored: %s", total, plural(total, "finding", "findings"), strings.Join(parts, ", "))
}
