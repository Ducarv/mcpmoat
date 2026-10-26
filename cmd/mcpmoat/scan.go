package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
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
	fs := flag.NewFlagSet("mcpmoat scan", flag.ContinueOnError)
	// We print our own messages and scanUsage prints the help, so the flag
	// package prints nothing and the flags have no usage text.
	fs.SetOutput(io.Discard)
	noConnect := fs.Bool("no-connect", false, "")
	noColor := fs.Bool("no-color", false, "")
	jsonOut := fs.Bool("json", false, "")
	timeout := fs.Duration("timeout", inspect.DefaultTimeout, "")
	concurrency := fs.Int("concurrency", inspect.DefaultConcurrency, "")

	// onceStringFlag refuses an empty value, so a result that is not ""
	// means the flag was given.
	var configPath, rulesDir string
	onceStringFlag(fs, "config", "a file name", &configPath)
	onceStringFlag(fs, "rules", "a folder name", &rulesDir)

	// fs.Func calls the function once for each --ignore, so the user can
	// give the flag more than once. ValidRuleID also refuses an empty value
	// and a flag name such as "--no-connect" that the flag package took as
	// the value: a rule ID starts with a letter. The flag error already holds
	// the value, so the message does not repeat it.
	var ignoreIDs []string
	fs.Func("ignore", "", func(value string) error {
		if !rules.ValidRuleID(value) {
			return errors.New("--ignore needs a rule ID")
		}
		ignoreIDs = append(ignoreIDs, value)
		return nil
	})

	// severityFlag refuses an empty value, so an empty result means the flag
	// was not given: then the default is high.
	var failOn rules.Severity
	severityFlag(fs, "fail-on", &failOn)

	// The LLM flags (FR-17), see addLLMFlags.
	var llmOpts llmFlags
	baseURLFlag := addLLMFlags(fs, &llmOpts)

	// The error of another flag, or the list of unexpected arguments, can
	// hold a base URL value too: for example "--timeout --llm-base-url=URL"
	// and "--timeout=--llm-base-url=URL" make the flag package quote the
	// whole value. hider removes every base URL value of args from that text
	// (see newArgHider).
	hider := newArgHider(args, flagLLMBaseURL)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			scanUsage(c.stdout)
			return exitOK
		}
		// The flag package puts the value into err. Print the problem that
		// the flag recorded instead: its text holds no value.
		if baseURLFlag.problem != nil {
			return c.usageError("scan", "%v", baseURLFlag.problem)
		}
		// The flag error holds untrusted argv inside its own text, so
		// termsafe.Quote escapes the whole message, and quotes it only when
		// it holds an unsafe rune. See dispatch in cli.go for why this
		// differs from quoteArg.
		return c.usageError("scan", "%s", termsafe.Quote(hider.hide(err.Error())))
	}
	if c.rejectArgs("scan", hider.hideAll(fs.Args())) {
		return exitError
	}
	if failOn == "" {
		failOn = rules.SeverityHigh
	}

	// Check the values in both modes, so a bad value is a usage error even
	// when --no-connect starts no server. The options go to inspect.Run.
	connOpts, err := connectOptions(*timeout, *concurrency)
	if err != nil {
		return c.usageError("scan", "%v", err)
	}

	// Check the LLM flags and the API key before scan reads a config file
	// (see setupLLM). Without --llm, classifier is nil: no key is read and no
	// client is built.
	classifier, ok := c.setupLLM(llmOpts, *noConnect)
	if !ok {
		return exitError
	}
	defer closeClassifier(classifier)

	// Load and check the rules in both modes, so a bad rule file gives exit
	// code 2 also with --no-connect. The set gives the severity and the texts
	// of the findings. The analyzer applies the description and schema rules
	// to the tools when scan connects to the servers.
	loaded, ok := c.loadRules(rulesDir)
	if !ok {
		return exitError
	}

	var connect *inspect.Options // nil with --no-connect
	if !*noConnect {
		connect = &connOpts
	}
	// Scan does not apply a rule from --rules with the target config, and it
	// applies no description or schema rule with --no-connect. Say so, or such
	// a rule would pass in silence. Each notice is fixed text.
	for _, n := range loaded.external.notices(*noConnect) {
		fprintf(c.stderr, "%s\n", n)
	}
	// No built-in rule is critical, so --fail-on critical gives exit code 0
	// for every built-in finding. Say so, or a CI log shows no sign that the
	// gate cannot fail.
	if failOn == rules.SeverityCritical {
		fprintf(c.stderr, "%s\n", failOnCriticalNotice)
	}

	// The typosquat check is built once and used for every server. An error
	// means a bug in mcpmoat (the list is part of the binary), so the message
	// is fixed text.
	typo, err := rules.NewBuiltinTyposquat()
	if err != nil {
		fprintf(c.stderr, "mcpmoat scan: internal error: built-in typosquat list is invalid\n")
		return exitError
	}
	// Colour is on only when stdout is a terminal, --no-color is not set and
	// NO_COLOR is empty (FR-14). opts.noColor holds the combined result of the
	// global flag (before "scan") and the environment variable. The scan flag
	// --no-color (after "scan") is read here, so both positions work.
	style := report.Style{Color: !opts.noColor && !*noColor && c.stdoutIsTTY}
	setup := scanSetup{
		checks:     configChecks{set: loaded.set, typo: typo},
		analyzer:   loaded.analyzer,
		toolBudget: c.toolBudgetOrDefault(),
		connect:    connect,
		style:      style,
		failOn:     failOn,
		jsonOut:    *jsonOut,
		classifier: classifier,
	}

	// The context ends when the process gets SIGINT, SIGTERM or SIGHUP (see
	// main). scan starts stdio servers in their own session, so the terminal
	// does not reach them: only this context stops them.
	return c.scanConfigs(c.ctxOrBackground(), configPath, ignoreIDs, setup)
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
	// classifier rates the tools with an LLM (--llm, see classifyTools). It
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

// failOnCriticalNotice is the line that runScan prints on stderr for
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

// hiddenArgText replaces the value of a secret flag in an error message.
const hiddenArgText = "(hidden)"

// argHider removes the values of one secret flag from the error text of the
// argument checks. The zero argHider changes nothing.
type argHider struct {
	r *strings.Replacer // nil when the args give no value
}

// newArgHider returns an argHider for the values that args gives to the flag
// name. It looks for the text "-name" in each argument, with one dash or more
// before name:
//   - "-name=" anywhere in the argument: the rest of the argument after each
//     "-name=" is a value. So "--name=value" counts, and so does the value of
//     another flag, as in "--timeout=--name=value", which the flag package
//     quotes whole in its error.
//   - "-name" at the end of the argument: the next argument is a value. So a
//     bare "--name" counts, and so does "--timeout=--name".
//
// It looks at every argument, also after "--" and after a flag that took
// "--name" as its own value, so it can find more values than Parse uses: that
// only hides more. A short value, for example one letter, also hides that
// text in the other words of the message: that is on purpose, because it
// fails safe.
func newArgHider(args []string, name string) argHider {
	token := "-" + name
	var values []string
	for i, arg := range args {
		// Each "-name=" gives a value. A later value is the end of an
		// earlier one. It is kept for a text that shows only that end.
		for rest := arg; ; {
			_, v, ok := strings.Cut(rest, token+"=")
			if !ok {
				break
			}
			values = append(values, v)
			rest = v
		}
		if strings.HasSuffix(arg, token) && i+1 < len(args) {
			values = append(values, args[i+1])
		}
	}
	// The flag package quotes a value with %q in `invalid value "..."`, so a
	// value with a quote, a backslash or a control rune shows escaped. Hide
	// that form too.
	var olds []string
	for _, v := range values {
		if v == "" {
			continue
		}
		olds = append(olds, v)
		if q := strconv.Quote(v); q[1:len(q)-1] != v {
			olds = append(olds, q[1:len(q)-1])
		}
	}
	if len(olds) == 0 {
		return argHider{}
	}
	// strings.Replacer tries the old strings in the order given, so the
	// longest goes first: a value that holds another value is hidden whole.
	// The text order of equal lengths puts duplicates side by side for
	// slices.Compact.
	slices.SortFunc(olds, func(a, b string) int {
		return cmp.Or(cmp.Compare(len(b), len(a)), strings.Compare(a, b))
	})
	olds = slices.Compact(olds)
	pairs := make([]string, 0, 2*len(olds))
	for _, o := range olds {
		pairs = append(pairs, o, hiddenArgText)
	}
	return argHider{r: strings.NewReplacer(pairs...)}
}

// hide returns s with every value of the secret flag replaced by
// hiddenArgText. The rest of s stays as it is.
func (h argHider) hide(s string) string {
	if h.r == nil {
		return s
	}
	return h.r.Replace(s)
}

// hideAll returns a copy of args with hide applied to each argument.
func (h argHider) hideAll(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = h.hide(a)
	}
	return out
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
// one entry for each --ignore ID in ids. The list for the pin rules and the
// LLM rules holds only the --ignore entries, because the file is untrusted
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
// An entry of the file for a pin rule (MOAT-T2-*) or an LLM rule
// (MOAT-LLM-001 or MOAT-LLM-002) is not applied: scan warns when such an
// entry matches a finding (see pinOutcomes and classifyTools).
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

// reportScan runs the config rules on the servers of res, with the ignore list
// ignore. When setup.connect is not nil, it also inspects the servers, checks
// their pins (see inspectAndPin) and applies the description and schema rules
// to their tools (see toolRulesStep). configPath is the --config value, or
// empty. It prints the report on stdout (see writeScanReport, or the JSON
// document with --json), and the file problems and warnings on stderr, and
// returns the exit code (see scanExitCode; docs/exit-codes.md is the
// contract, and the usage text in cli.go summarises it). The status of each
// server and the warnings of its inspection are part of the report on stdout
// (the summary), not warnings on stderr. They never change the exit code. When
// the ignore list dropped at least one finding, it prints one line on stderr
// after the report, with the rule IDs and their counts (see printIgnored).
//
// The pin findings, the tool rule findings and, with --llm, the LLM findings
// (see classifyTools) are merged with the config findings before the report
// (the table or the JSON document) is written, so the report holds them all
// and scanExitCode sees them all: an LLM finding counts for --fail-on like any
// other. A server whose rule analysis uses up setup.toolBudget gets a
// MOAT-T1-023 finding and a warning on stderr; that alone is not exit code 2.
// The finding is high, or critical when a description or schema rule from
// --rules is critical (see budgetSeverity).
// New pins are saved after the report is printed, so a save error never hides
// the report. The "pinned N tools" notices come after a successful save.
//
// A config file problem, a pins.json read or save error, an inspect.Run error,
// an incomplete LLM step (a failed request, or more tools than maxLLMTools) or
// a signal before the save of new pins (when there are new pins) gives exit
// code 2, also when there are findings at or above setup.failOn (see
// scanExitCode). The report is already printed when reportScan calls
// scanExitCode, so the user still sees the findings. Only a signal during the
// inspection, the tool rule step or the LLM step, an internal error of the
// tool rule step and a failed write of the report return exit code 2 without
// a full report.
func (c *cli) reportScan(ctx context.Context, res discover.Result, configPath string, setup scanSetup, ignore *scanIgnores) int {
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
			return exitError
		}
		// Any other error is already on stderr. The report of the config
		// rules still prints, and scan exits with 2.
		pinFailed = err != nil
		rows = append(rows, pr.rows...)
		ignored = mergeIgnored(ignored, pr.ignored)
	}

	// The tool rule step and the LLM step (--llm) run after the pin step, on
	// the tools of the servers that scan inspected. With --no-connect, or
	// with no server, there are no outcomes, so both steps check nothing.
	// When the pin step failed (pins.json cannot be read, or inspect.Run
	// failed), no server was inspected and the error is already on stderr,
	// so the steps do not run: the llmNoToolText notice would give the wrong
	// cause.
	var lr llmResult
	if !pinFailed {
		// The tool rule step applies the description and schema rules (T1
		// and T3) and adds its rows to counts (see toolRulesStep). A server
		// that uses up its time budget gets a MOAT-T1-023 row, not exit 2.
		tr, err := c.toolRulesStep(ctx, setup, outcomes, ignore, counts)
		if err != nil {
			// The user stopped the scan, as for a signal during the
			// inspection, or the guard of toolRulesStep caught an error: no
			// report and no saved pins. toolRulesStep wrote the line on
			// stderr.
			return exitError
		}
		rows = append(rows, tr.rows...)
		ignored = mergeIgnored(ignored, tr.ignored)

		// The LLM step only adds rows: it never changes or drops a rule
		// row, and it never touches pins, diffs or hints (see llmStep).
		var ok bool
		lr, ok = c.llmStep(ctx, setup.classifier, outcomes, ignore)
		if !ok {
			// The user stopped the scan, as for a signal during the
			// inspection, or the guard of llmStep caught an error: no report
			// and no saved pins. llmStep wrote the line on stderr.
			return exitError
		}
	}
	// A failed request or the tool cap makes the result incomplete: the
	// report still prints, and scan exits with 2.
	llmIncomplete := lr.incomplete()
	rows = append(rows, lr.rows...)
	ignored = mergeIgnored(ignored, lr.ignored)
	addLLMCounts(counts, lr.counts)

	configProblem := len(res.Errors) > 0
	var writeErr error
	if setup.jsonOut {
		mode := report.ModeNoConnect
		if setup.connect != nil {
			mode = report.ModeConnect
		}
		complete := !pinFailed && !configProblem && !llmIncomplete
		writeErr = c.writeScanJSON(mode, complete, res, rows, pr)
	} else {
		statuses := pr.serverStatuses(res.Servers, counts)
		if pinFailed {
			// The pin step stopped before any server was inspected. Say so, or
			// each line would look like a refused server. The error is on stderr.
			for i := range statuses {
				statuses[i].Reason = reasonPinStepFailed
			}
		}
		writeErr = c.writeScanReport(res.Servers, statuses, rows, pr, setup.style, configPath, configProblem)
	}
	if writeErr != nil {
		c.cmdPrintf("scan", "cannot write output")
		// stderr can still work. The file problems are the reason for a
		// failed scan, so the user must still see them. New pins are not
		// saved: the user did not see the report.
		c.printFileErrors("scan", res.Errors)
		return exitError
	}
	c.printIgnored(ignored)

	if !c.savePinned(ctx, pr) {
		pinFailed = true
	}

	if configProblem {
		// Print the problems in the order of the result, then the hint.
		c.printFileErrors("scan", res.Errors)
		fprintf(c.stderr, "%s\n", configErrorHint)
	}
	return scanExitCode(configProblem || pinFailed || llmIncomplete, rows, setup.failOn)
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
// worked, prints the "pinned N tools" notices. It returns false when ctx ended
// (the user stopped the scan while the report printed), or when the store
// cannot be read again or saved. The report is already out, so an error here
// cannot hide it. It writes nothing when no server was pinned, so a scan of
// pinned servers never writes pins.json (only "pin --accept" re-pins).
//
// The scan took a long time since it read pins.json first (it connected to the
// servers), and another scan or "pin --accept" may have changed the file. So
// savePinned reads the file again and adds each server only if the new store has
// no entry for it. It never overwrites an entry that another run wrote, and it
// prints no notice for it. This makes the window for a lost update short. It does
// not close it: two runs can still read and save at the same moment. A lock on
// the file is issue #150.
func (c *cli) savePinned(ctx context.Context, pr pinReport) bool {
	if len(pr.pinned) == 0 {
		return true
	}
	// A signal while the report printed means the user stopped the scan: save
	// nothing.
	if c.interrupted(ctx, "scan") {
		return false
	}
	store, ok := c.readPins("scan")
	if !ok {
		return false
	}
	var saved []pinnedServer
	for _, ps := range pr.pinned {
		if other, found := store.Get(ps.id); found {
			// Another run pinned the server meanwhile. Its pins stay, but
			// this scan did not compare them with the tools that it saw.
			if !maps.Equal(other, ps.snap) {
				c.scanWarnf("server %s was pinned by another run with other tools during this scan; run scan again", cutName(ps.name))
			}
			continue
		}
		// pinOutcomes checked the pins with the same rules, so an error here
		// is not expected.
		if err := store.Set(ps.id, ps.snap); err != nil {
			c.cmdErr("scan", "cannot set the pins of a server", err)
			return false
		}
		saved = append(saved, ps)
	}
	if len(saved) == 0 {
		return true
	}
	if err := store.Save(); err != nil {
		c.cmdErr("scan", "cannot save the pins file", err)
		return false
	}
	c.printPinned(saved)
	return true
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
// toolRulesStep) and the LLM step (see classifyTools). They are nil when it
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
