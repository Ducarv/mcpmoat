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
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// runScan implements "mcpmoat scan": it reads the client configs, runs the
// built-in config rules (T4 and T5) on every server and, unless --no-connect
// is given, inspects the servers and checks their tools against pins.json.
//
// docs/ARCHITECTURE.md describes the data flow. The usage text (scanUsage and
// usage in cli.go) is the one place that lists the flags and the exit codes
// (FR-16).
func (c *cli) runScan(_ options, args []string) int {
	fs := flag.NewFlagSet("mcpmoat scan", flag.ContinueOnError)
	// We print our own messages and scanUsage prints the help, so the flag
	// package prints nothing and the flags have no usage text.
	fs.SetOutput(io.Discard)
	noConnect := fs.Bool("no-connect", false, "")
	timeout := fs.Duration("timeout", inspect.DefaultTimeout, "")
	concurrency := fs.Int("concurrency", inspect.DefaultConcurrency, "")

	// pathFlag refuses an empty value, so a result that is not "" means the
	// flag was given.
	var configPath, rulesDir string
	pathFlag(fs, "config", "a file name", &configPath)
	pathFlag(fs, "rules", "a folder name", &rulesDir)

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

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			scanUsage(c.stdout)
			return exitOK
		}
		// The flag error holds untrusted argv inside its own text, so
		// termsafe.Quote escapes the whole message, and quotes it only when
		// it holds an unsafe rune. See dispatch in cli.go for why this
		// differs from quoteArg.
		return c.usageError("scan", "%s", termsafe.Quote(err.Error()))
	}
	if c.rejectArgs("scan", fs.Args()) {
		return exitError
	}

	// Check the values in both modes, so a bad value is a usage error even
	// when --no-connect starts no server. The options go to inspect.Run.
	connOpts, err := connectOptions(*timeout, *concurrency)
	if err != nil {
		return c.usageError("scan", "%v", err)
	}

	// Load and check the rules in both modes, so a bad rule file gives exit
	// code 2 also with --no-connect. The set gives the severity of the
	// built-in config rules.
	set, ok := c.loadRules(rulesDir)
	if !ok {
		return exitError
	}

	var connect *inspect.Options // nil with --no-connect
	if !*noConnect {
		connect = &connOpts
	}
	// A rule from --rules can target the config, but scan applies only the
	// built-in config checks. Say so, or such a rule would pass in silence.
	if rulesDir != "" {
		fprintf(c.stderr, "%s\n", rulesNotAppliedNotice)
	}

	// The typosquat check is built once and used for every server. An error
	// means a bug in mcpmoat (the list is part of the binary), so the message
	// is fixed text.
	typo, err := rules.NewBuiltinTyposquat()
	if err != nil {
		fprintf(c.stderr, "mcpmoat scan: internal error: built-in typosquat list is invalid\n")
		return exitError
	}
	setup := scanSetup{checks: configChecks{set: set, typo: typo}, connect: connect}

	// The context ends when the process gets SIGINT, SIGTERM or SIGHUP (see
	// main). scan starts stdio servers in their own session, so the terminal
	// does not reach them: only this context stops them.
	return c.scanConfigs(c.context(), configPath, ignoreIDs, setup)
}

// scanSetup holds what scan has built before it reads the config files.
type scanSetup struct {
	// checks are the config rules (T4 and T5).
	checks configChecks
	// ignore is the ignore list. scanConfigs sets it, because the working
	// directory (where .mcpmoat-ignore is) is known only after the load.
	ignore *scanIgnores
	// connect is nil with --no-connect. Otherwise it holds the options for
	// inspect.Run, and scan inspects the servers and checks their pins.
	connect *inspect.Options
}

// rulesNotAppliedNotice is the line that runScan prints on stderr when
// --rules is given. It is fixed text: it holds no path and no rule text.
const rulesNotAppliedNotice = "mcpmoat scan: rules from --rules are loaded and checked, but not applied yet"

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

// pathFlag adds a flag to fs that takes one path and stores it in *dest. The
// flag can be given once. An empty value, or a value that looks like another
// flag (see isFlagOf), is refused. what names the missing value in the error
// message, for example "a file name".
func pathFlag(fs *flag.FlagSet, name, what string, dest *string) {
	fs.Func(name, "", func(value string) error {
		if *dest != "" {
			return fmt.Errorf("--%s given more than once", name)
		}
		if value == "" || isFlagOf(fs, value) {
			return fmt.Errorf("--%s needs %s", name, what)
		}
		*dest = value
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
	setup.ignore = c.loadIgnore(wd, ignoreIDs)

	// A file that failed to load and gave no servers is a plain error. The
	// "No MCP servers found." line would be wrong and misleading here, so we
	// skip the table and print only the errors.
	if configPath != "" && loadFailed(res) {
		c.printFileErrors("scan", res.Errors)
		return exitError
	}
	return c.reportScan(ctx, res, setup)
}

// scanWarnf prints one scan warning line on stderr.
func (c *cli) scanWarnf(format string, a ...any) {
	c.warnf("scan", format, a...)
}

// loadIgnore builds the ignore lists (see scanIgnores). The list for the
// config rules holds the entries of .mcpmoat-ignore in the directory wd, then
// one entry for each --ignore ID in ids. The list for the pin rules holds only
// the --ignore entries, because the file is untrusted (see scanIgnores). ids
// holds only valid rule IDs: the --ignore flag checks them. An empty wd means
// that the working directory is not known, so loadIgnore reads no file.
//
// Every problem with the file is a warning on stderr, not an error: the scan
// goes on. A file that loadIgnore cannot read gives no entries. The warnings
// and the read error never hold file content. The error holds the path, so
// termsafe.Quote escapes it. When the file gives one or more entries,
// loadIgnore prints their number, because the file is untrusted and can hide
// findings. The --ignore IDs come from the user, so they give no notice.
//
// An entry of the file for a pin rule (MOAT-T2-*) is not applied: scan warns
// when such an entry matches a finding (see pinOutcomes).
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
		switch n := fromFile.Len(); {
		case n == 1:
			fprintf(c.stderr, "mcpmoat scan: using 1 entry from %s\n", rules.IgnoreFileName)
		case n > 1:
			fprintf(c.stderr, "mcpmoat scan: using %d entries from %s\n", n, rules.IgnoreFileName)
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
// problems, when it printed the table. It is fixed text: it holds no path and
// no config text.
const configErrorHint = "mcpmoat scan: a config file has a problem; " +
	"the table can miss servers that the client loads"

// reportScan runs the config rules on the servers of res. When setup.connect is
// not nil, it also inspects the servers and checks their pins (see
// inspectAndPin). It prints the report on stdout (see writeScanReport), and the
// file problems and warnings on stderr, and returns the exit code (the contract
// is in the usage text, see usage in cli.go). When the ignore list dropped at
// least one finding, it prints one line on stderr after the report, with the
// rule IDs and their counts (see printIgnored).
//
// The pin findings are merged with the config findings before the table is
// written, so one table holds them all and hasFailingFinding sees them all.
// New pins are saved after the report is printed, so a save error never hides
// the report. The "pinned N tools" notices come after a successful save.
func (c *cli) reportScan(ctx context.Context, res discover.Result, setup scanSetup) int {
	rows, ignored := setup.checks.findings(&setup.ignore.all, res.Servers)

	var pr pinReport
	var pinFailed bool
	// With no server there is nothing to inspect and nothing to pin, so scan
	// does not read pins.json.
	if setup.connect != nil && len(res.Servers) > 0 {
		var interrupted bool
		pr, pinFailed, interrupted = c.inspectAndPin(ctx, res.Servers, *setup.connect, setup.ignore)
		if interrupted {
			// Nothing is saved and no report is printed: the user stopped
			// the scan, so the result would be partial.
			fprintf(c.stderr, "%s\n", interruptedNotice)
			return exitError
		}
		rows = append(rows, pr.rows...)
		ignored = mergeIgnored(ignored, pr.ignored)
	}

	if err := c.writeScanReport(res.Servers, rows, pr); err != nil {
		fprintf(c.stderr, "mcpmoat scan: cannot write output\n")
		// stderr can still work. The file problems are the reason for a
		// failed scan, so the user must still see them. New pins are not
		// saved: the user did not see the report.
		c.printFileErrors("scan", res.Errors)
		return exitError
	}
	c.printIgnored(ignored)

	if !c.savePinned(pr) {
		pinFailed = true
	}

	if len(res.Errors) > 0 {
		// Print the problems in the order of the result, then the hint.
		c.printFileErrors("scan", res.Errors)
		fprintf(c.stderr, "%s\n", configErrorHint)
		return exitError
	}
	if pinFailed {
		return exitError
	}
	if hasFailingFinding(rows) {
		return exitFindings
	}
	return exitOK
}

// writeScanReport writes the report on w: the server table, the findings, the
// diffs of the changed and new tools, then the "To accept" lines. It returns the
// first write error. Do not use fprintf for it: a write error (a closed pipe,
// for example) must give exit code 2.
func (c *cli) writeScanReport(servers []discover.Server, rows []report.FindingRow, pr pinReport) error {
	if err := report.WriteServers(c.stdout, servers); err != nil {
		return err
	}
	if err := report.WriteFindings(c.stdout, rows); err != nil {
		return err
	}
	if err := report.WriteDiffs(c.stdout, pr.diffs); err != nil {
		return err
	}
	return writeAcceptHints(c.stdout, pr.hints)
}

// savePinned saves the new pins of the pin step and, only when the save
// worked, prints the "pinned N tools" notices. It returns false when the save
// failed. The report is already out, so a save error cannot hide it.
func (c *cli) savePinned(pr pinReport) bool {
	if err := pr.save(); err != nil {
		c.scanStoreErrorf("cannot save the pins file", err)
		return false
	}
	c.printPinned(pr.pinned)
	return true
}

// interruptedNotice is the line that scan prints on stderr when the process
// got a signal while it inspected the servers. It is fixed text.
const interruptedNotice = "mcpmoat scan: interrupted; no pins were saved"

// inspectAndPin reads the pins store, inspects the servers with c.inspector,
// writes a warning for each server that was not inspected, and checks the tools
// against the pins (see pinOutcomes).
//
// The store is read first, before inspect.Run starts any server, so a corrupt
// or newer pins.json gives exit code 2 before a stdio server runs. The second
// result is true when scan must exit with 2: the store could not be read, or
// inspect.Run refused its input (no inspector, or bad options; the flags are
// already checked, so this is a bug). The error is already written on stderr.
//
// The third result is true when ctx ended during the inspection (the process
// got a signal). The caller prints interruptedNotice and exits with 2. Nothing
// is saved: inspectAndPin never saves.
func (c *cli) inspectAndPin(ctx context.Context, servers []discover.Server, opts inspect.Options, ignore *scanIgnores) (pr pinReport, failed, interrupted bool) {
	store, err := c.loadPins()
	if err != nil {
		c.scanStoreErrorf("cannot read the pins file", err)
		return pinReport{}, true, false
	}

	outcomes, err := inspect.Run(ctx, servers, opts, c.inspector)
	if ctx.Err() != nil {
		return pinReport{}, false, true
	}
	if err != nil {
		// The text of an inspect.Run error holds only our own words.
		c.scanStoreErrorf("cannot inspect the servers", err)
		return pinReport{}, true, false
	}
	c.warnNotInspected(outcomes)
	return c.pinOutcomes(store, outcomes, ignore), false, false
}

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
	noun := "findings"
	if total == 1 {
		noun = "finding"
	}
	fprintf(c.stderr, "mcpmoat scan: %d %s ignored: %s\n", total, noun, strings.Join(parts, ", "))
}
