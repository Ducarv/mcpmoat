package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// runScan implements "mcpmoat scan". It reads the client configs, lists the
// servers it finds and runs the built-in config rules on every server (T4 with
// rules.CheckConfig, T5 with the typosquat check).
//
// With --no-connect that is all: scan starts no process, opens no network
// connection, and reads and writes no pins.json.
//
// Without --no-connect, scan then inspects the servers with c.inspector
// (inspect.Run with the --timeout and --concurrency values) and checks the
// tools of each server against pins.json (FR-11, FR-12): the first run pins
// the tools, and a later run reports a changed, new, removed or unverified
// tool as a finding, with a diff for a changed tool (see pinOutcomes). The
// YAML rules are not applied to the tools yet. A server that fails, times out
// or that the inspector refuses (an untrusted or turned-off server) is a
// warning on stderr, never exit code 2 (FR-06, FR-16). It is a finding only
// when the server is already pinned: then it gets a MOAT-T2-004 row (medium,
// "pinned server could not be inspected"), because a hostile server must not
// avoid the rug-pull check by failing on purpose.
//
// scan reads pins.json before it starts any server, so a corrupt or newer file
// gives exit code 2 before a stdio server runs. The "pinned N tools" notices
// come only after the new pins are saved.
//
// Signals: scan starts each stdio server in its own session, so the terminal
// does not signal it. main passes a context that ends on SIGINT, SIGTERM or
// SIGHUP, and inspect.Run stops the servers when it ends. Then scan saves
// nothing, prints "mcpmoat scan: interrupted; no pins were saved" and exits
// with 2.
//
// --rules loads the *.yaml and *.yml rule files of one folder in addition to
// the built-in rules, and checks them. Scan does not apply these rules yet. The
// loaded set only gives the severity of the built-in config rules.
//
// --config reads one file. The file can come from anywhere, for example from
// a cloned repository, so discover.ReadConfig reads it as an untrusted project
// file (confined to its directory, no "projects" section), unless it is the
// user's own global config file (~/.claude.json, ~/.cursor/mcp.json or
// ~/.codex/config.toml). The home directory is only used for that check.
//
// --timeout (default inspect.DefaultTimeout) is the time limit for one server.
// --concurrency (default inspect.DefaultConcurrency) is the number of servers
// inspected at the same time. Both are checked in both modes, also with
// --no-connect, which does not use them. A value that is not valid (a
// timeout of 0 or less, a concurrency below 1) is a usage error with exit
// code 2, like a value that the flag package cannot parse.
//
// --ignore <rule-id> ignores all findings of one rule. The user can give it
// more than once. A value that is not a valid rule ID is a usage error. In
// both modes scan also reads rules.IgnoreFileName (.mcpmoat-ignore) from the
// working directory (FR-10). That file is untrusted: a cloned repository can
// ship one that silences any server, also the user's global servers. So when
// the file gives one or more entries, scan prints a notice with their number
// on stderr. A malformed line, a file that scan cannot read and, with
// --config, an unknown working directory are warnings on stderr, never exit
// code 2. The ignore list drops the findings of the config rules.
//
// The ignore list drops pin findings too, by rule ID, server and tool name,
// but only the --ignore entries do. An entry of .mcpmoat-ignore for a pin rule
// (MOAT-T2-*) is not applied, or a cloned repository could silence the
// rug-pull alarm. scan prints one warning for each rule ID that the file would
// have ignored: ".mcpmoat-ignore cannot ignore MOAT-T2-001; use --ignore on
// the command line".
//
// Scan prints the server table, then the findings that the ignore list does
// not drop (the config findings, then the pin findings), then the diffs of the
// changed tools, then one line for each pinned server that has a pin finding
// that is not ignored, on stdout:
// "To accept <server>: mcpmoat pin --accept <server> --expect <digest>". The
// digest covers the tools that scan saw, so "pin --accept --expect" saves only
// those tools and not tools that a hostile server shows later (see
// writeAcceptHints). A first-run server, a server that was not inspected and a
// server whose tools cannot be pinned get no such line.
//
// Exit codes:
//   - 0: the table is printed, no config file had a problem, pins.json had no
//     problem, and no finding has severity high or above. A missing file is
//     not a problem in auto-discovery. A server that was not inspected does
//     not change the code. The tool rules do not run yet, so exit code 0 does
//     not mean that the tools of the servers are safe.
//   - 1: at least one finding that is not ignored has severity high or above
//     (--fail-on is not implemented yet, so the limit is always high). A
//     changed tool (MOAT-T2-001) is high.
//   - 2: a flag or usage error, an internal error (the built-in typosquat
//     list is invalid), no home or working directory in
//     auto-discovery, a write error on stdout, any problem with a rule file
//     or with the rule set (an invalid file, a duplicate ID, an ID that clashes
//     with a built-in rule), or any problem with a config file (a
//     discover.FileError), in auto-discovery too and also for the user's own
//     global files. A file that mcpmoat cannot read or refuses, or
//     a server entry that it refuses, can hide servers that the client still
//     loads. So the scan must not look clean: scan prints the table and all
//     problems first, and then exits with 2. The same holds for pins.json: if
//     scan cannot read it (a corrupt file, a newer format), it starts no server
//     and checks no pins; if it cannot save new pins, they are lost. A signal
//     during the inspection is also exit code 2, with no report. With a
//     problem, scan prints the report first. With --config, a file that gave
//     no servers at all gives only the problems, and no table. Exit code 2
//     wins over exit code 1.
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

	// connect is nil with --no-connect. Otherwise it holds the options for
	// inspect.Run, and scan inspects the servers and checks their pins.
	var connect *inspect.Options
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
	checks := configChecks{set: set, typo: typo}

	// The context ends when the process gets SIGINT, SIGTERM or SIGHUP (see
	// main). scan starts stdio servers in their own session, so the terminal
	// does not reach them: only this context stops them.
	ctx := c.context()

	if configPath != "" {
		return c.scanConfig(ctx, configPath, ignoreIDs, checks, connect)
	}
	return c.scanAuto(ctx, ignoreIDs, checks, connect)
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

// scanConfig reads the one file that --config names.
//
// A relative path is made absolute first, from the working directory.
// ReadConfig takes the project path of a project file from the file path, so
// a relative path would give a relative project path. Then the result would
// depend on how the user spells the path: the SCOPE cell would change, the
// check that keeps an absolute Codex cwd inside the project would refuse
// every such cwd, and the user's own global file would not be found.
//
// If the working directory is not known, the path stays relative. That is
// the safe side: the file is read as untrusted, and an absolute Codex cwd is
// refused. A server can be refused that the absolute path would accept, but
// never the other way.
//
// The working directory is also where .mcpmoat-ignore is. Without it, scan
// prints a warning and reads no ignore file.
//
// connect is nil with --no-connect. Otherwise it holds the inspect options
// (see reportScan).
func (c *cli) scanConfig(ctx context.Context, path string, ignoreIDs []string, checks configChecks, connect *inspect.Options) int {
	// The error text is not printed; a fixed warning is enough.
	wd, err := c.getwd()
	if err != nil {
		wd = "" // do not use a value that comes with an error
		c.scanWarnf("cannot read the working directory; %s is not read", rules.IgnoreFileName)
	}
	if !filepath.IsAbs(path) && wd != "" {
		path = filepath.Join(wd, path)
	}
	ignore := c.loadIgnore(wd, ignoreIDs)

	// The home directory only tells ReadConfig whether the file is one of the
	// user's own global files. Without a home, no file is: the file is read
	// as untrusted, the safe side. So a home error is not fatal here, and its
	// text is not printed.
	home, err := c.homeDir()
	if err != nil {
		home = ""
	}
	res := discover.ReadConfig(ctx, path, home)

	// A file that failed to load and gave no servers is a plain error. The
	// "No MCP servers found." line would be wrong and misleading here, so we
	// skip the table and print only the errors.
	if len(res.Servers) == 0 && len(res.Errors) > 0 {
		c.printFileErrors(res.Errors)
		return exitError
	}
	return c.reportScan(ctx, res, checks, ignore, connect)
}

// scanAuto looks for the config files of the known clients, in the home
// directory and in the working directory. connect is nil with --no-connect
// (see reportScan).
func (c *cli) scanAuto(ctx context.Context, ignoreIDs []string, checks configChecks, connect *inspect.Options) int {
	// The error text is not printed: a fixed message is enough.
	home, err := c.homeDir()
	if err != nil {
		fprintf(c.stderr, "mcpmoat scan: cannot find the home directory: set HOME or use --config\n")
		return exitError
	}
	wd, err := c.getwd()
	if err != nil {
		fprintf(c.stderr, "mcpmoat scan: cannot read the working directory; use --config\n")
		return exitError
	}
	ignore := c.loadIgnore(wd, ignoreIDs)
	return c.reportScan(ctx, discover.Discover(ctx, discover.Options{Home: home, WorkDir: wd}), checks, ignore, connect)
}

// scanWarnf prints one scan warning line on stderr.
func (c *cli) scanWarnf(format string, a ...any) {
	fprintf(c.stderr, "mcpmoat scan: warning: %s\n", fmt.Sprintf(format, a...))
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

// reportScan runs the config rules on the servers of res (see
// configChecks.findings). When connect is not nil, it also inspects the servers
// and checks their pins (see inspectAndPin). It prints the server table, the
// findings and the diffs of changed tools on stdout, and the file problems and
// warnings on stderr, and returns the exit code. When the ignore list dropped
// at least one finding, reportScan prints one line on stderr after the
// findings, with the rule IDs and their counts (see printIgnored). This line
// does not change the exit code.
//
// The pin findings are merged with the config findings before the table is
// written, so one table holds them all and hasFailingFinding sees them all.
// The "To accept" lines come after the diffs and are not part of the table.
// New pins are saved after the report is printed, so a save error never hides
// the report. The "pinned N tools" notices come after a successful save.
//
// The runScan doc holds the exit-code contract: 2 for a write error, a config
// file problem or a pins.json problem, else 1 for a finding of severity high
// or above, else 0.
func (c *cli) reportScan(ctx context.Context, res discover.Result, checks configChecks, ignore *scanIgnores, connect *inspect.Options) int {
	rows, ignored := checks.findings(&ignore.all, res.Servers)

	var pr pinReport
	var pinFailed bool
	// With no server there is nothing to inspect and nothing to pin, so scan
	// does not read pins.json.
	if connect != nil && len(res.Servers) > 0 {
		var interrupted bool
		pr, pinFailed, interrupted = c.inspectAndPin(ctx, res.Servers, *connect, ignore)
		if interrupted {
			// Nothing is saved and no report is printed: the user stopped
			// the scan, so the result would be partial.
			fprintf(c.stderr, "%s\n", interruptedNotice)
			return exitError
		}
		rows = append(rows, pr.rows...)
		ignored = mergeIgnored(ignored, pr.ignored)
	}

	// Do not use fprintf for the tables: a write error (a closed pipe, for
	// example) must give exit code 2.
	err := report.WriteServers(c.stdout, res.Servers)
	if err == nil {
		err = report.WriteFindings(c.stdout, rows)
	}
	if err == nil {
		err = report.WriteDiffs(c.stdout, pr.diffs)
	}
	if err == nil {
		err = writeAcceptHints(c.stdout, pr.hints)
	}
	if err != nil {
		fprintf(c.stderr, "mcpmoat scan: cannot write output\n")
		// stderr can still work. The file problems are the reason for a
		// failed scan, so the user must still see them. New pins are not
		// saved: the user did not see the report.
		c.printFileErrors(res.Errors)
		return exitError
	}
	c.printIgnored(ignored)

	// The report is out, so a save error cannot hide it.
	// Say "pinned" only when the save worked.
	if err := pr.save(); err != nil {
		c.pinErrorf("cannot save the pins file", err)
		pinFailed = true
	} else {
		c.printPinned(pr.pinned)
	}

	if len(res.Errors) > 0 {
		// Print the problems in the order of the result, then the hint.
		c.printFileErrors(res.Errors)
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
		c.pinErrorf("cannot read the pins file", err)
		return pinReport{}, true, false
	}

	outcomes, err := inspect.Run(ctx, servers, opts, c.inspector)
	if ctx.Err() != nil {
		return pinReport{}, false, true
	}
	if err != nil {
		// The text of an inspect.Run error holds only our own words.
		c.pinErrorf("cannot inspect the servers", err)
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

// printFileErrors writes one line per file problem on stderr, with the
// prefix "mcpmoat scan: ". A line holds only the fields of the FileError
// (path, position, project path, server name, fixed reason and OS error),
// never config text.
func (c *cli) printFileErrors(errs []*discover.FileError) {
	// FileError.Error already escapes the path and the server name.
	for _, e := range errs {
		fprintf(c.stderr, "mcpmoat scan: %s\n", e.Error())
	}
}
