package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// runScan implements "mcpmoat scan". For now it only supports --no-connect: it
// reads the client configs and lists the servers it finds. It starts no
// process and opens no network connection. M3 adds the connection step, and M4
// adds the rules.
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
// --no-connect, which does not use them yet. A value that is not valid (a
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
// code 2. The ignore list is not used yet: scan produces no findings before
// M4.
//
// Exit codes:
//   - 0: the table is printed, and no config file had a problem. A missing
//     file is not a problem in auto-discovery. No rules run yet, so scan
//     then prints noRulesNotice on stderr: exit code 0 does not mean that
//     the servers are safe.
//   - 2: a flag or usage error, no home or working directory in
//     auto-discovery, a write error on stdout, or any problem with a config
//     file (a discover.FileError), in auto-discovery too and also for the
//     user's own global files. A file that mcpmoat cannot read or refuses, or
//     a server entry that it refuses, can hide servers that the client still
//     loads. So the scan must not look clean: scan prints the table and all
//     problems first, and then exits with 2. With --config, a file that gave
//     no servers at all gives only the problems, and no table.
func (c *cli) runScan(_ options, args []string) int {
	fs := flag.NewFlagSet("mcpmoat scan", flag.ContinueOnError)
	// We print our own messages and scanUsage prints the help, so the flag
	// package prints nothing and the flags have no usage text.
	fs.SetOutput(io.Discard)
	noConnect := fs.Bool("no-connect", false, "")
	timeout := fs.Duration("timeout", inspect.DefaultTimeout, "")
	concurrency := fs.Int("concurrency", inspect.DefaultConcurrency, "")

	// fs.Func calls the function once for each time the user gives --config.
	// An error from it becomes a flag error: exit code 2 with a clear message.
	// An empty value is refused, so configPath != "" means --config was given.
	var configPath string
	fs.Func("config", "", func(value string) error {
		if configPath != "" {
			return errors.New("--config given more than once")
		}
		if value == "" || isFlagOf(fs, value) {
			return errors.New("--config needs a file name")
		}
		configPath = value
		return nil
	})

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
	// when --no-connect starts no server. M3 passes the options to
	// inspect.Run.
	if _, err := connectOptions(*timeout, *concurrency); err != nil {
		return c.usageError("scan", "%v", err)
	}

	if !*noConnect {
		fprintf(c.stderr, "mcpmoat scan: connecting to servers is not implemented yet; use --no-connect\n")
		return exitError
	}

	// context.Background() never ends. M3 adds signal handling in main, and
	// main will pass a context that ends on Ctrl-C.
	ctx := context.Background()

	if configPath != "" {
		return c.scanConfig(ctx, configPath, ignoreIDs)
	}
	return c.scanAuto(ctx, ignoreIDs)
}

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

// isFlagOf reports whether value looks like a flag of fs, in any form that
// the flag package accepts: "-name", "--name", "-name=x" or "--name=x". -h and
// -help count too, because the flag package treats them as a help request.
// The flag package takes the next argument as the value of --config, so
// "scan --config --no-connect" would use "--no-connect" as a file name. We
// reject that case. The names come from fs, so a new scan flag is covered
// without a second edit. A real file name that starts with "-" can be given
// as ./-name.
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
func (c *cli) scanConfig(ctx context.Context, path string, ignoreIDs []string) int {
	// The error text is not printed; a fixed warning is enough.
	wd, err := c.getwd()
	if err != nil {
		wd = "" // do not use a value that comes with an error
		fprintf(c.stderr, "mcpmoat scan: warning: cannot read the working directory; %s is not read\n", rules.IgnoreFileName)
	}
	if !filepath.IsAbs(path) && wd != "" {
		path = filepath.Join(wd, path)
	}
	_ = c.loadIgnore(wd, ignoreIDs) // TODO(#40): apply to the findings (FR-10 summary and exit code)

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
	return c.listServers(res)
}

// scanAuto looks for the config files of the known clients, in the home
// directory and in the working directory.
func (c *cli) scanAuto(ctx context.Context, ignoreIDs []string) int {
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
	_ = c.loadIgnore(wd, ignoreIDs) // TODO(#40): apply to the findings (FR-10 summary and exit code)
	return c.listServers(discover.Discover(ctx, discover.Options{Home: home, WorkDir: wd}))
}

// loadIgnore builds the ignore list: the entries of .mcpmoat-ignore in the
// directory wd, then one entry for each --ignore ID in ids. ids holds only
// valid rule IDs: the --ignore flag checks them. An empty wd means that the
// working directory is not known, so loadIgnore reads no file.
//
// Every problem with the file is a warning on stderr, not an error: the scan
// goes on. A file that loadIgnore cannot read gives no entries. The warnings
// and the read error never hold file content. The error holds the path, so
// termsafe.Quote escapes it. When the file gives one or more entries,
// loadIgnore prints their number, because the file is untrusted and can hide
// findings. The --ignore IDs come from the user, so they give no notice.
func (c *cli) loadIgnore(wd string, ids []string) rules.IgnoreList {
	var list rules.IgnoreList
	if wd != "" {
		fromFile, warnings, err := rules.ReadIgnoreFile(wd)
		if err != nil {
			// The error text already starts with "read ignore file <path>",
			// so the line does not name the file again.
			fprintf(c.stderr, "mcpmoat scan: warning: %s; mcpmoat uses no entries from it\n", termsafe.Quote(err.Error()))
		}
		for _, w := range warnings {
			fprintf(c.stderr, "mcpmoat scan: warning: %s\n", w)
		}
		switch n := fromFile.Len(); {
		case n == 1:
			fprintf(c.stderr, "mcpmoat scan: using 1 entry from %s\n", rules.IgnoreFileName)
		case n > 1:
			fprintf(c.stderr, "mcpmoat scan: using %d entries from %s\n", n, rules.IgnoreFileName)
		}
		list = fromFile
	}
	for _, id := range ids {
		list.Add(rules.IgnoreEntry{RuleID: id})
	}
	return list
}

// configErrorHint is the line that listServers prints after the file
// problems, when it printed the table. It is fixed text: it holds no path and
// no config text.
const configErrorHint = "mcpmoat scan: a config file has a problem; " +
	"the table can miss servers that the client loads"

// noRulesText says that --no-connect applies no rules yet (they come in M4),
// so exit code 0 must not read as "the servers are safe". noRulesNotice and
// the "Scan output" note of scanUsage both use it, so the two say the same.
const noRulesText = "no rules are applied yet, so exit code 0 does not mean that the servers are safe"

// noRulesNotice is the line that listServers prints on stderr when the scan
// exits with 0. It is a notice, not a warning or an error, and it is fixed
// text.
const noRulesNotice = "mcpmoat scan: " + noRulesText

// listServers prints the server table on stdout and the file problems on
// stderr, and returns the exit code. The runScan doc holds the exit-code
// contract.
func (c *cli) listServers(res discover.Result) int {
	// Do not use fprintf for the table: a write error (a closed pipe, for
	// example) must give exit code 2.
	if err := report.WriteServers(c.stdout, res.Servers); err != nil {
		fprintf(c.stderr, "mcpmoat scan: cannot write output\n")
		// stderr can still work. The file problems are the reason for a
		// failed scan, so the user must still see them.
		c.printFileErrors(res.Errors)
		return exitError
	}

	if len(res.Errors) == 0 {
		fprintf(c.stderr, "%s\n", noRulesNotice)
		return exitOK
	}
	// Print the problems in the order of the result, then the hint.
	c.printFileErrors(res.Errors)
	fprintf(c.stderr, "%s\n", configErrorHint)
	return exitError
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
