package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/report"
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

	// fs.Func calls the function once for each time the user gives --config.
	// An error from it becomes a flag error: exit code 2 with a clear message.
	// An empty value is refused, so configPath != "" means --config was given.
	var configPath string
	fs.Func("config", "", func(value string) error {
		if configPath != "" {
			return errors.New("--config given more than once")
		}
		if value == "" || isScanFlag(fs, value) {
			return errors.New("--config needs a file name")
		}
		configPath = value
		return nil
	})

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			scanUsage(c.stdout)
			return exitOK
		}
		// The flag error holds untrusted argv, so termsafe.Quote escapes it.
		fprintf(c.stderr, "mcpmoat scan: %s\n", termsafe.Quote(err.Error()))
		fprintf(c.stderr, "Run \"mcpmoat help\" for usage.\n")
		return exitError
	}
	if c.rejectArgs("scan", fs.Args()) {
		return exitError
	}

	if !*noConnect {
		fprintf(c.stderr, "mcpmoat scan: connecting to servers is not implemented yet; use --no-connect\n")
		return exitError
	}

	// context.Background() never ends. M3 adds signal handling in main, and
	// main will pass a context that ends on Ctrl-C.
	ctx := context.Background()

	if configPath != "" {
		return c.scanConfig(ctx, configPath)
	}
	return c.scanAuto(ctx)
}

// isScanFlag reports whether value looks like a flag of fs, in any form that
// the flag package accepts: "-name", "--name", "-name=x" or "--name=x". -h and
// -help count too, because the flag package treats them as a help request.
// The flag package takes the next argument as the value of --config, so
// "scan --config --no-connect" would use "--no-connect" as a file name. We
// reject that case. The names come from fs, so a new scan flag is covered
// without a second edit. A real file name that starts with "-" can be given
// as ./-name.
func isScanFlag(fs *flag.FlagSet, value string) bool {
	name, ok := strings.CutPrefix(value, "-")
	if !ok {
		return false
	}
	name = strings.TrimPrefix(name, "-")
	name, _, _ = strings.Cut(name, "=")
	return fs.Lookup(name) != nil || name == "h" || name == "help"
}

// scanConfig reads the one file that --config names.
func (c *cli) scanConfig(ctx context.Context, path string) int {
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
func (c *cli) scanAuto(ctx context.Context) int {
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
	return c.listServers(discover.Discover(ctx, discover.Options{Home: home, WorkDir: wd}))
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
// stderr. Any problem gives exit code 2, after the table and all problems are
// printed (see runScan). Without a problem it prints noRulesNotice and gives
// exit code 0.
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
