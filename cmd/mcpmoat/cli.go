package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"text/tabwriter"

	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// Exit codes (PRD FR-16). Exit code 1 means "findings at or above --fail-on".
// It has no constant yet because no command reports findings before M2.
const (
	exitOK    = 0 // success, no findings
	exitError = 2 // execution or usage error
)

// options holds the resolved global flags. The cli passes it explicitly to
// each command, so commands never read global state.
type options struct {
	noColor bool
}

// cli holds everything a command needs from the outside world. Tests build a
// cli with fake writers and a fake getenv instead of touching the real process.
type cli struct {
	stdout, stderr io.Writer
	getenv         func(string) string
	build          buildInfo
	// homeDir returns the user's home directory. run sets it to os.UserHomeDir.
	// Tests inject a fixture path.
	homeDir func() (string, error)
	// getwd returns the current working directory. run sets it to os.Getwd.
	getwd func() (string, error)
}

// command is one subcommand of mcpmoat.
type command struct {
	name    string
	summary string
	run     func(opts options, args []string) int
}

// run builds a cli from the real process environment and runs it. It returns
// the exit code. main passes that code to os.Exit.
//
// This is the only place that reads the linker variables (version, commit and
// date), the home directory and the working directory.
func run(args []string, stdout, stderr io.Writer) int {
	c := &cli{
		stdout:  stdout,
		stderr:  stderr,
		getenv:  os.Getenv,
		build:   resolveBuildInfo(buildInfo{version: version, commit: commit, date: date}, debug.ReadBuildInfo),
		homeDir: os.UserHomeDir,
		getwd:   os.Getwd,
	}
	return c.dispatch(args)
}

// commands returns the subcommands in the order that help shows them.
//
// This is a method and not a package-level variable for two reasons. A
// package variable that lists c.runHelp would create an initialization cycle,
// because runHelp calls usage and usage reads the list. A method also avoids
// global state.
func (c *cli) commands() []command {
	return []command{
		{name: "scan", summary: "Discover MCP servers, inspect them and report findings", run: c.runScan},
		{name: "pin", summary: "Accept a changed server after you review it", run: c.runPin},
		{name: "version", summary: "Print the version", run: c.runVersion},
		{name: "help", summary: "Show this help", run: c.runHelp},
	}
}

// dispatch parses the global flags, finds the command and runs it. All exit
// codes for usage problems are chosen here, in one place.
func (c *cli) dispatch(args []string) int {
	opts, rest, err := c.parseGlobals(args)
	if err != nil {
		// -h and --help are not errors: show help on stdout and exit 0.
		if errors.Is(err, flag.ErrHelp) {
			c.usage(c.stdout)
			return exitOK
		}
		// The flag error holds untrusted argv inside its own text, and the
		// flag package gives no way to get the argument out. So
		// termsafe.Quote escapes the whole message: it stays as it is when it
		// is safe, and it shows quoted only when it holds an unsafe rune.
		// quoteArg, for an argument that we hold on its own, always quotes.
		// scan.go does the same for the scan flags.
		fprintf(c.stderr, "mcpmoat: %s\n\n", termsafe.Quote(err.Error()))
		c.usage(c.stderr)
		return exitError
	}

	if len(rest) == 0 {
		c.usage(c.stderr)
		return exitError
	}

	name := rest[0]
	for _, cmd := range c.commands() {
		if cmd.name == name {
			return cmd.run(opts, rest[1:])
		}
	}

	// The command name comes from the user, so quoteArg escapes it.
	fprintf(c.stderr, "mcpmoat: unknown command %s\n\n", quoteArg(name))
	c.usage(c.stderr)
	return exitError
}

// parseGlobals parses the global flags at the start of args. It returns the
// resolved options and what is left: the command name and its arguments.
//
// Parsing stops at the first argument that is not a flag, so global flags
// must come before the command. On -h or --help the error is flag.ErrHelp.
func (c *cli) parseGlobals(args []string) (options, []string, error) {
	fs := flag.NewFlagSet("mcpmoat", flag.ContinueOnError)
	// The flag package would print its own usage text on errors. We print our
	// own, so we send the package output to io.Discard.
	fs.SetOutput(io.Discard)
	noColor := fs.Bool("no-color", false, "disable colored output")

	if err := fs.Parse(args); err != nil {
		return options{}, nil, err
	}
	return options{noColor: colorDisabled(*noColor, c.getenv)}, fs.Args(), nil
}

// colorDisabled reports whether colored output must stay off. Color is off if
// the --no-color flag is set or if NO_COLOR has any non-empty value, even "0"
// (see https://no-color.org/ and PRD FR-14).
//
// Terminal detection (color only when stdout is a terminal) comes in M6 with
// the report output. Until then no command prints color.
func colorDisabled(noColorFlag bool, getenv func(string) string) bool {
	return noColorFlag || getenv("NO_COLOR") != ""
}

// usage writes the help text to w. The command list comes from commands(), so
// a new command shows up in help without a second edit.
func (c *cli) usage(w io.Writer) {
	fprintf(w, "mcpmoat finds malicious or tampered MCP servers. It runs offline.\n\n")
	fprintf(w, "Usage:\n  mcpmoat [--no-color] <command> [arguments]\n\n")

	fprintf(w, "Commands:\n")
	// tabwriter aligns the columns. Cells end at a tab. Flush writes the
	// aligned text to w.
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	for _, cmd := range c.commands() {
		fprintf(tw, "  %s\t%s\n", cmd.name, cmd.summary)
	}
	_ = tw.Flush() // the write error is ignored on purpose, see fprintf

	fprintf(w, "\nGlobal flags (before the command):\n")
	fprintf(w, "  --no-color   Disable colored output (also set by the NO_COLOR environment variable)\n")

	fprintf(w, "\n")
	scanUsage(w)

	fprintf(w, "\nExit codes:\n")
	fprintf(w, "  0  no findings\n")
	fprintf(w, "  1  findings at or above --fail-on\n")
	fprintf(w, "  2  execution error\n")
	fprintf(w, "     (scan also exits 2 when a config file has a problem; a missing file is not a problem\n")
	fprintf(w, "     in auto-discovery, but a missing --config file is)\n")
}

// scanUsage writes the flags and the output notes of the scan command to w.
// usage includes it, and "mcpmoat scan -h" prints it alone. It is a plain
// function: it needs nothing from the cli.
func scanUsage(w io.Writer) {
	fprintf(w, "Scan flags (after \"scan\"):\n")
	// Padding 2 keeps the descriptions in one column, like the text in usage.
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fprintf(tw, "  --no-connect\tList the servers in the configs. Starts no process and opens no connection\n")
	fprintf(tw, "  --config <file>\tRead only this file (Claude Code JSON, Cursor JSON or Codex TOML); skips auto-discovery\n")
	fprintf(tw, "  \tA file that is not your own global config is read as an untrusted project file\n")
	_ = tw.Flush() // the write error is ignored on purpose, see fprintf

	fprintf(w, "\nScan output:\n")
	fprintf(w, "  A heuristic masks secret-like arguments. Review the output before you share it.\n")
	// The same text as the notice that a scan with exit code 0 prints.
	fprintf(w, "  --no-connect: %s.\n", noRulesText)
}

// fprintf writes formatted text to w and ignores the write error on purpose.
// If stdout or stderr is closed (a broken pipe, for example), there is nobody
// left to tell, and the exit code still carries the result. Keeping the
// "_, _ =" in this one place means the rest of the code stays short, and the
// errcheck linter has nothing to flag.
//
// Use it only for help and diagnostic text. Do not use it for the findings
// report (M6): if that write fails, the exit code must say so (exit 2), or a
// broken pipe could look like "no findings".
func fprintf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

// quoteArg returns one command-line argument as a quoted string for an error
// message. The argument comes from the user and is untrusted text.
// termsafe.QuoteIf with force escapes every rune that is not safe (which %q
// does not do for blank runes such as U+3164), and it quotes a safe argument
// too: every argument shows in double quotes, and the reader can see where it
// starts and ends.
func quoteArg(s string) string {
	return termsafe.QuoteIf(s, true)
}
