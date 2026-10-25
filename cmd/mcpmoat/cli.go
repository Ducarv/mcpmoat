package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"text/tabwriter"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// Exit codes (PRD FR-16): 0 no findings, 1 findings at or above --fail-on,
// 2 execution or usage error. Until --fail-on exists (issue #65), the limit
// is high, the PRD default.
const (
	exitOK       = 0 // success, no findings
	exitFindings = 1 // a finding that is not ignored has severity high or above
	exitError    = 2 // execution or usage error
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
	// stdoutIsTTY is true when stdout is a terminal. runWithContext sets it
	// from the stdout writer, when that writer is an *os.File (see
	// isTerminal). Tests set it directly.
	stdoutIsTTY bool
	// homeDir returns the user's home directory. runWithContext sets it to
	// os.UserHomeDir. Tests inject a fixture path.
	homeDir func() (string, error)
	// getwd returns the current working directory. runWithContext sets it to
	// os.Getwd.
	getwd func() (string, error)
	// inspector connects to the servers when scan runs without --no-connect.
	// runWithContext sets it to the SDK inspector. Tests inject a fake from
	// internal/inspect/inspecttest, so they start no process and open no
	// connection.
	inspector inspect.Inspector
	// ctx ends when the process gets a signal (see main). It is a field and
	// not a parameter of command.run, so that every command keeps one
	// signature. Use the ctxOrBackground method, which also handles a nil ctx.
	ctx context.Context
}

// ctxOrBackground returns the context of the process. A cli built without one
// (in a test, for example) gets a context that never ends.
func (c *cli) ctxOrBackground() context.Context {
	if c.ctx == nil {
		return context.Background()
	}
	return c.ctx
}

// command is one subcommand of mcpmoat.
type command struct {
	name    string
	summary string
	run     func(opts options, args []string) int
}

// runWithContext builds a cli from the real process environment and runs it.
// It returns the exit code. main passes that code to os.Exit. When ctx ends,
// scan and pin stop the servers that they started and exit with 2 (see
// runScan).
//
// This is the only place that reads the linker variables (version, commit and
// date), the home directory and the working directory. It also decides about
// colour: only when stdout is an *os.File that is a terminal (see isTerminal).
// Any other writer gets plain text.
func runWithContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	c := &cli{
		ctx:     ctx,
		stdout:  stdout,
		stderr:  stderr,
		getenv:  os.Getenv,
		build:   resolveBuildInfo(buildInfo{version: version, commit: commit, date: date}, debug.ReadBuildInfo),
		homeDir: os.UserHomeDir,
		getwd:   os.Getwd,
		// The zero SDKOptions refuse servers from untrusted project files and
		// servers that the client config turns off. scan has no flag to allow
		// them.
		inspector: inspect.New(inspect.SDKOptions{}),
	}
	// Decide from the writer that the report goes to, not from os.Stdout. A
	// writer that is not a file (a buffer, a pipe wrapper) is never a terminal.
	if f, ok := stdout.(*os.File); ok {
		c.stdoutIsTTY = isTerminal(f)
	}
	return c.dispatch(args)
}

// isTerminal reports whether f is a terminal. It uses only the standard
// library: a terminal is a character device. /dev/null is a character device
// too, so output sent there may get colour. That is harmless.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
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
// scan uses this result together with cli.stdoutIsTTY: colour is on only when
// stdout is a terminal and neither --no-color nor NO_COLOR is set.
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

	fprintf(w, "\n")
	pinUsage(w)

	fprintf(w, "\nExit codes:\n")
	fprintf(w, "  0  no findings\n")
	fprintf(w, "  1  findings at or above --fail-on\n")
	fprintf(w, "  2  execution error\n")
	fprintf(w, "     (scan also exits 2 when a config file has a problem or when pins.json cannot be read\n")
	fprintf(w, "     or saved, or when it is stopped by a signal; a missing file is not a problem in auto-discovery,\n")
	fprintf(w, "     but a missing --config file is. A server that fails or times out is a warning and does not\n")
	fprintf(w, "     change the exit code, unless its pins are already stored: then it is a high finding and scan exits 1)\n")
}

// scanUsage writes the flags and the output notes of the scan command to w.
// usage includes it, and "mcpmoat scan -h" prints it alone. It is a plain
// function: it needs nothing from the cli.
func scanUsage(w io.Writer) {
	fprintf(w, "Scan flags (after \"scan\"):\n")
	// Padding 2 keeps the descriptions in one column, like the text in usage.
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fprintf(tw, "  --no-connect\tList the servers in the configs and check the configs. Starts no process and opens no connection\n")
	fprintf(tw, "  --config <file>\tRead only this file (Claude Code JSON, Cursor JSON or Codex TOML); skips auto-discovery\n")
	fprintf(tw, "  \tA file that is not your own global config is read as an untrusted project file\n")
	fprintf(tw, "  --rules <dir>\tLoad extra *.yaml and *.yml rules from this folder (not recursive)\n")
	fprintf(tw, "  \tA folder with no rule file, or a rule ID that clashes with a built-in rule, is an error\n")
	fprintf(tw, "  --timeout <duration>\tTime limit for each server, a Go duration such as 10s or 1m30s (default %s)\n", inspect.DefaultTimeout)
	fprintf(tw, "  --concurrency <n>\tMaximum number of servers inspected at the same time (default %d)\n", inspect.DefaultConcurrency)
	fprintf(tw, "  \tThe two flags above apply when scan connects to servers. --no-connect ignores them, but still checks them\n")
	fprintf(tw, "  --no-color\tDisable colored output (also set by the NO_COLOR environment variable). It works before or after \"scan\"\n")
	fprintf(tw, "  --ignore <rule-id>\tIgnore all findings of this rule; repeatable\n")
	fprintf(tw, "  \tA %s file in the working directory also ignores findings: one \"RULE-ID [server[/tool]]\" per line; \"# ...\" on its own line or after the entry is a comment\n", rules.IgnoreFileName)
	fprintf(tw, "  \tThe file cannot ignore the pin rules (MOAT-T2-*): it can come from a cloned repository. Use --ignore for them\n")
	_ = tw.Flush() // the write error is ignored on purpose, see fprintf

	fprintf(w, "\nScan output:\n")
	fprintf(w, "  The report shows the server table, a summary for each server and the findings grouped by severity, each with its risk and fix.\n")
	fprintf(w, "  The summary of a server has its status (ok, timeout, failed or not inspected), its tool and finding counts and its connection warnings.\n")
	fprintf(w, "  Color is on only when stdout is a terminal. --no-color or the NO_COLOR environment variable turns it off.\n")
	fprintf(w, "  A heuristic masks secret-like arguments. Review the output before you share it.\n")
	fprintf(w, "  scan connects to each server (a stdio server is started) and lists its tools, then checks them against the pins in\n")
	fprintf(w, "  pins.json ($XDG_CONFIG_HOME/mcpmoat/, else ~/.config/mcpmoat/). The first run pins the tools of a server.\n")
	fprintf(w, "  Later runs report a changed tool (MOAT-T2-001), a new tool (MOAT-T2-002), a removed tool (MOAT-T2-003) and a tool\n")
	fprintf(w, "  that cannot be verified (MOAT-T2-004), with a diff for each changed, new or not verified tool. \"pin --accept <server>\" accepts the changes.\n")
	fprintf(w, "  A new tool is medium, so alone it does not give exit code 1; next to a removed tool (a likely rename) it is high.\n")
	fprintf(w, "  A server whose tools cannot be pinned is high (MOAT-T2-004).\n")
	fprintf(w, "  For each pinned server with a finding, scan prints \"To accept <server>: mcpmoat pin --accept <server> --expect <digest>\".\n")
	fprintf(w, "  The digest covers the tools that scan saw, so pin saves only those tools. Review the diff, then run that line.\n")
	fprintf(w, "  A server that fails, times out, or that scan refuses to start (an untrusted or turned-off server) is a warning in its summary on stdout.\n")
	fprintf(w, "  If that server is already pinned and failed or timed out, it is also a finding (MOAT-T2-004, high, exit code 1).\n")
	fprintf(w, "  The warnings of an inspection (cleartext-secrets, undeclared-capability, dns-pin-unavailable) show in the summary of that server, on stdout.\n")
	fprintf(w, "  scan reads pins.json before it starts a server, and reads it again just before it saves the first-run pins.\n")
	fprintf(w, "  Ctrl-C (or SIGTERM or SIGHUP) stops the servers, saves no pins and exits 2.\n")
	fprintf(w, "  --no-connect: scan runs only the built-in config rules (T4 and T5). It reads and writes no pins.\n")
	fprintf(w, "  The tool rules (YAML) are not applied to tools yet. Rules from --rules are loaded and checked, but not applied yet.\n")
	fprintf(w, "  Exit code 1 means a finding of severity high or above that is not ignored.\n")
}

// fprintf writes formatted text to w and ignores the write error on purpose.
// If stdout or stderr is closed (a broken pipe, for example), there is nobody
// left to tell, and the exit code still carries the result. Keeping the
// "_, _ =" in this one place means the rest of the code stays short, and the
// errcheck linter has nothing to flag.
//
// Use it only for help and diagnostic text. Do not use it for the report on
// stdout: if that write fails, the exit code must say so (exit 2), or a
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
