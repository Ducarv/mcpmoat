package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"text/tabwriter"
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
// date).
func run(args []string, stdout, stderr io.Writer) int {
	c := &cli{
		stdout: stdout,
		stderr: stderr,
		getenv: os.Getenv,
		build:  resolveBuildInfo(buildInfo{version: version, commit: commit, date: date}, debug.ReadBuildInfo),
	}
	return c.run(args)
}

// commands returns the subcommands in the order that help shows them.
//
// This is a method and not a package-level variable for two reasons. A
// package variable that lists c.runHelp would create an initialization cycle,
// because runHelp calls usage and usage reads the list. A method also avoids
// global state.
func (c *cli) commands() []command {
	return []command{
		{"scan", "Discover MCP servers, inspect them and report findings", c.runScan},
		{"pin", "Accept a changed server after you review it", c.runPin},
		{"version", "Print the version", c.runVersion},
		{"help", "Show this help", c.runHelp},
	}
}

// run parses the global flags, finds the command and runs it. All exit codes
// for usage problems are chosen here, in one place.
func (c *cli) run(args []string) int {
	fs := flag.NewFlagSet("mcpmoat", flag.ContinueOnError)
	// The flag package would print its own usage text on errors. We print our
	// own, so we send the package output to io.Discard.
	fs.SetOutput(io.Discard)
	noColor := fs.Bool("no-color", false, "disable colored output")

	if err := fs.Parse(args); err != nil {
		// -h and --help are not errors: show help on stdout and exit 0.
		if errors.Is(err, flag.ErrHelp) {
			c.usage(c.stdout)
			return exitOK
		}
		// The flag error contains untrusted argv, so it is quoted to stop
		// terminal escape injection.
		fprintf(c.stderr, "mcpmoat: %q\n\n", err.Error())
		c.usage(c.stderr)
		return exitError
	}

	// fs.Args() holds what is left after the global flags: the command name
	// and the arguments for that command.
	rest := fs.Args()
	if len(rest) == 0 {
		c.usage(c.stderr)
		return exitError
	}

	opts := options{noColor: colorDisabled(*noColor, c.getenv)}
	name := rest[0]
	for _, cmd := range c.commands() {
		if cmd.name == name {
			return cmd.run(opts, rest[1:])
		}
	}

	// The command name comes from the user, so we print it with %q.
	fprintf(c.stderr, "mcpmoat: unknown command %q\n\n", name)
	c.usage(c.stderr)
	return exitError
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

	fprintf(w, "\nExit codes:\n")
	fprintf(w, "  0  no findings\n")
	fprintf(w, "  1  findings at or above --fail-on\n")
	fprintf(w, "  2  execution error\n")
}

// runHelp implements "mcpmoat help".
func (c *cli) runHelp(_ options, args []string) int {
	if len(args) > 0 {
		fprintf(c.stderr, "mcpmoat help: unexpected arguments %q\n", args)
		fprintf(c.stderr, "Run \"mcpmoat help\" for usage.\n")
		return exitError
	}
	c.usage(c.stdout)
	return exitOK
}

// fprintf writes formatted text to w and ignores the write error on purpose.
// If stdout or stderr is closed (a broken pipe, for example), there is nobody
// left to tell, and the exit code still carries the result. Keeping the
// "_, _ =" in this one place means the rest of the code stays short, and the
// errcheck linter has nothing to flag.
func fprintf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}
