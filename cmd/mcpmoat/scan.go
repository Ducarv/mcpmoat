package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// runScan implements "mcpmoat scan". For now it only supports --no-connect: it
// reads the client configs and lists the servers it finds. It starts no
// process and opens no network connection. M3 adds the connection step, and M4
// adds the rules.
//
// Exit codes:
//   - 0: the table is printed. In auto-discovery, a problem with one of the
//     user's own files (~/.claude.json, ~/.cursor/mcp.json, the Codex file)
//     is only a warning on stderr, because one bad file must not hide the
//     servers in the other files.
//   - 2: a flag or usage error, no home or working directory, a write error
//     on stdout, any problem with the file named by --config, or, in
//     auto-discovery, a problem with a project file in the working directory
//     (<WorkDir>/.mcp.json or <WorkDir>/.cursor/mcp.json, FileError.Untrusted).
//     A cloned repository can ship that file, and a file that mcpmoat cannot
//     read or refuses (for example a symlink out of the project) can hide
//     servers that the client still loads. So the scan must not look clean:
//     scan prints the table and all problems first, and then exits with 2.
func (c *cli) runScan(_ options, args []string) int {
	fs := flag.NewFlagSet("mcpmoat scan", flag.ContinueOnError)
	// Like parseGlobals: we print our own messages, not the flag package.
	// So the usage strings below are never shown. scanUsage prints the help.
	fs.SetOutput(io.Discard)
	noConnect := fs.Bool("no-connect", false, "list the servers in the configs; start no process and open no connection")

	// fs.Func calls the function once for each time the user gives --config.
	// An error from it becomes a flag error: exit code 2 with a clear message.
	var configPath string
	configSet := false
	fs.Func("config", "read only this file; skip auto-discovery", func(value string) error {
		if configSet {
			return errors.New("--config given more than once")
		}
		if value == "" || isScanFlag(value) {
			return errors.New("--config needs a file name")
		}
		configPath = value
		configSet = true
		return nil
	})

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			c.scanUsage(c.stdout)
			return exitOK
		}
		// The flag error holds untrusted argv, so it is quoted.
		fprintf(c.stderr, "mcpmoat scan: %q\n", err.Error())
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

	if configSet {
		// The user named the file, so any problem with it is an error (strict).
		return c.listServers(discover.ReadConfig(ctx, configPath), true)
	}
	return c.scanAuto(ctx)
}

// isScanFlag reports whether value is the name of a scan flag. The flag package
// takes the next argument as the value of --config, so "scan --config
// --no-connect" would use "--no-connect" as a file name. We reject that case.
// A real file name that starts with "-" can be given as ./-name.
func isScanFlag(value string) bool {
	switch value {
	case "--no-connect", "-no-connect", "--config", "-config", "-h", "-help", "--help":
		return true
	}
	return false
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
	res := discover.Discover(ctx, discover.Options{Home: home, WorkDir: wd})
	return c.listServers(res, false)
}

// untrustedHint is the line that listServers prints after the file problems
// when a project file in the working directory had a problem. It is fixed
// text: it holds no path and no config text.
const untrustedHint = "mcpmoat scan: a project config in the working directory has a problem; " +
	"the table can miss servers that the client loads\n"

// listServers prints the server table on stdout and the file problems on
// stderr. In strict mode (--config) any problem gives exit code 2. In auto
// mode a problem with a trusted file is only a warning, because one bad file
// must not hide the servers in the other files. A problem with an untrusted
// project file (FileError.Untrusted) is an error and gives exit code 2 after
// the table and all problems are printed (see runScan).
func (c *cli) listServers(res discover.Result, strict bool) int {
	// In strict mode, a file that failed to load and gave no servers is a plain
	// error. The "No MCP servers found." line would be wrong and misleading
	// here, so we skip the table and print only the errors.
	if strict && len(res.Servers) == 0 && len(res.Errors) > 0 {
		c.printFileErrors(res.Errors, "mcpmoat scan: ")
		return exitError
	}

	// Do not use fprintf for the table: a write error (a closed pipe, for
	// example) must give exit code 2.
	if err := report.WriteServers(c.stdout, res.Servers); err != nil {
		fprintf(c.stderr, "mcpmoat scan: cannot write output\n")
		return exitError
	}

	if strict {
		c.printFileErrors(res.Errors, "mcpmoat scan: ")
		if len(res.Errors) > 0 {
			return exitError
		}
		return exitOK
	}

	// Auto mode. Print the problems in the order of the result. A problem
	// with an untrusted project file is an error, every other one a warning.
	untrusted := false
	for _, e := range res.Errors {
		if e.Untrusted {
			untrusted = true
			c.printFileErrors([]*discover.FileError{e}, "mcpmoat scan: ")
			continue
		}
		c.printFileErrors([]*discover.FileError{e}, "mcpmoat scan: warning: ")
	}
	if untrusted {
		fprintf(c.stderr, "%s", untrustedHint)
		return exitError
	}
	return exitOK
}

// printFileErrors writes one line per file problem on stderr. A line holds
// only the fields of the FileError (path, position, project path, server
// name, fixed reason and OS error), never config text.
func (c *cli) printFileErrors(errs []*discover.FileError, prefix string) {
	// FileError.Error already escapes the path and the server name.
	for _, e := range errs {
		fprintf(c.stderr, "%s%s\n", prefix, e.Error())
	}
}
