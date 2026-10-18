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

// listServers prints the server table on stdout and the file problems on
// stderr. In strict mode (--config) any problem gives exit code 2. In auto
// mode a problem is only a warning, because one bad file must not hide the
// servers in the other files.
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

	prefix := "mcpmoat scan: warning: "
	if strict {
		prefix = "mcpmoat scan: "
	}
	c.printFileErrors(res.Errors, prefix)

	if strict && len(res.Errors) > 0 {
		return exitError
	}
	return exitOK
}

// printFileErrors writes one line per file problem on stderr.
func (c *cli) printFileErrors(errs []*discover.FileError, prefix string) {
	// FileError.Error already escapes the path and the server name.
	for _, e := range errs {
		fprintf(c.stderr, "%s%s\n", prefix, e.Error())
	}
}
