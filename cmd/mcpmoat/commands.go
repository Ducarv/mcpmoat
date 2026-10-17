package main

// This file holds the command handlers. Each one has the signature of
// command.run: it gets the resolved global options and its own arguments, and
// returns the exit code.

// runScan is a stub for "mcpmoat scan". M2 (discovery) replaces it, and M3 to
// M4 extend it with inspection and rules. Until then it exits with code 2, so
// a stub can never look like a clean scan.
func (c *cli) runScan(_ options, _ []string) int {
	fprintf(c.stderr, "mcpmoat scan: not implemented\n")
	return exitError
}

// runPin is a stub for "mcpmoat pin". M5 (pins) replaces it.
func (c *cli) runPin(_ options, _ []string) int {
	fprintf(c.stderr, "mcpmoat pin: not implemented\n")
	return exitError
}

// runVersion implements "mcpmoat version".
func (c *cli) runVersion(_ options, args []string) int {
	if c.rejectArgs("version", args) {
		return exitError
	}
	fprintf(c.stdout, "%s\n", c.build)
	return exitOK
}

// runHelp implements "mcpmoat help".
func (c *cli) runHelp(_ options, args []string) int {
	if c.rejectArgs("help", args) {
		return exitError
	}
	c.usage(c.stdout)
	return exitOK
}

// rejectArgs is for commands that take no arguments. If args is not empty, it
// prints an error to stderr and returns true. The arguments come from the
// user, so they are printed with %q to stop terminal escape injection.
func (c *cli) rejectArgs(name string, args []string) bool {
	if len(args) == 0 {
		return false
	}
	fprintf(c.stderr, "mcpmoat %s: unexpected arguments %q\n", name, args)
	fprintf(c.stderr, "Run \"mcpmoat help\" for usage.\n")
	return true
}
