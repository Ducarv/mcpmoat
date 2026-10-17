package main

// The commands below are stubs. They print an error and exit with code 2 until
// the real code arrives (see the milestones in docs/PRD.md, section 9).

// runScan is a stub for "mcpmoat scan". M2 (discovery) replaces it, and M3 to
// M4 extend it with inspection and rules.
func (c *cli) runScan(_ options, _ []string) int {
	fprintf(c.stderr, "mcpmoat scan: not implemented\n")
	return exitError
}

// runPin is a stub for "mcpmoat pin". M5 (pins) replaces it.
func (c *cli) runPin(_ options, _ []string) int {
	fprintf(c.stderr, "mcpmoat pin: not implemented\n")
	return exitError
}
