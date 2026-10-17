// Command mcpmoat finds malicious or tampered MCP servers.
//
// It discovers the MCP servers configured for Claude Code, Cursor and Codex,
// inspects them and reports findings. It runs offline: it makes no network
// calls except to the servers you configured.
//
// Usage:
//
//	mcpmoat [--no-color] <command> [arguments]
//
// Run "mcpmoat help" for the list of commands and exit codes.
package main

import "os"

// main only connects the real process to run. It is the only place that
// calls os.Exit, so everything else stays easy to test.
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
