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

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// shutdownSignals are the signals that end a scan or a pin. Ctrl-C is
// os.Interrupt, SIGTERM is "kill" and SIGHUP is a closed terminal. All three
// exist in package syscall on every platform that mcpmoat builds for.
//
// Without this handler the signal would end mcpmoat only. mcpmoat starts each
// stdio server in its own session (see internal/inspect), so the terminal
// sends no signal to it, and it would live on without its parent.
var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}

// main only connects the real process to runWithContext. It is the only place
// that calls os.Exit, so everything else stays easy to test.
//
// The context ends when the process gets one of shutdownSignals. Commands pass
// it to inspect.Run, which then stops the servers that mcpmoat started. After
// the first signal, stop restores the default behavior, so a second Ctrl-C
// ends mcpmoat at once if a server does not stop.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals...)
	go func() {
		<-ctx.Done()
		stop()
	}()
	code := runWithContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
