// Command mailer is a TEST FIXTURE for mcpmoat. It is not a product.
//
// It is a benign fake MCP server and the victim of the T3 (cross-server
// tool shadowing) scenario. The "shadowing" fixture
// (testdata/servers/shadowing) tries to change how the model uses the tool
// "send_email" of this server. This server itself must look clean: no
// instructions in its text, so no rule reports a finding on it alone. The
// tool does not send anything. It ignores its arguments and returns the
// fixed text "queued (fixture, nothing sent)". The server makes no network
// call, starts no process and reads or writes no file.
//
// The server speaks MCP over stdio and lists one tool, "send_email".
//
// Flags:
//
//	-mode string
//	    ok        serve MCP on stdio until stdin closes (default)
//	    crash     exit with code 3 before the MCP handshake
//	    hang-init never read stdin and never reply
//
// Bad flags or an unknown mode exit with code 2. A server error other than a
// closed stdin or a signal exits with code 1. The server writes only MCP
// protocol messages to stdout. Errors go to stderr.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Exit codes of this program.
const (
	exitOK    = 0
	exitServe = 1 // the MCP server stopped with an error
	exitUsage = 2 // bad flags or unknown mode
	exitCrash = 3 // the crash mode
)

// The modes of the -mode flag.
const (
	modeOK       = "ok"
	modeCrash    = "crash"
	modeHangInit = "hang-init"
)

// modes lists the valid values of -mode, for the flag help and the check.
var modes = []string{modeOK, modeCrash, modeHangInit}

// sendInputSchema is fixed JSON text, so the bytes on the wire stay the same
// between builds.
var sendInputSchema = json.RawMessage(`{"type":"object","properties":{"to":{"type":"string","description":"Recipient address."},"subject":{"type":"string","description":"Subject line."},"body":{"type":"string","description":"Message text."}},"required":["to","subject","body"]}`)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run parses the flags, does the work for the selected mode and returns the
// exit code. It keeps os.Exit in main only.
func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("mailer", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", modeOK, strings.Join(modes, " | "))
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "mailer: unexpected arguments: %v\n", fs.Args())
		return exitUsage
	}
	if !slices.Contains(modes, *mode) {
		fmt.Fprintf(stderr, "mailer: unknown mode %q\n", *mode)
		return exitUsage
	}

	switch *mode {
	case modeCrash:
		return exitCrash
	case modeHangInit:
		// Do not use select{}: with no other goroutines the Go runtime
		// reports a deadlock and exits. A sleeping goroutine does not count.
		for {
			time.Sleep(time.Hour)
		}
	}

	// The context ends on Ctrl+C or SIGTERM, so the server can stop cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := newServer().Run(ctx, &mcp.StdioTransport{})
	// A closed stdin or a signal is a normal end for this server.
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		fmt.Fprintf(stderr, "mailer: %v\n", err)
		return exitServe
	}
	return exitOK
}

// newServer returns the server with its one tool.
func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "mailer", Version: "1.0.0"}, nil)

	server.AddTool(&mcp.Tool{
		Name:        "send_email",
		Description: "Send an email to one recipient.",
		InputSchema: sendInputSchema,
	}, sendEmail)

	return server
}

// sendEmail sends nothing. It ignores its arguments and returns a fixed text.
func sendEmail(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "queued (fixture, nothing sent)"}}}, nil
}
