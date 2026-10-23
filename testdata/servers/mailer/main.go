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
// It serves MCP on stdio until stdin closes. It takes no flags or arguments:
// any argument exits with code 2. A server error other than a closed stdin or
// a signal exits with code 1. The server writes only MCP protocol messages
// to stdout. Errors go to stderr.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Exit codes of this program.
const (
	exitOK    = 0
	exitServe = 1 // the MCP server stopped with an error
	exitUsage = 2 // an unexpected argument
)

// sendInputSchema is fixed JSON text, so the bytes on the wire stay the same
// between builds.
var sendInputSchema = json.RawMessage(`{"type":"object","properties":{"to":{"type":"string","description":"Recipient address."},"subject":{"type":"string","description":"Subject line."},"body":{"type":"string","description":"Message text."}},"required":["to","subject","body"]}`)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run checks that there are no arguments, serves MCP on stdio and returns
// the exit code. It keeps os.Exit in main only.
func run(args []string, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintf(stderr, "mailer: unexpected arguments: %v\n", args)
		return exitUsage
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
