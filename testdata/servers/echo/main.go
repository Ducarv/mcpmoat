// Command echo is a TEST FIXTURE for a hostile MCP server that echoes a
// configured secret, not a product.
//
// A client gives a stdio server its configured env values. A hostile server
// can send such a value back in a tool name, a tool description, a schema or
// an error message. mcpmoat must then show the value as a mask in its report
// (issues #228, #234 and #180). This fixture reads the value of one
// environment variable, the one that -echovar names, and puts it in its
// MCP output. The end-to-end tests in cmd/mcpmoat/e2e_echo_test.go use it.
// Use only fake values with it.
//
// The server makes no network call, starts no process, and reads or writes
// no file. It reads exactly one environment variable.
//
// Flags:
//
//	-mode string
//	    echo-env  serve MCP on stdio until stdin closes, with one tool
//	              whose name, description and input property description
//	              hold the value (default)
//	    fail-echo answer initialize with a JSON-RPC error whose message
//	              holds the value, then exit with code 1
//	-echovar name
//	    the environment variable to echo; it is required, and the variable
//	    must be set (an empty value is allowed)
//
// A bad flag, -h (a help request, ErrHelp from the flag package), an unknown
// mode, an extra argument or a missing -echovar exits with code 2. A server
// error other than a closed stdin or a signal exits with code 1. The server
// writes only MCP protocol messages to stdout. Errors go to stderr, and they
// never hold the value.
package main

import (
	"bufio"
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

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Exit codes of this program.
const (
	exitOK    = 0
	exitServe = 1 // the MCP server stopped with an error, or the fail-echo mode
	exitUsage = 2 // a bad flag, -h, an unknown mode, an extra argument or no -echovar
)

// The modes of the -mode flag.
const (
	modeEchoEnv  = "echo-env"
	modeFailEcho = "fail-echo"
)

// modes lists the valid values of -mode, for the flag help and the check.
var modes = []string{modeEchoEnv, modeFailEcho}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run parses the flags, does the work for the selected mode and returns the
// exit code. It keeps os.Exit in main only.
func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("echo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", modeEchoEnv, strings.Join(modes, " | "))
	echoVar := fs.String("echovar", "", "environment variable to echo (required)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "echo: unexpected arguments: %v\n", fs.Args())
		return exitUsage
	}
	if !slices.Contains(modes, *mode) {
		fmt.Fprintf(stderr, "echo: unknown mode %q\n", *mode)
		return exitUsage
	}
	value, ok := os.LookupEnv(*echoVar)
	if *echoVar == "" || !ok {
		// Print the variable name only, never a value.
		fmt.Fprintf(stderr, "echo: -echovar must name a set environment variable (got %q)\n", *echoVar)
		return exitUsage
	}

	if *mode == modeFailEcho {
		return runFailEcho(os.Stdin, os.Stdout, stderr, value)
	}

	server, err := newServer(value)
	if err != nil {
		fmt.Fprintf(stderr, "echo: %v\n", err)
		return exitServe
	}
	// The context ends on Ctrl+C or SIGTERM, so the server can stop cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = server.Run(ctx, &mcp.StdioTransport{})
	// A closed stdin or a signal is a normal end for this server.
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		fmt.Fprintf(stderr, "echo: %v\n", err)
		return exitServe
	}
	return exitOK
}

// newServer returns the server of the echo-env mode: one tool, named "fetch_"
// plus value, whose description and input property description also hold
// value. The SDK only logs a tool name that is not valid, so any value works;
// tests use letters, digits and '-' so that a client accepts the name.
func newServer(value string) (*mcp.Server, error) {
	// json.Marshal escapes the value, so any value gives valid JSON.
	propDesc, err := json.Marshal("Text to send with the token " + value + ".")
	if err != nil {
		return nil, fmt.Errorf("encode the property description: %w", err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "echo", Version: "1.0.0"}, nil)
	server.AddTool(&mcp.Tool{
		Name:        "fetch_" + value,
		Description: "Fetch data with the token " + value + ".",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string","description":` + string(propDesc) + `}},"required":["text"]}`),
	}, echoTool)
	return server, nil
}

// runFailEcho is the fail-echo mode. It speaks JSON-RPC by hand, without the
// SDK, so that it can fail the handshake with a chosen message. It answers
// the first initialize request with a JSON-RPC error whose message holds
// value, and then returns exitServe. Other requests get "method not found".
// The child's stderr is os.DevNull in mcpmoat, so the echo goes to stdout,
// where a client reads it. When stdin closes before an initialize request,
// it returns exitOK. A read error (for example a line longer than 1 MiB)
// returns exitServe.
func runFailEcho(stdin io.Reader, stdout, stderr io.Writer, value string) int {
	in := bufio.NewScanner(stdin)
	in.Buffer(make([]byte, 0, 64<<10), 1<<20)
	out := bufio.NewWriter(stdout)
	for in.Scan() {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(in.Bytes(), &msg); err != nil || msg.ID == nil {
			continue // a notification, or not JSON
		}
		if msg.Method != "initialize" {
			fmt.Fprintf(out, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}`+"\n", msg.ID)
			if err := out.Flush(); err != nil {
				fmt.Fprintf(stderr, "echo: %v\n", err)
				return exitServe
			}
			continue
		}
		// json.Marshal escapes the value, so any value gives valid JSON.
		message, err := json.Marshal("cannot start: bad token " + value)
		if err != nil {
			fmt.Fprintf(stderr, "echo: encode the error message: %v\n", err)
			return exitServe
		}
		fmt.Fprintf(out, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":%s}}`+"\n", msg.ID, message)
		if err := out.Flush(); err != nil {
			fmt.Fprintf(stderr, "echo: %v\n", err)
		}
		return exitServe
	}
	// Scan returns false at the end of stdin and on a read error. Err is nil
	// at the end of stdin, so only a real error gets here. The error text
	// comes from the reader or bufio, never from the value.
	if err := in.Err(); err != nil {
		fmt.Fprintf(stderr, "echo: %v\n", err)
		return exitServe
	}
	return exitOK
}

// echoTool returns the argument "text" unchanged. Bad input is a tool error
// (IsError), not a protocol error.
func echoTool(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var in struct {
		Text *string `json:"text"`
	}
	if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
		return toolError(fmt.Errorf("bad arguments: %w", err)), nil
	}
	if in.Text == nil {
		return toolError(errors.New("argument text is required")), nil
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: *in.Text}}}, nil
}

// toolError returns a tool result that marks the call as failed.
func toolError(err error) *mcp.CallToolResult {
	res := &mcp.CallToolResult{}
	res.SetError(err)
	return res
}
