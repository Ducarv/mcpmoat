// Command benign is a small, predictable MCP server for mcpmoat tests.
//
// It is a test fixture, not a product. It is the negative baseline for the
// detection rules (NFR-05): no rule or heuristic must ever report a finding
// on it. For this reason all names and descriptions are short, plain ASCII
// text with no instructions, no URLs and no hidden characters.
//
// The server speaks MCP over stdio (stdin and stdout) and offers:
//
//   - tools "add" and "echo" (the SDK lists them sorted by name),
//   - prompt "greeting",
//   - resource "mcpmoat://benign/readme".
//
// The page size is 1, so a client must follow nextCursor to read both tools.
//
// Flags:
//
//	-mode string
//	    ok        serve MCP on stdio until stdin closes (default)
//	    crash     exit with code 3 before the MCP handshake
//	    hang-init never read stdin and never reply
//	    hang-list complete the handshake, then block every tools/list request
//	-pidfile path
//	    if set, write the process ID and a newline to this file at start
//	-envfile path
//	    if set, write the sorted environment, one VAR=value per line, to this
//	    file at start (tests use it to check the scrubbed environment, NFR-04)
//
// Bad flags, an unknown mode or a file write error exit with code 2. A
// server error other than a closed stdin or a signal exits with code 1.
//
// The server writes only MCP protocol messages to stdout. Errors go to stderr.
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Exit codes of this program.
const (
	exitOK    = 0
	exitServe = 1 // the MCP server stopped with an error
	exitUsage = 2 // bad flags, unknown mode or a file write error
	exitCrash = 3 // the crash mode
)

// The modes of the -mode flag.
const (
	modeOK       = "ok"
	modeCrash    = "crash"
	modeHangInit = "hang-init"
	modeHangList = "hang-list"
)

// The input schemas are fixed JSON text, so the bytes on the wire stay the
// same between builds. A schema that the SDK infers from Go types could change
// when the SDK changes.
var (
	addInputSchema = json.RawMessage(`{"type":"object","properties":{"a":{"type":"number","description":"First number."},"b":{"type":"number","description":"Second number."}},"required":["a","b"]}`)

	echoInputSchema = json.RawMessage(`{"type":"object","properties":{"text":{"type":"string","description":"Text to return."}},"required":["text"]}`)
)

// readmeURI is the URI of the only resource.
const readmeURI = "mcpmoat://benign/readme"

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run parses the flags, does the work for the selected mode and returns the
// exit code. It keeps os.Exit in main only.
func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("benign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", modeOK, modeOK+" | "+modeCrash+" | "+modeHangInit+" | "+modeHangList)
	pidFile := fs.String("pidfile", "", "write the process ID to this file")
	envFile := fs.String("envfile", "", "write the sorted environment to this file")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "benign: unexpected arguments: %v\n", fs.Args())
		return exitUsage
	}

	switch *mode {
	case modeOK, modeCrash, modeHangInit, modeHangList:
	default:
		fmt.Fprintf(stderr, "benign: unknown mode %q\n", *mode)
		return exitUsage
	}

	if err := writeStartFiles(*pidFile, *envFile); err != nil {
		fmt.Fprintf(stderr, "benign: %v\n", err)
		return exitUsage
	}

	switch *mode {
	case modeCrash:
		return exitCrash
	case modeHangInit:
		// Do not use select{} here. With no other goroutines, the Go runtime
		// sees that nothing can ever wake up, reports a deadlock and exits.
		// A sleeping goroutine does not count as a deadlock.
		for {
			time.Sleep(time.Hour)
		}
	}

	// The context ends on Ctrl+C or SIGTERM, so the server can stop cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := newServer()
	if *mode == modeHangList {
		server.AddReceivingMiddleware(blockToolsList)
	}

	err := server.Run(ctx, &mcp.StdioTransport{})
	// A closed stdin or a signal is a normal end for this server.
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		fmt.Fprintf(stderr, "benign: %v\n", err)
		return exitServe
	}
	return exitOK
}

// writeStartFiles writes the process ID to pidFile and the sorted
// environment to envFile. An empty path skips that file.
func writeStartFiles(pidFile, envFile string) error {
	if pidFile != "" {
		pid := strconv.Itoa(os.Getpid()) + "\n"
		if err := os.WriteFile(pidFile, []byte(pid), 0o600); err != nil {
			return fmt.Errorf("write pidfile: %w", err)
		}
	}
	if envFile != "" {
		env := os.Environ()
		slices.Sort(env)
		var b strings.Builder
		for _, line := range env {
			b.WriteString(line)
			b.WriteString("\n")
		}
		if err := os.WriteFile(envFile, []byte(b.String()), 0o600); err != nil {
			return fmt.Errorf("write envfile: %w", err)
		}
	}
	return nil
}

// newServer returns the server with its tools, prompt and resource.
func newServer() *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "benign", Version: "1.0.0"},
		&mcp.ServerOptions{PageSize: 1},
	)

	server.AddTool(&mcp.Tool{
		Name:        "add",
		Description: "Add two numbers and return the sum.",
		InputSchema: addInputSchema,
	}, addTool)

	server.AddTool(&mcp.Tool{
		Name:        "echo",
		Description: "Return the input text unchanged.",
		InputSchema: echoInputSchema,
	}, echoTool)

	server.AddPrompt(&mcp.Prompt{
		Name:        "greeting",
		Description: "Write a short, friendly greeting.",
		Arguments: []*mcp.PromptArgument{{
			Name:        "name",
			Description: "Name of the person to greet.",
			Required:    true,
		}},
	}, greetingPrompt)

	server.AddResource(&mcp.Resource{
		URI:         readmeURI,
		Name:        "readme",
		Description: "Short text about this test server.",
		MIMEType:    "text/plain",
	}, readmeResource)

	return server
}

// addTool returns the sum of the arguments "a" and "b" as text.
//
// The low-level Server.AddTool API does not check the arguments against the
// schema, so the handler checks them. Bad input is a tool error (IsError), not
// a protocol error.
func addTool(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Pointers let us see if an argument is missing (nil) or zero.
	var in struct {
		A *float64 `json:"a"`
		B *float64 `json:"b"`
	}
	if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
		return toolError(fmt.Errorf("bad arguments: %w", err)), nil
	}
	if in.A == nil || in.B == nil {
		return toolError(errors.New("arguments a and b are required")), nil
	}
	sum := *in.A + *in.B
	return textResult(strconv.FormatFloat(sum, 'g', -1, 64)), nil
}

// echoTool returns the argument "text" unchanged.
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
	return textResult(*in.Text), nil
}

// textResult returns a tool result with one text item.
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// toolError returns a tool result that marks the call as failed.
func toolError(err error) *mcp.CallToolResult {
	res := &mcp.CallToolResult{}
	res.SetError(err)
	return res
}

// greetingPrompt returns one user message that asks for a greeting.
func greetingPrompt(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	name := req.Params.Arguments["name"]
	if name == "" {
		return nil, errors.New("argument name is required")
	}
	return &mcp.GetPromptResult{
		Description: "Write a short, friendly greeting.",
		Messages: []*mcp.PromptMessage{{
			Role:    "user",
			Content: &mcp.TextContent{Text: "Write a short, friendly greeting for " + name + "."},
		}},
	}, nil
}

// readmeResource returns the text of the readme resource.
func readmeResource(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{
			URI:      readmeURI,
			MIMEType: "text/plain",
			Text:     "This is the benign mcpmoat test server.",
		}},
	}, nil
}

// blockToolsList is a receiving middleware for the hang-list mode. It lets
// all methods through, except "tools/list": that request waits until its
// context ends (for example, the client cancels it or the connection closes).
// The handshake still works, so a test can check the list timeout.
func blockToolsList(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if method == "tools/list" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return next(ctx, method, req)
	}
}
