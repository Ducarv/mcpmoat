package inspect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// stopGrace is how long the SDK command transport waits at each step when it
// stops a stdio server: after it closes the stdin of the server, and again
// after it sends SIGTERM. After the second wait it sends SIGKILL and waits
// once more. So a server that ignores stdin and SIGTERM stops after about
// 2*stopGrace, and Close gives up after 3*stopGrace in the worst case.
const stopGrace = 2 * time.Second

// defaultClientVersion is the MCP client version that mcpmoat sends when
// Options.ClientVersion is empty.
const defaultClientVersion = "dev"

// errNoResult means that the SDK gave a nil result and a nil error for a
// list request. inspect treats it as a protocol error.
var errNoResult = errors.New("no result")

// SDKInspector is the [Inspector] that uses the official MCP Go SDK. It
// supports stdio servers. For an http or sse server it returns
// [ErrUnsupportedTransport] until issue #26.
//
// SDKInspector holds no mutable state: each call to Inspect makes its own
// SDK client, process and connection. So one SDKInspector is safe for
// concurrent use by multiple goroutines.
type SDKInspector struct {
	opts Options

	// getenv reads the environment of mcpmoat for the base keys of the
	// child environment (see childEnv). New sets it to os.Getenv; tests in
	// this package can replace it, so that they never read the real
	// environment. When it is nil (a zero SDKInspector), Inspect uses
	// os.Getenv.
	getenv func(string) string
}

var _ Inspector = (*SDKInspector)(nil)

// New returns an [SDKInspector] with the options opts.
func New(opts Options) *SDKInspector {
	return &SDKInspector{opts: opts, getenv: os.Getenv}
}

// Inspect starts the stdio server s, does the MCP handshake, lists its tools,
// prompts and resources, and stops the server. See the error contract on
// [Inspector].
//
// The MCP SDK silently drops some invalid tools from a tools/list result
// (see listWatch). When it drops one or more, Inspect returns an error that
// wraps [ErrProtocol] and gives the count, not a Result without those tools.
// So a server cannot hide a tool from the rules and the pins that way. The
// same listWatch applies the raw byte limit maxRawBytes to the list pages,
// which gives [ErrTooManyItems].
//
// Inspect does not start a server that is Untrusted unless
// Options.AllowUntrusted is true. It does not connect to a remote server.
//
// Stop guarantee: when Inspect returns, on success and on every error, the
// child process was stopped and reaped, and its temporary working directory,
// if any, was removed. A normal stop closes stdin of the server, then sends
// SIGTERM and SIGKILL if needed. When ctx ends, os/exec sends SIGKILL at
// once. The only exception is a process that the operating system cannot
// kill.
func (i *SDKInspector) Inspect(ctx context.Context, s discover.Server) (Result, error) {
	if s.Untrusted && !i.opts.AllowUntrusted {
		return Result{}, fmt.Errorf("%w: not started without the explicit opt-in", ErrUntrusted)
	}
	if s.Transport.IsRemote() {
		// IsRemote is true only for the two known constants, so the text
		// is "http" or "sse", not untrusted text.
		return Result{}, fmt.Errorf("%w: %s (remote servers come with issue #26)", ErrUnsupportedTransport, s.Transport)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	// The defers below stop things in this order:
	//
	//  1. cs.Close: ends the MCP session.
	//  2. transport.close: closes the connection, which closes stdin of the
	//     server and waits for the process to exit (SIGTERM and SIGKILL
	//     after stopGrace each). It also calls cmd.Wait, so the process is
	//     reaped.
	//  3. cleanup: removes the temporary working directory, now that the
	//     process no longer uses it.
	//  4. cancel: cancels the ctx of exec.CommandContext. If the process
	//     still runs at this point, os/exec kills it with SIGKILL. It is
	//     the last resort.
	//
	// The defer for cancel is registered first, so that it runs last.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	getenv := i.getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	cmd, cleanup, err := buildCommand(ctx, s, getenv)
	// cleanup is never nil, also on error, so it is safe to defer it before
	// the error check.
	defer cleanup()
	if err != nil {
		return Result{}, err
	}

	transport := &closingTransport{
		inner: &mcp.CommandTransport{Command: cmd, TerminateDuration: stopGrace},
	}
	defer transport.close()

	client, watch := i.newWatchedClient(maxRawBytes)
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		if transport.startErr != nil {
			// The error of exec.Cmd.Start names the command, never
			// the args or the env.
			return Result{}, fmt.Errorf("%w: %w", ErrStart, err)
		}
		return Result{}, sessionError(ctx, "handshake", err)
	}
	// Close is idempotent in the SDK, so a second close by transport.close
	// does no harm. The error of Close is the exit status of the server; it
	// does not change the result, so Inspect drops it.
	defer func() { _ = cs.Close() }()

	return inspectWatched(ctx, cs, watch)
}

// newClient returns a new SDK client for one call to Inspect.
//
// The client offers no capabilities to the server, and it serves no request
// of the server except ping:
//
//   - Capabilities is set and empty. A nil Capabilities would advertise
//     "roots" for historical reasons.
//   - CreateMessageHandler, CreateMessageWithToolsHandler and
//     ElicitationHandler stay nil. Then the SDK does not advertise sampling
//     or elicitation.
//   - The receiving middleware refuseServerRequests answers every server
//     request except ping with "method not found", before the SDK handler
//     runs: completion/complete, roots/list, sampling/createMessage,
//     elicitation/create and any other method. Without it, the SDK would
//     still answer roots/list (with an empty list), and it would send a
//     completion/complete request back to the server and wait for the
//     answer. Only a short allowlist of notifications passes; see
//     allowedServerMethod.
//   - The multi round-trip middleware is disabled. It answers input
//     requests from the server on tools/call, prompts/get and
//     resources/read, which mcpmoat never sends; disabling it removes one
//     more path for server requests.
//
// Logger stays nil, so the SDK logs nothing. Its logs could hold untrusted
// server text. Inspect finds the tools that the SDK drops without the logs:
// see newWatchedClient.
func (i *SDKInspector) newClient() *mcp.Client {
	version := i.opts.ClientVersion
	if version == "" {
		version = defaultClientVersion
	}
	c := mcp.NewClient(
		&mcp.Implementation{Name: "mcpmoat", Version: version},
		&mcp.ClientOptions{
			Capabilities:   &mcp.ClientCapabilities{},
			MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
		},
	)
	c.AddReceivingMiddleware(refuseServerRequests)
	return c
}

// inspectSession reads the handshake result of cs and lists the tools,
// prompts and resources of the server, one kind at a time.
//
// It lists a kind only when the server advertises its capability in the
// handshake (tools, prompts or resources). A server without that capability
// would answer "method not found". The slice of a kind that the server does
// not advertise stays nil. The slice of an advertised kind is never nil, also
// when it is empty, so callers can tell the two cases apart (issue #97).
//
// It uses the paged ListX calls through collect, not the SDK iterators such
// as cs.Tools, because the iterators have no limit on pages or items. One
// byte budget of maxBytes is shared by the three kinds, so the limit is for
// the server, not for one kind.
//
// On an error, the Result is zero, also when an earlier kind was listed
// without error. The error wraps [ErrProtocol],
// [ErrTooManyItems] or the context error.
func inspectSession(ctx context.Context, cs *mcp.ClientSession) (Result, error) {
	return inspectSessionBudget(ctx, cs, newByteBudget(maxBytes))
}

// inspectSessionBudget is inspectSession with the byte budget budget, which
// the three kinds share. Tests give a small budget, so that they can go over
// it without sending maxBytes through the SDK.
func inspectSessionBudget(ctx context.Context, cs *mcp.ClientSession, budget *byteBudget) (Result, error) {
	initRes := cs.InitializeResult()
	if initRes == nil {
		return Result{}, sessionError(ctx, "handshake", errNoResult)
	}

	res := Result{
		ProtocolVersion: initRes.ProtocolVersion,
		Instructions:    initRes.Instructions,
	}
	if initRes.ServerInfo != nil {
		res.ServerName = initRes.ServerInfo.Name
		res.ServerVersion = initRes.ServerInfo.Version
	}

	caps := initRes.Capabilities
	if caps == nil {
		// A server that sends no capabilities offers nothing to list.
		return res, nil
	}

	if caps.Tools != nil {
		tools, err := collect(ctx, budget, toolSize, func(ctx context.Context, cursor string) ([]Tool, string, error) {
			r, err := cs.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
			if err != nil {
				return nil, "", err
			}
			if r == nil {
				return nil, "", errNoResult
			}
			items, err := toTools(r.Tools)
			if err != nil {
				return nil, "", err
			}
			return items, r.NextCursor, nil
		})
		if err != nil {
			return Result{}, sessionError(ctx, "list tools", err)
		}
		res.Tools = tools
	}

	if caps.Prompts != nil {
		prompts, err := collect(ctx, budget, promptSize, func(ctx context.Context, cursor string) ([]Prompt, string, error) {
			r, err := cs.ListPrompts(ctx, &mcp.ListPromptsParams{Cursor: cursor})
			if err != nil {
				return nil, "", err
			}
			if r == nil {
				return nil, "", errNoResult
			}
			return toPrompts(r.Prompts), r.NextCursor, nil
		})
		if err != nil {
			return Result{}, sessionError(ctx, "list prompts", err)
		}
		res.Prompts = prompts
	}

	if caps.Resources != nil {
		resources, err := collect(ctx, budget, resourceSize, func(ctx context.Context, cursor string) ([]Resource, string, error) {
			r, err := cs.ListResources(ctx, &mcp.ListResourcesParams{Cursor: cursor})
			if err != nil {
				return nil, "", err
			}
			if r == nil {
				return nil, "", errNoResult
			}
			return toResources(r.Resources), r.NextCursor, nil
		})
		if err != nil {
			return Result{}, sessionError(ctx, "list resources", err)
		}
		res.Resources = resources
	}

	return res, nil
}

// sessionError wraps err, the error of the step op ("handshake" or
// "list tools", for example), so that it follows the error contract of
// [Inspector]:
//
//   - An error that wraps [ErrTooManyItems] keeps it as its only sentinel.
//     It is a limit of mcpmoat, not a broken protocol.
//   - When ctx is done, the error also wraps the context error, so that
//     errors.Is(err, context.DeadlineExceeded) works even if the SDK error
//     does not wrap it.
//   - Every other error wraps [ErrProtocol] once.
//
// err can hold text that the server sent. It never holds Args, Env, Headers
// or URL values, because the SDK never sees them: buildCommand passes them to
// the process only.
func sessionError(ctx context.Context, op string, err error) error {
	if errors.Is(err, ErrTooManyItems) {
		return fmt.Errorf("%s: %w", op, err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		return fmt.Errorf("%w: %s: %w: %w", ErrProtocol, op, err, ctxErr)
	}
	if errors.Is(err, ErrProtocol) {
		// For example a schema error from toTools: do not add the
		// sentinel twice.
		return fmt.Errorf("%s: %w", op, err)
	}
	return fmt.Errorf("%w: %s: %w", ErrProtocol, op, err)
}

// closingTransport is an [mcp.Transport] around the SDK command transport. It
// remembers what Connect did, for two reasons:
//
//   - Inspect must tell a start failure ([ErrStart]) from a handshake
//     failure ([ErrProtocol]). Both come back from Client.Connect.
//   - Client.Connect does not close the connection on every error path. With
//     the connection kept here, Inspect can always close it, and so always
//     stop and reap the process.
//
// Connect returns the connection of the inner transport unchanged, not a
// wrapper. The SDK checks the connection for optional interfaces, and a
// wrapper would hide them.
//
// The SDK calls Connect exactly once, in the goroutine that calls
// Client.Connect. So Inspect can read the fields after Client.Connect
// returns, without a mutex.
type closingTransport struct {
	inner mcp.Transport

	// conn is the connection that inner returned, or nil.
	conn mcp.Connection

	// startErr is the error of inner.Connect, or nil. The command transport
	// starts the process in Connect, so a non-nil startErr means that the
	// process did not start.
	startErr error
}

// Connect starts the server process through the inner transport.
func (t *closingTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.inner.Connect(ctx)
	if err != nil {
		t.startErr = err
		return nil, err
	}
	t.conn = conn
	return conn, nil
}

// close closes the connection, if Connect made one. It does nothing if the
// process never started.
//
// For the command transport, this is how the process stops: the close of
// the SDK connection runs only once (sync.Once), closes the stdin of the
// server and calls cmd.Wait. If the process does not exit within stopGrace,
// it sends SIGTERM, and after one more stopGrace, SIGKILL. A concurrent or
// earlier close by the SDK is fine: a second call waits for the first one
// to finish and returns its error. So when close returns, the process has
// exited and is reaped. The error is the exit status of the server, which
// does not matter here, so close drops it.
func (t *closingTransport) close() {
	if t.conn != nil {
		_ = t.conn.Close()
	}
}
