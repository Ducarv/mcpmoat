package inspect

import (
	"context"
	"errors"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// Inspector connects to one MCP server and lists what it offers.
//
// Inspector is the only way that the rest of mcpmoat talks MCP. The SDK stays
// behind it, so that MCP spec changes stay in this package (NFR-06).
//
// Error contract:
//
//   - A non-nil error always comes with a zero Result.
//   - An error wraps one of the sentinel errors of this package or the
//     context error, so errors.Is(err, context.DeadlineExceeded) and
//     errors.Is(err, context.Canceled) work.
//   - An error that ctx causes can also wrap [ErrProtocol] or [ErrStart].
//     So callers that map errors to messages must test
//     context.DeadlineExceeded and context.Canceled first.
//   - The error text never contains the values of Args, Env, Headers or URL
//     of the [discover.Server], because they can hold secrets. It can contain
//     the command name and text that the server sent. That text is
//     untrusted and can be very long, so callers must print the error
//     through package internal/termsafe, with termsafe.QuoteCut.
//
// An error means that the server was not scanned. A hostile server can cause
// an error on purpose to hide its tools: for example, it can fail
// prompts/list after it sent poisoned tools, or send too many items. An
// error that wraps [ErrTooManyItems] is a sign of a hostile or broken server.
// Callers must report every error as a finding about that server, and never
// treat the server as clean.
//
// Implementations must honour the cancellation of ctx. They must stop any
// child process that they start before Inspect returns.
//
// Implementations must be safe for concurrent use by multiple goroutines.
type Inspector interface {
	// Inspect connects to s, or starts it for a stdio server, and returns
	// what the server reports. See the error contract on [Inspector].
	Inspect(ctx context.Context, s discover.Server) (Result, error)
}

// Options configures an [Inspector].
type Options struct {
	// AllowUntrusted is the explicit opt-in of the user to start or connect
	// to a [discover.Server] whose Untrusted field is true. Such a server
	// comes from a project file that a cloned repository can ship. See the
	// package doc of internal/discover, Untrusted files. When AllowUntrusted
	// is false, Inspect returns [ErrUntrusted] for such a server.
	AllowUntrusted bool

	// ClientVersion is the version that mcpmoat sends as the MCP client
	// version in the handshake. An empty value sends "dev".
	ClientVersion string
}

// Sentinel errors of [Inspector.Inspect]. Use errors.Is to test for them.
var (
	// ErrUntrusted means that the server comes from an untrusted file and
	// Options.AllowUntrusted is false. mcpmoat did not start or connect to
	// it.
	ErrUntrusted = errors.New("inspect: server from untrusted file")

	// ErrUnsupportedTransport means that inspect does not support the
	// transport of the server yet (http and sse until issue #26).
	ErrUnsupportedTransport = errors.New("inspect: unsupported transport")

	// ErrInvalidServer means that the server config cannot be run safely,
	// for example an empty command, a bad env key, or a relative command
	// without an absolute Dir.
	ErrInvalidServer = errors.New("inspect: invalid server")

	// ErrStart means that the server process could not be prepared or
	// started, for example because its temporary working directory could
	// not be made or its command was not found.
	ErrStart = errors.New("inspect: start server")

	// ErrProtocol means that the MCP handshake or a list request failed.
	ErrProtocol = errors.New("inspect: protocol error")

	// ErrTooManyItems means that the server sent more pages, items or bytes
	// than the limits allow, or sent a cursor that it sent before.
	ErrTooManyItems = errors.New("inspect: too many items")
)
