package inspect

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// Status is the per-server result of one inspection.
type Status string

const (
	// StatusOK means the inspection finished and Result is valid.
	StatusOK Status = "ok"
	// StatusTimeout means the server did not finish before its timeout.
	StatusTimeout Status = "timeout"
	// StatusFailed means the inspection ended with an error.
	StatusFailed Status = "failed"
)

// Inspector connects to one MCP server and reads its content.
//
// Inspect MUST honour ctx. It must return soon after ctx is done. Run waits for
// Inspect to return and cannot abandon a call.
//
// Inspect must not start or connect to a server with s.Untrusted set unless
// the user gave an explicit opt-in (see the discover package doc, Untrusted
// files). Run does not check this: the opt-in belongs to the code that starts
// or connects to a server.
//
// In the same way, Inspect must not start or connect to a server whose
// s.State is not discover.StateEnabled (the client config turns it off, the
// user did not approve it, or only files from the repository approve it)
// unless the user gave an explicit opt-in (AllowDisabled). State and
// Untrusted are separate checks: a server must pass both. Run does not check
// State either.
//
// On every return, also on success, Inspect must stop the child processes it
// started. For a stdio child made with configureProcessGroup, call
// killProcessGroup before cmd.Wait, and then call Wait whatever the kill
// returns. Until Wait reaps the child, its PID stays taken, also after the
// child has exited, so the kill cannot reach another process. It stops the
// members that stay in the group, for example a daemon that the server
// started. cmd.Cancel does this only when ctx ends.
//
// Killing the child is not enough to return. A process that left the process
// group of the child can still hold the write end of a stdout pipe, so a read
// on that pipe does not end. When ctx is done, an implementation must also
// close its own end of every pipe it reads (for example with
// context.AfterFunc), so that the read returns.
//
// Run calls Inspect from several goroutines at the same time. An
// implementation must be safe for concurrent use.
//
// Error text can hold untrusted server output. It must never hold env or
// header values from the config. The same is true for the value of a panic in
// Inspect, because Run puts that value into Outcome.Err. Keep the text short:
// do not wrap the whole output of a server. The report layer prints it.
type Inspector interface {
	Inspect(ctx context.Context, s discover.Server) (Result, error)
}

const (
	// DefaultTimeout is the default time limit for one server (FR-06).
	DefaultTimeout = 10 * time.Second
	// DefaultConcurrency is the default number of servers inspected at the
	// same time (NFR-03).
	DefaultConcurrency = 4
)

// Options sets how Run inspects a list of servers.
type Options struct {
	// Timeout is the time limit for one server. It starts when the server
	// starts, not while the server waits in the queue.
	Timeout time.Duration
	// Concurrency is the maximum number of servers inspected at the same time.
	Concurrency int
}

// DefaultOptions returns Options with DefaultTimeout and DefaultConcurrency.
func DefaultOptions() Options {
	return Options{
		Timeout:     DefaultTimeout,
		Concurrency: DefaultConcurrency,
	}
}

// The errors that Options.Validate wraps. A caller can tell them apart with
// errors.Is, for example to name its own flag in a message.
var (
	// ErrInvalidTimeout means that Options.Timeout is 0 or less.
	ErrInvalidTimeout = errors.New("inspect: timeout must be greater than 0")
	// ErrInvalidConcurrency means that Options.Concurrency is below 1.
	ErrInvalidConcurrency = errors.New("inspect: concurrency must be at least 1")
)

// Validate reports whether the options are usable. The error wraps
// ErrInvalidTimeout or ErrInvalidConcurrency. When both values are bad, it
// reports the timeout.
//
// Zero does not mean "use the default". A Timeout of 0 or less is an error.
// A Concurrency below 1 is an error. Start from DefaultOptions to get the
// defaults.
func (o Options) Validate() error {
	if o.Timeout <= 0 {
		return fmt.Errorf("%w, got %s", ErrInvalidTimeout, o.Timeout)
	}
	if o.Concurrency < 1 {
		return fmt.Errorf("%w, got %d", ErrInvalidConcurrency, o.Concurrency)
	}
	return nil
}

// Outcome is the result of inspecting one server.
type Outcome struct {
	// Index is the index of the server in the servers slice that was given to
	// Run. Run sorts the outcomes, so the position of an Outcome does not tell
	// which input server it belongs to; Index does, also for servers that are
	// equal in every field.
	Index int
	// Server is the server that was inspected.
	Server discover.Server
	// Status tells how the inspection ended.
	Status Status
	// Result is valid only when Status is StatusOK.
	Result Result
	// Err is nil when Status is StatusOK and non-nil otherwise. Its text is
	// untrusted because it can carry server output. The report layer must
	// escape it with internal/termsafe before it prints it.
	Err error
}
