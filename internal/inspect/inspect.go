package inspect

import (
	"context"
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

// Result holds what an inspection read from one server.
//
// It is a placeholder. Issue #31 adds tools, prompts and resources as
// SDK-independent types.
type Result struct{}

// Inspector connects to one MCP server and reads its content.
//
// Inspect MUST honour ctx. It must return soon after ctx is done, and it must
// stop any child process it started (see ConfigureProcessGroup). Run waits for
// Inspect to return and cannot abandon a call.
//
// Run calls Inspect from several goroutines at the same time. An
// implementation must be safe for concurrent use.
//
// Error text can hold untrusted server output. It must never hold env or
// header values from the config.
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

// Validate reports whether the options are usable.
//
// Zero does not mean "use the default". A Timeout of 0 or less is an error.
// A Concurrency below 1 is an error. Start from DefaultOptions to get the
// defaults.
func (o Options) Validate() error {
	if o.Timeout <= 0 {
		return fmt.Errorf("inspect: timeout must be greater than 0, got %s", o.Timeout)
	}
	if o.Concurrency < 1 {
		return fmt.Errorf("inspect: concurrency must be at least 1, got %d", o.Concurrency)
	}
	return nil
}

// Outcome is the result of inspecting one server.
type Outcome struct {
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
