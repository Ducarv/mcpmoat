package inspect

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// Run inspects every server with insp and returns one Outcome for each.
//
// Contract:
//
//   - Run returns an error only when opts is invalid (see Options.Validate) or
//     insp is nil. The options error is the error of Validate, as is. A
//     problem with one server never becomes the returned error. It goes into
//     that server's Outcome (FR-06).
//   - The outcomes are sorted by Client, Source, Name, Scope, ProjectPath,
//     Transport, Command, Dir, URL and Args (NFR-03). The order does not
//     depend on timing or on opts.Concurrency. The sort is stable: servers
//     that are equal in all these fields (they can differ only in Env, Headers
//     or Untrusted) keep their input order. The input slice is not changed.
//   - Every server gets an Outcome with a non-empty Status. For zero servers,
//     Run returns a nil slice and a nil error.
//   - At most opts.Concurrency servers are inspected at the same time. The
//     opts.Timeout of a server starts when its inspection starts, not while it
//     waits in the queue.
//   - A server that returns no answer in time gets StatusTimeout. The Err of
//     that Outcome wraps context.DeadlineExceeded. An Inspect call that returns
//     an error after its own deadline has passed also gets StatusTimeout,
//     whatever the error is: the kill at the deadline makes the call fail
//     with an error of its own (for example "signal: killed"), so the error
//     alone cannot show a timeout. The text of that error is not kept.
//   - Once Run sees that ctx is done, it starts no new server. Those servers
//     get StatusFailed, and their Err wraps ctx.Err(). A server that is
//     already running gets StatusFailed too, and its Err wraps ctx.Err() as
//     well, so errors.Is(o.Err, context.Canceled) works. A server that a
//     worker takes at the moment ctx ends can still be started with a ctx
//     that is already done; the Inspector contract makes that call return at
//     once.
//   - A panic in insp.Inspect turns into StatusFailed for that server only.
//     So does a call that ends its goroutine with runtime.Goexit (for example
//     t.FailNow in a test fake). A Goexit also stops that worker, so the other
//     workers inspect the rest of the queue. If every worker stops this way,
//     the servers left in the queue get StatusFailed.
//   - Run waits for every Inspect call to return, and it leaves no goroutine
//     behind. An Inspector that ignores ctx therefore blocks Run (see the
//     Inspector contract).
//
// The text of Outcome.Err is untrusted. It can carry server output. The report
// layer must escape it with internal/termsafe before it prints it.
func Run(ctx context.Context, servers []discover.Server, opts Options, insp Inspector) ([]Outcome, error) {
	if err := opts.Validate(); err != nil {
		// The text of the error already starts with "inspect:".
		return nil, err
	}
	if insp == nil {
		return nil, errors.New("inspect: nil Inspector")
	}
	if len(servers) == 0 {
		return nil, nil
	}

	// Work on a copy: sorting must not change the caller's slice.
	sorted := slices.Clone(servers)
	slices.SortStableFunc(sorted, compareServers)

	// Each worker writes only to out[i] for the index i it took from jobs.
	// Distinct slice elements are distinct memory, so the writes do not race,
	// and no mutex is needed. wg.Wait below gives the happens-before edge that
	// makes all writes visible to this goroutine before it reads out.
	//
	// Every element starts as a failed Outcome, and a worker overwrites it.
	// A runtime.Goexit inside Inspect ends the worker before the write, and
	// recover cannot stop a Goexit. The default then stays, so no Outcome is
	// ever left with an empty Status.
	out := make([]Outcome, len(sorted))
	for i := range sorted {
		out[i] = Outcome{Server: sorted[i], Status: StatusFailed, Err: errNotFinished}
	}

	// This is a worker pool. The jobs channel is buffered for every index, so
	// we can fill it and close it before the workers start. Each worker takes
	// indexes until the channel is empty. The number of workers is the limit
	// on concurrent inspections.
	jobs := make(chan int, len(sorted))
	for i := range sorted {
		jobs <- i
	}
	close(jobs)

	workers := min(opts.Concurrency, len(sorted))
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range jobs {
				// Workers keep draining jobs after ctx is done. That way every
				// out[i] is filled, but no new server starts.
				if err := ctx.Err(); err != nil {
					out[i] = Outcome{
						Server: sorted[i],
						Status: StatusFailed,
						Err:    fmt.Errorf("inspect: not started: %w", err),
					}
					continue
				}
				out[i] = runOne(ctx, sorted[i], opts, insp)
			}
		})
	}
	wg.Wait()

	return out, nil
}

// errNotFinished is the Err of an Outcome whose Inspect call ended its
// goroutine without a return (runtime.Goexit), or that was never taken from the
// queue because every worker ended that way.
var errNotFinished = errors.New("inspect: inspection did not finish")

// compareServers orders servers for a stable result order. It returns a
// negative number, zero or a positive number, as cmp.Compare does.
//
// The revealed URL and the args are only compared here. They are never printed
// or stored. Env and Headers are not compared, so their values are never read.
func compareServers(a, b discover.Server) int {
	return cmp.Or(
		cmp.Compare(a.Client, b.Client),
		cmp.Compare(a.Source, b.Source),
		cmp.Compare(a.Name, b.Name),
		cmp.Compare(a.Scope, b.Scope),
		cmp.Compare(a.ProjectPath, b.ProjectPath),
		cmp.Compare(a.Transport, b.Transport),
		cmp.Compare(a.Command, b.Command),
		cmp.Compare(a.Dir, b.Dir),
		cmp.Compare(a.URL.Reveal(), b.URL.Reveal()),
		slices.Compare(a.Args.Values(), b.Args.Values()),
	)
}

// runOne inspects one server and maps the result to an Outcome. It never
// panics and it always returns a non-empty Status.
func runOne(parent context.Context, s discover.Server, opts Options, insp Inspector) (o Outcome) {
	o.Server = s

	// The timeout starts here, when the server starts, not in the queue.
	sctx, cancel := context.WithTimeout(parent, opts.Timeout)
	defer cancel()

	// A panic in one Inspector call must not stop the other servers. The
	// recovered value can be any type. We keep no stack trace.
	defer func() {
		if r := recover(); r != nil {
			o = Outcome{
				Server: s,
				Status: StatusFailed,
				Err:    fmt.Errorf("inspect: inspection panicked: %v", r),
			}
		}
	}()

	res, err := insp.Inspect(sctx, s)

	// Read each context state once, so that the case that is chosen and the
	// error that is wrapped see the same values. The parent can end at any
	// moment. Read sctx first: a parent sets its own error before it cancels
	// its children, so when sctx has passed a deadline and the parent still
	// has no error after that, the deadline is our own.
	serr := sctx.Err()
	perr := parent.Err()
	ownDeadline := perr == nil && errors.Is(serr, context.DeadlineExceeded)

	switch {
	case err == nil:
		// A nil error is success, even if the deadline passed just after the
		// inspector returned.
		o.Status = StatusOK
		o.Result = res
	case ownDeadline:
		// Only our own timeout fired. We do not wrap err here: its text is
		// untrusted and adds nothing to "no answer in time".
		o.Status = StatusTimeout
		o.Err = fmt.Errorf("inspect: no answer within %s: %w", opts.Timeout, context.DeadlineExceeded)
	case perr != nil:
		// The caller cancelled or its deadline passed. Wrap the parent error
		// too, so errors.Is works even if the inspector returned an unrelated
		// error.
		o.Status = StatusFailed
		o.Err = fmt.Errorf("inspect: %w: %w", perr, err)
	default:
		o.Status = StatusFailed
		o.Err = fmt.Errorf("inspect: %w", err)
	}
	return o
}
