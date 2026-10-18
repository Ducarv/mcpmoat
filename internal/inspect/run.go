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
//     insp is nil. A problem with one server never becomes the returned error.
//     It goes into that server's Outcome (FR-06).
//   - The outcomes are in a stable order that does not depend on the order of
//     servers, on timing or on opts.Concurrency. The order is by Client,
//     Source, Name, Scope, ProjectPath, Transport, Command, Dir, URL and Args
//     (NFR-03). The input slice is not changed.
//   - Every server gets an Outcome with a non-empty Status. For zero servers,
//     Run returns a nil slice and a nil error.
//   - At most opts.Concurrency servers are inspected at the same time. The
//     opts.Timeout of a server starts when its inspection starts, not while it
//     waits in the queue.
//   - A server that returns no answer in time gets StatusTimeout. The Err of
//     that Outcome wraps context.DeadlineExceeded.
//   - If ctx is done, servers that have not started do not start. They get
//     StatusFailed, and their Err wraps ctx.Err(). A server that is already
//     running gets StatusFailed too, and its Err wraps ctx.Err() as well, so
//     errors.Is(o.Err, context.Canceled) works.
//   - A panic in insp.Inspect turns into StatusFailed for that server only.
//   - Run waits for every Inspect call to return, and it leaves no goroutine
//     behind. An Inspector that ignores ctx therefore blocks Run (see the
//     Inspector contract).
//
// The text of Outcome.Err is untrusted. It can carry server output. The report
// layer must escape it with internal/termsafe before it prints it.
func Run(ctx context.Context, servers []discover.Server, opts Options, insp Inspector) ([]Outcome, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("inspect: invalid options: %w", err)
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
	out := make([]Outcome, len(sorted))

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

	switch {
	case err == nil:
		// A nil error is success, even if the deadline passed just after the
		// inspector returned.
		o.Status = StatusOK
		o.Result = res
	case parent.Err() == nil && errors.Is(sctx.Err(), context.DeadlineExceeded):
		// Only our own timeout fired. We do not wrap err here: its text is
		// untrusted and adds nothing to "no answer in time".
		o.Status = StatusTimeout
		o.Err = fmt.Errorf("inspect: no answer within %s: %w", opts.Timeout, context.DeadlineExceeded)
	case parent.Err() != nil:
		// The caller cancelled or its deadline passed. Wrap the parent error
		// too, so errors.Is works even if the inspector returned an unrelated
		// error.
		o.Status = StatusFailed
		o.Err = fmt.Errorf("inspect: %w: %w", parent.Err(), err)
	default:
		o.Status = StatusFailed
		o.Err = fmt.Errorf("inspect: %w", err)
	}
	return o
}
