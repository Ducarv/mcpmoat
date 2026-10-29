// Package inspecttest has test helpers for code that uses package
// internal/inspect.
//
// It holds:
//   - [Fake], an [inspect.Inspector] that returns canned results. Tests of
//     packages such as rules and pins use it, so that they never start a
//     real MCP server.
//   - [Fixture] and [RemoveBuilds], which build the fixture MCP servers in
//     testdata/servers/ and remove the builds when the tests are done.
//   - [BenignResult], the exact [inspect.Result] that the benign fixture
//     server reports.
//
// Import this package only from _test.go files, so the testing package never
// reaches the mcpmoat binary. The depguard rule inspecttest-only-in-tests in
// .golangci.yml enforces this.
package inspecttest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// ErrNoResult means that a [Fake] has no entry in Results or Errors for the
// server. The error that Inspect returns wraps it, so use errors.Is to test
// for it.
var ErrNoResult = errors.New("inspecttest: no fake result for server")

var _ inspect.Inspector = (*Fake)(nil)

// Fake is an [inspect.Inspector] that returns canned results and records
// each call. It never starts or connects to a server.
//
// Set Results and Errors before the first call to Inspect, and do not change
// them while calls run. With that rule, a Fake is safe for concurrent use by
// multiple goroutines. The zero value is ready to use: each call then
// returns an error that wraps [ErrNoResult].
type Fake struct {
	// Results maps a discover.Server.Name to the Result that Inspect returns
	// for that server.
	Results map[string]inspect.Result

	// Errors maps a discover.Server.Name to the error that Inspect returns
	// for that server. An entry in Errors wins over an entry in Results for
	// the same name. A nil error value counts as no entry.
	Errors map[string]error

	mu    sync.Mutex // protects calls
	calls []string   // server names, in call order
}

// Inspect records the call and returns the canned answer for s.Name. It
// follows the error contract of [inspect.Inspector]: a non-nil error always
// comes with a zero Result. In this order, it returns:
//
//  1. the error of ctx, if ctx is already canceled or past its deadline;
//  2. the entry of Errors for s.Name, if there is one and it is not nil;
//  3. the entry of Results for s.Name, if there is one;
//  4. an error that wraps [ErrNoResult].
//
// The returned Result has its own copies of the Tools, Prompts, Resources,
// ResourceTemplates, Warnings and Secrets slices, so a caller can change
// those slices without an effect on Results. Each Warning also gets its own
// copies of HeaderKeys and Capabilities. All other copies are shallow: nested
// slices and pointers, such as Tool.InputSchema, Tool.Annotations (and the
// hints in it) and Prompt.Arguments, are shared with the entry in Results, so
// callers must not change them.
func (f *Fake) Inspect(ctx context.Context, s discover.Server) (inspect.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, s.Name)
	f.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return inspect.Result{}, err
	}
	if err := f.Errors[s.Name]; err != nil {
		return inspect.Result{}, err
	}
	r, ok := f.Results[s.Name]
	if !ok {
		// The server name is test data, not a secret, so the error can
		// hold it.
		return inspect.Result{}, fmt.Errorf("%w %q", ErrNoResult, s.Name)
	}
	// slices.Clone keeps a nil slice nil, so the copy stays equal to the
	// entry in Results under reflect.DeepEqual.
	r.Tools = slices.Clone(r.Tools)
	r.Prompts = slices.Clone(r.Prompts)
	r.Resources = slices.Clone(r.Resources)
	r.ResourceTemplates = slices.Clone(r.ResourceTemplates)
	r.Warnings = slices.Clone(r.Warnings)
	// A discover.Secret cannot be changed in place, so a shallow copy of
	// the slice is enough.
	r.Secrets = slices.Clone(r.Secrets)
	// r.Warnings is now a copy, so a change to its elements does not
	// reach the entry in Results.
	for i := range r.Warnings {
		r.Warnings[i].HeaderKeys = slices.Clone(r.Warnings[i].HeaderKeys)
		r.Warnings[i].Capabilities = slices.Clone(r.Warnings[i].Capabilities)
	}
	return r, nil
}

// Calls returns the server names of all calls to Inspect so far, in call
// order. A name appears once for each call, also for calls that returned an
// error. It returns a new slice on each call, so callers can change it
// safely.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}
