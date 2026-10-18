package inspect_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// The tests that measure time run inside a synctest bubble. In a bubble, time
// is virtual: it moves forward only when every goroutine of the bubble is
// blocked. So "the run took exactly 3s" is a stable fact, not a measurement.
// synctest.Test also fails when a goroutine is still blocked at the end of the
// bubble, which checks that Run leaves no goroutine behind.

// errFake is the sentinel error that fake inspectors return.
var errFake = errors.New("fake inspector failure")

// fakeBehaviour is what the fake inspector does for one server.
type fakeBehaviour func(ctx context.Context, s discover.Server) (inspect.Result, error)

// fakeInspector is an Inspector for tests. It is safe for concurrent use: the
// maps are read-only after construction and the counters are atomic.
type fakeInspector struct {
	// byName picks a behaviour by Server.Name. Names that are not in the map
	// use fallback.
	byName   map[string]fakeBehaviour
	fallback fakeBehaviour

	calls       atomic.Int64 // number of Inspect calls
	inFlight    atomic.Int64 // Inspect calls running now
	maxInFlight atomic.Int64 // highest value that inFlight reached
}

func (f *fakeInspector) Inspect(ctx context.Context, s discover.Server) (inspect.Result, error) {
	f.calls.Add(1)
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		m := f.maxInFlight.Load()
		if n <= m || f.maxInFlight.CompareAndSwap(m, n) {
			break
		}
	}

	b, ok := f.byName[s.Name]
	if !ok {
		b = f.fallback
	}
	if b == nil {
		return inspect.Result{}, nil
	}
	return b(ctx, s)
}

// okAfter succeeds after d. It stops early with ctx.Err() if ctx is done.
func okAfter(d time.Duration) fakeBehaviour {
	return func(ctx context.Context, _ discover.Server) (inspect.Result, error) {
		if d <= 0 {
			return inspect.Result{}, nil
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
			return inspect.Result{}, nil
		case <-ctx.Done():
			return inspect.Result{}, ctx.Err()
		}
	}
}

// hang waits for ctx to be done and returns ctx.Err().
func hang(ctx context.Context, _ discover.Server) (inspect.Result, error) {
	<-ctx.Done()
	return inspect.Result{}, ctx.Err()
}

// failNow returns err at once.
func failNow(err error) fakeBehaviour {
	return func(context.Context, discover.Server) (inspect.Result, error) {
		return inspect.Result{}, err
	}
}

// panicWith panics with v.
func panicWith(v any) fakeBehaviour {
	return func(context.Context, discover.Server) (inspect.Result, error) {
		panic(v)
	}
}

// waitThenFail waits for ctx to be done and then returns err, an error that
// has nothing to do with ctx.
func waitThenFail(err error) fakeBehaviour {
	return func(ctx context.Context, _ discover.Server) (inspect.Result, error) {
		<-ctx.Done()
		return inspect.Result{}, err
	}
}

// ignoreCtxThenOK sleeps for d without looking at ctx and then succeeds.
func ignoreCtxThenOK(d time.Duration) fakeBehaviour {
	return func(context.Context, discover.Server) (inspect.Result, error) {
		time.Sleep(d)
		return inspect.Result{}, nil
	}
}

// fakeServer returns a minimal valid stdio server with the given name.
func fakeServer(name string) discover.Server {
	return discover.Server{
		Name:      name,
		Client:    discover.ClientClaudeCode,
		Scope:     discover.ScopeGlobal,
		Source:    "/cfg/claude.json",
		Transport: discover.TransportStdio,
		Command:   "server-cmd",
	}
}

// fakeServers returns n servers named s00, s01, ... (already in sorted order).
func fakeServers(n int) []discover.Server {
	servers := make([]discover.Server, n)
	for i := range servers {
		servers[i] = fakeServer(fmt.Sprintf("s%02d", i))
	}
	return servers
}

// describeServer describes the fields that decide the order of a server, as one
// string. Tests use it to compare servers in a readable way. It is test code,
// so it may read the args as written.
func describeServer(s discover.Server) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%q", s.Client, s.Source, s.Name, s.Scope, s.ProjectPath, s.Args.Values())
}

func describeServers(servers []discover.Server) []string {
	keys := make([]string, len(servers))
	for i, s := range servers {
		keys[i] = describeServer(s)
	}
	return keys
}

func outcomeKeys(outs []inspect.Outcome) []string {
	keys := make([]string, len(outs))
	for i, o := range outs {
		keys[i] = describeServer(o.Server)
	}
	return keys
}

func outcomeNames(outs []inspect.Outcome) []string {
	names := make([]string, len(outs))
	for i, o := range outs {
		names[i] = o.Server.Name
	}
	return names
}

// mustRun calls Run and fails the test on an error.
func mustRun(ctx context.Context, t *testing.T, servers []discover.Server, opts inspect.Options, insp inspect.Inspector) []inspect.Outcome {
	t.Helper()
	outs, err := inspect.Run(ctx, servers, opts, insp)
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if len(outs) != len(servers) {
		t.Fatalf("Run() returned %d outcomes, want %d", len(outs), len(servers))
	}
	return outs
}

// mustRunTimed is mustRun plus the virtual time that Run took. Call it only
// inside a synctest bubble.
func mustRunTimed(ctx context.Context, t *testing.T, servers []discover.Server, opts inspect.Options, insp inspect.Inspector) ([]inspect.Outcome, time.Duration) {
	t.Helper()
	start := time.Now()
	outs := mustRun(ctx, t, servers, opts, insp)
	return outs, time.Since(start)
}

// checkStatus fails the test if the outcome does not have the wanted status
// or if Err and Status disagree.
func checkStatus(t *testing.T, o inspect.Outcome, want inspect.Status) {
	t.Helper()
	if o.Status != want {
		t.Errorf("%s: Status = %q, want %q (Err = %v)", o.Server.Name, o.Status, want, o.Err)
	}
	if (o.Err == nil) != (o.Status == inspect.StatusOK) {
		t.Errorf("%s: Err = %v with Status %q, want Err nil exactly when Status is ok", o.Server.Name, o.Err, o.Status)
	}
}

func TestRunOrder(t *testing.T) {
	t.Parallel()

	withArgs := func(args []string) discover.Server {
		s := fakeServer("beta")
		s.Source = "/a"
		s.Args = discover.NewArgs(args)
		return s
	}
	withProject := func(path string) discover.Server {
		s := fakeServer("alpha")
		s.Source = "/a"
		s.Scope = discover.ScopeProject
		s.ProjectPath = path
		return s
	}
	in := func(client discover.Client, source, name string) discover.Server {
		s := fakeServer(name)
		s.Client = client
		s.Source = source
		return s
	}

	// want is the expected order, written by hand:
	// Client, then Source, then Name, then the tie-breakers (Scope,
	// ProjectPath, Args).
	want := []discover.Server{
		in(discover.ClientClaudeCode, "/a", "alpha"),
		withProject("/p1"),
		withProject("/p2"),
		withArgs(nil),
		withArgs([]string{"a"}),
		withArgs([]string{"a", "b"}),
		withArgs([]string{"b"}),
		in(discover.ClientClaudeCode, "/a", "gamma"),
		in(discover.ClientClaudeCode, "/b", "alpha"),
		in(discover.ClientCodex, "/a", "alpha"),
		in(discover.ClientCursor, "/a", "alpha"),
		in(discover.ClientCursor, "/a", "beta"),
	}
	wantKeys := describeServers(want)

	opts := inspect.Options{Timeout: time.Second, Concurrency: 3}

	t.Run("sorted by client source name then tie-breakers", func(t *testing.T) {
		t.Parallel()

		reversed := slices.Clone(want)
		slices.Reverse(reversed)
		perms := map[string][]discover.Server{
			"already sorted": slices.Clone(want),
			"reversed":       reversed,
		}
		//nolint:gosec // A fixed seed gives the same shuffles on every run; this is not security code.
		rng := rand.New(rand.NewPCG(1, 2))
		for i := range 25 {
			p := slices.Clone(want)
			rng.Shuffle(len(p), func(a, b int) { p[a], p[b] = p[b], p[a] })
			perms[fmt.Sprintf("shuffle %d", i)] = p
		}

		for name, input := range perms {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				outs := mustRun(t.Context(), t, input, opts, &fakeInspector{})
				got := outcomeKeys(outs)
				if !slices.Equal(got, wantKeys) {
					t.Errorf("order of outcomes:\n got %q\nwant %q", got, wantKeys)
				}
			})
		}
	})

	t.Run("order does not depend on timing or concurrency", func(t *testing.T) {
		t.Parallel()

		for _, conc := range []int{1, 2, 5, 50} {
			t.Run(fmt.Sprintf("concurrency %d", conc), func(t *testing.T) {
				t.Parallel()
				synctest.Test(t, func(t *testing.T) {
					// The delay depends on the name, so the finish order differs
					// from the sort order.
					input := slices.Clone(want)
					//nolint:gosec // A fixed seed gives the same shuffle on every run; this is not security code.
					rand.New(rand.NewPCG(7, uint64(conc))).Shuffle(len(input), func(a, b int) { input[a], input[b] = input[b], input[a] })
					insp := &fakeInspector{fallback: func(ctx context.Context, s discover.Server) (inspect.Result, error) {
						d := time.Duration(len(s.Name)+int(s.Name[0])%5) * time.Second
						return okAfter(d)(ctx, s)
					}}
					o := inspect.Options{Timeout: time.Minute, Concurrency: conc}
					outs := mustRun(context.Background(), t, input, o, insp)
					if got := outcomeKeys(outs); !slices.Equal(got, wantKeys) {
						t.Errorf("order of outcomes:\n got %q\nwant %q", got, wantKeys)
					}
				})
			})
		}
	})
}

func TestRunDoesNotChangeInput(t *testing.T) {
	t.Parallel()

	servers := []discover.Server{
		fakeServer("zulu"),
		fakeServer("alpha"),
		fakeServer("mike"),
		fakeServer("bravo"),
	}
	before := slices.Clone(servers)
	beforeNames := serverNames(servers)

	outs := mustRun(t.Context(), t, servers, inspect.Options{Timeout: time.Second, Concurrency: 2}, &fakeInspector{})

	if !reflect.DeepEqual(servers, before) {
		t.Errorf("input slice changed: got names %v, want %v", serverNames(servers), beforeNames)
	}
	// The outcomes are sorted, so a Run that sorts the input in place would
	// make both lists equal. Check the two orders differ.
	if slices.Equal(outcomeNames(outs), serverNames(servers)) {
		t.Errorf("outcome names %v equal the input names: the test input must be unsorted", outcomeNames(outs))
	}
}

func serverNames(servers []discover.Server) []string {
	names := make([]string, len(servers))
	for i, s := range servers {
		names[i] = s.Name
	}
	return names
}

func TestRunConcurrencyBound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		servers     int
		concurrency int
		wantMax     int64
	}{
		{name: "one at a time", servers: 6, concurrency: 1, wantMax: 1},
		{name: "two", servers: 6, concurrency: 2, wantMax: 2},
		{name: "four", servers: 6, concurrency: 4, wantMax: 4},
		{name: "exactly as many as servers", servers: 6, concurrency: 6, wantMax: 6},
		{name: "more than servers", servers: 6, concurrency: 50, wantMax: 6},
		{name: "one server", servers: 1, concurrency: 4, wantMax: 1},
		{name: "default options", servers: 9, concurrency: inspect.DefaultConcurrency, wantMax: int64(inspect.DefaultConcurrency)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				insp := &fakeInspector{fallback: okAfter(time.Second)}
				opts := inspect.Options{Timeout: time.Minute, Concurrency: tt.concurrency}

				outs := mustRun(context.Background(), t, fakeServers(tt.servers), opts, insp)

				if got := insp.maxInFlight.Load(); got != tt.wantMax {
					t.Errorf("max concurrent inspections = %d, want %d", got, tt.wantMax)
				}
				if got := insp.calls.Load(); got != int64(tt.servers) {
					t.Errorf("Inspect calls = %d, want %d", got, tt.servers)
				}
				if got := insp.inFlight.Load(); got != 0 {
					t.Errorf("inspections still running after Run: %d", got)
				}
				for _, o := range outs {
					checkStatus(t, o, inspect.StatusOK)
				}
			})
		})
	}
}

func TestRunStatusMapping(t *testing.T) {
	t.Parallel()

	t.Run("ok", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			insp := &fakeInspector{fallback: okAfter(time.Second)}
			outs, elapsed := mustRunTimed(context.Background(), t, fakeServers(1), inspect.Options{Timeout: 5 * time.Second, Concurrency: 1}, insp)
			checkStatus(t, outs[0], inspect.StatusOK)
			if elapsed != time.Second {
				t.Errorf("elapsed = %s, want 1s", elapsed)
			}
		})
	})

	t.Run("hang gives timeout after exactly the timeout", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			insp := &fakeInspector{fallback: hang}
			outs, elapsed := mustRunTimed(context.Background(), t, fakeServers(1), inspect.Options{Timeout: 2 * time.Second, Concurrency: 1}, insp)
			checkStatus(t, outs[0], inspect.StatusTimeout)
			if !errors.Is(outs[0].Err, context.DeadlineExceeded) {
				t.Errorf("Err = %v, want it to wrap context.DeadlineExceeded", outs[0].Err)
			}
			if errors.Is(outs[0].Err, context.Canceled) {
				t.Errorf("Err = %v, must not wrap context.Canceled", outs[0].Err)
			}
			if elapsed != 2*time.Second {
				t.Errorf("elapsed = %s, want 2s", elapsed)
			}
		})
	})

	t.Run("slow server that stops on ctx gives timeout", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			insp := &fakeInspector{fallback: okAfter(time.Hour)}
			outs, elapsed := mustRunTimed(context.Background(), t, fakeServers(1), inspect.Options{Timeout: 3 * time.Second, Concurrency: 1}, insp)
			checkStatus(t, outs[0], inspect.StatusTimeout)
			if elapsed != 3*time.Second {
				t.Errorf("elapsed = %s, want 3s", elapsed)
			}
		})
	})

	t.Run("unrelated error after the timeout is still a timeout", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			insp := &fakeInspector{fallback: waitThenFail(errFake)}
			outs, _ := mustRunTimed(context.Background(), t, fakeServers(1), inspect.Options{Timeout: time.Second, Concurrency: 1}, insp)
			checkStatus(t, outs[0], inspect.StatusTimeout)
			if !errors.Is(outs[0].Err, context.DeadlineExceeded) {
				t.Errorf("Err = %v, want it to wrap context.DeadlineExceeded", outs[0].Err)
			}
		})
	})

	t.Run("nil error after the deadline is ok", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			insp := &fakeInspector{fallback: ignoreCtxThenOK(2 * time.Second)}
			outs := mustRun(context.Background(), t, fakeServers(1), inspect.Options{Timeout: time.Second, Concurrency: 1}, insp)
			checkStatus(t, outs[0], inspect.StatusOK)
		})
	})

	t.Run("immediate error gives failed", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			insp := &fakeInspector{fallback: failNow(errFake)}
			outs, elapsed := mustRunTimed(context.Background(), t, fakeServers(1), inspect.Options{Timeout: 5 * time.Second, Concurrency: 1}, insp)
			checkStatus(t, outs[0], inspect.StatusFailed)
			if !errors.Is(outs[0].Err, errFake) {
				t.Errorf("Err = %v, want it to wrap the inspector error", outs[0].Err)
			}
			if errors.Is(outs[0].Err, context.DeadlineExceeded) || errors.Is(outs[0].Err, context.Canceled) {
				t.Errorf("Err = %v, must not wrap a context error", outs[0].Err)
			}
			if elapsed != 0 {
				t.Errorf("elapsed = %s, want 0s", elapsed)
			}
		})
	})

	t.Run("an error that wraps DeadlineExceeded before the timeout is failed", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			// The server's own HTTP client may report a deadline error that
			// is not our timeout. Our context is still alive, so this is a
			// failure, not a timeout.
			insp := &fakeInspector{fallback: failNow(fmt.Errorf("remote: %w", context.DeadlineExceeded))}
			outs := mustRun(context.Background(), t, fakeServers(1), inspect.Options{Timeout: 5 * time.Second, Concurrency: 1}, insp)
			checkStatus(t, outs[0], inspect.StatusFailed)
		})
	})

	panicValues := []struct {
		name string
		v    any
	}{
		{name: "string", v: "boom"},
		{name: "error", v: errFake},
		{name: "int", v: 42},
		{name: "nil", v: nil},
	}
	for _, pv := range panicValues {
		t.Run("panic with "+pv.name+" fails only that server", func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				servers := fakeServers(5)
				insp := &fakeInspector{
					byName:   map[string]fakeBehaviour{"s02": panicWith(pv.v)},
					fallback: okAfter(time.Second),
				}
				outs := mustRun(context.Background(), t, servers, inspect.Options{Timeout: time.Minute, Concurrency: 2}, insp)
				for _, o := range outs {
					if o.Server.Name == "s02" {
						checkStatus(t, o, inspect.StatusFailed)
						if o.Err != nil && !strings.Contains(o.Err.Error(), "panicked") {
							t.Errorf("Err = %q, want it to contain %q", o.Err, "panicked")
						}
						continue
					}
					checkStatus(t, o, inspect.StatusOK)
				}
			})
		})
	}

	t.Run("panic value text reaches the error", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			insp := &fakeInspector{fallback: panicWith("kaboom-marker")}
			outs := mustRun(context.Background(), t, fakeServers(1), inspect.Options{Timeout: time.Second, Concurrency: 1}, insp)
			if outs[0].Err == nil || !strings.Contains(outs[0].Err.Error(), "kaboom-marker") {
				t.Errorf("Err = %v, want it to contain the panic value", outs[0].Err)
			}
		})
	})
}

func TestRunHangDoesNotBlockOthers(t *testing.T) {
	t.Parallel()

	// Concurrency 2, one server that hangs until its 10s timeout, and five
	// servers that take 1s each. Workers take servers in sort order.
	tests := []struct {
		name     string
		hangName string
		want     time.Duration
	}{
		{
			// Worker A takes the hang server at 0s and is busy until 10s.
			// Worker B runs the five 1s servers one after another: 0s to 5s.
			// The total is the 10s of the hang.
			name:     "hang first",
			hangName: "a-hang",
			want:     10 * time.Second,
		},
		{
			// The two workers share the five 1s servers first, in this
			// schedule: one worker runs 0s-1s, 1s-2s, 2s-3s (3 servers) and the
			// other runs 0s-1s, 1s-2s (2 servers). The second worker is free
			// at 2s, takes the hang server and holds it until its 10s timeout
			// at 12s. The total is 12s.
			name:     "hang last",
			hangName: "z-hang",
			want:     12 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				servers := []discover.Server{fakeServer(tt.hangName)}
				for i := range 5 {
					servers = append(servers, fakeServer(fmt.Sprintf("m%d", i)))
				}
				insp := &fakeInspector{
					byName:   map[string]fakeBehaviour{tt.hangName: hang},
					fallback: okAfter(time.Second),
				}
				// With a single worker the total would be 15s (10s + 5 x 1s),
				// so a total below 15s shows that the other worker went on.
				opts := inspect.Options{Timeout: 10 * time.Second, Concurrency: 2}

				outs, elapsed := mustRunTimed(context.Background(), t, servers, opts, insp)

				for _, o := range outs {
					if o.Server.Name == tt.hangName {
						checkStatus(t, o, inspect.StatusTimeout)
						continue
					}
					checkStatus(t, o, inspect.StatusOK)
				}
				if elapsed != tt.want {
					t.Errorf("elapsed = %s, want %s", elapsed, tt.want)
				}
			})
		})
	}
}

func TestRunSchedule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		servers     int
		concurrency int
		want        time.Duration
	}{
		// ceil(10 / 4) = 3 rounds of 1s: 4 + 4 + 2 servers.
		{name: "10 servers, concurrency 4", servers: 10, concurrency: 4, want: 3 * time.Second},
		{name: "10 servers, concurrency 1", servers: 10, concurrency: 1, want: 10 * time.Second},
		{name: "10 servers, concurrency 10", servers: 10, concurrency: 10, want: time.Second},
		{name: "10 servers, concurrency 100", servers: 10, concurrency: 100, want: time.Second},
		{name: "10 servers, concurrency 3", servers: 10, concurrency: 3, want: 4 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				insp := &fakeInspector{fallback: okAfter(time.Second)}
				opts := inspect.Options{Timeout: time.Minute, Concurrency: tt.concurrency}

				outs, elapsed := mustRunTimed(context.Background(), t, fakeServers(tt.servers), opts, insp)

				for _, o := range outs {
					checkStatus(t, o, inspect.StatusOK)
				}
				if elapsed != tt.want {
					t.Errorf("elapsed = %s, want %s", elapsed, tt.want)
				}
			})
		})
	}
}

func TestRunTimeoutStartsWhenServerStarts(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// One worker, three servers of 1s, a timeout of 1.5s. The third server
		// starts at 2s. If the timeout counted from the start of Run, the
		// second and third servers would time out.
		insp := &fakeInspector{fallback: okAfter(time.Second)}
		opts := inspect.Options{Timeout: 1500 * time.Millisecond, Concurrency: 1}

		outs, elapsed := mustRunTimed(context.Background(), t, fakeServers(3), opts, insp)

		for _, o := range outs {
			checkStatus(t, o, inspect.StatusOK)
		}
		if elapsed != 3*time.Second {
			t.Errorf("elapsed = %s, want 3s", elapsed)
		}
	})
}

func TestRunParentCancel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		servers     int
		concurrency int
		// wantCalls is the number of servers that start before the cancel.
		wantCalls int64
	}{
		{name: "one worker, rest wait in the queue", servers: 3, concurrency: 1, wantCalls: 1},
		{name: "two workers, rest wait in the queue", servers: 5, concurrency: 2, wantCalls: 2},
		{name: "everyone is running", servers: 3, concurrency: 3, wantCalls: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				time.AfterFunc(time.Second, cancel)

				insp := &fakeInspector{fallback: hang}
				// The timeout is longer than the cancel, so a timeout must not
				// be the reason for any outcome.
				opts := inspect.Options{Timeout: time.Hour, Concurrency: tt.concurrency}
				servers := fakeServers(tt.servers)

				outs, elapsed := mustRunTimed(ctx, t, servers, opts, insp)

				for i, o := range outs {
					checkStatus(t, o, inspect.StatusFailed)
					if !errors.Is(o.Err, context.Canceled) {
						t.Errorf("%s: Err = %v, want it to wrap context.Canceled", o.Server.Name, o.Err)
					}
					if errors.Is(o.Err, context.DeadlineExceeded) {
						t.Errorf("%s: Err = %v, must not wrap context.DeadlineExceeded", o.Server.Name, o.Err)
					}
					if !reflect.DeepEqual(o.Server, servers[i]) {
						t.Errorf("outcome %d: Server = %s, want %s", i, describeServer(o.Server), describeServer(servers[i]))
					}
				}
				if got := insp.calls.Load(); got != tt.wantCalls {
					t.Errorf("Inspect calls = %d, want %d (queued servers must not start)", got, tt.wantCalls)
				}
				if elapsed != time.Second {
					t.Errorf("elapsed = %s, want 1s (Run must return at the cancel)", elapsed)
				}
			})
		})
	}

	t.Run("pre-cancelled context", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			insp := &fakeInspector{fallback: okAfter(time.Second)}
			servers := fakeServers(4)
			outs, elapsed := mustRunTimed(ctx, t, servers, inspect.Options{Timeout: time.Minute, Concurrency: 2}, insp)

			for i, o := range outs {
				checkStatus(t, o, inspect.StatusFailed)
				if !errors.Is(o.Err, context.Canceled) {
					t.Errorf("%s: Err = %v, want it to wrap context.Canceled", o.Server.Name, o.Err)
				}
				if !reflect.DeepEqual(o.Server, servers[i]) {
					t.Errorf("outcome %d: Server = %s, want %s", i, describeServer(o.Server), describeServer(servers[i]))
				}
			}
			if got := insp.calls.Load(); got != 0 {
				t.Errorf("Inspect calls = %d, want 0", got)
			}
			if elapsed != 0 {
				t.Errorf("elapsed = %s, want 0s", elapsed)
			}
		})
	})

	t.Run("parent deadline is failed, not timeout", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			insp := &fakeInspector{fallback: hang}
			outs, elapsed := mustRunTimed(ctx, t, fakeServers(3), inspect.Options{Timeout: time.Hour, Concurrency: 1}, insp)

			for _, o := range outs {
				checkStatus(t, o, inspect.StatusFailed)
				if !errors.Is(o.Err, context.DeadlineExceeded) {
					t.Errorf("%s: Err = %v, want it to wrap the parent's context.DeadlineExceeded", o.Server.Name, o.Err)
				}
			}
			if got := insp.calls.Load(); got != 1 {
				t.Errorf("Inspect calls = %d, want 1", got)
			}
			if elapsed != time.Second {
				t.Errorf("elapsed = %s, want 1s", elapsed)
			}
		})
	})

	t.Run("server that finished before the cancel keeps its result", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			time.AfterFunc(1500*time.Millisecond, cancel)

			// One worker: s00 ends at 1s (ok), s01 runs from 1s and is
			// cancelled at 1.5s, s02 never starts.
			insp := &fakeInspector{
				byName:   map[string]fakeBehaviour{"s00": okAfter(time.Second)},
				fallback: hang,
			}
			outs := mustRun(ctx, t, fakeServers(3), inspect.Options{Timeout: time.Hour, Concurrency: 1}, insp)

			checkStatus(t, outs[0], inspect.StatusOK)
			checkStatus(t, outs[1], inspect.StatusFailed)
			checkStatus(t, outs[2], inspect.StatusFailed)
			for _, o := range outs[1:] {
				if !errors.Is(o.Err, context.Canceled) {
					t.Errorf("%s: Err = %v, want it to wrap context.Canceled", o.Server.Name, o.Err)
				}
			}
			if got := insp.calls.Load(); got != 2 {
				t.Errorf("Inspect calls = %d, want 2", got)
			}
		})
	})
}

func TestRunUnrelatedErrorWhileParentCancelled(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		time.AfterFunc(time.Second, cancel)

		// The inspector sees the cancel but returns an error that is not
		// related to ctx. Run must still report the cancel.
		insp := &fakeInspector{fallback: waitThenFail(errFake)}
		outs := mustRun(ctx, t, fakeServers(2), inspect.Options{Timeout: time.Hour, Concurrency: 2}, insp)

		for _, o := range outs {
			checkStatus(t, o, inspect.StatusFailed)
			if !errors.Is(o.Err, context.Canceled) {
				t.Errorf("%s: Err = %v, want it to wrap context.Canceled", o.Server.Name, o.Err)
			}
			if !errors.Is(o.Err, errFake) {
				t.Errorf("%s: Err = %v, want it to keep the inspector error too", o.Server.Name, o.Err)
			}
		}
	})
}

func TestRunErrors(t *testing.T) {
	t.Parallel()

	good := inspect.Options{Timeout: time.Second, Concurrency: 1}
	tests := []struct {
		name    string
		servers []discover.Server
		opts    inspect.Options
		insp    inspect.Inspector
		wantErr bool
	}{
		{name: "zero timeout", servers: fakeServers(2), opts: inspect.Options{Timeout: 0, Concurrency: 1}, insp: &fakeInspector{}, wantErr: true},
		{name: "negative timeout", servers: fakeServers(2), opts: inspect.Options{Timeout: -time.Second, Concurrency: 1}, insp: &fakeInspector{}, wantErr: true},
		{name: "zero concurrency", servers: fakeServers(2), opts: inspect.Options{Timeout: time.Second, Concurrency: 0}, insp: &fakeInspector{}, wantErr: true},
		{name: "negative concurrency", servers: fakeServers(2), opts: inspect.Options{Timeout: time.Second, Concurrency: -1}, insp: &fakeInspector{}, wantErr: true},
		{name: "zero options", servers: fakeServers(2), opts: inspect.Options{}, insp: &fakeInspector{}, wantErr: true},
		{name: "invalid options with no servers", servers: nil, opts: inspect.Options{}, insp: &fakeInspector{}, wantErr: true},
		{name: "nil inspector", servers: fakeServers(2), opts: good, insp: nil, wantErr: true},
		{name: "nil inspector with no servers", servers: nil, opts: good, insp: nil, wantErr: true},
		{name: "nil servers", servers: nil, opts: good, insp: &fakeInspector{}},
		{name: "empty servers", servers: []discover.Server{}, opts: good, insp: &fakeInspector{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			outs, err := inspect.Run(t.Context(), tt.servers, tt.opts, tt.insp)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if outs != nil {
				t.Errorf("Run() outcomes = %v, want nil", outs)
			}
			if fi, ok := tt.insp.(*fakeInspector); ok {
				if got := fi.calls.Load(); got != 0 {
					t.Errorf("Inspect calls = %d, want 0", got)
				}
			}
		})
	}
}

func TestRunOutcomes(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// Each server has its own result. The input is in reverse order and
		// has Args and Env, so DeepEqual proves that Server is copied whole.
		mk := func(name string) discover.Server {
			s := fakeServer(name)
			s.Args = discover.NewArgs([]string{"--token", "super-secret-arg"})
			s.Env = discover.SecretMap{"API_KEY": discover.NewSecret("super-secret-env")}
			return s
		}
		sortedNames := []string{"s1-ok", "s2-hang", "s3-fail", "s4-panic", "s5-ok-slow"}
		var servers []discover.Server
		for _, n := range slices.Backward(sortedNames) {
			servers = append(servers, mk(n))
		}
		want := map[string]inspect.Status{
			"s1-ok":      inspect.StatusOK,
			"s2-hang":    inspect.StatusTimeout,
			"s3-fail":    inspect.StatusFailed,
			"s4-panic":   inspect.StatusFailed,
			"s5-ok-slow": inspect.StatusOK,
		}
		insp := &fakeInspector{
			byName: map[string]fakeBehaviour{
				"s1-ok":      okAfter(0),
				"s2-hang":    hang,
				"s3-fail":    failNow(errFake),
				"s4-panic":   panicWith("boom"),
				"s5-ok-slow": okAfter(500 * time.Millisecond),
			},
		}

		outs := mustRun(context.Background(), t, servers, inspect.Options{Timeout: time.Second, Concurrency: 3}, insp)

		if got := outcomeNames(outs); !slices.Equal(got, sortedNames) {
			t.Fatalf("outcome order = %v, want %v", got, sortedNames)
		}
		wantServers := make([]discover.Server, len(sortedNames))
		for i, n := range sortedNames {
			wantServers[i] = mk(n)
		}
		for i, o := range outs {
			if o.Status == "" {
				t.Errorf("%s: Status is empty", o.Server.Name)
			}
			checkStatus(t, o, want[o.Server.Name])
			if !reflect.DeepEqual(o.Server, wantServers[i]) {
				t.Errorf("outcome %d: Server = %s, want %s", i, describeServer(o.Server), describeServer(wantServers[i]))
			}
			// Secrets from the config must not reach the error text.
			if o.Err != nil {
				for _, secret := range []string{"super-secret-arg", "super-secret-env"} {
					if strings.Contains(o.Err.Error(), secret) {
						t.Errorf("%s: Err %q contains the secret %q", o.Server.Name, o.Err, secret)
					}
				}
			}
		}
	})
}

// TestRunInspectorSeesPerServerContext checks that each call gets its own
// deadline and that the server passed to the inspector is the sorted element.
func TestRunInspectorSeesPerServerContext(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		deadlines := map[string]time.Duration{}
		start := time.Now()
		insp := &fakeInspector{fallback: func(ctx context.Context, s discover.Server) (inspect.Result, error) {
			dl, ok := ctx.Deadline()
			if !ok {
				return inspect.Result{}, errors.New("no deadline on the inspection context")
			}
			mu.Lock()
			deadlines[s.Name] = dl.Sub(start)
			mu.Unlock()
			return okAfter(time.Second)(ctx, s)
		}}
		opts := inspect.Options{Timeout: 5 * time.Second, Concurrency: 1}

		outs := mustRun(context.Background(), t, fakeServers(3), opts, insp)

		for _, o := range outs {
			checkStatus(t, o, inspect.StatusOK)
		}
		// Server i starts at i seconds, so its deadline is i + 5 seconds.
		for i := range 3 {
			name := fmt.Sprintf("s%02d", i)
			want := time.Duration(i)*time.Second + 5*time.Second
			if got := deadlines[name]; got != want {
				t.Errorf("%s: deadline = start+%s, want start+%s", name, got, want)
			}
		}
	})
}
