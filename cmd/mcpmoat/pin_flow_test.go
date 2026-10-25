package main

// In-process tests of the pin flow across scan and "pin --accept":
//
//   - a pinned server that was not inspected is a high MOAT-T2-004 finding,
//     also after a second outcome with the same identity;
//   - scan and "pin --accept" read pins.json again before they save, and keep
//     what another run wrote in the meantime;
//   - the "To accept" line says when a diff was cut;
//   - pin prints its --expect note before it saves.
//
// A run that writes pins.json while another run inspects its servers is
// simulated with a hookInspector: its hook runs inside Inspect, so inside the
// window between the first read and the save. None of the tests calls
// t.Setenv, so all of them run in parallel.

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// hintCutText is the end of a "To accept" line whose diff was cut. The text is
// spelled out here, so that a change of it shows in the tests.
const hintCutText = " (the diff was cut: review the full tool first)"

// hookInspector runs hook before it asks inner. The hook gets the server that
// is inspected and may run in any goroutine, so it must not call t.Fatal.
type hookInspector struct {
	inner inspect.Inspector
	hook  func(discover.Server)
}

func (h hookInspector) Inspect(ctx context.Context, s discover.Server) (inspect.Result, error) {
	h.hook(s)
	return h.inner.Inspect(ctx, s)
}

// writePinsAside simulates another mcpmoat run: it reads the pins file at path,
// sets the pins of the server id to tools and saves the file. It reports an
// error with t.Errorf and not t.Fatalf, because it can run in a goroutine of
// inspect.Run.
func writePinsAside(t *testing.T, path string, id pins.Identity, tools ...inspect.Tool) {
	t.Helper()
	store, err := pins.Load(path)
	if err != nil {
		t.Errorf("pins.Load(%q) error = %v, want nil", path, err)
		return
	}
	snap, err := pins.Snapshot(tools)
	if err != nil {
		t.Errorf("pins.Snapshot() error = %v, want nil", err)
		return
	}
	if err := store.Set(id, snap); err != nil {
		t.Errorf("Store.Set() error = %v, want nil", err)
		return
	}
	if err := store.Save(); err != nil {
		t.Errorf("Store.Save() error = %v, want nil", err)
	}
}

// corruptPinsAside writes content to the pins file at path, so that it cannot be
// read, like a hand edit that breaks the file.
func corruptPinsAside(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Errorf("make the folder of %s: %v", path, err)
		return
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Errorf("write %s: %v", path, err)
	}
}

// onceFor returns a hook that runs fn once, when the server called name is
// inspected.
func onceFor(name string, fn func(discover.Server)) func(discover.Server) {
	var once sync.Once
	return func(s discover.Server) {
		if s.Name == name {
			once.Do(func() { fn(s) })
		}
	}
}

// storeFor builds a cli and the store for a pinOutcomes call: srv is pinned with
// tools when pinned is true.
func storeFor(t *testing.T, e *pinEnv, pinned bool, srv discover.Server, tools []inspect.Tool) (*cli, *pins.Store) {
	t.Helper()
	c, _, _ := e.cli(nil)
	store, ok := c.readPins("scan")
	if !ok {
		t.Fatal("readPins() = false, want true")
	}
	if pinned {
		snap, err := pins.Snapshot(tools)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Set(serverIdentity(srv), snap); err != nil {
			t.Fatal(err)
		}
	}
	return c, store
}

// TestPinOutcomesUnverifiedSeverity checks the severity and the number of the
// MOAT-T2-004 rows that pinOutcomes makes for a server that scan cannot verify:
// "high" when the identity is pinned, "medium" when it is not. Discovery cannot
// give two servers with one identity, so the test builds the outcomes.
func TestPinOutcomesUnverifiedSeverity(t *testing.T) {
	t.Parallel()

	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "/cfg/mcp.json"}
	tools := []inspect.Tool{mkTool("a", "Add.")}
	changed := []inspect.Tool{mkTool("a", "Add. Changed.")}
	okWith := func(ts []inspect.Tool) inspect.Outcome {
		return inspect.Outcome{Server: srv, Status: inspect.StatusOK, Result: inspect.Result{Tools: ts}}
	}
	boom := errors.New("boom")
	failed := inspect.Outcome{Server: srv, Status: inspect.StatusFailed, Err: boom}
	timedOut := inspect.Outcome{Server: srv, Status: inspect.StatusTimeout, Err: boom}

	type row struct{ rule, severity, reason string }
	tests := []struct {
		name      string
		pinBefore bool
		outcomes  []inspect.Outcome
		want      []row
	}{
		{
			name: "listed twice on a pinned identity is high", pinBefore: true,
			outcomes: []inspect.Outcome{okWith(tools), okWith(tools)},
			want:     []row{{"MOAT-T2-004", "high", reasonListedTwice}},
		},
		{
			name:     "listed twice on an identity that is not pinned is medium",
			outcomes: []inspect.Outcome{okWith(tools), okWith(tools)},
			want:     []row{{"MOAT-T2-004", "medium", reasonListedTwice}},
		},
		{
			name: "listed three times on a pinned identity gives a row for each extra", pinBefore: true,
			outcomes: []inspect.Outcome{okWith(tools), okWith(tools), okWith(tools)},
			want: []row{
				{"MOAT-T2-004", "high", reasonListedTwice},
				{"MOAT-T2-004", "high", reasonListedTwice},
			},
		},
		{
			name: "not inspected on a pinned identity is high", pinBefore: true,
			outcomes: []inspect.Outcome{failed},
			want:     []row{{"MOAT-T2-004", "high", reasonNotInspected}},
		},
		{
			name: "two failing outcomes with one pinned identity give one row", pinBefore: true,
			outcomes: []inspect.Outcome{failed, timedOut},
			want:     []row{{"MOAT-T2-004", "high", reasonNotInspected}},
		},
		{
			name: "three failing outcomes with one pinned identity give one row", pinBefore: true,
			outcomes: []inspect.Outcome{failed, timedOut, failed},
			want:     []row{{"MOAT-T2-004", "high", reasonNotInspected}},
		},
		{
			name:     "two failing outcomes with an identity that is not pinned give no row",
			outcomes: []inspect.Outcome{failed, timedOut},
		},
		{
			name: "inspected after a failed outcome is still compared: no change", pinBefore: true,
			outcomes: []inspect.Outcome{failed, okWith(tools)},
			want:     []row{{"MOAT-T2-004", "high", reasonNotInspected}},
		},
		{
			name: "inspected after a failed outcome is still compared: change", pinBefore: true,
			outcomes: []inspect.Outcome{failed, okWith(changed)},
			want: []row{
				{"MOAT-T2-004", "high", reasonNotInspected},
				{"MOAT-T2-001", "high", ""},
			},
		},
		{
			name: "failed, failed, then inspected: one failed row and the comparison", pinBefore: true,
			outcomes: []inspect.Outcome{failed, failed, okWith(changed)},
			want: []row{
				{"MOAT-T2-004", "high", reasonNotInspected},
				{"MOAT-T2-001", "high", ""},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			c, store := storeFor(t, e, tt.pinBefore, srv, tools)

			pr := c.pinOutcomes(store, tt.outcomes, &scanIgnores{})

			var got []row
			for _, r := range pr.rows {
				got = append(got, row{r.RuleID, r.Severity, r.Related})
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("rows = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestScanPinnedNotInspectedExit checks that scan exits 1 for a pinned server
// that was not inspected, shows the high row and the reason in the report, and
// that --ignore of the rule is the only way to exit 0.
func TestScanPinnedNotInspectedExit(t *testing.T) {
	t.Parallel()

	pinned := []inspect.Tool{mkTool("a", "Add.")}

	t.Run("exit 1 and a high row with the reason", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, pinned...)

		got := e.scan(blockingInspector{}, "--timeout", "20ms")

		assertScanRun(t, got, scanWant{
			code:   exitFindings,
			stdout: []string{"MOAT-T2-004", "high", "pinned server could not be inspected"},
			stderr: []string{"warning: server srv: timeout: "},
		})
		// A server that was not inspected has no tools to show, so no hint.
		assertContainsNone(t, "stdout", got.stdout, []string{acceptHintPrefix})
	})

	t.Run("--ignore of the rule gives exit 0", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, pinned...)

		got := e.scan(blockingInspector{}, "--timeout", "20ms", "--ignore", "MOAT-T2-004")

		assertScanRun(t, got, scanWant{
			code:     exitOK,
			stderr:   []string{"warning: server srv: timeout: ", "1 finding ignored: MOAT-T2-004 (1)"},
			noStdout: []string{"MOAT-T2-004"},
		})
	})

	t.Run("an unpinned server that fails exits 0", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))

		got := e.scan(blockingInspector{}, "--timeout", "20ms")

		assertScanRun(t, got, scanWant{code: exitOK, stderr: []string{"warning: server srv: timeout: "}})
		assertNoPinRows(t, got.stdout)
	})
}

// TestScanFreshStoreKeepsOtherRun checks the lost-update narrowing of scan: scan
// reads pins.json again before it saves the first-run pins, and sets only the
// identities that the fresh store does not hold.
func TestScanFreshStoreKeepsOtherRun(t *testing.T) {
	t.Parallel()

	servers := map[string]any{
		"srv":   map[string]any{"command": "npx"},
		"other": map[string]any{"command": "npx"},
	}
	current := map[string][]inspect.Tool{
		"srv":   {mkTool("a", "Add.")},
		"other": {mkTool("o", "Other.")},
	}
	concurrent := mkTool("x", "Written by another run.")

	t.Run("an entry written meanwhile is kept, another identity is saved", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, servers)
		insp := hookInspector{
			inner: fakeServers(current),
			hook: onceFor("srv", func(s discover.Server) {
				writePinsAside(t, e.pinsPath(), serverIdentity(s), concurrent)
			}),
		}

		got := e.scan(insp)

		assertScanRun(t, got, scanWant{
			code:     exitOK,
			stdout:   []string{"srv", "other"},
			stderr:   []string{"mcpmoat scan: pinned 1 tool for other\n"},
			noStdout: []string{"MOAT-T2-"},
		})
		// No notice for the identity that the other run pinned.
		assertContainsNone(t, "stderr", got.stderr, []string{"for srv"})
		if n := strings.Count(got.stderr, "pinned "); n != 1 {
			t.Errorf("stderr has %d pinned notices, want 1\nstderr:\n%s", n, got.stderr)
		}
		file := e.readPins()
		if names := file.serverNames(); !slices.Equal(names, []string{"other", "srv"}) {
			t.Fatalf("servers in pins.json = %v, want [other srv]", names)
		}
		srvTools, _ := file.tools("srv")
		if got := slices.Sorted(maps.Keys(srvTools)); !slices.Equal(got, []string{"x"}) {
			t.Errorf("pinned tools of srv = %v, want [x] (the entry of the other run)", got)
		}
		otherTools, _ := file.tools("other")
		if got := slices.Sorted(maps.Keys(otherTools)); !slices.Equal(got, []string{"o"}) {
			t.Errorf("pinned tools of other = %v, want [o]", got)
		}
	})

	t.Run("every identity held by the fresh store: nothing is saved and no notice", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		insp := hookInspector{
			inner: fakeServers(current),
			hook: onceFor("srv", func(s discover.Server) {
				writePinsAside(t, e.pinsPath(), serverIdentity(s), concurrent)
			}),
		}

		got := e.scan(insp)

		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}})
		if got.stderr != "" {
			t.Errorf("stderr = %q, want empty (no pinned notice)", got.stderr)
		}
		srvTools, ok := e.readPins().tools("srv")
		if got := slices.Sorted(maps.Keys(srvTools)); !ok || !slices.Equal(got, []string{"x"}) {
			t.Errorf("pinned tools of srv = %v (found %v), want [x]", got, ok)
		}
	})

	t.Run("an unreadable pins file at save time exits 2 after the report", func(t *testing.T) {
		t.Parallel()
		const corrupt = "{this is not json"
		e := newPinEnv(t, servers)
		insp := hookInspector{
			inner: fakeServers(current),
			hook: onceFor("srv", func(discover.Server) {
				corruptPinsAside(t, e.pinsPath(), corrupt)
			}),
		}
		writePinsAside(t, e.pinsPath(), pins.Identity{Client: "x", Source: "/x", Name: "x"}, concurrent)

		got := e.scan(insp)

		assertScanRun(t, got, scanWant{
			code:   exitError,
			stdout: []string{"srv", "other"}, // the report is printed before the save
			stderr: []string{"mcpmoat scan: cannot read the pins file: "},
		})
		assertContainsNone(t, "stderr", got.stderr, []string{"pinned "})
		if after := string(readFileBytes(t, e.pinsPath())); after != corrupt {
			t.Errorf("pins.json = %q, want it unchanged (%q)", after, corrupt)
		}
	})

	t.Run("a scan with nothing to pin does not read the file again", func(t *testing.T) {
		t.Parallel()
		const corrupt = "{this is not json"
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("a", "Add."))
		insp := hookInspector{
			inner: fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}}),
			// A second read of this file would fail and give exit code 2.
			hook: onceFor("srv", func(discover.Server) {
				corruptPinsAside(t, e.pinsPath(), corrupt)
			}),
		}

		got := e.scan(insp)

		assertScanRun(t, got, scanWant{code: exitOK})
		if after := string(readFileBytes(t, e.pinsPath())); after != corrupt {
			t.Errorf("pins.json = %q, want it untouched by scan (%q)", after, corrupt)
		}
	})
}

// TestPinAcceptFreshStoreKeepsOtherEntries checks that "pin --accept" reads
// pins.json again after the digest check, sets only its own server and saves, so
// an entry that another run wrote during the inspection stays.
func TestPinAcceptFreshStoreKeepsOtherEntries(t *testing.T) {
	t.Parallel()

	servers := map[string]any{
		"target": map[string]any{"command": "npx"},
		"other":  map[string]any{"command": "npx"},
	}
	first := fakeServers(map[string][]inspect.Tool{
		"target": {mkTool("a", "Add.")},
		"other":  {mkTool("o", "Other.")},
	})
	current := fakeServers(map[string][]inspect.Tool{
		"target": {mkTool("a", "Add. Changed.")},
		"other":  {mkTool("o", "Other.")},
	})
	latecomer := mkTool("l", "Written by another run.")

	prepare := func(t *testing.T) *pinEnv {
		t.Helper()
		e := newPinEnv(t, servers)
		if got := e.scan(first); got.code != exitOK {
			t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
		}
		return e
	}
	// withExpect is the flags of the same accept with the digest of the tools.
	flagSets := []struct {
		name  string
		flags []string
	}{
		{"without --expect", nil},
		{"with --expect", []string{"--expect", digestOf(t, mkTool("a", "Add. Changed."))}},
	}

	for _, fs := range flagSets {
		t.Run("an entry for another server written meanwhile is kept "+fs.name, func(t *testing.T) {
			t.Parallel()
			e := prepare(t)
			insp := hookInspector{
				inner: current,
				hook: onceFor("target", func(s discover.Server) {
					id := serverIdentity(s)
					id.Name = "late"
					writePinsAside(t, e.pinsPath(), id, latecomer)
				}),
			}

			got := e.pin(insp, append([]string{"--accept", "target"}, fs.flags...)...)

			stderr := []string{}
			if len(fs.flags) == 0 {
				stderr = append(stderr, noExpectNote)
			}
			assertPinRun(t, got, scanWant{
				code:   exitOK,
				stdout: []string{"accepted target: 0 new, 1 changed, 0 removed\n"},
				stderr: stderr,
			})
			file := e.readPins()
			if names := file.serverNames(); !slices.Equal(names, []string{"late", "other", "target"}) {
				t.Fatalf("servers in pins.json = %v, want [late other target]", names)
			}
			late, _ := file.tools("late")
			if got := slices.Sorted(maps.Keys(late)); !slices.Equal(got, []string{"l"}) {
				t.Errorf("pinned tools of late = %v, want [l]", got)
			}
			other, _ := file.tools("other")
			if got := slices.Sorted(maps.Keys(other)); !slices.Equal(got, []string{"o"}) {
				t.Errorf("pinned tools of other = %v, want [o]", got)
			}
			// The accepted server holds the tools that pin saw: the next scan is clean.
			if next := e.scan(current); next.code != exitOK {
				t.Errorf("scan after the accept: exit code = %d\nstdout:\n%s", next.code, next.stdout)
			}
		})

		t.Run("the diff and the counts use the entry that the save replaces "+fs.name, func(t *testing.T) {
			t.Parallel()
			e := prepare(t)
			// Another run accepts the same tools while this pin inspects the
			// server, so the accept changes nothing.
			insp := hookInspector{
				inner: current,
				hook: onceFor("target", func(s discover.Server) {
					writePinsAside(t, e.pinsPath(), serverIdentity(s), mkTool("a", "Add. Changed."))
				}),
			}

			got := e.pin(insp, append([]string{"--accept", "target"}, fs.flags...)...)

			if want := "accepted target: 0 new, 0 changed, 0 removed\n"; got.code != exitOK || got.stdout != want {
				t.Errorf("exit code %d, stdout %q, want exit code %d and stdout %q", got.code, got.stdout, exitOK, want)
			}
		})

		t.Run("an unreadable pins file at save time exits 2 and saves nothing "+fs.name, func(t *testing.T) {
			t.Parallel()
			const corrupt = "{this is not json"
			e := prepare(t)
			insp := hookInspector{
				inner: current,
				hook: onceFor("target", func(discover.Server) {
					corruptPinsAside(t, e.pinsPath(), corrupt)
				}),
			}

			got := e.pin(insp, append([]string{"--accept", "target"}, fs.flags...)...)

			assertPinRun(t, got, scanWant{
				code:   exitError,
				stderr: []string{"mcpmoat pin: cannot read the pins file: "},
			})
			assertContainsNone(t, "stdout", got.stdout, []string{"accepted"})
			if after := string(readFileBytes(t, e.pinsPath())); after != corrupt {
				t.Errorf("pins.json = %q, want it unchanged (%q)", after, corrupt)
			}
		})
	}
}

// TestScanAcceptHintCutNote checks that the "To accept" line of a server has no
// command and ends with the cut note when a kept diff of that server was cut,
// and holds the command otherwise.
func TestScanAcceptHintCutNote(t *testing.T) {
	t.Parallel()

	short := []inspect.Tool{mkTool("a", "Add.")}
	longLines := linesDescription(2500)

	tests := []struct {
		name    string
		current []inspect.Tool
		flags   []string
		wantCut bool
	}{
		{
			name:    "a new tool with a cut diff",
			current: []inspect.Tool{mkTool("a", "Add."), mkTool("b", longLines)}, wantCut: true,
		},
		{
			name:    "a changed tool with a cut diff",
			current: []inspect.Tool{mkTool("a", longLines)}, wantCut: true,
		},
		{
			name:    "a small new tool",
			current: []inspect.Tool{mkTool("a", "Add."), mkTool("b", "New.")},
		},
		{
			name:    "a small changed tool",
			current: []inspect.Tool{mkTool("a", "Add. Changed.")},
		},
		{
			name:    "a large diff below the limits",
			current: []inspect.Tool{mkTool("a", linesDescription(1500))},
		},
		{
			// A removed tool has no diff, so nothing can be cut.
			name:    "a removed tool",
			current: nil,
		},
		{
			// The row of the cut diff is ignored and its diff is not kept: the
			// user did not miss anything in the report.
			name:    "the cut diff is ignored and another row is kept",
			current: []inspect.Tool{mkTool("a", "Add. Changed."), mkTool("b", longLines)},
			flags:   []string{"--ignore", "MOAT-T2-002"},
		},
		{
			name:    "the cut diff is kept and another row is ignored",
			current: []inspect.Tool{mkTool("a", longLines), mkTool("b", "New.")},
			flags:   []string{"--ignore", "MOAT-T2-002"}, wantCut: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			firstScan(t, e, short...)

			got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tt.current}), tt.flags...)

			if got.code != exitOK && got.code != exitFindings {
				t.Fatalf("exit code = %d, want 0 or 1\nstderr:\n%s", got.code, got.stderr)
			}
			line := acceptHintPrefix + "srv: mcpmoat pin --accept srv --config " + e.config + " --expect " + digestOf(t, tt.current...)
			if tt.wantCut || len(tt.flags) > 0 {
				// The user did not see every change (a cut diff, or a row that
				// --ignore dropped), so the line has no command.
				line = acceptHintPrefix + "srv: run pin --accept with this server name, --config with the file of this scan, and --expect " +
					digestOf(t, tt.current...)
			}
			if tt.wantCut {
				line += hintCutText
			}
			if len(tt.flags) > 0 {
				line += hintIgnoredNote
			}
			if !strings.HasSuffix(got.stdout, "\n"+line+"\n") {
				t.Errorf("stdout does not end with the hint %q\nstdout tail:\n%s", line, tail(got.stdout, 400))
			}
			wantNotes := 0
			if tt.wantCut {
				wantNotes = 1
			}
			if n := strings.Count(got.stdout, hintCutText); n != wantNotes {
				t.Errorf("stdout has the cut note %d times, want %d", n, wantNotes)
			}
			// The hint is data: it belongs on stdout, and the cut note never on stderr.
			assertContainsNone(t, "stderr", got.stderr, []string{hintCutText, acceptHintPrefix})
		})
	}
}

// TestScanAcceptHintCutNotePerServer checks that the cut note, and the line
// without a command, are for the server with the cut diff only.
func TestScanAcceptHintCutNotePerServer(t *testing.T) {
	t.Parallel()

	servers := map[string]any{
		"cut":   map[string]any{"command": "npx"},
		"small": map[string]any{"command": "npx"},
	}
	e := newPinEnv(t, servers)
	if got := e.scan(fakeServers(map[string][]inspect.Tool{
		"cut":   {mkTool("a", "Add.")},
		"small": {mkTool("a", "Add.")},
	})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}
	cutTools := []inspect.Tool{mkTool("a", linesDescription(2500))}
	smallTools := []inspect.Tool{mkTool("a", "Add. Changed.")}

	got := e.scan(fakeServers(map[string][]inspect.Tool{"cut": cutTools, "small": smallTools}))

	if got.code != exitFindings {
		t.Fatalf("exit code = %d, want %d\nstderr:\n%s", got.code, exitFindings, got.stderr)
	}
	_, hints := cutAcceptHints(got.stdout)
	want := []string{
		acceptHintPrefix + "cut: run pin --accept with this server name, --config with the file of this scan, and --expect " + digestOf(t, cutTools...) + hintCutText,
		acceptHintPrefix + "small: mcpmoat pin --accept small --config " + e.config + " --expect " + digestOf(t, smallTools...),
	}
	if !slices.Equal(hints, want) {
		t.Errorf("hint lines = %q, want %q", hints, want)
	}
}

// tail returns the last n bytes of s.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// pinShared runs "pin --config <file> args..." with one buffer for stdout and
// stderr, so that a test can check the order of lines between the two streams.
func (e *pinEnv) pinShared(insp inspect.Inspector, args ...string) (code int, out string) {
	e.t.Helper()
	c, _, _ := e.cli(insp)
	var buf bytes.Buffer
	c.stdout, c.stderr = &buf, &buf
	code = c.dispatch(append([]string{"pin", "--config", e.config}, args...))
	return code, buf.String()
}

// TestPinNoExpectNoteOrder checks that the note of a pin without --expect comes
// after the diffs and before the save, so before the "accepted" line, and that it
// shows when the save then fails. With --expect there is no note.
func TestPinNoExpectNoteOrder(t *testing.T) {
	t.Parallel()

	const newDiff = "New tool a on server srv:"
	tools := map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}}

	t.Run("the note is after the diff and before accepted", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))

		code, out := e.pinShared(fakeServers(tools), "--accept", "srv")

		if code != exitOK {
			t.Fatalf("exit code = %d, want %d\noutput:\n%s", code, exitOK, out)
		}
		diff, note, accepted := strings.Index(out, newDiff), strings.Index(out, noExpectNote), strings.Index(out, "accepted srv:")
		if diff < 0 || note < 0 || accepted < 0 || diff >= note || note >= accepted {
			t.Errorf("want the diff (%d), then the note (%d), then accepted (%d)\noutput:\n%s", diff, note, accepted, out)
		}
		if n := strings.Count(out, noExpectNote); n != 1 {
			t.Errorf("output has the note %d times, want 1", n)
		}
	})

	t.Run("the note shows when the save fails", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		readOnlyPinsDir(t, e)

		code, out := e.pinShared(fakeServers(tools), "--accept", "srv")

		if code != exitError {
			t.Fatalf("exit code = %d, want %d\noutput:\n%s", code, exitError, out)
		}
		diff, note, failure := strings.Index(out, newDiff), strings.Index(out, noExpectNote), strings.Index(out, "mcpmoat pin: cannot save the pins file: ")
		if diff < 0 || note < 0 || failure < 0 || diff >= note || note >= failure {
			t.Errorf("want the diff (%d), then the note (%d), then the save error (%d)\noutput:\n%s", diff, note, failure, out)
		}
		assertContainsNone(t, "output", out, []string{"accepted"})
	})

	t.Run("a pins file that cannot be read again stops pin before the diff and the note", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		insp := hookInspector{
			inner: fakeServers(tools),
			hook: onceFor("srv", func(discover.Server) {
				corruptPinsAside(t, e.pinsPath(), "{this is not json")
			}),
		}
		// The first read happens before the server runs, so the file must be
		// valid or missing then: the hook corrupts it during the inspection.

		code, out := e.pinShared(insp, "--accept", "srv")

		if code != exitError {
			t.Fatalf("exit code = %d, want %d\noutput:\n%s", code, exitError, out)
		}
		// pin reads the file again before it shows the diff, so the diff is
		// made against the entry that the save would replace.
		assertContainsAll(t, "output", out, []string{"mcpmoat pin: cannot read the pins file: "})
		assertContainsNone(t, "output", out, []string{newDiff, noExpectNote, "accepted"})
	})

	t.Run("with --expect there is no note", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))

		got := e.pin(fakeServers(tools), "--accept", "srv", "--expect", digestOf(t, tools["srv"]...))

		assertPinRun(t, got, scanWant{code: exitOK, stdout: []string{"accepted srv:"}})
		if got.stderr != "" {
			t.Errorf("stderr = %q, want empty", got.stderr)
		}
	})

	t.Run("a digest mismatch prints no note and saves nothing", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		wrong := digestOf(t, mkTool("a", "Another."))

		got := e.pin(fakeServers(tools), "--accept", "srv", "--expect", wrong)

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{"differ from what scan showed"}})
		assertContainsNone(t, "stderr", got.stderr, []string{"note: without --expect"})
		if _, err := os.Stat(e.pinsPath()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("pins.json exists after a digest mismatch (stat error = %v)", err)
		}
	})
}

// TestFindingsTableHoldsNotInspectedReason checks that the findings table of a
// pinned server that was not inspected shows the severity and the reason.
func TestFindingsTableHoldsNotInspectedReason(t *testing.T) {
	t.Parallel()

	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "/cfg/mcp.json"}
	e := newPinEnv(t, oneServer("srv"))
	c, store := storeFor(t, e, true, srv, []inspect.Tool{mkTool("a", "Add.")})

	pr := c.pinOutcomes(store, []inspect.Outcome{{Server: srv, Status: inspect.StatusFailed, Err: errors.New("boom")}}, &scanIgnores{})

	var out bytes.Buffer
	if err := report.WriteFindings(&out, pr.rows); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MOAT-T2-004", "high", "srv", "pinned server could not be inspected"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("findings table has no %q\n%s", want, out.String())
		}
	}
}

// TestPinOutcomesNotInspectedAfterDuplicate checks the MOAT-T2-004 row for a
// pinned server that was not inspected. A second outcome with an identity that
// the run already handled gets no "pinned server could not be inspected" row:
// the server was not pinned before this run, or it was checked in this run.
// Discovery cannot give two servers with one identity, so the test calls
// pinOutcomes with outcomes that it builds.
func TestPinOutcomesNotInspectedAfterDuplicate(t *testing.T) {
	t.Parallel()

	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "/cfg/mcp.json"}
	tools := []inspect.Tool{mkTool("a", "Add.")}
	ok := inspect.Outcome{Server: srv, Status: inspect.StatusOK, Result: inspect.Result{Tools: tools}}
	boom := errors.New("boom")
	failed := inspect.Outcome{Server: srv, Status: inspect.StatusFailed, Err: boom}
	timedOut := inspect.Outcome{Server: srv, Status: inspect.StatusTimeout, Err: boom}

	tests := []struct {
		name string
		// pinBefore says that srv is in the store before the run.
		pinBefore bool
		outcomes  []inspect.Outcome
		// wantReasons are the Related texts of the MOAT-T2-004 rows, in order.
		wantReasons []string
		// wantPinned is the number of servers that the run pinned for the first
		// time.
		wantPinned int
	}{
		{
			name:       "pinned in this run, then not inspected: no row",
			outcomes:   []inspect.Outcome{ok, failed},
			wantPinned: 1,
		},
		{
			name:       "pinned in this run, then timeout: no row",
			outcomes:   []inspect.Outcome{ok, timedOut},
			wantPinned: 1,
		},
		{
			name:        "pinned before the run and not inspected: row",
			pinBefore:   true,
			outcomes:    []inspect.Outcome{failed},
			wantReasons: []string{reasonNotInspected},
		},
		{
			name:        "pinned before the run and timeout: row",
			pinBefore:   true,
			outcomes:    []inspect.Outcome{timedOut},
			wantReasons: []string{reasonNotInspected},
		},
		{
			name:      "pinned before the run, checked in this run, then not inspected: no row",
			pinBefore: true,
			outcomes:  []inspect.Outcome{ok, failed},
		},
		{
			name:        "not inspected first, then inspected: row for the first only",
			pinBefore:   true,
			outcomes:    []inspect.Outcome{failed, ok},
			wantReasons: []string{reasonNotInspected},
		},
		{
			name:     "not in the store and not inspected: only a warning, no row",
			outcomes: []inspect.Outcome{failed},
		},
		{
			name:        "second inspected outcome is listed twice, not not inspected",
			outcomes:    []inspect.Outcome{ok, ok, failed},
			wantReasons: []string{reasonListedTwice},
			wantPinned:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			c, _, stderr := e.cli(nil)
			store, ok := c.readPins("scan")
			if !ok {
				t.Fatal("readPins() = false, want true")
			}
			if tt.pinBefore {
				snap, err := pins.Snapshot(tools)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Set(serverIdentity(srv), snap); err != nil {
					t.Fatal(err)
				}
			}

			pr := c.pinOutcomes(store, tt.outcomes, &scanIgnores{})

			var reasons []string
			for _, row := range pr.rows {
				if row.RuleID != "MOAT-T2-004" {
					t.Errorf("row = %+v, want only MOAT-T2-004 rows", row)
				}
				reasons = append(reasons, row.Related)
			}
			if !slices.Equal(reasons, tt.wantReasons) {
				t.Errorf("row reasons = %q, want %q", reasons, tt.wantReasons)
			}
			if len(pr.pinned) != tt.wantPinned {
				t.Errorf("pinned = %+v, want %d entries", pr.pinned, tt.wantPinned)
			}
			if stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty (pinOutcomes prints no warning here)", stderr.String())
			}
		})
	}
}

// cancelOnWrite is a writer that cancels a context on its first write, like a
// Ctrl-C while the output prints.
type cancelOnWrite struct {
	buf    *bytes.Buffer
	cancel context.CancelFunc
}

func (w cancelOnWrite) Write(p []byte) (int, error) {
	w.cancel()
	return w.buf.Write(p)
}

// TestSignalWhileOutputPrintsSavesNothing checks that a signal that comes after
// the inspection, while scan or pin writes its output, stops the save: exit 2,
// the interrupted message, and no change to pins.json.
func TestSignalWhileOutputPrintsSavesNothing(t *testing.T) {
	t.Parallel()

	for _, cmd := range []string{"scan", "pin"} {
		t.Run(cmd, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			c, _, stderr := e.cli(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}}))
			c.ctx = ctx
			var out bytes.Buffer
			c.stdout = cancelOnWrite{buf: &out, cancel: cancel}
			args := []string{"scan", "--config", e.config}
			if cmd == "pin" {
				args = []string{"pin", "--config", e.config, "--accept", "srv"}
			}

			code := c.dispatch(args)

			if code != exitError {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitError, out.String(), stderr.String())
			}
			assertContainsAll(t, "stderr", stderr.String(), []string{"mcpmoat " + cmd + ": " + interruptedText + "\n"})
			assertContainsNone(t, "output", out.String()+stderr.String(), []string{"accepted", "pinned 1 tool"})
			if _, err := os.Stat(e.pinsPath()); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("pins.json exists after an interrupted %s (stat error = %v)", cmd, err)
			}
		})
	}
}

// TestRelativeConfigPathIsNotPinned checks that a server whose config path is
// not absolute is neither pinned nor compared by scan (a high MOAT-T2-004 row),
// and that pin refuses it: its identity would not match the store.
func TestRelativeConfigPathIsNotPinned(t *testing.T) {
	t.Parallel()

	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "cfg/mcp.json"}
	tools := []inspect.Tool{mkTool("a", "Add.")}

	t.Run("scan", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		c, _, _ := e.cli(nil)
		store, ok := c.readPins("scan")
		if !ok {
			t.Fatal("readPins() = false, want true")
		}

		pr := c.pinOutcomes(store, []inspect.Outcome{{Server: srv, Status: inspect.StatusOK, Result: inspect.Result{Tools: tools}}}, &scanIgnores{})

		if len(pr.rows) != 1 || pr.rows[0].RuleID != "MOAT-T2-004" || pr.rows[0].Severity != "high" || pr.rows[0].Related != reasonRelativeSource {
			t.Errorf("rows = %+v, want one high MOAT-T2-004 row with the reason %q", pr.rows, reasonRelativeSource)
		}
		if len(pr.pinned) != 0 || len(pr.hints) != 0 {
			t.Errorf("pinned = %+v, hints = %+v, want none", pr.pinned, pr.hints)
		}
	})

	t.Run("pin", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		c, stdout, stderr := e.cli(nil)

		code := c.acceptTools(t.Context(), srv, tools, "")

		if code != exitError || stdout.Len() != 0 || !strings.Contains(stderr.String(), "the path of its config file is not absolute") {
			t.Errorf("exit code %d, stdout %q, stderr %q, want exit code %d and the path error", code, stdout, stderr, exitError)
		}
		if _, err := os.Stat(e.pinsPath()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("pins.json exists after a refused pin (stat error = %v)", err)
		}
	})
}
