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
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
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
		// status is the inspection status that the --json report shows for
		// the identity.
		status report.InspectionStatus
	}{
		{
			name: "listed twice on a pinned identity is high", pinBefore: true,
			outcomes: []inspect.Outcome{okWith(tools), okWith(tools)},
			want:     []row{{"MOAT-T2-004", "high", reasonListedTwice}},
			status:   report.InspectionOK,
		},
		{
			name:     "listed twice on an identity that is not pinned is medium",
			outcomes: []inspect.Outcome{okWith(tools), okWith(tools)},
			want:     []row{{"MOAT-T2-004", "medium", reasonListedTwice}},
			status:   report.InspectionOK,
		},
		{
			name: "listed three times on a pinned identity gives a row for each extra", pinBefore: true,
			outcomes: []inspect.Outcome{okWith(tools), okWith(tools), okWith(tools)},
			want: []row{
				{"MOAT-T2-004", "high", reasonListedTwice},
				{"MOAT-T2-004", "high", reasonListedTwice},
			},
			status: report.InspectionOK,
		},
		{
			name: "not inspected on a pinned identity is high", pinBefore: true,
			outcomes: []inspect.Outcome{failed},
			want:     []row{{"MOAT-T2-004", "high", reasonNotInspected}},
			status:   report.InspectionFailed,
		},
		{
			name: "two failing outcomes with one pinned identity give one row", pinBefore: true,
			outcomes: []inspect.Outcome{failed, timedOut},
			want:     []row{{"MOAT-T2-004", "high", reasonNotInspected}},
			status:   report.InspectionFailed,
		},
		{
			name: "three failing outcomes with one pinned identity give one row", pinBefore: true,
			outcomes: []inspect.Outcome{failed, timedOut, failed},
			want:     []row{{"MOAT-T2-004", "high", reasonNotInspected}},
			status:   report.InspectionFailed,
		},
		{
			name:     "two failing outcomes with an identity that is not pinned give no row",
			outcomes: []inspect.Outcome{failed, timedOut},
			status:   report.InspectionFailed,
		},
		{
			name: "inspected after a failed outcome is still compared: no change", pinBefore: true,
			outcomes: []inspect.Outcome{failed, okWith(tools)},
			want:     []row{{"MOAT-T2-004", "high", reasonNotInspected}},
			status:   report.InspectionOK,
		},
		{
			name: "inspected after a failed outcome is still compared: change", pinBefore: true,
			outcomes: []inspect.Outcome{failed, okWith(changed)},
			want: []row{
				{"MOAT-T2-004", "high", reasonNotInspected},
				{"MOAT-T2-001", "high", ""},
			},
			status: report.InspectionOK,
		},
		{
			name: "failed, failed, then inspected: one failed row and the comparison", pinBefore: true,
			outcomes: []inspect.Outcome{failed, failed, okWith(changed)},
			want: []row{
				{"MOAT-T2-004", "high", reasonNotInspected},
				{"MOAT-T2-001", "high", ""},
			},
			status: report.InspectionOK,
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
			if got := pr.inspectionOf(srv); got != tt.status {
				t.Errorf("inspectionOf() = %q, want %q", got, tt.status)
			}
		})
	}
}

// TestPinOutcomesRemediation checks the Fix text of the pin rows. A
// MOAT-T2-004 row that scan makes itself gets its own fixed text. A row from
// pins.Compare keeps the text of its kind, unless the tools of the server
// cannot be pinned: then scan prints no "To accept" line, so every row of the
// server gets the fixed text for tools that cannot be pinned. A row with no
// "To accept" line never tells the user to run "pin --accept", which would
// refuse those tools.
func TestPinOutcomesRemediation(t *testing.T) {
	t.Parallel()

	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "/cfg/mcp.json"}
	relative := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "cfg/mcp.json"}
	tools := []inspect.Tool{mkTool("a", "Add.")}
	dup := []inspect.Tool{mkTool("a", "One."), mkTool("a", "Two.")}
	okWith := func(s discover.Server, ts []inspect.Tool) inspect.Outcome {
		return inspect.Outcome{Server: s, Status: inspect.StatusOK, Result: inspect.Result{Tools: ts}}
	}
	failed := inspect.Outcome{Server: srv, Status: inspect.StatusFailed, Err: errors.New("boom")}
	const notPinnable = "Do not use this server until its tools are valid, have unique names and fit the size limit of pins.json, then run mcpmoat scan again."

	tests := []struct {
		name      string
		pinBefore bool
		outcomes  []inspect.Outcome
		// want holds the rule ID and the Fix text of each row, in row order.
		want [][2]string
		// hint is true when scan prints a "To accept" line for the server.
		hint bool
		// scanMade is true when scan makes the one row itself. It is about
		// the whole server, so it has the server-level risk text.
		scanMade bool
	}{
		{
			name:     "listed twice",
			outcomes: []inspect.Outcome{okWith(srv, tools), okWith(srv, tools)},
			want:     [][2]string{{"MOAT-T2-004", "Remove the duplicate entry of this server from the config file, then run mcpmoat scan again."}},
			scanMade: true,
		},
		{
			name:     "relative config path",
			outcomes: []inspect.Outcome{okWith(relative, tools)},
			want:     [][2]string{{"MOAT-T2-004", "Run mcpmoat scan again with an absolute --config path, or from a working directory that mcpmoat can read."}},
			scanMade: true,
		},
		{
			name:      "pinned server not inspected",
			pinBefore: true,
			outcomes:  []inspect.Outcome{failed},
			want:      [][2]string{{"MOAT-T2-004", "Find out why the server could not be inspected (see its status in the summary), fix it, then run mcpmoat scan again."}},
			scanMade:  true,
		},
		{
			name:     "tools cannot be pinned",
			outcomes: []inspect.Outcome{okWith(srv, dup)},
			want:     [][2]string{{"MOAT-T2-004", notPinnable}},
			scanMade: true,
		},
		{
			name:      "row from pins.Compare for tools that cannot be pinned",
			pinBefore: true,
			outcomes:  []inspect.Outcome{okWith(srv, dup)},
			want:      [][2]string{{"MOAT-T2-004", notPinnable}},
		},
		{
			name:      "changed tool next to a duplicate tool name",
			pinBefore: true,
			outcomes:  []inspect.Outcome{okWith(srv, []inspect.Tool{mkTool("a", "Changed."), mkTool("b", "One."), mkTool("b", "Two.")})},
			want:      [][2]string{{"MOAT-T2-001", notPinnable}, {"MOAT-T2-004", notPinnable}},
		},
		{
			name:      "new tool next to an empty tool name",
			pinBefore: true,
			outcomes:  []inspect.Outcome{okWith(srv, []inspect.Tool{mkTool("", "No name."), mkTool("a", "Add."), mkTool("n", "New.")})},
			want:      [][2]string{{"MOAT-T2-004", notPinnable}, {"MOAT-T2-002", notPinnable}},
		},
		{
			name:      "changed tool keeps the text of the kind",
			pinBefore: true,
			outcomes:  []inspect.Outcome{okWith(srv, []inspect.Tool{mkTool("a", "Changed.")})},
			want:      [][2]string{{"MOAT-T2-001", pins.KindChanged.Remediation()}},
			hint:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			c, store := storeFor(t, e, tt.pinBefore, srv, tools)

			pr := c.pinOutcomes(store, tt.outcomes, &scanIgnores{})

			got := make([][2]string, len(pr.rows))
			for i, r := range pr.rows {
				got[i] = [2]string{r.RuleID, r.Remediation}
				if !tt.hint && strings.Contains(r.Remediation, "pin --accept") {
					t.Errorf("%s Remediation = %q, must not point to pin --accept", r.RuleID, r.Remediation)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("rows (rule ID, Fix) =\n%q\nwant\n%q", got, tt.want)
			}
			if tt.scanMade && (len(pr.rows) != 1 || pr.rows[0].Risk != riskServerUnverified) {
				t.Errorf("rows = %+v, want one row with the risk %q", pr.rows, riskServerUnverified)
			}
			if gotHint := len(pr.hints) > 0; gotHint != tt.hint {
				t.Errorf("hint = %v, want %v (hints %+v)", gotHint, tt.hint, pr.hints)
			}
		})
	}
}

// TestScanPinnedNotInspectedExit checks that scan exits 1 for a pinned server
// that was not inspected, shows the high row in the report and the failure in
// the SUMMARY block (not on stderr), and that --ignore of the rule is the only
// way to exit 0.
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
			stdout: []string{"MOAT-T2-004", "pinned server could not be inspected"},
		})
		assertSummaryStatus(t, got, "srv", "timeout", "inspect: no answer within 20ms: context deadline exceeded")
		findings := parseFindings(t, got.stdout)
		if len(findings) != 1 || findings[0].RuleID != "MOAT-T2-004" || findings[0].Severity != "high" || findings[0].Name != "srv" {
			t.Errorf("findings = %+v, want one high MOAT-T2-004 finding for srv", findings)
		}
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
			stderr:   []string{"1 finding ignored: MOAT-T2-004 (1)"},
			noStdout: []string{"MOAT-T2-004"},
		})
		assertSummaryStatus(t, got, "srv", "timeout", "inspect: no answer within 20ms: context deadline exceeded")
	})

	t.Run("an unpinned server that fails exits 0", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))

		got := e.scan(blockingInspector{}, "--timeout", "20ms")

		assertScanRun(t, got, scanWant{code: exitOK})
		assertSummaryStatus(t, got, "srv", "timeout", "inspect: no answer within 20ms: context deadline exceeded")
		assertNoPinRows(t, got.stdout)
	})
}

// parallelPinWarning is the warning of scan when another run pinned a server
// with other tools during the scan.
const parallelPinWarning = "mcpmoat scan: warning: server srv was pinned by another run with other tools during this scan; run scan again\n"

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
		// No notice for the identity that the other run pinned, but a warning:
		// the other run pinned other tools than this scan saw.
		assertContainsNone(t, "stderr", got.stderr, []string{"for srv"})
		assertContainsAll(t, "stderr", got.stderr, []string{parallelPinWarning})
		if n := strings.Count(got.stderr, "mcpmoat scan: pinned "); n != 1 {
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

		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}, stderr: []string{parallelPinWarning}})
		if got.stderr != parallelPinWarning {
			t.Errorf("stderr = %q, want only %q (no pinned notice)", got.stderr, parallelPinWarning)
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
		// The save created pins.json: its notice comes after the note and
		// before the "accepted" line, once.
		notice := newPinsFileNotice("pin", e.pinsPath())
		if i := strings.Index(out, notice); i < 0 || i <= note || i >= accepted {
			t.Errorf("want the note (%d), then the new pins file notice (%d), then accepted (%d)\noutput:\n%s", note, i, accepted, out)
		}
		if n := strings.Count(out, notice); n != 1 {
			t.Errorf("output has the new pins file notice %d times, want 1", n)
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

		// The save creates pins.json, so stderr holds the new pins file notice
		// and nothing else: no note.
		notice := newPinsFileNotice("pin", e.pinsPath())
		assertPinRun(t, got, scanWant{code: exitOK, stdout: []string{"accepted srv:"}, stderr: []string{notice}})
		if rest := withoutPinsFileNotice(t, got.stderr, "pin", e.pinsPath()); rest != "" {
			t.Errorf("stderr without the notice = %q, want empty", rest)
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

// TestFindingsTableHoldsNotInspectedReason checks that the FINDINGS block of a
// pinned server that was not inspected shows the severity group and the reason.
func TestFindingsTableHoldsNotInspectedReason(t *testing.T) {
	t.Parallel()

	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "/cfg/mcp.json"}
	e := newPinEnv(t, oneServer("srv"))
	c, store := storeFor(t, e, true, srv, []inspect.Tool{mkTool("a", "Add.")})

	pr := c.pinOutcomes(store, []inspect.Outcome{{Server: srv, Status: inspect.StatusFailed, Err: errors.New("boom")}}, &scanIgnores{})

	var out bytes.Buffer
	if err := report.WriteFindings(&out, pr.rows, report.Style{}); err != nil {
		t.Fatal(err)
	}
	// WriteFindings starts with a blank line, as it follows a table in a scan.
	got := parseFindings(t, "\n"+out.String())
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want one\n%s", got, out.String())
	}
	f := got[0]
	if f.RuleID != "MOAT-T2-004" || f.Severity != "high" || f.Name != "srv" {
		t.Errorf("finding = %s %s on %q, want a high MOAT-T2-004 finding on srv", f.RuleID, f.Severity, f.Name)
	}
	if f.Tool != "" || !strings.Contains(f.Reason, reasonNotInspected) {
		t.Errorf("Tool line = %q and Reason line = %q, want no Tool line and the reason %q", f.Tool, f.Reason, reasonNotInspected)
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

		code := c.acceptTools(t.Context(), srv, inspect.Result{Tools: tools}, "", false)

		if code != exitError || stdout.Len() != 0 || !strings.Contains(stderr.String(), "the path of its config file is not absolute") {
			t.Errorf("exit code %d, stdout %q, stderr %q, want exit code %d and the path error", code, stdout, stderr, exitError)
		}
		if _, err := os.Stat(e.pinsPath()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("pins.json exists after a refused pin (stat error = %v)", err)
		}
	})
}

// TestPinnedServerRefusedIsWarningOnly checks that a pinned server that a gate
// refuses (here: the client config turns it off) gives no finding, while a
// pinned server that fails gives a high one. The user, not the server, sets the
// state that a gate reads.
func TestPinnedServerRefusedIsWarningOnly(t *testing.T) {
	t.Parallel()

	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "/cfg/mcp.json", State: discover.StateDisabled}
	_, refused := inspect.New(inspect.SDKOptions{}).Inspect(t.Context(), srv)
	if !inspect.Refused(refused) {
		t.Fatalf("Inspect() error = %v, want a gate refusal", refused)
	}

	for _, tt := range []struct {
		name     string
		err      error
		wantRows int
	}{
		{"refused by a gate", refused, 0},
		{"failed", errors.New("boom"), 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			writePinsAside(t, e.pinsPath(), serverIdentity(srv), mkTool("a", "Add."))
			c, _, _ := e.cli(nil)
			store, ok := c.readPins("scan")
			if !ok {
				t.Fatal("readPins() = false, want true")
			}

			pr := c.pinOutcomes(store, []inspect.Outcome{{Server: srv, Status: inspect.StatusFailed, Err: tt.err}}, &scanIgnores{})

			if len(pr.rows) != tt.wantRows {
				t.Errorf("rows = %+v, want %d", pr.rows, tt.wantRows)
			}
		})
	}
}

// TestWarningText checks the stderr text of each inspection warning: keys and
// fixed names only, escaped.
func TestWarningText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		w    inspect.Warning
		want string
	}{
		{
			"cleartext secrets",
			inspect.Warning{Kind: inspect.WarnCleartextSecrets, HeaderKeys: []string{"Authorization", "X-Key\x1b[2J"}, URLUserInfo: true, URLSecrets: true},
			`server srv: cleartext-secrets: secrets go over plain http to a host that is not loopback: header Authorization, header "X-Key\x1b[2J", the user info of the URL, secret parts of the URL`,
		},
		{
			"undeclared capability",
			inspect.Warning{Kind: inspect.WarnUndeclaredCapability, Capabilities: []string{"tools", "prompts"}},
			"server srv: undeclared-capability: the server answered lists that it did not declare (it can show other lists to other clients): tools, prompts",
		},
		{
			"dns pin unavailable",
			inspect.Warning{Kind: inspect.WarnDNSPinUnavailable},
			"server srv: dns-pin-unavailable: a proxy from the environment resolves the host, so the DNS pin and the address checks do not apply",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := warningText("srv", tt.w); got != tt.want {
				t.Errorf("warningText() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestScanAndPinPrintInspectionWarnings checks where the warnings of an
// inspection go, also for a server that failed. scan shows them in the SUMMARY
// block on stdout and nothing on stderr. With --json there is no summary, so
// scan prints them on stderr, like pin.
func TestScanAndPinPrintInspectionWarnings(t *testing.T) {
	t.Parallel()

	undeclared := inspect.Warning{Kind: inspect.WarnUndeclaredCapability, Capabilities: []string{"tools"}}
	const text = "undeclared-capability: "

	// assertScanWarning checks that the one SUMMARY row of srv holds the warning
	// and that stderr holds no warning.
	assertScanWarning := func(t *testing.T, got pinRunResult, status string) {
		t.Helper()
		rows := summaryRows(t, got.stdout)
		if len(rows) != 1 || rows[0].Name != "srv" || rows[0].Status != status {
			t.Fatalf("summary rows = %+v, want one row for srv with the status %q\nstdout:\n%s", rows, status, got.stdout)
		}
		if len(rows[0].Warnings) != 1 || !strings.HasPrefix(rows[0].Warnings[0], text) {
			t.Errorf("warnings of srv = %q, want one that starts with %q", rows[0].Warnings, text)
		}
		assertContainsNone(t, "stderr", got.stderr, []string{"warning"})
	}

	t.Run("scan, inspected", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := &inspecttest.Fake{Results: map[string]inspect.Result{"srv": {Tools: []inspect.Tool{mkTool("a", "Add.")}, Warnings: []inspect.Warning{undeclared}}}}

		got := e.scan(fake)

		assertScanWarning(t, got, "ok")
	})

	t.Run("scan, failed", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := &inspecttest.Fake{Errors: map[string]error{"srv": &inspect.ConnectError{Kind: inspect.KindNetwork, Server: "srv", Reason: "refused", Warnings: []inspect.Warning{undeclared}}}}

		got := e.scan(fake)

		assertScanWarning(t, got, "failed")
	})

	t.Run("scan --json, failed", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := &inspecttest.Fake{Errors: map[string]error{"srv": &inspect.ConnectError{Kind: inspect.KindNetwork, Server: "srv", Reason: "refused", Warnings: []inspect.Warning{undeclared}}}}

		got := e.scan(fake, "--json")

		lines := nonEmptyLines(got.stderr)
		if len(lines) != 2 || !strings.HasPrefix(lines[0], "mcpmoat scan: warning: server srv: failed: ") ||
			!strings.HasPrefix(lines[1], "mcpmoat scan: warning: server srv: "+text) {
			t.Errorf("stderr = %q, want the failed line, then the warning", got.stderr)
		}
		if got.code != exitOK {
			t.Errorf("exit code = %d, want %d: the warnings do not change it", got.code, exitOK)
		}
		decodeScanJSON(t, got.stdout)
	})

	t.Run("pin", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := &inspecttest.Fake{Results: map[string]inspect.Result{"srv": {Tools: []inspect.Tool{mkTool("a", "Add.")}, Warnings: []inspect.Warning{undeclared}}}}

		got := e.pin(fake, "--accept", "srv")

		assertContainsAll(t, "stderr", got.stderr, []string{"mcpmoat pin: warning: server srv: " + text})
	})
}

// pinsReadingCommands are the two commands that read pins.json before they
// start any server. Each has a name for the subtests, a run function and an
// assert function that checks the run like assertScanRun or assertPinRun.
// The other fields say how the command differs: what it prints on stdout when
// it refuses the pins, what it prints on stderr when it works, and whether it
// saves pins.json again.
var pinsReadingCommands = []struct {
	name          string
	run           func(e *pinEnv, insp inspect.Inspector) pinRunResult
	assert        func(t *testing.T, r pinRunResult, want scanWant)
	refusedStdout []string // must be on stdout after a refusal; nil means stdout is empty
	okStderr      []string // must be on stderr after a run that works
	rewritesFile  bool     // a run that works saves a new pins.json with mode 0600
}{
	{
		name:          "scan",
		run:           func(e *pinEnv, insp inspect.Inspector) pinRunResult { return e.scan(insp) },
		assert:        assertScanRun,
		refusedStdout: []string{"not inspected, 0 findings (scan stopped before it inspected the servers"},
	},
	{
		name:         "pin --accept",
		run:          func(e *pinEnv, insp inspect.Inspector) pinRunResult { return e.pin(insp, "--accept", "srv") },
		assert:       assertPinRun,
		okStderr:     []string{noExpectNote},
		rewritesFile: true,
	},
}

// pinsPermTools returns the tools that the fake inspector gives the server srv
// in the pins permission tests. It returns a new map for each test.
func pinsPermTools() map[string][]inspect.Tool {
	return map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}}
}

// TestPinsInsecurePermissionsRefused checks that scan and "pin --accept" refuse
// a pins folder or a pins.json that group or others can write: exit code 2, the
// message names the path, the mode and the fix, nothing is printed on stdout,
// no server starts, and the run changes neither the mode nor the bytes of
// pins.json (FR-16, T2).
func TestPinsInsecurePermissionsRefused(t *testing.T) {
	t.Parallel()

	// The mode tables are in internal/pins. Here two modes per kind prove the wiring.
	cases := []struct {
		kind string // pinsKindDir or pinsKindFile
		mode os.FileMode
	}{
		{pinsKindDir, 0o777},
		{pinsKindDir, 0o770},
		{pinsKindFile, 0o666},
		{pinsKindFile, 0o660},
	}
	for _, cmd := range pinsReadingCommands {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s, %s %04o", cmd.name, tc.kind, tc.mode), func(t *testing.T) {
				t.Parallel()
				tools := pinsPermTools()
				e := newPinEnv(t, oneServer("srv"))
				firstScan(t, e, tools["srv"]...)
				setPinsMode(t, e, tc.kind, tc.mode)
				path := pinsStorePath(t, e, tc.kind)
				before := readFileBytes(t, e.pinsPath())
				fake := fakeServers(tools)

				got := cmd.run(e, fake)

				cmd.assert(t, got, scanWant{code: exitError, stderr: []string{
					"cannot read the pins file",
					"pins " + tc.kind + " " + path + " is not safe",
					fmt.Sprintf("mode %04o", tc.mode),
					"writable by group or others",
					chmodHint(path),
					pins.ErrInsecurePermissions.Error(),
				}})
				// scan still lists the servers and shows them as not inspected;
				// it prints no finding. pin --accept prints nothing.
				assertContainsNone(t, "stdout", got.stdout, []string{"FINDINGS", "MOAT-", "accepted"})
				if cmd.refusedStdout != nil {
					assertContainsAll(t, "stdout", got.stdout, cmd.refusedStdout)
				} else if got.stdout != "" {
					t.Errorf("stdout = %q, want empty", got.stdout)
				}
				if calls := fake.Calls(); len(calls) != 0 {
					t.Errorf("the inspector got the calls %v, want none: no server may start", calls)
				}
				if mode := modeOf(t, path); mode != tc.mode {
					t.Errorf("mode of %s = %04o after the run, want %04o: the run must not change it", path, mode, tc.mode)
				}
				if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(after, before) {
					t.Errorf("pins.json changed:\nbefore:\n%s\nafter:\n%s", before, after)
				}
			})
		}
	}
}

// chmodHint is the fix that the refusal message gives for an unsafe path: the
// chmod command with "--" and the path in single quotes.
func chmodHint(path string) string {
	return "chmod go-w -- '" + path + "'"
}

// TestPinsInsecureHintQuotesPath checks that the fix in the refusal message
// shell-quotes a path with a single quote, because the user copies it into a
// shell: the quote becomes quote, backslash, quote, quote. The tests of
// internal/pins cover the other odd paths.
func TestPinsInsecureHintQuotesPath(t *testing.T) {
	t.Parallel()

	tools := pinsPermTools()
	e := newPinEnv(t, oneServer("srv"))
	root := e.xdg
	e.xdg = filepath.Join(root, "it's")
	if err := os.MkdirAll(e.xdg, 0o700); err != nil {
		t.Fatal(err)
	}
	firstScan(t, e, tools["srv"]...)
	setPinsMode(t, e, pinsKindDir, 0o777)
	fake := fakeServers(tools)

	got := e.scan(fake)

	assertScanRun(t, got, scanWant{code: exitError, stderr: []string{
		"chmod go-w -- '" + filepath.Join(root, `it'\''s`, "mcpmoat") + "'",
		pins.ErrInsecurePermissions.Error(),
	}})
	if calls := fake.Calls(); len(calls) != 0 {
		t.Errorf("the inspector got the calls %v, want none: no server may start", calls)
	}
}

// TestPinsSafePermissionsWork checks that the normal modes still work: the
// folder 0700 with pins.json 0600 that mcpmoat makes itself, and the common
// modes 0755 and 0644, which group and others can read but not write.
func TestPinsSafePermissionsWork(t *testing.T) {
	t.Parallel()

	modes := []struct{ dir, file os.FileMode }{
		{0o700, 0o600},
		{0o755, 0o644},
	}
	for _, cmd := range pinsReadingCommands {
		for _, m := range modes {
			t.Run(fmt.Sprintf("%s, directory %04o and file %04o", cmd.name, m.dir, m.file), func(t *testing.T) {
				t.Parallel()
				tools := pinsPermTools()
				e := newPinEnv(t, oneServer("srv"))
				firstScan(t, e, tools["srv"]...)
				setPinsMode(t, e, pinsKindDir, m.dir)
				setPinsMode(t, e, pinsKindFile, m.file)
				fake := fakeServers(tools)

				got := cmd.run(e, fake)

				// The tools did not change, so the run finds nothing. A scan
				// prints nothing on stderr. A pin --accept prints its
				// --expect note, which is not an error.
				want := scanWant{code: exitOK, noStdout: []string{"MOAT-T2-"}, stderr: cmd.okStderr}
				cmd.assert(t, got, want)
				if calls := fake.Calls(); !slices.Equal(calls, []string{"srv"}) {
					t.Errorf("the inspector got the calls %v, want [srv]", calls)
				}
				if mode := modeOf(t, filepath.Dir(e.pinsPath())); mode != m.dir {
					t.Errorf("mode of the folder = %04o after the run, want %04o", mode, m.dir)
				}
				// pin --accept saves pins.json again, with a new file of mode
				// 0600; scan finds no change and does not save.
				wantFile := m.file
				if cmd.rewritesFile {
					wantFile = 0o600
				}
				if mode := modeOf(t, e.pinsPath()); mode != wantFile {
					t.Errorf("mode of pins.json = %04o after the run, want %04o", mode, wantFile)
				}
			})
		}
	}
}

// TestPinsFolderUnsafeBeforeSave checks the read that scan and "pin --accept"
// do again before they save: when a folder that did not exist at the first
// read has become writable by others during the inspection, the run refuses it
// with exit code 2, saves nothing and creates no pins.json. The first read
// already checks the folder, and the second read checks it again, so the check
// in Store.Save is not reachable from here without a hook that production code
// does not have. The tests of internal/pins cover Save.
func TestPinsFolderUnsafeBeforeSave(t *testing.T) {
	t.Parallel()

	for _, cmd := range pinsReadingCommands {
		t.Run(cmd.name, func(t *testing.T) {
			t.Parallel()
			skipWithoutModeBits(t)
			e := newPinEnv(t, oneServer("srv"))
			dir := filepath.Dir(e.pinsPath())
			restorePinsModes(t, e)
			insp := hookInspector{
				inner: fakeServers(pinsPermTools()),
				hook: onceFor("srv", func(discover.Server) {
					// A process makes the folder during the inspection, and lets everybody write it.
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Errorf("make the folder: %v", err)
						return
					}
					if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // G302: the test makes the folder unsafe on purpose
						t.Errorf("chmod the folder: %v", err)
					}
				}),
			}

			got := cmd.run(e, insp)

			cmd.assert(t, got, scanWant{code: exitError, stderr: []string{
				"cannot read the pins file",
				"pins directory " + dir + " is not safe",
				"mode 0777",
				chmodHint(dir),
			}, noStdout: []string{"accepted"}})
			e.assertNoPinsFile(t, "a refused folder")
		})
	}
}
