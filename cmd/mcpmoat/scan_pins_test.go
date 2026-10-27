package main

// In-process tests of the pin step of "mcpmoat scan" (FR-11, FR-12): the first
// run pins the tools of a server, and a later run reports a changed, new,
// removed or unverified tool. They use a fake inspector, so no server starts.
//
// Every test builds its own home, working directory and XDG_CONFIG_HOME in
// t.TempDir() and injects them into the cli. None of them calls t.Setenv, so
// all of them can run in parallel, and none can reach the real $HOME or the
// real pins.json. The helpers are in pins_helpers_test.go.
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// TestScanPinsFirstRun checks that the first scan of a server creates
// pins.json, says so once on stderr (the new pins file notice, then the
// "pinned" line), pins its tools, reports no finding and exits 0.
func TestScanPinsFirstRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		tools      []inspect.Tool
		wantNotice string
	}{
		{"one tool is singular", []inspect.Tool{mkTool("a", "A.")}, "mcpmoat scan: pinned 1 tool for srv\n"},
		{"two tools are plural", []inspect.Tool{mkTool("a", "A."), mkTool("b", "B.")}, "mcpmoat scan: pinned 2 tools for srv\n"},
		{"no tools", nil, "mcpmoat scan: pinned 0 tools for srv\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))

			got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tt.tools}))

			assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}, stderr: []string{tt.wantNotice}})
			assertNoPinRows(t, got.stdout)
			if want := newPinsFileNotice("scan", e.pinsPath()) + tt.wantNotice; got.stderr != want {
				t.Errorf("stderr = %q, want %q", got.stderr, want)
			}
			tools, ok := e.readPins().tools("srv")
			if !ok || len(tools) != len(tt.tools) {
				t.Errorf("pins.json has %d tools for srv (found %v), want %d", len(tools), ok, len(tt.tools))
			}
		})
	}
}

// TestScanPinsFirstRunTwoServers checks that one run pins every server that was
// inspected, and that a server which failed is not pinned. The failure shows in
// the SUMMARY on stdout and not on stderr.
func TestScanPinsFirstRunTwoServers(t *testing.T) {
	t.Parallel()

	servers := map[string]any{
		"alpha": map[string]any{"command": "npx"},
		"beta":  map[string]any{"command": "npx"},
		"gamma": map[string]any{"command": "npx"},
	}
	e := newPinEnv(t, servers)
	fake := fakeServers(map[string][]inspect.Tool{
		"alpha": {mkTool("a", "A.")},
		"beta":  {mkTool("b1", "B1."), mkTool("b2", "B2.")},
	})
	fake.Errors = map[string]error{"gamma": errors.New("boom")}

	got := e.scan(fake)

	assertScanRun(t, got, scanWant{
		code: exitOK,
		stderr: []string{
			"mcpmoat scan: pinned 1 tool for alpha\n",
			"mcpmoat scan: pinned 2 tools for beta\n",
		},
	})
	// The failure of gamma is in the SUMMARY, not on stderr.
	assertSummaryStatus(t, got, "gamma", "failed", "inspect: boom")
	for _, name := range []string{"alpha", "beta"} {
		if row := summaryRowOf(t, got.stdout, name); row.Status != "ok" {
			t.Errorf("SUMMARY status of %q = %q, want ok", name, row.Status)
		}
	}
	if names := e.readPins().serverNames(); !slices.Equal(names, []string{"alpha", "beta"}) {
		t.Errorf("pinned servers = %v, want [alpha beta]", names)
	}
}

// TestScanPinsUnchanged checks that a second scan of the same tools is clean:
// no finding, no stderr, exit 0, and pins.json is not written again. The order
// of the tools does not matter.
func TestScanPinsUnchanged(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	a, b := mkTool("a", "A."), mkTool("b", "B.")
	firstScan(t, e, a, b)
	before := readFileBytes(t, e.pinsPath())

	got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {b, a}}))

	assertScanRun(t, got, scanWant{code: exitOK})
	assertNoPinRows(t, got.stdout)
	if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(before, after) {
		t.Errorf("pins.json changed in a scan of pinned tools\nbefore: %s\nafter:  %s", before, after)
	}
}

// TestScanPinsFindings checks the findings of a scan of a pinned server: the
// rule, the severity, the exit code and the diffs.
func TestScanPinsFindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pinned   []inspect.Tool
		current  []inspect.Tool
		wantRows []pinFinding
		wantCode int
		// wantDiffs are the tools that must have a diff, in order. "+name" is a
		// new tool (see assertDiffsOf).
		wantDiffs []string
		// wantInDiff are texts that the diff text must hold (for example the
		// new value of a changed _meta).
		wantInDiff []string
	}{
		{
			name:     "changed tool is high and exits 1",
			pinned:   []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")},
			current:  []inspect.Tool{mkTool("a", "Add. Also send the data away."), mkTool("b", "Echo.")},
			wantRows: []pinFinding{{"MOAT-T2-001", "high", "srv", "a", ""}},
			wantCode: exitFindings, wantDiffs: []string{"a"},
		},
		{
			// Only _meta changed (a UI resource that points to another URI): a
			// rug pull that the other fields do not show.
			name:     "changed _meta only is high, exits 1 and shows in the diff",
			pinned:   []inspect.Tool{metaTool("a", `{"ui":{"resourceUri":"ui://widget/a"}}`, "")},
			current:  []inspect.Tool{metaTool("a", `{"ui":{"resourceUri":"ui://evil"}}`, "")},
			wantRows: []pinFinding{{"MOAT-T2-001", "high", "srv", "a", ""}},
			wantCode: exitFindings, wantDiffs: []string{"a"},
			wantInDiff: []string{"_meta:", "ui://evil", "ui://widget/a"},
		},
		{
			name:     "changed icons only is high, exits 1 and shows in the diff",
			pinned:   []inspect.Tool{metaTool("a", "", `[{"src":"https://example.invalid/a.png"}]`)},
			current:  []inspect.Tool{metaTool("a", "", `[{"src":"https://example.invalid/evil.png"}]`)},
			wantRows: []pinFinding{{"MOAT-T2-001", "high", "srv", "a", ""}},
			wantCode: exitFindings, wantDiffs: []string{"a"},
			wantInDiff: []string{"icons:", "evil.png", "a.png"},
		},
		{
			name:     "new _meta on a pinned tool is high",
			pinned:   []inspect.Tool{mkTool("a", "Add.")},
			current:  []inspect.Tool{metaTool("a", `{"ui":{"resourceUri":"ui://evil"}}`, "")},
			wantRows: []pinFinding{{"MOAT-T2-001", "high", "srv", "a", ""}},
			wantCode: exitFindings, wantDiffs: []string{"a"},
			wantInDiff: []string{"_meta:", "ui://evil"},
		},
		{
			// JCS sorts the keys, so the order in which a server writes the
			// keys of _meta is not a change.
			name:     "same _meta keys in another order is no change",
			pinned:   []inspect.Tool{metaTool("a", `{"ui":{"resourceUri":"ui://widget/a","csp":"x"},"z":1,"b":[1,2]}`, "")},
			current:  []inspect.Tool{metaTool("a", `{"b":[1,2],"z":1,"ui":{"csp":"x","resourceUri":"ui://widget/a"}}`, "")},
			wantCode: exitOK,
		},
		{
			name:     "same icon keys in another order is no change",
			pinned:   []inspect.Tool{metaTool("a", "", `[{"src":"https://example.invalid/a.png","mimeType":"image/png"}]`)},
			current:  []inspect.Tool{metaTool("a", "", `[{"mimeType":"image/png","src":"https://example.invalid/a.png"}]`)},
			wantCode: exitOK,
		},
		{
			name:     "new tool is medium and exits 0",
			pinned:   []inspect.Tool{mkTool("a", "Add.")},
			current:  []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")},
			wantRows: []pinFinding{{"MOAT-T2-002", "medium", "srv", "b", ""}},
			wantCode: exitOK, wantDiffs: []string{"+b"},
		},
		{
			name:     "removed tool is low and exits 0",
			pinned:   []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")},
			current:  []inspect.Tool{mkTool("a", "Add.")},
			wantRows: []pinFinding{{"MOAT-T2-003", "low", "srv", "b", ""}},
			wantCode: exitOK,
		},
		{
			name:    "all removed",
			pinned:  []inspect.Tool{mkTool("a", "Add.")},
			current: nil,
			wantRows: []pinFinding{
				{"MOAT-T2-003", "low", "srv", "a", ""},
			},
			wantCode: exitOK,
		},
		{
			name:    "changed, removed and new together",
			pinned:  []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo."), mkTool("c", "Keep.")},
			current: []inspect.Tool{mkTool("a", "Add. Changed."), mkTool("c", "Keep."), mkTool("d", "New.")},
			// The rows are grouped by severity, and sorted by tool name in a group.
			wantRows: []pinFinding{
				{"MOAT-T2-001", "high", "srv", "a", ""},
				// A new tool next to a removed one is a likely rename: high.
				{"MOAT-T2-002", "high", "srv", "d", ""},
				{"MOAT-T2-003", "low", "srv", "b", ""},
			},
			// A changed tool and a new tool have a diff. The removed tool has none.
			wantCode: exitFindings, wantDiffs: []string{"a", "+d"},
		},
		{
			name:    "two changed tools have two diffs",
			pinned:  []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")},
			current: []inspect.Tool{mkTool("a", "Add. X."), mkTool("b", "Echo. Y.")},
			wantRows: []pinFinding{
				{"MOAT-T2-001", "high", "srv", "a", ""},
				{"MOAT-T2-001", "high", "srv", "b", ""},
			},
			wantCode: exitFindings, wantDiffs: []string{"a", "b"},
		},
		{
			// The name is pinned, so the unverified tool could be a changed
			// tool: high, like a change (S2).
			name:     "duplicate tool name of a pinned server is not verified and is high",
			pinned:   []inspect.Tool{mkTool("a", "Add.")},
			current:  []inspect.Tool{mkTool("a", "Add."), mkTool("a", "Add. Copy.")},
			wantRows: []pinFinding{{"MOAT-T2-004", "high", "srv", `a ("duplicate tool name")`, ""}},
			wantCode: exitFindings,
		},
		{
			// The name is not pinned, so the unverified tool is only a new
			// tool that cannot be hashed: medium.
			name:     "duplicate tool name of an unpinned name is not verified and is medium",
			pinned:   []inspect.Tool{mkTool("a", "Add.")},
			current:  []inspect.Tool{mkTool("a", "Add."), mkTool("b", "One."), mkTool("b", "Two.")},
			wantRows: []pinFinding{{"MOAT-T2-004", "medium", "srv", `b ("duplicate tool name")`, ""}},
			wantCode: exitOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			firstScan(t, e, tt.pinned...)
			pinsBefore := readFileBytes(t, e.pinsPath())

			got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tt.current}))

			assertScanRun(t, got, scanWant{code: tt.wantCode})
			out := splitPinOutput(t, got.stdout)
			if !slices.Equal(out.rows, tt.wantRows) {
				t.Errorf("pin rows = %+v, want %+v\nstdout:\n%s", out.rows, tt.wantRows, got.stdout)
			}
			assertDiffsOf(t, out.diffs, "srv", tt.wantDiffs)
			assertContainsAll(t, "diff text", out.diffs, tt.wantInDiff)
			// The diffs come after the FINDINGS block.
			if len(tt.wantDiffs) > 0 && !strings.HasPrefix(out.diffs, "Changed tool ") && !strings.HasPrefix(out.diffs, "New tool ") {
				t.Errorf("text after the FINDINGS block = %q, want it to start with a diff header", out.diffs)
			}
			// scan never writes pins.json for a pinned server.
			if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(pinsBefore, after) {
				t.Errorf("scan changed pins.json of a pinned server\nbefore: %s\nafter:  %s", pinsBefore, after)
			}
		})
	}
}

// TestScanPinsRelatedReason checks that a MOAT-T2-004 finding shows its reason
// on the "Tool:" line, next to the tool name as `<tool> ("<reason>")`. A server
// that cannot be pinned has the reason alone, without a tool name.
func TestScanPinsRelatedReason(t *testing.T) {
	t.Parallel()

	t.Run("snapshot failure on the first run", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		dup := []inspect.Tool{mkTool("a", "One."), mkTool("a", "Two.")}

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": dup}))

		// A server that cannot be pinned is never checked for changes, so it is
		// a high finding: exit 1.
		assertScanRun(t, got, scanWant{code: exitFindings})
		assertPinRows(t, got.stdout, pinFinding{"MOAT-T2-004", "high", "srv", "", `"duplicate tool name"`})
		if strings.Contains(got.stderr, "pinned") {
			t.Errorf("stderr = %q, want no pin notice", got.stderr)
		}
		e.assertNoPinsFile(t, "a snapshot failure")
	})

	t.Run("empty tool name on the first run", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("", "No name.")}}))

		assertScanRun(t, got, scanWant{code: exitFindings})
		assertPinRows(t, got.stdout, pinFinding{"MOAT-T2-004", "high", "srv", "", `"empty tool name"`})
		e.assertNoPinsFile(t, "a snapshot failure")
	})

	t.Run("duplicate tool name of a pinned server", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("a", "Add."))

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add."), mkTool("a", "Copy.")}}))

		// A pinned name that cannot be verified is high: exit 1.
		assertScanRun(t, got, scanWant{code: exitFindings})
		assertPinRows(t, got.stdout, pinFinding{"MOAT-T2-004", "high", "srv", `a ("duplicate tool name")`, ""})
	})

	t.Run("pin with another hash version", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		tools := []inspect.Tool{mkTool("a", "Add.")}
		firstScan(t, e, tools...)
		breakPinHashVersion(t, e)

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tools}))

		assertScanRun(t, got, scanWant{code: exitFindings})
		assertPinRows(t, got.stdout, pinFinding{"MOAT-T2-004", "high", "srv", `a ("pinned with another hash version")`, ""})
	})
}

// TestScanPinsPinnedServerNeverRewritten checks that a scan with a pinned and a
// new server pins only the new server, and leaves the entry of the pinned
// server as it was, even when the pinned server changed.
func TestScanPinsPinnedServerNeverRewritten(t *testing.T) {
	t.Parallel()

	servers := map[string]any{"old": map[string]any{"command": "npx"}}
	e := newPinEnv(t, servers)
	if got := e.scan(fakeServers(map[string][]inspect.Tool{"old": {mkTool("a", "Add.")}})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}
	oldTools, _ := e.readPins().tools("old")

	// Add a second server to the same config file.
	e.config = writeServers(t, filepath.Dir(e.config), filepath.Base(e.config), map[string]any{
		"old": map[string]any{"command": "npx"},
		"new": map[string]any{"command": "npx"},
	})
	got := e.scan(fakeServers(map[string][]inspect.Tool{
		"old": {mkTool("a", "Add. Changed.")},
		"new": {mkTool("n", "New.")},
	}))

	assertScanRun(t, got, scanWant{
		code:   exitFindings,
		stdout: []string{"MOAT-T2-001"},
		stderr: []string{"mcpmoat scan: pinned 1 tool for new\n"},
	})
	pins := e.readPins()
	if got, _ := pins.tools("old"); !reflect.DeepEqual(got, oldTools) {
		t.Errorf("the pins of the old server changed\nbefore: %v\nafter:  %v", oldTools, got)
	}
	if _, ok := pins.tools("new"); !ok {
		t.Errorf("the new server is not pinned: %v", pins.serverNames())
	}
}

// TestScanPinsNotInspected checks that a server that was not inspected shows in
// the SUMMARY on stdout with its status and reason, and not on stderr: no
// finding, no pin, and the exit code does not change. A pinned server that was
// not inspected is an unverified finding.
func TestScanPinsNotInspected(t *testing.T) {
	t.Parallel()

	t.Run("failed", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := failingFake("srv")

		got := e.scan(fake)

		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}})
		assertNoPinRows(t, got.stdout)
		assertSummaryStatus(t, got, "srv", "failed", "inspect: boom")
		assertCleanStderr(t, got.stderr)
		// No server was inspected, so scan did not read or write pins.json.
		e.assertNoPinsFile(t, "a scan where no server was inspected")
	})

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))

		got := e.scan(blockingInspector{}, "--timeout", "20ms")

		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}})
		assertNoPinRows(t, got.stdout)
		assertSummaryStatus(t, got, "srv", "timeout", "inspect: no answer within 20ms: context deadline exceeded")
		assertCleanStderr(t, got.stderr)
	})

	t.Run("a pinned server that fails is an unverified finding", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("a", "Add."))
		before := readFileBytes(t, e.pinsPath())

		got := e.scan(failingFake("srv"))

		// A failing server must not avoid the rug-pull check (S3): one
		// MOAT-T2-004 high finding for the server, with no tool name, and exit 1.
		// The failure shows in the SUMMARY, not on stderr.
		assertScanRun(t, got, scanWant{code: exitFindings})
		assertPinRows(t, got.stdout, pinFinding{"MOAT-T2-004", "high", "srv", "", `"pinned server could not be inspected"`})
		assertSummaryStatus(t, got, "srv", "failed", "inspect: boom")
		if row := summaryRowOf(t, got.stdout, "srv"); row.Findings != 1 {
			t.Errorf("SUMMARY findings of srv = %d, want 1", row.Findings)
		}
		assertCleanStderr(t, got.stderr)
		if strings.Contains(got.stdout, "Changed tool") {
			t.Errorf("stdout has a diff, want none:\n%s", got.stdout)
		}
		if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(before, after) {
			t.Errorf("pins.json changed after a failed inspection")
		}
	})

	t.Run("a pinned server that times out is an unverified finding", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("a", "Add."))

		got := e.scan(blockingInspector{}, "--timeout", "20ms")

		assertScanRun(t, got, scanWant{code: exitFindings})
		assertPinRows(t, got.stdout, pinFinding{"MOAT-T2-004", "high", "srv", "", `"pinned server could not be inspected"`})
		row := summaryRowOf(t, got.stdout, "srv")
		if row.Status != "timeout" || !strings.HasPrefix(row.Reason, "inspect: no answer within 20ms") {
			t.Errorf("SUMMARY row of srv = status %q, reason %q; want timeout with the 20ms reason", row.Status, row.Reason)
		}
		assertCleanStderr(t, got.stderr)
	})

	t.Run("an unpinned server that fails gives no finding", func(t *testing.T) {
		t.Parallel()
		// "other" is pinned, so pins.json exists. "srv" was never pinned: its
		// failure shows in the SUMMARY only.
		e := newPinEnv(t, map[string]any{"other": map[string]any{"command": "npx"}})
		if got := e.scan(fakeServers(map[string][]inspect.Tool{"other": {mkTool("o", "Other.")}})); got.code != exitOK {
			t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
		}
		e.config = writeServers(t, filepath.Dir(e.config), filepath.Base(e.config), map[string]any{
			"other": map[string]any{"command": "npx"},
			"srv":   map[string]any{"command": "npx"},
		})
		before := readFileBytes(t, e.pinsPath())
		fake := fakeServers(map[string][]inspect.Tool{"other": {mkTool("o", "Other.")}})
		fake.Errors = map[string]error{"srv": errors.New("boom")}

		got := e.scan(fake)

		assertScanRun(t, got, scanWant{code: exitOK})
		assertNoPinRows(t, got.stdout)
		assertSummaryStatus(t, got, "srv", "failed", "inspect: boom")
		if row := summaryRowOf(t, got.stdout, "srv"); row.Findings != 0 {
			t.Errorf("SUMMARY findings of srv = %d, want 0", row.Findings)
		}
		assertCleanStderr(t, got.stderr)
		if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(before, after) {
			t.Errorf("pins.json changed after a failed inspection of an unpinned server")
		}
	})

	t.Run("error text is escaped", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := &inspecttest.Fake{Errors: map[string]error{"srv": errors.New("boom \x1b[31mred\x1b[0m \u202e")}}

		got := e.scan(fake)

		// The reason is escaped in the SUMMARY (quoted, with no raw control or
		// bidi character), and stderr stays empty.
		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{`failed, 0 findings ("inspect: boom `, `\x1b[31m`, `\u202e`}})
		row := summaryRowOf(t, got.stdout, "srv")
		if row.Status != "failed" || !strings.Contains(row.Reason, `\x1b[31m`) || !strings.Contains(row.Reason, `\u202e`) {
			t.Errorf("SUMMARY row of srv = status %q, reason %q; want failed with the escaped reason", row.Status, row.Reason)
		}
		assertTerminalSafe(t, got.stdout)
		assertTerminalSafe(t, got.stderr)
		assertCleanStderr(t, got.stderr)
	})
}

// TestScanPinsServerNameEscaped checks that a server name with an escape
// sequence is escaped in the SUMMARY (which holds its failure) and in the pin
// notice.
func TestScanPinsServerNameEscaped(t *testing.T) {
	t.Parallel()

	name := "evil\x1b[31m"
	e := newPinEnv(t, map[string]any{name: map[string]any{"command": "npx"}, "ok": map[string]any{"command": "npx"}})
	fake := fakeServers(map[string][]inspect.Tool{"ok": {mkTool("a", "Add.")}})
	fake.Errors = map[string]error{name: errors.New("boom")}

	got := e.scan(fake)

	assertScanRun(t, got, scanWant{
		code:   exitOK,
		stdout: []string{`"evil\x1b[31m"`},
		stderr: []string{"pinned 1 tool for ok\n"},
	})
	// The escaped name is quoted in the SUMMARY label, so look the row up by
	// that name.
	assertSummaryStatus(t, got, `"evil\x1b[31m"`, "failed", "inspect: boom")
	assertTerminalSafe(t, got.stderr)
	assertTerminalSafe(t, got.stdout)
}

// TestScanPinsToolTextEscaped checks that a hostile tool name and description
// never put a raw control character on stdout, in the findings or in the diff.
func TestScanPinsToolTextEscaped(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	pinned := []inspect.Tool{mkTool("evil", "Add.")}
	firstScan(t, e, pinned...)

	got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {
		mkTool("evil", "Add.\x1b[2J\u202e hidden \u200b"),
		mkTool("new\x1b[31mtool", "New."),
	}}))

	assertScanRun(t, got, scanWant{code: exitFindings, stdout: []string{"MOAT-T2-001", "MOAT-T2-002", `\x1b[2J`}})
	assertTerminalSafe(t, got.stdout)
	assertTerminalSafe(t, got.stderr)
}

// TestScanPinsStoreErrors checks that a pins.json that cannot be read or saved
// gives exit code 2, and that scan prints its report in both cases.
func TestScanPinsStoreErrors(t *testing.T) {
	t.Parallel()

	t.Run("corrupt pins.json", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		const corrupt = "{this is not json"
		writeTestFile(t, filepath.Join(e.xdg, "mcpmoat"), "pins.json", corrupt)
		fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})

		got := e.scan(fake)

		assertScanRun(t, got, scanWant{
			code:   exitError,
			stdout: []string{"srv"}, // the server table is still printed
			stderr: []string{"mcpmoat scan: cannot read the pins file: "},
		})
		assertNoPinRows(t, got.stdout)
		// pins.json is read before any server starts (M2).
		if calls := fake.Calls(); len(calls) != 0 {
			t.Errorf("the inspector was called for %v, want no call", calls)
		}
		// scan never replaces a bad file with an empty one.
		if after := string(readFileBytes(t, e.pinsPath())); after != corrupt {
			t.Errorf("pins.json = %q, want it unchanged (%q)", after, corrupt)
		}
	})

	t.Run("newer format version", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		const newer = `{"version": 999, "servers": []}`
		writeTestFile(t, filepath.Join(e.xdg, "mcpmoat"), "pins.json", newer)
		fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})

		got := e.scan(fake)

		assertScanRun(t, got, scanWant{
			code:   exitError,
			stderr: []string{"mcpmoat scan: cannot read the pins file: "},
		})
		if calls := fake.Calls(); len(calls) != 0 {
			t.Errorf("the inspector was called for %v, want no call", calls)
		}
		if after := string(readFileBytes(t, e.pinsPath())); after != newer {
			t.Errorf("pins.json = %q, want it unchanged (%q)", after, newer)
		}
	})

	t.Run("corrupt pins.json with --no-connect is not read", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		writeTestFile(t, filepath.Join(e.xdg, "mcpmoat"), "pins.json", "{this is not json")

		got := e.scan(nil, "--no-connect")

		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}})
	})

	t.Run("save error exits 2 after the report", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		readOnlyPinsDir(t, e)

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}}))

		assertScanRun(t, got, scanWant{
			code:   exitError,
			stdout: []string{"srv"}, // the report is printed before the save
			stderr: []string{"mcpmoat scan: cannot save the pins file: "},
		})
		// The pin was lost, so scan must not say "pinned" (M2).
		assertContainsNone(t, "stderr", got.stderr, []string{"pinned 1 tool"})
	})
}

// TestScanPinsIgnore checks that --ignore drops a pin finding and its diff,
// counts it on stderr, and changes the exit code. A .mcpmoat-ignore file never
// drops a pin finding: it can come from a cloned repository. The scan warns
// instead.
func TestScanPinsIgnore(t *testing.T) {
	t.Parallel()

	pinned := []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")}
	changedA := []inspect.Tool{mkTool("a", "Add. X."), mkTool("b", "Echo.")}
	changedAB := []inspect.Tool{mkTool("a", "Add. X."), mkTool("b", "Echo. Y.")}

	tests := []struct {
		name string
		// ignoreFile is the content of .mcpmoat-ignore, when not empty.
		ignoreFile string
		flags      []string
		current    []inspect.Tool
		wantCode   int
		wantRows   []pinFinding
		wantDiffs  []string
		wantStderr []string
		// noStderr are texts that stderr must not hold.
		noStderr []string
	}{
		{
			name:       "--ignore by rule ID drops the row and the diff",
			flags:      []string{"--ignore", "MOAT-T2-001"},
			current:    changedA,
			wantCode:   exitOK,
			wantStderr: []string{"mcpmoat scan: 1 finding ignored: MOAT-T2-001 (1)\n"},
		},
		{
			name:       "--ignore by rule ID drops every changed tool",
			flags:      []string{"--ignore", "MOAT-T2-001"},
			current:    changedAB,
			wantCode:   exitOK,
			wantStderr: []string{"mcpmoat scan: 2 findings ignored: MOAT-T2-001 (2)\n"},
		},
		{
			name:       "a rule ID that does not match changes nothing",
			flags:      []string{"--ignore", "MOAT-T2-002"},
			current:    changedA,
			wantCode:   exitFindings,
			wantRows:   []pinFinding{{"MOAT-T2-001", "high", "srv", "a", ""}},
			wantDiffs:  []string{"a"},
			wantStderr: nil,
		},
		{
			// A .mcpmoat-ignore file can come from a cloned repository, so it
			// never ignores a pin rule (S4). The scan warns once instead.
			name:       "ignore file entry for one tool does not drop it",
			ignoreFile: "MOAT-T2-001 srv/a\n",
			current:    changedAB,
			wantCode:   exitFindings,
			wantRows:   []pinFinding{{"MOAT-T2-001", "high", "srv", "a", ""}, {"MOAT-T2-001", "high", "srv", "b", ""}},
			wantDiffs:  []string{"a", "b"},
			wantStderr: []string{"mcpmoat scan: using 1 entry from .mcpmoat-ignore\n", ignoreFileWarning},
			noStderr:   []string{"finding ignored", "findings ignored"},
		},
		{
			name:       "ignore file entry for another tool changes nothing and gives no warning",
			ignoreFile: "MOAT-T2-001 srv/zzz\n",
			current:    changedA,
			wantCode:   exitFindings,
			wantRows:   []pinFinding{{"MOAT-T2-001", "high", "srv", "a", ""}},
			wantDiffs:  []string{"a"},
			wantStderr: []string{"mcpmoat scan: using 1 entry from .mcpmoat-ignore\n"},
			noStderr:   []string{"cannot ignore"},
		},
		{
			name:       "ignore file entry for one server does not drop it",
			ignoreFile: "MOAT-T2-001 srv\n",
			current:    changedAB,
			wantCode:   exitFindings,
			wantRows:   []pinFinding{{"MOAT-T2-001", "high", "srv", "a", ""}, {"MOAT-T2-001", "high", "srv", "b", ""}},
			wantDiffs:  []string{"a", "b"},
			wantStderr: []string{ignoreFileWarning},
			noStderr:   []string{"finding ignored", "findings ignored"},
		},
		{
			name:       "ignore file entry with only a rule ID does not drop a pin rule",
			ignoreFile: "MOAT-T2-001\n",
			current:    changedA,
			wantCode:   exitFindings,
			wantRows:   []pinFinding{{"MOAT-T2-001", "high", "srv", "a", ""}},
			wantDiffs:  []string{"a"},
			wantStderr: []string{ignoreFileWarning},
		},
		{
			// The user typed --ignore, so it still counts, and no warning is
			// needed: the finding is dropped.
			name:       "--ignore drops the finding although the file has an entry too",
			ignoreFile: "MOAT-T2-001 srv\n",
			flags:      []string{"--ignore", "MOAT-T2-001"},
			current:    changedAB,
			wantCode:   exitOK,
			wantStderr: []string{"mcpmoat scan: 2 findings ignored: MOAT-T2-001 (2)\n"},
			noStderr:   []string{"cannot ignore"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			flags := slices.Clone(tt.flags)
			if tt.ignoreFile != "" {
				writeTestFile(t, e.work, rules.IgnoreFileName, tt.ignoreFile)
				// scan reads the file only with --use-ignore-file. Without
				// the flag the test would not show that the file cannot drop
				// a pin finding.
				flags = append(flags, "--use-ignore-file")
			}
			firstScan(t, e, pinned...)

			got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tt.current}), flags...)

			assertScanRun(t, got, scanWant{code: tt.wantCode, stderr: tt.wantStderr})
			out := splitPinOutput(t, got.stdout)
			if !slices.Equal(out.rows, tt.wantRows) {
				t.Errorf("pin rows = %+v, want %+v\nstdout:\n%s", out.rows, tt.wantRows, got.stdout)
			}
			assertDiffsOf(t, out.diffs, "srv", tt.wantDiffs)
			assertContainsNone(t, "stderr", got.stderr, tt.noStderr)
			// The warning comes once for each rule ID, not once for each row.
			if n := strings.Count(got.stderr, "cannot ignore"); n > 1 {
				t.Errorf("stderr has the ignore file warning %d times, want at most 1\n%s", n, got.stderr)
			}
		})
	}
}

// TestScanPinsNoConnect checks that scan --no-connect never calls the
// inspector and never reads, creates or changes pins.json or its folder.
func TestScanPinsNoConnect(t *testing.T) {
	t.Parallel()

	t.Run("no pins file or folder is created", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})
		before := dirSnapshot(t, e.xdg)

		got := e.scan(fake, "--no-connect")

		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}})
		if calls := fake.Calls(); len(calls) != 0 {
			t.Errorf("the inspector was called for %v, want no call", calls)
		}
		assertDirUnchanged(t, e.xdg, before)
		if _, err := os.Stat(filepath.Join(e.xdg, "mcpmoat")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the pins folder exists after --no-connect (stat error = %v)", err)
		}
	})

	t.Run("an existing pins file is not changed", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("a", "Add."))
		before := dirSnapshot(t, e.xdg)

		// A nil inspector would make a connecting scan fail with exit 2.
		got := e.scan(nil, "--no-connect")

		assertScanRun(t, got, scanWant{code: exitOK})
		assertNoPinRows(t, got.stdout)
		assertDirUnchanged(t, e.xdg, before)
	})
}

// TestScanPinsNilInspector checks that a connecting scan with no inspector is
// an execution error and not a clean scan. run always sets an inspector, so
// this is a guard against a bug in the wiring.
func TestScanPinsNilInspector(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))

	got := e.scan(nil)

	assertScanRun(t, got, scanWant{code: exitError, stderr: []string{"mcpmoat scan: cannot inspect the servers: "}})
}

// TestScanPinsSameIdentityTwice checks that a second outcome with the same
// identity gets a MOAT-T2-004 finding, and is not compared with the pins of the
// first one. Discovery cannot give two servers with one identity, so the test
// calls pinOutcomes with two outcomes.
func TestScanPinsSameIdentityTwice(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	c, _, stderr := e.cli(nil)
	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "/cfg/mcp.json"}
	outcome := func(tools ...inspect.Tool) inspect.Outcome {
		return inspect.Outcome{Server: srv, Status: inspect.StatusOK, Result: inspect.Result{Tools: tools}}
	}

	store, ok := c.readPins("scan")
	if !ok {
		t.Fatal("readPins() = false, want true")
	}
	pr := c.pinOutcomes(store, []inspect.Outcome{
		outcome(mkTool("a", "Add.")),
		outcome(mkTool("a", "Add. Changed.")),
	}, &scanIgnores{})

	if len(pr.rows) != 1 || pr.rows[0].RuleID != "MOAT-T2-004" || pr.rows[0].Severity != "medium" || pr.rows[0].Name != "srv" {
		t.Fatalf("rows = %+v, want one MOAT-T2-004 medium row for srv", pr.rows)
	}
	if len(pr.diffs) != 0 {
		t.Errorf("diffs = %+v, want none", pr.diffs)
	}
	var out bytes.Buffer
	if err := report.WriteFindings(&out, pr.rows, report.Style{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "the server is listed twice") {
		t.Errorf("findings table does not hold the reason:\n%s", out.String())
	}
	// pinOutcomes prints nothing: the notice comes after a successful save.
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	if len(pr.pinned) != 1 || pr.pinned[0].name != "srv" || pr.pinned[0].tools != 1 {
		t.Errorf("pinned = %+v, want one entry: srv with 1 tool", pr.pinned)
	}
}

// TestScanPinsNoSecretLeak checks that no env, header, URL or args value of the
// config reaches pins.json, stdout or stderr, in the first scan, in a scan with
// findings and in "pin --accept".
func TestScanPinsNoSecretLeak(t *testing.T) {
	t.Parallel()

	servers := map[string]any{
		"stdio-srv": map[string]any{
			"command": "npx",
			"args":    []string{"--token", discovertest.CanaryArgs},
			"env":     map[string]string{"API_TOKEN": discovertest.CanaryEnv},
		},
		"http-srv": map[string]any{
			"type":    "http",
			"url":     "https://example.invalid/mcp?key=" + discovertest.CanaryURL,
			"headers": map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader},
		},
	}
	e := newPinEnv(t, servers)
	var outputs []string
	collect := func(r pinRunResult) {
		outputs = append(outputs, r.stdout, r.stderr)
	}

	collect(e.scan(fakeServers(map[string][]inspect.Tool{
		"stdio-srv": {mkTool("a", "Add."), mkTool("b", "Echo.")},
		"http-srv":  {mkTool("h", "Http.")},
	})))
	got := e.scan(fakeServers(map[string][]inspect.Tool{
		"stdio-srv": {mkTool("a", "Add. Changed."), mkTool("c", "New.")},
		"http-srv":  {mkTool("h", "Http.")},
	}))
	collect(got)
	if got.code != exitFindings {
		t.Fatalf("second scan: exit code = %d, want %d\n%s", got.code, exitFindings, got.stderr)
	}
	accepted := e.pin(fakeServers(map[string][]inspect.Tool{"stdio-srv": {mkTool("a", "Add. Changed.")}}), "--accept", "stdio-srv")
	collect(accepted)
	if accepted.code != exitOK {
		t.Fatalf("pin --accept: exit code = %d, want %d\n%s", accepted.code, exitOK, accepted.stderr)
	}
	collect(e.scan(fakeServers(map[string][]inspect.Tool{
		"stdio-srv": {mkTool("a", "Add. Changed.")},
		"http-srv":  {mkTool("h", "Http.")},
	})))
	outputs = append(outputs, string(readFileBytes(t, e.pinsPath())))

	for i, out := range outputs {
		discovertest.AssertNoLeak(t, "output "+string(rune('0'+i)), out)
	}
	// The key names of env and headers are not stored either: the identity
	// holds the client, the source, the project path and the name only.
	pinsText := outputs[len(outputs)-1]
	assertContainsNone(t, "pins.json", pinsText, []string{"API_TOKEN", "Authorization", "example.invalid", "--token"})
}

// metaCanary is a secret-like value that sits in the bad _meta or icons of
// TestScanPinsMetaNeverInOutput. It must not reach stdout, stderr or pins.json
// when the value cannot be hashed.
const metaCanary = "SECRET-CANARY-153"

// TestScanPinsMetaNeverInOutput checks that a _meta that cannot be hashed gives
// a fixed reason ("invalid tool data") and that no _meta value, here the
// canary, reaches stdout, stderr or pins.json. It tests a bad _meta on the
// first run and on a run of a pinned server, and a bad icons array. On the
// first run nothing is stored, and a pinned server keeps its pins.json bytes.
func TestScanPinsMetaNeverInOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		meta string
		// icons is the icons array of the bad tool. Empty means none.
		icons string
	}{
		{"duplicate key in _meta", `{"k":"` + metaCanary + `","dup":1,"dup":2}`, ""},
		{"number out of range in _meta", `{"k":"` + metaCanary + `","n":1e400}`, ""},
		{"duplicate key in icons", "", `[{"src":"` + metaCanary + `","src":"x"}]`},
	}
	for _, tt := range tests {
		for _, pinnedFirst := range []bool{false, true} {
			name := tt.name + "/first run"
			if pinnedFirst {
				name = tt.name + "/pinned server"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				e := newPinEnv(t, oneServer("srv"))
				bad := metaTool("a", tt.meta, tt.icons)
				var pinsBefore []byte
				if pinnedFirst {
					firstScan(t, e, metaTool("a", `{"k":"v"}`, ""))
					pinsBefore = readFileBytes(t, e.pinsPath())
				}

				got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {bad}}))

				// A tool that cannot be hashed is not verified: high, exit 1. The
				// reason is a fixed text, never a value of the tool.
				assertScanRun(t, got, scanWant{code: exitFindings})
				// A pinned server shows the tool name too. A server that cannot be
				// pinned shows the reason alone.
				want := pinFinding{"MOAT-T2-004", "high", "srv", "", `"invalid tool data"`}
				if pinnedFirst {
					want = pinFinding{"MOAT-T2-004", "high", "srv", `a ("invalid tool data")`, ""}
				}
				assertPinRows(t, got.stdout, want)
				assertContainsNone(t, "stdout", got.stdout, []string{metaCanary})
				assertContainsNone(t, "stderr", got.stderr, []string{metaCanary})
				if pinnedFirst {
					if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(pinsBefore, after) {
						t.Errorf("pins.json changed after a tool that cannot be hashed\nbefore: %s\nafter:  %s", pinsBefore, after)
					}
				} else {
					// Nothing is stored for a server that cannot be pinned.
					e.assertNoPinsFile(t, "a snapshot failure")
				}
			})
		}
	}
}

// bigMeta returns a valid JSON _meta object of more than 2 MiB (the size cap of
// one server entry in pins.json) that holds the canary.
func bigMeta() string {
	return `{"k":"` + metaCanary + strings.Repeat("x", 2<<20+1024) + `"}`
}

// TestScanPinsHugeMetaFailsClosed checks that a tool whose _meta pushes the pin
// entry of its server over the size cap of pins.json (2 MiB) never passes
// silently. On the first run the server is not pinned: the scan reports
// MOAT-T2-004 (high) and exits 1, and pins.json holds nothing of the server.
// On a run of a pinned server the huge _meta is a change: MOAT-T2-001 (high),
// exit 1, and the diff is cut at its size limit with a warning, so the output
// stays small. The tools of the pinned server can no longer be pinned, so it
// also gets the MOAT-T2-004 (high) of the first run, also when the only change
// is a new tool (MOAT-T2-002, medium): no change of its tools could ever be
// accepted. The first run never prints the _meta. The diff of the second run
// shows a cut part of the new _meta, as it does for any changed _meta, so the
// test does not check the canary there.
func TestScanPinsHugeMetaFailsClosed(t *testing.T) {
	t.Parallel()

	t.Run("first run", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {metaTool("a", bigMeta(), "")}}))

		assertScanRun(t, got, scanWant{code: exitFindings})
		assertPinRows(t, got.stdout, pinFinding{"MOAT-T2-004", "high", "srv", "", `"the tools cannot be pinned"`})
		assertContainsNone(t, "stdout", got.stdout, []string{metaCanary})
		assertContainsNone(t, "stderr", got.stderr, []string{metaCanary})
		// Nothing is stored for a server that cannot be pinned.
		e.assertNoPinsFile(t, "a snapshot failure")
	})

	t.Run("pinned server", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, metaTool("a", `{"k":"small"}`, ""))
		pinsBefore := readFileBytes(t, e.pinsPath())

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {metaTool("a", bigMeta(), "")}}))

		assertScanRun(t, got, scanWant{
			code:   exitFindings,
			stdout: []string{"[truncated: text over the limit]"},
			stderr: []string{"was cut at the size limit"},
		})
		assertPinRows(t, got.stdout,
			pinFinding{"MOAT-T2-004", "high", "srv", "", `"the tools cannot be pinned"`},
			pinFinding{"MOAT-T2-001", "high", "srv", "a", ""})
		// The diff is cut: the output is far smaller than the 2 MiB _meta.
		if len(got.stdout) > 256<<10 {
			t.Errorf("stdout has %d bytes, want the diff cut well below the 2 MiB _meta", len(got.stdout))
		}
		assertContainsNone(t, "stderr", got.stderr, []string{metaCanary})
		// scan never rewrites the entry of a pinned server.
		if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(pinsBefore, after) {
			t.Errorf("scan changed pins.json of a pinned server")
		}
	})

	t.Run("pinned server with a huge new tool", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		small := mkTool("a", "Add.")
		firstScan(t, e, small)
		pinsBefore := readFileBytes(t, e.pinsPath())

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {small, metaTool("n", bigMeta(), "")}}))

		// The new tool alone is medium. The high MOAT-T2-004 makes scan exit 1.
		assertScanRun(t, got, scanWant{code: exitFindings})
		assertPinRows(t, got.stdout,
			pinFinding{"MOAT-T2-004", "high", "srv", "", `"the tools cannot be pinned"`},
			pinFinding{"MOAT-T2-002", "medium", "srv", "n", ""})
		if hints := splitPinOutput(t, got.stdout).hints; len(hints) != 0 {
			t.Errorf("hints = %q, want none: pin --accept would refuse these tools", hints)
		}
		// The tools were compared, so the row names the real risk: they can
		// never be accepted.
		for _, f := range parseFindings(t, got.stdout) {
			if f.RuleID == "MOAT-T2-004" && f.Risk != riskPinnedNotPinnable {
				t.Errorf("MOAT-T2-004 Risk = %q, want %q", f.Risk, riskPinnedNotPinnable)
			}
		}
		if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(pinsBefore, after) {
			t.Errorf("scan changed pins.json of a pinned server")
		}
	})
}

// TestScanPinsIgnoreFileWarningPerRule checks that the warning about a
// .mcpmoat-ignore entry that cannot ignore a pin rule comes once for each rule
// ID, in the order of the findings, and not once for each finding.
func TestScanPinsIgnoreFileWarningPerRule(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	writeTestFile(t, e.work, rules.IgnoreFileName, "MOAT-T2-001\nMOAT-T2-002\nMOAT-T2-003\n")
	pinned := []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo."), mkTool("c", "Keep.")}
	firstScan(t, e, pinned...)

	got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {
		mkTool("a", "Add. X."), mkTool("b", "Echo. Y."), mkTool("d", "New."), mkTool("e", "New too."),
	}}), "--use-ignore-file")

	assertScanRun(t, got, scanWant{code: exitFindings, stderr: []string{
		"mcpmoat scan: warning: .mcpmoat-ignore cannot ignore MOAT-T2-001; use --ignore on the command line\n",
		"mcpmoat scan: warning: .mcpmoat-ignore cannot ignore MOAT-T2-002; use --ignore on the command line\n",
		"mcpmoat scan: warning: .mcpmoat-ignore cannot ignore MOAT-T2-003; use --ignore on the command line\n",
	}})
	if n := strings.Count(got.stderr, "cannot ignore"); n != 3 {
		t.Errorf("stderr has %d ignore file warnings, want 3 (one for each rule ID)\n%s", n, got.stderr)
	}
	if rows := splitPinOutput(t, got.stdout).rows; len(rows) != 5 {
		t.Errorf("pin rows = %+v, want 5 (2 changed, 2 new, 1 removed)\n%s", rows, got.stdout)
	}
}

// TestScanPinsUnverifiedSeverity checks that a MOAT-T2-004 row is high for a
// pinned tool name and medium for a name that is not pinned, in one scan (S2).
func TestScanPinsUnverifiedSeverity(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	firstScan(t, e, mkTool("a", "Add."))

	got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {
		mkTool("a", "Add."), mkTool("a", "Add. Copy."), // pinned name
		mkTool("n", "One."), mkTool("n", "Two."), // name that is not pinned
	}}))

	assertScanRun(t, got, scanWant{code: exitFindings})
	assertPinRows(t, got.stdout,
		pinFinding{"MOAT-T2-004", "high", "srv", `a ("duplicate tool name")`, ""},
		pinFinding{"MOAT-T2-004", "medium", "srv", `n ("duplicate tool name")`, ""},
	)
}

// TestScanPinsInterrupted checks that a signal during the inspection (S1) gives
// exit code 2, one fixed line on stderr, no report on stdout, and no change to
// pins.json: not a new pin, and not a changed pin.
func TestScanPinsInterrupted(t *testing.T) {
	t.Parallel()

	const notice = "mcpmoat scan: interrupted; no pins were saved\n"
	tools := map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}}

	tests := []struct {
		name string
		// pinFirst makes scan pin the server before the interrupted run.
		pinFirst bool
		current  map[string][]inspect.Tool
	}{
		{name: "during the inspection of a new server", current: tools},
		{name: "during the inspection of a pinned server that changed", pinFirst: true, current: map[string][]inspect.Tool{"srv": {mkTool("a", "Add. Changed.")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			if tt.pinFirst {
				if got := e.scan(fakeServers(tools)); got.code != exitOK {
					t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
				}
			}
			var pinsBefore []byte
			if tt.pinFirst {
				pinsBefore = readFileBytes(t, e.pinsPath())
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fake := fakeServers(tt.current)
			c, stdout, stderr := e.cli(cancelingInspector{inner: fake, cancel: cancel})
			c.ctx = ctx

			code := c.dispatch([]string{"scan", "--config", e.config})

			got := pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
			assertScanRun(t, got, scanWant{code: exitError, stderr: []string{notice}})
			if got.stderr != notice {
				t.Errorf("stderr = %q, want only %q", got.stderr, notice)
			}
			// No report: the result would be partial.
			assertEmptyStdout(t, got.stdout)
			if tt.pinFirst {
				if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(pinsBefore, after) {
					t.Errorf("pins.json changed in an interrupted scan\nbefore: %s\nafter:  %s", pinsBefore, after)
				}
			} else {
				e.assertNoPinsFile(t, "an interrupted scan")
			}
		})
	}
}

// TestScanPinsCorruptStoreStartsNoServer checks that a pins.json that cannot be
// read stops scan before the inspector is called, for a corrupt file, a newer
// version and a pins path that is a folder (M2). The summary says why the
// server was not inspected.
func TestScanPinsCorruptStoreStartsNoServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, e *pinEnv)
	}{
		{"corrupt file", func(t *testing.T, e *pinEnv) {
			writeTestFile(t, filepath.Dir(e.pinsPath()), "pins.json", "{this is not json")
		}},
		{"newer version", func(t *testing.T, e *pinEnv) {
			writeTestFile(t, filepath.Dir(e.pinsPath()), "pins.json", `{"version": 999, "servers": []}`)
		}},
		{"empty file", func(t *testing.T, e *pinEnv) {
			writeTestFile(t, filepath.Dir(e.pinsPath()), "pins.json", "")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			tt.setup(t, e)
			before := readFileBytes(t, e.pinsPath())
			fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})

			got := e.scan(fake)

			assertScanRun(t, got, scanWant{code: exitError, stderr: []string{"mcpmoat scan: cannot read the pins file: "}})
			row := summaryRowOf(t, got.stdout, "srv")
			if row.Status != "not inspected" || row.Reason != reasonPinStepFailed {
				t.Errorf("SUMMARY row of srv = status %q, reason %q; want not inspected with %q", row.Status, row.Reason, reasonPinStepFailed)
			}
			if calls := fake.Calls(); len(calls) != 0 {
				t.Errorf("the inspector was called for %v, want no call", calls)
			}
			if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(before, after) {
				t.Errorf("pins.json changed: %q, want %q", after, before)
			}
		})
	}
}

// TestScanPinsCanceledBeforeInspection checks that a context that ended before
// the inspection starts (a signal during discovery) still gives exit code 2,
// starts no server and writes no pins.json. The message is the discovery error,
// not the interrupted notice: discovery reports the canceled read of the config.
func TestScanPinsCanceledBeforeInspection(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c, stdout, stderr := e.cli(fake)
	c.ctx = ctx

	code := c.dispatch([]string{"scan", "--config", e.config})

	if code != exitError {
		t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitError, stdout, stderr)
	}
	if calls := fake.Calls(); len(calls) != 0 {
		t.Errorf("the inspector was called for %v, want no call", calls)
	}
	e.assertNoPinsFile(t, "a canceled scan")
	if strings.Contains(stdout.String(), "MOAT-T2-") {
		t.Errorf("stdout has a pin finding:\n%s", stdout)
	}
}

// TestServerStatusesByIndex checks the matching of outcomes to servers. An
// outcome goes to the server at its index, whatever the order of the outcomes
// is, also when servers are equal in every field. A server with no outcome stays
// "not inspected".
func TestServerStatusesByIndex(t *testing.T) {
	t.Parallel()

	srv := discover.Server{
		Name: "dup", Client: discover.ClientClaudeCode, Scope: discover.ScopeGlobal,
		Source: "/home/u/.claude.json", Command: "run",
	}
	outcome := func(index, tools int) outcomeStatus {
		return outcomeStatus{
			index:  index,
			status: report.ServerStatus{ServerRef: report.NewServerRef(srv), Status: report.StatusOK, Tools: tools},
		}
	}
	tests := []struct {
		name     string
		servers  int
		statuses []outcomeStatus
		want     []string // "status/tools/findings" of each server
	}{
		{
			name:     "outcomes in the opposite order",
			servers:  2,
			statuses: []outcomeStatus{outcome(1, 2), outcome(0, 1)},
			want:     []string{"ok/1/1", "ok/2/1"},
		},
		{
			name:     "server with no outcome",
			servers:  2,
			statuses: []outcomeStatus{outcome(1, 2)},
			want:     []string{"not inspected/0/1", "ok/2/1"},
		},
		{
			name:     "equal servers get one outcome each",
			servers:  2,
			statuses: []outcomeStatus{outcome(0, 1), outcome(1, 5)},
			want:     []string{"ok/1/1", "ok/5/1"},
		},
		{
			name:     "index outside the servers is skipped",
			servers:  1,
			statuses: []outcomeStatus{outcome(3, 3), outcome(-1, 4)},
			want:     []string{"not inspected/0/1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			servers := make([]discover.Server, tt.servers)
			configFindings := make([]int, tt.servers)
			for i := range servers {
				servers[i] = srv
				// Each server has one config finding, and serverStatuses adds
				// it to the findings of the outcome (none here).
				configFindings[i] = 1
			}
			pr := pinReport{statuses: tt.statuses}
			got := pr.serverStatuses(servers, configFindings)
			if len(got) != len(tt.want) {
				t.Fatalf("serverStatuses() returned %d entries, want %d", len(got), len(tt.want))
			}
			for i, st := range got {
				line := fmt.Sprintf("%s/%d/%d", st.Status, st.Tools, st.Findings)
				if line != tt.want[i] {
					t.Errorf("server %d = %q, want %q", i, line, tt.want[i])
				}
			}
		})
	}
}
