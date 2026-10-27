package main

// In-process tests of the pins budget of scan: the "To accept" hint of a
// pinned server whose new tools do not fit in pins.json (#220, see
// markStoreFull), and the share of the project servers (#219,
// pins.ProjectShareMiB) at report time (firstPin) and at save time
// (savePinned). They use the near-full helpers of pins_helpers_test.go
// (writeNearFullPins, fillNearFullProjectShare, writeNearFullProjectShare). They
// never call t.Setenv. The tests that write a large pins file do not run in
// parallel, for the reason of TestScanPinsStoreFullAtReport.

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// shareTestServer returns a stdio server for the pinOutcomes and savePinned
// tests of the project share. An empty project gives a server of the user
// scope (ProjectPath ""), and a project path gives a project server, which
// counts toward the share. The source is absolute, so checkOutcome compares or
// pins the server.
func shareTestServer(name, project string) discover.Server {
	s := discover.Server{
		Name:      name,
		Client:    discover.ClientClaudeCode,
		Scope:     discover.ScopeGlobal,
		Source:    "/share/user/mcp.json",
		Transport: discover.TransportStdio,
		Command:   "npx",
	}
	if project != "" {
		s.Scope = discover.ScopeProject
		s.ProjectPath = project
		s.Source = project + "/.mcp.json"
	}
	return s
}

// shareTestOutcome returns the outcome of a server that inspect read, with
// its tools, at index i of the servers of the scan.
func shareTestOutcome(i int, s discover.Server, tools ...inspect.Tool) inspect.Outcome {
	return inspect.Outcome{
		Index:  i,
		Server: s,
		Status: inspect.StatusOK,
		Result: inspect.Result{ServerName: s.Name, Tools: tools},
	}
}

// snapshotOf returns the pins of tools. It fails the test when the tools
// cannot be pinned.
func snapshotOf(t *testing.T, tools ...inspect.Tool) pins.ServerPins {
	t.Helper()
	snap, err := pins.Snapshot(tools)
	if err != nil {
		t.Fatalf("pins.Snapshot() error = %v, want nil", err)
	}
	return snap
}

// metaSizeTool returns a tool whose _meta holds n bytes of text, so that its
// pins entry is a little larger than n bytes. Like bigStoreTool, the size is
// in _meta, so no description rule adds a row.
func metaSizeTool(name string, n int) inspect.Tool {
	return metaTool(name, `{"k":"`+strings.Repeat("a", n)+`"}`, "")
}

// TestScanBudgetHintStoreFull checks the "To accept" hint of a pinned server
// whose tools grew so much that pins.json, near its 32 MiB limit, has no room
// for them (#220). The first scan pins "grow" and "same" with one small tool
// each, and then fillPinsFileNearFull adds the fillers of writeNearFullPins.
// In the second scan "grow" has 24 new tools (about 24 KiB of pins, more than
// nearFullGap), and "same" changed one word, so it does not grow.
//
//   - The hint of "grow" keeps the digest of the tools that scan saw, but
//     shows the prose steps, not a "mcpmoat pin --accept" command that pin
//     would refuse, and ends with hintStoreFullNote.
//   - The hint of "same" is the full command, as without a full file.
//   - With --json, the accept object of "grow" has the digest and no command
//     key, and the one of "same" has the command of the terminal hint.
//   - The real "pin --accept grow --expect <digest>" then fails as the hint
//     said: exit code 2, the "pins file is full" line, pins.json unchanged.
//
// The growth uses many mid-size tools and not bigStoreTool: the diff of
// bigStoreTool is cut, and the cut note alone would turn the hint into prose
// steps, so the test would not show the effect of the full file. That a hint
// that does not grow keeps a command that works is cheap to check without a
// large file: TestScanBudgetProjectShare and TestPinAcceptAfterScanReview.
func TestScanBudgetHintStoreFull(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a near-32 MiB pins file; slow under -race")
	}
	e := newPinEnv(t, map[string]any{
		"grow": map[string]any{"command": "npx"},
		"same": map[string]any{"command": "npx"},
	})

	first := e.scan(fakeServers(map[string][]inspect.Tool{
		"grow": {mkTool("a", "Add.")},
		"same": {mkTool("b", "One.")},
	}))
	assertScanRun(t, first, scanWant{code: exitOK, stderr: []string{pinnedLine("grow", 1), pinnedLine("same", 1)}})
	fillPinsFileNearFull(t, e.pinsPath())

	grown := []inspect.Tool{mkTool("a", "Add.")}
	for i := range 24 {
		grown = append(grown, mkTool(fmt.Sprintf("t%02d", i), strings.Repeat("Adds numbers. ", 70)))
	}
	changed := []inspect.Tool{mkTool("b", "Two.")}
	second := fakeServers(map[string][]inspect.Tool{"grow": grown, "same": changed})
	growDigest, sameDigest := digestOf(t, grown...), digestOf(t, changed...)
	sameCommand := "mcpmoat pin --accept same --config " + e.config + " --expect " + sameDigest

	text := e.scan(second)

	assertScanRun(t, text, scanWant{code: exitFindings})
	_, hints := cutAcceptHints(text.stdout)
	wantHints := []string{
		acceptHintPrefix + "grow: run pin --accept with this server name, --config with the file of this scan, and --expect " +
			growDigest + hintStoreFullNote,
		acceptHintPrefix + "same: " + sameCommand,
	}
	if !slices.Equal(hints, wantHints) {
		t.Errorf("accept hints =\n%q\nwant\n%q", hints, wantHints)
	}
	if strings.Contains(hints[0], "mcpmoat pin --accept") {
		t.Errorf("the hint of grow %q holds a command that pin would refuse", hints[0])
	}

	jsonRun := e.scan(second, "--json")

	assertScanRun(t, jsonRun, scanWant{code: exitFindings})
	assertAcceptMatchesTerminal(t, jsonRun.stdout, text.stdout)
	accepts := map[string]map[string]any{}
	for _, s := range rawServers(t, jsonRun.stdout) {
		if a, ok := s["accept"].(map[string]any); ok {
			accepts[s["name"].(string)] = a
		}
	}
	if a := accepts["grow"]; a["digest"] != growDigest {
		t.Errorf("grow: accept = %v, want the digest %q", a, growDigest)
	}
	if command, has := accepts["grow"]["command"]; has {
		t.Errorf("grow: accept.command = %v, want no command key (pins.json has no room)", command)
	}
	if a := accepts["same"]; a["digest"] != sameDigest || a["command"] != sameCommand {
		t.Errorf("same: accept = %v, want digest %q and command %q", a, sameDigest, sameCommand)
	}

	// The hint was right: pin refuses the tools of grow.
	before := fileDigest(t, e.pinsPath())
	refused := e.pin(second, "--accept", "grow", "--expect", growDigest)

	const full = "mcpmoat pin: cannot pin grow: the pins file is full (32 MiB); remove servers you no longer use from pins.json\n"
	assertPinRun(t, refused, scanWant{code: exitError, stderr: []string{full}})
	if !strings.HasSuffix(refused.stderr, full) {
		t.Errorf("stderr = %q, want it to end with %q", refused.stderr, full)
	}
	assertContainsNone(t, "stdout", refused.stdout, []string{"accepted"})
	if after := fileDigest(t, e.pinsPath()); after != before {
		t.Errorf("pins.json changed after a refused accept, want it byte for byte the same")
	}
}

// TestScanBudgetProjectShare checks the share of the project servers in the
// pin step of scan (pinOutcomes), on a store whose project servers fill their
// share up to nearFullGap bytes (fillNearFullProjectShare). The files of
// pins.json are not written: pinOutcomes only reads the store. The store is
// filled once and each subtest uses a Clone, so the test stays cheap.
//
// "first run over the share" is #219 at report time: a project server on its
// first run that does not fit in the share gets one high MOAT-T2-004 row with
// reasonShareFull and fixShareFull and is not pinned, while a server of the
// user scope with the same tools is still pinned. The hint of a pinned project
// server that grew past the share has storeFull.
//
// The table checks the budget of the hints (#220, markStoreFull): each hint
// gets its own clone of the budget, after all first-run servers were added.
func TestScanBudgetProjectShare(t *testing.T) {
	t.Parallel()

	base := newPinsStore(t, filepath.Join(t.TempDir(), "mcpmoat", "pins.json"))
	fillNearFullProjectShare(t, base)
	small := []inspect.Tool{mkTool("a", "Add.")}

	t.Run("first run over the share", func(t *testing.T) {
		t.Parallel()
		store := base.Clone()
		pinnedProj := shareTestServer("pinned-proj", "/proj")
		if err := store.Set(serverIdentity(pinnedProj), snapshotOf(t, small...)); err != nil {
			t.Fatal(err)
		}
		grown := []inspect.Tool{mkTool("a", "Add."), bigStoreTool()}
		projNew, userNew := shareTestServer("proj-new", "/proj"), shareTestServer("user-new", "")
		c, _, _ := newTestCLI(fakeGetenv(nil), testBuild)

		pr := c.pinOutcomes(store, []inspect.Outcome{
			shareTestOutcome(0, pinnedProj, grown...),
			shareTestOutcome(1, projNew, bigStoreTool()),
			shareTestOutcome(2, userNew, bigStoreTool()),
		}, &scanIgnores{})

		var unverified []report.FindingRow
		for _, row := range pr.rows {
			if row.RuleID == "MOAT-T2-004" {
				unverified = append(unverified, row)
			}
		}
		if len(unverified) != 1 {
			t.Fatalf("MOAT-T2-004 rows = %+v, want exactly one, for proj-new", unverified)
		}
		row := unverified[0]
		if row.Name != "proj-new" || row.Severity != "high" || row.Related != reasonShareFull ||
			row.Remediation != fixShareFull || row.Risk != riskServerUnverified {
			t.Errorf("MOAT-T2-004 row = {name %q, severity %q, related %q, fix %q, risk %q}, want {proj-new, high, %q, %q, %q}",
				row.Name, row.Severity, row.Related, row.Remediation, row.Risk, reasonShareFull, fixShareFull, riskServerUnverified)
		}
		var pinned []string
		for _, p := range pr.pinned {
			pinned = append(pinned, p.name)
		}
		if !slices.Equal(pinned, []string{"user-new"}) {
			t.Errorf("pinned = %v, want [user-new]: the share does not apply to the user scope", pinned)
		}
		if len(pr.hints) != 1 || pr.hints[0].name != "pinned-proj" || !pr.hints[0].storeFull ||
			pr.hints[0].digest != digestOf(t, grown...) {
			t.Errorf("hints = %+v, want one hint for pinned-proj with storeFull and the digest of its tools", pr.hints)
		}
		for _, s := range []discover.Server{projNew, userNew} {
			if _, found := store.Get(serverIdentity(s)); found {
				t.Errorf("pinOutcomes changed the store: it has %s, want only the pins of the earlier runs", s.Name)
			}
		}
	})

	// step is one server of a run in the table: pinned is true when the store
	// holds the pins of small for it before the run.
	type step struct {
		server discover.Server
		pinned bool
		tools  []inspect.Tool
	}
	// The room of the share is nearFullGap (16 KiB) less the small entries
	// of the pinned project servers. A growth of metaSizeTool(9 KiB) fits in
	// it alone, but two do not. A first-run server of metaSizeTool(10 KiB)
	// fits, and leaves less room than one such growth.
	grow9 := append(slices.Clone(small), metaSizeTool("m", 9<<10))
	tests := []struct {
		name  string
		steps []step
		// wantFull is storeFull of each hint, by server name.
		wantFull map[string]bool
		// wantPinned are the first-run servers that scan pins.
		wantPinned []string
	}{
		{
			name: "each hint is checked alone",
			steps: []step{
				{server: shareTestServer("p1", "/proj"), pinned: true, tools: grow9},
				{server: shareTestServer("p2", "/proj"), pinned: true, tools: grow9},
				{server: shareTestServer("late", "/proj"), tools: small},
			},
			wantFull:   map[string]bool{"p1": false, "p2": false},
			wantPinned: []string{"late"},
		},
		{
			name: "a later first-run server takes the room of a hint",
			steps: []step{
				{server: shareTestServer("p1", "/proj"), pinned: true, tools: grow9},
				{server: shareTestServer("late", "/proj"), tools: []inspect.Tool{metaSizeTool("m", 10<<10)}},
			},
			wantFull:   map[string]bool{"p1": true},
			wantPinned: []string{"late"},
		},
		{
			name: "a hint of the user scope does not count toward the share",
			steps: []step{
				{server: shareTestServer("u", ""), pinned: true, tools: []inspect.Tool{mkTool("a", "Add."), bigStoreTool()}},
			},
			wantFull: map[string]bool{"u": false},
		},
		{
			name: "a change that does not grow fits",
			steps: []step{
				{server: shareTestServer("p1", "/proj"), pinned: true, tools: []inspect.Tool{mkTool("a", "Sub.")}},
			},
			wantFull: map[string]bool{"p1": false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := base.Clone()
			var outcomes []inspect.Outcome
			for i, s := range tt.steps {
				if s.pinned {
					if err := store.Set(serverIdentity(s.server), snapshotOf(t, small...)); err != nil {
						t.Fatal(err)
					}
				}
				outcomes = append(outcomes, shareTestOutcome(i, s.server, s.tools...))
			}
			c, _, _ := newTestCLI(fakeGetenv(nil), testBuild)

			pr := c.pinOutcomes(store, outcomes, &scanIgnores{})

			gotFull := map[string]bool{}
			for _, h := range pr.hints {
				gotFull[h.name] = h.storeFull
			}
			if !maps.Equal(gotFull, tt.wantFull) {
				t.Errorf("storeFull of the hints = %v, want %v", gotFull, tt.wantFull)
			}
			var pinned []string
			for _, p := range pr.pinned {
				pinned = append(pinned, p.name)
			}
			if !slices.Equal(pinned, tt.wantPinned) {
				t.Errorf("pinned = %v, want %v", pinned, tt.wantPinned)
			}
			for _, row := range pr.rows {
				if row.RuleID == "MOAT-T2-004" {
					t.Errorf("unexpected MOAT-T2-004 row for %s: %q", row.Name, row.Related)
				}
			}
		})
	}
}

// TestScanBudgetProjectShareAtSave checks #219 at save time (savePinned and
// setNewPins): pins.json holds project servers up to nearFullGap bytes below
// their share (writeNearFullProjectShare), so the project server "proj-new"
// does not fit, but "user-new", a server of the user scope with the same
// tools, does. savePinned warns about proj-new with the share text
// (storeFullText), still saves user-new and prints its "pinned" line, and
// returns false, so scan exits with 2 as for the file limit (see
// TestScanPinsStoreFullAtSave). pins.json existed, so there is no new pins
// file notice.
func TestScanBudgetProjectShareAtSave(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 16 MiB pins file; slow under -race")
	}
	e := newPinEnv(t, oneServer("unused"))
	writeNearFullProjectShare(t, e.pinsPath())
	projNew, userNew := shareTestServer("proj-new", "/proj"), shareTestServer("user-new", "")
	pr := pinReport{storeExisted: true, pinned: []pinnedServer{
		{id: serverIdentity(projNew), snap: snapshotOf(t, bigStoreTool()), name: projNew.Name, tools: 1},
		{id: serverIdentity(userNew), snap: snapshotOf(t, bigStoreTool()), name: userNew.Name, tools: 1},
	}}
	c, stdout, stderr := e.cli(nil)

	if c.savePinned(t.Context(), pr) {
		t.Error("savePinned() = true, want false (a refused server gives exit code 2)")
	}

	want := scanWarnPrefix + "server proj-new not pinned: the project servers use all of their share of the pins file (16 MiB)\n" +
		pinnedLine("user-new", 1) + "\n"
	if got := stderr.String(); got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	assertPinsFileMode(t, e.pinsPath())
	wantNames := append(projectFillerNames(), "user-new")
	slices.Sort(wantNames)
	if names := bigPinsServerNames(t, e.pinsPath()); !slices.Equal(names, wantNames) {
		t.Errorf("pinned servers = %v, want %v (proj-new is not pinned)", names, wantNames)
	}
}
