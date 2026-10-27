package main

// In-process tests of the save step of "mcpmoat scan" (savePinned): the notice
// for a new pins file, the lock on the pins directory and its release before
// the output, a pins file that was removed while scan ran, and the size limit
// of pins.json (32 MiB) at report time and at save time. They use a fake
// inspector, so no server starts, and they never call t.Setenv: each test has
// its own home and XDG_CONFIG_HOME in t.TempDir(). The shared pin helpers are
// in pins_helpers_test.go, also the near-full pins file (writeNearFullPins and
// bigStoreTool) and the lock probe (lockProbeWriter).

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// TestScanPinsNewFileNotice checks the stderr notice of a scan that creates a
// new pins.json. It shows exactly once, after the save and before the
// "pinned" lines, also with --json (stdout stays a clean JSON document). A
// scan that finds pins.json on disk never prints it: not on a second run of
// the same servers, and not when it pins a new server into an existing file.
// A deleted pins.json makes every server look new, so the notice shows again.
func TestScanPinsNewFileNotice(t *testing.T) {
	t.Parallel()

	tools := map[string][]inspect.Tool{
		"alpha": {mkTool("a", "A.")},
		"beta":  {mkTool("b1", "B1."), mkTool("b2", "B2.")},
	}
	servers := map[string]any{
		"alpha": map[string]any{"command": "npx"},
		"beta":  map[string]any{"command": "npx"},
	}
	pinnedBoth := pinnedLine("alpha", 1) + "\n" + pinnedLine("beta", 2) + "\n"

	for _, args := range [][]string{nil, {"--json"}} {
		t.Run("first run "+strings.Join(append([]string{"scan"}, args...), " "), func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, servers)

			got := e.scan(fakeServers(tools), args...)

			assertScanRun(t, got, scanWant{code: exitOK, stderr: []string{pinnedBoth}})
			if want := newPinsFileNotice("scan", e.pinsPath()) + pinnedBoth; got.stderr != want {
				t.Errorf("stderr = %q, want %q", got.stderr, want)
			}
			if names := e.readPins().serverNames(); !slices.Equal(names, []string{"alpha", "beta"}) {
				t.Errorf("pinned servers = %v, want [alpha beta]", names)
			}
		})
	}

	t.Run("second run prints no notice", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, servers)
		first := e.scan(fakeServers(tools))
		withoutPinsFileNotice(t, first.stderr, "scan", e.pinsPath())

		got := e.scan(fakeServers(tools))

		assertScanRun(t, got, scanWant{code: exitOK})
		if got.stderr != "" {
			t.Errorf("stderr of the second run = %q, want empty", got.stderr)
		}
	})

	t.Run("new server in an existing pins file prints no notice", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, servers)
		// The first run pins alpha only: beta fails, so it is not pinned.
		first := pinAlphaOnly(t, e, tools["alpha"])
		if rest := withoutPinsFileNotice(t, first.stderr, "scan", e.pinsPath()); rest != pinnedLine("alpha", 1)+"\n" {
			t.Fatalf("first run stderr without the notice = %q, want only the pinned line of alpha", rest)
		}

		got := e.scan(fakeServers(tools))

		assertScanRun(t, got, scanWant{code: exitOK, stderr: []string{pinnedLine("beta", 2)}})
		if want := pinnedLine("beta", 2) + "\n"; got.stderr != want {
			t.Errorf("stderr = %q, want %q (no new pins file notice)", got.stderr, want)
		}
		if names := e.readPins().serverNames(); !slices.Equal(names, []string{"alpha", "beta"}) {
			t.Errorf("pinned servers = %v, want [alpha beta]", names)
		}
	})

	t.Run("deleted pins file prints the notice again", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, servers)
		first := e.scan(fakeServers(tools))
		withoutPinsFileNotice(t, first.stderr, "scan", e.pinsPath())
		if err := os.Remove(e.pinsPath()); err != nil {
			t.Fatal(err)
		}

		got := e.scan(fakeServers(tools))

		assertScanRun(t, got, scanWant{code: exitOK, stderr: []string{pinnedBoth}})
		if want := newPinsFileNotice("scan", e.pinsPath()) + pinnedBoth; got.stderr != want {
			t.Errorf("stderr = %q, want %q", got.stderr, want)
		}
	})
}

// TestScanPinsLockHeld checks a scan while another run holds the lock on the
// pins directory (holdPinsLock). A test cli has pinsLockWait 0, so the scan
// tries once. The report is already out when savePinned asks for the lock, so
// stdout has the report, and stderr has exactly the read error and the
// pinsLockedText line. The scan exits with 2, saves nothing and prints no
// "pinned" line and no new pins file notice. When the other run releases the
// lock, the same scan works.
func TestScanPinsLockHeld(t *testing.T) {
	t.Parallel()

	tools := map[string][]inspect.Tool{"alpha": {mkTool("a", "A.")}, "beta": {mkTool("b", "B.")}}
	servers := map[string]any{
		"alpha": map[string]any{"command": "npx"},
		"beta":  map[string]any{"command": "npx"},
	}

	tests := []struct {
		name string
		// pinAlpha makes a first run that pins alpha only, so pins.json
		// exists and the locked scan has only beta to pin.
		pinAlpha bool
		// wantAfter is the stderr of the scan after the release, without the
		// new pins file notice.
		wantAfter string
		// notice is true when the scan after the release creates pins.json.
		notice bool
	}{
		{
			name:      "first run, no pins file",
			wantAfter: pinnedLine("alpha", 1) + "\n" + pinnedLine("beta", 1) + "\n",
			notice:    true,
		},
		{
			name:      "existing pins file, new server",
			pinAlpha:  true,
			wantAfter: pinnedLine("beta", 1) + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, servers)
			if tt.pinAlpha {
				pinAlphaOnly(t, e, tools["alpha"])
			}
			before, existed := readIfExists(t, e.pinsPath())
			release := holdPinsLock(t, e.pinsPath())

			got := e.scan(fakeServers(tools))

			assertScanRun(t, got, scanWant{code: exitError, stdout: []string{"alpha", "beta"}})
			assertStderrLines(t, got.stderr, []lineWant{
				prefixLine(scanPrefix + "cannot read the pins file: "),
				exactLine(scanPrefix + pinsLockedText),
			})
			after, existsNow := readIfExists(t, e.pinsPath())
			if existsNow != existed || !bytes.Equal(before, after) {
				t.Errorf("pins.json changed while another run held the lock (existed %v, exists %v)\nbefore: %s\nafter:  %s",
					existed, existsNow, before, after)
			}

			release()
			again := e.scan(fakeServers(tools))

			assertScanRun(t, again, scanWant{code: exitOK, stderr: []string{tt.wantAfter}})
			want := tt.wantAfter
			if tt.notice {
				want = newPinsFileNotice("scan", e.pinsPath()) + want
			}
			if again.stderr != want {
				t.Errorf("stderr after the release = %q, want %q", again.stderr, want)
			}
			if names := e.readPins().serverNames(); !slices.Equal(names, []string{"alpha", "beta"}) {
				t.Errorf("pinned servers after the release = %v, want [alpha beta]", names)
			}
		})
	}
}

// TestScanReasonsFitShortCell checks that each fixed reason of the
// MOAT-T2-004 rows that scan makes itself fits in a short report cell
// (report.MaxShortCellRunes, such as the "Reason:" line of a finding), so the
// terminal shows the full text and not a cut one.
func TestScanReasonsFitShortCell(t *testing.T) {
	t.Parallel()

	reasons := map[string]string{
		"reasonListedTwice":    reasonListedTwice,
		"reasonNotInspected":   reasonNotInspected,
		"reasonNotPinnable":    reasonNotPinnable,
		"reasonRelativeSource": reasonRelativeSource,
		"reasonStoreFull":      reasonStoreFull,
		"reasonShareFull":      reasonShareFull,
	}
	for name, reason := range reasons {
		if n := utf8.RuneCountInString(reason); n > report.MaxShortCellRunes {
			t.Errorf("%s has %d runes, want at most %d (the terminal cuts it): %q", name, n, report.MaxShortCellRunes, reason)
		}
	}
}

// storeFullReasonCell is the "Reason:" text of the terminal row of a server
// that does not fit in pins.json: reasonStoreFull in quotes, because it holds
// spaces. It is not cut (see TestScanReasonsFitShortCell), so it has no
// termsafe.CutMarker.
func storeFullReasonCell() string {
	return `"` + reasonStoreFull + `"`
}

// TestScanPinsStoreFullAtReport checks a first run of two servers when
// pins.json is nearly full (writeNearFullPins). The server "big" does not fit,
// so the pin step refuses it before the report: it gets a high MOAT-T2-004
// row with the reason reasonStoreFull, the risk riskServerUnverified and the
// fix fixStoreFull, and it is not pinned. The server "tiny" fits and is
// pinned. The high row reaches the default --fail-on high, so the exit code
// is 1, and the save works, so it is not 2. pins.json existed, so stderr has
// only the "pinned" line of tiny: no new pins file notice and no "pins file
// is full" warning (that warning is for a refusal at save time). A second run
// with --json gives the same row with the full reason text.
//
// No t.Parallel: the file is almost 32 MiB, and the scan reads it and writes
// it again, so the test keeps its memory use away from the parallel tests.
func TestScanPinsStoreFullAtReport(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a near-32 MiB pins file; slow under -race")
	}
	e := newPinEnv(t, map[string]any{
		"big":  map[string]any{"command": "npx"},
		"tiny": map[string]any{"command": "npx"},
	})
	writeNearFullPins(t, e.pinsPath())
	tools := map[string][]inspect.Tool{"big": {bigStoreTool()}, "tiny": {mkTool("add_numbers", "Add.")}}

	got := e.scan(fakeServers(tools))

	assertScanRun(t, got, scanWant{code: exitFindings})
	if want := pinnedLine("tiny", 1) + "\n"; got.stderr != want {
		t.Errorf("stderr = %q, want %q", got.stderr, want)
	}
	assertPinRows(t, got.stdout, pinFinding{"MOAT-T2-004", "high", "big", "", storeFullReasonCell()})
	// The line ends right after the closing quote, so it has no
	// termsafe.CutMarker: the terminal shows the full reason.
	if want := "    Reason: " + storeFullReasonCell() + "\n"; !strings.Contains(got.stdout, want) {
		t.Errorf("stdout has no full reason line %q\nstdout:\n%s", want, got.stdout)
	}
	for _, f := range parseFindings(t, got.stdout) {
		if f.RuleID == "MOAT-T2-004" && (f.Risk != riskServerUnverified || f.Fix != fixStoreFull) {
			t.Errorf("MOAT-T2-004 Risk = %q, Fix = %q; want %q, %q", f.Risk, f.Fix, riskServerUnverified, fixStoreFull)
		}
	}
	assertPinsFileMode(t, e.pinsPath())
	wantNames := append(fillerNames(), "tiny")
	if names := bigPinsServerNames(t, e.pinsPath()); !slices.Equal(names, wantNames) {
		t.Errorf("pinned servers = %v, want %v (big is not pinned)", names, wantNames)
	}

	jsonRun := e.scan(fakeServers(tools), "--json")

	assertScanRun(t, jsonRun, scanWant{code: exitFindings})
	assertCleanStderr(t, jsonRun.stderr)
	rows := jsonRowsOf(jsonFindings(t, jsonRun.stdout), "MOAT-T2-004")
	if len(rows) != 1 || rows[0].Severity != "high" || rows[0].Server != "big" || rows[0].Related != reasonStoreFull {
		t.Errorf("JSON MOAT-T2-004 rows = %+v, want one high row for big with related %q", rows, reasonStoreFull)
	}
}

// TestScanPinsStoreFullAtSave checks the refusal at save time: pins.json was
// small when the pin step checked the budget, so the report has no
// MOAT-T2-004 row, but another run made it nearly full before savePinned. Set
// then refuses "big" with pins.ErrStoreFull. scan prints the warning for big,
// still saves "tiny" (with its "pinned" line), and exits with 2, so the
// refusal is never silent. pins.json existed at the save, so there is no new
// pins file notice.
//
// The inspector (hookInspector) simulates another run that makes pins.json
// larger while this scan inspects its servers: after scan read the store for
// the pin step, and before savePinned reads it again. The near-full file is
// built before the scan in a scratch folder, and the hook moves it into place
// with os.Rename, so the hook does no slow work inside inspect.Run. No
// t.Parallel, for the reason of TestScanPinsStoreFullAtReport.
//
// The stderr of scan is a lockProbeWriter: savePinned collects the warning
// while it holds the lock and prints it after the release, so the lock must be
// free when the warning is written. Only the warning is probed: each probe
// reads the near-full file, and TestScanPinsReleasesLockBeforeOutput already
// probes the "pinned" lines.
func TestScanPinsStoreFullAtSave(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a near-32 MiB pins file; slow under -race")
	}
	e := newPinEnv(t, map[string]any{
		"big":  map[string]any{"command": "npx"},
		"tiny": map[string]any{"command": "npx"},
	})
	scratch := filepath.Join(t.TempDir(), "mcpmoat", "pins.json")
	writeNearFullPins(t, scratch)
	grow := func() {
		// t.Errorf, not t.Fatalf: this runs in a goroutine of inspect.Run.
		if err := os.MkdirAll(filepath.Dir(e.pinsPath()), 0o700); err != nil {
			t.Errorf("create the pins directory: %v", err)
			return
		}
		if err := os.Rename(scratch, e.pinsPath()); err != nil {
			t.Errorf("move the near-full pins.json into place: %v", err)
		}
	}
	// once runs grow at the first Inspect call, for any server. once.Do
	// makes the other calls wait until grow is done, so no server is
	// inspected before the file is in place.
	var once sync.Once
	insp := hookInspector{
		inner: fakeServers(map[string][]inspect.Tool{"big": {bigStoreTool()}, "tiny": {mkTool("add_numbers", "Add.")}}),
		hook:  func(discover.Server) { once.Do(grow) },
	}

	c, stdout, stderr := e.cli(insp)
	probe := newLockProbeWriter(t, stderr, e.pinsPath(), "not pinned: ")
	c.stderr = probe

	code := c.dispatch([]string{"scan", "--config", e.config})

	got := pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
	assertScanRun(t, got, scanWant{code: exitError})
	want := scanWarnPrefix + "server big not pinned: the pins file is full (32 MiB)\n" + pinnedLine("tiny", 1) + "\n"
	if got.stderr != want {
		t.Errorf("stderr = %q, want %q", got.stderr, want)
	}
	assertLockFreeAt(t, probe, "server big not pinned: ")
	// The report came before the save, when big still fitted.
	assertNoPinRows(t, got.stdout)
	assertPinsFileMode(t, e.pinsPath())
	wantNames := append(fillerNames(), "tiny")
	if names := bigPinsServerNames(t, e.pinsPath()); !slices.Equal(names, wantNames) {
		t.Errorf("pinned servers = %v, want %v (big is not pinned)", names, wantNames)
	}
}

// TestScanPinsReleasesLockBeforeOutput checks that savePinned releases the lock
// on the pins directory right after the save, before it prints the new pins
// file notice and the "pinned" lines. A slow or blocked reader of stderr must
// not keep other runs from the pins file. The stderr of scan is a
// lockProbeWriter: each write of one of those lines tries the lock as another
// run would, and the lock must be free.
func TestScanPinsReleasesLockBeforeOutput(t *testing.T) {
	t.Parallel()

	tools := map[string][]inspect.Tool{"alpha": {mkTool("a", "A.")}, "beta": {mkTool("b", "B.")}}
	servers := map[string]any{
		"alpha": map[string]any{"command": "npx"},
		"beta":  map[string]any{"command": "npx"},
	}

	tests := []struct {
		name string
		// pinAlpha makes a first run that pins alpha only, so pins.json
		// exists and the probed scan has only beta to pin.
		pinAlpha bool
		// wantProbes are the stderr lines at which the lock is tried, in order.
		wantProbes []string
	}{
		{
			name:       "first run, no pins file",
			wantProbes: []string{"no pins file was found", "pinned 1 tool for alpha", "pinned 1 tool for beta"},
		},
		{
			name:       "existing pins file, new server",
			pinAlpha:   true,
			wantProbes: []string{"pinned 1 tool for beta"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, servers)
			if tt.pinAlpha {
				pinAlphaOnly(t, e, tools["alpha"])
			}
			c, stdout, stderr := e.cli(fakeServers(tools))
			probe := newLockProbeWriter(t, stderr, e.pinsPath(), "no pins file was found", "pinned ")
			c.stderr = probe

			code := c.dispatch([]string{"scan", "--config", e.config})

			got := pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
			assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"alpha", "beta"}, stderr: []string{pinnedLine("beta", 1)}})
			assertLockFreeAt(t, probe, tt.wantProbes...)
			if names := e.readPins().serverNames(); !slices.Equal(names, []string{"alpha", "beta"}) {
				t.Errorf("pinned servers = %v, want [alpha beta]", names)
			}
		})
	}
}

// TestScanPinsWarnsAfterRelease checks that the warning for a server that
// another run pinned with other tools during the scan is written after the
// release of the lock. savePinned finds the entry while it holds the lock,
// collects the warning, and prints it after the release, before the "pinned"
// line of the other server. The stderr of scan is a lockProbeWriter, so each
// of the two lines tries the lock as another run would, and the lock must be
// free.
//
// The other run is simulated by the inspector (hookInspector): it pins srv
// with another tool while scan inspects srv, like TestScanFreshStoreKeepsOtherRun.
func TestScanPinsWarnsAfterRelease(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, map[string]any{
		"srv":   map[string]any{"command": "npx"},
		"other": map[string]any{"command": "npx"},
	})
	insp := hookInspector{
		inner: fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}, "other": {mkTool("o", "Other.")}}),
		hook: onceFor("srv", func(s discover.Server) {
			writePinsAside(t, e.pinsPath(), serverIdentity(s), mkTool("x", "Written by another run."))
		}),
	}
	c, stdout, stderr := e.cli(insp)
	probe := newLockProbeWriter(t, stderr, e.pinsPath(), "was pinned by another run", "pinned 1 tool for other")
	c.stderr = probe

	code := c.dispatch([]string{"scan", "--config", e.config})

	got := pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
	assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv", "other"}, stderr: []string{parallelPinWarning}})
	// The other run created pins.json before the locked read, so there is no
	// new pins file notice.
	if want := parallelPinWarning + pinnedLine("other", 1) + "\n"; got.stderr != want {
		t.Errorf("stderr = %q, want exactly %q", got.stderr, want)
	}
	assertLockFreeAt(t, probe, "was pinned by another run", "pinned 1 tool for other")
	if names := e.readPins().serverNames(); !slices.Equal(names, []string{"other", "srv"}) {
		t.Errorf("pinned servers = %v, want [other srv]", names)
	}
}

// TestScanPinsFileRemovedDuringScan checks a pins.json that was on disk at the
// first read of scan but is gone at the read with the lock in savePinned:
// another process removed it while scan inspected the servers. A save would
// write a new file with only the servers of this run and drop every older pin
// (here alpha), so a later rug pull would look like a first run. So scan saves
// nothing: exit code 2, exactly the pinsRemovedText line on stderr, no
// "pinned" line, no new pins file notice, and no pins.json. The report is
// already out on stdout. The stderr of scan is a lockProbeWriter: savePinned
// prints the pinsRemovedText line after the release, so the lock must be free
// at that write.
//
// The removal runs in the inspector (hookInspector), so it comes after the
// first read and before savePinned, like the growth of pins.json in
// TestScanPinsStoreFullAtSave. The control, a real first run with no file at
// both reads, is TestScanPinsNewFileNotice: it saves and prints the notice.
func TestScanPinsFileRemovedDuringScan(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, map[string]any{
		"alpha": map[string]any{"command": "npx"},
		"beta":  map[string]any{"command": "npx"},
	})
	// The first run pins alpha only: beta fails, so it is new on the next run.
	pinAlphaOnly(t, e, []inspect.Tool{mkTool("a", "A.")})
	insp := hookInspector{
		inner: fakeServers(map[string][]inspect.Tool{"alpha": {mkTool("a", "A.")}, "beta": {mkTool("b", "B.")}}),
		hook: onceFor("beta", func(discover.Server) {
			// t.Errorf, not t.Fatalf: this runs in a goroutine of inspect.Run.
			if err := os.Remove(e.pinsPath()); err != nil {
				t.Errorf("remove pins.json while scan inspects: %v", err)
			}
		}),
	}

	c, stdout, stderr := e.cli(insp)
	probe := newLockProbeWriter(t, stderr, e.pinsPath(), pinsRemovedText)
	c.stderr = probe

	code := c.dispatch([]string{"scan", "--config", e.config})

	got := pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
	assertScanRun(t, got, scanWant{code: exitError, stdout: []string{"alpha", "beta"}})
	e.assertNoPinsFile(t, "a scan whose pins file was removed while it ran")
	assertContainsNone(t, "stderr", got.stderr, []string{"pinned ", "no pins file was found"})
	assertStderrLines(t, got.stderr, []lineWant{exactLine(scanPrefix + pinsRemovedText)})
	assertLockFreeAt(t, probe, pinsRemovedText)
}
