package main

// In-process tests of issue #221: "scan --json" writes its document before
// savePinned saves the new pins, on purpose (the user sees the report first).
// So "complete": true covers the scan steps only, and a document with
// "complete": true and exit code 2 means that the pin save failed. Each case
// below makes one cause of that failure happen after the document is written,
// and checks that stdout is still one valid, complete document with the
// findings of the report, that stderr gives the reason, that no line says
// that pins were saved, and that pins.json did not change.
//
// The tests use a fake inspector, so no server starts, and they never call
// t.Setenv: each test has its own home and XDG_CONFIG_HOME in t.TempDir(). A
// failure "at save time" is made by a hook of the inspector (hookInspector):
// it runs after scan read pins.json for the pin step, and before savePinned
// reads it again with the lock.

import (
	"context"
	"crypto/sha256"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// saveJSONServers returns the config servers of these tests. alpha gives one
// medium config finding (MOAT-T4-003) and beta one low config finding
// (MOAT-T4-004), so the report has findings, and a clean run still exits
// with 0 at the default --fail-on high.
func saveJSONServers() map[string]any {
	return map[string]any{"alpha": failOnMediumServer, "beta": failOnLowServer}
}

// saveJSONTools returns the tools that the fake inspector gives alpha and
// beta. They give no finding.
func saveJSONTools() map[string][]inspect.Tool {
	return map[string][]inspect.Tool{"alpha": {mkTool("a", "A.")}, "beta": {mkTool("b", "B.")}}
}

// jsonFindingID is the part of a --json finding that these tests compare.
type jsonFindingID struct {
	server, rule, severity string
}

// saveJSONFindings are the findings of saveJSONServers, sorted by server.
var saveJSONFindings = []jsonFindingID{
	{"alpha", "MOAT-T4-003", "medium"},
	{"beta", "MOAT-T4-004", "low"},
}

// findingIDsOf returns the findings of doc as jsonFindingID values, sorted by
// server, then rule.
func findingIDsOf(doc report.ScanReport) []jsonFindingID {
	out := make([]jsonFindingID, len(doc.Findings))
	for i, f := range doc.Findings {
		out[i] = jsonFindingID{f.Server, f.RuleID, f.Severity}
	}
	slices.SortFunc(out, func(a, b jsonFindingID) int {
		return strings.Compare(a.server+"\x00"+a.rule, b.server+"\x00"+b.rule)
	})
	return out
}

// pinsState is what a test knows about pins.json at one moment: whether the
// file exists, and the SHA-256 of its content. A hash keeps the near-full
// file of writeNearFullPins (32 MiB) out of the memory of the test.
type pinsState struct {
	exists bool
	sum    [sha256.Size]byte
}

// pinsStateOf returns the pinsState of the file at path.
func pinsStateOf(t *testing.T, path string) pinsState {
	t.Helper()
	data, ok := readIfExists(t, path)
	return pinsState{exists: ok, sum: sha256.Sum256(data)}
}

// saveFailPrep is what the prepare function of a case gives the runner.
type saveFailPrep struct {
	// hook runs at an Inspect call of the scan (see hookInspector), or is nil.
	hook func(discover.Server)
	// wantPins is the state of pins.json after the scan, or nil when the scan
	// must leave pins.json as it was right before the scan.
	wantPins *pinsState
}

// assertStderrLineSet fails the test unless the non-empty lines of stderr
// match wants one for one, in any order. inspect.Run sorts the servers, so a
// test that wants one line for each server does not depend on that order.
func assertStderrLineSet(t *testing.T, stderr string, wants []lineWant) {
	t.Helper()
	lines := nonEmptyLines(stderr)
	if len(lines) != len(wants) {
		t.Fatalf("stderr has %d lines, want %d:\n%s", len(lines), len(wants), stderr)
	}
	used := make([]bool, len(lines))
	for _, w := range wants {
		found := false
		for i, line := range lines {
			ok := line == w.text
			if w.prefix {
				ok = strings.HasPrefix(line, w.text)
			}
			if ok && !used[i] {
				used[i], found = true, true
				break
			}
		}
		if !found {
			t.Errorf("stderr has no line for %+v:\n%s", w, stderr)
		}
	}
}

// assertJSONReportIntact checks that stdout is exactly one valid scan
// document (see decodeScanJSON) with the given complete value, in connect
// mode, with the findings of saveJSONServers. When complete is true, it also
// checks that the scan inspected both servers.
func assertJSONReportIntact(t *testing.T, stdout string, complete bool) {
	t.Helper()
	doc := decodeScanJSON(t, stdout)
	if doc.Complete != complete {
		t.Errorf("complete = %v, want %v", doc.Complete, complete)
	}
	if doc.Mode != report.ModeConnect {
		t.Errorf("mode = %q, want %q", doc.Mode, report.ModeConnect)
	}
	if got := findingIDsOf(doc); !slices.Equal(got, saveJSONFindings) {
		t.Errorf("findings = %+v, want %+v", got, saveJSONFindings)
	}
	if complete {
		want := map[string]report.InspectionStatus{"alpha": report.InspectionOK, "beta": report.InspectionOK}
		if got := inspectionByName(doc); !maps.Equal(got, want) {
			t.Errorf("inspection statuses = %v, want %v", got, want)
		}
	}
}

// TestScanJSONSaveFailedAfterReport checks each cause of a failed pin save
// with --json: exit code 2, stdout is one valid document with "complete":
// true and all the findings, stderr holds exactly the reason lines of that
// cause, no line says that pins were saved (no "pinned" line and no new pins
// file notice), and pins.json is as the case wants: unchanged, or gone when
// another process removed it.
//
// Not covered: pins.ErrPinsDirChanged. Save checks the pins directory right
// before the rename, in the same call as LoadLocked and Set, and the command
// has no hook between those steps, so a test could only race it.
//
// The case "server no longer fits" builds a near-32 MiB pins file, so it does
// not call t.Parallel and is skipped with -short, like
// TestScanPinsStoreFullAtSave.
func TestScanJSONSaveFailedAfterReport(t *testing.T) {
	t.Parallel()

	cannotRead := prefixLine(scanPrefix + "cannot read the pins file: ")
	tests := []struct {
		name string
		// big is true for the near-full pins file: no t.Parallel, and skipped
		// with -short.
		big bool
		// modeBits skips the case where the mode bits do not stop the user
		// (see skipWithoutModeBits).
		modeBits bool
		// pinAlpha makes a first run that pins alpha only, so pins.json exists
		// and the scan has only beta to pin.
		pinAlpha bool
		// tools replaces saveJSONTools when not nil.
		tools map[string][]inspect.Tool
		// prepare runs before the scan, after pinAlpha.
		prepare func(t *testing.T, e *pinEnv) saveFailPrep
		// interrupt cancels the context of the run after the report is
		// written, as a signal would.
		interrupt bool
		// stderr are the lines of stderr, in any order.
		stderr []lineWant
		// stderrHas are more substrings of stderr.
		stderrHas []string
	}{
		{
			name: "lock held by another process",
			prepare: func(t *testing.T, e *pinEnv) saveFailPrep {
				holdPinsLock(t, e.pinsPath())
				return saveFailPrep{}
			},
			stderr: []lineWant{cannotRead, exactLine(scanPrefix + pinsLockedText)},
		},
		{
			name:     "pins file removed during the run",
			pinAlpha: true,
			prepare: func(t *testing.T, e *pinEnv) saveFailPrep {
				return saveFailPrep{
					hook: onceFor("beta", func(discover.Server) {
						// t.Errorf, not t.Fatalf: this runs in a goroutine of
						// inspect.Run.
						if err := os.Remove(e.pinsPath()); err != nil {
							t.Errorf("remove pins.json while scan inspects: %v", err)
						}
					}),
					wantPins: &pinsState{exists: false, sum: sha256.Sum256(nil)},
				}
			},
			stderr: []lineWant{exactLine(scanPrefix + pinsRemovedText)},
		},
		{
			name: "server no longer fits at save",
			big:  true,
			// Both servers are too large for the near-full file, so the save
			// pins nothing and writes nothing.
			tools: map[string][]inspect.Tool{"alpha": {bigStoreTool()}, "beta": {bigStoreTool()}},
			prepare: func(t *testing.T, e *pinEnv) saveFailPrep {
				scratch := filepath.Join(t.TempDir(), "mcpmoat", "pins.json")
				writeNearFullPins(t, scratch)
				full := pinsStateOf(t, scratch)
				grow := func() {
					// t.Errorf, not t.Fatalf: this runs in a goroutine of
					// inspect.Run.
					if err := os.MkdirAll(filepath.Dir(e.pinsPath()), 0o700); err != nil {
						t.Errorf("create the pins directory: %v", err)
						return
					}
					if err := os.Rename(scratch, e.pinsPath()); err != nil {
						t.Errorf("move the near-full pins.json into place: %v", err)
					}
				}
				// once.Do makes the other Inspect calls wait until grow is
				// done.
				var once sync.Once
				return saveFailPrep{hook: func(discover.Server) { once.Do(grow) }, wantPins: &full}
			},
			stderr: []lineWant{
				exactLine(scanWarnPrefix + "server alpha not pinned: " + pinsFullText),
				exactLine(scanWarnPrefix + "server beta not pinned: " + pinsFullText),
			},
		},
		{
			name:     "unsafe pins directory at save",
			modeBits: true,
			pinAlpha: true,
			prepare: func(t *testing.T, e *pinEnv) saveFailPrep {
				restorePinsModes(t, e)
				dir := filepath.Dir(e.pinsPath())
				return saveFailPrep{hook: onceFor("alpha", func(discover.Server) {
					if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // G302: the test makes the folder unsafe on purpose
						t.Errorf("make the pins directory group and world writable: %v", err)
					}
				})}
			},
			stderr:    []lineWant{cannotRead},
			stderrHas: []string{"pins directory", "is not safe: mode 0777", "insecure permissions"},
		},
		{
			name:     "read-only pins directory at save",
			modeBits: true,
			prepare: func(t *testing.T, e *pinEnv) saveFailPrep {
				readOnlyPinsDir(t, e)
				return saveFailPrep{}
			},
			stderr:    []lineWant{prefixLine(scanPrefix + "cannot save the pins file: ")},
			stderrHas: []string{"permission denied"},
		},
		{
			name:     "lock file open to others",
			modeBits: true,
			prepare: func(t *testing.T, e *pinEnv) saveFailPrep {
				dir := filepath.Dir(e.pinsPath())
				lock := filepath.Join(dir, pinsLockFileName)
				return saveFailPrep{hook: onceFor("alpha", func(discover.Server) {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Errorf("create the pins directory: %v", err)
						return
					}
					if err := os.WriteFile(lock, nil, 0o600); err != nil {
						t.Errorf("create the lock file: %v", err)
						return
					}
					if err := os.Chmod(lock, 0o644); err != nil { //nolint:gosec // G302: the test makes the lock file unsafe on purpose
						t.Errorf("make the lock file readable by others: %v", err)
					}
				})}
			},
			stderr:    []lineWant{cannotRead},
			stderrHas: []string{"pins lock file", "is not safe: mode 0644", "insecure permissions"},
		},
		{
			name:      "interrupt after the report",
			interrupt: true,
			stderr:    []lineWant{exactLine(scanPrefix + interruptedText)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.big {
				if testing.Short() {
					t.Skip("builds a near-32 MiB pins file; slow under -race")
				}
			} else {
				t.Parallel()
			}
			if tt.modeBits {
				skipWithoutModeBits(t)
			}
			e := newPinEnv(t, saveJSONServers())
			if tt.pinAlpha {
				pinAlphaOnly(t, e, saveJSONTools()["alpha"])
			}
			var prep saveFailPrep
			if tt.prepare != nil {
				prep = tt.prepare(t, e)
			}
			before := pinsStateOf(t, e.pinsPath())
			tools := tt.tools
			if tools == nil {
				tools = saveJSONTools()
			}
			var insp inspect.Inspector = fakeServers(tools)
			if prep.hook != nil {
				insp = hookInspector{inner: insp, hook: prep.hook}
			}
			c, stdout, stderr := e.cli(insp)
			if tt.interrupt {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				c.ctx = ctx
				// cancelOnWrite (pin_flow_test.go) cancels at the first write:
				// the --json document. Scan only writes after the steps, so the
				// context ends after the report and before savePinned, as a
				// signal would.
				c.stdout = cancelOnWrite{buf: stdout, cancel: cancel}
			}

			code := c.dispatch([]string{"scan", "--config", e.config, "--json"})

			got := pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
			if got.code != exitError {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", got.code, exitError, got.stderr)
			}
			assertJSONReportIntact(t, got.stdout, true)
			assertStderrLineSet(t, got.stderr, tt.stderr)
			assertContainsAll(t, "stderr", got.stderr, tt.stderrHas)
			assertContainsNone(t, "stderr", got.stderr, []string{scanPrefix + "pinned ", "no pins file was found"})
			assertContainsNone(t, "stdout", got.stdout, []string{scanPrefix})
			assertScanPrefix(t, got.stderr)
			assertNoLeakBoth(t, got.stdout, got.stderr)
			assertNoEscape(t, got.stdout, got.stderr)

			want := before
			if prep.wantPins != nil {
				want = *prep.wantPins
			}
			if after := pinsStateOf(t, e.pinsPath()); after != want {
				t.Errorf("pins.json after the scan: exists = %v (same content %v), want exists = %v and the content of the case",
					after.exists, after.sum == want.sum, want.exists)
			}
		})
	}
}

// TestScanJSONSaveControls checks the two other sides of the "complete"
// field. A clean run saves the pins: "complete": true, exit code 0, the new
// pins file notice and one "pinned" line for each server on stderr, and both
// servers in pins.json. A run whose pin step fails as a whole (pins.json
// cannot be read, as in TestScanJSONIncomplete) has "complete": false, exit
// code 2, the findings of the config rules, and leaves pins.json as it was.
func TestScanJSONSaveControls(t *testing.T) {
	t.Parallel()

	t.Run("clean run saves", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, saveJSONServers())

		got := e.scan(fakeServers(saveJSONTools()), "--json")

		if got.code != exitOK {
			t.Errorf("exit code = %d, want %d\nstderr:\n%s", got.code, exitOK, got.stderr)
		}
		assertJSONReportIntact(t, got.stdout, true)
		want := newPinsFileNotice("scan", e.pinsPath()) + pinnedLine("alpha", 1) + "\n" + pinnedLine("beta", 1) + "\n"
		if got.stderr != want {
			t.Errorf("stderr = %q, want %q", got.stderr, want)
		}
		if names := e.readPins().serverNames(); !slices.Equal(names, []string{"alpha", "beta"}) {
			t.Errorf("pinned servers = %v, want [alpha beta]", names)
		}
	})

	t.Run("incomplete scan", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, saveJSONServers())
		writeTestFile(t, filepath.Dir(e.pinsPath()), "pins.json", "{this is not json")
		before := pinsStateOf(t, e.pinsPath())

		got := e.scan(fakeServers(saveJSONTools()), "--json")

		if got.code != exitError {
			t.Errorf("exit code = %d, want %d\nstderr:\n%s", got.code, exitError, got.stderr)
		}
		assertJSONReportIntact(t, got.stdout, false)
		assertStderrLines(t, got.stderr, []lineWant{prefixLine(scanPrefix + "cannot read the pins file: ")})
		assertContainsNone(t, "stderr", got.stderr, []string{scanPrefix + "pinned ", "no pins file was found"})
		if after := pinsStateOf(t, e.pinsPath()); after != before {
			t.Errorf("pins.json changed after a scan that could not read it (exists = %v)", after.exists)
		}
	})
}
