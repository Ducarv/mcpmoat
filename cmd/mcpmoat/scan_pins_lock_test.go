package main

// In-process tests of the save step of "mcpmoat scan" (savePinned): the notice
// for a new pins file, the lock on the pins directory and its release before
// the output, a pins file that was removed while scan ran, and the size limit
// of pins.json (32 MiB) at report time and at save time. They use a fake
// inspector, so no server starts, and they never call t.Setenv: each test has
// its own home and XDG_CONFIG_HOME in t.TempDir(). The shared pin helpers are
// in pins_helpers_test.go. The near-full pins file (writeNearFullPins and
// bigStoreTool) is here, and TestPinAcceptStoreFull uses it too.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/pins"
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
		fake := fakeServers(map[string][]inspect.Tool{"alpha": tools["alpha"]})
		fake.Errors = map[string]error{"beta": errors.New("boom")}
		first := e.scan(fake)
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
				fake := fakeServers(map[string][]inspect.Tool{"alpha": tools["alpha"]})
				fake.Errors = map[string]error{"beta": errors.New("boom")}
				if r := e.scan(fake); r.code != exitOK {
					t.Fatalf("first scan: exit code = %d, stderr:\n%s", r.code, r.stderr)
				}
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

// readIfExists returns the content of path and true, or nil and false when
// the file does not exist. It fails the test on another error.
func readIfExists(t *testing.T, path string) ([]byte, bool) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is under the test's own t.TempDir()
	if errors.Is(err, os.ErrNotExist) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return data, true
}

// pinsFileLimitBytes is the size limit of pins.json in bytes: maxFileSize in
// internal/pins, which the messages show as pinsFileLimit ("32 MiB"). This is
// the one copy of the number in the cmd tests. internal/pins exports it as
// pins.MaxFileSize only to its own tests (export_test.go), so this package
// cannot read it. If the limit changes, the store-full tests fail: with a lower
// limit Set refuses a filler in writeNearFullPins, and with a higher one the
// big server fits.
const pinsFileLimitBytes = 32 << 20

// nearFullGap is the free space that writeNearFullPins leaves below
// pinsFileLimitBytes. The entry of a server with bigStoreTool is larger than
// it, and the entry of a server with one mkTool is far smaller.
const nearFullGap = 16 << 10

// nearFullServers is the number of filler servers in the file of
// writeNearFullPins. With 17, each entry is about 1.9 MiB, well below the
// limit of one server (2 MiB).
const nearFullServers = 17

// bigStoreTool returns a tool whose pins entry is larger than nearFullGap:
// its _meta alone is twice that size. The size is in _meta and not in the
// description, so no description rule (for example the one for a long
// description) adds a row, and the rule step stays fast.
func bigStoreTool() inspect.Tool {
	return metaTool("big_tool", `{"k":"`+strings.Repeat("a", 2*nearFullGap)+`"}`, "")
}

// fillerIdentity returns the identity of the filler server i. The names have
// the same length, so every filler entry has the same fixed bytes.
func fillerIdentity(i int) pins.Identity {
	return pins.Identity{Client: "fixture", Source: "/fixture/mcp.json", Name: fmt.Sprintf("fill-%02d", i)}
}

// fillerNames returns the names of the nearFullServers filler servers.
func fillerNames() []string {
	names := make([]string, nearFullServers)
	for i := range names {
		names[i] = fillerIdentity(i).Name
	}
	return names
}

// fillerPins returns the pins of a filler server: one tool "fill" with the
// canonical text and its hash. The hash is built like the one of
// setPinCanonical (pins.HashVersion, a colon, the hex SHA-256), so it has the
// same length for every text.
func fillerPins(canonical string) pins.ServerPins {
	sum := sha256.Sum256([]byte(canonical))
	return pins.ServerPins{"fill": {Hash: pins.HashVersion + ":" + hex.EncodeToString(sum[:]), Canonical: canonical}}
}

// saveFillers saves a new pins store at path with one filler server for each
// canonical text (fillerIdentity(i), fillerPins(canonicals[i])) and returns
// the size of the file. It uses the pins API only: pins.Load of a missing
// file gives an empty store, and Save writes the directory with mode 0700
// and the file with mode 0600, as the CLI requires.
func saveFillers(t *testing.T, path string, canonicals ...string) int {
	t.Helper()
	store, err := pins.Load(path)
	if err != nil {
		t.Fatalf("pins.Load(%q) error = %v, want nil", path, err)
	}
	if store.Existed() {
		t.Fatalf("pins.Load(%q): the file exists, want a new store", path)
	}
	for i, c := range canonicals {
		if err := store.Set(fillerIdentity(i), fillerPins(c)); err != nil {
			t.Fatalf("Store.Set(filler %d) error = %v, want nil", i, err)
		}
	}
	if err := store.Save(); err != nil {
		t.Fatalf("Store.Save() error = %v, want nil", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return int(info.Size())
}

// writeNearFullPins writes a valid pins.json at path with nearFullServers
// filler servers, so that the file has exactly pinsFileLimitBytes -
// nearFullGap bytes. A server entry larger than nearFullGap then does not
// fit (pins.ErrStoreFull), and a small one does.
//
// The size of the file depends on the format of Save, so the helper measures
// it: it saves one and two fillers with a one-byte text in scratch folders.
// The file grows by one byte for each byte of a canonical text of letters, so
// the sizes give the fixed bytes of the file and of one entry. The filler
// texts share one string, so the memory use stays near the size of the file.
func writeNearFullPins(t *testing.T, path string) {
	t.Helper()
	one := saveFillers(t, filepath.Join(t.TempDir(), "mcpmoat", "pins.json"), "a")
	two := saveFillers(t, filepath.Join(t.TempDir(), "mcpmoat", "pins.json"), "a", "a")
	entry := two - one // one entry with a one-byte text
	fixed := one - entry

	want := pinsFileLimitBytes - nearFullGap
	textBytes := want - fixed - nearFullServers*(entry-1)
	n := textBytes / nearFullServers
	long := strings.Repeat("a", n+textBytes%nearFullServers)
	canonicals := make([]string, nearFullServers)
	for i := range canonicals {
		canonicals[i] = long[:n]
	}
	canonicals[nearFullServers-1] = long

	if size := saveFillers(t, path, canonicals...); size != want {
		t.Fatalf("near-full pins.json has %d bytes, want %d (the size model of Save changed)", size, want)
	}
}

// bigPinsServerNames returns the server names in the pins file at path,
// sorted. It is for the near-full file of writeNearFullPins: a JSON decode of
// 32 MiB is slow with -race, so it finds each `"name": "` key with
// bytes.Index. The key text matches the server entries only: Save writes one
// space after the colon, and a canonical text in the file is a JSON string,
// so its quotes are escaped (\"name\":\"...\"). The names of the tests are
// plain words with no escape.
func bigPinsServerNames(t *testing.T, path string) []string {
	t.Helper()
	const key = `"name": "`
	data := readFileBytes(t, path)
	var names []string
	for {
		i := bytes.Index(data, []byte(key))
		if i < 0 {
			break
		}
		data = data[i+len(key):]
		end := bytes.IndexByte(data, '"')
		if end < 0 {
			t.Fatalf("pins file %s has a name with no end quote", path)
		}
		names = append(names, string(data[:end]))
		data = data[end:]
	}
	slices.Sort(names)
	return names
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

// growPinsInspector is a fake inspector that runs grow once, at its first
// Inspect call, and then answers like inner. It simulates another run that
// makes pins.json larger while this scan inspects its servers: after scan
// read the store for the pin step, and before savePinned reads it again.
// sync.Once makes the other Inspect calls wait until grow is done.
type growPinsInspector struct {
	inner *inspecttest.Fake
	once  *sync.Once
	grow  func()
}

func (g growPinsInspector) Inspect(ctx context.Context, s discover.Server) (inspect.Result, error) {
	g.once.Do(g.grow)
	return g.inner.Inspect(ctx, s)
}

// TestScanPinsStoreFullAtSave checks the refusal at save time: pins.json was
// small when the pin step checked the budget, so the report has no
// MOAT-T2-004 row, but another run made it nearly full before savePinned. Set
// then refuses "big" with pins.ErrStoreFull. scan prints the warning for big,
// still saves "tiny" (with its "pinned" line), and exits with 2, so the
// refusal is never silent. pins.json existed at the save, so there is no new
// pins file notice.
//
// The near-full file is built before the scan in a scratch folder, and the
// inspector moves it into place with os.Rename, so the hook does no slow work
// inside inspect.Run. No t.Parallel, for the reason of
// TestScanPinsStoreFullAtReport.
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
	insp := growPinsInspector{
		inner: fakeServers(map[string][]inspect.Tool{"big": {bigStoreTool()}, "tiny": {mkTool("add_numbers", "Add.")}}),
		once:  &sync.Once{},
		grow: func() {
			// t.Errorf, not t.Fatalf: this runs in a goroutine of inspect.Run.
			if err := os.MkdirAll(filepath.Dir(e.pinsPath()), 0o700); err != nil {
				t.Errorf("create the pins directory: %v", err)
				return
			}
			if err := os.Rename(scratch, e.pinsPath()); err != nil {
				t.Errorf("move the near-full pins.json into place: %v", err)
			}
		},
	}

	got := e.scan(insp)

	assertScanRun(t, got, scanWant{code: exitError})
	want := scanWarnPrefix + "server big not pinned: the pins file is full (32 MiB)\n" + pinnedLine("tiny", 1) + "\n"
	if got.stderr != want {
		t.Errorf("stderr = %q, want %q", got.stderr, want)
	}
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
				fake := fakeServers(map[string][]inspect.Tool{"alpha": tools["alpha"]})
				fake.Errors = map[string]error{"beta": errors.New("boom")}
				if r := e.scan(fake); r.code != exitOK {
					t.Fatalf("first scan: exit code = %d, stderr:\n%s", r.code, r.stderr)
				}
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

// TestScanPinsFileRemovedDuringScan checks a pins.json that was on disk at the
// first read of scan but is gone at the read with the lock in savePinned:
// another process removed it while scan inspected the servers. A save would
// write a new file with only the servers of this run and drop every older pin
// (here alpha), so a later rug pull would look like a first run. So scan saves
// nothing: exit code 2, exactly the pinsRemovedText line on stderr, no
// "pinned" line, no new pins file notice, and no pins.json. The report is
// already out on stdout.
//
// The removal runs in the inspector (hookInspector), so it comes after the
// first read and before savePinned, like growPinsInspector in
// TestScanPinsStoreFullAtSave. The control, a real first run with no file at
// both reads, is TestScanPinsNewFileNotice: it saves and prints the notice.
func TestScanPinsFileRemovedDuringScan(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, map[string]any{
		"alpha": map[string]any{"command": "npx"},
		"beta":  map[string]any{"command": "npx"},
	})
	// The first run pins alpha only: beta fails, so it is new on the next run.
	fake := fakeServers(map[string][]inspect.Tool{"alpha": {mkTool("a", "A.")}})
	fake.Errors = map[string]error{"beta": errors.New("boom")}
	if r := e.scan(fake); r.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", r.code, r.stderr)
	}
	insp := hookInspector{
		inner: fakeServers(map[string][]inspect.Tool{"alpha": {mkTool("a", "A.")}, "beta": {mkTool("b", "B.")}}),
		hook: onceFor("beta", func(discover.Server) {
			// t.Errorf, not t.Fatalf: this runs in a goroutine of inspect.Run.
			if err := os.Remove(e.pinsPath()); err != nil {
				t.Errorf("remove pins.json while scan inspects: %v", err)
			}
		}),
	}

	got := e.scan(insp)

	assertScanRun(t, got, scanWant{code: exitError, stdout: []string{"alpha", "beta"}})
	e.assertNoPinsFile(t, "a scan whose pins file was removed while it ran")
	assertContainsNone(t, "stderr", got.stderr, []string{"pinned ", "no pins file was found"})
	assertStderrLines(t, got.stderr, []lineWant{exactLine(scanPrefix + pinsRemovedText)})
}
