package main

// In-process tests of the save step of "pin --accept": the notice for a new
// pins file, the lock on the pins directory and its release before the
// output, the size limit of pins.json (ErrStoreFull), the warning when another
// run changed the pins of the server while pin showed the diff, and a pins
// file that was removed meanwhile. They use the helpers of
// pins_helpers_test.go, and the near-full pins file of writeNearFullPins
// (scan_pins_lock_test.go). Only TestPinAcceptStoreFull does not run in
// parallel: it builds a pins file of almost 32 MiB.

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// pinsReadErrPrefix starts the line that pin prints when it cannot read the
// pins file, also when another run holds the lock.
const pinsReadErrPrefix = "mcpmoat pin: cannot read the pins file: "

// pinsLockedLine is the line that pin prints after pinsReadErrPrefix when
// another process held the lock on the pins directory: pinsLockedText with
// the pin prefix.
const pinsLockedLine = pinPrefix + pinsLockedText + "\n"

// pinsChangedWarning returns the warning line that pin prints when another run
// changed the pins of the server name between the read for the diff and the
// read with the lock. name must be a bare name that needs no escape.
func pinsChangedWarning(name string) string {
	return "mcpmoat pin: warning: another mcpmoat run changed the pins of server " + name +
		" while pin showed the diff; the diff is against the older pins\n"
}

// pinStreams runs "mcpmoat pin --config <file> args..." and returns the exit
// code, stdout and stderr, and also both streams in one buffer in the order of
// the writes. A test can then check what goes to which stream and the order of
// lines across the two streams with one run.
func (e *pinEnv) pinStreams(insp inspect.Inspector, args ...string) (r pinRunResult, shared string) {
	e.t.Helper()
	c, _, _ := e.cli(insp)
	var stdout, stderr, both bytes.Buffer
	c.stdout = io.MultiWriter(&stdout, &both)
	c.stderr = io.MultiWriter(&stderr, &both)
	code := c.dispatch(append([]string{"pin", "--config", e.config}, args...))
	return pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}, both.String()
}

// TestPinAcceptNewPinsFileNotice checks the notice of a new pins file: the
// accept that creates pins.json prints it once on stderr, after the diff and
// the note and before the "accepted" line. The next accept, on the file that
// now exists, does not print it. When the file is removed, the next accept
// prints it again, because a lost file is what the notice is for.
func TestPinAcceptNewPinsFileNotice(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	notice := newPinsFileNotice("pin", e.pinsPath())
	first := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})

	got, both := e.pinStreams(first, "--accept", "srv")

	assertPinRun(t, got, scanWant{code: exitOK, stdout: []string{"accepted srv: 1 new, 0 changed, 0 removed\n"}, stderr: []string{notice}})
	if want := noExpectNote + notice; got.stderr != want {
		t.Errorf("first accept: stderr = %q, want exactly %q", got.stderr, want)
	}
	assertContainsNone(t, "stdout", got.stdout, []string{"no pins file was found"})
	diff, note, at, accepted := strings.Index(both, "New tool a on server srv:"), strings.Index(both, noExpectNote),
		strings.Index(both, notice), strings.Index(both, "accepted srv:")
	if diff < 0 || note <= diff || at <= note || accepted <= at {
		t.Errorf("want the diff (%d), the note (%d), the notice (%d), then accepted (%d)\noutput:\n%s", diff, note, at, accepted, both)
	}
	assertPinsFileMode(t, e.pinsPath())
	if pinned, ok := e.readPins().tools("srv"); !ok || len(pinned) != 1 {
		t.Errorf("pins.json has %d tools for srv (found %v), want 1", len(pinned), ok)
	}

	// The second accept saves into the file that the first one created.
	again := e.pin(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add. Changed.")}}), "--accept", "srv")

	assertPinRun(t, again, scanWant{code: exitOK, stdout: []string{"accepted srv: 0 new, 1 changed, 0 removed\n"}, stderr: []string{noExpectNote}})
	if again.stderr != noExpectNote {
		t.Errorf("second accept: stderr = %q, want only the note %q", again.stderr, noExpectNote)
	}

	// A removed pins file is new again.
	if err := os.Remove(e.pinsPath()); err != nil {
		t.Fatal(err)
	}
	lost := e.pin(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}}), "--accept", "srv")

	assertPinRun(t, lost, scanWant{code: exitOK, stdout: []string{"accepted srv: 1 new, 0 changed, 0 removed\n"}, stderr: []string{notice}})
	if want := noExpectNote + notice; lost.stderr != want {
		t.Errorf("accept after the file was removed: stderr = %q, want exactly %q", lost.stderr, want)
	}
}

// TestPinAcceptLockHeld checks "pin --accept" while another run holds the lock
// on the pins directory: exit code 2, the read error and the locked line on
// stderr, no "accepted" line, and pins.json as it was. The diff still shows,
// because pin takes the lock only after it printed the diff. When the other
// run releases the lock, the same command works. A cli built in a test waits
// zero time for the lock (cli.pinsLockWait), so the run fails at once.
func TestPinAcceptLockHeld(t *testing.T) {
	t.Parallel()

	current := []inspect.Tool{mkTool("a", "Add. Changed.")}

	tests := []struct {
		name string
		// pinned is true when a scan pins srv first, so pins.json exists.
		pinned bool
		// wantDiffs are the diffs that pin prints before it asks for the lock
		// (see assertDiffsOf).
		wantDiffs []string
		// wantAccepted is the "accepted" line after the release.
		wantAccepted string
	}{
		{
			name:         "pinned server",
			pinned:       true,
			wantDiffs:    []string{"a"},
			wantAccepted: "accepted srv: 0 new, 1 changed, 0 removed\n",
		},
		{
			name:         "no pins file yet",
			wantDiffs:    []string{"+a"},
			wantAccepted: "accepted srv: 1 new, 0 changed, 0 removed\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			if tt.pinned {
				firstScan(t, e, mkTool("a", "Add."))
			}
			var before []byte
			if tt.pinned {
				before = readFileBytes(t, e.pinsPath())
			}
			release := holdPinsLock(t, e.pinsPath())

			got := e.pin(fakeServers(map[string][]inspect.Tool{"srv": current}), "--accept", "srv")

			assertPinRun(t, got, scanWant{code: exitError, stderr: []string{pinsReadErrPrefix, pinsLockedLine}})
			// The note comes before the lock, then the read error, then the
			// locked line as the last line.
			if !strings.HasPrefix(got.stderr, noExpectNote+pinsReadErrPrefix) || !strings.HasSuffix(got.stderr, pinsLockedLine) {
				t.Errorf("stderr = %q, want the note, the read error, then %q", got.stderr, pinsLockedLine)
			}
			if n := len(nonEmptyLines(got.stderr)); n != 3 {
				t.Errorf("stderr has %d lines, want 3\n%s", n, got.stderr)
			}
			assertContainsNone(t, "stderr", got.stderr, []string{"no pins file was found"})
			assertContainsNone(t, "stdout", got.stdout, []string{"accepted"})
			assertDiffsOf(t, got.stdout, "srv", tt.wantDiffs)
			if tt.pinned {
				if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(before, after) {
					t.Errorf("pins.json changed while another run held the lock\nbefore: %s\nafter:  %s", before, after)
				}
			} else {
				e.assertNoPinsFile(t, "a pin that found the lock held")
			}

			release()
			again := e.pin(fakeServers(map[string][]inspect.Tool{"srv": current}), "--accept", "srv")

			assertPinRun(t, again, scanWant{code: exitOK, stdout: []string{tt.wantAccepted}, stderr: []string{noExpectNote}})
			wantStderr := noExpectNote
			if !tt.pinned {
				wantStderr += newPinsFileNotice("pin", e.pinsPath())
			}
			if again.stderr != wantStderr {
				t.Errorf("after the release: stderr = %q, want exactly %q", again.stderr, wantStderr)
			}
			if next := e.scan(fakeServers(map[string][]inspect.Tool{"srv": current})); next.code != exitOK {
				t.Errorf("scan after the accept: exit code = %d, want %d\nstdout:\n%s", next.code, exitOK, next.stdout)
			}
		})
	}
}

// fileDigest returns the SHA-256 of the file at path. A test compares two
// digests to check that a large file did not change, without two copies of
// the file in memory.
func fileDigest(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: path is under the test's own t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// TestPinAcceptStoreFull checks "pin --accept" for a new server that does not
// fit in a pins file near its 32 MiB limit (writeNearFullPins, with the tool
// of bigStoreTool): exit code 2, the "pins file is full" line with the
// escaped server name, no "accepted" line, and pins.json unchanged. A small
// server still fits in the same file and is accepted.
//
// It does not call t.Parallel: the file is almost 32 MiB, and the runs read it
// several times, so it runs alone to keep the memory of the test binary low.
func TestPinAcceptStoreFull(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a near-32 MiB pins file; slow under -race")
	}
	// The name holds an escape, so the test also checks that the line escapes
	// the name of the server, which comes from a config file.
	const big = "big\x1b[31m"
	e := newPinEnv(t, map[string]any{
		big:    map[string]any{"command": "npx"},
		"tiny": map[string]any{"command": "npx"},
	})
	writeNearFullPins(t, e.pinsPath())
	assertPinsFileMode(t, e.pinsPath())
	if mode := modeOf(t, filepath.Dir(e.pinsPath())); mode != 0o700 {
		t.Errorf("pins folder mode = %o, want 700", mode)
	}
	before := fileDigest(t, e.pinsPath())
	fake := fakeServers(map[string][]inspect.Tool{big: {bigStoreTool()}, "tiny": {mkTool("t", "Tiny.")}})

	got := e.pin(fake, "--accept", big)

	const full = `mcpmoat pin: cannot pin "big\x1b[31m": the pins file is full (32 MiB); remove servers you no longer use from pins.json` + "\n"
	assertPinRun(t, got, scanWant{code: exitError, stderr: []string{full}})
	if !strings.HasSuffix(got.stderr, full) {
		t.Errorf("stderr = %q, want it to end with %q", got.stderr, full)
	}
	assertTerminalSafe(t, got.stderr)
	assertContainsNone(t, "stdout", got.stdout, []string{"accepted"})
	assertContainsNone(t, "stderr", got.stderr, []string{"no pins file was found", "cannot save"})
	if after := fileDigest(t, e.pinsPath()); after != before {
		t.Errorf("pins.json changed after a refused accept, want it byte for byte the same")
	}

	// The control: a small server fits in the space that is left.
	small := e.pin(fake, "--accept", "tiny")

	assertPinRun(t, small, scanWant{code: exitOK, stdout: []string{"accepted tiny: 1 new, 0 changed, 0 removed\n"}, stderr: []string{noExpectNote}})
	if small.stderr != noExpectNote {
		t.Errorf("small accept: stderr = %q, want only the note %q", small.stderr, noExpectNote)
	}
	// bigPinsServerNames scans the bytes: a JSON decode of 32 MiB is slow
	// with -race. The list has no entry for big.
	wantNames := append(fillerNames(), "tiny")
	if names := bigPinsServerNames(t, e.pinsPath()); !slices.Equal(names, wantNames) {
		t.Errorf("pinned servers = %q, want %q (the fillers and tiny, not big)", names, wantNames)
	}
}

// hookWriter runs hook once, before its first Write, and then writes to w. As
// the stdout of pin, it runs hook after pin read pins.json for the diff and
// before pin reads it again with the lock.
type hookWriter struct {
	w    io.Writer
	once sync.Once
	hook func()
}

func (h *hookWriter) Write(p []byte) (int, error) {
	h.once.Do(h.hook)
	return h.w.Write(p)
}

// TestPinAcceptPinsChangedDuringDiff checks the window between the read of
// pins.json for the diff and the read with the lock. Another run that writes
// the entry of the accepted server there gives a warning, and the "accepted"
// line counts against the entry that the save replaces (the locked read), not
// against the diff. Another run that writes the entry of another server gives
// no warning. In every case the save holds the tools that pin saw.
//
// The other run is simulated by the stdout of pin: a hookWriter writes the
// pins file when pin prints the first byte of the diff.
func TestPinAcceptPinsChangedDuringDiff(t *testing.T) {
	t.Parallel()

	current := []inspect.Tool{mkTool("a", "Add. Changed.")}

	tests := []struct {
		name string
		// pinned are the tools that a scan pins first. nil means no scan.
		pinned []inspect.Tool
		// otherServer makes the other run write the server "late" and not srv.
		otherServer bool
		// aside are the tools that the other run writes.
		aside []inspect.Tool
		// wantDiffs are the diffs that pin prints: against the first read.
		wantDiffs []string
		// wantWarning is true when pin must warn that the pins changed.
		wantWarning bool
		// wantAccepted is the "accepted" line: against the locked read.
		wantAccepted string
	}{
		{
			name:         "another run accepted the same tools",
			pinned:       []inspect.Tool{mkTool("a", "Add.")},
			aside:        current,
			wantDiffs:    []string{"a"},
			wantWarning:  true,
			wantAccepted: "accepted srv: 0 new, 0 changed, 0 removed\n",
		},
		{
			name:         "another run pinned other tools",
			pinned:       []inspect.Tool{mkTool("a", "Add.")},
			aside:        []inspect.Tool{mkTool("a", "Add. Other."), mkTool("b", "Extra.")},
			wantDiffs:    []string{"a"},
			wantWarning:  true,
			wantAccepted: "accepted srv: 0 new, 1 changed, 1 removed\n",
		},
		{
			name:         "another run pinned the server that was not pinned",
			aside:        current,
			wantDiffs:    []string{"+a"},
			wantWarning:  true,
			wantAccepted: "accepted srv: 0 new, 0 changed, 0 removed\n",
		},
		{
			name:         "another run pinned another server",
			pinned:       []inspect.Tool{mkTool("a", "Add.")},
			otherServer:  true,
			aside:        []inspect.Tool{mkTool("l", "Late.")},
			wantDiffs:    []string{"a"},
			wantAccepted: "accepted srv: 0 new, 1 changed, 0 removed\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			if tt.pinned != nil {
				firstScan(t, e, tt.pinned...)
			}
			// The inspector hook records the server, so the stdout hook can
			// build its identity. inspect.Run returns only after the hook ran,
			// and pin writes stdout only after that.
			var srv discover.Server
			insp := hookInspector{
				inner: fakeServers(map[string][]inspect.Tool{"srv": current}),
				hook:  onceFor("srv", func(s discover.Server) { srv = s }),
			}
			c, stdout, stderr := e.cli(insp)
			c.stdout = &hookWriter{w: stdout, hook: func() {
				id := serverIdentity(srv)
				if tt.otherServer {
					id.Name = "late"
				}
				writePinsAside(t, e.pinsPath(), id, tt.aside...)
			}}

			code := c.dispatch([]string{"pin", "--config", e.config, "--accept", "srv"})

			got := pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
			assertPinRun(t, got, scanWant{code: exitOK, stderr: []string{noExpectNote}})
			// The other run created pins.json before the locked read, so pin
			// prints no new pins file notice, also for a server that was not
			// pinned.
			wantStderr := noExpectNote
			if tt.wantWarning {
				wantStderr += pinsChangedWarning("srv")
			}
			if got.stderr != wantStderr {
				t.Errorf("stderr = %q, want exactly %q", got.stderr, wantStderr)
			}
			diffs, accepted := splitAcceptedLine(got.stdout)
			if accepted != tt.wantAccepted {
				t.Errorf("accepted line = %q, want %q\nstdout:\n%s", accepted, tt.wantAccepted, got.stdout)
			}
			assertDiffsOf(t, diffs, "srv", tt.wantDiffs)
			// The save holds the tools that pin saw: the next scan is clean.
			if next := e.scan(fakeServers(map[string][]inspect.Tool{"srv": current})); next.code != exitOK {
				t.Errorf("scan after the accept: exit code = %d, want %d\nstdout:\n%s", next.code, exitOK, next.stdout)
			}
			if tt.otherServer {
				if _, ok := e.readPins().tools("late"); !ok {
					t.Error("pins.json lost the entry that the other run wrote for late")
				}
			}
		})
	}
}

// TestPinAcceptReleasesLockBeforeOutput checks that "pin --accept" releases the
// lock on the pins directory right after the save, before it prints the new
// pins file notice and the "accepted" line. A slow or blocked reader of
// stdout or stderr must not keep other runs from the pins file. The stdout
// and the stderr of pin are lockProbeWriters: each write of one of those
// lines tries the lock as another run would, and the lock must be free.
func TestPinAcceptReleasesLockBeforeOutput(t *testing.T) {
	t.Parallel()

	current := []inspect.Tool{mkTool("a", "Add. Changed.")}

	tests := []struct {
		name string
		// pinned is true when a scan pins srv first, so pins.json exists and
		// pin prints no new pins file notice.
		pinned bool
		// wantStderrProbes are the stderr lines at which the lock is tried.
		wantStderrProbes []string
		wantAccepted     string
	}{
		{
			name:             "no pins file yet",
			wantStderrProbes: []string{"no pins file was found"},
			wantAccepted:     "accepted srv: 1 new, 0 changed, 0 removed\n",
		},
		{
			name:         "pinned server",
			pinned:       true,
			wantAccepted: "accepted srv: 0 new, 1 changed, 0 removed\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			if tt.pinned {
				firstScan(t, e, mkTool("a", "Add."))
			}
			c, stdout, stderr := e.cli(fakeServers(map[string][]inspect.Tool{"srv": current}))
			outProbe := newLockProbeWriter(t, stdout, e.pinsPath(), "accepted srv:")
			errProbe := newLockProbeWriter(t, stderr, e.pinsPath(), "no pins file was found")
			c.stdout, c.stderr = outProbe, errProbe

			code := c.dispatch([]string{"pin", "--config", e.config, "--accept", "srv"})

			got := pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
			assertPinRun(t, got, scanWant{code: exitOK, stdout: []string{tt.wantAccepted}, stderr: []string{noExpectNote}})
			assertLockFreeAt(t, outProbe, "accepted srv:")
			assertLockFreeAt(t, errProbe, tt.wantStderrProbes...)
			// The probes left the file as the save wrote it.
			if pinned, ok := e.readPins().tools("srv"); !ok || len(pinned) != 1 {
				t.Errorf("pins.json has %d tools for srv (found %v), want 1", len(pinned), ok)
			}
		})
	}
}

// TestPinAcceptPinsRemovedDuringDiff checks a pins.json that was on disk at the
// read for the diff but is gone at the read with the lock: another process
// removed it while pin showed the diff. A save would write a new file with only
// srv and drop every older pin, so pin saves nothing: exit code 2, the note
// and then pinsRemovedText on stderr, no "accepted" line, no new pins file
// notice, and no pins.json. A hookWriter on stdout removes the file when pin
// prints the first byte of the diff.
//
// The control, a real first run with no file at both reads, is
// TestPinAcceptNewPinsFileNotice: it saves and prints the notice.
func TestPinAcceptPinsRemovedDuringDiff(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	firstScan(t, e, mkTool("a", "Add."))
	c, stdout, stderr := e.cli(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add. Changed.")}}))
	c.stdout = &hookWriter{w: stdout, hook: func() {
		if err := os.Remove(e.pinsPath()); err != nil {
			t.Errorf("remove pins.json while pin shows the diff: %v", err)
		}
	}}

	code := c.dispatch([]string{"pin", "--config", e.config, "--accept", "srv"})

	got := pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
	removed := pinPrefix + pinsRemovedText + "\n"
	assertPinRun(t, got, scanWant{code: exitError, stderr: []string{removed}})
	if want := noExpectNote + removed; got.stderr != want {
		t.Errorf("stderr = %q, want exactly %q", got.stderr, want)
	}
	assertContainsNone(t, "stdout", got.stdout, []string{"accepted"})
	assertContainsNone(t, "stderr", got.stderr, []string{"no pins file was found"})
	// The diff printed before the removal, against the pins of the first read.
	assertDiffsOf(t, got.stdout, "srv", []string{"a"})
	e.assertNoPinsFile(t, "a pin whose pins file was removed while it ran")
}

// TestPinAcceptPinsRemovedDuringInspection checks a pins.json that was on disk
// at the first read of pin but is gone when pin reads it again for the diff:
// another process removed it while pin inspected the server. srv and other
// are pinned. A save would write a new file with only srv and drop the pins of
// other, and the diff would show every tool of srv as new. So pin stops before
// the diff: exit code 2, exactly the pinsRemovedText line on stderr, nothing on
// stdout (no diff and no "accepted" line), no new pins file notice, and no
// pins.json. The removal runs in the inspector (hookInspector), like in
// TestScanPinsFileRemovedDuringScan.
//
// The control runs the same flow without the removal: pin saves, and pins.json
// keeps other. The real first run, with no file at every read, is
// TestPinAcceptNewPinsFileNotice.
func TestPinAcceptPinsRemovedDuringInspection(t *testing.T) {
	t.Parallel()

	servers := map[string]any{
		"srv":   map[string]any{"command": "npx"},
		"other": map[string]any{"command": "npx"},
	}
	pinned := map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}, "other": {mkTool("o", "Other.")}}
	current := map[string][]inspect.Tool{"srv": {mkTool("a", "Add. Changed.")}, "other": {mkTool("o", "Other.")}}

	tests := []struct {
		name string
		// remove is true when the inspector removes pins.json while it
		// inspects srv.
		remove bool
	}{
		{name: "removed while the server is inspected", remove: true},
		{name: "control: not removed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, servers)
			if r := e.scan(fakeServers(pinned)); r.code != exitOK {
				t.Fatalf("first scan: exit code = %d, stderr:\n%s", r.code, r.stderr)
			}
			if names := e.readPins().serverNames(); !slices.Equal(names, []string{"other", "srv"}) {
				t.Fatalf("pinned servers before pin = %v, want [other srv]", names)
			}
			insp := hookInspector{
				inner: fakeServers(current),
				hook: onceFor("srv", func(discover.Server) {
					if !tt.remove {
						return
					}
					// t.Errorf, not t.Fatalf: this runs in a goroutine of
					// inspect.Run.
					if err := os.Remove(e.pinsPath()); err != nil {
						t.Errorf("remove pins.json while pin inspects: %v", err)
					}
				}),
			}

			got := e.pin(insp, "--accept", "srv")

			if !tt.remove {
				assertPinRun(t, got, scanWant{code: exitOK, stdout: []string{"accepted srv: 0 new, 1 changed, 0 removed\n"}, stderr: []string{noExpectNote}})
				if got.stderr != noExpectNote {
					t.Errorf("stderr = %q, want only the note %q", got.stderr, noExpectNote)
				}
				diffs, _ := splitAcceptedLine(got.stdout)
				assertDiffsOf(t, diffs, "srv", []string{"a"})
				if names := e.readPins().serverNames(); !slices.Equal(names, []string{"other", "srv"}) {
					t.Errorf("pinned servers after pin = %v, want [other srv]", names)
				}
				return
			}
			removed := pinPrefix + pinsRemovedText + "\n"
			assertPinRun(t, got, scanWant{code: exitError, stderr: []string{removed}})
			if got.stderr != removed {
				t.Errorf("stderr = %q, want exactly %q", got.stderr, removed)
			}
			if got.stdout != "" {
				t.Errorf("stdout = %q, want nothing: no diff and no accepted line", got.stdout)
			}
			e.assertNoPinsFile(t, "a pin whose pins file was removed while it inspected the server")
		})
	}
}
