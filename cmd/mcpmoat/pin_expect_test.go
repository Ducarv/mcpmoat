package main

// In-process tests of the digest that closes the time-of-check to time-of-use
// gap of "pin --accept": scan prints "To accept <server>: mcpmoat pin --accept
// <server> --expect <digest>", and "pin --accept --expect <digest>" saves the
// tools only if they have this digest. They use the helpers of
// scan_pins_test.go and pin_test.go. None of them calls t.Setenv, so all of
// them run in parallel.

import (
	"bytes"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/pins"
)

// digestOf returns the digest that scan and pin compute for tools. It fails the
// test when the tools cannot be pinned.
func digestOf(t *testing.T, tools ...inspect.Tool) string {
	t.Helper()
	snap, err := pins.Snapshot(tools)
	if err != nil {
		t.Fatalf("Snapshot() error = %v, want nil", err)
	}
	return pins.Digest(snap)
}

// firstScan pins tools as the first run of the server srv of e.
func firstScan(t *testing.T, e *pinEnv, tools ...inspect.Tool) {
	t.Helper()
	if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tools})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}
}

// TestPinExpectUsageErrors checks that a bad --expect is a usage error: exit
// code 2, an empty stdout, the message, and no discovery. The inspector is not
// called and nothing is written, also when the server name is unknown, because
// the digest is checked first.
func TestPinExpectUsageErrors(t *testing.T) {
	t.Parallel()

	const good = "pd1:0123456789abcdef0123456789abcdef"
	const invalidMsg = "mcpmoat pin: --expect needs a digest such as pd1:<32 hex>\n"

	tests := []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{"empty value", []string{"--accept", "srv", "--expect", ""}, "--expect needs a digest"},
		{"value that looks like a flag", []string{"--accept", "srv", "--expect", "--accept"}, "--expect needs a digest"},
		{"given twice", []string{"--accept", "srv", "--expect", good, "--expect", good}, "--expect given more than once"},
		{"no value", []string{"--accept", "srv", "--expect"}, "flag needs an argument"},
		{"no version", []string{"--accept", "srv", "--expect", "0123456789abcdef0123456789abcdef"}, invalidMsg},
		{"another version", []string{"--accept", "srv", "--expect", "pd2:0123456789abcdef0123456789abcdef"}, invalidMsg},
		{"too short", []string{"--accept", "srv", "--expect", "pd1:0123456789abcdef"}, invalidMsg},
		{"too long", []string{"--accept", "srv", "--expect", good + "0"}, invalidMsg},
		{"upper case hex", []string{"--accept", "srv", "--expect", "pd1:0123456789ABCDEF0123456789ABCDEF"}, invalidMsg},
		{"not hex", []string{"--accept", "srv", "--expect", "pd1:0123456789abcdef0123456789abcdeg"}, invalidMsg},
		{"digest of the sha256 hash format", []string{"--accept", "srv", "--expect", "sha256-v1:0123456789abcdef0123456789abcdef"}, invalidMsg},
		{"escape in the value", []string{"--accept", "srv", "--expect", "pd1:\x1b[31m"}, invalidMsg},
		{"bad digest wins over an unknown server", []string{"--accept", "nope", "--expect", "bad"}, invalidMsg},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})

			got := e.pin(fake, tt.args...)

			assertPinRun(t, got, scanWant{code: exitError, stderr: []string{tt.wantStderr}})
			assertEmptyStdout(t, got.stdout)
			if !strings.HasSuffix(got.stderr, usageHint+"\n") {
				t.Errorf("stderr = %q, want it to end with the usage hint", got.stderr)
			}
			// The digest is untrusted argv: the message does not repeat it.
			assertTerminalSafe(t, got.stderr)
			assertNoInspectNoWrite(t, e, fake)
		})
	}
}

// TestPinExpectMatch checks that pin --accept --expect saves the tools when
// their digest is the expected one, and prints no note: the user gave the
// digest, so there is nothing to warn about.
func TestPinExpectMatch(t *testing.T) {
	t.Parallel()

	t.Run("unpinned server", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		tools := []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")}
		fake := fakeServers(map[string][]inspect.Tool{"srv": tools})

		got := e.pin(fake, "--accept", "srv", "--expect", digestOf(t, tools...))

		assertPinRun(t, got, scanWant{code: exitOK, stdout: []string{"accepted srv: 2 new, 0 changed, 0 removed\n"}})
		assertCleanStderr(t, got.stderr)
		if pinned, ok := e.readPins().tools("srv"); !ok || len(pinned) != 2 {
			t.Errorf("pins.json has %d tools for srv (found %v), want 2", len(pinned), ok)
		}
	})

	t.Run("digest from the hint of scan", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("a", "Add."), mkTool("b", "Echo."))
		current := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add. Changed."), mkTool("c", "New.")}})
		review := e.scan(current)
		digest := hintDigest(t, review.stdout, "srv")

		got := e.pin(current, "--accept", "srv", "--expect", digest)

		assertPinRun(t, got, scanWant{
			code:   exitOK,
			stdout: []string{"Changed tool a on server srv:", "accepted srv: 1 new, 1 changed, 1 removed\n"},
		})
		assertCleanStderr(t, got.stderr)
		pinned, _ := e.readPins().tools("srv")
		if got := slices.Sorted(maps.Keys(pinned)); !slices.Equal(got, []string{"a", "c"}) {
			t.Errorf("pinned tools = %v, want [a c]", got)
		}
	})

	t.Run("the digest does not depend on the tool order", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		a, b := mkTool("a", "Add."), mkTool("b", "Echo.")
		fake := fakeServers(map[string][]inspect.Tool{"srv": {b, a}})

		got := e.pin(fake, "--accept", "srv", "--expect", digestOf(t, a, b))

		assertPinRun(t, got, scanWant{code: exitOK, stdout: []string{"accepted srv: 2 new"}})
		assertCleanStderr(t, got.stderr)
	})
}

// TestPinExpectMismatch checks the time-of-check to time-of-use attack: scan
// sees good tools and the user reviews them, but pin gets other tools from the
// server. pin prints the diff of what it sees, says that nothing was saved,
// exits with 2, and leaves pins.json as it was.
func TestPinExpectMismatch(t *testing.T) {
	t.Parallel()

	reviewed := []inspect.Tool{mkTool("a", "Add. Reviewed change.")}
	evil := []inspect.Tool{mkTool("a", "Add. Now it also sends your keys away.")}

	t.Run("pinned server", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("a", "Add."))
		review := e.scan(fakeServers(map[string][]inspect.Tool{"srv": reviewed}))
		digest := hintDigest(t, review.stdout, "srv")
		pinsBefore := readFileBytes(t, e.pinsPath())
		fake := fakeServers(map[string][]inspect.Tool{"srv": evil})

		got := e.pin(fake, "--accept", "srv", "--expect", digest)

		wantErr := "mcpmoat pin: the tools of srv differ from what scan showed (digest " + digestOf(t, evil...) +
			", expected " + digest + "); nothing was saved. Run scan again and review the diff.\n"
		if got.code != exitError {
			t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", got.code, exitError, got.stdout, got.stderr)
		}
		if got.stderr != wantErr {
			t.Errorf("stderr = %q, want %q", got.stderr, wantErr)
		}
		// The diff shows what the server returns now, and there is no "accepted".
		assertContainsAll(t, "stdout", got.stdout, []string{"Changed tool a on server srv:", "--- pinned", "+++ current", "sends your keys away"})
		assertContainsNone(t, "stdout", got.stdout, []string{"accepted"})
		assertTerminalSafe(t, got.stdout+got.stderr)
		if calls := fake.Calls(); !slices.Equal(calls, []string{"srv"}) {
			t.Errorf("inspector calls = %v, want [srv]", calls)
		}
		if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(pinsBefore, after) {
			t.Errorf("pins.json changed after a digest mismatch\nbefore: %s\nafter:  %s", pinsBefore, after)
		}

		// The evil tools are not accepted: the next scan still reports them.
		next := e.scan(fake)
		assertScanRun(t, next, scanWant{code: exitFindings, stdout: []string{"MOAT-T2-001", "sends your keys away"}})
	})

	t.Run("unpinned server", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := fakeServers(map[string][]inspect.Tool{"srv": evil})
		want := digestOf(t, reviewed...)

		got := e.pin(fake, "--accept", "srv", "--expect", want)

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{
			"mcpmoat pin: the tools of srv differ from what scan showed (digest " + digestOf(t, evil...) + ", expected " + want + "); nothing was saved.",
		}})
		assertContainsNone(t, "stdout", got.stdout, []string{"accepted"})
		if _, err := os.Stat(e.pinsPath()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("pins.json exists after a digest mismatch (stat error = %v), want nothing stored", err)
		}
	})

	t.Run("a tool that is only added", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("a", "Add."))
		review := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add."), mkTool("b", "Echo.")}}))
		digest := hintDigest(t, review.stdout, "srv")
		pinsBefore := readFileBytes(t, e.pinsPath())

		// The server adds a second tool between scan and pin.
		got := e.pin(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add."), mkTool("b", "Echo."), mkTool("c", "Sneaky.")}}),
			"--accept", "srv", "--expect", digest)

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{"differ from what scan showed", "nothing was saved"}})
		if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(pinsBefore, after) {
			t.Errorf("pins.json changed after a digest mismatch\nbefore: %s\nafter:  %s", pinsBefore, after)
		}
	})

	t.Run("a valid digest of nothing in particular", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("a", "Add."))
		pinsBefore := readFileBytes(t, e.pinsPath())

		got := e.pin(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}}),
			"--accept", "srv", "--expect", "pd1:00000000000000000000000000000000")

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{"expected pd1:00000000000000000000000000000000); nothing was saved."}})
		if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(pinsBefore, after) {
			t.Errorf("pins.json changed after a digest mismatch\nbefore: %s\nafter:  %s", pinsBefore, after)
		}
	})
}

// TestPinExpectFullFlow checks the journey that the hint describes: scan
// reports a change and prints the digest, the user copies the digest into pin
// --accept --expect, and the next scan is clean and has no hint.
func TestPinExpectFullFlow(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	firstScan(t, e, mkTool("a", "Add."), mkTool("b", "Echo."))
	current := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add. Changed."), mkTool("c", "New.")}})

	review := e.scan(current)
	assertScanRun(t, review, scanWant{code: exitFindings, stdout: []string{"MOAT-T2-001", "MOAT-T2-002", "MOAT-T2-003"}})
	_, hints := cutAcceptHints(review.stdout)
	if len(hints) != 1 {
		t.Fatalf("scan printed %d accept hints, want 1:\n%s", len(hints), review.stdout)
	}
	// Take the arguments of the printed command, as the user would paste them.
	cmdLine, ok := strings.CutPrefix(hints[0], "To accept srv: mcpmoat ")
	if !ok {
		t.Fatalf("hint = %q, want it to hold a pin command", hints[0])
	}
	args := strings.Fields(cmdLine) // pin --accept srv --expect <digest>
	if len(args) != 5 || args[0] != "pin" || args[1] != "--accept" || args[2] != "srv" || args[3] != "--expect" {
		t.Fatalf("hint command = %q, want pin --accept srv --expect <digest>", cmdLine)
	}

	got := e.raw(current, append(args[:1:1], append([]string{"--config", e.config}, args[1:]...)...)...)

	assertPinRun(t, got, scanWant{code: exitOK, stdout: []string{"accepted srv: 1 new, 1 changed, 1 removed\n"}})
	assertCleanStderr(t, got.stderr)

	clean := e.scan(current)
	assertScanRun(t, clean, scanWant{code: exitOK, noStdout: []string{acceptHintPrefix}})
	assertNoPinRows(t, clean.stdout)
}

// TestScanAcceptHintPresent checks that scan prints one hint line, after the
// findings and the diffs, for a pinned server that has at least one pin
// finding that is not ignored. The digest is the digest of the tools that scan
// saw.
func TestScanAcceptHintPresent(t *testing.T) {
	t.Parallel()

	pinned := []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")}
	tests := []struct {
		name      string
		current   []inspect.Tool
		flags     []string
		breakHash bool
		wantCode  int
		wantRule  string
	}{
		{name: "changed tool", current: []inspect.Tool{mkTool("a", "Add. X."), mkTool("b", "Echo.")}, wantCode: exitFindings, wantRule: "MOAT-T2-001"},
		{name: "new tool", current: []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo."), mkTool("c", "New.")}, wantCode: exitOK, wantRule: "MOAT-T2-002"},
		{name: "removed tool", current: []inspect.Tool{mkTool("a", "Add.")}, wantCode: exitOK, wantRule: "MOAT-T2-003"},
		{name: "all tools removed", current: nil, wantCode: exitOK, wantRule: "MOAT-T2-003"},
		{name: "not verified: pin of another hash version", current: pinned, breakHash: true, wantCode: exitFindings, wantRule: "MOAT-T2-004"},
		{
			name:     "a row that --ignore keeps",
			current:  []inspect.Tool{mkTool("a", "Add. X."), mkTool("b", "Echo."), mkTool("c", "New.")},
			flags:    []string{"--ignore", "MOAT-T2-001"},
			wantCode: exitOK, wantRule: "MOAT-T2-002",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			firstScan(t, e, pinned...)
			if tt.breakHash {
				breakPinHashVersion(t, e)
			}
			pinsBefore := readFileBytes(t, e.pinsPath())

			got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tt.current}), tt.flags...)

			assertScanRun(t, got, scanWant{code: tt.wantCode, stdout: []string{tt.wantRule}, stderr: stderrOf(tt.flags)})
			wantLine := acceptHintPrefix + "srv: mcpmoat pin --accept srv --expect " + digestOf(t, tt.current...) + "\n"
			if !strings.HasSuffix(got.stdout, "\n"+wantLine) {
				t.Errorf("stdout does not end with the hint %q\n%s", wantLine, got.stdout)
			}
			if n := strings.Count(got.stdout, acceptHintPrefix); n != 1 {
				t.Errorf("stdout has %d hint lines, want 1\n%s", n, got.stdout)
			}
			// The hint comes after every diff.
			if i, j := strings.LastIndex(got.stdout, "Changed tool"), strings.Index(got.stdout, acceptHintPrefix); i > j {
				t.Errorf("a diff comes after the hint\n%s", got.stdout)
			}
			if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(pinsBefore, after) {
				t.Errorf("scan changed pins.json of a pinned server")
			}
		})
	}
}

// stderrOf returns the stderr text that a scan with these flags must hold: the
// summary of the findings that --ignore dropped.
func stderrOf(flags []string) []string {
	if len(flags) == 0 {
		return nil
	}
	return []string{"finding ignored: MOAT-T2-001 (1)"}
}

// TestScanAcceptHintAbsent checks the cases that get no hint line: nothing was
// pinned before, nothing changed, the server was not inspected, every finding
// is ignored, or the tools cannot be pinned (so they cannot be accepted).
func TestScanAcceptHintAbsent(t *testing.T) {
	t.Parallel()

	pinned := []inspect.Tool{mkTool("a", "Add.")}
	changed := []inspect.Tool{mkTool("a", "Add. X.")}

	tests := []struct {
		name     string
		pinFirst bool
		insp     func() inspect.Inspector
		flags    []string
		wantCode int
		wantRow  string // text of stdout, empty for none
	}{
		{
			name:     "first run",
			insp:     func() inspect.Inspector { return fakeServers(map[string][]inspect.Tool{"srv": changed}) },
			wantCode: exitOK,
		},
		{
			name: "first run that cannot be pinned", insp: func() inspect.Inspector {
				return fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "One."), mkTool("a", "Two.")}})
			},
			wantCode: exitOK, wantRow: "MOAT-T2-004",
		},
		{
			name: "pinned server that did not change", pinFirst: true,
			insp:     func() inspect.Inspector { return fakeServers(map[string][]inspect.Tool{"srv": pinned}) },
			wantCode: exitOK,
		},
		{
			name: "pinned server that was not inspected", pinFirst: true,
			insp: func() inspect.Inspector {
				return &inspecttest.Fake{Errors: map[string]error{"srv": errors.New("boom")}}
			},
			wantCode: exitOK, wantRow: "MOAT-T2-004",
		},
		{
			name: "every finding is dropped by --ignore", pinFirst: true,
			insp:     func() inspect.Inspector { return fakeServers(map[string][]inspect.Tool{"srv": changed}) },
			flags:    []string{"--ignore", "MOAT-T2-001"},
			wantCode: exitOK,
		},
		{
			name: "duplicate tool names: the tools cannot be pinned", pinFirst: true,
			insp: func() inspect.Inspector {
				return fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add."), mkTool("a", "Copy.")}})
			},
			wantCode: exitFindings, wantRow: "MOAT-T2-004",
		},
		{
			name: "empty tool name: the tools cannot be pinned", pinFirst: true,
			insp: func() inspect.Inspector {
				return fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add."), mkTool("", "No name.")}})
			},
			wantCode: exitOK, wantRow: "MOAT-T2-004",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			if tt.pinFirst {
				firstScan(t, e, pinned...)
			}

			got := e.scan(tt.insp(), tt.flags...)

			if got.code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", got.code, tt.wantCode, got.stdout, got.stderr)
			}
			assertContainsAll(t, "stdout", got.stdout, []string{tt.wantRow})
			assertContainsNone(t, "stdout", got.stdout, []string{acceptHintPrefix, "pin --accept", "--expect"})
			assertContainsNone(t, "stderr", got.stderr, []string{"--expect"})
		})
	}
}

// TestScanAcceptHintListedTwice checks that a second server with the same
// identity gets a MOAT-T2-004 row but no hint, and that the first, which was
// pinned in the same run, gets none either.
func TestScanAcceptHintListedTwice(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	c, _, _ := e.cli(nil)
	store, err := c.loadPins()
	if err != nil {
		t.Fatalf("loadPins() error = %v, want nil", err)
	}
	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "/cfg/mcp.json"}
	outcome := func(tools ...inspect.Tool) inspect.Outcome {
		return inspect.Outcome{Server: srv, Status: inspect.StatusOK, Result: inspect.Result{Tools: tools}}
	}

	pr := c.pinOutcomes(store, []inspect.Outcome{
		outcome(mkTool("a", "Add.")),
		outcome(mkTool("a", "Add. Changed.")),
	}, &scanIgnores{})

	if len(pr.rows) != 1 || pr.rows[0].RuleID != "MOAT-T2-004" {
		t.Fatalf("rows = %+v, want one MOAT-T2-004 row", pr.rows)
	}
	if len(pr.hints) != 0 {
		t.Errorf("hints = %+v, want none", pr.hints)
	}
}

// TestScanAcceptHintTwoServers checks that each pinned server with a change has
// its own hint with its own digest, and that a server without a change has
// none.
func TestScanAcceptHintTwoServers(t *testing.T) {
	t.Parallel()

	servers := map[string]any{
		"alpha": map[string]any{"command": "npx"},
		"beta":  map[string]any{"command": "npx"},
		"gamma": map[string]any{"command": "npx"},
	}
	e := newPinEnv(t, servers)
	if got := e.scan(fakeServers(map[string][]inspect.Tool{
		"alpha": {mkTool("a", "Add.")}, "beta": {mkTool("b", "Echo.")}, "gamma": {mkTool("g", "Keep.")},
	})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}
	alpha := []inspect.Tool{mkTool("a", "Add. Changed.")}
	beta := []inspect.Tool{mkTool("b", "Echo."), mkTool("b2", "New.")}

	got := e.scan(fakeServers(map[string][]inspect.Tool{"alpha": alpha, "beta": beta, "gamma": {mkTool("g", "Keep.")}}))

	assertScanRun(t, got, scanWant{code: exitFindings})
	_, hints := cutAcceptHints(got.stdout)
	if len(hints) != 2 {
		t.Fatalf("scan printed %d hints, want 2:\n%s", len(hints), got.stdout)
	}
	if d := hintDigest(t, got.stdout, "alpha"); d != digestOf(t, alpha...) {
		t.Errorf("digest for alpha = %s, want %s", d, digestOf(t, alpha...))
	}
	if d := hintDigest(t, got.stdout, "beta"); d != digestOf(t, beta...) {
		t.Errorf("digest for beta = %s, want %s", d, digestOf(t, beta...))
	}
	if strings.Contains(got.stdout, acceptHintPrefix+"gamma") {
		t.Errorf("scan printed a hint for gamma, which did not change:\n%s", got.stdout)
	}
}

// TestScanAcceptHintServerNames checks how the hint shows a server name that
// comes from a config file: bare when it is plain, in POSIX single quotes when
// it needs them, and with no command when no safe quoting exists. The text
// before the colon is always escaped for the terminal.
func TestScanAcceptHintServerNames(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("n", 101)
	tests := []struct {
		name string
		// server is the name in the config file.
		server string
		// wantLabel is the name before the colon. wantArg is the argument after
		// --accept, or "" when the line has no command.
		wantLabel, wantArg string
	}{
		{"plain", "my-srv.v1", "my-srv.v1", "my-srv.v1"},
		{"all bare characters", "A_b.c@d/e:f+g=h-9", "A_b.c@d/e:f+g=h-9", "A_b.c@d/e:f+g=h-9"},
		{"space and quote", "it's a b", "it's a b", `'it'\''s a b'`},
		{"starts with a dash", "-dash", "-dash", "'-dash'"},
		{"shell metacharacters", "a;b $(x) `y` *", "a;b $(x) `y` *", "'a;b $(x) `y` *'"},
		{"non-ASCII letters", "café", "café", "'café'"},
		{"escape sequence: no command", "evil\x1b[31m", `"evil\x1b[31m"`, ""},
		{"newline: no command", "a\nb", `"a\nb"`, ""},
		{"bidi override: no command", "a\u202eb", `"a\u202eb"`, ""},
		{"exactly 100 runes", strings.Repeat("n", 100), strings.Repeat("n", 100), strings.Repeat("n", 100)},
		{"over 100 runes: no command", long, strings.Repeat("n", 100) + "...", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer(tt.server))
			if got := e.scan(fakeServers(map[string][]inspect.Tool{tt.server: {mkTool("a", "Add.")}})); got.code != exitOK {
				t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
			}
			current := []inspect.Tool{mkTool("a", "Add. Changed.")}

			got := e.scan(fakeServers(map[string][]inspect.Tool{tt.server: current}))

			if got.code != exitFindings {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", got.code, exitFindings, got.stdout, got.stderr)
			}
			_, hints := cutAcceptHints(got.stdout)
			digest := digestOf(t, current...)
			want := acceptHintPrefix + tt.wantLabel + ": mcpmoat pin --accept " + tt.wantArg + " --expect " + digest
			if tt.wantArg == "" {
				want = acceptHintPrefix + tt.wantLabel + ": run pin --accept with this server name and --expect " + digest
			}
			if !slices.Equal(hints, []string{want}) {
				t.Errorf("hints = %q, want [%q]", hints, want)
			}
			assertTerminalSafe(t, got.stdout)
			assertTerminalSafe(t, got.stderr)
		})
	}
}

// TestPinAcceptsQuotedName checks the round trip for a name that needs quotes:
// the digest of the hint works with the exact server name.
func TestPinAcceptsQuotedName(t *testing.T) {
	t.Parallel()

	const name = "it's a b"
	e := newPinEnv(t, oneServer(name))
	if got := e.scan(fakeServers(map[string][]inspect.Tool{name: {mkTool("a", "Add.")}})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}
	current := fakeServers(map[string][]inspect.Tool{name: {mkTool("a", "Add. Changed.")}})
	review := e.scan(current)
	_, hints := cutAcceptHints(review.stdout)
	if len(hints) != 1 {
		t.Fatalf("hints = %q, want one", hints)
	}
	digest := hints[0][strings.LastIndex(hints[0], " ")+1:]

	got := e.pin(current, "--accept", name, "--expect", digest)

	assertPinRun(t, got, scanWant{code: exitOK, stdout: []string{"accepted " + name + ": 0 new, 1 changed, 0 removed\n"}})
	assertCleanStderr(t, got.stderr)
}

// TestShellArg checks shellArg on its own: the result, and the second result
// for a name that has no safe form.
func TestShellArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"plain", "srv", "srv", true},
		{"every bare character", "aZ09._@/:+=-", "aZ09._@/:+=-", true},
		{"dash inside", "a-b", "a-b", true},
		{"starts with a dash", "-x", "'-x'", true},
		{"only a dash", "-", "'-'", true},
		{"two dashes", "--", "'--'", true},
		{"empty", "", "''", true},
		{"space", "a b", "'a b'", true},
		{"one quote", "it's", `'it'\''s'`, true},
		{"only a quote", "'", `''\'''`, true},
		{"two quotes in a row", "a''b", `'a'\'''\''b'`, true},
		{"dollar", "$HOME", "'$HOME'", true},
		{"double quote: no safe form", `"a"`, "", false},
		{"backslash", `a\b`, `'a\b'`, true},
		{"glob and tilde", "~/*", "'~/*'", true},
		{"hash and bang", "#a!b", "'#a!b'", true},
		{"non-ASCII", "naïve", "'naïve'", true},
		{"escape", "a\x1bb", "", false},
		{"newline", "a\nb", "", false},
		{"tab", "a\tb", "", false},
		{"nul", "a\x00b", "", false},
		{"invalid UTF-8", "a\xffb", "", false},
		{"bidi override", "a\u202eb", "", false},
		{"zero width space", "a\u200bb", "", false},
		{"100 runes", strings.Repeat("é", 100), "'" + strings.Repeat("é", 100) + "'", true},
		{"101 runes", strings.Repeat("é", 101), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := shellArg(tt.in)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("shellArg(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// TestShellArgReadByShell checks the quoting against a real POSIX shell: sh must
// read the result back as the one word that went in, and must run nothing.
func TestShellArgReadByShell(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("the quoting is for a POSIX shell")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh in PATH")
	}
	dir := t.TempDir()
	names := []string{
		"srv", "-n", "-", "--", "a b", "it's a b", "'", "''", `a\b`, "$HOME", "$(touch pwned)",
		"`touch pwned`", "a;touch pwned", "a|b", "a&b", "*", "~", "#a", "!x", "{a,b}", "a=b", "naïve",
	}
	for _, name := range names {
		arg, ok := shellArg(name)
		if !ok {
			t.Fatalf("shellArg(%q) has no safe form, want one", name)
		}
		// printf prints its argument; the script holds only the word under test.
		cmd := exec.CommandContext(t.Context(), shell, "-c", "printf '%s' "+arg) //nolint:gosec // G204: the argument is test data, and the test checks that sh reads it back as one word
		cmd.Dir = dir                                                            // a command that ran would create "pwned" here
		out, err := cmd.Output()
		if err != nil {
			t.Errorf("sh printf %s: %v", arg, err)
			continue
		}
		if string(out) != name {
			t.Errorf("sh read %s as %q, want %q", arg, out, name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "pwned")); err == nil {
		t.Error("a quoted name ran a command in the shell")
	}
}
