package main

// In-process tests of the digest that closes the time-of-check to time-of-use
// gap of "pin --accept": scan prints "To accept <server>: mcpmoat pin --accept
// <server> --expect <digest>", and "pin --accept --expect <digest>" saves the
// tools only if they have this digest. They use the helpers of
// pins_helpers_test.go and pin_test.go. None of them calls t.Setenv, so all of
// them run in parallel.

import (
	"bytes"
	"errors"
	"maps"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/pins"
)

// TestPinExpectUsageErrors checks that a bad --expect is a usage error: exit
// code 2, an empty stdout, the message, and no discovery. The inspector is not
// called and nothing is written, also when the server name is unknown, because
// the digest is checked first.
func TestPinExpectUsageErrors(t *testing.T) {
	t.Parallel()

	const good = "pd1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const invalidMsg = "mcpmoat pin: --expect needs a digest such as pd1:<64 hex>\n"

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
			"--accept", "srv", "--expect", "pd1:0000000000000000000000000000000000000000000000000000000000000000")

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{"expected pd1:0000000000000000000000000000000000000000000000000000000000000000); nothing was saved."}})
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
	args := strings.Fields(cmdLine) // pin --accept srv --config <file> --expect <digest>
	if len(args) != 7 || args[0] != "pin" || args[1] != "--accept" || args[2] != "srv" ||
		args[3] != "--config" || args[4] != e.config || args[5] != "--expect" {
		t.Fatalf("hint command = %q, want pin --accept srv --config %s --expect <digest>", cmdLine, e.config)
	}

	got := e.raw(current, args...)

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
		wantNote  string // the note at the end of the hint line, or ""
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
			// The digest covers the changed tool that --ignore hid.
			wantNote: hintIgnoredNote,
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

			assertScanRun(t, got, scanWant{code: tt.wantCode, stdout: []string{tt.wantRule}, stderr: ignoredSummaryFor(tt.flags)})
			wantLine := acceptHintPrefix + "srv: mcpmoat pin --accept srv --config " + e.config + " --expect " + digestOf(t, tt.current...) + "\n"
			if tt.wantNote != "" {
				// The user did not see every change, so the line has no command.
				wantLine = acceptHintPrefix + "srv: run pin --accept with this server name, --config with the file of this scan, and --expect " +
					digestOf(t, tt.current...) + tt.wantNote + "\n"
			}
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
			if tt.breakHash {
				// The pins cannot be checked, so the report shows the whole
				// current text of each tool that the digest covers.
				assertContainsAll(t, "stdout", got.stdout, []string{
					"Not verified tool a on server srv (current text):\n",
					"Not verified tool b on server srv (current text):\n",
				})
			}
		})
	}
}

// ignoredSummaryFor returns the stderr text that a scan with these flags must hold: the
// summary of the findings that --ignore dropped.
func ignoredSummaryFor(flags []string) []string {
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
			wantCode: exitFindings, wantRow: "MOAT-T2-004",
		},
		{
			name: "pinned server that did not change", pinFirst: true,
			insp:     func() inspect.Inspector { return fakeServers(map[string][]inspect.Tool{"srv": pinned}) },
			wantCode: exitOK,
		},
		{
			name: "pinned server that was not inspected", pinFirst: true,
			insp: func() inspect.Inspector {
				return failingFake("srv")
			},
			wantCode: exitFindings, wantRow: "MOAT-T2-004",
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
			// Store.Set refuses a server over 2 MiB, so pin --accept could
			// never save these tools.
			name: "tools over the size limit of one server", pinFirst: true,
			insp: func() inspect.Inspector {
				return fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", strings.Repeat("x", 2<<20))}})
			},
			wantCode: exitFindings, wantRow: "MOAT-T2-001",
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
			assertContainsNone(t, "stdout", got.stdout, []string{acceptHintPrefix})
			// The Fix line of a MOAT-T2 finding names "pin --accept ... --expect"
			// in general. Only the text after the FINDINGS block (the diffs and
			// the hint lines) must hold neither.
			assertContainsNone(t, "stdout after the findings", splitScanSections(got.stdout).Rest, []string{"pin --accept", "--expect"})
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
	store, ok := c.readPins("scan")
	if !ok {
		t.Fatal("readPins() = false, want true")
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
// comes from a config file: in the command when it is a bare shell word, and
// with no command otherwise, because no quoting is safe in every shell. The
// text before the colon is always escaped for the terminal.
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
		{"space and quote: no command", "it's a b", "it's a b", ""},
		{"starts with a dash: no command", "-dash", "-dash", ""},
		{"starts with @: no command", "@args", "@args", ""},
		{"shell metacharacters: no command", "a;b $(x) `y` *", "a;b $(x) `y` *", ""},
		{"non-ASCII letters: no command", "café", "café", ""},
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
			want := acceptHintPrefix + tt.wantLabel + ": mcpmoat pin --accept " + tt.wantArg + " --config " + e.config + " --expect " + digest
			if tt.wantArg == "" {
				want = acceptHintPrefix + tt.wantLabel + ": run pin --accept with this server name, --config with the file of this scan, and --expect " + digest
			}
			if !slices.Equal(hints, []string{want}) {
				t.Errorf("hints = %q, want [%q]", hints, want)
			}
			assertTerminalSafe(t, got.stdout)
			assertTerminalSafe(t, got.stderr)
		})
	}
}

// TestPinAcceptsNameWithoutCommand checks the round trip for a name that is not
// a bare shell word: the hint has no command, but its digest works with the
// exact server name.
func TestPinAcceptsNameWithoutCommand(t *testing.T) {
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

// TestAcceptCommand checks the command of a "To accept" line: with --config when
// scan had one, and none when the name or the config path is not a bare shell
// word.
func TestAcceptCommand(t *testing.T) {
	t.Parallel()

	const d = "pd1:00"
	tests := []struct {
		name, server, project, config, want string
	}{
		{"no config", "srv", "", "", "mcpmoat pin --accept srv --expect pd1:00"},
		{"project", "srv", "/home/u/proj", "", "mcpmoat pin --accept srv --project /home/u/proj --expect pd1:00"},
		{"project and config", "srv", "/p", "/c.json", "mcpmoat pin --accept srv --project /p --config /c.json --expect pd1:00"},
		{"project with a space", "srv", "/home/u/my proj", "", ""},
		{"bare config", "srv", "", "/home/u/.cursor/mcp.json", "mcpmoat pin --accept srv --config /home/u/.cursor/mcp.json --expect pd1:00"},
		{"relative config", "srv", "", "cfg/mcp.json", "mcpmoat pin --accept srv --config cfg/mcp.json --expect pd1:00"},
		{"config with a space", "srv", "", "/Users/u/Application Support/c.json", ""},
		{"config with a quote", "srv", "", "/tmp/a'b.json", ""},
		{"config that starts with a dash", "srv", "", "-x.json", ""},
		{"config that starts with a dot", "srv", "", "./mcp.json", ""},
		{"config over 500 bytes", "srv", "", "/" + strings.Repeat("a", 500), ""},
		{"name that is not bare, with config", "a b", "", "/c.json", ""},
		{"name that is not bare, no config", "a b", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := acceptCommand(tt.server, tt.project, tt.config, d)
			if got != tt.want || ok != (tt.want != "") {
				t.Errorf("acceptCommand(%q, %q) = (%q, %v), want (%q, %v)", tt.server, tt.config, got, ok, tt.want, tt.want != "")
			}
		})
	}
}

// TestWriteAcceptHints checks when a "To accept" line has a command, and the
// text and the notes that it has when it has none.
func TestWriteAcceptHints(t *testing.T) {
	t.Parallel()

	const d = "pd1:00"
	const steps = "To accept srv: run pin --accept with this server name and --expect pd1:00"
	const stepsConfig = "To accept srv: run pin --accept with this server name, --config with its config file, and --expect pd1:00"
	tests := []struct {
		name          string
		hint          acceptHint
		config        string
		configProblem bool
		want          string
	}{
		{"command", acceptHint{name: "srv", digest: d}, "", false, "To accept srv: mcpmoat pin --accept srv --expect pd1:00"},
		// The user did not see the change that --ignore hid.
		{"ignored rows: no command", acceptHint{name: "srv", digest: d, ignored: true}, "", false, steps + hintIgnoredNote},
		// The diff of a change is a fixed note, so the user saw no text of it.
		{"diff that is a note: no command", acceptHint{name: "srv", digest: d, noText: true}, "", false, steps + hintNoTextNote},
		// The user did not see the whole tool, so they must type the command.
		{"cut diff: no command", acceptHint{name: "srv", digest: d, truncated: true}, "", false, steps + hintCutNote},
		{"cut diff and ignored rows", acceptHint{name: "srv", digest: d, truncated: true, ignored: true}, "", false,
			steps + hintCutNote + hintIgnoredNote},
		// pin refuses a name that two servers use, and any config problem.
		{"ambiguous name: no command", acceptHint{name: "srv", digest: d, ambiguous: true}, "", false, stepsConfig},
		{"project", acceptHint{name: "srv", digest: d, project: "/p"}, "", false, "To accept srv: mcpmoat pin --accept srv --project /p --expect pd1:00"},
		{"project that is not bare", acceptHint{name: "srv", digest: d, project: "/my p"}, "", false,
			"To accept srv: run pin --accept with this server name, --project with its project path, and --expect pd1:00"},
		{"config problem: no command", acceptHint{name: "srv", digest: d}, "", true,
			"To accept srv: fix the config file first, then run pin --accept with this server name, --config with its config file, and --expect pd1:00"},
		{"config problem with --config", acceptHint{name: "srv", digest: d}, "/c.json", true,
			"To accept srv: fix the config file first, then run pin --accept with this server name, --config with the file of this scan, and --expect pd1:00"},
		{"name that is not bare", acceptHint{name: "a b", digest: d}, "", false,
			"To accept a b: run pin --accept with this server name and --expect pd1:00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var b strings.Builder
			if err := writeAcceptHints(&b, []acceptHint{tt.hint}, tt.config, tt.configProblem); err != nil {
				t.Fatalf("writeAcceptHints() error = %v, want nil", err)
			}
			if got := b.String(); got != tt.want+"\n" {
				t.Errorf("writeAcceptHints() = %q, want %q", got, tt.want+"\n")
			}
		})
	}
}

// TestScanAcceptHintSharedName checks that two global servers with one name in
// different config files get hints with no command, because pin refuses the
// name without --config.
func TestScanAcceptHintSharedName(t *testing.T) {
	t.Parallel()

	srvA := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "/a/mcp.json"}
	srvB := discover.Server{Name: "srv", Client: discover.ClientCursor, Source: "/b/mcp.json"}
	e := newPinEnv(t, oneServer("srv"))
	for _, s := range []discover.Server{srvA, srvB} {
		writePinsAside(t, e.pinsPath(), serverIdentity(s), mkTool("a", "Add."))
	}
	c, _, _ := e.cli(nil)
	store, ok := c.readPins("scan")
	if !ok {
		t.Fatal("readPins() = false, want true")
	}
	changed := []inspect.Tool{mkTool("a", "Add. Changed.")}

	pr := c.pinOutcomes(store, []inspect.Outcome{
		{Server: srvA, Status: inspect.StatusOK, Result: inspect.Result{Tools: changed}},
		{Server: srvB, Status: inspect.StatusOK, Result: inspect.Result{Tools: changed}},
	}, &scanIgnores{})

	if len(pr.hints) != 2 || !pr.hints[0].ambiguous || !pr.hints[1].ambiguous {
		t.Errorf("hints = %+v, want two ambiguous hints", pr.hints)
	}
}

// TestIsBareShellWord checks isBareShellWord on its own.
func TestIsBareShellWord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"plain", "srv", true},
		{"every bare character", "aZ09._@/:+=-", true},
		{"starts with _", "_srv", true},
		{"absolute path", "/home/u/mcp.json", true},
		{"dash inside", "a-b", true},
		{"@ inside", "a@b", true},
		{"= inside", "a=b", true},
		{"exactly the cap", strings.Repeat("a", 20), true},
		{"over the cap", strings.Repeat("a", 21), false},
		// pin would read a word that starts with a dash as a flag.
		{"starts with a dash", "-x", false},
		{"only a dash", "-", false},
		{"two dashes", "--", false},
		// PowerShell reads @name as splatting.
		{"starts with @", "@x", false},
		// zsh expands =name to the path of a command.
		{"starts with =", "=ls", false},
		// PowerShell can read 1kb or .5 as a number.
		{"starts with a digit", "1kb", false},
		{"starts with a dot", ".5", false},
		{"starts with +", "+5", false},
		{"starts with :", ":a", false},
		{"empty", "", false},
		{"space", "a b", false},
		{"quote", "it's", false},
		{"double quote", `"a"`, false},
		{"dollar", "$HOME", false},
		{"backslash", `a\b`, false},
		{"glob and tilde", "~/*", false},
		{"semicolon", "a;b", false},
		{"ampersand", "a&b", false},
		{"pipe", "a|b", false},
		{"percent", "%PATH%", false},
		{"caret", "a^b", false},
		{"backtick", "a`b", false},
		{"comma", "a,b", false},
		{"non-ASCII", "naïve", false},
		{"escape", "a\x1bb", false},
		{"newline", "a\nb", false},
		{"nul", "a\x00b", false},
		{"invalid UTF-8", "a\xffb", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isBareShellWord(tt.in, 20); got != tt.want {
				t.Errorf("isBareShellWord(%q, 20) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestBareShellWordReadByShell checks bare words against a real POSIX shell: sh
// must read each one back as the word that went in, and must run nothing.
func TestBareShellWordReadByShell(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("the check uses a POSIX shell")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh in PATH")
	}
	dir := t.TempDir()
	for _, word := range []string{"srv", "a-n", "a=b", "a:b", "a+b", "a@b", "a/b.c", "/abs/path", "_x", "aZ09._@/:+=-"} {
		if !isBareShellWord(word, maxWarnNameRunes) {
			t.Fatalf("isBareShellWord(%q) = false, want true", word)
		}
		// printf prints its argument; the script holds only the word under test.
		cmd := exec.CommandContext(t.Context(), shell, "-c", "printf '%s' "+word) //nolint:gosec // G204: the argument is test data, and the test checks that sh reads it back as one word
		cmd.Dir = dir                                                             // a command that ran would create files here
		out, err := cmd.Output()
		if err != nil {
			t.Errorf("sh printf %s: %v", word, err)
			continue
		}
		if string(out) != word {
			t.Errorf("sh read %s as %q, want %q", word, out, word)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the shell created files: %v, error %v", entries, err)
	}
}

// TestSelectServers checks which servers "pin --accept <name> [--project
// <path>]" selects.
func TestSelectServers(t *testing.T) {
	t.Parallel()

	global := discover.Server{Name: "gh", Source: "/h/.claude.json"}
	projA := discover.Server{Name: "gh", Source: "/h/.claude.json", ProjectPath: "/p/a"}
	projB := discover.Server{Name: "gh", Source: "/h/.claude.json", ProjectPath: "/p/b"}
	cursor := discover.Server{Name: "gh", Source: "/h/.cursor/mcp.json"}
	other := discover.Server{Name: "x", Source: "/h/.claude.json"}

	tests := []struct {
		name    string
		servers []discover.Server
		project string
		want    []discover.Server
	}{
		{"one server", []discover.Server{global, other}, "", []discover.Server{global}},
		{"unknown name", []discover.Server{other}, "", nil},
		{"global and projects: the global one", []discover.Server{projA, global, projB}, "", []discover.Server{global}},
		{"projects only: ambiguous", []discover.Server{projA, projB}, "", []discover.Server{projA, projB}},
		{"two globals: ambiguous", []discover.Server{global, cursor, projA}, "", []discover.Server{global, cursor, projA}},
		{"project selects one", []discover.Server{projA, global, projB}, "/p/b", []discover.Server{projB}},
		{"unknown project", []discover.Server{projA, global}, "/p/c", nil},
		{"one project server, no flag", []discover.Server{projA, other}, "", []discover.Server{projA}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ids := func(servers []discover.Server) []pins.Identity {
				var out []pins.Identity
				for _, s := range servers {
					out = append(out, serverIdentity(s))
				}
				return out
			}
			if got := selectServers(tt.servers, "gh", tt.project); !slices.Equal(ids(got), ids(tt.want)) {
				t.Errorf("selectServers(%q) = %+v, want %+v", tt.project, ids(got), ids(tt.want))
			}
		})
	}
}

// TestSetSelectors checks the --project value of a hint, and when the name
// cannot select the server at all.
func TestSetSelectors(t *testing.T) {
	t.Parallel()

	global := discover.Server{Name: "gh", Client: discover.ClientClaudeCode, Source: "/h/.claude.json"}
	projA := discover.Server{Name: "gh", Client: discover.ClientClaudeCode, Source: "/h/.claude.json", ProjectPath: "/p/a"}
	projB := discover.Server{Name: "gh", Client: discover.ClientClaudeCode, Source: "/h/.claude.json", ProjectPath: "/p/b"}
	cursor := discover.Server{Name: "gh", Client: discover.ClientCursor, Source: "/h/.cursor/mcp.json"}
	projAFile := discover.Server{Name: "gh", Client: discover.ClientClaudeCode, Source: "/p/a/.mcp.json", ProjectPath: "/p/a"}

	tests := []struct {
		name          string
		servers       []discover.Server
		hint          discover.Server
		wantProject   string
		wantAmbiguous bool
	}{
		{"only server", []discover.Server{global}, global, "", false},
		{"global next to projects", []discover.Server{global, projA, projB}, global, "", false},
		{"project next to the global one", []discover.Server{global, projA, projB}, projA, "/p/a", false},
		{"one project server alone", []discover.Server{projB}, projB, "", false},
		{"two globals", []discover.Server{global, cursor}, cursor, "", true},
		// Two projects use the name in ~/.claude.json and one in a project
		// file: --project alone matches two servers, so pin needs --config
		// and --project together.
		{"same project in two files", []discover.Server{projA, projB, projAFile}, projA, "/p/a", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hints := []acceptHint{{name: tt.hint.Name, id: serverIdentity(tt.hint)}}
			setSelectors(hints, tt.servers)
			if hints[0].project != tt.wantProject || hints[0].ambiguous != tt.wantAmbiguous {
				t.Errorf("hint = %+v, want project %q and ambiguous %v", hints[0], tt.wantProject, tt.wantAmbiguous)
			}
		})
	}
}
