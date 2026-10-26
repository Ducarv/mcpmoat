package main

// In-process tests of the diff of a new tool and of the truncation warning, in
// "mcpmoat scan" and in "mcpmoat pin --accept" (FR-12, FR-13). They use the
// helpers of pins_helpers_test.go and a fake inspector, so no server starts.

import (
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// linesDescription returns a description of n lines. Over 2000 lines, the diff
// of a tool with this description is cut at the line limit.
func linesDescription(n int) string {
	return strings.Repeat("a line of the description\n", n)
}

// bytesDescription returns a description of one line of n bytes. The line is
// short enough to keep the line count low, so only the byte limit (64 KiB) can
// cut the diff.
func bytesDescription(n int) string {
	return strings.Repeat("x", n)
}

// truncationWarning is the stderr line for a diff that was cut. cmd is "scan" or
// "pin". tool and server are the text as printed (escaped and cut).
func truncationWarning(cmd, tool, server string) string {
	return "mcpmoat " + cmd + ": warning: the diff of tool " + tool + " on server " + server +
		" was cut at the size limit; review the full tool before you accept it\n"
}

// TestScanNewToolDiff checks that scan prints the diff of a tool that is new on
// a pinned server: a "New tool" header and added lines only. --ignore drops the
// row and its diff.
func TestScanNewToolDiff(t *testing.T) {
	t.Parallel()

	pinned := []inspect.Tool{mkTool("a", "Add.")}
	current := []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo. Sends data.")}

	t.Run("a new tool has a diff", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, pinned...)

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": current}))

		assertScanRun(t, got, scanWant{
			code:     exitOK,
			stdout:   []string{"MOAT-T2-002", "New tool b on server srv:\n", "+name: b", "+description: Echo. Sends data.", ""},
			noStdout: []string{"Changed tool"},
		})
		out := splitPinOutput(t, got.stdout)
		if want := []pinFinding{{"MOAT-T2-002", "medium", "srv", "b", ""}}; !slices.Equal(out.rows, want) {
			t.Errorf("pin rows = %+v, want %+v", out.rows, want)
		}
		assertDiffsOf(t, out.diffs, "srv", []string{"+b"})
		if want := []string{acceptHintPrefix + "srv: mcpmoat pin --accept srv --config " + e.config + " --expect " + digestOf(t, current...)}; !slices.Equal(out.hints, want) {
			t.Errorf("hints = %q, want %q", out.hints, want)
		}
	})

	t.Run("--ignore drops the row and the diff", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, pinned...)

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": current}), "--ignore", "MOAT-T2-002")

		assertScanRun(t, got, scanWant{
			code:     exitOK,
			stderr:   []string{"mcpmoat scan: 1 finding ignored: MOAT-T2-002 (1)\n"},
			noStdout: []string{"New tool", "Changed tool", "--- pinned", "MOAT-T2-002", acceptHintPrefix},
		})
	})

	t.Run("--ignore of another rule keeps the diff", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, pinned...)

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": current}), "--ignore", "MOAT-T2-001")

		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"New tool b on server srv:\n"}})
		assertDiffsOf(t, splitPinOutput(t, got.stdout).diffs, "srv", []string{"+b"})
	})

	t.Run("a new tool and a changed tool each have a diff, in tool order", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, pinned...)

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add. X."), mkTool("b", "New.")}}))

		assertScanRun(t, got, scanWant{code: exitFindings})
		assertDiffsOf(t, splitPinOutput(t, got.stdout).diffs, "srv", []string{"a", "+b"})
	})
}

// TestPinAcceptNewToolsOfUnpinnedServer checks that "pin --accept" on a server
// that scan never pinned prints a New diff for every tool, before the
// "accepted" line.
func TestPinAcceptNewToolsOfUnpinnedServer(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))

	got := e.pin(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add."), mkTool("b", "Echo.")}}), "--accept", "srv")

	assertPinRun(t, got, scanWant{
		code: exitOK,
		stdout: []string{
			"New tool a on server srv:\n", "New tool b on server srv:\n",
			"+description: Add.", "+description: Echo.",
		},
		noStdout: []string{"Changed tool"},
		stderr:   []string{noExpectNote},
	})
	assertNoExpectNote(t, got.stderr)
	diffs, accepted := splitAcceptedLine(got.stdout)
	if want := "accepted srv: 2 new, 0 changed, 0 removed\n"; accepted != want {
		t.Errorf("accepted line = %q, want %q", accepted, want)
	}
	assertDiffsOf(t, diffs, "srv", []string{"+a", "+b"})
}

// truncationCase is one row of TestDiffTruncationWarning.
type truncationCase struct {
	name string
	// pinned is what scan pins first. It is the pin of "srv". For pin on an
	// unpinned server it is nil.
	pinned  []inspect.Tool
	current []inspect.Tool
	// pin runs "pin --accept srv" instead of a scan.
	pin   bool
	flags []string
	// wantTool is the tool whose diff is cut, or "" when there is no warning.
	wantTool string
}

// TestDiffTruncationWarning checks that scan and pin warn on stderr when the
// diff of a changed or new tool was cut at the size limit, and that they stay
// silent for a small change and for an ignored row.
func TestDiffTruncationWarning(t *testing.T) {
	t.Parallel()

	short := []inspect.Tool{mkTool("a", "Add.")}
	longLines := linesDescription(2500)
	longBytes := bytesDescription(70 * 1024)

	var tests []truncationCase
	for _, cmd := range []string{"scan", "pin"} {
		isPin := cmd == "pin"
		tests = append(tests,
			truncationCase{
				name: cmd + ": changed tool over the line limit", pin: isPin, pinned: short,
				current: []inspect.Tool{mkTool("a", longLines)}, wantTool: "a",
			},
			truncationCase{
				name: cmd + ": changed tool over the byte limit", pin: isPin, pinned: short,
				current: []inspect.Tool{mkTool("a", longBytes)}, wantTool: "a",
			},
			truncationCase{
				name: cmd + ": new tool over the line limit", pin: isPin, pinned: short,
				current: []inspect.Tool{mkTool("a", "Add."), mkTool("b", longLines)}, wantTool: "b",
			},
			truncationCase{
				name: cmd + ": new tool over the byte limit", pin: isPin, pinned: short,
				current: []inspect.Tool{mkTool("a", "Add."), mkTool("b", longBytes)}, wantTool: "b",
			},
			truncationCase{
				name: cmd + ": small changed tool", pin: isPin, pinned: short,
				current: []inspect.Tool{mkTool("a", "Add. Changed.")},
			},
			truncationCase{
				name: cmd + ": small new tool", pin: isPin, pinned: short,
				current: []inspect.Tool{mkTool("a", "Add."), mkTool("b", "New.")},
			},
			truncationCase{
				name: cmd + ": large tool below the limits", pin: isPin, pinned: short,
				current: []inspect.Tool{mkTool("a", linesDescription(1500))},
			},
		)
	}
	tests = append(tests,
		truncationCase{
			name: "pin: new tool of an unpinned server over the limit", pin: true,
			current: []inspect.Tool{mkTool("a", longLines)}, wantTool: "a",
		},
		truncationCase{
			name: "scan: ignored changed tool gives no warning", pinned: short,
			current: []inspect.Tool{mkTool("a", longLines)}, flags: []string{"--ignore", "MOAT-T2-001"},
		},
		truncationCase{
			name: "scan: ignored new tool gives no warning", pinned: short,
			current: []inspect.Tool{mkTool("a", "Add."), mkTool("b", longLines)}, flags: []string{"--ignore", "MOAT-T2-002"},
		},
		truncationCase{
			// Only the row of the new tool is ignored: the changed tool is
			// cut and still warns, the new tool does not.
			name: "scan: warns for the kept row only", pinned: short,
			current:  []inspect.Tool{mkTool("a", longLines), mkTool("b", longLines)},
			flags:    []string{"--ignore", "MOAT-T2-002"},
			wantTool: "a",
		},
	)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			if tt.pinned != nil {
				firstScan(t, e, tt.pinned...)
			}
			fake := fakeServers(map[string][]inspect.Tool{"srv": tt.current})

			var got pinRunResult
			cmd := "scan"
			if tt.pin {
				cmd = "pin"
				got = e.pin(fake, append([]string{"--accept", "srv"}, tt.flags...)...)
				assertPinRun(t, got, scanWant{code: exitOK, stderr: []string{noExpectNote}})
			} else {
				got = e.scan(fake, tt.flags...)
				if got.code != exitOK && got.code != exitFindings {
					t.Fatalf("exit code = %d, want 0 or 1\nstderr:\n%s", got.code, got.stderr)
				}
			}

			warning := truncationWarning(cmd, tt.wantTool, "srv")
			const marker = "was cut at the size limit"
			n := strings.Count(got.stderr, marker)
			switch {
			case tt.wantTool == "" && n != 0:
				t.Errorf("stderr = %q, want no truncation warning", got.stderr)
			case tt.wantTool != "" && (n != 1 || !strings.Contains(got.stderr, warning)):
				t.Errorf("stderr = %q, want exactly one %q", got.stderr, warning)
			}
			// The warning is on stderr only: stdout never holds it.
			assertContainsNone(t, "stdout", got.stdout, []string{marker, "warning:"})
			if tt.pin {
				// The accept worked: the pins hold the tools that pin saw.
				pinned, ok := e.readPins().tools("srv")
				if !ok || len(pinned) != len(tt.current) {
					t.Errorf("pins.json has %d tools for srv (found %v), want %d", len(pinned), ok, len(tt.current))
				}
			}
		})
	}
}

// TestDiffTruncationWarningNames checks that the tool name and the server name
// in the truncation warning, and in the header of a new diff, are escaped, so a
// hostile name cannot send a control sequence to the terminal. A name over 100
// runes is cut.
func TestDiffTruncationWarningNames(t *testing.T) {
	t.Parallel()

	const (
		hostileServer = "evil\x1b[31m\u202e"
		hostileTool   = "t\x1b[2J\u200b"
	)
	longTool := strings.Repeat("t", 150)
	long := linesDescription(2500)

	tests := []struct {
		name string
		// tool is the name of the tool that is new on the pinned server.
		tool string
		// server is the server name in the config file.
		server string
		// wantTool and wantServer are the names as the warning prints them.
		wantTool, wantServer string
	}{
		{"hostile server and tool", hostileTool, hostileServer, `"t\x1b[2J\u200b"`, `"evil\x1b[31m\u202e"`},
		{"hostile tool only", hostileTool, "srv", `"t\x1b[2J\u200b"`, "srv"},
		{"hostile server only", "b", hostileServer, "b", `"evil\x1b[31m\u202e"`},
		{"long tool name is cut", longTool, "srv", strings.Repeat("t", 100) + "...", "srv"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer(tt.server))
			if got := e.scan(fakeServers(map[string][]inspect.Tool{tt.server: {mkTool("a", "Add.")}})); got.code != exitOK {
				t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
			}
			current := []inspect.Tool{mkTool("a", "Add."), mkTool(tt.tool, long)}
			wantScan := truncationWarning("scan", tt.wantTool, tt.wantServer)
			wantPin := truncationWarning("pin", tt.wantTool, tt.wantServer)

			scan := e.scan(fakeServers(map[string][]inspect.Tool{tt.server: current}))
			pin := e.pin(fakeServers(map[string][]inspect.Tool{tt.server: current}), "--accept", tt.server)

			// The long description of the new tool also fires two description
			// rules: MOAT-T1-007 (low, a long text) and MOAT-T1-017 (high,
			// longer than the match window). The high row gives exit code 1
			// with the default --fail-on high. pin applies no rules.
			assertScanRun(t, scan, scanWant{code: exitFindings, stderr: []string{wantScan}})
			assertFindingIDs(t, scan.stdout, []string{"MOAT-T1-007", "MOAT-T1-017", "MOAT-T2-002"})
			assertPinRun(t, pin, scanWant{code: exitOK, stderr: []string{wantPin}})
			for _, got := range []pinRunResult{scan, pin} {
				// No raw escape, bidi or invisible rune on either stream.
				assertTerminalSafe(t, got.stdout)
				assertTerminalSafe(t, got.stderr)
				// The header of the new diff names the tool and the server
				// in escaped form, too.
				if tt.tool == longTool {
					continue // the report does not cut a long name in the header
				}
				header := "New tool " + tt.wantTool + " on server " + tt.wantServer + ":"
				if !strings.Contains(got.stdout, header) {
					t.Errorf("stdout has no header %q\nstdout:\n%s", header, got.stdout)
				}
			}
		})
	}
}
