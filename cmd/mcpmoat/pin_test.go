package main

// In-process tests of "mcpmoat pin --accept <server>" (FR-13). They use the
// helpers of scan_pins_test.go: a fake inspector, and a home, a working
// directory and an XDG_CONFIG_HOME in t.TempDir(). None of them calls t.Setenv,
// so all of them can run in parallel.

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

// pinPrefix is the start of every stderr line of pin.
const pinPrefix = "mcpmoat pin: "

// noExpectNote is the line that a successful "pin --accept" without --expect
// prints on stderr. The text is spelled out here, so that a change of it shows
// in the tests.
const noExpectNote = "mcpmoat pin: note: without --expect, pin trusts the tools the server returns now; " +
	"use the digest from scan to be sure they match what you reviewed.\n"

// assertNoExpectNote fails the test unless stderr is exactly the note of a
// successful pin without --expect.
func assertNoExpectNote(t *testing.T, stderr string) {
	t.Helper()
	if stderr != noExpectNote {
		t.Errorf("stderr = %q, want exactly the no --expect note %q", stderr, noExpectNote)
	}
}

// assertPinRun checks a pin run like assertScanRun does a scan run. Every
// stderr line of a usage error starts with "mcpmoat pin: ", and the usage hint
// is the one exception (it starts with "Run").
func assertPinRun(t *testing.T, r pinRunResult, want scanWant) {
	t.Helper()
	assertRun(t, pinPrefix, pinRunWithoutHint(r), want)
}

// pinRunWithoutHint returns r without the usage hint line on stderr, which has
// no prefix. The hint is checked on its own in the usage error tests.
func pinRunWithoutHint(r pinRunResult) pinRunResult {
	var lines []string
	for _, line := range nonEmptyLines(r.stderr) {
		if line != usageHint {
			lines = append(lines, line)
		}
	}
	if len(lines) > 0 {
		r.stderr = strings.Join(lines, "\n") + "\n"
	} else {
		r.stderr = ""
	}
	return r
}

// TestPinUsageErrors checks the arguments of pin: a usage error is exit code 2,
// an empty stdout, a message that starts with "mcpmoat pin: " and the usage
// hint. pin never inspects a server or writes pins.json for such an error.
func TestPinUsageErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantStderr []string
	}{
		{"no arguments", []string{"pin"}, []string{"mcpmoat pin: --accept <server> is required\n"}},
		{"--timeout without --accept", []string{"pin", "--timeout", "5s"}, []string{"mcpmoat pin: --accept <server> is required\n"}},
		{"--config without --accept", []string{"pin", "--config", "x.json"}, []string{"mcpmoat pin: --accept <server> is required\n"}},
		{"unexpected argument", []string{"pin", "--accept", "srv", "extra"}, []string{`mcpmoat pin: unexpected arguments ["extra"]` + "\n"}},
		{"bare name instead of the flag", []string{"pin", "srv"}, []string{`mcpmoat pin: unexpected arguments ["srv"]` + "\n"}},
		{"unexpected argument with an escape", []string{"pin", "--accept", "srv", "a\x1b[31m"}, []string{`unexpected arguments ["a\x1b[31m"]`}},
		{"unknown flag", []string{"pin", "--accept", "srv", "--bogus"}, []string{"mcpmoat pin: flag provided but not defined: -bogus\n"}},
		{"--no-connect is a scan flag", []string{"pin", "--accept", "srv", "--no-connect"}, []string{"flag provided but not defined: -no-connect"}},
		{"--accept without a value", []string{"pin", "--accept"}, []string{"flag needs an argument"}},
		{"--accept with an empty value", []string{"pin", "--accept", ""}, []string{"--accept needs a server name"}},
		{"--accept takes no flag as value", []string{"pin", "--accept", "--config", "x.json"}, []string{"--accept needs a server name"}},
		{"--accept given twice", []string{"pin", "--accept", "a", "--accept", "b"}, []string{"--accept given more than once"}},
		{"--config given twice", []string{"pin", "--accept", "a", "--config", "x", "--config", "y"}, []string{"--config given more than once"}},
		{"--config with an empty value", []string{"pin", "--accept", "a", "--config", ""}, []string{"--config needs a file name"}},
		{"timeout 0", []string{"pin", "--accept", "srv", "--timeout", "0"}, []string{"mcpmoat pin: --timeout must be greater than 0\n"}},
		{"negative timeout", []string{"pin", "--accept", "srv", "--timeout", "-5s"}, []string{"mcpmoat pin: --timeout must be greater than 0\n"}},
		{"timeout that is no duration", []string{"pin", "--accept", "srv", "--timeout", "abc"}, []string{"mcpmoat pin: ", "timeout"}},
		{"timeout with an escape", []string{"pin", "--accept", "srv", "--timeout", "\x1b[31mred"}, []string{"mcpmoat pin: ", "timeout"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})
			xdgBefore := dirSnapshot(t, e.xdg)

			got := e.raw(fake, tt.args...)

			assertPinRun(t, got, scanWant{code: exitError, stderr: tt.wantStderr})
			assertEmptyStdout(t, got.stdout)
			if !strings.HasSuffix(got.stderr, usageHint+"\n") {
				t.Errorf("stderr = %q, want it to end with the usage hint", got.stderr)
			}
			assertTerminalSafe(t, got.stderr)
			if calls := fake.Calls(); len(calls) != 0 {
				t.Errorf("the inspector was called for %v, want no call", calls)
			}
			assertDirUnchanged(t, e.xdg, xdgBefore)
		})
	}
}

// TestPinHelp checks that "pin -h" prints the pin usage on stdout with exit
// code 0, and that the main help holds the same text.
func TestPinHelp(t *testing.T) {
	t.Parallel()

	var want bytes.Buffer
	pinUsage(&want)

	for _, flagName := range []string{"-h", "--help", "-help"} {
		t.Run(flagName, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))

			got := e.raw(nil, "pin", flagName)

			if got.code != exitOK {
				t.Errorf("exit code = %d, want %d", got.code, exitOK)
			}
			if got.stdout != want.String() {
				t.Errorf("stdout differs from pinUsage\n--- got ---\n%s--- want ---\n%s", got.stdout, want.String())
			}
			assertCleanStderr(t, got.stderr)
			assertContainsAll(t, "stdout", got.stdout, []string{"--accept <server>", "--config <file>", "--timeout <duration>", "default 10s"})
		})
	}

	t.Run("help wins over a bad value after it", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))

		got := e.raw(nil, "pin", "-h", "--timeout", "0")

		if got.code != exitOK || got.stdout != want.String() {
			t.Errorf("exit code = %d, stdout = %q; want %d and the pin usage", got.code, got.stdout, exitOK)
		}
	})

	t.Run("main help holds the pin usage", func(t *testing.T) {
		t.Parallel()
		if text := usageText(t); !strings.Contains(text, want.String()) {
			t.Errorf("the main help does not hold the pin usage\n--- help ---\n%s", text)
		}
	})
}

// TestPinServerLookup checks that pin accepts exactly one server: an unknown
// name, an ambiguous name and any config problem are exit code 2, with no
// inspection and no write.
func TestPinServerLookup(t *testing.T) {
	t.Parallel()

	// fake would give tools to every name, so a call shows in Calls.
	newFake := func() *inspecttest.Fake {
		return fakeServers(map[string][]inspect.Tool{
			"dup": {mkTool("a", "Add.")}, "other": {mkTool("a", "Add.")},
		})
	}

	t.Run("unknown server", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := newFake()

		got := e.pin(fake, "--accept", "nope")

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{"mcpmoat pin: unknown server nope\n"}})
		assertEmptyStdout(t, got.stdout)
		assertNoInspectNoWrite(t, e, fake)
	})

	t.Run("a name must match exactly", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := newFake()

		for _, name := range []string{"SRV", "sr", "srv ", "srv*"} {
			got := e.pin(fake, "--accept", name)
			assertPinRun(t, got, scanWant{code: exitError, stderr: []string{"unknown server"}})
		}
		assertNoInspectNoWrite(t, e, fake)
	})

	t.Run("unknown server name with an escape is escaped", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := newFake()

		got := e.pin(fake, "--accept", "x\x1b[31m")

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{`unknown server "x\x1b[31m"`}})
		assertTerminalSafe(t, got.stderr)
		assertNoInspectNoWrite(t, e, fake)
	})

	t.Run("no server in the home", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := newFake()

		got := e.raw(fake, "pin", "--accept", "srv") // auto-discovery: the home is empty

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{"mcpmoat pin: unknown server srv\n"}})
		assertNoInspectNoWrite(t, e, fake)
	})

	t.Run("same name in two sources is ambiguous", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		writeServers(t, e.home, ".claude.json", oneServer("dup"))
		writeServers(t, e.home, filepath.Join(".cursor", "mcp.json"), oneServer("dup"))
		fake := newFake()

		got := e.raw(fake, "pin", "--accept", "dup")

		// The lines under the first one list the matches, with no prefix.
		assertRun(t, "", got, scanWant{code: exitError, stderr: []string{
			"mcpmoat pin: 2 servers are named dup; narrow it with --config <file>:\n",
			"  client claude-code, source ",
			"  client cursor, source ",
			"scope ",
		}})
		assertContainsAll(t, "stderr", got.stderr, []string{
			filepath.Join(e.home, ".claude.json"),
			filepath.Join(e.home, ".cursor", "mcp.json"),
		})
		assertEmptyStdout(t, got.stdout)
		assertNoInspectNoWrite(t, e, fake)
	})

	t.Run("--config narrows an ambiguous name", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		claude := writeServers(t, e.home, ".claude.json", oneServer("dup"))
		writeServers(t, e.home, filepath.Join(".cursor", "mcp.json"), oneServer("dup"))
		fake := newFake()

		got := e.raw(fake, "pin", "--accept", "dup", "--config", claude)

		assertPinRun(t, got, scanWant{code: exitOK, stdout: []string{"accepted dup: 1 new, 0 changed, 0 removed\n"}, stderr: []string{noExpectNote}})
		assertNoExpectNote(t, got.stderr)
		if got := fake.Calls(); !slices.Equal(got, []string{"dup"}) {
			t.Errorf("inspector calls = %v, want [dup]", got)
		}
	})

	t.Run("a broken config file fails closed even if one server matches", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		writeTestFile(t, e.home, ".claude.json", "{not json")
		writeServers(t, e.home, filepath.Join(".cursor", "mcp.json"), oneServer("dup"))
		fake := newFake()

		got := e.raw(fake, "pin", "--accept", "dup")

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{
			"mcpmoat pin: ", ".claude.json", "invalid JSON",
			"mcpmoat pin: fix the config file or choose one with --config <file>\n",
		}})
		assertEmptyStdout(t, got.stdout)
		assertNoInspectNoWrite(t, e, fake)
	})

	t.Run("--config file that does not exist", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := newFake()

		got := e.raw(fake, "pin", "--accept", "dup", "--config", filepath.Join(e.work, "missing.json"))

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{"mcpmoat pin: ", "missing.json", "file not found"}})
		assertEmptyStdout(t, got.stdout)
		assertNoInspectNoWrite(t, e, fake)
	})

	t.Run("--config file with a bad entry next to the server", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		cfg := writeServers(t, t.TempDir(), "mcp.json", map[string]any{
			"dup": map[string]any{"command": "npx"},
			"bad": map[string]any{"url": 5},
		})
		fake := newFake()

		got := e.raw(fake, "pin", "--accept", "dup", "--config", cfg)

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{
			"mcpmoat pin: ", "bad",
			"mcpmoat pin: fix the config file or choose one with --config <file>\n",
		}})
		assertNoInspectNoWrite(t, e, fake)
	})

	t.Run("no home directory", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := newFake()
		c, stdout, stderr := e.cli(fake)
		c.homeDir = func() (string, error) { return "", errors.New("no home") }

		code := c.dispatch([]string{"pin", "--accept", "srv"})

		assertPinRun(t, pinRunResult{code, stdout.String(), stderr.String()}, scanWant{
			code: exitError, stderr: []string{"mcpmoat pin: cannot find the home directory: set HOME or use --config\n"},
		})
		assertNoInspectNoWrite(t, e, fake)
	})
}

// assertNoInspectNoWrite fails the test if the fake inspector was called or if
// anything was created under the XDG folder of e.
func assertNoInspectNoWrite(t *testing.T, e *pinEnv, fake *inspecttest.Fake) {
	t.Helper()
	if calls := fake.Calls(); len(calls) != 0 {
		t.Errorf("the inspector was called for %v, want no call", calls)
	}
	if _, err := os.Stat(filepath.Join(e.xdg, "mcpmoat")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the pins folder exists (stat error = %v), want nothing written", err)
	}
}

// TestPinInspectFailure checks that a server that is not inspected is an error
// for pin, exit code 2, and that pins.json stays as it was.
func TestPinInspectFailure(t *testing.T) {
	t.Parallel()

	pinnedTools := []inspect.Tool{mkTool("a", "Add.")}

	tests := []struct {
		name       string
		insp       func() inspect.Inspector
		flags      []string
		wantStderr []string
	}{
		{
			name: "failed",
			insp: func() inspect.Inspector {
				return &inspecttest.Fake{Errors: map[string]error{"srv": errors.New("boom")}}
			},
			wantStderr: []string{"mcpmoat pin: server srv: failed: inspect: boom\n"},
		},
		{
			name:       "timeout",
			insp:       func() inspect.Inspector { return blockingInspector{} },
			flags:      []string{"--timeout", "20ms"},
			wantStderr: []string{"mcpmoat pin: server srv: timeout: inspect: no answer within 20ms: context deadline exceeded\n"},
		},
		{
			name: "error text is escaped",
			insp: func() inspect.Inspector {
				return &inspecttest.Fake{Errors: map[string]error{"srv": errors.New("boom \x1b[31m\u202e")}}
			},
			wantStderr: []string{"mcpmoat pin: server srv: failed: ", `\x1b[31m`},
		},
		{
			name:       "nil inspector",
			insp:       func() inspect.Inspector { return nil },
			wantStderr: []string{"mcpmoat pin: cannot inspect the server: "},
		},
	}
	for _, tt := range tests {
		for _, pinned := range []bool{false, true} {
			name := tt.name + ", server not pinned"
			if pinned {
				name = tt.name + ", server pinned"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				e := newPinEnv(t, oneServer("srv"))
				if pinned {
					if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": pinnedTools})); got.code != exitOK {
						t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
					}
				}
				before := dirSnapshot(t, e.xdg)

				got := e.pin(tt.insp(), append([]string{"--accept", "srv"}, tt.flags...)...)

				assertPinRun(t, got, scanWant{code: exitError, stderr: tt.wantStderr})
				assertEmptyStdout(t, got.stdout)
				assertTerminalSafe(t, got.stderr)
				assertDirUnchanged(t, e.xdg, before)
			})
		}
	}
}

// TestPinSnapshotFailure checks that tools which cannot be pinned (a name used
// twice, or an empty name) are exit code 2, and that the store is not changed.
func TestPinSnapshotFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		tools []inspect.Tool
	}{
		{"duplicate tool name", []inspect.Tool{mkTool("a", "One."), mkTool("a", "Two.")}},
		{"empty tool name", []inspect.Tool{mkTool("", "No name.")}},
	}
	for _, tt := range tests {
		for _, pinned := range []bool{false, true} {
			name := tt.name + ", server not pinned"
			if pinned {
				name = tt.name + ", server pinned"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				e := newPinEnv(t, oneServer("srv"))
				if pinned {
					if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})); got.code != exitOK {
						t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
					}
				}
				before := dirSnapshot(t, e.xdg)

				got := e.pin(fakeServers(map[string][]inspect.Tool{"srv": tt.tools}), "--accept", "srv")

				assertPinRun(t, got, scanWant{code: exitError, stderr: []string{"mcpmoat pin: cannot pin the tools of server srv: "}})
				assertEmptyStdout(t, got.stdout)
				assertDirUnchanged(t, e.xdg, before)
			})
		}
	}
}

// TestPinStoreErrors checks that a pins.json that cannot be read or saved is
// exit code 2 and that nothing is accepted.
func TestPinStoreErrors(t *testing.T) {
	t.Parallel()

	fake := func() *inspecttest.Fake {
		return fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})
	}

	t.Run("corrupt pins.json", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		const corrupt = "{this is not json"
		writeTestFile(t, filepath.Join(e.xdg, "mcpmoat"), "pins.json", corrupt)
		insp := fake()

		got := e.pin(insp, "--accept", "srv")

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{"mcpmoat pin: cannot read the pins file: "}})
		assertEmptyStdout(t, got.stdout)
		// pins.json is read before the server starts (M2).
		if calls := insp.Calls(); len(calls) != 0 {
			t.Errorf("the inspector was called for %v, want no call", calls)
		}
		if after := string(readFileBytes(t, e.pinsPath())); after != corrupt {
			t.Errorf("pins.json = %q, want it unchanged", after)
		}
	})

	t.Run("newer format version", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		const newer = `{"version": 999, "servers": []}`
		writeTestFile(t, filepath.Join(e.xdg, "mcpmoat"), "pins.json", newer)
		insp := fake()

		got := e.pin(insp, "--accept", "srv")

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{"mcpmoat pin: cannot read the pins file: "}})
		assertEmptyStdout(t, got.stdout)
		if calls := insp.Calls(); len(calls) != 0 {
			t.Errorf("the inspector was called for %v, want no call", calls)
		}
		if after := string(readFileBytes(t, e.pinsPath())); after != newer {
			t.Errorf("pins.json = %q, want it unchanged", after)
		}
	})

	t.Run("save error", func(t *testing.T) {
		t.Parallel()
		if os.Geteuid() == 0 || filepath.Separator == '\\' {
			t.Skip("a read-only directory does not stop this user")
		}
		e := newPinEnv(t, oneServer("srv"))
		dir := filepath.Join(e.xdg, "mcpmoat")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // G302: the test makes the folder read-only on purpose
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: restores the folder so that t.TempDir can remove it

		got := e.pin(fake(), "--accept", "srv")

		assertPinRun(t, got, scanWant{code: exitError, stderr: []string{"mcpmoat pin: cannot save the pins file: "}})
		// Nothing says "accepted" when the save failed.
		assertEmptyStdout(t, got.stdout)
	})
}

// TestPinAccept checks the success path: the "accepted" line, the counts, and
// that only the entry of the accepted server changes.
func TestPinAccept(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// pinned is the state of srv before pin. nil means that scan never saw
		// the server, so it is not in pins.json.
		pinned  []inspect.Tool
		current []inspect.Tool
		// breakHash makes the pins of srv use another hash version first.
		breakHash bool
		// wantStdout is the "accepted" line, the last line of stdout.
		wantStdout string
		// wantDiffs are the changed tools whose diff pin prints before the
		// "accepted" line, in order. No tool means no text before the line.
		wantDiffs []string
	}{
		{
			name:       "unpinned server: every tool is new",
			current:    []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")},
			wantStdout: "accepted srv: 2 new, 0 changed, 0 removed\n",
		},
		{
			name:       "unpinned server with no tool",
			current:    nil,
			wantStdout: "accepted srv: 0 new, 0 changed, 0 removed\n",
		},
		{
			name:       "changed, removed and new",
			pinned:     []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo."), mkTool("c", "Keep.")},
			current:    []inspect.Tool{mkTool("a", "Add. Changed."), mkTool("c", "Keep."), mkTool("d", "New."), mkTool("e", "New too.")},
			wantStdout: "accepted srv: 2 new, 1 changed, 1 removed\n",
			wantDiffs:  []string{"a"},
		},
		{
			name:       "nothing changed",
			pinned:     []inspect.Tool{mkTool("a", "Add.")},
			current:    []inspect.Tool{mkTool("a", "Add.")},
			wantStdout: "accepted srv: 0 new, 0 changed, 0 removed\n",
		},
		{
			name:       "pin of another hash version is counted as not verified",
			pinned:     []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")},
			current:    []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")},
			breakHash:  true,
			wantStdout: "accepted srv: 0 new, 0 changed, 0 removed, 2 not verified\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			if tt.pinned != nil {
				if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tt.pinned})); got.code != exitOK {
					t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
				}
				if tt.breakHash {
					breakPinHashVersion(t, e)
				}
			}
			fake := fakeServers(map[string][]inspect.Tool{"srv": tt.current})

			got := e.pin(fake, "--accept", "srv")

			assertPinRun(t, got, scanWant{code: exitOK, stderr: []string{noExpectNote}})
			assertNoExpectNote(t, got.stderr)
			// pin prints the diff of each changed tool, then the "accepted" line.
			diffs, accepted := splitAcceptedLine(got.stdout)
			if accepted != tt.wantStdout {
				t.Errorf("accepted line = %q, want %q\nstdout:\n%s", accepted, tt.wantStdout, got.stdout)
			}
			assertDiffsOf(t, diffs, "srv", tt.wantDiffs)
			if len(tt.wantDiffs) == 0 && diffs != "" {
				t.Errorf("text before the accepted line = %q, want none", diffs)
			}
			if calls := fake.Calls(); !slices.Equal(calls, []string{"srv"}) {
				t.Errorf("inspector calls = %v, want [srv]", calls)
			}
			pinned, ok := e.readPins().tools("srv")
			if !ok || len(pinned) != len(tt.current) {
				t.Errorf("pins.json has %d tools for srv (found %v), want %d", len(pinned), ok, len(tt.current))
			}

			// The acceptance criterion: the next scan has no MOAT-T2 finding
			// for the server, no diff, no stderr, and exit code 0.
			next := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tt.current}))
			assertScanRun(t, next, scanWant{code: exitOK})
			assertNoPinRows(t, next.stdout)
		})
	}
}

// TestPinAcceptKeepsOtherServers checks that pin changes the entry of the
// accepted server only. The pins of every other server stay as they were, also
// when that server has a change that scan reports.
func TestPinAcceptKeepsOtherServers(t *testing.T) {
	t.Parallel()

	servers := map[string]any{
		"target": map[string]any{"command": "npx"},
		"other":  map[string]any{"command": "npx"},
		"third":  map[string]any{"command": "npx"},
	}
	e := newPinEnv(t, servers)
	firstScan := fakeServers(map[string][]inspect.Tool{
		"target": {mkTool("a", "Add."), mkTool("b", "Echo.")},
		"other":  {mkTool("o", "Other.")},
		"third":  {mkTool("t1", "Third."), mkTool("t2", "Third too.")},
	})
	if got := e.scan(firstScan); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}
	before := e.readPins()
	otherBefore, _ := before.tools("other")
	thirdBefore, _ := before.tools("third")
	targetBefore, _ := before.tools("target")

	// target changes, and other changes too, but pin accepts only target.
	current := fakeServers(map[string][]inspect.Tool{
		"target": {mkTool("a", "Add. Changed."), mkTool("c", "New.")},
		"other":  {mkTool("o", "Other. Changed.")},
		"third":  {mkTool("t1", "Third."), mkTool("t2", "Third too.")},
	})

	got := e.pin(current, "--accept", "target")

	assertPinRun(t, got, scanWant{code: exitOK, stdout: []string{"accepted target: 1 new, 1 changed, 1 removed\n"}, stderr: []string{noExpectNote}})
	assertNoExpectNote(t, got.stderr)
	if calls := current.Calls(); !slices.Equal(calls, []string{"target"}) {
		t.Errorf("inspector calls = %v, want only [target]", calls)
	}
	after := e.readPins()
	if got := after.serverNames(); !slices.Equal(got, []string{"other", "target", "third"}) {
		t.Errorf("servers in pins.json = %v, want [other target third]", got)
	}
	otherAfter, _ := after.tools("other")
	thirdAfter, _ := after.tools("third")
	targetAfter, _ := after.tools("target")
	if !reflect.DeepEqual(otherBefore, otherAfter) {
		t.Errorf("the pins of other changed\nbefore: %v\nafter:  %v", otherBefore, otherAfter)
	}
	if !reflect.DeepEqual(thirdBefore, thirdAfter) {
		t.Errorf("the pins of third changed\nbefore: %v\nafter:  %v", thirdBefore, thirdAfter)
	}
	if reflect.DeepEqual(targetBefore, targetAfter) {
		t.Errorf("the pins of target did not change: %v", targetAfter)
	}
	if got := slices.Sorted(maps.Keys(targetAfter)); !slices.Equal(got, []string{"a", "c"}) {
		t.Errorf("pinned tools of target = %v, want [a c]", got)
	}

	// The next scan reports no finding for target, but still reports other.
	next := e.scan(current)
	assertScanRun(t, next, scanWant{code: exitFindings, stdout: []string{"MOAT-T2-001"}})
	out := splitPinOutput(t, next.stdout)
	want := []pinFindingRow{{"MOAT-T2-001", "high", "other", "tool", "o"}}
	if !slices.Equal(out.rows, want) {
		t.Errorf("rows after pin = %+v, want %+v", out.rows, want)
	}
	assertDiffsOf(t, out.diffs, "other", []string{"o"})
}

// TestPinAcceptAfterScanReview checks the whole flow of FR-13: scan reports a
// changed tool, exits 1 and prints the digest of the tools that it saw, pin
// --accept --expect with that digest accepts the tools, and the next scan is
// clean.
func TestPinAcceptAfterScanReview(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}
	changed := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add. Now it also reads your keys.")}})

	review := e.scan(changed)
	assertScanRun(t, review, scanWant{
		code:   exitFindings,
		stdout: []string{"MOAT-T2-001", "high", "Changed tool a on server srv:", "--- pinned", "+++ current", "reads your keys"},
	})
	digest := hintDigest(t, review.stdout, "srv")

	accepted := e.pin(changed, "--accept", "srv", "--expect", digest)
	assertPinRun(t, accepted, scanWant{code: exitOK, stdout: []string{"accepted srv: 0 new, 1 changed, 0 removed\n"}})
	assertCleanStderr(t, accepted.stderr) // --expect is given: no note

	clean := e.scan(changed)
	assertScanRun(t, clean, scanWant{code: exitOK})
	assertNoPinRows(t, clean.stdout)
	if strings.Contains(clean.stdout, acceptHintPrefix) {
		t.Errorf("the scan after the accept has an accept hint, want none:\n%s", clean.stdout)
	}
}

// TestPinNoSecretLeak checks that no env, header, URL or args value of the
// config reaches pins.json or the output of pin, also on an error. The scan
// test in scan_pins_test.go covers the output of scan.
func TestPinNoSecretLeak(t *testing.T) {
	t.Parallel()

	const (
		envValue    = "mcpmoat-canary-env-pin-3Zp9Qd"
		headerValue = "mcpmoat-canary-header-pin-8Lk2Vr"
	)
	servers := map[string]any{
		"stdio-srv": map[string]any{
			"command": "npx",
			"env":     map[string]string{"API_TOKEN": envValue},
		},
		"http-srv": map[string]any{
			"type":    "http",
			"url":     "https://example.invalid/mcp",
			"headers": map[string]string{"Authorization": "Bearer " + headerValue},
		},
	}
	e := newPinEnv(t, servers)
	tools := map[string][]inspect.Tool{"stdio-srv": {mkTool("a", "Add.")}, "http-srv": {mkTool("h", "Http.")}}

	for _, name := range []string{"stdio-srv", "http-srv"} {
		got := e.pin(fakeServers(tools), "--accept", name)
		assertPinRun(t, got, scanWant{code: exitOK, stdout: []string{"accepted " + name + ": "}, stderr: []string{noExpectNote}})
		assertNoExpectNote(t, got.stderr)
		assertContainsNone(t, "stdout", got.stdout, []string{envValue, headerValue})
		assertContainsNone(t, "stderr", got.stderr, []string{envValue, headerValue})
	}
	// An error path: the inspector fails.
	failed := e.pin(&inspecttest.Fake{Errors: map[string]error{"stdio-srv": errors.New("boom")}}, "--accept", "stdio-srv")
	assertPinRun(t, failed, scanWant{code: exitError, stderr: []string{"failed"}})
	assertContainsNone(t, "stderr", failed.stderr, []string{envValue, headerValue})

	pinsText := string(readFileBytes(t, e.pinsPath()))
	assertContainsNone(t, "pins.json", pinsText, []string{envValue, headerValue, "API_TOKEN", "Authorization", "example.invalid"})
}

// splitAcceptedLine splits the stdout of "pin --accept" into the text before the
// last line, which holds the diffs, and the last line (with its newline), which
// is the "accepted" line.
func splitAcceptedLine(stdout string) (before, accepted string) {
	trimmed := strings.TrimSuffix(stdout, "\n")
	i := strings.LastIndex(trimmed, "\n")
	return stdout[:i+1], stdout[i+1:]
}

// TestPinAcceptShowsDiffBeforeAccepted checks that "pin --accept" prints the
// diff of each changed tool on stdout, before the "accepted" line, and that
// the diff is the same text as the scan prints (M1).
func TestPinAcceptShowsDiffBeforeAccepted(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	pinned := []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo."), mkTool("c", "Keep.")}
	if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": pinned})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}
	current := fakeServers(map[string][]inspect.Tool{"srv": {
		mkTool("a", "Add. Now it also reads your keys."), mkTool("b", "Echo. Also this."), mkTool("c", "Keep."),
	}})
	review := e.scan(current)
	if review.code != exitFindings {
		t.Fatalf("review scan: exit code = %d, want %d\n%s", review.code, exitFindings, review.stderr)
	}

	got := e.pin(current, "--accept", "srv")

	assertPinRun(t, got, scanWant{
		code:   exitOK,
		stdout: []string{"Changed tool a on server srv:", "Changed tool b on server srv:", "--- pinned", "+++ current", "reads your keys"},
		stderr: []string{noExpectNote},
	})
	assertNoExpectNote(t, got.stderr)
	diffs, accepted := splitAcceptedLine(got.stdout)
	if want := "accepted srv: 0 new, 2 changed, 0 removed\n"; accepted != want {
		t.Errorf("last line = %q, want %q", accepted, want)
	}
	assertDiffsOf(t, diffs, "srv", []string{"a", "b"})
	if i, j := strings.Index(got.stdout, "Changed tool a"), strings.Index(got.stdout, "accepted srv"); i < 0 || j < i {
		t.Errorf("the diff must come before the accepted line\n%s", got.stdout)
	}
	// The diffs are the text that the scan printed after its findings table.
	// Every diff block starts with a blank line; splitPinOutput cuts the first.
	if scanDiffs := splitPinOutput(t, review.stdout).diffs; strings.TrimPrefix(diffs, "\n") != scanDiffs {
		t.Errorf("pin diffs differ from the scan diffs\npin:\n%s\nscan:\n%s", diffs, scanDiffs)
	}
}

// TestPinAcceptNoDiffWithoutChange checks that pin prints no diff block for a
// new tool, a removed tool or an unchanged tool: only a changed tool has one.
func TestPinAcceptNoDiffWithoutChange(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add."), mkTool("b", "Echo.")}})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}

	got := e.pin(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add."), mkTool("c", "New.")}}), "--accept", "srv")

	assertPinRun(t, got, scanWant{code: exitOK, noStdout: []string{"Changed tool", "--- pinned"}, stderr: []string{noExpectNote}})
	assertNoExpectNote(t, got.stderr)
	if want := "accepted srv: 1 new, 0 changed, 1 removed\n"; got.stdout != want {
		t.Errorf("stdout = %q, want %q", got.stdout, want)
	}
}

// TestPinInterrupted checks that a signal during the inspection (S1) gives exit
// code 2, one fixed line on stderr, nothing on stdout and no change to
// pins.json, even though the fake server has an answer.
func TestPinInterrupted(t *testing.T) {
	t.Parallel()

	const notice = "mcpmoat pin: interrupted; no pins were saved\n"

	tests := []struct {
		name     string
		pinFirst bool
	}{
		{name: "unpinned server"},
		{name: "pinned server that changed", pinFirst: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			if tt.pinFirst {
				if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})); got.code != exitOK {
					t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
				}
			}
			var pinsBefore []byte
			if tt.pinFirst {
				pinsBefore = readFileBytes(t, e.pinsPath())
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add. Changed."), mkTool("b", "New.")}})
			c, stdout, stderr := e.cli(cancelingInspector{inner: fake, cancel: cancel})
			c.ctx = ctx

			code := c.dispatch([]string{"pin", "--config", e.config, "--accept", "srv"})

			got := pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
			assertPinRun(t, got, scanWant{code: exitError, stderr: []string{notice}})
			if got.stderr != notice {
				t.Errorf("stderr = %q, want only %q", got.stderr, notice)
			}
			assertEmptyStdout(t, got.stdout)
			if tt.pinFirst {
				if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(pinsBefore, after) {
					t.Errorf("pins.json changed in an interrupted pin\nbefore: %s\nafter:  %s", pinsBefore, after)
				}
			} else if _, err := os.Stat(e.pinsPath()); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("pins.json exists after an interrupted pin (stat error = %v), want nothing stored", err)
			}
		})
	}
}
