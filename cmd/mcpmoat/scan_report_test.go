package main

// In-process tests of the terminal safety of the scan report (issue #63): text
// that a server controls must never reach the terminal as a control sequence,
// and output that is not for a terminal has no colour.
//
// TestScanTerminalSafety and TestScanColorGolden cover the config side (a
// hostile server name, command and args) and the colour of a clean report.
// These tests cover the server side: a tool description or name, an
// inspection warning and a failure reason. They use a fake inspector and a
// pinEnv (pins_helpers_test.go), so no server starts and nothing touches the
// real $HOME or the real pins.json. No test calls t.Setenv, so all can run in
// parallel.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

// Hostile text, as a server or a config could send it. Each one holds an ANSI
// CSI sequence (colour and "clear screen"), an OSC 8 hyperlink, an OSC title,
// a bidi override (U+202E), a carriage return and bytes that are not UTF-8.
const (
	hostileText = "Read files.\x1b[31m RED \x1b[2J\x1b]8;;http://evil\x07link\x1b]8;;\x07 \u202egnp.exe\rOVERWRITE end"
	hostileName = "t\x1b[2Jool\u202e"
	hostileKey  = "X-Key\x1b[31m\nSUMMARY"
	hostileFail = "boom \x1b]0;title\x07 \u202e\r\nnext\xff"
)

// scanRunTTY runs "scan --config" in e with insp. tty is the answer of the
// terminal check: colour is possible only when it is true.
func scanRunTTY(e *pinEnv, insp inspect.Inspector, tty bool) pinRunResult {
	e.t.Helper()
	c, stdout, stderr := e.cli(insp)
	c.stdoutIsTTY = tty
	code := c.dispatch([]string{"scan", "--config", e.config})
	return pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// assertNoControlOutput checks a plain run (no colour): neither stream holds
// an ESC, a carriage return, a bidi override or any other unsafe rune, and
// both streams are valid UTF-8.
func assertNoControlOutput(t *testing.T, r pinRunResult) {
	t.Helper()
	assertNoEscape(t, r.stdout, r.stderr)
	for name, out := range map[string]string{"stdout": r.stdout, "stderr": r.stderr} {
		if strings.ContainsAny(out, "\r\u202e\x07") {
			t.Errorf("%s has a raw CR, BEL or U+202E\n%q", name, out)
		}
		if !utf8.ValidString(out) {
			t.Errorf("%s is not valid UTF-8\n%q", name, out)
		}
		assertTerminalSafe(t, out)
	}
}

// assertHostileSafe runs the scan of e twice with insp, without a terminal and
// with one, and checks both runs. It returns the plain run.
//
// The coloured run may hold the SGR codes of the report, so a check on the
// stripped text alone would hide a hostile "\x1b[31m" that the report passed
// through. So the stripped coloured text must equal the plain text: the SGR
// codes of the report are then the only difference.
func assertHostileSafe(t *testing.T, e *pinEnv, insp inspect.Inspector, wantCode int) pinRunResult {
	t.Helper()

	// The first scan of a server pins it and says so on stderr. The warm-up run
	// takes that note out of the way, so the two runs below are comparable.
	assertNoControlOutput(t, scanRunTTY(e, insp, false))

	plain := scanRunTTY(e, insp, false)
	if plain.code != wantCode {
		t.Fatalf("plain run: exit code = %d, want %d\nstderr:\n%s", plain.code, wantCode, plain.stderr)
	}
	assertNoControlOutput(t, plain)

	colored := scanRunTTY(e, insp, true)
	if colored.code != wantCode {
		t.Fatalf("colour run: exit code = %d, want %d\nstderr:\n%s", colored.code, wantCode, colored.stderr)
	}
	if !strings.Contains(colored.stdout, "\x1b[") {
		t.Errorf("colour is on, but stdout has no SGR sequence\n%q", colored.stdout)
	}
	if got := stripSGR(colored.stdout); got != plain.stdout {
		t.Errorf("stdout without SGR differs from the plain stdout\n--- got ---\n%q\n--- want ---\n%q", got, plain.stdout)
	}
	if colored.stderr != plain.stderr {
		t.Errorf("stderr differs when colour is on\n--- got ---\n%q\n--- want ---\n%q", colored.stderr, plain.stderr)
	}
	assertNoControlOutput(t, pinRunResult{stdout: stripSGR(colored.stdout), stderr: colored.stderr})
	return plain
}

// TestScanReportHostileTools checks that a hostile tool description and a
// hostile tool name of a pinned server are escaped in the diffs, with colour
// off and on. The description is the first place where server text reaches
// the terminal.
func TestScanReportHostileTools(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// pinned are the tools of the first scan; now are the tools that the
		// server offers in the scan that is checked.
		pinned, now []inspect.Tool
		// wantCode is the exit code: a changed tool is a high finding, a new
		// tool a medium one, and --fail-on is high by default.
		wantCode    int
		wantHeader  string
		wantEscaped []string
	}{
		{
			name:        "changed tool, hostile description",
			wantCode:    exitFindings,
			pinned:      []inspect.Tool{mkTool("read", "Read files.")},
			now:         []inspect.Tool{mkTool("read", hostileText)},
			wantHeader:  "Changed tool read on server srv:",
			wantEscaped: []string{`\x1b[31m`, `\x1b[2J`, `\x1b]8;;http://evil\a`, `\u202e`, `\r`},
		},
		{
			name:        "new tool, hostile description",
			wantCode:    exitOK,
			pinned:      []inspect.Tool{mkTool("read", "Read files.")},
			now:         []inspect.Tool{mkTool("read", "Read files."), mkTool("write", hostileText)},
			wantHeader:  "New tool write on server srv:",
			wantEscaped: []string{`\x1b[31m`, `\x1b[2J`, `\x1b]8;;http://evil\a`, `\u202e`, `\r`},
		},
		{
			name:        "new tool, hostile name",
			wantCode:    exitOK,
			pinned:      []inspect.Tool{mkTool("read", "Read files.")},
			now:         []inspect.Tool{mkTool("read", "Read files."), mkTool(hostileName, hostileText)},
			wantEscaped: []string{`\x1b[2J`, `\u202e`},
		},
		{
			// Text that is not UTF-8 cannot be hashed, so the report has an
			// "invalid tool data" finding and no diff. It must be safe too.
			name:     "tool text that is not UTF-8",
			wantCode: exitFindings,
			pinned:   []inspect.Tool{mkTool("read", "Read files.")},
			now:      []inspect.Tool{mkTool("read", hostileText+"\xff\xfe"), mkTool("bad\xff\x1b[2J", "x\xff")},
		},
		{
			name:        "changed tool, hostile name and description",
			wantCode:    exitFindings,
			pinned:      []inspect.Tool{mkTool(hostileName, "Old.")},
			now:         []inspect.Tool{mkTool(hostileName, hostileText)},
			wantEscaped: []string{`\x1b[2J`, `\u202e`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := newPinEnv(t, oneServer("srv"))
			firstScan(t, e, tt.pinned...)
			insp := fakeServers(map[string][]inspect.Tool{"srv": tt.now})

			plain := assertHostileSafe(t, e, insp, tt.wantCode)

			if tt.wantHeader != "" && !strings.Contains(plain.stdout, tt.wantHeader) {
				t.Errorf("stdout does not contain the header %q\n%s", tt.wantHeader, plain.stdout)
			}
			for _, want := range tt.wantEscaped {
				if !strings.Contains(plain.stdout, want) {
					t.Errorf("stdout does not show the escape %s\n%q", want, plain.stdout)
				}
			}
			// The report keeps its shape: one server in the summary.
			if rows := summaryRows(t, plain.stdout); len(rows) != 1 || rows[0].Name != "srv" {
				t.Errorf("summary = %+v, want one server srv", rows)
			}
		})
	}
}

// TestScanReportHostileWarning checks that a hostile header key in an
// inspection warning is escaped, and that a newline in the key does not make
// a new line in the SUMMARY block.
func TestScanReportHostileWarning(t *testing.T) {
	t.Parallel()

	warning := inspect.Warning{Kind: inspect.WarnCleartextSecrets, HeaderKeys: []string{hostileKey, "Authorization"}}
	connectErr := &inspect.ConnectError{
		Kind:     inspect.KindNetwork,
		Server:   "srv",
		Reason:   "refused",
		Warnings: []inspect.Warning{warning},
	}

	tests := []struct {
		name     string
		insp     inspect.Inspector
		wantCode int
	}{
		{
			name: "warning of an inspection that worked",
			insp: &inspecttest.Fake{Results: map[string]inspect.Result{
				"srv": {ServerName: "srv", Tools: []inspect.Tool{mkTool("read", "Read files.")}, Warnings: []inspect.Warning{warning}},
			}},
		},
		{
			name: "warning of an inspection that failed",
			insp: &inspecttest.Fake{Errors: map[string]error{"srv": connectErr}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := newPinEnv(t, oneServer("srv"))

			plain := assertHostileSafe(t, e, tt.insp, tt.wantCode)

			// The key shows escaped, with its newline as \n, in the summary.
			for _, want := range []string{`\x1b[31m`, `\n`, "Authorization"} {
				if !strings.Contains(plain.stdout, want) {
					t.Errorf("stdout does not contain %s\n%q", want, plain.stdout)
				}
			}
			rows := summaryRows(t, plain.stdout)
			if len(rows) != 1 || rows[0].Name != "srv" || len(rows[0].Warnings) != 1 {
				t.Errorf("summary = %+v, want one server srv with one warning\n%q", rows, plain.stdout)
			}
			if got := strings.Count("\n"+plain.stdout, "\nSUMMARY\n"); got != 1 {
				t.Errorf("stdout has %d SUMMARY headings, want 1: the key must not forge a heading\n%q", got, plain.stdout)
			}
		})
	}
}

// TestScanReportHostileFailure checks that a hostile reason of a failed
// inspection is escaped, for a plain error and for a *inspect.ConnectError.
func TestScanReportHostileFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{"plain error", errors.New(hostileFail)},
		{"connect error", &inspect.ConnectError{Kind: inspect.KindProtocol, Server: "srv", Reason: hostileFail}},
		{"connect error with a hostile URL part", &inspect.ConnectError{Kind: inspect.KindHTTP, Server: "srv", Status: 502, Reason: hostileFail, URL: "https://h.example/\x1b[2J"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := newPinEnv(t, oneServer("srv"))
			insp := &inspecttest.Fake{Errors: map[string]error{"srv": tt.err}}

			plain := assertHostileSafe(t, e, insp, exitOK)

			if !strings.Contains(plain.stdout+plain.stderr, `\x1b]0;title\a`) {
				t.Errorf("the output does not show the escaped reason\nstdout: %q\nstderr: %q", plain.stdout, plain.stderr)
			}
			rows := summaryRows(t, plain.stdout)
			if len(rows) != 1 || rows[0].Name != "srv" || rows[0].Status != "failed" {
				t.Errorf("summary = %+v, want one failed server srv\n%q", rows, plain.stdout)
			}
		})
	}
}

// TestIsTerminalPipedOutput checks the real decision path of the colour: a
// regular file, a pipe and a closed file are not terminals, so output that is
// redirected to them has no colour. (A real terminal is not tested here.)
func TestIsTerminalPipedOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		open func(t *testing.T) *os.File
	}{
		{"regular file", func(t *testing.T) *os.File {
			f, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			return f
		}},
		{"pipe writer", func(t *testing.T) *os.File {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
			return w
		}},
		{"pipe reader", func(t *testing.T) *os.File {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
			return r
		}},
		{"closed file", func(t *testing.T) *os.File {
			f, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			return f
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if isTerminal(tt.open(t)) {
				t.Errorf("isTerminal = true, want false")
			}
		})
	}
}

// TestRunWithContextBufferHasNoColor checks that runWithContext decides about
// colour from the stdout writer that it gets, not from os.Stdout. A bytes.Buffer
// is not a terminal, so the report has no ESC byte, even with no flag and with
// NO_COLOR empty. The test points HOME, XDG_CONFIG_HOME and the working
// directory at temporary folders, so it never reads the real home. It changes
// the environment, so it does not run in parallel.
func TestRunWithContextBufferHasNoColor(t *testing.T) {
	home, work := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("NO_COLOR", "")
	t.Chdir(work)
	writeServers(t, home, ".claude.json", map[string]any{
		"github": map[string]any{
			"command": "npx",
			"args":    []string{"-y", "github-mcp"},
		},
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--no-connect"}, &stdout, &stderr)

	if code != exitOK && code != exitFindings {
		t.Fatalf("exit code = %d, want %d or %d\nstderr: %s", code, exitOK, exitFindings, stderr.String())
	}
	if !strings.Contains(stdout.String(), "github") {
		t.Fatalf("stdout does not show the server:\n%s", stdout.String())
	}
	if strings.ContainsRune(stdout.String(), '\x1b') {
		t.Errorf("stdout holds an ESC byte, want plain text:\n%q", stdout.String())
	}
}

// TestScanReportNoColorWithoutTerminal checks that a scan that connects, with
// no terminal and no flag, writes no ESC byte, also with a pin finding and a
// diff in the report. TestScanColorGolden covers the --no-connect report.
func TestScanReportNoColorWithoutTerminal(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	firstScan(t, e, mkTool("read", "Read files."))

	got := scanRunTTY(e, fakeServers(map[string][]inspect.Tool{"srv": {mkTool("read", "Changed.")}}), false)

	if strings.TrimSpace(got.stdout) == "" {
		t.Fatal("stdout is empty")
	}
	assertNoEscape(t, got.stdout, got.stderr)
}
