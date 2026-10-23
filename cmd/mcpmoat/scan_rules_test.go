package main

// In-process tests of the --rules flag of "mcpmoat scan". They call
// c.dispatch with empty home and working directories, so they never read the
// real $HOME or real client configs. None of them calls t.Setenv, so all of
// them can run in parallel.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// scanRulesFixture returns the path of a directory under testdata/rules at the
// repository root. Tests run in cmd/mcpmoat, so the root is two levels up.
func scanRulesFixture(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata", "rules"}, parts...)...)
}

// scanRulesResult is the outcome of one scan run.
type scanRulesResult struct {
	code           int
	stdout, stderr string
}

// scanRulesEmpty runs "mcpmoat scan args..." with a new empty home and a
// new empty working directory, so auto-discovery finds no server.
func scanRulesEmpty(t *testing.T, args ...string) scanRulesResult {
	t.Helper()
	return scanIn(t, t.TempDir(), t.TempDir(), args...)
}

// scanIn runs "mcpmoat scan args..." with the given home and working
// directory.
func scanIn(t *testing.T, home, work string, args ...string) scanRulesResult {
	t.Helper()
	c, stdout, stderr := dirsCLI(t, home, work)
	code := c.dispatch(append([]string{"scan"}, args...))
	return scanRulesResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// firstUnsafeRune returns the first rune of s that can change a terminal or
// hide text, and its byte offset. The newline that ends a line is allowed. The
// unsafe runes are:
//   - the C0 controls (below 0x20, including ESC), DEL (0x7f) and the C1
//     controls U+0080 to U+009F (U+009B is CSI), all from unicode.IsControl;
//   - the format characters (category Cf): the bidi controls such as U+202E,
//     the zero-width characters such as U+200B, the tag characters;
//   - the line and paragraph separators U+2028 and U+2029;
//   - a byte that is not valid UTF-8, because a terminal can read a lone
//     0x9b byte as CSI.
func firstUnsafeRune(s string) (r rune, offset int, found bool) {
	for i, r := range s {
		switch {
		case r == '\n':
			continue
		case r == utf8.RuneError:
			// range gives U+FFFD for an invalid byte. A real U+FFFD in the
			// text is 3 bytes long and is safe.
			if _, size := utf8.DecodeRuneInString(s[i:]); size == 1 {
				return r, i, true
			}
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == '\u2028', r == '\u2029':
			return r, i, true
		}
	}
	return 0, 0, false
}

// assertScanRulesStderr fails the test if stderr holds a rune that can change
// the terminal or hide text (see firstUnsafeRune). The newline that ends a
// line is the only control character it accepts.
func assertScanRulesStderr(t *testing.T, stderr string) {
	t.Helper()
	if r, i, found := firstUnsafeRune(stderr); found {
		t.Errorf("stderr has the unsafe rune %U at offset %d\nstderr: %q", r, i, stderr)
	}
}

// TestFirstUnsafeRune checks the helper that the escape tests rely on: it must
// find every kind of unsafe rune and accept plain text, a newline and a
// printable non-ASCII letter.
func TestFirstUnsafeRune(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want rune // 0 means safe
	}{
		{"plain text", "mcpmoat scan: ok\n", 0},
		{"printable non-ASCII", "caf\u00e9 \u65e5\u672c \ufffd", 0},
		{"ESC", "a\x1bb", 0x1b},
		{"DEL", "a\x7fb", 0x7f},
		{"tab", "a\tb", '\t'},
		{"carriage return", "a\rb", '\r'},
		{"C1 CSI", "a\u009bb", 0x9b},
		{"C1 NEL", "a\u0085b", 0x85},
		{"bidi override", "a\u202eb", 0x202e},
		{"bidi isolate", "a\u2066b", 0x2066},
		{"zero-width space", "a\u200bb", 0x200b},
		{"BOM", "a\ufeffb", 0xfeff},
		{"tag character", "a\U000e0041b", 0xe0041},
		{"line separator", "a\u2028b", 0x2028},
		{"paragraph separator", "a\u2029b", 0x2029},
		{"invalid UTF-8 byte", "a\x9bb", utf8.RuneError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, _, found := firstUnsafeRune(tt.in)
			if found != (tt.want != 0) || (found && got != tt.want) {
				t.Errorf("firstUnsafeRune(%q) = %U, %v; want %U", tt.in, got, found, tt.want)
			}
		})
	}
}

// dirSnapshot returns one line for each entry under dir: the relative path,
// the mode, and for a regular file the size and the content. Two snapshots
// are equal when nothing was created, removed or changed.
func dirSnapshot(t *testing.T, dir string) []string {
	t.Helper()
	var lines []string
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil // a folder that does not exist has nothing to compare
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		line := rel + " " + info.Mode().String()
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path) //nolint:gosec // G304: path comes from walking a test directory
			if err != nil {
				return err
			}
			line += " " + string(data)
		}
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot of %s: %v", dir, err)
	}
	return lines
}

// copyRuleFile copies the fixture file src to dir/name.
func copyRuleFile(t *testing.T, src, dir, name string) {
	t.Helper()
	data, err := os.ReadFile(src) //nolint:gosec // G304: src is a fixed fixture path in the test
	if err != nil {
		t.Fatal(err)
	}
	// Write directly instead of through writeTestFile: gosec's taint analysis
	// follows the fixture bytes read above into that shared helper and reports
	// its os.WriteFile as a path traversal.
	dst := filepath.Join(dir, filepath.Base(name))
	if err := os.WriteFile(dst, data, 0o600); err != nil { //nolint:gosec // G703: copies a repo fixture to a fixed name under the test's own t.TempDir()
		t.Fatal(err)
	}
}

// TestScanRulesNoFlag checks that a scan without --rules keeps its output:
// the "No MCP servers found." line on stdout and only the notice on stderr.
func TestScanRulesNoFlag(t *testing.T) {
	t.Parallel()

	got := scanRulesEmpty(t, "--no-connect")

	assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{code: exitOK})
	if want := "No MCP servers found.\n"; got.stdout != want {
		t.Errorf("stdout = %q, want %q", got.stdout, want)
	}
}

// TestScanRulesAccepted checks that valid rule folders give exit code 0 and
// the same output as a scan without --rules, because the rules are loaded
// but not applied yet.
func TestScanRulesAccepted(t *testing.T) {
	t.Parallel()

	extraFile := filepath.Join(scanRulesFixture("extra"), "MOAT-X-001.yaml")

	tests := []struct {
		name string
		// dir returns the rules folder for the case.
		dir func(t *testing.T) string
	}{
		{
			name: "valid external rule",
			dir:  func(*testing.T) string { return scanRulesFixture("extra") },
		},
		{
			name: "yml file name",
			dir: func(t *testing.T) string {
				dir := t.TempDir()
				copyRuleFile(t, extraFile, dir, "MOAT-X-001.yml")
				return dir
			},
		},
		{
			name: "folder and txt file are ignored",
			dir: func(t *testing.T) string {
				dir := t.TempDir()
				copyRuleFile(t, extraFile, dir, "MOAT-X-001.yaml")
				// A rule in a subfolder or in a .txt file is not loaded. If it
				// were, its bad content would fail the scan.
				writeTestFile(t, dir, filepath.Join("sub", "broken.yaml"), "not: [valid\n")
				writeTestFile(t, dir, "notes.txt", "not: [valid\n")
				return dir
			},
		},
		{
			name: "empty folder",
			dir:  func(t *testing.T) string { return t.TempDir() },
		},
	}

	home, work := t.TempDir(), t.TempDir()
	base := scanIn(t, home, work, "--no-connect")
	assertScanResult(t, base.code, base.stdout, base.stderr, scanWant{code: exitOK})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := tt.dir(t)
			before := dirSnapshot(t, dir)

			got := scanIn(t, home, work, "--no-connect", "--rules", dir)

			assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{code: exitOK})
			if got.stdout != base.stdout || got.stderr != base.stderr {
				t.Errorf("output differs from the scan without --rules\nstdout: %q (want %q)\nstderr: %q (want %q)",
					got.stdout, base.stdout, got.stderr, base.stderr)
			}
			if after := dirSnapshot(t, dir); !slices.Equal(before, after) {
				t.Errorf("the rules folder changed\nbefore: %q\nafter:  %q", before, after)
			}
		})
	}
}

// TestScanRulesWithConnect checks the mode without --no-connect. The rules
// are loaded before the step that connects, so valid rules give the same
// result as a scan without --rules (today: exit code 2, "not implemented
// yet", because connecting is not built). The scan never starts a server:
// home and working directory are empty.
func TestScanRulesWithConnect(t *testing.T) {
	t.Parallel()

	home, work := t.TempDir(), t.TempDir()
	base := scanIn(t, home, work)
	if base.code != exitError || !strings.Contains(base.stderr, "connecting to servers is not implemented yet") {
		t.Fatalf("scan without --rules: exit code = %d, stderr = %q", base.code, base.stderr)
	}

	got := scanIn(t, home, work, "--rules", scanRulesFixture("extra"))

	if got != base {
		t.Errorf("valid --rules changes the result\ngot:  %+v\nwant: %+v", got, base)
	}
	assertScanErrorLines(t, got.stderr)
}

// TestScanRulesErrors checks that a bad rules folder gives exit code 2, an
// empty stdout and one "mcpmoat scan: " line on stderr for the problem. It
// runs every case in both modes, because the rules are checked before scan
// looks at --no-connect.
func TestScanRulesErrors(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "does", "not", "exist")
	regularFile := writeTestFile(t, t.TempDir(), "rules.yaml", "id: x\n")

	tests := []struct {
		name       string
		dir        string
		wantStderr []string
	}{
		{
			name:       "invalid severity",
			dir:        scanRulesFixture("invalid"),
			wantStderr: []string{"mcpmoat scan: ", "bad-severity.yaml", ":4:11", "field severity"},
		},
		{
			name: "ID clashes with a built-in rule",
			dir:  scanRulesFixture("collide"),
			wantStderr: []string{
				"mcpmoat scan: ", filepath.Join(scanRulesFixture("collide"), "MOAT-T1-003.yaml"),
				"rule ID clashes with a built-in rule",
			},
		},
		{
			name:       "the built-in ID in a copy of the built-in rule",
			dir:        scanRulesFixture("valid"),
			wantStderr: []string{"mcpmoat scan: ", "MOAT-T1-003.yaml", "rule ID clashes with a built-in rule"},
		},
		{
			name:       "folder does not exist",
			dir:        missing,
			wantStderr: []string{"mcpmoat scan: ", "cannot read directory"},
		},
		{
			name:       "path is a regular file",
			dir:        regularFile,
			wantStderr: []string{"mcpmoat scan: ", "cannot read directory"},
		},
	}

	modes := []struct {
		name string
		args []string
	}{
		{"with --no-connect", []string{"--no-connect"}},
		{"without --no-connect", nil},
	}

	for _, tt := range tests {
		for _, mode := range modes {
			t.Run(tt.name+" "+mode.name, func(t *testing.T) {
				t.Parallel()
				before := dirSnapshot(t, tt.dir)

				got := scanRulesEmpty(t, append(slices.Clone(mode.args), "--rules", tt.dir)...)

				assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{
					code:   exitError,
					stderr: tt.wantStderr,
				})
				if got.stdout != "" {
					t.Errorf("stdout = %q, want it empty", got.stdout)
				}
				if strings.Contains(got.stderr, "not implemented yet") {
					t.Errorf("the rules error must come before the connect step\nstderr: %q", got.stderr)
				}
				if lines := nonEmptyLines(got.stderr); len(lines) != 1 {
					t.Errorf("stderr has %d lines, want 1\nstderr: %q", len(lines), got.stderr)
				}
				assertScanRulesStderr(t, got.stderr)
				if after := dirSnapshot(t, tt.dir); !slices.Equal(before, after) {
					t.Errorf("the rules folder changed\nbefore: %q\nafter:  %q", before, after)
				}
			})
		}
	}
}

// TestScanRulesFlagErrors checks the errors of the --rules flag itself.
func TestScanRulesFlagErrors(t *testing.T) {
	t.Parallel()

	const usageHint = `Run "mcpmoat help" for usage.`
	extra := scanRulesFixture("extra")

	tests := []struct {
		name       string
		args       []string
		wantStderr []string
		noStderr   []string
	}{
		{
			name:       "given twice",
			args:       []string{"--no-connect", "--rules", extra, "--rules", extra},
			wantStderr: []string{"--rules given more than once"},
		},
		{
			name:       "given twice with different folders",
			args:       []string{"--no-connect", "--rules", "a", "--rules", "b"},
			wantStderr: []string{"--rules given more than once"},
			noStderr:   []string{"cannot read directory"},
		},
		{
			name:       "empty value",
			args:       []string{"--no-connect", "--rules", ""},
			wantStderr: []string{"--rules needs a folder name"},
		},
		{
			name:       "empty value with equals sign",
			args:       []string{"--no-connect", "--rules="},
			wantStderr: []string{"--rules needs a folder name"},
		},
		{
			// The flag package would take --no-connect as the folder name.
			// scan refuses it, and it must not try to read a folder named
			// "--no-connect".
			name:       "value that looks like a flag",
			args:       []string{"--rules", "--no-connect"},
			wantStderr: []string{"--rules needs a folder name"},
			noStderr:   []string{"cannot read directory", "not implemented yet"},
		},
		{
			name:       "value that looks like a flag with a value",
			args:       []string{"--rules", "--config=x", "--no-connect"},
			wantStderr: []string{"--rules needs a folder name"},
			noStderr:   []string{"cannot read directory"},
		},
		{
			name:       "no value",
			args:       []string{"--no-connect", "--rules"},
			wantStderr: []string{"flag needs an argument"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := scanRulesEmpty(t, tt.args...)

			// A usage error prints the message and then the hint line, which
			// has no scan prefix, so assertScanResult does not fit here.
			if got.code != exitError {
				t.Errorf("exit code = %d, want %d\nstderr: %q", got.code, exitError, got.stderr)
			}
			assertContainsAll(t, "stderr", got.stderr, append([]string{"mcpmoat scan: "}, tt.wantStderr...))
			if lines := nonEmptyLines(got.stderr); len(lines) != 2 || lines[1] != usageHint {
				t.Errorf("stderr = %q, want the message and then %q", got.stderr, usageHint)
			}
			assertNoEscape(t, got.stdout, got.stderr)
			if got.stdout != "" {
				t.Errorf("stdout = %q, want it empty", got.stdout)
			}
			for _, bad := range tt.noStderr {
				if strings.Contains(got.stderr, bad) {
					t.Errorf("stderr contains %q\nstderr: %q", bad, got.stderr)
				}
			}
			assertScanRulesStderr(t, got.stderr)
		})
	}
}

// TestScanRulesUsage checks that the help of scan and the general help show
// the --rules flag.
func TestScanRulesUsage(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{{"scan", "-h"}, {"scan", "--help"}, {"help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)

			code := c.dispatch(args)

			if code != exitOK {
				t.Fatalf("exit code = %d, want %d", code, exitOK)
			}
			assertContainsAll(t, "stdout", stdout.String(), []string{"--rules <dir>", "*.yaml", "*.yml"})
			if stderr.Len() != 0 {
				t.Errorf("stderr = %q, want it empty", stderr)
			}
		})
	}
}

// TestScanRulesSeveralErrors checks that scan prints every problem, one
// "mcpmoat scan: " line each, in the order of the file names.
func TestScanRulesSeveralErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Write the files in a different order from the file names.
	writeTestFile(t, dir, "c-empty.yaml", "")
	writeTestFile(t, dir, "a-broken.yaml", "id: [unclosed\n")
	writeTestFile(t, dir, "b-unknown.yml", "colour: red\n")
	// A good rule in the same folder does not hide the problems.
	copyRuleFile(t, filepath.Join(scanRulesFixture("extra"), "MOAT-X-001.yaml"), dir, "d-good.yaml")
	before := dirSnapshot(t, dir)

	got := scanRulesEmpty(t, "--no-connect", "--rules", dir)

	assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{code: exitError})
	if got.stdout != "" {
		t.Errorf("stdout = %q, want it empty", got.stdout)
	}
	lines := nonEmptyLines(got.stderr)
	wantNames := []string{"a-broken.yaml", "b-unknown.yml", "c-empty.yaml"}
	if len(lines) != len(wantNames) {
		t.Fatalf("stderr has %d lines, want %d\nstderr:\n%s", len(lines), len(wantNames), got.stderr)
	}
	for i, name := range wantNames {
		if !strings.HasPrefix(lines[i], "mcpmoat scan: ") || !strings.Contains(lines[i], name) {
			t.Errorf("stderr line %d = %q, want the prefix and %q", i+1, lines[i], name)
		}
	}
	if strings.Contains(got.stderr, "d-good.yaml") {
		t.Errorf("stderr names the good rule file\nstderr:\n%s", got.stderr)
	}
	assertScanRulesStderr(t, got.stderr)
	if after := dirSnapshot(t, dir); !slices.Equal(before, after) {
		t.Errorf("the rules folder changed\nbefore: %q\nafter:  %q", before, after)
	}
}

// TestScanRulesEscapeSafety checks that text from a rule file or from argv
// never puts a raw control byte on stderr. The file names, the YAML keys and
// the YAML values below hold ESC, newline and other control bytes.
func TestScanRulesEscapeSafety(t *testing.T) {
	t.Parallel()

	const goodRule = `id: MOAT-X-777
title: Fixture rule
severity: low
target: description
match:
  keywords:
    - deprecated
risk: Fixture.
remediation: Fixture.
should_match:
  - deprecated
should_not_match:
  - fine
`

	tests := []struct {
		name string
		// setup writes the files and returns the folder argument. It may
		// skip the test when the file system refuses a file name.
		setup func(t *testing.T) string
	}{
		{
			name: "file name with ESC and newline",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				name := "bad\x1b[31m\nname.yaml"
				writeFileOrSkip(t, dir, name, "colour: red\n")
				return dir
			},
		},
		{
			name: "file name with ESC and newline and a valid rule",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				name := "bad\x1b[31m\nname.yaml"
				writeFileOrSkip(t, dir, name, goodRule)
				// The same ID in a second file: the duplicate error names
				// the bad file.
				writeTestFile(t, dir, "other.yaml", goodRule)
				return dir
			},
		},
		{
			name: "unknown key with ESC and newline, raw bytes",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "key.yaml", goodRule+"\"\x1b[31m\nred\": 1\n")
				return dir
			},
		},
		{
			name: "unknown key with ESC and newline, YAML escapes",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "key.yaml", goodRule+`"\x1b[31m\nred\x07\x7f\u202e": 1`+"\n")
				return dir
			},
		},
		{
			name: "unknown nested key with ESC",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "nested.yaml", strings.Replace(goodRule,
					"  keywords:\n", "  \"\\e[31m\\nkw\": [a]\n  keywords:\n", 1))
				return dir
			},
		},
		{
			name: "bad severity with ESC, YAML escapes",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "sev.yaml", strings.Replace(goodRule,
					"severity: low", `severity: "ur\x1b[31mgent\n\x00"`, 1))
				return dir
			},
		},
		{
			name: "bad severity with a raw ESC byte",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "sev.yaml", strings.Replace(goodRule,
					"severity: low", "severity: \"ur\x1b[31mgent\"", 1))
				return dir
			},
		},
		{
			name: "invalid YAML with ESC",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "yaml.yaml", "id: \x1b[31m[unclosed\n\x1b]0;title\x07")
				return dir
			},
		},
		{
			name: "file name with U+009B, U+202E and U+200B",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				name := "bad\u009b\u202e\u200bname.yaml"
				writeFileOrSkip(t, dir, name, "colour: red\n")
				return dir
			},
		},
		{
			name: "file name with U+2028 and U+2029",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				name := "bad\u2028\u2029name.yaml"
				writeFileOrSkip(t, dir, name, "colour: red\n")
				return dir
			},
		},
		{
			name: "unknown key with U+009B, U+202E and U+200B, raw runes",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "key.yaml", goodRule+"\"k\u009b\u202e\u200bx\": 1\n")
				return dir
			},
		},
		{
			// Raw U+009B makes the YAML invalid, so the case above tests the
			// syntax error. Without it the YAML is valid and the key error
			// has to escape the key itself.
			name: "unknown key with U+202E and U+200B, valid YAML with raw runes",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "key.yaml", goodRule+"\"k\u202e\u200bx\": 1\n")
				return dir
			},
		},
		{
			name: "bad severity with U+202E and U+200B, valid YAML with raw runes",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "sev.yaml", strings.Replace(goodRule,
					"severity: low", "severity: \"ur\u202e\u200bgent\"", 1))
				return dir
			},
		},
		{
			name: "unknown key with U+009B, U+202E and U+200B, YAML escapes",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "key.yaml", goodRule+`"k\u009b\u202e\u200bx": 1`+"\n")
				return dir
			},
		},
		{
			name: "unknown key with U+2028 and U+2029, YAML escapes",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "key.yaml", goodRule+`"k\u2028\u2029x": 1`+"\n")
				return dir
			},
		},
		{
			name: "bad severity with U+009B, U+202E and U+200B, raw runes",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "sev.yaml", strings.Replace(goodRule,
					"severity: low", "severity: \"ur\u009b\u202e\u200bgent\"", 1))
				return dir
			},
		},
		{
			name: "bad severity with U+009B, U+202E and U+200B, YAML escapes",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "sev.yaml", strings.Replace(goodRule,
					"severity: low", `severity: "ur\u009b\u202e\u200bgent"`, 1))
				return dir
			},
		},
		{
			name: "folder path with U+009B, U+202E and U+200B",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "no\u009b\u202e\u200bsuch")
			},
		},
		{
			name: "folder path with ESC",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "no\x1b[31m\nsuch\x7f")
			},
		},
	}

	for _, tt := range tests {
		for _, noConnect := range []bool{true, false} {
			name := tt.name + " with --no-connect"
			args := []string{"--no-connect"}
			if !noConnect {
				name = tt.name + " without --no-connect"
				args = nil
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				dir := tt.setup(t)

				got := scanRulesEmpty(t, append(slices.Clone(args), "--rules", dir)...)

				// assertScanResult checks that every stderr line has the
				// scan prefix (a raw newline from a file name would break
				// this) and that stderr has no raw ESC byte.
				assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{code: exitError})
				if got.stdout != "" {
					t.Errorf("stdout = %q, want it empty", got.stdout)
				}
				if got.stderr == "" {
					t.Error("stderr is empty, want the problem")
				}
				assertScanRulesStderr(t, got.stderr)
			})
		}
	}
}

// floodRuleFile returns the content of rule file number i of the flood
// folder: a valid header and a hostile body. The odd files have a list of
// 2000 null items (each is one error, and the loader keeps the first 20); the
// even files have 30 unknown keys. Every ID is different.
func floodRuleFile(i int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "id: MOAT-X-%03d\ntitle: Flood fixture\nseverity: low\ntarget: description\n", i)
	b.WriteString("match:\n  keywords:\n    - x\nrisk: Fixture.\nremediation: Fixture.\n")
	if i%2 == 1 {
		b.WriteString("should_match:\n")
		b.WriteString(strings.Repeat("  -\n", 2000))
		return b.String()
	}
	for k := range 30 {
		fmt.Fprintf(&b, "unknown_%02d: 1\n", k)
	}
	return b.String()
}

// floodDir writes 300 hostile rule files in a new folder and returns it.
func floodDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for i := range 300 {
		writeTestFile(t, dir, fmt.Sprintf("flood-%03d.yaml", i), floodRuleFile(i))
	}
	return dir
}

// maxFloodLines is the most stderr lines a flood may print: the loader stops
// after 100 errors and adds one "too many errors" line (maxFolderErrors+1 in
// internal/rules, which is not exported).
const maxFloodLines = 101

// floodGuard is the time a flood scan may take. The loader stops early, so the
// real time is a few milliseconds. The guard is long on purpose, so a slow
// runner with -race does not fail it; it only catches a hang. The line counts
// show that the loader stopped early.
const floodGuard = 30 * time.Second

// assertFloodResult checks the result of a scan of floodDir: exit code 2,
// empty stdout, a capped list of errors that ends with the "too many errors"
// line, and no unsafe rune.
func assertFloodResult(t *testing.T, code int, stdout, stderr string) {
	t.Helper()
	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want it empty", stdout)
	}
	lines := nonEmptyLines(stderr)
	if len(lines) < 2 || len(lines) > maxFloodLines {
		t.Fatalf("stderr has %d lines, want 2 to %d", len(lines), maxFloodLines)
	}
	assertScanErrorLines(t, stderr)
	assertContainsAll(t, "the last stderr line", lines[len(lines)-1],
		[]string{"mcpmoat scan: ", "too many errors", "files not checked"})
	assertScanRulesStderr(t, stderr)
}

// TestScanRulesErrorFlood checks that 300 hostile rule files print a capped
// list of errors on stderr and not one line per bad item.
func TestScanRulesErrorFlood(t *testing.T) {
	t.Parallel()

	dir := floodDir(t)
	start := time.Now()

	got := scanRulesEmpty(t, "--no-connect", "--rules", dir)

	if d := time.Since(start); d > floodGuard {
		t.Errorf("the scan took %v, want less than %v", d, floodGuard)
	}
	assertFloodResult(t, got.code, got.stdout, got.stderr)
}

// idFloodFiles is the number of valid rule files in an ID flood folder.
const idFloodFiles = 1000

// idFloodRule returns a valid rule file with the given ID. All the ID flood
// files have the same content, so the folder passes LoadDir and only NewSet
// finds the problem.
func idFloodRule(id string) string {
	return "id: " + id + "\ntitle: ID flood fixture\nseverity: low\ntarget: description\n" +
		"match:\n  keywords:\n    - secret\nrisk: Fixture.\nremediation: Fixture.\n" +
		"should_match:\n  - a secret value\nshould_not_match:\n  - nothing here\n"
}

// idFloodDir writes idFloodFiles valid rule files with the same ID in a new
// folder (r0000.yaml and so on) and returns the folder. The content is built
// once, and every file reuses it.
func idFloodDir(t *testing.T, id string) string {
	t.Helper()
	dir := t.TempDir()
	content := idFloodRule(id)
	for i := range idFloodFiles {
		writeTestFile(t, dir, fmt.Sprintf("r%04d.yaml", i), content)
	}
	return dir
}

// assertIDFloodResult checks the result of a scan of idFloodDir: exit code 2,
// empty stdout, exactly 101 stderr lines (100 errors and the summary), and no
// unsafe rune. Each of the first 100 lines holds reason. The last line says
// "rule set: too many errors" and "<more> more errors not shown".
func assertIDFloodResult(t *testing.T, code int, stdout, stderr, reason string, more int) {
	t.Helper()
	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want it empty", stdout)
	}
	lines := nonEmptyLines(stderr)
	if len(lines) != maxFloodLines {
		t.Fatalf("stderr has %d lines, want %d", len(lines), maxFloodLines)
	}
	assertScanErrorLines(t, stderr)
	for i, line := range lines[:maxFloodLines-1] {
		if !strings.Contains(line, reason) {
			t.Errorf("stderr line %d = %q, want it to mention %q", i+1, line, reason)
		}
	}
	assertContainsAll(t, "the last stderr line", lines[len(lines)-1],
		[]string{"mcpmoat scan: ", "rule set: too many errors", fmt.Sprintf("%d more errors not shown", more)})
	assertScanRulesStderr(t, stderr)
}

// TestScanRulesIDClashFlood checks that valid rule files cannot flood stderr
// through NewSet. LoadDir finds no error in them, so only the cap in NewSet
// keeps the output short.
func TestScanRulesIDClashFlood(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		id     string
		reason string
		more   int
	}{
		// The built-in rule MOAT-T1-003 is embedded, so every file clashes.
		{"every file clashes with a built-in rule", "MOAT-T1-003", "rule ID clashes with a built-in rule", idFloodFiles - 100},
		// The first file with DUP-1 loads, and the other 999 are duplicates.
		{"every file repeats one new ID", "DUP-1", "duplicate rule ID", idFloodFiles - 1 - 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := idFloodDir(t, tt.id)
			before := dirSnapshot(t, dir)
			start := time.Now()

			got := scanRulesEmpty(t, "--no-connect", "--rules", dir)

			if d := time.Since(start); d > floodGuard {
				t.Errorf("the scan took %v, want less than %v", d, floodGuard)
			}
			assertIDFloodResult(t, got.code, got.stdout, got.stderr, tt.reason, tt.more)
			if after := dirSnapshot(t, dir); !slices.Equal(before, after) {
				t.Error("the rules folder changed during the scan")
			}
		})
	}
}

// TestScanRulesCreatesNothing checks that a scan with --rules creates no file
// in the rules folder, in the home directory or in the working directory.
func TestScanRulesCreatesNothing(t *testing.T) {
	t.Parallel()

	rulesDir := t.TempDir()
	copyRuleFile(t, filepath.Join(scanRulesFixture("extra"), "MOAT-X-001.yaml"), rulesDir, "MOAT-X-001.yaml")
	badDir := t.TempDir()
	writeTestFile(t, badDir, "bad.yaml", "colour: red\n")

	tests := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{"valid rules, --no-connect", []string{"--no-connect", "--rules", rulesDir}, exitOK},
		{"valid rules, no --no-connect", []string{"--rules", rulesDir}, exitError},
		{"bad rules, --no-connect", []string{"--no-connect", "--rules", badDir}, exitError},
		{"bad rules, no --no-connect", []string{"--rules", badDir}, exitError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := t.TempDir(), t.TempDir()
			dirs := []string{home, work, rulesDir, badDir}
			before := make([][]string, len(dirs))
			for i, d := range dirs {
				before[i] = dirSnapshot(t, d)
			}

			got := scanIn(t, home, work, tt.args...)

			if got.code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstderr: %q", got.code, tt.wantCode, got.stderr)
			}
			for i, d := range dirs {
				if after := dirSnapshot(t, d); !slices.Equal(before[i], after) {
					t.Errorf("directory %d changed\nbefore: %q\nafter:  %q", i, before[i], after)
				}
			}
		})
	}
}
