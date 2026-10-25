package main

// In-process tests of the --rules flag of "mcpmoat scan". They call
// c.dispatch with empty home and working directories, so they never read the
// real $HOME or real client configs. None of them calls t.Setenv, so all of
// them can run in parallel.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

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
// directory. The inspector is an empty fake: it knows no server, so a scan that
// finds no server never needs it.
func scanIn(t *testing.T, home, work string, args ...string) scanRulesResult {
	t.Helper()
	return scanInWith(t, &inspecttest.Fake{}, home, work, args...)
}

// scanInWith is scanIn with the given fake inspector.
func scanInWith(t *testing.T, fake *inspecttest.Fake, home, work string, args ...string) scanRulesResult {
	t.Helper()
	c, stdout, stderr := dirsCLI(t, home, work)
	c.inspector = fake
	code := c.dispatch(append([]string{"scan"}, args...))
	return scanRulesResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
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

			// The only change is the notice that the rules are not applied.
			assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{code: exitOK, stderr: []string{rulesNotAppliedNotice}})
			wantStderr := base.stderr + rulesNotAppliedNotice + "\n"
			if got.stdout != base.stdout || got.stderr != wantStderr {
				t.Errorf("output differs from the scan without --rules\nstdout: %q (want %q)\nstderr: %q (want %q)",
					got.stdout, base.stdout, got.stderr, wantStderr)
			}
			assertDirUnchanged(t, dir, before)
		})
	}
}

// TestScanRulesWithConnect checks the mode without --no-connect. The rules
// are loaded before the step that connects, and scan does not apply them, so
// valid rules give the same result as a scan without --rules plus the notice
// that the rules are not applied. The scan never starts a server: the
// inspector is a fake. The first scan pins the tools of the server, so the
// second scan, with --rules, has no pin notice and no pin finding.
func TestScanRulesWithConnect(t *testing.T) {
	t.Parallel()

	home, work := t.TempDir(), t.TempDir()
	writeServers(t, home, ".claude.json", okServer)
	fake := &inspecttest.Fake{Results: map[string]inspect.Result{"ok-srv": inspecttest.BenignResult()}}

	base := scanInWith(t, fake, home, work)
	assertScanResult(t, base.code, base.stdout, base.stderr, scanWant{
		code:   exitOK,
		stdout: []string{"ok-srv"},
		stderr: []string{"mcpmoat scan: pinned 2 tools for ok-srv\n"},
	})

	got := scanInWith(t, fake, home, work, "--rules", scanRulesFixture("extra"))

	assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{code: exitOK, stderr: []string{rulesNotAppliedNotice}})
	if got.stdout != base.stdout {
		t.Errorf("valid --rules changes stdout\ngot:  %q\nwant: %q", got.stdout, base.stdout)
	}
	if want := rulesNotAppliedNotice + "\n"; got.stderr != want {
		t.Errorf("stderr = %q, want %q", got.stderr, want)
	}
}

// noRuleFilesText is the reason text of a --rules folder with no rule file. It
// is the same as rules.ReasonNoRuleFiles. The test keeps its own copy, so a
// change of the text in the loader shows up as a failed test.
const noRuleFilesText = "no rule files (*.yaml or *.yml) found"

// builtinClashText is the reason text of a rule whose ID is the ID of a
// built-in rule. It is the same as rules.ReasonBuiltinIDClash. The test keeps
// its own copy, so a change of the text in the loader shows up as a failed
// test.
const builtinClashText = "rule ID clashes with a built-in rule"

// duplicateIDText is the reason text of a rule whose ID another rule file
// already uses. It is the same as rules.ReasonDuplicateID. The test keeps its
// own copy, for the same reason as noRuleFilesText.
const duplicateIDText = "duplicate rule ID"

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
				builtinClashText,
			},
		},
		{
			name:       "the built-in ID in a copy of the built-in rule",
			dir:        scanRulesFixture("valid"),
			wantStderr: []string{"mcpmoat scan: ", "MOAT-T1-003.yaml", builtinClashText},
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

	for _, tt := range tests {
		for _, mode := range scanModes {
			t.Run(tt.name+" "+mode.name, func(t *testing.T) {
				t.Parallel()
				before := dirSnapshot(t, tt.dir)

				got := scanRulesEmpty(t, append(slices.Clone(mode.args), "--rules", tt.dir)...)

				assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{
					code:   exitError,
					stderr: tt.wantStderr,
				})
				assertEmptyStdout(t, got.stdout)
				if strings.Contains(got.stderr, "pinned") || strings.Contains(got.stderr, "cannot inspect") {
					t.Errorf("the rules error must come before the connect step\nstderr: %q", got.stderr)
				}
				if lines := nonEmptyLines(got.stderr); len(lines) != 1 {
					t.Errorf("stderr has %d lines, want 1\nstderr: %q", len(lines), got.stderr)
				}
				assertTerminalSafe(t, got.stderr)
				assertDirUnchanged(t, tt.dir, before)
			})
		}
	}
}

// TestScanRulesNoRuleFiles checks that a folder with no rule file gives exit
// code 2 and exactly one line on stderr: the folder and the reason, at the end
// of the line. A folder where every name is wrong would otherwise look like a
// scan that uses extra rules and does not. Both modes fail the same way,
// because the rules are checked before scan looks at --no-connect.
func TestScanRulesNoRuleFiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{name: "empty folder", setup: func(*testing.T, string) {}},
		{name: "other names only", setup: func(t *testing.T, dir string) {
			writeTestFile(t, dir, "rule.txt", "id: x\n")
			writeTestFile(t, dir, "rule.yaml.bak", "id: x\n")
		}},
		{name: "subfolders only", setup: func(t *testing.T, dir string) {
			writeTestFile(t, dir, filepath.Join("sub", "inner.yaml"), "id: x\n")
			writeTestFile(t, dir, filepath.Join("named.yaml", "inner.yaml"), "id: x\n")
		}},
	}
	for _, tt := range tests {
		for _, mode := range scanModes {
			t.Run(tt.name+" "+mode.name, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				tt.setup(t, dir)
				before := dirSnapshot(t, dir)

				got := scanRulesEmpty(t, append(slices.Clone(mode.args), "--rules", dir)...)

				assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{code: exitError})
				assertEmptyStdout(t, got.stdout)
				if want := "mcpmoat scan: " + dir + ": " + noRuleFilesText + "\n"; got.stderr != want {
					t.Errorf("stderr = %q, want %q", got.stderr, want)
				}
				assertDirUnchanged(t, dir, before)
			})
		}
	}
}

// TestScanRulesFlagErrors checks the errors of the --rules flag itself.
func TestScanRulesFlagErrors(t *testing.T) {
	t.Parallel()

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
			noStderr:   []string{"cannot read directory", "pinned", "cannot inspect"},
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
			assertEmptyStdout(t, got.stdout)
			for _, bad := range tt.noStderr {
				if strings.Contains(got.stderr, bad) {
					t.Errorf("stderr contains %q\nstderr: %q", bad, got.stderr)
				}
			}
			assertTerminalSafe(t, got.stderr)
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
			assertContainsAll(t, "stdout", stdout.String(), []string{"--rules <dir>", "*.yaml", "*.yml", "no rule file"})
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
	assertEmptyStdout(t, got.stdout)
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
	assertTerminalSafe(t, got.stderr)
	assertDirUnchanged(t, dir, before)
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
		for _, mode := range scanModes {
			t.Run(tt.name+" "+mode.name, func(t *testing.T) {
				t.Parallel()
				dir := tt.setup(t)

				got := scanRulesEmpty(t, append(slices.Clone(mode.args), "--rules", dir)...)

				// assertScanResult checks that every stderr line has the
				// scan prefix (a raw newline from a file name would break
				// this) and that stderr has no raw ESC byte.
				assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{code: exitError})
				assertEmptyStdout(t, got.stdout)
				if got.stderr == "" {
					t.Error("stderr is empty, want the problem")
				}
				assertTerminalSafe(t, got.stderr)
			})
		}
	}
}

// TestScanRulesErrorFlood checks that 300 hostile rule files print a capped
// list of errors on stderr and not one line per bad item.
func TestScanRulesErrorFlood(t *testing.T) {
	t.Parallel()

	dir := floodDir(t)
	start := time.Now()

	got := scanRulesEmpty(t, "--no-connect", "--rules", dir)

	assertFast(t, start)
	assertFloodResult(t, got.code, got.stdout, got.stderr)
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
		{"every file clashes with a built-in rule", "MOAT-T1-003", builtinClashText, idFloodFiles - floodCap},
		// The first file with DUP-1 loads, and the other 999 are duplicates.
		{"every file repeats one new ID", "DUP-1", duplicateIDText, idFloodFiles - 1 - floodCap},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := idFloodDir(t, tt.id)
			before := dirSnapshot(t, dir)
			start := time.Now()

			got := scanRulesEmpty(t, "--no-connect", "--rules", dir)

			assertFast(t, start)
			assertIDFloodResult(t, got.code, got.stdout, got.stderr, tt.reason, tt.more)
			assertDirUnchanged(t, dir, before)
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
		// The home has no server, so scan inspects none and writes no pins.
		{"valid rules, no --no-connect", []string{"--rules", rulesDir}, exitOK},
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
				assertDirUnchanged(t, d, before[i])
			}
		})
	}
}
