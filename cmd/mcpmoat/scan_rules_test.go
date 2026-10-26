package main

// In-process tests of the --rules flag of "mcpmoat scan". They call
// c.dispatch with empty home and working directories, so they never read the
// real $HOME or real client configs. None of them calls t.Setenv, so all of
// them can run in parallel.

import (
	"encoding/json"
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

// scanRulesSchemaRule is an external rule with the target schema. The fixtures
// under testdata/rules hold no schema rule, so the tests write this one to a
// t.TempDir(). It matches the keyword "deprecated" in a tool input schema.
const scanRulesSchemaRule = `id: MOAT-X-004
title: Fixture rule for a deprecated field in a tool input schema
severity: low
target: schema
match:
  keywords:
    - deprecated
risk: Fixture.
remediation: Fixture.
should_match:
  - '{"description":"This field is deprecated."}'
should_not_match:
  - '{"description":"A file name."}'
`

// scanRulesSchemaDir returns a new folder that holds only scanRulesSchemaRule.
func scanRulesSchemaDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "MOAT-X-004.yaml", scanRulesSchemaRule)
	return dir
}

// scanRulesDirOf returns a new folder with a copy of each fixture rule file in
// srcs, under its own base name.
func scanRulesDirOf(t *testing.T, srcs ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, src := range srcs {
		copyRuleFile(t, src, dir, filepath.Base(src))
	}
	return dir
}

// The fixture rules from --rules: MOAT-X-001 has the target description and
// MOAT-X-003 has the target config. Both are low.
var (
	scanRulesExtraFile  = filepath.Join(scanRulesFixture("extra"), "MOAT-X-001.yaml")
	scanRulesConfigFile = filepath.Join(scanRulesFixture("configtarget"), "MOAT-X-003.yaml")
)

// TestScanRulesAccepted checks valid rule folders with --no-connect. Without a
// connection scan applies no description or schema rule, and it never applies
// a config rule from --rules. So the exit code is 0 and stdout is the same as
// for a scan without --rules. The only change is on stderr: one notice for
// each kind of rule that scan does not apply, in a fixed order.
func TestScanRulesAccepted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// dir returns the rules folder for the case.
		dir func(t *testing.T) string
		// wantNotices are the lines that scan adds on stderr, in this order.
		wantNotices []string
	}{
		{
			name:        "valid external rule",
			dir:         func(*testing.T) string { return scanRulesFixture("extra") },
			wantNotices: []string{toolRulesNoConnectNotice},
		},
		{
			name: "yml file name",
			dir: func(t *testing.T) string {
				dir := t.TempDir()
				copyRuleFile(t, scanRulesExtraFile, dir, "MOAT-X-001.yml")
				return dir
			},
			wantNotices: []string{toolRulesNoConnectNotice},
		},
		{
			name: "folder and txt file are ignored",
			dir: func(t *testing.T) string {
				dir := t.TempDir()
				copyRuleFile(t, scanRulesExtraFile, dir, "MOAT-X-001.yaml")
				// A rule in a subfolder or in a .txt file is not loaded. If it
				// were, its bad content would fail the scan.
				writeTestFile(t, dir, filepath.Join("sub", "broken.yaml"), "not: [valid\n")
				writeTestFile(t, dir, "notes.txt", "not: [valid\n")
				return dir
			},
			wantNotices: []string{toolRulesNoConnectNotice},
		},
		{
			name:        "schema target rule",
			dir:         scanRulesSchemaDir,
			wantNotices: []string{toolRulesNoConnectNotice},
		},
		{
			name:        "config target rule",
			dir:         func(*testing.T) string { return scanRulesFixture("configtarget") },
			wantNotices: []string{configRulesNotice},
		},
		{
			// The description rule loads first (MOAT-X-001 sorts before
			// MOAT-X-003), but the config notice still comes first.
			name: "config and description rules",
			dir: func(t *testing.T) string {
				return scanRulesDirOf(t, scanRulesExtraFile, scanRulesConfigFile)
			},
			wantNotices: []string{configRulesNotice, toolRulesNoConnectNotice},
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

			assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{code: exitOK, stderr: tt.wantNotices})
			wantStderr := base.stderr + strings.Join(tt.wantNotices, "\n") + "\n"
			if got.stdout != base.stdout || got.stderr != wantStderr {
				t.Errorf("output differs from the scan without --rules\nstdout: %q (want %q)\nstderr: %q (want %q)",
					got.stdout, base.stdout, got.stderr, wantStderr)
			}
			assertDirUnchanged(t, dir, before)
		})
	}
}

// scanRulesTool returns the tool "lookup" with the description and the raw
// JSON input schema given.
func scanRulesTool(description, schema string) inspect.Tool {
	return inspect.Tool{Name: "lookup", Description: description, InputSchema: json.RawMessage(schema)}
}

// The tools of the tests below. The texts hold no secret and no word that a
// built-in rule matches: each test first checks that a scan without --rules
// gives no finding.
var (
	// scanRulesPlainTool has no "deprecated" keyword.
	scanRulesPlainTool = scanRulesTool("Lists the files in a folder.", `{"type":"object"}`)
	// scanRulesDeprecatedTool has the keyword of MOAT-X-001 in its
	// description, and none in its input schema.
	scanRulesDeprecatedTool = scanRulesTool("Lists the files in a folder. This tool is deprecated.", `{"type":"object"}`)
	// scanRulesDeprecatedSchemaTool has the keyword of MOAT-X-004 in its input
	// schema, and none in its description.
	scanRulesDeprecatedSchemaTool = scanRulesTool("Lists the files in a folder.",
		`{"properties":{"path":{"description":"This field is deprecated.","type":"string"}},"type":"object"}`)
)

// scanRulesToolTexts are parts of the tool texts above. A finding row holds no
// tool text, so they must never show on stdout or stderr.
var scanRulesToolTexts = []string{"Lists the files", "This tool is deprecated", "This field is deprecated"}

// scanRulesPinned is the stderr of the first scan of the server ok-srv with
// one tool, which pins that tool.
const scanRulesPinned = "mcpmoat scan: pinned 1 tool for ok-srv\n"

// TestScanRulesWithConnect checks the mode without --no-connect. Scan applies
// the description and schema rules from --rules to the tools of each server.
// A hit is a row with the field "tool", the tool name, and the target of the
// rule ("description" or "schema") in parentheses. The exit code follows
// --fail-on: the fixture rules are low, so the default --fail-on high gives
// exit code 0 and --fail-on low gives exit code 1. With a connection scan
// prints no notice for a description or schema rule, but it still prints the
// notice for a config rule, which it never applies.
//
// The scan never starts a server: the inspector is a fake. A first scan
// without --rules pins the tool, so the scan with --rules has no pin notice and
// no pin finding.
func TestScanRulesWithConnect(t *testing.T) {
	t.Parallel()

	descRow := []string{"MOAT-X-001", "low", "ok-srv", "tool", "lookup", "(description)"}
	schemaRow := []string{"MOAT-X-004", "low", "ok-srv", "tool", "lookup", "(schema)"}
	failOnLow := []string{"--fail-on", "low"}

	tests := []struct {
		name string
		// dir returns the rules folder for the case.
		dir  func(t *testing.T) string
		tool inspect.Tool
		// args are more scan flags after --rules.
		args        []string
		wantCode    int
		wantRows    [][]string
		wantNotices []string
	}{
		{
			name:     "description rule, tool without the keyword",
			dir:      func(*testing.T) string { return scanRulesFixture("extra") },
			tool:     scanRulesPlainTool,
			wantCode: exitOK,
		},
		{
			name:     "description rule hit, default fail-on high",
			dir:      func(*testing.T) string { return scanRulesFixture("extra") },
			tool:     scanRulesDeprecatedTool,
			wantCode: exitOK,
			wantRows: [][]string{descRow},
		},
		{
			name:     "description rule hit, fail-on low",
			dir:      func(*testing.T) string { return scanRulesFixture("extra") },
			tool:     scanRulesDeprecatedTool,
			args:     failOnLow,
			wantCode: exitFindings,
			wantRows: [][]string{descRow},
		},
		{
			name:     "description rule does not read the schema",
			dir:      func(*testing.T) string { return scanRulesFixture("extra") },
			tool:     scanRulesDeprecatedSchemaTool,
			args:     failOnLow,
			wantCode: exitOK,
		},
		{
			name:     "schema rule hit, fail-on low",
			dir:      scanRulesSchemaDir,
			tool:     scanRulesDeprecatedSchemaTool,
			args:     failOnLow,
			wantCode: exitFindings,
			wantRows: [][]string{schemaRow},
		},
		{
			name:     "schema rule does not read the description",
			dir:      scanRulesSchemaDir,
			tool:     scanRulesDeprecatedTool,
			args:     failOnLow,
			wantCode: exitOK,
		},
		{
			name:        "config rule only",
			dir:         func(*testing.T) string { return scanRulesFixture("configtarget") },
			tool:        scanRulesDeprecatedTool,
			args:        failOnLow,
			wantCode:    exitOK,
			wantNotices: []string{configRulesNotice},
		},
		{
			name: "config and description rules",
			dir: func(t *testing.T) string {
				return scanRulesDirOf(t, scanRulesExtraFile, scanRulesConfigFile)
			},
			tool:        scanRulesDeprecatedTool,
			args:        failOnLow,
			wantCode:    exitFindings,
			wantRows:    [][]string{descRow},
			wantNotices: []string{configRulesNotice},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := t.TempDir(), t.TempDir()
			writeServers(t, home, ".claude.json", okServer)
			fake := fakeServers(map[string][]inspect.Tool{"ok-srv": {tt.tool}})
			dir := tt.dir(t)
			before := dirSnapshot(t, dir)

			// The first scan, without --rules, pins the tool. It also proves
			// that no built-in rule matches the tool, so every row below
			// comes from the rules in dir.
			base := scanInWith(t, fake, home, work, tt.args...)
			assertScanResult(t, base.code, base.stdout, base.stderr, scanWant{
				code:   exitOK,
				stdout: []string{"ok-srv"},
				stderr: []string{scanRulesPinned},
			})
			if rows := findingRows(t, base.stdout); len(rows) != 0 {
				t.Fatalf("the scan without --rules has findings %q, want none", rows)
			}

			got := scanInWith(t, fake, home, work, append([]string{"--rules", dir}, tt.args...)...)

			assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{
				code:     tt.wantCode,
				stdout:   []string{"ok-srv"},
				noStdout: scanRulesToolTexts,
				stderr:   tt.wantNotices,
			})
			if rows := findingRows(t, got.stdout); !slices.EqualFunc(rows, tt.wantRows, slices.Equal) {
				t.Errorf("finding rows = %q, want %q\nstdout:\n%s", rows, tt.wantRows, got.stdout)
			}
			if len(tt.wantRows) == 0 && got.stdout != base.stdout {
				t.Errorf("--rules with no hit changes stdout\ngot:  %q\nwant: %q", got.stdout, base.stdout)
			}
			// No notice for the tool rules: scan applies them. No pin
			// notice: the first scan pinned the tool.
			wantStderr := ""
			if len(tt.wantNotices) > 0 {
				wantStderr = strings.Join(tt.wantNotices, "\n") + "\n"
			}
			if got.stderr != wantStderr {
				t.Errorf("stderr = %q, want %q", got.stderr, wantStderr)
			}
			assertContainsNone(t, "stderr", got.stderr, scanRulesToolTexts)
			assertDirUnchanged(t, dir, before)
		})
	}
}

// TestScanRulesWithConnectJSON checks the JSON row of a description rule from
// --rules: the rule ID, the severity of the rule, the server, the field
// "tool", the tool name as the key and the target "description" as the
// related text. The tool text is not in the document.
func TestScanRulesWithConnectJSON(t *testing.T) {
	t.Parallel()

	home, work := t.TempDir(), t.TempDir()
	writeServers(t, home, ".claude.json", okServer)
	fake := fakeServers(map[string][]inspect.Tool{"ok-srv": {scanRulesDeprecatedTool}})

	got := scanInWith(t, fake, home, work, "--json", "--rules", scanRulesFixture("extra"))

	// The first scan of the server pins its tool. The low finding does not
	// reach the default --fail-on high.
	assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{
		code:     exitOK,
		noStdout: scanRulesToolTexts,
		stderr:   []string{scanRulesPinned},
	})
	if got.stderr != scanRulesPinned {
		t.Errorf("stderr = %q, want %q", got.stderr, scanRulesPinned)
	}
	doc := decodeScanJSON(t, got.stdout)
	if len(doc.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(doc.Findings), doc.Findings)
	}
	f := doc.Findings[0]
	want := map[string][2]string{
		"rule_id":  {f.RuleID, "MOAT-X-001"},
		"severity": {f.Severity, "low"},
		"server":   {f.Server, "ok-srv"},
		"field":    {f.Field, "tool"},
		"key":      {f.Key, "lookup"},
		"related":  {f.Related, "description"},
	}
	for name, pair := range want {
		if pair[0] != pair[1] {
			t.Errorf("finding %s = %q, want %q", name, pair[0], pair[1])
		}
	}
}

// TestScanRulesNoConnectSkipsToolRules checks that --no-connect applies no
// description rule from --rules, also when the server has a tool that the rule
// would match: scan does not start the server, prints exactly
// toolRulesNoConnectNotice on stderr and gives no finding, also with
// --fail-on low.
func TestScanRulesNoConnectSkipsToolRules(t *testing.T) {
	t.Parallel()

	home, work := t.TempDir(), t.TempDir()
	writeServers(t, home, ".claude.json", okServer)
	fake := fakeServers(map[string][]inspect.Tool{"ok-srv": {scanRulesDeprecatedTool}})
	homeBefore := dirSnapshot(t, home)

	got := scanInWith(t, fake, home, work, "--no-connect", "--fail-on", "low", "--rules", scanRulesFixture("extra"))

	assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{
		code:   exitOK,
		stdout: []string{"ok-srv"},
		stderr: []string{toolRulesNoConnectNotice},
	})
	if want := toolRulesNoConnectNotice + "\n"; got.stderr != want {
		t.Errorf("stderr = %q, want %q", got.stderr, want)
	}
	if rows := findingRows(t, got.stdout); len(rows) != 0 {
		t.Errorf("finding rows = %q, want none\nstdout:\n%s", rows, got.stdout)
	}
	if calls := fake.Calls(); len(calls) != 0 {
		t.Errorf("inspector calls = %q, want none with --no-connect", calls)
	}
	// --no-connect reads and writes no pins.
	assertDirUnchanged(t, home, homeBefore)
}

// TestScanRulesBadRegex checks a rule from --rules whose regex does not
// compile. Scan compiles every description and schema rule before it looks at
// --no-connect, so both modes give exit code 2, an empty stdout and one stderr
// line that names the file and the field "match". Scan never starts the server
// and writes no pins.
func TestScanRulesBadRegex(t *testing.T) {
	t.Parallel()

	dir := scanRulesFixture("badregex")
	file := filepath.Join(dir, "MOAT-X-002.yaml")

	for _, mode := range scanModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()
			home, work := t.TempDir(), t.TempDir()
			writeServers(t, home, ".claude.json", okServer)
			fake := fakeServers(map[string][]inspect.Tool{"ok-srv": {scanRulesDeprecatedTool}})
			homeBefore := dirSnapshot(t, home)
			dirBefore := dirSnapshot(t, dir)

			got := scanInWith(t, fake, home, work, append(slices.Clone(mode.args), "--rules", dir)...)

			assertScanResult(t, got.code, got.stdout, got.stderr, scanWant{
				code:   exitError,
				stderr: []string{"mcpmoat scan: " + file + ": ", "field match"},
			})
			assertEmptyStdout(t, got.stdout)
			if lines := nonEmptyLines(got.stderr); len(lines) != 1 {
				t.Errorf("stderr has %d lines, want 1\nstderr: %q", len(lines), got.stderr)
			}
			// The pattern text of the rule never shows.
			assertContainsNone(t, "stderr", got.stderr, []string{"(unclosed"})
			assertTerminalSafe(t, got.stderr)
			if calls := fake.Calls(); len(calls) != 0 {
				t.Errorf("inspector calls = %q, want none: the rules error comes before the connect step", calls)
			}
			assertDirUnchanged(t, home, homeBefore)
			assertDirUnchanged(t, dir, dirBefore)
		})
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
		{
			// rules.NewAnalyzer compiles the regex, also with --no-connect.
			name:       "regex that does not compile",
			dir:        scanRulesFixture("badregex"),
			wantStderr: []string{"mcpmoat scan: ", "MOAT-X-002.yaml", "field match"},
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

	assertFast(t, start, floodGuard)
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

			assertFast(t, start, floodGuard)
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
