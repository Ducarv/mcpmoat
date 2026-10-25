package main

// Helpers that the in-process CLI tests (scan_test.go) and the end-to-end
// tests (e2e_test.go) share.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// run is runWithContext with a context that never ends: no signal stops it.
// Only tests use it. main uses runWithContext.
func run(args []string, stdout, stderr io.Writer) int {
	return runWithContext(context.Background(), args, stdout, stderr)
}

// usageHint is the last line of every usage error on stderr.
const usageHint = `Run "mcpmoat help" for usage.`

// emptyScanOutput is the stdout of "scan --no-connect" when it finds no server.
const emptyScanOutput = "No MCP servers found.\n"

// repoPath returns the path of a file or directory relative to the repository
// root. Tests run in cmd/mcpmoat, so the root is two levels up.
func repoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

// testdataPath returns the path of a directory under testdata/<kind> at the
// repository root.
func testdataPath(kind string, parts ...string) string {
	return repoPath(append([]string{"testdata", kind}, parts...)...)
}

// fixtureDir returns the path of a fixture under the repository's
// testdata/discover directory.
func fixtureDir(parts ...string) string { return testdataPath("discover", parts...) }

// scanRulesFixture returns the path of a directory under testdata/rules.
func scanRulesFixture(parts ...string) string { return testdataPath("rules", parts...) }

// scanModes are the two ways to run scan: with and without --no-connect. args
// holds the flags to add after "scan". A test that runs in both modes loops
// over this list, so the subtest names are the same everywhere. Do not change
// args in place: copy it first (for example with slices.Clone).
var scanModes = []struct {
	name string
	args []string
}{
	{name: "with --no-connect", args: []string{"--no-connect"}},
	{name: "without --no-connect", args: nil},
}

// dirsCLI builds a test cli whose homeDir returns home and whose getwd returns
// work. It returns the cli and its stdout and stderr buffers. getenv reads an
// empty environment; a test that needs variables sets c.getenv itself.
func dirsCLI(t *testing.T, home, work string) (*cli, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)
	c.homeDir = func() (string, error) { return home, nil }
	c.getwd = func() (string, error) { return work, nil }
	return c, stdout, stderr
}

// tableHeader is the header row of the server table, split into words.
var tableHeader = []string{"NAME", "CLIENT", "SCOPE", "TRANSPORT", "STATE", "SOURCE", "COMMAND/URL"}

// tableRows splits the server table on stdout into data rows. Each row is its
// list of whitespace-separated words. It fails the test when the first line
// is not the table header, and it drops that line. The table ends at the first
// blank line: the findings table, when there is one, follows after it (see
// findingRows).
//
// CLIENT never holds a space, and report quotes a NAME, SCOPE or SOURCE cell
// that holds one. The test names and paths hold no space, so the first two
// words of a row are safe to use. Use a later word only when no cell before
// it can hold a space. The SCOPE cell of an untrusted server ends with
// " (untrusted)", which is one more word.
func tableRows(t *testing.T, stdout string) [][]string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if !slices.Equal(strings.Fields(lines[0]), tableHeader) {
		t.Fatalf("stdout does not start with the table header %q:\n%s", tableHeader, stdout)
	}
	var rows [][]string
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		rows = append(rows, strings.Fields(line))
	}
	return rows
}

// findingsHeader is the header row of the findings table, split into words.
var findingsHeader = []string{"RULE", "SEVERITY", "SERVER", "FIELD", "KEY/RELATED"}

// findingRows returns the rows of the findings table on stdout. The table
// starts after the first blank line. Each row is its list of
// whitespace-separated words. It returns nil when stdout has no blank line,
// which is the case when scan finds nothing. It fails the test when the line
// after the blank line is not the findings header, and it drops that line.
//
// A cell can be quoted when it holds a space, so use only the first four
// words of a row (RULE, SEVERITY, SERVER, FIELD) when the names hold no
// space.
func findingRows(t *testing.T, stdout string) [][]string {
	t.Helper()
	_, after, found := splitScanOutput(stdout)
	if !found {
		return nil
	}
	lines := strings.Split(strings.TrimSuffix(after, "\n"), "\n")
	if !slices.Equal(strings.Fields(lines[0]), findingsHeader) {
		t.Fatalf("the text after the blank line does not start with the findings header %q:\n%s", findingsHeader, stdout)
	}
	var rows [][]string
	for _, line := range lines[1:] {
		rows = append(rows, strings.Fields(line))
	}
	return rows
}

// splitScanOutput splits the stdout of a scan at the first blank line: the
// server table comes before it, the findings table after it. found is false
// when stdout has no blank line (no findings).
func splitScanOutput(stdout string) (table, findings string, found bool) {
	return strings.Cut(stdout, "\n\n")
}

// dangerousCanaries are the synthetic canaries of testdata/configs/dangerous:
// a header value, a token, an arg and a URL query value. They are not
// credentials, and they must not appear anywhere in stdout or stderr.
var dangerousCanaries = []string{
	"mcpmoat-canary-header-8Fk2Zs",
	"ghp_mcpmoatcanaryZk3Qp8Vw2LxN7rTb5HcYd4M",
	"Zq8Lm3Vx0Rt5Ws2Hy7Nb4Kd1",
	"Jt6Pc9Gh2Fw8Ye4Ua1Xs7Mq3",
}

// configModes are the two ways a test gives scan its config: "auto"
// (auto-discovery in the home folder) and "config" (--config on one file).
var configModes = []string{"auto", "config"}

// scanServersArgs writes servers for mode and returns the scan arguments. In
// mode "auto" it writes .claude.json in home. In mode "config" it writes
// mcp.json in a new temporary folder and passes it with --config. Any other
// mode fails the test.
func scanServersArgs(t *testing.T, mode, home string, servers map[string]any) []string {
	t.Helper()
	args := []string{"scan", "--no-connect"}
	switch mode {
	case "auto":
		writeServers(t, home, ".claude.json", servers)
	case "config":
		args = append(args, "--config", writeServers(t, t.TempDir(), "mcp.json", servers))
	default:
		t.Fatalf("unknown scan mode %q", mode)
	}
	return args
}

// findingIDs returns the rule ID (the first word) of each findings row.
func findingIDs(rows [][]string) []string { return column(rows, 0) }

// sortedFindingIDs returns the rule IDs of the findings table of stdout,
// sorted. It returns nil when stdout has no findings table.
func sortedFindingIDs(t *testing.T, stdout string) []string {
	t.Helper()
	ids := findingIDs(findingRows(t, stdout))
	slices.Sort(ids)
	return ids
}

// failOnLevels are the four --fail-on values, from low to critical.
var failOnLevels = []rules.Severity{
	rules.SeverityLow, rules.SeverityMedium, rules.SeverityHigh, rules.SeverityCritical,
}

// levelWant returns want[level]. A test table keys its expectations by
// --fail-on value. levelWant fails the test when want does not hold exactly
// the four values of failOnLevels, so no table can skip a level.
func levelWant[T any](t *testing.T, want map[rules.Severity]T, level rules.Severity) T {
	t.Helper()
	if len(want) != len(failOnLevels) {
		t.Fatalf("the test table has %d --fail-on values, want the %d of failOnLevels: %v", len(want), len(failOnLevels), want)
	}
	got, ok := want[level]
	if !ok {
		t.Fatalf("the test table has no expectation for --fail-on %s: %v", level, want)
	}
	return got
}

// column returns word i (0 is NAME) of each row. It skips a row that is too
// short.
func column(rows [][]string, i int) []string {
	var out []string
	for _, row := range rows {
		if len(row) > i {
			out = append(out, row[i])
		}
	}
	return out
}

// nonEmptyLines returns the non-empty lines of text.
func nonEmptyLines(text string) []string {
	var lines []string
	for line := range strings.SplitSeq(text, "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// assertContainsAll fails the test for each string in wants that got does not
// contain. what names got in the message, for example "stdout".
func assertContainsAll(t *testing.T, what, got string, wants []string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Errorf("%s does not contain %q\n%s:\n%s", what, want, what, got)
		}
	}
}

// assertScanErrorLines fails the test if a non-empty line of stderr does not
// start with "mcpmoat scan: ", or if it is a warning. A config problem fails
// the scan, so scan must report it as an error and never as a warning. An
// ignore-file notice ("using 1 entry from ...") has the same prefix and is
// not a warning either.
func assertScanErrorLines(t *testing.T, stderr string) {
	t.Helper()
	assertScanPrefix(t, stderr)
	for _, line := range nonEmptyLines(stderr) {
		if strings.HasPrefix(line, scanWarnPrefix) {
			t.Errorf("stderr line %q is a warning, want an error", line)
		}
	}
}

// assertEmptyStdout fails the test unless stdout is empty.
func assertEmptyStdout(t *testing.T, stdout string) {
	t.Helper()
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
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

// assertDirUnchanged fails the test if the directory dir differs from before,
// which is an earlier dirSnapshot(t, dir).
func assertDirUnchanged(t *testing.T, dir string, before []string) {
	t.Helper()
	if after := dirSnapshot(t, dir); !slices.Equal(before, after) {
		t.Errorf("directory %s changed\nbefore: %q\nafter:  %q", dir, before, after)
	}
}

// assertCleanStderr fails the test unless stderr is empty. A scan with exit
// code 0 prints nothing on stderr when no ignore entry, warning or problem
// applies.
func assertCleanStderr(t *testing.T, stderr string) {
	t.Helper()
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
}

// scanWant is the expected result of one scan run, for assertScanResult.
type scanWant struct {
	code     int
	stdout   []string // substrings of stdout
	noStdout []string // strings that stdout must not contain
	// stderr are substrings of stderr. With code exitOK and no substring,
	// stderr must be empty: a clean scan prints nothing on stderr.
	stderr []string
}

// assertScanResult checks the exit code, stdout and stderr of a scan run
// against want. It also checks the rules that hold for every scan:
//   - exit code 0 with no wanted stderr substring prints nothing on stderr;
//   - every stderr line starts with "mcpmoat scan: " and is not a warning;
//   - no canary value leaks and no raw escape byte shows.
func assertScanResult(t *testing.T, code int, stdout, stderr string, want scanWant) {
	t.Helper()
	if code != want.code {
		t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, want.code, stdout, stderr)
	}
	assertContainsAll(t, "stdout", stdout, want.stdout)
	assertContainsNone(t, "stdout", stdout, want.noStdout)
	assertContainsAll(t, "stderr", stderr, want.stderr)
	if want.code == exitOK && len(want.stderr) == 0 {
		assertCleanStderr(t, stderr)
	}
	assertScanErrorLines(t, stderr)
	assertNoLeakBoth(t, stdout, stderr)
	assertNoEscape(t, stdout, stderr)
}

// assertPartialFailureStderr checks the stderr of a scan of the
// "all/partial-failure" fixture: exactly two lines, the problem of the bad
// ~/.claude.json first and then configErrorHint, each with the scan prefix
// and none a warning.
func assertPartialFailureStderr(t *testing.T, stderr string) {
	t.Helper()
	lines := nonEmptyLines(stderr)
	if len(lines) != 2 {
		t.Fatalf("stderr has %d lines, want 2 (the problem and the hint):\n%s", len(lines), stderr)
	}
	assertContainsAll(t, "the first stderr line", lines[0], []string{"mcpmoat scan: ", ".claude.json", "invalid JSON"})
	assertScanErrorLines(t, stderr)
	if lines[1] != configErrorHint {
		t.Errorf("last stderr line = %q, want the hint %q", lines[1], configErrorHint)
	}
}

// assertNoLeakBoth fails the test if stdout or stderr holds any canary value
// of discovertest.
func assertNoLeakBoth(t *testing.T, stdout, stderr string) {
	t.Helper()
	discovertest.AssertNoLeak(t, "stdout", stdout)
	discovertest.AssertNoLeak(t, "stderr", stderr)
}

// writeTestFile writes content to dir/name and returns the full path. It
// creates the parent directories first.
func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeServers writes a JSON config with servers as its "mcpServers" object
// to dir/name and returns the full path.
func writeServers(t *testing.T, dir, name string, servers map[string]any) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{"mcpServers": servers})
	if err != nil {
		t.Fatal(err)
	}
	return writeTestFile(t, dir, name, string(data))
}

// outsideServers returns the servers of a config outside the project, for
// writeServers. The canary in its args must never show, also when mcpmoat
// refuses the file.
func outsideServers() map[string]any {
	return map[string]any{
		"outside": map[string]any{"command": "run", "args": []string{"--token", discovertest.CanaryArgs}},
	}
}

// relativePathCase is one case of the tests that compare a relative --config
// path with the absolute path of the same file.
type relativePathCase struct {
	name string
	// rel is the --config path relative to the project directory.
	rel string
	// content returns the file content for the project directory.
	content func(project string) string
	// wantStdout returns substrings of stdout for the project directory.
	wantStdout func(project string) []string
}

// relativePathCases returns the cases that TestScanConfigRelativePath and
// TestE2EScanConfigRelativePath share. Every case gives exit code 0, and its
// SCOPE cell shows the absolute project path, never "project:.". For the Codex
// file, an absolute cwd inside the project is accepted.
func relativePathCases() []relativePathCase {
	return []relativePathCase{
		{
			name: "codex file with an absolute cwd inside the project",
			rel:  filepath.Join(".codex", "config.toml"),
			content: func(project string) string {
				// A TOML literal string ('...') keeps a Windows backslash as
				// it is.
				return "[mcp_servers.in-srv]\ncommand = \"npx\"\ncwd = '" + filepath.Join(project, "sub") + "'\n"
			},
			wantStdout: func(project string) []string {
				return []string{"in-srv", "codex", "project:" + project}
			},
		},
		{
			name:    "cursor file",
			rel:     filepath.Join(".cursor", "mcp.json"),
			content: func(string) string { return `{"mcpServers":{"cur-srv":{"command":"npx"}}}` },
			wantStdout: func(project string) []string {
				return []string{"cur-srv", "cursor", "project:" + project}
			},
		},
	}
}

// writeMarkerScript writes the shell script dir/server.sh and returns its
// path and the path of its marker file. The script creates the marker file
// when it runs, so a test can prove that a configured command never started.
// The script is executable, so a start would really work. It needs a Unix
// shell.
func writeMarkerScript(t *testing.T, dir string) (script, marker string) {
	t.Helper()
	marker = filepath.Join(dir, "marker")
	script = filepath.Join(dir, "server.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil { //nolint:gosec // G306: the script must be executable
		t.Fatal(err)
	}
	return script, marker
}

// symlink makes link point to target. It creates the parent directory of
// link first.
//
// It skips the test only on Windows, where a user without the right
// privilege cannot make a symlink. On every other system a failed symlink is
// a test bug, so it fails the test.
func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}
}

// okServer is a server map with one valid server, ok-srv, for writeServers.
// It is only read, so the parallel tests can share it.
var okServer = map[string]any{"ok-srv": map[string]any{"command": "npx"}}

// runScanArgs runs "mcpmoat <args>" on c and returns the exit code, stdout and
// stderr.
func runScanArgs(c *cli, stdout, stderr *bytes.Buffer, args ...string) (int, string, string) {
	code := c.dispatch(args)
	return code, stdout.String(), stderr.String()
}

// lineWant is the expected text of one stderr line: the exact line, or only
// its start when prefix is true.
type lineWant struct {
	text   string
	prefix bool
}

// exactLine wants a line that is exactly s.
func exactLine(s string) lineWant { return lineWant{text: s} }

// prefixLine wants a line that starts with s.
func prefixLine(s string) lineWant { return lineWant{text: s, prefix: true} }

// assertStderrLines fails the test unless the non-empty lines of stderr match
// wants, one for one and in order.
func assertStderrLines(t *testing.T, stderr string, wants []lineWant) {
	t.Helper()
	lines := nonEmptyLines(stderr)
	if len(lines) != len(wants) {
		t.Fatalf("stderr has %d lines, want %d:\n%s", len(lines), len(wants), stderr)
	}
	for i, w := range wants {
		ok := lines[i] == w.text
		if w.prefix {
			ok = strings.HasPrefix(lines[i], w.text)
		}
		if !ok {
			kind := "="
			if w.prefix {
				kind = "starting with"
			}
			t.Errorf("stderr line %d = %q, want a line %s %q", i+1, lines[i], kind, w.text)
		}
	}
}

// assertScanPrefix fails the test if a non-empty stderr line does not start
// with "mcpmoat scan: ".
func assertScanPrefix(t *testing.T, stderr string) {
	t.Helper()
	for _, line := range nonEmptyLines(stderr) {
		if !strings.HasPrefix(line, scanPrefix) {
			t.Errorf("stderr line %q does not start with %q", line, scanPrefix)
		}
	}
}

// replaceToken returns a copy of args in which each arg equal to token is
// value.
func replaceToken(args []string, token, value string) []string {
	out := slices.Clone(args)
	for i, a := range out {
		if a == token {
			out[i] = value
		}
	}
	return out
}

// assertContainsNone fails the test for each string in bad that got contains.
// what names got in the message.
func assertContainsNone(t *testing.T, what, got string, bad []string) {
	t.Helper()
	for _, b := range bad {
		if strings.Contains(got, b) {
			t.Errorf("%s contains %q\n%s:\n%s", what, b, what, got)
		}
	}
}

// scanPrefix is the start of every stderr line of scan.
const scanPrefix = "mcpmoat scan: "

// scanWarnPrefix is the start of every scan warning line.
const scanWarnPrefix = scanPrefix + "warning: "

// writeFileOrSkip writes content to dir/name. The file system may refuse a file
// name (a name with a control rune, for example). That is not a failure of
// mcpmoat, so the test skips.
func writeFileOrSkip(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Skipf("the file system refuses this file name: %v", err)
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

// assertFast fails the test when more than floodGuard has passed since start.
func assertFast(t *testing.T, start time.Time) {
	t.Helper()
	if d := time.Since(start); d > floodGuard {
		t.Errorf("the scan took %v, want less than %v", d, floodGuard)
	}
}

// floodCap is the number of folder errors the loader prints before its last
// "too many errors" line.
const floodCap = maxFloodLines - 1

// assertFloodResult checks the result of a scan of floodDir: exit code 2,
// empty stdout, a capped list of errors that ends with the "too many errors"
// line, and no unsafe rune.
func assertFloodResult(t *testing.T, code int, stdout, stderr string) {
	t.Helper()
	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	assertEmptyStdout(t, stdout)
	lines := nonEmptyLines(stderr)
	if len(lines) < 2 || len(lines) > maxFloodLines {
		t.Fatalf("stderr has %d lines, want 2 to %d", len(lines), maxFloodLines)
	}
	assertScanErrorLines(t, stderr)
	assertContainsAll(t, "the last stderr line", lines[len(lines)-1],
		[]string{"mcpmoat scan: ", "too many errors", "files not fully checked"})
	assertTerminalSafe(t, stderr)
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
	assertEmptyStdout(t, stdout)
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
	assertTerminalSafe(t, stderr)
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

// assertTerminalSafe fails the test if out, the text of one stream (stdout or
// stderr), holds a rune that can change the terminal or hide text (see
// firstUnsafeRune). The newline is the only control character it accepts.
func assertTerminalSafe(t *testing.T, out string) {
	t.Helper()
	if r, i, found := firstUnsafeRune(out); found {
		t.Errorf("output has the unsafe rune %U at offset %d\noutput: %q", r, i, out)
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
