package main

// Helpers that the in-process CLI tests (scan_test.go) and the end-to-end
// tests (e2e_test.go) share.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// fixtureDir returns the path of a fixture under the repository's
// testdata/discover directory. Tests run in cmd/mcpmoat, so the repository
// root is two levels up.
func fixtureDir(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata", "discover"}, parts...)...)
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
var tableHeader = []string{"NAME", "CLIENT", "SCOPE", "TRANSPORT", "SOURCE", "COMMAND/URL"}

// tableRows splits the server table on stdout into data rows. Each row is its
// list of whitespace-separated words. It fails the test when the first line
// is not the table header, and it drops that line.
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
		rows = append(rows, strings.Fields(line))
	}
	return rows
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
// the scan, so scan must report it as an error and never as a warning. The
// notice noRulesNotice has the same prefix and is not a warning either.
func assertScanErrorLines(t *testing.T, stderr string) {
	t.Helper()
	const prefix = "mcpmoat scan: "
	for _, line := range nonEmptyLines(stderr) {
		if !strings.HasPrefix(line, prefix) || strings.Contains(line, "warning:") {
			t.Errorf("stderr line %q must start with %q and not be a warning", line, prefix)
		}
	}
}

// assertNoRulesNotice fails the test unless stderr is exactly the notice
// line that a scan with exit code 0 prints.
func assertNoRulesNotice(t *testing.T, stderr string) {
	t.Helper()
	if want := noRulesNotice + "\n"; stderr != want {
		t.Errorf("stderr = %q, want only the notice %q", stderr, want)
	}
}

// scanWant is the expected result of one scan run, for assertScanResult.
type scanWant struct {
	code     int
	stdout   []string // substrings of stdout
	noStdout []string // strings that stdout must not contain
	// stderr are substrings of stderr. With code exitOK, stderr must be
	// exactly the notice line, so leave stderr empty.
	stderr []string
}

// assertScanResult checks the exit code, stdout and stderr of a scan run
// against want. It also checks the rules that hold for every scan:
//   - exit code 0 prints only noRulesNotice on stderr, and exit code 2 never
//     prints it;
//   - every stderr line starts with "mcpmoat scan: " and is not a warning;
//   - no canary value leaks and no raw escape byte shows.
func assertScanResult(t *testing.T, code int, stdout, stderr string, want scanWant) {
	t.Helper()
	if code != want.code {
		t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, want.code, stdout, stderr)
	}
	assertContainsAll(t, "stdout", stdout, want.stdout)
	for _, bad := range want.noStdout {
		if strings.Contains(stdout, bad) {
			t.Errorf("stdout contains %q\nstdout:\n%s", bad, stdout)
		}
	}
	assertContainsAll(t, "stderr", stderr, want.stderr)
	if want.code == exitOK {
		assertNoRulesNotice(t, stderr)
	} else if strings.Contains(stderr, noRulesNotice) {
		t.Errorf("stderr holds the notice %q, but the scan failed\nstderr:\n%s", noRulesNotice, stderr)
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
