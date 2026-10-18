package main

// Helpers that the in-process CLI tests (scan_test.go) and the end-to-end
// tests (e2e_test.go) share.

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
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
// The NAME and CLIENT cells never hold a space, so the first two words of a
// row are safe to use. Use a later word only when no cell before it can hold
// a space.
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
// the scan, so scan must report it as an error and never as a warning.
func assertScanErrorLines(t *testing.T, stderr string) {
	t.Helper()
	const prefix = "mcpmoat scan: "
	for _, line := range nonEmptyLines(stderr) {
		if !strings.HasPrefix(line, prefix) || strings.Contains(line, "warning:") {
			t.Errorf("stderr line %q must start with %q and not be a warning", line, prefix)
		}
	}
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
