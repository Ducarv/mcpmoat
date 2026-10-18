package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"text/tabwriter"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// update rewrites the golden files. Run "go test ./cmd/mcpmoat/ -run
// TestScanNoConnectGolden -update", then read "git diff" before you commit.
var update = flag.Bool("update", false, "rewrite golden files")

// scanFixtureDir returns the path of a fixture under the repository's
// testdata/discover directory. Tests run in cmd/mcpmoat, so the repository root
// is two levels up.
func scanFixtureDir(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata", "discover"}, parts...)...)
}

// scanCLI builds a test cli whose home and working directory are fresh copies
// of the fixture. It returns the cli, the two output buffers and the two copy
// paths. The tests never touch the fixture itself.
func scanCLI(t *testing.T, fixture ...string) (c *cli, stdout, stderr *bytes.Buffer, home, work string) {
	t.Helper()
	home, work = discovertest.CopyFixture(t, scanFixtureDir(fixture...))
	c, stdout, stderr = newTestCLI(fakeGetenv(nil), testBuild)
	c.homeDir = func() (string, error) { return home, nil }
	c.getwd = func() (string, error) { return work, nil }
	return c, stdout, stderr, home, work
}

// scanWriteFile writes content to dir/name and returns the full path.
func scanWriteFile(t *testing.T, dir, name, content string) string {
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

// scanRows splits the table on stdout into rows of whitespace-separated
// fields. It drops the header line. Use it only when no cell holds a space.
func scanRows(t *testing.T, stdout string) [][]string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "NAME") {
		t.Fatalf("stdout does not start with the table header:\n%s", stdout)
	}
	var rows [][]string
	for _, line := range lines[1:] {
		rows = append(rows, strings.Fields(line))
	}
	return rows
}

// scanNonEmptyLines returns the non-empty lines of text.
func scanNonEmptyLines(text string) []string {
	var lines []string
	for line := range strings.SplitSeq(text, "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// scanConfigCLI returns a cli for --config runs. Its homeDir returns home,
// which --config uses only to tell whether the file is one of the user's own
// global files. Its getwd fails the test when it is called: it proves that
// --config never looks at the working directory.
func scanConfigCLI(t *testing.T, home string) (*cli, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)
	c.homeDir = func() (string, error) { return home, nil }
	c.getwd = func() (string, error) {
		t.Error("getwd was called, but --config must not read the working directory")
		return "", errors.New("forbidden")
	}
	return c, stdout, stderr
}

func TestScanFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout []string
		wantStderr []string
	}{
		{
			name:       "help flag",
			args:       []string{"scan", "-h"},
			wantCode:   exitOK,
			wantStdout: []string{"Scan flags", "--no-connect", "--config <file>"},
		},
		{
			name:       "long help flag",
			args:       []string{"scan", "--help"},
			wantCode:   exitOK,
			wantStdout: []string{"Scan flags"},
		},
		{
			name:       "unknown flag",
			args:       []string{"scan", "--bogus"},
			wantCode:   exitError,
			wantStderr: []string{`mcpmoat scan: "flag provided but not defined: -bogus"`, `Run "mcpmoat help" for usage.`},
		},
		{
			name:       "extra argument",
			args:       []string{"scan", "--no-connect", "extra"},
			wantCode:   exitError,
			wantStderr: []string{`mcpmoat scan: unexpected arguments ["extra"]`, `Run "mcpmoat help" for usage.`},
		},
		{
			name:       "empty config name",
			args:       []string{"scan", "--no-connect", "--config", ""},
			wantCode:   exitError,
			wantStderr: []string{"--config needs a file name", `Run "mcpmoat help" for usage.`},
		},
		{
			name:       "empty config name with equals sign",
			args:       []string{"scan", "--no-connect", "--config="},
			wantCode:   exitError,
			wantStderr: []string{"--config needs a file name"},
		},
		{
			// The flag package would take "--no-connect" as the file name.
			name:       "config followed by a scan flag",
			args:       []string{"scan", "--config", "--no-connect"},
			wantCode:   exitError,
			wantStderr: []string{"--config needs a file name"},
		},
		{
			name:       "config given twice",
			args:       []string{"scan", "--no-connect", "--config", "a", "--config", "b"},
			wantCode:   exitError,
			wantStderr: []string{"--config given more than once"},
		},
		{
			// A file name that starts with "-" works as ./-x.json. The file does
			// not exist, so this is a "file not found" error, not a flag error.
			name:       "config file name that starts with a dash",
			args:       []string{"scan", "--no-connect", "--config", "./-x.json"},
			wantCode:   exitError,
			wantStderr: []string{"file not found"},
		},
		{
			name:       "no flags",
			args:       []string{"scan"},
			wantCode:   exitError,
			wantStderr: []string{"not implemented", "use --no-connect"},
		},
		{
			name:       "config without --no-connect",
			args:       []string{"scan", "--config", "x"},
			wantCode:   exitError,
			wantStderr: []string{"not implemented", "use --no-connect"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The default test cli has failing homeDir and getwd. A flag error
			// must come before any directory lookup.
			c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)

			code := c.dispatch(tt.args)

			if code != tt.wantCode {
				t.Errorf("dispatch(%q) = %d, want %d", tt.args, code, tt.wantCode)
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout does not contain %q\nstdout: %s", want, stdout)
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr does not contain %q\nstderr: %s", want, stderr)
				}
			}
			if len(tt.wantStdout) == 0 && stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if len(tt.wantStderr) == 0 && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr)
			}
			assertNoEscape(t, stdout.String(), stderr.String())
		})
	}
}

// TestScanHelpMatchesUsage checks that "scan -h" prints exactly the scan
// section of the main help.
func TestScanHelpMatchesUsage(t *testing.T) {
	t.Parallel()

	c, stdout, _ := newTestCLI(fakeGetenv(nil), testBuild)
	c.scanUsage(stdout)
	want := stdout.String()

	c2, stdout2, _ := newTestCLI(fakeGetenv(nil), testBuild)
	if code := c2.dispatch([]string{"scan", "-h"}); code != exitOK {
		t.Fatalf("scan -h = %d, want %d", code, exitOK)
	}
	if got := stdout2.String(); got != want {
		t.Errorf("scan -h stdout = %q, want %q", got, want)
	}
	if !strings.Contains(usageText(t), want) {
		t.Errorf("the main help does not contain the scan usage %q", want)
	}
}

// scanNormalize makes the table output the same on every machine. The tests
// copy the fixture into a temporary directory, so the output holds those
// paths. Normalizing does three things:
//   - It replaces the two temporary paths with $HOME and $WORK.
//   - It aligns the columns again. tabwriter pads each column to its widest
//     cell, and the SOURCE column holds the temporary paths, so the padding
//     depends on the length of the path. The function splits each line at
//     runs of three or more spaces (the gap between two columns is always at
//     least three, and no cell holds three spaces in a row) and writes the
//     cells through a new tabwriter with the same settings as report.WriteServers.
//   - It turns backslashes into slashes, for Windows paths.
func scanNormalize(t *testing.T, out string, replacements map[string]string) string {
	t.Helper()
	// Replace the longer path first, in case one path is inside the other.
	paths := make([]string, 0, len(replacements))
	for p := range replacements {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, p := range paths {
		out = strings.ReplaceAll(out, p, replacements[p])
	}
	out = filepath.ToSlash(out)

	gap := regexp.MustCompile(` {3,}`)
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 0, 3, ' ', 0)
	for line := range strings.SplitSeq(strings.TrimSuffix(out, "\n"), "\n") {
		if _, err := fmt.Fprintln(tw, gap.ReplaceAllString(line, "\t")); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Flush(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// assertScanGolden compares got with the golden file. With -update it writes
// the file first.
func assertScanGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name+".golden")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: path is built from a fixed golden file name in the test
	if err != nil {
		t.Fatalf("read golden (run the test with -update to create it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s; run the test with -update and review the diff\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func TestScanNoConnectGolden(t *testing.T) {
	t.Parallel()

	c, stdout, stderr, home, work := scanCLI(t, "all", "full")

	code := c.dispatch([]string{"scan", "--no-connect"})

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitOK, stderr)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	got := scanNormalize(t, stdout.String(), map[string]string{home: "$HOME", work: "$WORK"})
	assertScanGolden(t, "scan_no_connect_full", []byte(got))
}

func TestScanAutoPartialFailure(t *testing.T) {
	t.Parallel()

	c, stdout, stderr, _, _ := scanCLI(t, "all", "partial-failure")

	code := c.dispatch([]string{"scan", "--no-connect"})

	if code != exitError {
		t.Errorf("exit code = %d, want %d (a bad global file fails the scan)", code, exitError)
	}
	if rows := scanRows(t, stdout.String()); len(rows) != 4 {
		t.Errorf("table has %d rows, want 4\nstdout:\n%s", len(rows), stdout)
	}
	lines := scanNonEmptyLines(stderr.String())
	if len(lines) != 2 {
		t.Fatalf("stderr has %d lines, want 2 (the problem and the hint)\nstderr:\n%s", len(lines), stderr)
	}
	for _, want := range []string{"mcpmoat scan: ", ".claude.json", "invalid JSON"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("stderr line does not contain %q\nline: %s", want, lines[0])
		}
	}
	if !strings.HasPrefix(lines[0], "mcpmoat scan: ") || strings.Contains(lines[0], "warning:") {
		t.Errorf("stderr line = %q, want the prefix %q and no warning", lines[0], "mcpmoat scan: ")
	}
	if got, want := lines[1]+"\n", configErrorHint; got != want {
		t.Errorf("last stderr line = %q, want the hint %q", got, want)
	}
}

func TestScanEmpty(t *testing.T) {
	t.Parallel()

	// The "missing" fixture has no home and no work directory, so CopyFixture
	// makes two empty directories.
	c, stdout, stderr, _, _ := scanCLI(t, "claude-code", "missing")

	code := c.dispatch([]string{"scan", "--no-connect"})

	if code != exitOK {
		t.Errorf("exit code = %d, want %d", code, exitOK)
	}
	if got, want := stdout.String(), "No MCP servers found.\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr)
	}
}

func TestScanConfigFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fixture []string
		file    string // path inside the fixture copy
		// homeFile makes the fixture's home directory the user's home, so a
		// file below it is one of the user's own global files. Otherwise the
		// home is an empty directory and the file is untrusted.
		homeFile   bool
		wantClient string
		wantNames  []string
		// wantProject is the project directory of an untrusted file, inside
		// the fixture copy. "" means the file is read as a global file.
		wantProject string
	}{
		{
			name:       "claude code ~/.claude.json",
			fixture:    []string{"claude-code", "valid"},
			file:       filepath.Join("home", ".claude.json"),
			homeFile:   true,
			wantClient: "claude-code",
			wantNames:  []string{"filesystem", "remote-http", "remote-sse", "alpha-tool", "gamma-tool"},
		},
		{
			// Not the home file: the projects section is not read.
			name:        "claude code .claude.json in another directory",
			fixture:     []string{"claude-code", "valid"},
			file:        filepath.Join("home", ".claude.json"),
			wantClient:  "claude-code",
			wantNames:   []string{"filesystem", "remote-http", "remote-sse"},
			wantProject: "home",
		},
		{
			name:        "claude code .mcp.json",
			fixture:     []string{"claude-code", "valid"},
			file:        filepath.Join("work", ".mcp.json"),
			homeFile:    true,
			wantClient:  "claude-code",
			wantNames:   []string{"local-db", "team-api"},
			wantProject: "work",
		},
		{
			name:       "cursor ~/.cursor/mcp.json",
			fixture:    []string{"cursor", "valid"},
			file:       filepath.Join("home", ".cursor", "mcp.json"),
			homeFile:   true,
			wantClient: "cursor",
			wantNames:  []string{"git", "remote", "events"},
		},
		{
			name:        "cursor project mcp.json",
			fixture:     []string{"cursor", "valid"},
			file:        filepath.Join("work", ".cursor", "mcp.json"),
			homeFile:    true,
			wantClient:  "cursor",
			wantNames:   []string{"project-remote", "project-tools"},
			wantProject: "work",
		},
		{
			name:       "codex ~/.codex/config.toml",
			fixture:    []string{"codex", "valid"},
			file:       filepath.Join("home", ".codex", "config.toml"),
			homeFile:   true,
			wantClient: "codex",
			wantNames:  []string{"docs", "remote", "git"},
		},
		{
			name:        "codex config.toml in another directory",
			fixture:     []string{"codex", "valid"},
			file:        filepath.Join("home", ".codex", "config.toml"),
			wantClient:  "codex",
			wantNames:   []string{"docs", "remote", "git"},
			wantProject: "home",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			home, _ := discovertest.CopyFixture(t, scanFixtureDir(tt.fixture...))
			root := filepath.Dir(home)
			userHome := t.TempDir()
			if tt.homeFile {
				userHome = home
			}
			// The forbidden getwd proves that --config does not read the
			// working directory.
			c, stdout, stderr := scanConfigCLI(t, userHome)

			code := c.dispatch([]string{"scan", "--no-connect", "--config", filepath.Join(root, tt.file)})

			if code != exitOK {
				t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitOK, stderr)
			}
			if stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr)
			}
			rows := scanRows(t, stdout.String())
			var names []string
			for _, row := range rows {
				names = append(names, row[0])
				if row[1] != tt.wantClient {
					t.Errorf("row %q has client %q, want %q", row[0], row[1], tt.wantClient)
				}
				if tt.wantProject != "" {
					// An untrusted file shows as a project file in SCOPE.
					if want := "project:" + filepath.Join(root, tt.wantProject); row[2] != want {
						t.Errorf("row %q has scope %q, want %q", row[0], row[2], want)
					}
				}
			}
			slices.Sort(names)
			want := slices.Clone(tt.wantNames)
			slices.Sort(want)
			if !slices.Equal(names, want) {
				t.Errorf("server names = %q, want %q", names, want)
			}
		})
	}
}

func TestScanConfigErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup returns the --config argument. It may write files.
		setup           func(t *testing.T) string
		wantStdout      []string
		wantStdoutEmpty bool
		wantStderr      []string
		wantStderrLines int
	}{
		{
			name: "missing file",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nope.json")
			},
			wantStdoutEmpty: true,
			wantStderr:      []string{"mcpmoat scan: ", "nope.json", "file not found"},
			wantStderrLines: 1,
		},
		{
			name: "unknown format",
			setup: func(t *testing.T) string {
				return scanWriteFile(t, t.TempDir(), "notes.txt", "hello\n")
			},
			wantStdoutEmpty: true,
			wantStderr:      []string{"mcpmoat scan: ", "notes.txt", "unknown config format"},
			wantStderrLines: 1,
		},
		{
			name: "malformed JSON",
			setup: func(t *testing.T) string {
				home, _ := discovertest.CopyFixture(t, scanFixtureDir("claude-code", "malformed"))
				return filepath.Join(home, ".claude.json")
			},
			wantStdoutEmpty: true,
			wantStderr:      []string{"mcpmoat scan: ", "invalid JSON"},
			wantStderrLines: 1,
		},
		{
			name: "invalid entries",
			setup: func(t *testing.T) string {
				home, _ := discovertest.CopyFixture(t, scanFixtureDir("cursor", "invalid-entries"))
				return filepath.Join(home, ".cursor", "mcp.json")
			},
			wantStdout:      []string{"good"},
			wantStderr:      []string{"mcpmoat scan: ", configErrorHint},
			wantStderrLines: 5, // 4 problems and the hint
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, stdout, stderr := scanConfigCLI(t, t.TempDir())
			path := tt.setup(t)

			code := c.dispatch([]string{"scan", "--no-connect", "--config", path})

			if code != exitError {
				t.Errorf("exit code = %d, want %d", code, exitError)
			}
			if tt.wantStdoutEmpty && stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout does not contain %q\nstdout: %s", want, stdout)
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr does not contain %q\nstderr: %s", want, stderr)
				}
			}
			lines := scanNonEmptyLines(stderr.String())
			if len(lines) != tt.wantStderrLines {
				t.Errorf("stderr has %d lines, want %d\nstderr:\n%s", len(lines), tt.wantStderrLines, stderr)
			}
			for _, line := range lines {
				if !strings.HasPrefix(line, "mcpmoat scan: ") || strings.HasPrefix(line, "mcpmoat scan: warning: ") {
					t.Errorf("stderr line %q must start with %q and not be a warning", line, "mcpmoat scan: ")
				}
			}
		})
	}

	t.Run("malformed JSON has line and column", func(t *testing.T) {
		t.Parallel()

		c, _, stderr := scanConfigCLI(t, t.TempDir())
		home, _ := discovertest.CopyFixture(t, scanFixtureDir("claude-code", "malformed"))

		code := c.dispatch([]string{"scan", "--no-connect", "--config", filepath.Join(home, ".claude.json")})

		if code != exitError {
			t.Errorf("exit code = %d, want %d", code, exitError)
		}
		if !regexp.MustCompile(`\.claude\.json:\d+:\d+: invalid JSON`).MatchString(stderr.String()) {
			t.Errorf("stderr does not show path:line:col and the reason\nstderr: %s", stderr)
		}
	})
}

func TestScanDirectoryErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		homeErr    bool
		wantStderr string
	}{
		{name: "home directory error", homeErr: true, wantStderr: "cannot find the home directory"},
		{name: "working directory error", homeErr: false, wantStderr: "working directory"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)
			if !tt.homeErr {
				home := t.TempDir()
				c.homeDir = func() (string, error) { return home, nil }
			}
			// In the first case homeDir fails, so getwd is not called. In the
			// second case homeDir succeeds and getwd fails (the default of
			// newTestCLI).

			code := c.dispatch([]string{"scan", "--no-connect"})

			if code != exitError {
				t.Errorf("exit code = %d, want %d", code, exitError)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr does not contain %q\nstderr: %s", tt.wantStderr, stderr)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout)
			}
		})
	}
}

// TestScanStartsNoProcess proves that --no-connect never runs a configured
// command. One server points to a script that would create a marker file. The
// other points to a path that does not exist.
func TestScanStartsNoProcess(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	servers := map[string]any{
		"missing-cmd": map[string]any{"command": "/nonexistent/mcpmoat-test"},
	}
	if runtime.GOOS != "windows" {
		script := scanWriteFile(t, dir, "server.sh", "#!/bin/sh\ntouch "+marker+"\n")
		if err := os.Chmod(script, 0o700); err != nil { //nolint:gosec // G302: the test script must be executable
			t.Fatal(err)
		}
		servers["script-cmd"] = map[string]any{"command": script}
	}
	data, err := json.Marshal(map[string]any{"mcpServers": servers})
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	scanWriteFile(t, home, ".claude.json", string(data))
	work := t.TempDir()

	c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)
	c.homeDir = func() (string, error) { return home, nil }
	c.getwd = func() (string, error) { return work, nil }

	code := c.dispatch([]string{"scan", "--no-connect"})

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitOK, stderr)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	for name := range servers {
		if !strings.Contains(stdout.String(), name) {
			t.Errorf("stdout does not list %q\nstdout:\n%s", name, stdout)
		}
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("marker file exists or cannot be checked (err = %v): the script ran", err)
	}
}

// TestScanOpensNoConnection proves that --no-connect never calls a configured
// URL. The test server counts every request.
func TestScanOpensNoConnection(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(srv.Close)

	// The URL has credentials and a query secret. The table must show the
	// redacted form.
	host := srv.Listener.Addr().String()
	rawURL := "http://user:" + discovertest.CanaryURL + "@" + host + "/mcp?key=" + discovertest.CanaryURL
	wantURL := "http://" + discover.Mask + "@" + host + "/mcp"

	home := t.TempDir()
	work := t.TempDir()
	entry := func(transport string) map[string]any {
		return map[string]any{"type": transport, "url": rawURL}
	}
	write := func(dir, name string, servers map[string]any) {
		data, err := json.Marshal(map[string]any{"mcpServers": servers})
		if err != nil {
			t.Fatal(err)
		}
		scanWriteFile(t, dir, name, string(data))
	}
	write(work, ".mcp.json", map[string]any{"claude-http": entry("http"), "claude-sse": entry("sse")})
	write(home, filepath.Join(".cursor", "mcp.json"), map[string]any{"cursor-http": entry("http"), "cursor-sse": entry("sse")})

	c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)
	c.homeDir = func() (string, error) { return home, nil }
	c.getwd = func() (string, error) { return work, nil }

	code := c.dispatch([]string{"scan", "--no-connect"})

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitOK, stderr)
	}
	rows := scanRows(t, stdout.String())
	if len(rows) != 4 {
		t.Errorf("table has %d rows, want 4\nstdout:\n%s", len(rows), stdout)
	}
	if got := strings.Count(stdout.String(), wantURL); got != 4 {
		t.Errorf("stdout shows the redacted URL %q %d times, want 4\nstdout:\n%s", wantURL, got, stdout)
	}
	discovertest.AssertNoLeak(t, "stdout", stdout.String())
	discovertest.AssertNoLeak(t, "stderr", stderr.String())
	if got := requests.Load(); got != 0 {
		t.Errorf("the test server got %d requests, want 0", got)
	}
}

func TestScanNoLeak(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fixture []string
		// configFiles are the files for the --config runs, inside the copy.
		configFiles []string
	}{
		{
			name:    "claude code",
			fixture: []string{"claude-code", "secrets"},
			configFiles: []string{
				filepath.Join("home", ".claude.json"),
				filepath.Join("work", ".mcp.json"),
			},
		},
		{
			name:    "cursor",
			fixture: []string{"cursor", "secrets"},
			configFiles: []string{
				filepath.Join("home", ".cursor", "mcp.json"),
				filepath.Join("work", ".cursor", "mcp.json"),
			},
		},
		{
			name:        "codex",
			fixture:     []string{"codex", "secrets"},
			configFiles: []string{filepath.Join("home", ".codex", "config.toml")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/auto", func(t *testing.T) {
			t.Parallel()

			c, stdout, stderr, _, _ := scanCLI(t, tt.fixture...)

			code := c.dispatch([]string{"scan", "--no-connect"})

			if code != exitOK {
				t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitOK, stderr)
			}
			if len(scanRows(t, stdout.String())) == 0 {
				t.Errorf("table has no rows, so the test checks nothing\nstdout:\n%s", stdout)
			}
			scanAssertNoSecret(t, stdout.String(), stderr.String())
		})

		for _, file := range tt.configFiles {
			t.Run(tt.name+"/config/"+filepath.ToSlash(file), func(t *testing.T) {
				t.Parallel()

				home, _ := discovertest.CopyFixture(t, scanFixtureDir(tt.fixture...))
				// With the fixture's home as the user's home, the home files
				// are read as global files and the work files as untrusted.
				c, stdout, stderr := scanConfigCLI(t, home)
				path := filepath.Join(filepath.Dir(home), file)

				code := c.dispatch([]string{"scan", "--no-connect", "--config", path})

				if code != exitOK {
					t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitOK, stderr)
				}
				if len(scanRows(t, stdout.String())) == 0 {
					t.Errorf("table has no rows, so the test checks nothing\nstdout:\n%s", stdout)
				}
				scanAssertNoSecret(t, stdout.String(), stderr.String())
			})
		}
	}
}

// scanAssertNoSecret fails if stdout or stderr holds a canary value or an env
// key from the secrets fixtures.
func scanAssertNoSecret(t *testing.T, stdout, stderr string) {
	t.Helper()
	discovertest.AssertNoLeak(t, "stdout", stdout)
	discovertest.AssertNoLeak(t, "stderr", stderr)
	for name, out := range map[string]string{"stdout": stdout, "stderr": stderr} {
		if strings.Contains(out, "API_KEY") {
			t.Errorf("%s shows the env key API_KEY, but it must show no env at all\n%s", name, out)
		}
	}
}

func TestScanTerminalSafety(t *testing.T) {
	t.Parallel()

	// The JSON escapes below are decoded by the JSON reader of mcpmoat, so the
	// Go source and the file hold no raw control character. The values are:
	// ESC in the server name, a tab in the command, and U+202E (a bidi
	// override) in an argument.
	const config = `{"mcpServers":{"a\u001b[31mb":{"command":"echo\tx","args":["\u202e"]}}}`

	// The name shows in Go quoted form (Escape uses strconv.Quote). The
	// command and the args go through the RedactArgs allowlist, which masks
	// every part with a character that is not safe.
	wantName := strconv.Quote("a\x1b[31mb")
	wantCommand := discover.Mask + " " + discover.Mask

	c, stdout, stderr := scanConfigCLI(t, t.TempDir())
	path := scanWriteFile(t, t.TempDir(), ".mcp.json", config)

	code := c.dispatch([]string{"scan", "--no-connect", "--config", path})

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitOK, stderr)
	}
	out := stdout.String()
	assertNoEscape(t, out, stderr.String())
	if strings.Contains(out, "\t") {
		t.Errorf("stdout has a raw tab\n%q", out)
	}
	if strings.Contains(out, "\u202e") {
		t.Errorf("stdout has a raw U+202E\n%q", out)
	}
	for _, want := range []string{wantName, wantCommand} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout does not contain %s\n%q", want, out)
		}
	}
	// The row must keep its shape: header line and one row line.
	if lines := scanNonEmptyLines(out); len(lines) != 2 {
		t.Errorf("stdout has %d lines, want 2\n%q", len(lines), out)
	}
}

func TestScanNoColor(t *testing.T) {
	t.Parallel()

	home, work := discovertest.CopyFixture(t, scanFixtureDir("all", "full"))

	// runWith runs the scan with one set of args and one environment on the
	// same home and working directory copies.
	runWith := func(args []string, env map[string]string) (string, string, int) {
		c, stdout, stderr := newTestCLI(fakeGetenv(env), testBuild)
		c.homeDir = func() (string, error) { return home, nil }
		c.getwd = func() (string, error) { return work, nil }
		code := c.dispatch(args)
		return stdout.String(), stderr.String(), code
	}

	plain, plainErr, plainCode := runWith([]string{"scan", "--no-connect"}, nil)
	if plainCode != exitOK || plainErr != "" {
		t.Fatalf("plain run: exit code = %d, stderr = %q", plainCode, plainErr)
	}

	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{name: "--no-color flag", args: []string{"--no-color", "scan", "--no-connect"}},
		{name: "NO_COLOR=1", args: []string{"scan", "--no-connect"}, env: map[string]string{"NO_COLOR": "1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, gotErr, code := runWith(tt.args, tt.env)

			if code != exitOK {
				t.Errorf("exit code = %d, want %d", code, exitOK)
			}
			if got != plain {
				t.Errorf("stdout differs from the plain run\n--- got ---\n%s\n--- want ---\n%s", got, plain)
			}
			if gotErr != "" {
				t.Errorf("stderr = %q, want empty", gotErr)
			}
			assertNoEscape(t, got, gotErr)
		})
	}
	assertNoEscape(t, plain, plainErr)
}

// scanFailWriter is a writer that always fails, like a closed pipe.
type scanFailWriter struct{}

func (scanFailWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestScanWriteError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fixture []string
	}{
		{name: "table", fixture: []string{"all", "full"}},
		{name: "empty state line", fixture: []string{"claude-code", "missing"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, _, stderr, _, _ := scanCLI(t, tt.fixture...)
			c.stdout = scanFailWriter{}

			code := c.dispatch([]string{"scan", "--no-connect"})

			if code != exitError {
				t.Errorf("exit code = %d, want %d", code, exitError)
			}
			if !strings.Contains(stderr.String(), "cannot write output") {
				t.Errorf("stderr does not contain %q\nstderr: %s", "cannot write output", stderr)
			}
		})
	}
}

// TestScanArgsMasked checks that the COMMAND/URL cell never shows an argument
// as written. The configs put the args canary in secret-like shapes, in a
// global and in a project file.
func TestScanArgsMasked(t *testing.T) {
	t.Parallel()

	const c = discovertest.CanaryArgs
	args := []string{
		"-y", "@scope/server",
		"--token", c,
		"--api-key=" + c,
		"-e", "GITHUB_TOKEN=" + c,
		"-H", "Authorization: Bearer " + c,
		"postgres://user:" + c + "@db.example.com/app",
		"https://h.example.com/sse?key=" + c,
		`{"token":"` + c + `"}`,
		"/data/" + c + "/x",
		"admin:" + c,
		"-p" + c,
		c,
	}
	data, err := json.Marshal(map[string]any{
		"mcpServers": map[string]any{"srv": map[string]any{"command": "npx", "args": args}},
	})
	if err != nil {
		t.Fatal(err)
	}
	home, work := t.TempDir(), t.TempDir()
	scanWriteFile(t, home, ".claude.json", string(data))
	scanWriteFile(t, work, ".mcp.json", string(data))

	c2, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)
	c2.homeDir = func() (string, error) { return home, nil }
	c2.getwd = func() (string, error) { return work, nil }

	code := c2.dispatch([]string{"scan", "--no-connect"})

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitOK, stderr)
	}
	discovertest.AssertNoLeak(t, "stdout", stdout.String())
	discovertest.AssertNoLeak(t, "stderr", stderr.String())
	// The safe parts stay, so the leak check is not a pass on empty output.
	if got := strings.Count(stdout.String(), "npx -y @scope/server --token "+discover.Mask+" "); got != 2 {
		t.Errorf("stdout shows the redacted command line %d times, want 2\nstdout:\n%s", got, stdout)
	}
}

// TestScanAutoExitCodes checks the exit code of auto-discovery for problems
// with config files. Any problem (a discover.FileError), with a project file
// in the working directory or with one of the user's own global files, gives
// exit code 2 after the table, the problems and the hint are printed. A
// missing file is not a problem.
func TestScanAutoExitCodes(t *testing.T) {
	t.Parallel()

	// outsideConfig is a config outside the working directory. The canary in
	// its args must never show, also when mcpmoat refuses the file.
	outsideConfig := `{"mcpServers":{"outside":{"command":"run","args":["` + discovertest.CanaryArgs + `"]}}}`
	const globalConfig = `{"mcpServers":{"global-srv":{"command":"npx"}}}`

	// symlink makes link point to target. It skips the test when the system
	// cannot make a symlink (Windows without the right privilege).
	symlink := func(t *testing.T, target, link string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink: %v", err)
		}
	}

	tests := []struct {
		name string
		// setup writes files below home and work. outside is a directory
		// outside both.
		setup      func(t *testing.T, home, work, outside string)
		wantCode   int
		wantStdout []string // substrings of stdout
		wantStderr []string // substrings of stderr
	}{
		{
			name: ".mcp.json is a symlink out of the project",
			setup: func(t *testing.T, home, work, outside string) {
				scanWriteFile(t, home, ".claude.json", globalConfig)
				symlink(t, scanWriteFile(t, outside, "real.json", outsideConfig), filepath.Join(work, ".mcp.json"))
			},
			wantCode:   exitError,
			wantStdout: []string{"global-srv"},
			wantStderr: []string{"mcpmoat scan: ", ".mcp.json: file is outside the project", configErrorHint},
		},
		{
			name: ".cursor/mcp.json is a symlink out of the project",
			setup: func(t *testing.T, home, work, outside string) {
				scanWriteFile(t, home, ".claude.json", globalConfig)
				symlink(t, scanWriteFile(t, outside, "mcp.json", outsideConfig), filepath.Join(work, ".cursor", "mcp.json"))
			},
			wantCode:   exitError,
			wantStdout: []string{"global-srv"},
			wantStderr: []string{"mcp.json: file is outside the project", configErrorHint},
		},
		{
			name: "project file is invalid JSON",
			setup: func(t *testing.T, home, work, _ string) {
				scanWriteFile(t, home, ".claude.json", globalConfig)
				scanWriteFile(t, work, ".mcp.json", `{"mcpServers":`)
			},
			wantCode:   exitError,
			wantStdout: []string{"global-srv"},
			wantStderr: []string{".mcp.json:1:", "invalid JSON", configErrorHint},
		},
		{
			name: "no servers at all still prints the empty line first",
			setup: func(t *testing.T, _, work, outside string) {
				symlink(t, scanWriteFile(t, outside, "real.json", outsideConfig), filepath.Join(work, ".mcp.json"))
			},
			wantCode:   exitError,
			wantStdout: []string{"No MCP servers found."},
			wantStderr: []string{"file is outside the project", configErrorHint},
		},
		{
			name: "relative project symlink that stays inside the project is followed",
			setup: func(t *testing.T, _, work, _ string) {
				scanWriteFile(t, work, filepath.Join("conf", "mcp.json"), `{"mcpServers":{"inside":{"command":"npx"}}}`)
				symlink(t, filepath.Join("conf", "mcp.json"), filepath.Join(work, ".mcp.json"))
			},
			wantCode:   exitOK,
			wantStdout: []string{"inside"},
		},
		{
			// os.Root refuses every absolute symlink, also one that points
			// into the project.
			name: "absolute project symlink is refused",
			setup: func(t *testing.T, _, work, _ string) {
				target := scanWriteFile(t, work, filepath.Join("conf", "mcp.json"), `{"mcpServers":{"inside":{"command":"npx"}}}`)
				symlink(t, target, filepath.Join(work, ".mcp.json"))
			},
			wantCode:   exitError,
			wantStdout: []string{"No MCP servers found."},
			wantStderr: []string{"file is outside the project", configErrorHint},
		},
		{
			name: "global file with invalid JSON fails the scan",
			setup: func(t *testing.T, home, work, _ string) {
				scanWriteFile(t, home, ".claude.json", `{"mcpServers":`)
				scanWriteFile(t, work, ".mcp.json", `{"mcpServers":{"project-srv":{"command":"npx"}}}`)
			},
			wantCode:   exitError,
			wantStdout: []string{"project-srv"},
			wantStderr: []string{"mcpmoat scan: ", ".claude.json:1:", "invalid JSON", configErrorHint},
		},
		{
			name: "global file with an ambiguous key fails the scan",
			setup: func(t *testing.T, home, _, _ string) {
				scanWriteFile(t, home, filepath.Join(".cursor", "mcp.json"),
					`{"mcpServers":{"amb":{"command":"npx","Command":"evil"},"ok-srv":{"command":"uvx"}}}`)
			},
			wantCode:   exitError,
			wantStdout: []string{"ok-srv"},
			wantStderr: []string{"mcpmoat scan: ", "server amb", "ambiguous key", configErrorHint},
		},
		{
			name: "global codex file that is not valid TOML fails the scan",
			setup: func(t *testing.T, home, _, _ string) {
				scanWriteFile(t, home, filepath.Join(".codex", "config.toml"), "[mcp_servers.a\n")
			},
			wantCode:   exitError,
			wantStdout: []string{"No MCP servers found."},
			wantStderr: []string{"config.toml:1:", "invalid TOML", configErrorHint},
		},
		{
			name: "missing files are not a problem",
			setup: func(t *testing.T, home, _, _ string) {
				scanWriteFile(t, home, ".claude.json", globalConfig)
			},
			wantCode:   exitOK,
			wantStdout: []string{"global-srv"},
		},
		{
			name:       "no config files at all",
			setup:      func(*testing.T, string, string, string) {},
			wantCode:   exitOK,
			wantStdout: []string{"No MCP servers found."},
		},
		{
			name: "global symlink out of the home directory is followed",
			setup: func(t *testing.T, home, _, outside string) {
				symlink(t, scanWriteFile(t, outside, "real.json", outsideConfig), filepath.Join(home, ".cursor", "mcp.json"))
			},
			wantCode:   exitOK,
			wantStdout: []string{"outside", "run " + discover.Mask},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			home, work, outside := t.TempDir(), t.TempDir(), t.TempDir()
			tt.setup(t, home, work, outside)
			c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)
			c.homeDir = func() (string, error) { return home, nil }
			c.getwd = func() (string, error) { return work, nil }

			code := c.dispatch([]string{"scan", "--no-connect"})

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, stdout, stderr)
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout does not contain %q\nstdout:\n%s", want, stdout)
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr does not contain %q\nstderr:\n%s", want, stderr)
				}
			}
			if len(tt.wantStderr) == 0 && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr)
			}
			for _, line := range scanNonEmptyLines(stderr.String()) {
				if !strings.HasPrefix(line, "mcpmoat scan: ") || strings.Contains(line, "warning:") {
					t.Errorf("stderr line %q must start with %q and not be a warning", line, "mcpmoat scan: ")
				}
			}
			discovertest.AssertNoLeak(t, "stdout", stdout.String())
			discovertest.AssertNoLeak(t, "stderr", stderr.String())
			assertNoEscape(t, stdout.String(), stderr.String())
		})
	}
}

// TestScanConfigIsUntrusted checks that --config reads a file as an untrusted
// project file: the read is confined to the directory of the file, the
// servers show as project servers, and the "projects" section of a Claude
// Code file is not read. The exception is a path that resolves to one of the
// user's own global files: that file is read as a global file.
func TestScanConfigIsUntrusted(t *testing.T) {
	t.Parallel()

	// symlink makes link point to target. It skips the test when the system
	// cannot make a symlink (Windows without the right privilege).
	symlink := func(t *testing.T, target, link string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink: %v", err)
		}
	}

	// outsideConfig is a config outside the directory of the --config file.
	// The canary in its args must never show.
	outsideConfig := `{"mcpServers":{"outside":{"command":"run","args":["` + discovertest.CanaryArgs + `"]}}}`
	const withProjects = `{"mcpServers":{"top-srv":{"command":"npx"}},` +
		`"projects":{"/p":{"mcpServers":{"proj-srv":{"command":"npx"}}}}}`

	tests := []struct {
		name string
		// setup writes the files and returns the --config argument. home is
		// the user's home directory, repo a directory outside it, outside a
		// third directory.
		setup      func(t *testing.T, home, repo, outside string) string
		wantCode   int
		wantStdout []string
		noStdout   []string
		wantStderr []string
	}{
		{
			name: "repository .mcp.json is a project file",
			setup: func(t *testing.T, _, repo, _ string) string {
				return scanWriteFile(t, repo, ".mcp.json", `{"mcpServers":{"repo-srv":{"command":"npx"}}}`)
			},
			wantCode:   exitOK,
			wantStdout: []string{"repo-srv", "project:"},
			noStdout:   []string{"global"},
		},
		{
			name: "symlink out of the directory is refused",
			setup: func(t *testing.T, _, repo, outside string) string {
				link := filepath.Join(repo, ".mcp.json")
				symlink(t, scanWriteFile(t, outside, "real.json", outsideConfig), link)
				return link
			},
			wantCode:   exitError,
			noStdout:   []string{"outside"},
			wantStderr: []string{"mcpmoat scan: ", ".mcp.json: file is outside the project"},
		},
		{
			name: "projects section of a .claude.json outside home is not read",
			setup: func(t *testing.T, _, repo, _ string) string {
				return scanWriteFile(t, repo, ".claude.json", withProjects)
			},
			wantCode:   exitOK,
			wantStdout: []string{"top-srv", "project:"},
			noStdout:   []string{"proj-srv"},
		},
		{
			name: "the home ~/.claude.json is a global file",
			setup: func(t *testing.T, home, _, _ string) string {
				return scanWriteFile(t, home, ".claude.json", withProjects)
			},
			wantCode:   exitOK,
			wantStdout: []string{"top-srv", "global", "proj-srv", "project:/p"},
		},
		{
			name: "a symlink to the home ~/.claude.json is a global file",
			setup: func(t *testing.T, home, repo, _ string) string {
				link := filepath.Join(repo, "mine.json")
				symlink(t, scanWriteFile(t, home, ".claude.json", withProjects), link)
				return link
			},
			wantCode:   exitOK,
			wantStdout: []string{"top-srv", "global", "proj-srv", "project:/p"},
		},
		{
			name: "codex file outside home is a project file",
			setup: func(t *testing.T, _, repo, _ string) string {
				return scanWriteFile(t, repo, filepath.Join(".codex", "config.toml"), "[mcp_servers.codex-srv]\ncommand = \"npx\"\n")
			},
			wantCode:   exitOK,
			wantStdout: []string{"codex-srv", "codex", "project:"},
			noStdout:   []string{"global"},
		},
		{
			name: "codex symlink out of the directory is refused",
			setup: func(t *testing.T, _, repo, outside string) string {
				target := scanWriteFile(t, outside, "real.toml",
					"[mcp_servers.outside]\ncommand = \"run\"\nargs = [\""+discovertest.CanaryArgs+"\"]\n")
				link := filepath.Join(repo, ".codex", "config.toml")
				symlink(t, target, link)
				return link
			},
			wantCode:   exitError,
			noStdout:   []string{"outside"},
			wantStderr: []string{"config.toml: file is outside the project"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			home, repo, outside := t.TempDir(), t.TempDir(), t.TempDir()
			path := tt.setup(t, home, repo, outside)
			c, stdout, stderr := scanConfigCLI(t, home)

			code := c.dispatch([]string{"scan", "--no-connect", "--config", path})

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, stdout, stderr)
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout does not contain %q\nstdout:\n%s", want, stdout)
				}
			}
			for _, bad := range tt.noStdout {
				if strings.Contains(stdout.String(), bad) {
					t.Errorf("stdout contains %q\nstdout:\n%s", bad, stdout)
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr does not contain %q\nstderr:\n%s", want, stderr)
				}
			}
			if len(tt.wantStderr) == 0 && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr)
			}
			discovertest.AssertNoLeak(t, "stdout", stdout.String())
			discovertest.AssertNoLeak(t, "stderr", stderr.String())
			assertNoEscape(t, stdout.String(), stderr.String())
		})
	}

	t.Run("no home directory reads the file as untrusted", func(t *testing.T) {
		t.Parallel()

		path := scanWriteFile(t, t.TempDir(), ".claude.json", withProjects)
		c, stdout, stderr := scanConfigCLI(t, "")
		c.homeDir = func() (string, error) { return "", errors.New("no home") }

		code := c.dispatch([]string{"scan", "--no-connect", "--config", path})

		if code != exitOK {
			t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitOK, stderr)
		}
		if out := stdout.String(); !strings.Contains(out, "top-srv") || strings.Contains(out, "proj-srv") {
			t.Errorf("stdout = %q, want top-srv and no proj-srv", out)
		}
		if stderr.Len() != 0 {
			t.Errorf("stderr = %q, want empty", stderr)
		}
	})
}
