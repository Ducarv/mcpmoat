package main

import (
	"bytes"
	"cmp"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
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

// scanCLI builds a test cli whose home and working directory are fresh copies
// of the fixture. It returns the cli, the two output buffers and the two copy
// paths. The tests never touch the fixture itself.
func scanCLI(t *testing.T, fixture ...string) (c *cli, stdout, stderr *bytes.Buffer, home, work string) {
	t.Helper()
	home, work = discovertest.CopyFixture(t, fixtureDir(fixture...))
	c, stdout, stderr = dirsCLI(t, home, work)
	return c, stdout, stderr, home, work
}

// scanConfigCLI returns a cli for --config runs with an absolute path. Its
// homeDir returns home, which --config uses only to tell whether the file is
// one of the user's own global files. Its getwd fails the test when it is
// called: it proves that --config with an absolute path never looks at the
// working directory. A test with a relative path uses dirsCLI instead.
func scanConfigCLI(t *testing.T, home string) (*cli, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	c, stdout, stderr := dirsCLI(t, home, "")
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
			wantStderr: []string{"mcpmoat scan: flag provided but not defined: -bogus\n", usageHint},
		},
		{
			// %q keeps a blank rune as it is. termsafe.Quote escapes it.
			name:       "unknown flag with a blank rune",
			args:       []string{"scan", "--\u3164"},
			wantCode:   exitError,
			wantStderr: []string{`mcpmoat scan: "flag provided but not defined: -\u3164"`},
		},
		{
			name:       "extra argument",
			args:       []string{"scan", "--no-connect", "extra"},
			wantCode:   exitError,
			wantStderr: []string{`mcpmoat scan: unexpected arguments ["extra"]`, usageHint},
		},
		{
			name:       "empty config name",
			args:       []string{"scan", "--no-connect", "--config", ""},
			wantCode:   exitError,
			wantStderr: []string{"--config needs a file name", usageHint},
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
			name:       "config followed by a scan flag with a value",
			args:       []string{"scan", "--config", "--no-connect=true"},
			wantCode:   exitError,
			wantStderr: []string{"--config needs a file name"},
		},
		{
			name:       "config followed by itself with one dash and a value",
			args:       []string{"scan", "--no-connect", "--config", "-config=x"},
			wantCode:   exitError,
			wantStderr: []string{"--config needs a file name"},
		},
		{
			name:       "config followed by a help flag",
			args:       []string{"scan", "--no-connect", "--config", "--h"},
			wantCode:   exitError,
			wantStderr: []string{"--config needs a file name"},
		},
		{
			name:       "config followed by a long help flag",
			args:       []string{"scan", "--no-connect", "--config", "-help"},
			wantCode:   exitError,
			wantStderr: []string{"--config needs a file name"},
		},
		{
			// "-x.json" is no scan flag, so it is a file name. The file does
			// not exist.
			name:       "config file name that starts with a dash and is no flag",
			args:       []string{"scan", "--no-connect", "--config", "-x.json"},
			wantCode:   exitError,
			wantStderr: []string{"-x.json", "file not found"},
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
			assertContainsAll(t, "stdout", stdout.String(), tt.wantStdout)
			assertContainsAll(t, "stderr", stderr.String(), tt.wantStderr)
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

	var buf bytes.Buffer
	scanUsage(&buf)
	want := buf.String()

	c, stdout, _ := newTestCLI(fakeGetenv(nil), testBuild)
	if code := c.dispatch([]string{"scan", "-h"}); code != exitOK {
		t.Fatalf("scan -h = %d, want %d", code, exitOK)
	}
	if got := stdout.String(); got != want {
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
	paths := slices.SortedFunc(maps.Keys(replacements), func(a, b string) int { return cmp.Compare(len(b), len(a)) })
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
	assertNoRulesNotice(t, stderr.String())
	got := scanNormalize(t, stdout.String(), map[string]string{home: "$HOME", work: "$WORK"})
	assertScanGolden(t, "scan_no_connect_full", []byte(got))
}

// stateCells maps the NAME of each table row to its STATE cell. STATE is the
// fifth column, after TRANSPORT. The SCOPE cell of an untrusted server ends
// with the extra word "(untrusted)", so the STATE word moves one place right.
// The fixture names and temporary paths hold no space, so the words before
// STATE are the cells themselves.
func stateCells(t *testing.T, stdout string) map[string]string {
	t.Helper()
	states := make(map[string]string)
	for _, row := range tableRows(t, stdout) {
		i := 4
		if len(row) > 3 && row[3] == "(untrusted)" {
			i = 5
		}
		if len(row) <= i {
			t.Fatalf("row %q has no STATE cell", row)
		}
		states[row[0]] = row[i]
	}
	return states
}

// serverStateCases are the fixtures of the STATE column tests, with the
// STATE of every row. TestScanNoConnectState runs them in-process and
// TestE2EScanServerState with the real binary. The binary runs in the work
// directory of the fixture, so it reads the project files there, as the
// in-process cli does. Tests must not change the maps.
var serverStateCases = []struct {
	name    string
	fixture []string
	want    map[string]string // NAME -> STATE, for every row
}{
	{
		// ~/.codex/config.toml has enabled = false on "git" only.
		name:    "codex enabled key",
		fixture: []string{"codex", "valid"},
		want: map[string]string{
			"docs":   "enabled",
			"remote": "enabled",
			"git":    "disabled",
		},
	},
	{
		// The user's own ~/.claude/settings.json approves approved-srv.
		// work/.claude/settings.local.json approves repo-srv and rejects
		// rejected-srv; that file comes from the repository, so repo-srv
		// is only project-approved. Nothing names pending-srv, so it
		// waits for approval. global-srv comes from ~/.claude.json, which
		// needs no approval.
		name:    "claude code project approval",
		fixture: []string{"claude-code", "state"},
		want: map[string]string{
			"global-srv":   "enabled",
			"approved-srv": "enabled",
			"repo-srv":     "project-approved",
			"rejected-srv": "disabled",
			"pending-srv":  "unapproved",
		},
	},
}

// TestScanNoConnectState checks the STATE column of scan --no-connect for
// the enabled and approval settings of each client config. The state only
// changes the table: it never changes the exit code.
func TestScanNoConnectState(t *testing.T) {
	t.Parallel()

	for _, tt := range serverStateCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, stdout, stderr, _, _ := scanCLI(t, tt.fixture...)

			code := c.dispatch([]string{"scan", "--no-connect"})

			// A disabled or unapproved server is not a config problem: exit
			// code 0 and only the notice on stderr.
			assertScanResult(t, code, stdout.String(), stderr.String(), scanWant{code: exitOK})
			if got := stateCells(t, stdout.String()); !maps.Equal(got, tt.want) {
				t.Errorf("STATE per server = %v, want %v\nstdout:\n%s", got, tt.want, stdout)
			}
		})
	}
}

// TestScanConfigMcpjsonState checks that scan --config of a project
// .mcp.json shows every server as unapproved: --config reads no settings
// file, so it knows no approval, and it fails closed. The settings next to
// the file approve two servers and reject one; plain scan shows that (see
// TestScanNoConnectState).
func TestScanConfigMcpjsonState(t *testing.T) {
	t.Parallel()
	home, work := discovertest.CopyFixture(t, fixtureDir("claude-code", "state"))
	c, stdout, stderr := scanConfigCLI(t, home)

	code := c.dispatch([]string{"scan", "--no-connect", "--config", filepath.Join(work, ".mcp.json")})

	assertScanResult(t, code, stdout.String(), stderr.String(), scanWant{code: exitOK})
	want := map[string]string{
		"approved-srv": "unapproved",
		"repo-srv":     "unapproved",
		"rejected-srv": "unapproved",
		"pending-srv":  "unapproved",
	}
	if got := stateCells(t, stdout.String()); !maps.Equal(got, want) {
		t.Errorf("STATE per server = %v, want %v\nstdout:\n%s", got, want, stdout)
	}
}

func TestScanAutoPartialFailure(t *testing.T) {
	t.Parallel()

	c, stdout, stderr, _, _ := scanCLI(t, "all", "partial-failure")

	code := c.dispatch([]string{"scan", "--no-connect"})

	if code != exitError {
		t.Errorf("exit code = %d, want %d (a bad global file fails the scan)", code, exitError)
	}
	if rows := tableRows(t, stdout.String()); len(rows) != 4 {
		t.Errorf("table has %d rows, want 4\nstdout:\n%s", len(rows), stdout)
	}
	assertPartialFailureStderr(t, stderr.String())
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
	if got := stdout.String(); got != emptyScanOutput {
		t.Errorf("stdout = %q, want %q", got, emptyScanOutput)
	}
	// No rules ran, so the notice shows also when there is no server.
	assertNoRulesNotice(t, stderr.String())
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
		// wantStderr are substrings of stderr. Empty means: exit code 0 and
		// only the notice on stderr. Otherwise the exit code must be 2.
		wantStderr []string
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
			// Not the home file: the projects section is not read. That is a
			// problem, because the table can miss servers, so the exit code
			// is 2. The top-level servers still show.
			name:        "claude code .claude.json in another directory",
			fixture:     []string{"claude-code", "valid"},
			file:        filepath.Join("home", ".claude.json"),
			wantClient:  "claude-code",
			wantNames:   []string{"filesystem", "remote-http", "remote-sse"},
			wantProject: "home",
			wantStderr:  []string{"mcpmoat scan: ", ".claude.json", "projects section not read", configErrorHint},
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
			// Not the home file: the server "git" has cwd = "/tmp", outside
			// the project, so it is dropped and the scan fails.
			name:        "codex config.toml in another directory",
			fixture:     []string{"codex", "valid"},
			file:        filepath.Join("home", ".codex", "config.toml"),
			wantClient:  "codex",
			wantNames:   []string{"docs", "remote"},
			wantProject: "home",
			wantStderr: []string{
				"mcpmoat scan: ", "config.toml", "server git: working directory is outside the project or cannot be checked", configErrorHint,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			home, _ := discovertest.CopyFixture(t, fixtureDir(tt.fixture...))
			root := filepath.Dir(home)
			userHome := t.TempDir()
			if tt.homeFile {
				userHome = home
			}
			// The forbidden getwd proves that --config does not read the
			// working directory.
			c, stdout, stderr := scanConfigCLI(t, userHome)

			code := c.dispatch([]string{"scan", "--no-connect", "--config", filepath.Join(root, tt.file)})

			want := scanWant{code: exitOK, stderr: tt.wantStderr}
			if len(tt.wantStderr) > 0 {
				want.code = exitError
			}
			assertScanResult(t, code, stdout.String(), stderr.String(), want)
			rows := tableRows(t, stdout.String())
			for i, client := range column(rows, 1) {
				if client != tt.wantClient {
					t.Errorf("row %d has client %q, want %q", i, client, tt.wantClient)
				}
			}
			if tt.wantProject != "" {
				// An untrusted file shows as a project file in SCOPE, with the
				// untrusted marker. The temporary path holds no space, so word
				// 2 is the path and word 3 the marker.
				for i, scope := range column(rows, 2) {
					if want := "project:" + filepath.Join(root, tt.wantProject); scope != want {
						t.Errorf("row %d has scope %q, want %q", i, scope, want)
					}
				}
				for i, marker := range column(rows, 3) {
					if marker != "(untrusted)" {
						t.Errorf("row %d has %q after the scope, want %q", i, marker, "(untrusted)")
					}
				}
			}
			names := column(rows, 0)
			slices.Sort(names)
			wantNames := slices.Clone(tt.wantNames)
			slices.Sort(wantNames)
			if !slices.Equal(names, wantNames) {
				t.Errorf("server names = %q, want %q", names, wantNames)
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
				return writeTestFile(t, t.TempDir(), "notes.txt", "hello\n")
			},
			wantStdoutEmpty: true,
			wantStderr:      []string{"mcpmoat scan: ", "notes.txt", "unknown config format"},
			wantStderrLines: 1,
		},
		{
			name: "malformed JSON",
			setup: func(t *testing.T) string {
				home, _ := discovertest.CopyFixture(t, fixtureDir("claude-code", "malformed"))
				return filepath.Join(home, ".claude.json")
			},
			wantStdoutEmpty: true,
			wantStderr:      []string{"mcpmoat scan: ", "invalid JSON"},
			wantStderrLines: 1,
		},
		{
			name: "invalid entries",
			setup: func(t *testing.T) string {
				home, _ := discovertest.CopyFixture(t, fixtureDir("cursor", "invalid-entries"))
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

			assertScanResult(t, code, stdout.String(), stderr.String(),
				scanWant{code: exitError, stdout: tt.wantStdout, stderr: tt.wantStderr})
			if tt.wantStdoutEmpty && stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if lines := nonEmptyLines(stderr.String()); len(lines) != tt.wantStderrLines {
				t.Errorf("stderr has %d lines, want %d\nstderr:\n%s", len(lines), tt.wantStderrLines, stderr)
			}
		})
	}

	t.Run("malformed JSON has line and column", func(t *testing.T) {
		t.Parallel()

		c, _, stderr := scanConfigCLI(t, t.TempDir())
		home, _ := discovertest.CopyFixture(t, fixtureDir("claude-code", "malformed"))

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

	servers := map[string]any{
		"missing-cmd": map[string]any{"command": "/nonexistent/mcpmoat-test"},
	}
	// marker stays empty on Windows, where the test has no shell script.
	var marker string
	if runtime.GOOS != "windows" {
		var script string
		script, marker = writeMarkerScript(t, t.TempDir())
		servers["script-cmd"] = map[string]any{"command": script}
	}
	home := t.TempDir()
	writeServers(t, home, ".claude.json", servers)
	c, stdout, stderr := dirsCLI(t, home, t.TempDir())

	code := c.dispatch([]string{"scan", "--no-connect"})

	assertScanResult(t, code, stdout.String(), stderr.String(), scanWant{code: exitOK})
	for name := range servers {
		if !strings.Contains(stdout.String(), name) {
			t.Errorf("stdout does not list %q\nstdout:\n%s", name, stdout)
		}
	}
	if marker != "" {
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("marker file exists or cannot be checked (err = %v): the script ran", err)
		}
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
	writeServers(t, work, ".mcp.json", map[string]any{"claude-http": entry("http"), "claude-sse": entry("sse")})
	writeServers(t, home, filepath.Join(".cursor", "mcp.json"), map[string]any{"cursor-http": entry("http"), "cursor-sse": entry("sse")})

	c, stdout, stderr := dirsCLI(t, home, work)

	code := c.dispatch([]string{"scan", "--no-connect"})

	assertScanResult(t, code, stdout.String(), stderr.String(), scanWant{code: exitOK})
	rows := tableRows(t, stdout.String())
	if len(rows) != 4 {
		t.Errorf("table has %d rows, want 4\nstdout:\n%s", len(rows), stdout)
	}
	if got := strings.Count(stdout.String(), wantURL); got != 4 {
		t.Errorf("stdout shows the redacted URL %q %d times, want 4\nstdout:\n%s", wantURL, got, stdout)
	}
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
			if len(tableRows(t, stdout.String())) == 0 {
				t.Errorf("table has no rows, so the test checks nothing\nstdout:\n%s", stdout)
			}
			scanAssertNoSecret(t, stdout.String(), stderr.String())
		})

		for _, file := range tt.configFiles {
			t.Run(tt.name+"/config/"+filepath.ToSlash(file), func(t *testing.T) {
				t.Parallel()

				home, _ := discovertest.CopyFixture(t, fixtureDir(tt.fixture...))
				// With the fixture's home as the user's home, the home files
				// are read as global files and the work files as untrusted.
				c, stdout, stderr := scanConfigCLI(t, home)
				path := filepath.Join(filepath.Dir(home), file)

				code := c.dispatch([]string{"scan", "--no-connect", "--config", path})

				if code != exitOK {
					t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitOK, stderr)
				}
				if len(tableRows(t, stdout.String())) == 0 {
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
	assertNoLeakBoth(t, stdout, stderr)
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

	// The name shows in Go quoted form (termsafe.Quote). The
	// command and the args go through the RedactArgs allowlist, which masks
	// every part with a character that is not safe.
	wantName := strconv.Quote("a\x1b[31mb")
	wantCommand := discover.Mask + " " + discover.Mask

	c, stdout, stderr := scanConfigCLI(t, t.TempDir())
	path := writeTestFile(t, t.TempDir(), ".mcp.json", config)

	code := c.dispatch([]string{"scan", "--no-connect", "--config", path})

	assertScanResult(t, code, stdout.String(), stderr.String(), scanWant{code: exitOK})
	out := stdout.String()
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
	if lines := nonEmptyLines(out); len(lines) != 2 {
		t.Errorf("stdout has %d lines, want 2\n%q", len(lines), out)
	}
}

func TestScanNoColor(t *testing.T) {
	t.Parallel()

	home, work := discovertest.CopyFixture(t, fixtureDir("all", "full"))

	// runWith runs the scan with one set of args and one environment on the
	// same home and working directory copies.
	runWith := func(args []string, env map[string]string) (string, string, int) {
		c, stdout, stderr := dirsCLI(t, home, work)
		c.getenv = fakeGetenv(env)
		code := c.dispatch(args)
		return stdout.String(), stderr.String(), code
	}

	plain, plainErr, plainCode := runWith([]string{"scan", "--no-connect"}, nil)
	if plainCode != exitOK || plainErr != noRulesNotice+"\n" {
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
			if gotErr != plainErr {
				t.Errorf("stderr = %q, want %q", gotErr, plainErr)
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
		// wantProblem are substrings of the second stderr line, a config
		// problem. Empty means: stderr has only the write error line.
		wantProblem []string
	}{
		{name: "table", fixture: []string{"all", "full"}},
		{name: "empty state line", fixture: []string{"claude-code", "missing"}},
		{
			// The config problem is still printed: it is a reason for the
			// failed scan too.
			name:        "table and a config problem",
			fixture:     []string{"all", "partial-failure"},
			wantProblem: []string{"mcpmoat scan: ", ".claude.json", "invalid JSON"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, _, stderr, _, _ := scanCLI(t, tt.fixture...)
			c.stdout = scanFailWriter{}

			code := c.dispatch([]string{"scan", "--no-connect"})

			assertScanResult(t, code, "", stderr.String(), scanWant{code: exitError})
			wantLines := 1
			if len(tt.wantProblem) > 0 {
				wantLines = 2
			}
			lines := nonEmptyLines(stderr.String())
			if len(lines) != wantLines {
				t.Fatalf("stderr has %d lines, want %d\nstderr:\n%s", len(lines), wantLines, stderr)
			}
			if want := "mcpmoat scan: cannot write output"; lines[0] != want {
				t.Errorf("first stderr line = %q, want %q", lines[0], want)
			}
			if wantLines == 2 {
				assertContainsAll(t, "the second stderr line", lines[1], tt.wantProblem)
			}
		})
	}
}

// TestScanArgsMasked checks that the COMMAND/URL cell never shows an argument
// as written. The configs put the args canary in secret-like shapes, in a
// global and in a project file.
func TestScanArgsMasked(t *testing.T) {
	t.Parallel()

	const canary = discovertest.CanaryArgs
	args := []string{
		"-y", "@scope/server",
		"--token", canary,
		"--api-key=" + canary,
		"-e", "GITHUB_TOKEN=" + canary,
		"-H", "Authorization: Bearer " + canary,
		"postgres://user:" + canary + "@db.example.com/app",
		"https://h.example.com/sse?key=" + canary,
		`{"token":"` + canary + `"}`,
		"/data/" + canary + "/x",
		"admin:" + canary,
		"-p" + canary,
		canary,
	}
	servers := map[string]any{"srv": map[string]any{"command": "npx", "args": args}}
	home, work := t.TempDir(), t.TempDir()
	writeServers(t, home, ".claude.json", servers)
	writeServers(t, work, ".mcp.json", servers)

	c, stdout, stderr := dirsCLI(t, home, work)

	code := c.dispatch([]string{"scan", "--no-connect"})

	assertScanResult(t, code, stdout.String(), stderr.String(), scanWant{code: exitOK})
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

	const globalConfig = `{"mcpServers":{"global-srv":{"command":"npx"}}}`

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
				writeTestFile(t, home, ".claude.json", globalConfig)
				symlink(t, writeServers(t, outside, "real.json", outsideServers()), filepath.Join(work, ".mcp.json"))
			},
			wantCode:   exitError,
			wantStdout: []string{"global-srv"},
			wantStderr: []string{"mcpmoat scan: ", ".mcp.json: file is outside the project", configErrorHint},
		},
		{
			name: ".cursor/mcp.json is a symlink out of the project",
			setup: func(t *testing.T, home, work, outside string) {
				writeTestFile(t, home, ".claude.json", globalConfig)
				symlink(t, writeServers(t, outside, "mcp.json", outsideServers()), filepath.Join(work, ".cursor", "mcp.json"))
			},
			wantCode:   exitError,
			wantStdout: []string{"global-srv"},
			wantStderr: []string{"mcp.json: file is outside the project", configErrorHint},
		},
		{
			name: "project file is invalid JSON",
			setup: func(t *testing.T, home, work, _ string) {
				writeTestFile(t, home, ".claude.json", globalConfig)
				writeTestFile(t, work, ".mcp.json", `{"mcpServers":`)
			},
			wantCode:   exitError,
			wantStdout: []string{"global-srv"},
			wantStderr: []string{".mcp.json:1:", "invalid JSON", configErrorHint},
		},
		{
			name: "no servers at all still prints the empty line first",
			setup: func(t *testing.T, _, work, outside string) {
				symlink(t, writeServers(t, outside, "real.json", outsideServers()), filepath.Join(work, ".mcp.json"))
			},
			wantCode:   exitError,
			wantStdout: []string{"No MCP servers found."},
			wantStderr: []string{"file is outside the project", configErrorHint},
		},
		{
			name: "relative project symlink that stays inside the project is followed",
			setup: func(t *testing.T, _, work, _ string) {
				writeTestFile(t, work, filepath.Join("conf", "mcp.json"), `{"mcpServers":{"inside":{"command":"npx"}}}`)
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
				target := writeTestFile(t, work, filepath.Join("conf", "mcp.json"), `{"mcpServers":{"inside":{"command":"npx"}}}`)
				symlink(t, target, filepath.Join(work, ".mcp.json"))
			},
			wantCode:   exitError,
			wantStdout: []string{"No MCP servers found."},
			wantStderr: []string{"file is outside the project", configErrorHint},
		},
		{
			name: "global file with invalid JSON fails the scan",
			setup: func(t *testing.T, home, work, _ string) {
				writeTestFile(t, home, ".claude.json", `{"mcpServers":`)
				writeTestFile(t, work, ".mcp.json", `{"mcpServers":{"project-srv":{"command":"npx"}}}`)
			},
			wantCode:   exitError,
			wantStdout: []string{"project-srv"},
			wantStderr: []string{"mcpmoat scan: ", ".claude.json:1:", "invalid JSON", configErrorHint},
		},
		{
			name: "global file with an ambiguous key fails the scan",
			setup: func(t *testing.T, home, _, _ string) {
				writeTestFile(t, home, filepath.Join(".cursor", "mcp.json"),
					`{"mcpServers":{"amb":{"command":"npx","Command":"evil"},"ok-srv":{"command":"uvx"}}}`)
			},
			wantCode:   exitError,
			wantStdout: []string{"ok-srv"},
			wantStderr: []string{"mcpmoat scan: ", "server amb", "ambiguous key", configErrorHint},
		},
		{
			name: "global codex file that is not valid TOML fails the scan",
			setup: func(t *testing.T, home, _, _ string) {
				writeTestFile(t, home, filepath.Join(".codex", "config.toml"), "[mcp_servers.a\n")
			},
			wantCode:   exitError,
			wantStdout: []string{"No MCP servers found."},
			wantStderr: []string{"config.toml:1:", "invalid TOML", configErrorHint},
		},
		{
			name: "missing files are not a problem",
			setup: func(t *testing.T, home, _, _ string) {
				writeTestFile(t, home, ".claude.json", globalConfig)
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
				symlink(t, writeServers(t, outside, "real.json", outsideServers()), filepath.Join(home, ".cursor", "mcp.json"))
			},
			wantCode:   exitOK,
			wantStdout: []string{"outside", "run --token " + discover.Mask},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			home, work, outside := t.TempDir(), t.TempDir(), t.TempDir()
			tt.setup(t, home, work, outside)
			c, stdout, stderr := dirsCLI(t, home, work)

			code := c.dispatch([]string{"scan", "--no-connect"})

			assertScanResult(t, code, stdout.String(), stderr.String(),
				scanWant{code: tt.wantCode, stdout: tt.wantStdout, stderr: tt.wantStderr})
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
				return writeTestFile(t, repo, ".mcp.json", `{"mcpServers":{"repo-srv":{"command":"npx"}}}`)
			},
			wantCode:   exitOK,
			wantStdout: []string{"repo-srv", "project:"},
			noStdout:   []string{"global"},
		},
		{
			name: "symlink out of the directory is refused",
			setup: func(t *testing.T, _, repo, outside string) string {
				link := filepath.Join(repo, ".mcp.json")
				symlink(t, writeServers(t, outside, "real.json", outsideServers()), link)
				return link
			},
			wantCode:   exitError,
			noStdout:   []string{"outside"},
			wantStderr: []string{"mcpmoat scan: ", ".mcp.json: file is outside the project"},
		},
		{
			name: "projects section of a .claude.json outside home is not read",
			setup: func(t *testing.T, _, repo, _ string) string {
				return writeTestFile(t, repo, ".claude.json", withProjects)
			},
			// A section that is not read can hide servers, so the scan
			// fails. The top-level servers still show.
			wantCode:   exitError,
			wantStdout: []string{"top-srv", "project:"},
			noStdout:   []string{"proj-srv"},
			wantStderr: []string{"mcpmoat scan: ", ".claude.json", "projects section not read", configErrorHint},
		},
		{
			name: "the home ~/.claude.json is a global file",
			setup: func(t *testing.T, home, _, _ string) string {
				return writeTestFile(t, home, ".claude.json", withProjects)
			},
			wantCode:   exitOK,
			wantStdout: []string{"top-srv", "global", "proj-srv", "project:/p"},
		},
		{
			name: "a symlink to the home ~/.claude.json is a global file",
			setup: func(t *testing.T, home, repo, _ string) string {
				link := filepath.Join(repo, "mine.json")
				symlink(t, writeTestFile(t, home, ".claude.json", withProjects), link)
				return link
			},
			wantCode:   exitOK,
			wantStdout: []string{"top-srv", "global", "proj-srv", "project:/p"},
		},
		{
			name: "codex file outside home is a project file",
			setup: func(t *testing.T, _, repo, _ string) string {
				return writeTestFile(t, repo, filepath.Join(".codex", "config.toml"), "[mcp_servers.codex-srv]\ncommand = \"npx\"\n")
			},
			wantCode:   exitOK,
			wantStdout: []string{"codex-srv", "codex", "project:"},
			noStdout:   []string{"global"},
		},
		{
			// A repository Codex file must not start a server in a directory
			// outside the project. The server is dropped and the scan fails.
			name: "codex working directory outside the project fails the scan",
			setup: func(t *testing.T, _, repo, _ string) string {
				return writeTestFile(t, repo, filepath.Join(".codex", "config.toml"),
					"[mcp_servers.out-srv]\ncommand = \"npx\"\ncwd = \"/\"\n\n[mcp_servers.ok-srv]\ncommand = \"npx\"\n")
			},
			wantCode:   exitError,
			wantStdout: []string{"ok-srv", "project:"},
			noStdout:   []string{"out-srv"},
			wantStderr: []string{
				"mcpmoat scan: ", "config.toml", "server out-srv: working directory is outside the project or cannot be checked", configErrorHint,
			},
		},
		{
			name: "codex symlink out of the directory is refused",
			setup: func(t *testing.T, _, repo, outside string) string {
				target := writeTestFile(t, outside, "real.toml",
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

			assertScanResult(t, code, stdout.String(), stderr.String(), scanWant{
				code: tt.wantCode, stdout: tt.wantStdout, noStdout: tt.noStdout, stderr: tt.wantStderr,
			})
		})
	}

	t.Run("no home directory reads the file as untrusted", func(t *testing.T) {
		t.Parallel()

		path := writeTestFile(t, t.TempDir(), ".claude.json", withProjects)
		c, stdout, stderr := scanConfigCLI(t, "")
		c.homeDir = func() (string, error) { return "", errors.New("no home") }

		code := c.dispatch([]string{"scan", "--no-connect", "--config", path})

		// The file is untrusted, so its projects section is not read, and
		// that fails the scan (see the case above).
		if code != exitError {
			t.Errorf("exit code = %d, want %d; stderr:\n%s", code, exitError, stderr)
		}
		if out := stdout.String(); !strings.Contains(out, "top-srv") || strings.Contains(out, "proj-srv") {
			t.Errorf("stdout = %q, want top-srv and no proj-srv", out)
		}
		assertContainsAll(t, "stderr", stderr.String(), []string{"projects section not read"})
		assertScanErrorLines(t, stderr.String())
	})
}

// TestScanConfigRelativePath checks that a relative --config path gives the
// same result as the absolute path of the same file: scanConfig makes it
// absolute from the working directory first. So the SCOPE cell does not
// depend on the spelling, and an absolute Codex cwd inside the project is
// accepted in both spellings.
func TestScanConfigRelativePath(t *testing.T) {
	t.Parallel()

	for _, tt := range relativePathCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			home, project := t.TempDir(), t.TempDir()
			abs := writeTestFile(t, project, tt.rel, tt.content(project))

			type result struct {
				code           int
				stdout, stderr string
			}
			runWith := func(path string) result {
				t.Helper()
				c, stdout, stderr := dirsCLI(t, home, project)
				code := c.dispatch([]string{"scan", "--no-connect", "--config", path})
				return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
			}
			absRes := runWith(abs)
			relRes := runWith(tt.rel)
			dotRes := runWith("." + string(filepath.Separator) + tt.rel)

			for _, r := range []result{absRes, relRes, dotRes} {
				assertScanResult(t, r.code, r.stdout, r.stderr, scanWant{
					code: exitOK, stdout: tt.wantStdout(project), noStdout: []string{"project:."},
				})
			}
			if relRes != absRes {
				t.Errorf("relative path %q gives\n%+v\nwant the result of the absolute path\n%+v", tt.rel, relRes, absRes)
			}
			if dotRes != absRes {
				t.Errorf("path ./%s gives\n%+v\nwant the result of the absolute path\n%+v", tt.rel, dotRes, absRes)
			}
		})
	}

	// Without a working directory the path stays relative. The test process
	// runs in cmd/mcpmoat, so a fixture path relative to it still opens. The
	// file is read as an untrusted project file, the safe side.
	t.Run("no working directory keeps the path relative", func(t *testing.T) {
		t.Parallel()

		c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)
		path := fixtureDir("claude-code", "valid", "work", ".mcp.json")
		code := c.dispatch([]string{"scan", "--no-connect", "--config", path})

		if code != exitOK {
			t.Errorf("exit code = %d, want %d; stderr:\n%s", code, exitOK, stderr)
		}
		assertContainsAll(t, "stdout", stdout.String(), []string{"(untrusted)", path})
	})
}
