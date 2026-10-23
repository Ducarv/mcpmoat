package main

// End-to-end tests. They build the real mcpmoat binary once and run it as a
// child process with a fake HOME. They check the exit code, stdout and stderr
// of whole commands, the way a user sees them.
//
// These tests use os/exec and not the testscript module, because the project
// adds no new modules for tests.

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// The binary is built once, on the first call to binaryPath. TestMain removes
// the build directory when all tests are done.
var (
	buildOnce sync.Once
	buildDir  string
	binPath   string
	buildErr  error
)

// TestMain only exists to remove the build directory after the tests.
func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		_ = os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

// binaryPath builds the mcpmoat binary on the first call and returns its path.
// It skips the test in short mode, because the build takes a few seconds.
func binaryPath(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping the end-to-end test in short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the end-to-end tests need a Unix system")
	}
	buildOnce.Do(func() {
		buildDir, buildErr = os.MkdirTemp("", "mcpmoat-e2e-")
		if buildErr != nil {
			return
		}
		binPath = filepath.Join(buildDir, "mcpmoat")
		// "go test" puts the bin directory of its own toolchain first in PATH,
		// so LookPath finds the go tool that runs this test. (runtime.GOROOT
		// is deprecated.)
		goTool, err := exec.LookPath("go")
		if err != nil {
			buildErr = err
			return
		}
		// The test directory is the package directory, so "." is cmd/mcpmoat.
		cmd := exec.Command(goTool, "build", "-o", binPath, ".") //nolint:gosec // G204: the go tool comes from the test's own toolchain, and the arguments are fixed
		out, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("go build failed: %w\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatalf("build the mcpmoat binary: %v", buildErr)
	}
	return binPath
}

// runBin runs the mcpmoat binary with args, in directory dir, with home as the
// only home directory. It returns stdout, stderr and the exit code.
//
// The child process gets a new environment with only HOME and PATH. It never
// sees the real environment, so it can never read the real home directory.
func runBin(t *testing.T, home, dir string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	bin := binaryPath(t)

	cmd := exec.Command(bin, args...) //nolint:gosec // G204: the test runs the binary it just built
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	if err != nil {
		exitErr, ok := errors.AsType[*exec.ExitError](err)
		if !ok {
			// The process did not start or did not finish: this is a test problem.
			t.Fatalf("run %s %v: %v", bin, args, err)
		}
		code = exitErr.ExitCode()
	}
	return outBuf.String(), errBuf.String(), code
}

func TestE2EScanAllClients(t *testing.T) {
	t.Parallel()
	home, work := discovertest.CopyFixture(t, fixtureDir("all", "full"))

	stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect")

	assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK})
	want := []string{"cc-global", "cc-alpha", "cc-project", "cursor-global", "cursor-project", "codex-global"}
	if got := column(tableRows(t, stdout), 0); !slices.Equal(got, want) {
		t.Errorf("server names = %v, want %v\nstdout:\n%s", got, want, stdout)
	}
}

// TestE2EScanServerState runs the real binary and checks the STATE column for
// the enabled and approval settings of each client config. A disabled or
// unapproved server is not a config problem, so the exit code stays 0 and
// stderr holds only the notice.
func TestE2EScanServerState(t *testing.T) {
	t.Parallel()
	// serverStateCases is in scan_test.go.
	for _, tt := range serverStateCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := discovertest.CopyFixture(t, fixtureDir(tt.fixture...))

			stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect")

			assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK})
			// stateCells is in scan_test.go. It parses the table and
			// fails the test when the header is wrong or a row has no
			// STATE cell, so an empty output does not pass.
			if got := stateCells(t, stdout); !maps.Equal(got, tt.want) {
				t.Errorf("STATE per server = %v, want %v\nstdout:\n%s", got, tt.want, stdout)
			}
		})
	}
}

// TestE2EScanPartialFailure checks that a bad global file fails the scan
// with exit code 2. The servers of the other files are still listed, and the
// problem and the hint go to stderr.
func TestE2EScanPartialFailure(t *testing.T) {
	t.Parallel()
	home, work := discovertest.CopyFixture(t, fixtureDir("all", "partial-failure"))

	stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect")

	assertScanResult(t, code, stdout, stderr, scanWant{code: exitError})
	want := []string{"cc-project", "cursor-global", "cursor-project", "codex-global"}
	if got := column(tableRows(t, stdout), 0); !slices.Equal(got, want) {
		t.Errorf("server names = %v, want %v\nstdout:\n%s", got, want, stdout)
	}

	assertPartialFailureStderr(t, stderr)
}

// TestE2EScanUntrustedProjectFile checks that a project .mcp.json that is a
// symlink out of the working directory gives exit code 2. The table of the
// global file is still printed, and the content of the refused file never
// shows.
func TestE2EScanUntrustedProjectFile(t *testing.T) {
	t.Parallel()
	home, work, outside := t.TempDir(), t.TempDir(), t.TempDir()
	writeServers(t, home, ".claude.json", map[string]any{"global-srv": map[string]any{"command": "npx"}})
	target := writeServers(t, outside, "real.json", outsideServers())
	symlink(t, target, filepath.Join(work, ".mcp.json"))

	stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect")

	assertScanResult(t, code, stdout, stderr, scanWant{
		code:   exitError,
		stderr: []string{".mcp.json: file is outside the project", configErrorHint},
	})
	if got := column(tableRows(t, stdout), 0); !slices.Equal(got, []string{"global-srv"}) {
		t.Errorf("server names = %v, want [global-srv]\nstdout:\n%s", got, stdout)
	}
}

func TestE2EScanEmpty(t *testing.T) {
	t.Parallel()
	stdout, stderr, code := runBin(t, t.TempDir(), t.TempDir(), "scan", "--no-connect")

	assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK})
	if want := "No MCP servers found.\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestE2EScanConfigFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		file       []string // path below the valid fixture's home directory
		fixture    string
		wantClient string
		wantNames  []string
		// otherHome runs the binary with a home directory that does not
		// exist. The file is then not one of the user's own global files,
		// so mcpmoat reads it as an untrusted project file.
		otherHome bool
		// wantStderr are substrings of stderr. Empty means: exit code 0 and
		// only the notice on stderr. Otherwise the exit code must be 2.
		wantStderr []string
	}{
		{
			name:       "claude code",
			fixture:    "claude-code",
			file:       []string{".claude.json"},
			wantClient: "claude-code",
			wantNames:  []string{"filesystem", "remote-http", "remote-sse", "alpha-tool", "gamma-tool"},
		},
		{
			// The "projects" section of an untrusted file is not read. That
			// fails the scan, but the top-level servers still show.
			name:       "claude code outside home",
			fixture:    "claude-code",
			file:       []string{".claude.json"},
			wantClient: "claude-code",
			wantNames:  []string{"filesystem", "remote-http", "remote-sse"},
			otherHome:  true,
			wantStderr: []string{"mcpmoat scan: ", ".claude.json", "projects section not read", configErrorHint},
		},
		{
			name:       "cursor",
			fixture:    "cursor",
			file:       []string{".cursor", "mcp.json"},
			wantClient: "cursor",
			wantNames:  []string{"events", "git", "remote"},
		},
		{
			name:       "codex",
			fixture:    "codex",
			file:       []string{".codex", "config.toml"},
			wantClient: "codex",
			wantNames:  []string{"docs", "git", "remote"},
		},
		{
			// The server "git" has cwd = "/tmp", outside the project of an
			// untrusted file. It is dropped, and that fails the scan.
			name:       "codex outside home",
			fixture:    "codex",
			file:       []string{".codex", "config.toml"},
			wantClient: "codex",
			wantNames:  []string{"docs", "remote"},
			otherHome:  true,
			wantStderr: []string{
				"mcpmoat scan: ", "config.toml", "server git: working directory is outside the project or cannot be checked", configErrorHint,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := discovertest.CopyFixture(t, fixtureDir(tt.fixture, "valid"))
			file := filepath.Join(append([]string{home}, tt.file...)...)
			runHome := home
			if tt.otherHome {
				runHome = filepath.Join(t.TempDir(), "does-not-exist")
			}

			stdout, stderr, code := runBin(t, runHome, work, "scan", "--no-connect", "--config", file)

			want := scanWant{code: exitOK, stderr: tt.wantStderr}
			if len(tt.wantStderr) > 0 {
				want.code = exitError
			}
			assertScanResult(t, code, stdout, stderr, want)
			// tableRows checks the header, so CLIENT and SCOPE are the second
			// and third words.
			rows := tableRows(t, stdout)
			if len(rows) == 0 {
				t.Fatalf("stdout has no server rows:\n%s", stdout)
			}
			for i, got := range column(rows, 1) {
				if got != tt.wantClient {
					t.Errorf("row %d: client = %q, want %q", i, got, tt.wantClient)
				}
			}
			if got := column(rows, 0); !slices.Equal(got, tt.wantNames) {
				t.Errorf("server names = %v, want %v", got, tt.wantNames)
			}
			if tt.otherHome {
				// An untrusted file shows as a project file in SCOPE.
				for i, got := range column(rows, 2) {
					if !strings.HasPrefix(got, "project:") {
						t.Errorf("row %d: scope = %q, want a project scope", i, got)
					}
				}
			}
		})
	}
}

// TestE2EScanConfigRelativePath runs the binary in a project directory and
// checks that a relative --config path gives the same output and exit code as
// the absolute path of the same file. For a Codex file, an absolute cwd
// inside the project is accepted in both spellings. For a Cursor file, SCOPE
// shows the same absolute project path.
func TestE2EScanConfigRelativePath(t *testing.T) {
	t.Parallel()
	for _, tt := range relativePathCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			// The child process reads its working directory without symlinks
			// (on macOS /var is a symlink to /private/var), so the test uses
			// the resolved path too.
			project, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			abs := writeTestFile(t, project, tt.rel, tt.content(project))

			absOut, absErr, absCode := runBin(t, home, project, "scan", "--no-connect", "--config", abs)
			relOut, relErr, relCode := runBin(t, home, project, "scan", "--no-connect", "--config", tt.rel)

			assertScanResult(t, absCode, absOut, absErr, scanWant{
				code: exitOK, stdout: tt.wantStdout(project), noStdout: []string{"project:."},
			})
			if relCode != absCode || relOut != absOut || relErr != absErr {
				t.Errorf("relative path %q gives exit code %d\nstdout:\n%s\nstderr:\n%s\nwant the result of the absolute path: exit code %d\nstdout:\n%s\nstderr:\n%s",
					tt.rel, relCode, relOut, relErr, absCode, absOut, absErr)
			}
		})
	}
}

// TestE2EScanConfigSymlinkOut checks that a --config file that is a symlink
// out of its directory is refused with exit code 2, and that the content of
// the target never shows.
func TestE2EScanConfigSymlinkOut(t *testing.T) {
	t.Parallel()
	home, repo, outside := t.TempDir(), t.TempDir(), t.TempDir()
	target := writeServers(t, outside, "real.json", outsideServers())
	link := filepath.Join(repo, ".mcp.json")
	symlink(t, target, link)

	stdout, stderr, code := runBin(t, home, repo, "scan", "--no-connect", "--config", link)

	assertScanResult(t, code, stdout, stderr, scanWant{
		code:   exitError,
		stderr: []string{".mcp.json: file is outside the project"},
	})
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
}

func TestE2EScanConfigErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		create  bool   // false: the file does not exist
		content string // file content, used only when create is true
		file    string
		wantErr string
	}{
		{name: "missing file", file: "missing.json", wantErr: "file not found"},
		{name: "unknown format", file: "notes.txt", create: true, content: "hello\n", wantErr: "unknown config format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, tt.file)
			if tt.create {
				writeTestFile(t, dir, tt.file, tt.content)
			}

			stdout, stderr, code := runBin(t, dir, dir, "scan", "--no-connect", "--config", path)

			assertScanResult(t, code, stdout, stderr, scanWant{code: exitError, stderr: []string{tt.wantErr}})
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
		})
	}
}

func TestE2EScanWithoutNoConnect(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	stdout, stderr, code := runBin(t, dir, dir, "scan")

	assertScanResult(t, code, stdout, stderr, scanWant{code: exitError, stderr: []string{"not implemented"}})
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
}

// TestE2EScanTimeoutFlags checks --timeout and --concurrency in the real
// binary. A bad value gives exit code 2 with a clear message and no stdout, in
// both modes. With --no-connect, a good value changes nothing: the output is
// the same as without the flags.
func TestE2EScanTimeoutFlags(t *testing.T) {
	t.Parallel()
	const (
		timeoutMsg     = "mcpmoat scan: --timeout must be greater than 0"
		concurrencyMsg = "mcpmoat scan: --concurrency must be at least 1"
		usageHint      = `Run "mcpmoat help" for usage.`
	)
	tests := []struct {
		name      string
		args      []string
		wantError string // empty means: exit code 0 and the same output as without the flags
	}{
		{name: "timeout zero", args: []string{"scan", "--no-connect", "--timeout", "0"}, wantError: timeoutMsg},
		{name: "timeout negative", args: []string{"scan", "--no-connect", "--timeout", "-1s"}, wantError: timeoutMsg},
		{name: "concurrency zero", args: []string{"scan", "--no-connect", "--concurrency", "0"}, wantError: concurrencyMsg},
		{name: "concurrency negative", args: []string{"scan", "--no-connect", "--concurrency", "-2"}, wantError: concurrencyMsg},
		{name: "timeout zero with connect", args: []string{"scan", "--timeout", "0"}, wantError: timeoutMsg},
		{name: "concurrency zero with connect", args: []string{"scan", "--concurrency", "0"}, wantError: concurrencyMsg},
		{name: "good values", args: []string{"scan", "--no-connect", "--timeout", "3s", "--concurrency", "2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := discovertest.CopyFixture(t, fixtureDir("all", "full"))

			stdout, stderr, code := runBin(t, home, work, tt.args...)

			if tt.wantError != "" {
				// A usage error prints the problem and then the usage hint, so
				// assertScanResult (every line has the scan prefix) does not fit.
				if code != exitError {
					t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitError, stdout, stderr)
				}
				if want := tt.wantError + "\n" + usageHint + "\n"; stderr != want {
					t.Errorf("stderr = %q, want %q", stderr, want)
				}
				if stdout != "" {
					t.Errorf("stdout = %q, want empty", stdout)
				}
				return
			}
			assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK})
			if len(tableRows(t, stdout)) == 0 {
				t.Fatalf("stdout has no server rows:\n%s", stdout)
			}
			baseOut, baseErr, baseCode := runBin(t, home, work, "scan", "--no-connect")
			if code != baseCode || stdout != baseOut || stderr != baseErr {
				t.Errorf("flags change the result: exit code %d\nstdout:\n%s\nstderr:\n%s\nwant the result without the flags: exit code %d\nstdout:\n%s\nstderr:\n%s",
					code, stdout, stderr, baseCode, baseOut, baseErr)
			}
		})
	}
}

func TestE2EScanSecretsDoNotLeak(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		fixture string
		file    []string // path of the config file below the fixture's home directory
	}{
		{name: "claude code", fixture: "claude-code", file: []string{".claude.json"}},
		{name: "cursor", fixture: "cursor", file: []string{".cursor", "mcp.json"}},
		{name: "codex", fixture: "codex", file: []string{".codex", "config.toml"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := discovertest.CopyFixture(t, fixtureDir(tt.fixture, "secrets"))
			file := filepath.Join(append([]string{home}, tt.file...)...)

			modes := []struct {
				name string
				args []string
			}{
				{name: "auto", args: []string{"scan", "--no-connect"}},
				{name: "config", args: []string{"scan", "--no-connect", "--config", file}},
			}
			for _, mode := range modes {
				t.Run(mode.name, func(t *testing.T) {
					stdout, stderr, code := runBin(t, home, work, mode.args...)

					// assertScanResult also checks that no canary leaks.
					assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK})
					// Check that the scan listed servers. Without this, an
					// empty output would pass the leak check.
					if len(tableRows(t, stdout)) == 0 {
						t.Errorf("stdout has no server rows:\n%s", stdout)
					}
				})
			}
		})
	}
}

func TestE2EScanStartsNoProcess(t *testing.T) {
	t.Parallel()
	home, work := t.TempDir(), t.TempDir()
	script, marker := writeMarkerScript(t, t.TempDir())

	writeServers(t, home, ".claude.json", map[string]any{
		"marker-server":  map[string]any{"command": script},
		"missing-binary": map[string]any{"command": "/nonexistent/mcpmoat-e2e"},
	})

	stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect")

	assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK})
	// Both servers are listed. json.Marshal sorts the map keys, and the
	// reader keeps that order, but the test does not depend on the order.
	for _, name := range []string{"marker-server", "missing-binary"} {
		if !strings.Contains(stdout, name) {
			t.Errorf("stdout does not list %q:\n%s", name, stdout)
		}
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("marker file exists or cannot be checked (err = %v): mcpmoat started a server", err)
	}
}

// e2eRulesDir returns the absolute path of a folder below testdata/rules.
// The child process runs in another working directory, so a relative path
// would not work.
func e2eRulesDir(t *testing.T, parts ...string) string {
	t.Helper()
	dir, err := filepath.Abs(scanRulesFixture(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// e2eEmptyScanOutput is the stdout of "scan --no-connect" with an empty home.
const e2eEmptyScanOutput = "No MCP servers found.\n"

// TestE2EScanRulesDefault checks that scan loads the built-in rules with no
// flags: the output is the same as before the rules existed.
func TestE2EScanRulesDefault(t *testing.T) {
	t.Parallel()
	stdout, stderr, code := runBin(t, t.TempDir(), t.TempDir(), "scan", "--no-connect")

	assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK})
	if stdout != e2eEmptyScanOutput {
		t.Errorf("stdout = %q, want %q", stdout, e2eEmptyScanOutput)
	}
}

// TestE2EScanRulesExtra checks that a valid external rule folder changes
// nothing yet, because scan loads the rules but does not apply them.
func TestE2EScanRulesExtra(t *testing.T) {
	t.Parallel()
	home, work := t.TempDir(), t.TempDir()

	stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect", "--rules", e2eRulesDir(t, "extra"))

	assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK})
	if stdout != e2eEmptyScanOutput {
		t.Errorf("stdout = %q, want %q", stdout, e2eEmptyScanOutput)
	}
	baseOut, baseErr, baseCode := runBin(t, home, work, "scan", "--no-connect")
	if code != baseCode || stdout != baseOut || stderr != baseErr {
		t.Errorf("--rules changes the result: exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", code, baseCode, stdout, stderr)
	}
}

// TestE2EScanRulesErrors checks that a bad rule folder gives exit code 2 with
// the problem on stderr and nothing on stdout, with and without --no-connect.
// Scan loads the rules before it connects, so the rule error comes first.
func TestE2EScanRulesErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		dir     func(t *testing.T) string
		wantErr []string
	}{
		{
			name:    "invalid severity",
			dir:     func(t *testing.T) string { return e2eRulesDir(t, "invalid") },
			wantErr: []string{"bad-severity.yaml:4:11", "severity"},
		},
		{
			name:    "built-in ID clash",
			dir:     func(t *testing.T) string { return e2eRulesDir(t, "collide") },
			wantErr: []string{"MOAT-T1-003.yaml", "rule ID clashes with a built-in rule"},
		},
		{
			name:    "missing folder",
			dir:     func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
			wantErr: []string{"cannot read directory"},
		},
	}
	for _, tt := range tests {
		for _, noConnect := range []bool{true, false} {
			name := tt.name + " with connect"
			args := []string{"scan"}
			if noConnect {
				name = tt.name + " no-connect"
				args = append(args, "--no-connect")
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				args := append(slices.Clone(args), "--rules", tt.dir(t))

				stdout, stderr, code := runBin(t, t.TempDir(), t.TempDir(), args...)

				assertScanResult(t, code, stdout, stderr, scanWant{
					code:     exitError,
					stderr:   tt.wantErr,
					noStdout: []string{"No MCP servers found"},
				})
				if stdout != "" {
					t.Errorf("stdout = %q, want empty", stdout)
				}
				if strings.Contains(stderr, "not implemented") {
					t.Errorf("stderr reaches the connect step, but the rules are wrong:\n%s", stderr)
				}
			})
		}
	}
}

// TestE2EScanRulesFlagMisuse checks that a repeated, empty or flag-like
// --rules value is a usage error: exit code 2, no stdout.
func TestE2EScanRulesFlagMisuse(t *testing.T) {
	t.Parallel()
	extra := e2eRulesDir(t, "extra")
	tests := []struct {
		name string
		args []string
	}{
		{"repeated", []string{"scan", "--no-connect", "--rules", extra, "--rules", extra}},
		{"empty", []string{"scan", "--no-connect", "--rules", ""}},
		{"empty with equals", []string{"scan", "--no-connect", "--rules="}},
		{"flag-like value", []string{"scan", "--rules", "--no-connect"}},
		{"flag-like value with equals", []string{"scan", "--no-connect", "--rules", "-timeout=1s"}},
		{"missing value", []string{"scan", "--no-connect", "--rules"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, code := runBin(t, t.TempDir(), t.TempDir(), tt.args...)

			// A usage error ends with the usage hint, which has no scan prefix.
			if code != exitError {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitError, stdout, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if !strings.HasPrefix(stderr, "mcpmoat scan: ") || !strings.HasSuffix(stderr, `Run "mcpmoat help" for usage.`+"\n") {
				t.Errorf("stderr = %q, want a scan usage error with the usage hint", stderr)
			}
			assertNoLeakBoth(t, stdout, stderr)
		})
	}
}

// TestE2EScanRulesEscapeSafety checks that a rule file from an untrusted
// repository cannot put a control byte, a C1 control (U+009B), a bidi control
// (U+202E) or a zero-width character (U+200B) on the terminal through the
// error text: they stay escaped in a key, a value, a file name and a path.
func TestE2EScanRulesEscapeSafety(t *testing.T) {
	t.Parallel()
	const head = "id: MOAT-X-901\ntitle: Escape fixture\n"
	const tail = "target: description\nmatch:\n  keywords:\n    - x\n"
	tests := []struct {
		name     string
		content  string
		fileName string // the rule file name; "bad.yaml" when empty
		noDir    bool   // pass a folder that does not exist
	}{
		{name: "yaml escapes in key and value", content: head + "\"bad\\u001b[31mkey\\nforged\": 1\nseverity: \"ur\\ngent\\u001b[2J\"\n" + tail},
		{name: "raw bytes in key and value", content: head + "bad\x1b[31mkey: 1\nseverity: ur\x1b[2Jgent\n" + tail},
		{name: "raw escape in file name", content: head + "severity: urgent\n" + tail, fileName: "bad\x1b[31m\nname.yaml"},
		{name: "hostile runes in file name", content: head + "severity: urgent\n" + tail, fileName: "bad\u009b\u202e\u200bname.yaml"},
		{name: "hostile runes in key, raw", content: head + "\"k\u009b\u202e\u200bx\": 1\nseverity: low\n" + tail},
		{name: "hostile runes in key, YAML escapes", content: head + "\"k\\u009b\\u202e\\u200bx\": 1\nseverity: low\n" + tail},
		{name: "bidi and zero-width in key, valid YAML", content: head + "\"k\u202e\u200bx\": 1\nseverity: low\n" + tail},
		{name: "bidi and zero-width in severity, valid YAML", content: head + "severity: \"ur\u202e\u200bgent\"\n" + tail},
		{name: "hostile runes in severity, raw", content: head + "severity: \"ur\u009b\u202e\u200bgent\"\n" + tail},
		{name: "hostile runes in severity, YAML escapes", content: head + "severity: \"ur\\u009b\\u202e\\u200bgent\"\n" + tail},
		{name: "hostile runes in the folder path", noDir: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if tt.noDir {
				dir = filepath.Join(dir, "no\u009b\u202e\u200bsuch")
			} else {
				name := cmp.Or(tt.fileName, "bad.yaml")
				// The file system may refuse a file name. A write error is
				// not a failure of mcpmoat, so the test skips.
				writeFileOrSkip(t, dir, name, tt.content)
			}

			stdout, stderr, code := runBin(t, t.TempDir(), t.TempDir(), "scan", "--no-connect", "--rules", dir)

			assertScanResult(t, code, stdout, stderr, scanWant{code: exitError})
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if stderr == "" {
				t.Fatal("stderr is empty, want the rule problem")
			}
			assertScanRulesStderr(t, stderr)
		})
	}
}

// TestE2EScanRulesErrorFlood runs the real binary on 300 hostile rule files
// and checks that it prints a capped list of errors: exit code 2, empty
// stdout, at most 101 stderr lines that end with the "too many errors" line.
func TestE2EScanRulesErrorFlood(t *testing.T) {
	t.Parallel()
	dir := floodDir(t)
	home, work := t.TempDir(), t.TempDir()
	binaryPath(t) // build first, so the guard below does not count the build
	start := time.Now()

	stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect", "--rules", dir)

	if d := time.Since(start); d > floodGuard {
		t.Errorf("the scan took %v, want less than %v", d, floodGuard)
	}
	assertFloodResult(t, code, stdout, stderr)
}

// TestE2EScanRulesIDClashFlood runs the real binary on 1000 valid rule files
// that all reuse the ID of a built-in rule. LoadDir accepts every file, so
// only the cap in NewSet limits stderr: exit code 2, empty stdout, 101 lines
// that end with the "too many errors" line.
func TestE2EScanRulesIDClashFlood(t *testing.T) {
	t.Parallel()
	dir := idFloodDir(t, "MOAT-T1-003")
	home, work := t.TempDir(), t.TempDir()
	binaryPath(t) // build first, so the guard below does not count the build
	start := time.Now()

	stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect", "--rules", dir)

	if d := time.Since(start); d > floodGuard {
		t.Errorf("the scan took %v, want less than %v", d, floodGuard)
	}
	assertIDFloodResult(t, code, stdout, stderr, "rule ID clashes with a built-in rule", idFloodFiles-100)
}
