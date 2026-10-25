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
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// The binary is built once, on the first call to binaryPath. TestMain removes
// the build directory when all tests are done.
var (
	buildOnce sync.Once
	buildDir  string
	binPath   string
	buildErr  error
)

// TestMain only exists to remove the build directories after the tests: the
// one of the mcpmoat binary and the one of the fixture servers.
func TestMain(m *testing.M) {
	code := m.Run()
	inspecttest.RemoveBuilds()
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
// The child process gets a new environment with only HOME, XDG_CONFIG_HOME and
// PATH. XDG_CONFIG_HOME is home/.config (see pinsPath), so pins.json is always
// below the fake home. The child never sees the real environment, so it can
// never read or write the real home directory or the real pins.json.
func runBin(t *testing.T, home, dir string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	bin := binaryPath(t)

	cmd := exec.Command(bin, args...) //nolint:gosec // G204: the test runs the binary it just built
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"), "PATH=/usr/bin:/bin"}
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

// pinsPath returns the pins.json path of a run of runBin with this home.
func pinsPath(home string) string {
	return filepath.Join(home, ".config", "mcpmoat", "pins.json")
}

// assertNoPinsFile fails the test when pins.json exists below home, or when
// its state cannot be checked.
func assertNoPinsFile(t *testing.T, home string) {
	t.Helper()
	if _, err := os.Stat(pinsPath(home)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pins.json exists or cannot be checked (err = %v), want no file", err)
	}
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
	if stdout != emptyScanOutput {
		t.Errorf("stdout = %q, want %q", stdout, emptyScanOutput)
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
	assertEmptyStdout(t, stdout)
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
			assertEmptyStdout(t, stdout)
		})
	}
}

// TestE2EScanWithoutNoConnect checks that scan with no config at all starts
// nothing and pins nothing: the empty-state notice, exit code 0 and no
// pins.json.
func TestE2EScanWithoutNoConnect(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	stdout, stderr, code := runBin(t, dir, dir, "scan")

	assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK})
	if stdout != emptyScanOutput {
		t.Errorf("stdout = %q, want %q", stdout, emptyScanOutput)
	}
	assertNoPinsFile(t, dir)
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
				assertEmptyStdout(t, stdout)
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

					// The secrets fixtures hold plaintext secrets, so the config
					// rules find MOAT-T4-002 (high) and the exit code is 1.
					// assertScanResult also checks that no canary leaks.
					assertScanResult(t, code, stdout, stderr, scanWant{code: exitFindings})
					assertCleanStderr(t, stderr)
					// Check that the scan listed servers and findings. Without
					// this, an empty output would pass the leak check.
					if len(tableRows(t, stdout)) == 0 {
						t.Errorf("stdout has no server rows:\n%s", stdout)
					}
					if !slices.Contains(findingIDs(findingRows(t, stdout)), "MOAT-T4-002") {
						t.Errorf("no MOAT-T4-002 finding, so the findings block is not checked\nstdout:\n%s", stdout)
					}
					// The server table and stderr show no env at all. The
					// findings block may name the key API_KEY, never a value.
					scanAssertNoSecret(t, stdout, stderr)
				})
			}
		})
	}
}

// TestE2EScanConfigFindings scans the dangerous config fixture (T4). The
// findings block names keys, never values, and the ignore list can remove the
// high findings and so change the exit code.
func TestE2EScanConfigFindings(t *testing.T) {
	t.Parallel()
	canaries := dangerousCanaries

	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantRows [][]string // whole rows (RULE, SEVERITY, SERVER, FIELD, KEY/RELATED) that must show
		wantNone []string   // rule IDs that must not show
		// wantStderr is the one line on stderr ("" for an empty stderr): the
		// line that counts the ignored findings.
		wantStderr string
	}{
		{
			name:     "findings",
			args:     []string{"scan", "--no-connect"},
			wantCode: exitFindings,
			wantRows: [][]string{
				{"MOAT-T4-001", "high", "remote-plain", "url", "-"},
				{"MOAT-T4-002", "high", "env-secret", "env", "GITHUB_TOKEN"},
			},
		},
		{
			name:     "high findings ignored",
			args:     []string{"scan", "--no-connect", "--ignore", "MOAT-T4-001", "--ignore", "MOAT-T4-002"},
			wantCode: exitOK,
			wantNone: []string{"MOAT-T4-001", "MOAT-T4-002"},
			// Hidden findings are never silent: the count is on stderr, with
			// rule IDs only.
			wantStderr: "mcpmoat scan: 5 findings ignored: MOAT-T4-001 (1), MOAT-T4-002 (4)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := discovertest.CopyFixture(t, filepath.Join("..", "..", "testdata", "configs", "dangerous"))

			stdout, stderr, code := runBin(t, home, work, tt.args...)

			want := scanWant{code: tt.wantCode}
			if tt.wantStderr != "" {
				want.stderr = []string{tt.wantStderr}
			}
			assertScanResult(t, code, stdout, stderr, want)
			if tt.wantStderr == "" {
				assertCleanStderr(t, stderr)
			} else {
				assertStderrLines(t, stderr, []lineWant{exactLine(tt.wantStderr)})
			}
			assertContainsNone(t, "stdout", stdout, canaries)
			assertContainsNone(t, "stderr", stderr, canaries)
			if len(tableRows(t, stdout)) == 0 {
				t.Fatalf("stdout has no server rows:\n%s", stdout)
			}
			rows := findingRows(t, stdout)
			for _, want := range tt.wantRows {
				if !slices.ContainsFunc(rows, func(row []string) bool { return slices.Equal(row, want) }) {
					t.Errorf("no finding row %v\nstdout:\n%s", want, stdout)
				}
			}
			for _, id := range tt.wantNone {
				if slices.Contains(findingIDs(rows), id) {
					t.Errorf("finding %s shows, but it is ignored\nstdout:\n%s", id, stdout)
				}
			}
		})
	}
}

// TestE2EScanJSON runs scan --json with the real binary. Stdout is one JSON
// document, and --json changes neither stderr nor the exit code.
func TestE2EScanJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		setup        func(t *testing.T) (home, work string)
		wantCode     int
		wantFindings bool
	}{
		{
			name: "dangerous",
			setup: func(t *testing.T) (string, string) {
				return discovertest.CopyFixture(t, filepath.Join("..", "..", "testdata", "configs", "dangerous"))
			},
			wantCode:     exitFindings,
			wantFindings: true,
		},
		{
			name:     "benign",
			setup:    func(t *testing.T) (string, string) { return benignHome(t, "benign-srv") },
			wantCode: exitOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := tt.setup(t)

			plainOut, plainErr, plainCode := runBin(t, home, work, "scan", "--no-connect")
			stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect", "--json")

			if code != tt.wantCode || plainCode != tt.wantCode {
				t.Errorf("exit codes: --json %d, plain %d, want %d\nstderr:\n%s", code, plainCode, tt.wantCode, stderr)
			}
			if stderr != plainErr {
				t.Errorf("stderr with --json = %q, without = %q", stderr, plainErr)
			}
			assertContainsNone(t, "stdout", stdout, dangerousCanaries)
			assertContainsNone(t, "stderr", stderr, dangerousCanaries)
			assertContainsNone(t, "stdout", stdout, []string{pinEnvCanary})
			if plainOut == stdout {
				t.Errorf("--json stdout equals the table output:\n%s", stdout)
			}

			dec := json.NewDecoder(strings.NewReader(stdout))
			var doc map[string]any
			if err := dec.Decode(&doc); err != nil {
				t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
			}
			if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
				t.Errorf("stdout has more than one JSON document (err = %v):\n%s", err, stdout)
			}
			if doc["schema_version"] != float64(1) || doc["mode"] != "no-connect" {
				t.Errorf("schema_version = %v, mode = %v, want 1 and no-connect", doc["schema_version"], doc["mode"])
			}
			if servers, _ := doc["servers"].([]any); len(servers) == 0 {
				t.Errorf("servers = %v, want a non-empty array", doc["servers"])
			}
			findings, ok := doc["findings"].([]any)
			if !ok {
				t.Fatalf("findings = %#v, want an array (an empty one is [], not null)", doc["findings"])
			}
			if (len(findings) > 0) != tt.wantFindings {
				t.Errorf("got %d findings, want findings: %v", len(findings), tt.wantFindings)
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

// TestE2EScanIgnore checks the ignore file and the --ignore flag in the real
// binary. A malformed line of .mcpmoat-ignore is a warning, not an error: the
// scan reads the good line, prints the number of entries and lists the
// servers. An empty --ignore value is a usage error.
func TestE2EScanIgnore(t *testing.T) {
	t.Parallel()

	t.Run("file with a malformed line", func(t *testing.T) {
		t.Parallel()
		home, work := discovertest.CopyFixture(t, fixtureDir("all", "full"))
		// Line 2 has an invalid rule ID, so it gets a warning and is skipped.
		writeTestFile(t, work, rules.IgnoreFileName, "MOAT-T1-003\n/onlytool\n")

		stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect", "--ignore", "MOAT-T1-001")

		if code != exitOK {
			t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, stdout, stderr)
		}
		// The warning and the entry count come before the notice. The
		// warning text after the line number is not checked here.
		assertStderrLines(t, stderr, []lineWant{
			prefixLine(scanWarnPrefix + rules.IgnoreFileName + ":2: "),
			exactLine("mcpmoat scan: using 1 entry from " + rules.IgnoreFileName),
		})
		if strings.Contains(stderr, "onlytool") {
			t.Errorf("stderr shows content of the ignore file:\n%s", stderr)
		}
		want := []string{"cc-global", "cc-alpha", "cc-project", "cursor-global", "cursor-project", "codex-global"}
		if got := column(tableRows(t, stdout), 0); !slices.Equal(got, want) {
			t.Errorf("server names = %v, want %v\nstdout:\n%s", got, want, stdout)
		}
		assertNoLeakBoth(t, stdout, stderr)
		assertNoEscape(t, stdout, stderr)
	})

	t.Run("empty flag value", func(t *testing.T) {
		t.Parallel()
		home, work := discovertest.CopyFixture(t, fixtureDir("all", "full"))

		stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect", "--ignore", "")

		if code != exitError {
			t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitError, stdout, stderr)
		}
		assertContainsAll(t, "stderr", stderr, []string{"mcpmoat scan: ", "-ignore", usageHint})
		if stdout != "" {
			t.Errorf("stdout = %q, want empty", stdout)
		}
	})
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

// TestE2EScanRulesExtra checks that a valid external rule folder changes
// nothing yet, because scan loads the rules but does not apply them. The only
// change is the notice on stderr that says so.
func TestE2EScanRulesExtra(t *testing.T) {
	t.Parallel()
	home, work := t.TempDir(), t.TempDir()

	stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect", "--rules", e2eRulesDir(t, "extra"))

	assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK, stderr: []string{rulesNotAppliedNotice}})
	baseOut, baseErr, baseCode := runBin(t, home, work, "scan", "--no-connect")
	wantErr := baseErr + rulesNotAppliedNotice + "\n"
	if code != baseCode || stdout != baseOut || stderr != wantErr {
		t.Errorf("--rules changes the result: exit code %d, want %d\nstdout:\n%s\nwant stdout:\n%s\nstderr:\n%s\nwant stderr:\n%s",
			code, baseCode, stdout, baseOut, stderr, wantErr)
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
			wantErr: []string{"MOAT-T1-003.yaml", builtinClashText},
		},
		{
			name:    "missing folder",
			dir:     func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
			wantErr: []string{"cannot read directory"},
		},
		{
			name:    "empty folder",
			dir:     func(t *testing.T) string { return t.TempDir() },
			wantErr: []string{noRuleFilesText},
		},
		{
			name: "folder with no rule file name",
			dir: func(t *testing.T) string {
				dir := t.TempDir()
				writeTestFile(t, dir, "notes.txt", "id: x\n")
				writeTestFile(t, dir, filepath.Join("sub.yaml", "inner.yaml"), "id: x\n")
				return dir
			},
			wantErr: []string{noRuleFilesText},
		},
	}
	for _, tt := range tests {
		for _, mode := range scanModes {
			t.Run(tt.name+" "+mode.name, func(t *testing.T) {
				t.Parallel()
				args := append(append([]string{"scan"}, mode.args...), "--rules", tt.dir(t))

				stdout, stderr, code := runBin(t, t.TempDir(), t.TempDir(), args...)

				assertScanResult(t, code, stdout, stderr, scanWant{
					code:   exitError,
					stderr: tt.wantErr,
				})
				assertEmptyStdout(t, stdout)
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
			assertEmptyStdout(t, stdout)
			if !strings.HasPrefix(stderr, "mcpmoat scan: ") || !strings.HasSuffix(stderr, usageHint+"\n") {
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
			assertEmptyStdout(t, stdout)
			if stderr == "" {
				t.Fatal("stderr is empty, want the rule problem")
			}
			assertTerminalSafe(t, stderr)
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

	assertFast(t, start)
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

	assertFast(t, start)
	assertIDFloodResult(t, code, stdout, stderr, builtinClashText, idFloodFiles-floodCap)
}

// pinEnvCanary is a plain env value that must never reach pins.json or an output.
const pinEnvCanary = "e2e-plain-env-value-7c1f"

// benignHome makes a fake home with a trusted global Claude Code config. The
// config has one stdio server, name, that runs the benign fixture. The server
// has a canary env value, which must never reach a file or an output. The
// value looks like plain text, so the config rules do not flag it. It
// returns the home and an empty working directory.
func benignHome(t *testing.T, name string) (home, work string) {
	t.Helper()
	home, work = t.TempDir(), t.TempDir()
	requirePrivateChain(t, home)
	writeServers(t, home, ".claude.json", map[string]any{
		name: map[string]any{
			"command": inspecttest.Fixture(t, "benign"),
			"env":     map[string]string{"E2E_MODE": pinEnvCanary},
		},
	})
	return home, work
}

// requirePrivateChain skips the test when another user can write to dir or
// to one of its parents, such as /tmp on Linux. The binary refuses to make
// its run directory below such a home (see checkChain in internal/inspect).
// CI sets TMPDIR to a private directory, so on CI the test fails instead of a
// silent skip.
func requirePrivateChain(t *testing.T, dir string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	for p := dir; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o022 != 0 {
			msg := fmt.Sprintf("%s is writable by its group or by others, so mcpmoat makes no run directory below it; set TMPDIR to a private directory", p)
			if os.Getenv("CI") != "" {
				t.Fatal(msg)
			}
			t.Skip(msg)
		}
		if filepath.Dir(p) == p {
			return
		}
	}
}

// TestE2EPinAccept runs the pin journey on the real binary: the first scan pins
// the tools, a second scan finds nothing, "pin --accept" of an unchanged
// server changes nothing, and a bad name or an ambiguous name is exit code 2.
func TestE2EPinAccept(t *testing.T) {
	t.Parallel()
	const name = "benign-srv"
	home, work := benignHome(t, name)
	pinsJSON := pinsPath(home)

	// scanClean runs a scan that must find nothing: exit code 0, no MOAT-T2
	// row, and the server in the table.
	scanClean := func(t *testing.T, wantStderr []string) {
		t.Helper()
		stdout, stderr, code := runBin(t, home, work, "scan")
		assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK, noStdout: []string{"MOAT-T2"}, stderr: wantStderr})
		if got := column(tableRows(t, stdout), 0); !slices.Equal(got, []string{name}) {
			t.Errorf("server names = %v, want [%s]\nstdout:\n%s", got, name, stdout)
		}
		if len(wantStderr) == 0 {
			assertCleanStderr(t, stderr)
		}
		assertContainsNone(t, "stdout", stdout, []string{pinEnvCanary})
		assertContainsNone(t, "stderr", stderr, []string{pinEnvCanary})
	}

	// Step 1: the first scan pins the two tools of the fixture.
	scanClean(t, []string{"mcpmoat scan: pinned 2 tools for " + name})
	info, err := os.Stat(pinsJSON)
	if err != nil {
		t.Fatalf("pins.json is missing after the first scan: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("pins.json mode = %o, want 600", mode)
	}
	data, err := os.ReadFile(pinsJSON) //nolint:gosec // G304: the path is below the t.TempDir() home
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), pinEnvCanary) || strings.Contains(string(data), "E2E_MODE") {
		t.Errorf("pins.json holds the env of the server config:\n%s", data)
	}
	pinned := string(data)
	// assertPinsUnchanged checks that pins.json still holds the first pins.
	assertPinsUnchanged := func(t *testing.T, after string) {
		t.Helper()
		got, err := os.ReadFile(pinsJSON) //nolint:gosec // G304: the path is below the t.TempDir() home
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != pinned {
			t.Errorf("pins.json changed after %s:\n%s", after, got)
		}
	}

	// Step 2: a scan of a pinned server finds nothing and writes nothing.
	scanClean(t, nil)
	assertPinsUnchanged(t, "a scan of a pinned server")

	// Step 3: accepting an unchanged server counts no change. Without --expect,
	// stderr holds the one note that pin trusts what the server returns.
	stdout, stderr, code := runBin(t, home, work, "pin", "--accept", name)
	if want := "accepted " + name + ": 0 new, 0 changed, 0 removed\n"; code != exitOK || stdout != want || stderr != noExpectNote {
		t.Errorf("pin --accept: exit code %d, stdout %q, stderr %q, want exit code %d, stdout %q and stderr %q", code, stdout, stderr, exitOK, want, noExpectNote)
	}
	scanClean(t, nil)

	// Step 3b: --expect with a valid digest of other tools is exit code 2, and
	// pins.json stays as it was.
	const wrongDigest = "pd1:0000000000000000000000000000000000000000000000000000000000000000"
	stdout, stderr, code = runBin(t, home, work, "pin", "--accept", name, "--expect", wrongDigest)
	if code != exitError || stdout != "" ||
		!strings.Contains(stderr, "mcpmoat pin: the tools of "+name+" differ from what scan showed (digest pd1:") ||
		!strings.Contains(stderr, "expected "+wrongDigest+"); nothing was saved. Run scan again and review the diff.") {
		t.Errorf("pin --expect wrong digest: exit code %d, stdout %q, stderr %q, want exit code %d, no stdout and the digest mismatch error", code, stdout, stderr, exitError)
	}
	assertPinsUnchanged(t, "a pin with the wrong digest")
	assertNoLeakBoth(t, stdout, stderr)

	// Step 3c: the mismatch error names the digest of the tools that the server
	// returns now. With that digest, pin accepts and prints no note.
	_, rest, _ := strings.Cut(stderr, "(digest ")
	digest, _, _ := strings.Cut(rest, ",")
	if !pins.ValidDigest(digest) {
		t.Fatalf("no valid digest in the mismatch error: %q", stderr)
	}
	stdout, stderr, code = runBin(t, home, work, "pin", "--accept", name, "--expect", digest)
	if want := "accepted " + name + ": 0 new, 0 changed, 0 removed\n"; code != exitOK || stdout != want || stderr != "" {
		t.Errorf("pin --expect right digest: exit code %d, stdout %q, stderr %q, want exit code %d, stdout %q and no stderr", code, stdout, stderr, exitOK, want)
	}
	scanClean(t, nil)

	// Step 3d: a malformed digest is a usage error before any server starts.
	stdout, stderr, code = runBin(t, home, work, "pin", "--accept", name, "--expect", "not-a-digest")
	if code != exitError || stdout != "" || !strings.Contains(stderr, "mcpmoat pin: --expect needs a digest such as pd1:<64 hex>") {
		t.Errorf("pin --expect bad digest: exit code %d, stdout %q, stderr %q, want exit code %d, no stdout and the digest usage error", code, stdout, stderr, exitError)
	}

	// Step 4: an unknown name is exit code 2 and changes nothing.
	stdout, stderr, code = runBin(t, home, work, "pin", "--accept", "unknown")
	if code != exitError || stdout != "" || !strings.Contains(stderr, "mcpmoat pin: unknown server") {
		t.Errorf("pin --accept unknown: exit code %d, stdout %q, stderr %q, want exit code %d, no stdout and the unknown server error", code, stdout, stderr, exitError)
	}
	assertPinsUnchanged(t, "a refused pin")

	// Step 5: a missing --accept is a usage error.
	stdout, stderr, code = runBin(t, home, work, "pin")
	if code != exitError || stdout != "" || !strings.Contains(stderr, "--accept") {
		t.Errorf("pin without --accept: exit code %d, stdout %q, stderr %q, want exit code %d, no stdout and a --accept error", code, stdout, stderr, exitError)
	}
	assertNoLeakBoth(t, stdout, stderr)
}

// TestE2EPinAcceptAmbiguous checks that a name that two global config files
// use is exit code 2, and that pin lists the sources and writes no pins.json.
func TestE2EPinAcceptAmbiguous(t *testing.T) {
	t.Parallel()
	home, work := benignHome(t, "dup")
	writeServers(t, filepath.Join(home, ".cursor"), "mcp.json", map[string]any{"dup": map[string]any{"command": "run"}})

	stdout, stderr, code := runBin(t, home, work, "pin", "--accept", "dup")

	if code != exitError || stdout != "" || !strings.Contains(stderr, "2 servers are named dup") {
		t.Errorf("exit code %d, stdout %q, stderr %q, want exit code %d, no stdout and the ambiguous name error", code, stdout, stderr, exitError)
	}
	assertNoPinsFile(t, home)
	assertNoLeakBoth(t, stdout, stderr)
}

// TestE2EPinAcceptProject checks the selection of a name that the global
// config and a project file both use: without --project pin takes the global
// server, and --project takes the project server (which pin then refuses, as
// a gate refuses a project server by default).
func TestE2EPinAcceptProject(t *testing.T) {
	t.Parallel()
	home, work := benignHome(t, "dup")
	writeServers(t, work, ".mcp.json", map[string]any{"dup": map[string]any{"command": "run"}})
	// The project path is the working directory that the binary sees, with
	// symlinks resolved (on macOS /var is /private/var).
	project, err := filepath.EvalSymlinks(work)
	if err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runBin(t, home, work, "pin", "--accept", "dup", "--project", project)

	if code != exitError || stdout != "" || !strings.Contains(stderr, "server dup: failed: ") || !strings.Contains(stderr, "needs explicit opt-in") {
		t.Errorf("--project: exit code %d, stdout %q, stderr %q, want exit code %d and the gate refusal", code, stdout, stderr, exitError)
	}
	assertNoPinsFile(t, home)

	stdout, stderr, code = runBin(t, home, work, "pin", "--accept", "dup")

	if code != exitOK || !strings.Contains(stdout, "accepted dup: 2 new, 0 changed, 0 removed\n") {
		t.Errorf("no --project: exit code %d, stdout %q, stderr %q, want exit code %d and the accepted line", code, stdout, stderr, exitOK)
	}
	assertNoLeakBoth(t, stdout, stderr)
}
