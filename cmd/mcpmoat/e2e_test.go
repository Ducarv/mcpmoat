package main

// End-to-end tests. They build the real mcpmoat binary once and run it as a
// child process with a fake HOME. They check the exit code, stdout and stderr
// of whole commands, the way a user sees them.
//
// These tests use os/exec and not the testscript module, because the project
// adds no new modules for tests.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

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

// TestE2EScanPartialFailure checks that a bad global file fails the scan
// with exit code 2. The servers of the other files are still listed, and the
// problem and the hint go to stderr.
func TestE2EScanPartialFailure(t *testing.T) {
	t.Parallel()
	home, work := discovertest.CopyFixture(t, fixtureDir("all", "partial-failure"))

	stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect")

	if code != exitError {
		t.Errorf("exit code = %d, want %d; stderr:\n%s", code, exitError, stderr)
	}
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

// outsideServers returns the servers of a config outside the project. The
// canary in its args must never show, also when mcpmoat refuses the file.
func outsideServers() map[string]any {
	return map[string]any{
		"outside": map[string]any{"command": "run", "args": []string{"--token", discovertest.CanaryArgs}},
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
				"mcpmoat scan: ", "config.toml", "server git: working directory is outside the project", configErrorHint,
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
	tests := []struct {
		name    string
		rel     string
		content func(project string) string
		want    func(project string) []string
	}{
		{
			name: "codex",
			rel:  filepath.Join(".codex", "config.toml"),
			content: func(project string) string {
				// A TOML literal string ('...') keeps a Windows backslash.
				return "[mcp_servers.in-srv]\ncommand = \"npx\"\ncwd = '" + filepath.Join(project, "sub") + "'\n"
			},
			want: func(project string) []string { return []string{"in-srv", "project:" + project} },
		},
		{
			name:    "cursor",
			rel:     filepath.Join(".cursor", "mcp.json"),
			content: func(string) string { return `{"mcpServers":{"cur-srv":{"command":"npx"}}}` },
			want:    func(project string) []string { return []string{"cur-srv", "project:" + project} },
		},
	}
	for _, tt := range tests {
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

			assertScanResult(t, absCode, absOut, absErr, scanWant{code: exitOK, stdout: tt.want(project)})
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

			if code != exitError {
				t.Errorf("exit code = %d, want %d", code, exitError)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantErr)
			}
		})
	}
}

func TestE2EScanWithoutNoConnect(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	stdout, stderr, code := runBin(t, dir, dir, "scan")

	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "not implemented") {
		t.Errorf("stderr = %q, want it to contain %q", stderr, "not implemented")
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
	home, work, scripts := t.TempDir(), t.TempDir(), t.TempDir()

	// This script would create the marker file if the server ever started.
	marker := filepath.Join(scripts, "marker")
	script := filepath.Join(scripts, "server.sh")
	body := "#!/bin/sh\ntouch " + marker + "\n"
	// The script must be executable, so a start would really work.
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // G306: the script must be executable
		t.Fatal(err)
	}

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
