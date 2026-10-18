package main

// End-to-end tests. They build the real mcpmoat binary once and run it as a
// child process with a fake HOME. They check the exit code, stdout and stderr
// of whole commands, the way a user sees them.
//
// These tests use os/exec and not the testscript module, because the project
// adds no new modules for tests.

import (
	"bytes"
	"encoding/json"
	"errors"
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

// fixtureRoot is the discover fixture directory, seen from this package.
const fixtureRoot = "../../testdata/discover"

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
			buildErr = errors.New("go build failed: " + err.Error() + "\n" + string(out))
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
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			// The process did not start or did not finish: this is a test problem.
			t.Fatalf("run %s %v: %v", bin, args, err)
		}
		code = exitErr.ExitCode()
	}
	return outBuf.String(), errBuf.String(), code
}

// tableRows splits a server table into rows. Each row is its list of
// white-space separated words. The first row is the header. The NAME and
// CLIENT cells never hold spaces, so the first two words of a row are safe to
// use. The later cells can hold spaces.
func tableRows(stdout string) [][]string {
	var rows [][]string
	for line := range strings.Lines(stdout) {
		rows = append(rows, strings.Fields(line))
	}
	return rows
}

// column returns the cells of column i (0 is NAME) of the data rows. It
// returns nil when there are no data rows. It skips a row that is too short.
func column(rows [][]string, i int) []string {
	if len(rows) < 2 {
		return nil
	}
	var out []string
	for _, row := range rows[1:] {
		if len(row) <= i {
			continue
		}
		out = append(out, row[i])
	}
	return out
}

// fixtureDir returns the path of a fixture directory.
func fixtureDir(parts ...string) string {
	return filepath.Join(append([]string{fixtureRoot}, parts...)...)
}

func TestE2EScanAllClients(t *testing.T) {
	t.Parallel()
	home, work := discovertest.CopyFixture(t, fixtureDir("all", "full"))

	stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect")

	if code != 0 {
		t.Errorf("exit code = %d, want 0; stderr:\n%s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	rows := tableRows(stdout)
	if len(rows) == 0 {
		t.Fatalf("stdout is empty, want a table")
	}
	if got := rows[0][0]; got != "NAME" {
		t.Errorf("first word of the header = %q, want %q", got, "NAME")
	}
	want := []string{"cc-global", "cc-alpha", "cc-project", "cursor-global", "cursor-project", "codex-global"}
	if got := column(rows, 0); !slices.Equal(got, want) {
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

	if code != 2 {
		t.Errorf("exit code = %d, want 2; stderr:\n%s", code, stderr)
	}
	want := []string{"cc-project", "cursor-global", "cursor-project", "codex-global"}
	rows := tableRows(stdout)
	if len(rows) < 2 {
		t.Fatalf("stdout has no server rows:\n%s", stdout)
	}
	if got := column(rows, 0); !slices.Equal(got, want) {
		t.Errorf("server names = %v, want %v\nstdout:\n%s", got, want, stdout)
	}

	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stderr has %d lines, want 2:\n%s", len(lines), stderr)
	}
	for _, sub := range []string{"mcpmoat scan: ", ".claude.json", "invalid JSON"} {
		if !strings.Contains(lines[0], sub) {
			t.Errorf("error line %q does not contain %q", lines[0], sub)
		}
	}
	if strings.Contains(stderr, "warning:") {
		t.Errorf("stderr shows the problem as a warning:\n%s", stderr)
	}
	if !strings.Contains(lines[1], "a config file has a problem") {
		t.Errorf("last stderr line = %q, want the hint", lines[1])
	}
}

// TestE2EScanUntrustedProjectFile checks that a project .mcp.json that is a
// symlink out of the working directory gives exit code 2. The table of the
// global file is still printed, and the content of the refused file never
// shows.
func TestE2EScanUntrustedProjectFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	work := filepath.Join(root, "work")
	outside := filepath.Join(root, "outside")
	for _, dir := range []string{home, work, outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(home, ".claude.json"): `{"mcpServers":{"global-srv":{"command":"npx"}}}`,
		filepath.Join(outside, "real.json"): `{"mcpServers":{"outside":{"command":"run","args":["--token","` +
			discovertest.CanaryArgs + `"]}}}`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(outside, "real.json"), filepath.Join(work, ".mcp.json")); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect")

	if code != 2 {
		t.Errorf("exit code = %d, want 2; stderr:\n%s", code, stderr)
	}
	if got := column(tableRows(stdout), 0); !slices.Equal(got, []string{"global-srv"}) {
		t.Errorf("server names = %v, want [global-srv]\nstdout:\n%s", got, stdout)
	}
	for _, want := range []string{".mcp.json: file is outside the project", "a config file has a problem"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not contain %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "warning:") {
		t.Errorf("stderr shows the problem as a warning:\n%s", stderr)
	}
	discovertest.AssertNoLeak(t, "stdout", stdout)
	discovertest.AssertNoLeak(t, "stderr", stderr)
}

func TestE2EScanEmpty(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	work := filepath.Join(root, "work")
	for _, dir := range []string{home, work} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect")

	if code != 0 {
		t.Errorf("exit code = %d, want 0; stderr:\n%s", code, stderr)
	}
	if want := "No MCP servers found.\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
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
	}{
		{
			name:       "claude code",
			fixture:    "claude-code",
			file:       []string{".claude.json"},
			wantClient: "claude-code",
			wantNames:  []string{"filesystem", "remote-http", "remote-sse", "alpha-tool", "gamma-tool"},
		},
		{
			// The "projects" section of an untrusted file is not read.
			name:       "claude code outside home",
			fixture:    "claude-code",
			file:       []string{".claude.json"},
			wantClient: "claude-code",
			wantNames:  []string{"filesystem", "remote-http", "remote-sse"},
			otherHome:  true,
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
			name:       "codex outside home",
			fixture:    "codex",
			file:       []string{".codex", "config.toml"},
			wantClient: "codex",
			wantNames:  []string{"docs", "git", "remote"},
			otherHome:  true,
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

			if code != 0 {
				t.Errorf("exit code = %d, want 0; stderr:\n%s", code, stderr)
			}
			if stderr != "" {
				t.Errorf("stderr = %q, want empty", stderr)
			}
			rows := tableRows(stdout)
			if len(rows) < 2 {
				t.Fatalf("stdout has no server rows:\n%s", stdout)
			}
			if len(rows[0]) < 3 || rows[0][1] != "CLIENT" || rows[0][2] != "SCOPE" {
				t.Errorf("header = %v, want CLIENT and SCOPE in the second and third columns", rows[0])
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

// TestE2EScanConfigSymlinkOut checks that a --config file that is a symlink
// out of its directory is refused with exit code 2, and that the content of
// the target never shows.
func TestE2EScanConfigSymlinkOut(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	repo := filepath.Join(root, "repo")
	outside := filepath.Join(root, "outside")
	for _, dir := range []string{home, repo, outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(outside, "real.json")
	content := `{"mcpServers":{"outside":{"command":"run","args":["--token","` + discovertest.CanaryArgs + `"]}}}`
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repo, ".mcp.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runBin(t, home, repo, "scan", "--no-connect", "--config", link)

	if code != 2 {
		t.Errorf("exit code = %d, want 2; stderr:\n%s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, ".mcp.json: file is outside the project") {
		t.Errorf("stderr does not name the refused file:\n%s", stderr)
	}
	discovertest.AssertNoLeak(t, "stdout", stdout)
	discovertest.AssertNoLeak(t, "stderr", stderr)
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
				if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			stdout, stderr, code := runBin(t, dir, dir, "scan", "--no-connect", "--config", path)

			if code != 2 {
				t.Errorf("exit code = %d, want 2", code)
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

	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
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
				stdout, stderr, code := runBin(t, home, work, mode.args...)

				if code != 0 {
					t.Errorf("%s: exit code = %d, want 0; stderr:\n%s", mode.name, code, stderr)
				}
				// Check that the scan listed servers. Without this, an empty
				// output would pass the leak check.
				if len(tableRows(stdout)) < 2 {
					t.Errorf("%s: stdout has no server rows:\n%s", mode.name, stdout)
				}
				discovertest.AssertNoLeak(t, mode.name+" stdout", stdout)
				discovertest.AssertNoLeak(t, mode.name+" stderr", stderr)
			}
		})
	}
}

func TestE2EScanStartsNoProcess(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	work := filepath.Join(root, "work")
	for _, dir := range []string{home, work} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// This script would create the marker file if the server ever started.
	marker := filepath.Join(root, "marker")
	script := filepath.Join(root, "server.sh")
	body := "#!/bin/sh\ntouch " + marker + "\n"
	// The script must be executable, so a start would really work.
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // G306: the script must be executable
		t.Fatal(err)
	}

	cfg := map[string]any{
		"mcpServers": map[string]any{
			"marker-server":  map[string]any{"command": script},
			"missing-binary": map[string]any{"command": "/nonexistent/mcpmoat-e2e"},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runBin(t, home, work, "scan", "--no-connect")

	if code != 0 {
		t.Errorf("exit code = %d, want 0; stderr:\n%s", code, stderr)
	}
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
