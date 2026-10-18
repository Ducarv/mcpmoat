package inspect

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// cmdMarker is a unique text in the commands of the error tests. An error
// text must never contain it, because the error contract of buildCommand
// says that the error does not contain the command.
const cmdMarker = "mcpmoat-cmd-marker-8Fq2Zp"

// parentCanary is a fake secret in the parent environment. It must never
// reach the child environment (NFR-04).
const parentCanary = "mcpmoat-parent-canary-3Kd9Lx"

// stdioServer returns a stdio server with command, args and dir.
func stdioServer(command string, args []string, dir string) discover.Server {
	return discover.Server{
		Name:      "test",
		Transport: discover.TransportStdio,
		Command:   command,
		Args:      discover.NewArgs(args),
		Dir:       dir,
	}
}

// mustBuild calls buildCommand and fails the test on error. It registers
// cleanup with t.Cleanup, so a temporary directory never outlives the test.
func mustBuild(t *testing.T, s discover.Server, getenv func(string) string) *exec.Cmd {
	t.Helper()
	cmd, cleanup, err := buildCommand(t.Context(), s, getenv)
	if cleanup == nil {
		t.Fatal("buildCommand() cleanup = nil, want non-nil")
	}
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatalf("buildCommand() error = %v, want nil", err)
	}
	if cmd == nil {
		t.Fatal("buildCommand() cmd = nil, want non-nil")
	}
	return cmd
}

// absCommand returns an absolute path for a command name. The file does not
// need to exist: exec.CommandContext does not look up a path with a
// directory part, and these tests do not start the process.
func absCommand(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

func TestBuildCommandExactArgs(t *testing.T) {
	t.Parallel()

	// Shell syntax, spaces, empty and unicode args must reach the child as
	// written, one config arg to one argv entry.
	tricky := []string{
		"a b",
		"$(whoami)",
		"`id`",
		"; rm -rf /",
		"| cat /etc/passwd",
		"&& echo pwned",
		"",
		"--flag=x",
		"'single' \"double\"",
		"*",
		"~",
		"line1\nline2",
		"caf\u00e9 \u65e5\u672c \U0001F512",
		discovertest.CanaryArgs,
	}

	tests := []struct {
		name string
		args []string
	}{
		{name: "tricky args", args: tricky},
		{name: "nil args", args: nil},
		{name: "empty args", args: []string{}},
		{name: "one empty arg", args: []string{""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			command := absCommand(t, "server")
			cmd := mustBuild(t, stdioServer(command, tt.args, ""), fakeGetenv(nil))

			want := append([]string{command}, tt.args...)
			if !slices.Equal(cmd.Args, want) {
				t.Errorf("cmd.Args = %q, want %q", cmd.Args, want)
			}
			if cmd.Path != command {
				t.Errorf("cmd.Path = %q, want %q", cmd.Path, command)
			}
			if cmd.Err != nil {
				t.Errorf("cmd.Err = %v, want nil for an absolute command", cmd.Err)
			}
		})
	}
}

// TestBuildCommandNoShell checks that buildCommand never wraps the command
// in a shell and never joins the args into one string (NFR-04).
func TestBuildCommandNoShell(t *testing.T) {
	t.Parallel()

	command := absCommand(t, "server")
	args := []string{"--x", "a; b", "$(c)"}
	cmd := mustBuild(t, stdioServer(command, args, ""), fakeGetenv(nil))

	switch filepath.Base(cmd.Path) {
	case "sh", "bash", "zsh", "dash", "cmd.exe", "powershell.exe":
		t.Errorf("cmd.Path = %q, want the configured command, not a shell", cmd.Path)
	}
	if len(cmd.Args) != 1+len(args) {
		t.Fatalf("len(cmd.Args) = %d, want %d (args joined?): %q", len(cmd.Args), 1+len(args), cmd.Args)
	}
	for _, a := range cmd.Args {
		if a == "-c" || a == "/c" {
			t.Errorf("cmd.Args = %q contains shell flag %q", cmd.Args, a)
		}
	}
}

// TestBuildCommandBareName checks that a bare name is looked up in PATH by
// os/exec: cmd.Path is the LookPath result and cmd.Args[0] stays the name
// as written.
func TestBuildCommandBareName(t *testing.T) {
	t.Parallel()

	wantPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh in PATH: %v", err)
	}

	args := []string{"-c", "echo hi"}
	cmd := mustBuild(t, stdioServer("sh", args, ""), fakeGetenv(nil))

	if cmd.Path != wantPath {
		t.Errorf("cmd.Path = %q, want LookPath result %q", cmd.Path, wantPath)
	}
	want := []string{"sh", "-c", "echo hi"}
	if !slices.Equal(cmd.Args, want) {
		t.Errorf("cmd.Args = %q, want %q", cmd.Args, want)
	}
	if cmd.Err != nil {
		t.Errorf("cmd.Err = %v, want nil", cmd.Err)
	}
}

// TestBuildCommandBareNameNotFound checks that a failed PATH lookup is not
// a buildCommand error: os/exec stores it in cmd.Err and Start returns it.
func TestBuildCommandBareNameNotFound(t *testing.T) {
	t.Parallel()

	const name = "mcpmoat-no-such-command-6Rw1Bq"
	cmd := mustBuild(t, stdioServer(name, nil, ""), fakeGetenv(nil))

	if cmd.Err == nil {
		t.Fatal("cmd.Err = nil, want a lookup error")
	}
	if !errors.Is(cmd.Err, exec.ErrNotFound) {
		t.Errorf("cmd.Err = %v, want it to wrap exec.ErrNotFound", cmd.Err)
	}
	if err := cmd.Start(); err == nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("cmd.Start() error = nil, want the lookup error")
	}
}

func TestBuildCommandEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		parent map[string]string
		env    discover.SecretMap
		want   []string
	}{
		{
			name: "base keys and config env",
			parent: map[string]string{
				"PATH":                  "/usr/bin:/bin",
				"HOME":                  "/home/dev",
				"AWS_SECRET_ACCESS_KEY": parentCanary,
				"GITHUB_TOKEN":          parentCanary,
			},
			env: secrets(map[string]string{"API_KEY": discovertest.CanaryEnv}),
			want: []string{
				"API_KEY=" + discovertest.CanaryEnv,
				"HOME=/home/dev",
				"PATH=/usr/bin:/bin",
			},
		},
		{
			name: "config PATH wins",
			parent: map[string]string{
				"PATH":                  "/usr/bin",
				"AWS_SECRET_ACCESS_KEY": parentCanary,
			},
			env:  secrets(map[string]string{"PATH": "/opt/bin"}),
			want: []string{"PATH=/opt/bin"},
		},
		{
			// An empty but non-nil cmd.Env is important: a nil cmd.Env
			// makes os/exec pass the whole parent environment.
			name:   "nothing to pass",
			parent: map[string]string{"AWS_SECRET_ACCESS_KEY": parentCanary},
			env:    nil,
			want:   []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			getenv := fakeGetenv(tt.parent)
			s := stdioServer(absCommand(t, "server"), nil, "")
			s.Env = tt.env
			cmd := mustBuild(t, s, getenv)

			if cmd.Env == nil {
				t.Fatal("cmd.Env = nil, want non-nil (nil inherits the parent environment)")
			}
			if !slices.Equal(cmd.Env, tt.want) {
				t.Errorf("cmd.Env = %q, want %q", cmd.Env, tt.want)
			}
			wantEnv, err := childEnv(getenv, tt.env)
			if err != nil {
				t.Fatalf("childEnv() error = %v", err)
			}
			if !slices.Equal(cmd.Env, wantEnv) {
				t.Errorf("cmd.Env = %q, want childEnv result %q", cmd.Env, wantEnv)
			}
			for _, entry := range cmd.Env {
				if strings.HasPrefix(entry, "AWS_SECRET_ACCESS_KEY=") || strings.HasPrefix(entry, "GITHUB_TOKEN=") {
					t.Errorf("cmd.Env has parent entry %q", entry)
				}
			}
			discovertest.AssertNoLeak(t, "cmd.Env", strings.Join(cmd.Env, "\n"), parentCanary)
		})
	}
}

func TestBuildCommandAbsoluteDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cmd, cleanup, err := buildCommand(t.Context(), stdioServer(absCommand(t, "server"), nil, dir), fakeGetenv(nil))
	if err != nil {
		t.Fatalf("buildCommand() error = %v, want nil", err)
	}
	if cmd.Dir != dir {
		t.Errorf("cmd.Dir = %q, want %q", cmd.Dir, dir)
	}

	// cleanup must not remove the directory of the user.
	cleanup()
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("after cleanup, os.Stat(Dir) error = %v, want the directory to stay", err)
	}
}

func TestBuildCommandTempDir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dir  string
	}{
		{name: "empty Dir", dir: ""},
		{name: "relative Dir", dir: "sub"},
		{name: "dot relative Dir", dir: "./sub"},
		{name: "parent relative Dir", dir: "../sub"},
		{name: "dot Dir", dir: "."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd, cleanup, err := buildCommand(t.Context(), stdioServer(absCommand(t, "server"), nil, tt.dir), fakeGetenv(nil))
			if cleanup == nil {
				t.Fatal("buildCommand() cleanup = nil, want non-nil")
			}
			t.Cleanup(cleanup)
			if err != nil {
				t.Fatalf("buildCommand() error = %v, want nil", err)
			}

			if !filepath.IsAbs(cmd.Dir) {
				t.Fatalf("cmd.Dir = %q, want an absolute temporary directory", cmd.Dir)
			}
			if cmd.Dir == tt.dir {
				t.Fatalf("cmd.Dir = %q, want a temporary directory, not the relative Dir", cmd.Dir)
			}
			if base := filepath.Base(cmd.Dir); !strings.HasPrefix(base, "mcpmoat-server-") {
				t.Errorf("filepath.Base(cmd.Dir) = %q, want prefix %q", base, "mcpmoat-server-")
			}
			if got, want := filepath.Dir(cmd.Dir), filepath.Clean(os.TempDir()); got != want {
				t.Errorf("parent of cmd.Dir = %q, want os.TempDir() %q", got, want)
			}

			info, err := os.Stat(cmd.Dir)
			if err != nil {
				t.Fatalf("os.Stat(cmd.Dir) error = %v, want the directory to exist", err)
			}
			if !info.IsDir() {
				t.Fatalf("cmd.Dir %q is not a directory", cmd.Dir)
			}
			if runtime.GOOS != "windows" {
				if perm := info.Mode().Perm(); perm != 0o700 {
					t.Errorf("cmd.Dir mode = %v, want %v", perm, fs.FileMode(0o700))
				}
			}
			entries, err := os.ReadDir(cmd.Dir)
			if err != nil {
				t.Fatalf("os.ReadDir(cmd.Dir) error = %v", err)
			}
			if len(entries) != 0 {
				t.Errorf("cmd.Dir has %d entries, want an empty directory", len(entries))
			}

			cleanup()
			if _, err := os.Stat(cmd.Dir); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("after cleanup, os.Stat(cmd.Dir) error = %v, want fs.ErrNotExist", err)
			}
			// A second call must be safe (t.Cleanup calls it again).
			cleanup()
		})
	}
}

// TestBuildCommandTempDirError checks that a failure to make the temporary
// working directory wraps ErrStart, returns no command and a non-nil
// cleanup.
//
// This test is not parallel, because it calls t.Setenv. It is skipped on
// Windows, where os.TempDir reads TMP and TEMP, not TMPDIR.
func TestBuildCommandTempDirError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.TempDir does not read TMPDIR on Windows")
	}
	command := absCommand(t, "server")
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))

	cmd, cleanup, err := buildCommand(t.Context(), stdioServer(command, nil, ""), fakeGetenv(nil))
	if cleanup == nil {
		t.Fatal("buildCommand() cleanup = nil, want non-nil")
	}
	cleanup()
	if !errors.Is(err, ErrStart) {
		t.Errorf("buildCommand() error = %v, want errors.Is ErrStart", err)
	}
	if cmd != nil {
		t.Errorf("buildCommand() cmd = %v, want nil on error", cmd)
	}
}

// TestBuildCommandTempDirIsNew checks that each call makes its own
// directory, so one server cannot leave files for the next one.
func TestBuildCommandTempDirIsNew(t *testing.T) {
	t.Parallel()

	s := stdioServer(absCommand(t, "server"), nil, "")
	a := mustBuild(t, s, fakeGetenv(nil))
	b := mustBuild(t, s, fakeGetenv(nil))
	if a.Dir == b.Dir {
		t.Errorf("two calls gave the same directory %q, want a new one for each call", a.Dir)
	}
}

func TestBuildCommandRelativeCommand(t *testing.T) {
	t.Parallel()

	commands := []string{"./server", "bin/server", "../server", "./bin/server", "server/"}
	for _, command := range commands {
		for _, dir := range []string{"", "sub", "./sub"} {
			t.Run(command+" refused with Dir "+dir, func(t *testing.T) {
				t.Parallel()

				cmd, cleanup, err := buildCommand(t.Context(), stdioServer(command, nil, dir), fakeGetenv(nil))
				if cleanup == nil {
					t.Fatal("buildCommand() cleanup = nil, want non-nil")
				}
				cleanup()
				if !errors.Is(err, ErrInvalidServer) {
					t.Fatalf("buildCommand() error = %v, want ErrInvalidServer", err)
				}
				if cmd != nil {
					t.Errorf("buildCommand() cmd = %v, want nil on error", cmd)
				}
			})
		}

		t.Run(command+" ok with absolute Dir", func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			cmd := mustBuild(t, stdioServer(command, nil, dir), fakeGetenv(nil))
			// cmd.Path stays relative: the child resolves it against
			// cmd.Dir after it changes to that directory.
			if cmd.Path != command {
				t.Errorf("cmd.Path = %q, want %q (relative to Dir)", cmd.Path, command)
			}
			if cmd.Dir != dir {
				t.Errorf("cmd.Dir = %q, want %q", cmd.Dir, dir)
			}
			if cmd.Err != nil {
				t.Errorf("cmd.Err = %v, want nil", cmd.Err)
			}
		})
	}
}

func TestBuildCommandErrors(t *testing.T) {
	t.Parallel()

	absDir := t.TempDir()
	goodArgs := []string{"--token", discovertest.CanaryArgs}
	goodEnv := secrets(map[string]string{"API_KEY": discovertest.CanaryEnv})
	goodCommand := "/opt/" + cmdMarker + "/server"

	tests := []struct {
		name    string
		server  discover.Server
		wantErr error
	}{
		{
			name:    "empty command",
			server:  discover.Server{Transport: discover.TransportStdio, Args: discover.NewArgs(goodArgs), Env: goodEnv},
			wantErr: ErrInvalidServer,
		},
		{
			name:    "empty command with absolute Dir",
			server:  discover.Server{Transport: discover.TransportStdio, Dir: absDir, Env: goodEnv},
			wantErr: ErrInvalidServer,
		},
		{
			name:    "command with NUL",
			server:  discover.Server{Transport: discover.TransportStdio, Command: "/opt/" + cmdMarker + "\x00/server", Args: discover.NewArgs(goodArgs), Env: goodEnv},
			wantErr: ErrInvalidServer,
		},
		{
			name:    "bare command with NUL and absolute Dir",
			server:  discover.Server{Transport: discover.TransportStdio, Command: cmdMarker + "\x00", Dir: absDir, Env: goodEnv},
			wantErr: ErrInvalidServer,
		},
		{
			name:    "relative command without Dir",
			server:  discover.Server{Transport: discover.TransportStdio, Command: "./" + cmdMarker, Args: discover.NewArgs(goodArgs), Env: goodEnv},
			wantErr: ErrInvalidServer,
		},
		{
			name: "env key with '='",
			server: discover.Server{
				Transport: discover.TransportStdio, Command: goodCommand, Args: discover.NewArgs(goodArgs),
				Env: secrets(map[string]string{"A=B": discovertest.CanaryEnv}),
			},
			wantErr: ErrInvalidServer,
		},
		{
			name: "empty env key",
			server: discover.Server{
				Transport: discover.TransportStdio, Command: goodCommand,
				Env: secrets(map[string]string{"": discovertest.CanaryEnv}),
			},
			wantErr: ErrInvalidServer,
		},
		{
			name: "env key with NUL",
			server: discover.Server{
				Transport: discover.TransportStdio, Command: goodCommand,
				Env: secrets(map[string]string{"A\x00B": discovertest.CanaryEnv}),
			},
			wantErr: ErrInvalidServer,
		},
		{
			name: "env value with NUL",
			server: discover.Server{
				Transport: discover.TransportStdio, Command: goodCommand,
				Env: secrets(map[string]string{"API_KEY": discovertest.CanaryEnv + "\x00x"}),
			},
			wantErr: ErrInvalidServer,
		},
		{
			name: "bad env key with absolute Dir",
			server: discover.Server{
				Transport: discover.TransportStdio, Command: goodCommand, Dir: absDir,
				Env: secrets(map[string]string{"A=B": discovertest.CanaryEnv}),
			},
			wantErr: ErrInvalidServer,
		},
		{
			name:    "http transport",
			server:  discover.Server{Transport: discover.TransportHTTP, Command: goodCommand, Args: discover.NewArgs(goodArgs), Env: goodEnv},
			wantErr: ErrUnsupportedTransport,
		},
		{
			name:    "sse transport",
			server:  discover.Server{Transport: discover.TransportSSE, Command: goodCommand, Args: discover.NewArgs(goodArgs), Env: goodEnv},
			wantErr: ErrUnsupportedTransport,
		},
		{
			name:    "zero transport",
			server:  discover.Server{Command: goodCommand, Env: goodEnv},
			wantErr: ErrUnsupportedTransport,
		},
		{
			name:    "unknown transport",
			server:  discover.Server{Transport: "stdio ", Command: goodCommand},
			wantErr: ErrUnsupportedTransport,
		},
		{
			// The transport check comes first: an http server has no
			// command, and that is not a config error.
			name:    "http transport without command",
			server:  discover.Server{Transport: discover.TransportHTTP},
			wantErr: ErrUnsupportedTransport,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parent := map[string]string{"PATH": "/usr/bin", "AWS_SECRET_ACCESS_KEY": parentCanary}
			cmd, cleanup, err := buildCommand(t.Context(), tt.server, fakeGetenv(parent))
			if cleanup == nil {
				t.Fatal("buildCommand() cleanup = nil, want non-nil on error")
			}
			cleanup()
			cleanup()

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("buildCommand() error = %v, want %v", err, tt.wantErr)
			}
			for _, other := range []error{ErrInvalidServer, ErrUnsupportedTransport} {
				if !errors.Is(other, tt.wantErr) && errors.Is(err, other) {
					t.Errorf("buildCommand() error = %v, also wraps %v", err, other)
				}
			}
			if cmd != nil {
				t.Errorf("buildCommand() cmd = %v, want nil on error", cmd)
			}

			msg := err.Error()
			discovertest.AssertNoLeak(t, "error", msg,
				discovertest.CanaryArgs, discovertest.CanaryEnv, parentCanary)
			if strings.Contains(msg, cmdMarker) {
				t.Errorf("error %q contains the command", msg)
			}
			if strings.Contains(msg, "A=B") || strings.Contains(msg, "API_KEY") {
				t.Errorf("error %q contains an env key", msg)
			}
		})
	}
}

// TestBuildCommandFields checks the fields that the SDK command transport
// and the terminal safety depend on.
func TestBuildCommandFields(t *testing.T) {
	t.Parallel()

	cmd := mustBuild(t, stdioServer(absCommand(t, "server"), nil, ""), fakeGetenv(nil))

	// Stdin and Stdout must be nil: cmd.StdinPipe and cmd.StdoutPipe fail
	// if they are set. Stderr must be nil so it goes to os.DevNull.
	if cmd.Stdin != nil {
		t.Errorf("cmd.Stdin = %v, want nil", cmd.Stdin)
	}
	if cmd.Stdout != nil {
		t.Errorf("cmd.Stdout = %v, want nil", cmd.Stdout)
	}
	if cmd.Stderr != nil {
		t.Errorf("cmd.Stderr = %v, want nil (os.DevNull)", cmd.Stderr)
	}
	if cmd.WaitDelay != waitDelay {
		t.Errorf("cmd.WaitDelay = %v, want %v", cmd.WaitDelay, waitDelay)
	}
	if waitDelay <= 0 {
		t.Errorf("waitDelay = %v, want > 0 (0 means Wait can block forever on open pipes)", waitDelay)
	}
	if cmd.Cancel == nil {
		t.Error("cmd.Cancel = nil, want the kill func of exec.CommandContext")
	}
	if cmd.Process != nil {
		t.Error("cmd.Process != nil, want buildCommand not to start the process")
	}
}

// writeScript writes an executable shell script to dir/rel.
func writeScript(t *testing.T, dir, rel, body string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil { //nolint:gosec // G306: the test script must be executable
		t.Fatal(err)
	}
}

// evalDir resolves symlinks in dir, for example /var to /private/var on
// macOS, so two paths to one directory compare equal.
func evalDir(t *testing.T, dir string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("filepath.EvalSymlinks(%q) error = %v", dir, err)
	}
	return resolved
}

// TestBuildCommandRunsRelativeToDir starts a real process. It proves that a
// relative command resolves against the absolute Dir, not against the
// working directory of the test.
func TestBuildCommandRunsRelativeToDir(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("uses a /bin/sh script")
	}

	dir := t.TempDir()
	writeScript(t, dir, filepath.Join("bin", "server"), "pwd\n")

	cmd := mustBuild(t, stdioServer("bin/server", nil, dir), fakeGetenv(map[string]string{"PATH": os.Getenv("PATH")}))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("cmd.Run() error = %v", err)
	}

	got := evalDir(t, strings.TrimSpace(out.String()))
	if want := evalDir(t, dir); got != want {
		t.Errorf("server ran in %q, want %q", got, want)
	}
}

// TestBuildCommandRunsWithoutShell starts a real process. It proves that
// every arg reaches the child as one argv entry, without shell expansion.
func TestBuildCommandRunsWithoutShell(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("uses a /bin/sh script")
	}

	dir := t.TempDir()
	// printf '%s\0' prints each arg, as received, followed by a NUL byte.
	writeScript(t, dir, "server", "printf '%s\\0' \"$@\"\n")

	args := []string{"a b", "$(whoami)", "`id`", "; echo pwned", "", "*", "~", "$HOME", "line1\nline2", "caf\u00e9"}
	cmd := mustBuild(t, stdioServer(filepath.Join(dir, "server"), args, ""), fakeGetenv(map[string]string{"PATH": os.Getenv("PATH")}))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("cmd.Run() error = %v", err)
	}

	got := strings.Split(strings.TrimSuffix(out.String(), "\x00"), "\x00")
	if !slices.Equal(got, args) {
		t.Errorf("child got args %q, want %q", got, args)
	}
}

// TestBuildCommandRunsWithScrubbedEnv starts a real process. It proves
// that the child sees exactly cmd.Env and nothing of the test environment.
func TestBuildCommandRunsWithScrubbedEnv(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("uses /usr/bin/env")
	}
	const envPath = "/usr/bin/env"
	if _, err := os.Stat(envPath); err != nil {
		t.Skipf("no %s: %v", envPath, err)
	}

	parent := map[string]string{
		"PATH":                  os.Getenv("PATH"),
		"HOME":                  "/home/dev",
		"AWS_SECRET_ACCESS_KEY": parentCanary,
	}
	s := stdioServer(envPath, nil, "")
	s.Env = secrets(map[string]string{"API_KEY": discovertest.CanaryEnv})
	cmd := mustBuild(t, s, fakeGetenv(parent))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("cmd.Run() error = %v", err)
	}

	got := strings.Split(strings.TrimSpace(out.String()), "\n")
	slices.Sort(got)
	want := []string{
		"API_KEY=" + discovertest.CanaryEnv,
		"HOME=/home/dev",
	}
	if p := os.Getenv("PATH"); p != "" {
		want = append(want, "PATH="+p)
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("child env = %q, want %q", got, want)
	}
	discovertest.AssertNoLeak(t, "child env", out.String(), parentCanary)
}

func TestCheckCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		hasDir  bool
		wantErr bool
	}{
		{name: "absolute", command: "/usr/bin/node", hasDir: false, wantErr: false},
		{name: "absolute with Dir", command: "/usr/bin/node", hasDir: true, wantErr: false},
		{name: "bare name", command: "npx", hasDir: false, wantErr: false},
		{name: "bare name with Dir", command: "npx", hasDir: true, wantErr: false},
		{name: "dot slash without Dir", command: "./server", hasDir: false, wantErr: true},
		{name: "dot slash with Dir", command: "./server", hasDir: true, wantErr: false},
		{name: "subdir without Dir", command: "bin/server", hasDir: false, wantErr: true},
		{name: "subdir with Dir", command: "bin/server", hasDir: true, wantErr: false},
		{name: "parent without Dir", command: "../server", hasDir: false, wantErr: true},
		{name: "tilde path without Dir", command: "~/bin/server", hasDir: false, wantErr: true},
		{name: "empty", command: "", hasDir: false, wantErr: true},
		{name: "empty with Dir", command: "", hasDir: true, wantErr: true},
		{name: "NUL", command: "/usr/bin/no\x00de", hasDir: false, wantErr: true},
		{name: "NUL with Dir", command: "node\x00", hasDir: true, wantErr: true},
		{name: "only NUL", command: "\x00", hasDir: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := checkCommand(tt.command, tt.hasDir)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkCommand(%q, %v) error = %v, want error %v", tt.command, tt.hasDir, err, tt.wantErr)
			}
			if err == nil {
				return
			}
			if !errors.Is(err, ErrInvalidServer) {
				t.Errorf("checkCommand(%q, %v) error = %v, want ErrInvalidServer", tt.command, tt.hasDir, err)
			}
			if visible := strings.TrimRight(tt.command, "\x00"); visible != "" && strings.Contains(err.Error(), visible) {
				t.Errorf("checkCommand(%q, %v) error %q contains the command", tt.command, tt.hasDir, err)
			}
		})
	}
}

func TestIsRelativePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		command string
		want    bool
	}{
		{command: "npx", want: false},
		{command: "node", want: false},
		{command: "server.js", want: false},
		{command: "/usr/bin/node", want: false},
		{command: "/", want: false},
		{command: "./server", want: true},
		{command: "bin/server", want: true},
		{command: "../server", want: true},
		{command: "a/b/c", want: true},
		{command: "server/", want: true},
		{command: "~/bin/server", want: true},
	}
	if runtime.GOOS == "windows" {
		tests = append(tests,
			struct {
				command string
				want    bool
			}{command: `bin\server`, want: true},
			struct {
				command string
				want    bool
			}{command: `C:\bin\server.exe`, want: false},
		)
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			t.Parallel()

			if got := isRelativePath(tt.command); got != tt.want {
				t.Errorf("isRelativePath(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}
