package inspect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// waitDelay is a backstop for Wait after ctx is done. os/exec then kills the
// process (cmd.Cancel). If Wait still has not returned after waitDelay, it
// kills the process again and closes the pipes. It does not bound a normal
// stop: stdin and stdout are pipes from StdinPipe and StdoutPipe and stderr
// is os.DevNull, so os/exec copies nothing in a goroutine, and Wait returns
// when the child exits, even if a process that the child started still
// holds the pipes.
const waitDelay = 2 * time.Second

// noCleanup is the cleanup func that buildCommand returns when there is
// nothing to remove. Callers can always call cleanup without a nil check.
func noCleanup() {}

// buildCommand prepares the child process for the stdio server s. It does
// not start the process: the caller (the SDK command transport) does that.
//
// Security (NFR-04):
//
//   - The process runs exactly s.Command with exactly s.Args, through
//     exec.CommandContext. There is no shell, so shell syntax in the config
//     (";", "|", "$(...)") stays plain text in one argument.
//   - The environment is built from scratch by [childEnv] with getenv. The
//     process does not inherit the environment of mcpmoat.
//   - When s.Dir is absolute, the process runs in s.Dir. Otherwise it runs
//     in a new, empty temporary directory under runRoot (see
//     [defaultRunRoot]), so a relative argument such as "./server.js"
//     never resolves against the working directory of mcpmoat. A relative
//     Dir counts as no Dir: it is relative to where the user runs the
//     client, which mcpmoat does not know.
//   - Without an absolute Dir, a relative command with a directory part
//     (for example "./server" or "bin/server") is refused. It could only
//     resolve against the temporary directory, so it cannot be the
//     command that the client runs.
//   - The stderr of the process goes to os.DevNull, so server output never
//     reaches the terminal unescaped.
//
// A bare command name such as "npx" is looked up in the PATH of mcpmoat by
// exec.CommandContext (exec.LookPath), not in the PATH of childEnv. Since Go
// 1.19, LookPath refuses a result found through "." or an empty PATH entry
// (exec.ErrDot), so a bare name never runs from the working directory of
// mcpmoat. A lookup failure is stored in cmd.Err and returned by Start.
//
// The returned cleanup removes the temporary directory, if buildCommand
// made one. Call it after the process has exited. cleanup is never nil, also
// on error.
//
// The error wraps [ErrUnsupportedTransport] for a server that is not
// TransportStdio, [ErrInvalidServer] for a config that cannot run safely,
// and [ErrStart] when runRoot fails or the temporary working directory
// cannot be made. The
// error text never contains the values of Args or Env, and it does not
// contain the command.
func buildCommand(ctx context.Context, s discover.Server, getenv func(string) string, runRoot func() (string, error)) (cmd *exec.Cmd, cleanup func(), err error) {
	if s.Transport != discover.TransportStdio {
		return nil, noCleanup, fmt.Errorf("%w: not a stdio server", ErrUnsupportedTransport)
	}

	// An absolute Dir is used as is. An empty or relative Dir is not
	// trusted (see the doc on discover.Server.Dir).
	hasDir := filepath.IsAbs(s.Dir)
	if err := checkCommand(s.Command, hasDir); err != nil {
		return nil, noCleanup, err
	}

	// Build the environment before the temporary directory, so that an
	// invalid env needs no cleanup.
	env, err := childEnv(getenv, s.Env)
	if err != nil {
		return nil, noCleanup, err
	}

	dir := s.Dir
	cleanup = noCleanup
	if !hasDir {
		root, err := runRoot()
		if err != nil {
			return nil, noCleanup, fmt.Errorf("%w: working directory root: %w", ErrStart, err)
		}
		// MkdirTemp makes a new directory with mode 0o700 and a random
		// suffix, so no earlier run can put files in it. runRoot is private
		// too, so no other user can put files in a parent directory that a
		// launcher reads (see defaultRunRoot).
		dir, err = os.MkdirTemp(root, "mcpmoat-server-*")
		if err != nil {
			return nil, noCleanup, fmt.Errorf("%w: create working directory: %w", ErrStart, err)
		}
		cleanup = func() { _ = os.RemoveAll(dir) }
	}

	cmd = exec.CommandContext(ctx, s.Command, s.Args.Values()...) //nolint:gosec // G204: runs exactly the command and args the user configured in their MCP client, without a shell (NFR-04)

	// cmd.Dir is the working directory of the child. A relative command
	// with a directory part ("bin/server") stays relative in cmd.Path:
	// the os/exec docs say "If Path is relative, it is evaluated relative
	// to Dir", and the child process changes to Dir before it starts the
	// program. So with an absolute s.Dir the child runs <s.Dir>/bin/server,
	// the same as a client that starts the server with that cwd. There is
	// no need to join s.Dir and s.Command here.
	cmd.Dir = dir
	cmd.Env = env

	// A nil Stderr connects the stderr of the child to os.DevNull. Server
	// output is untrusted text: it must not reach the terminal unescaped.
	cmd.Stderr = nil
	// Stdin and Stdout stay nil on purpose. The SDK command transport calls
	// cmd.StdinPipe and cmd.StdoutPipe, which fail if they are already set.

	cmd.WaitDelay = waitDelay

	return cmd, cleanup, nil
}

// defaultRunRoot returns <user cache dir>/mcpmoat/run, the directory in
// which buildCommand makes the working directory of a server without an
// absolute Dir. It makes the directory if it does not exist, and checks it
// with [privateDir].
//
// Why not os.TempDir: on most Linux systems it is /tmp, which every user can
// write. Launchers look for their config in the parent directories of their
// working directory: npx walks up to the first directory with package.json
// or node_modules and runs node_modules/.bin/<name> from there, and reads
// .npmrc there; uv run walks up to pyproject.toml. So another local user
// could put /tmp/node_modules/.bin/<name> in place, and a scan would run it
// with the secret env of the server. The user cache dir is in the home
// directory of the user ($XDG_CACHE_HOME or ~/.cache on Linux,
// ~/Library/Caches on macOS), whose parents other users cannot write.
//
// The residual: if the user sets XDG_CACHE_HOME to a directory below a
// shared directory such as /tmp, a parent of the root is shared again.
func defaultRunRoot() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return privateDir(filepath.Join(cache, "mcpmoat", "run"))
}

// privateDir makes dir with mode 0o700 if it does not exist, and returns it.
// It returns an error when dir is not a real directory (for example a
// symbolic link) or when, on Unix, its group or other users have any access
// to it. It does not change an existing directory.
func privateDir(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}
	// Windows reports no Unix permission bits for a directory.
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm&0o077 != 0 {
		return "", fmt.Errorf("%s has mode %v, want no access for group and others", dir, perm)
	}
	return dir, nil
}

// checkCommand reports why command cannot run safely, or nil if it can.
// hasDir tells whether the server has an absolute working directory. The
// error wraps [ErrInvalidServer] and never contains the command itself.
func checkCommand(command string, hasDir bool) error {
	switch {
	case command == "":
		return fmt.Errorf("%w: command is empty", ErrInvalidServer)
	case strings.ContainsRune(command, 0):
		return fmt.Errorf("%w: command contains a NUL byte", ErrInvalidServer)
	case !hasDir && isRelativeWithDir(command):
		return fmt.Errorf("%w: relative command path needs an absolute working directory", ErrInvalidServer)
	}
	return nil
}

// isRelativeWithDir reports whether command is a relative path with a
// directory part, such as "./server" or "bin/server". It is false for a bare
// name such as "npx", which exec looks up in PATH. The test filepath.Base(command) !=
// command is the same test that exec.Command uses to decide whether to call
// LookPath.
func isRelativeWithDir(command string) bool {
	return !filepath.IsAbs(command) && filepath.Base(command) != command
}
