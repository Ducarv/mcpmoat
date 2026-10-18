package inspect

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// The errors below have fixed text on purpose. The command, the args, the
// env names and the env values come from untrusted config text and can hold
// secrets, so no error from stdioCommand includes them.

// errNotStdio reports that stdioCommand got a server whose transport is not
// stdio.
var errNotStdio = errors.New("inspect: server does not use the stdio transport")

// errUntrusted reports that the server comes from an untrusted project file
// and the user did not opt in to start such servers. See the discover
// package doc, Untrusted files.
var errUntrusted = errors.New("inspect: server from an untrusted project file needs an explicit opt-in to start")

// errEmptyCommand reports that the server config sets no command.
var errEmptyCommand = errors.New("inspect: server config has an empty command")

// errInvalidArg reports that the command, an arg or the absolute work
// directory (Dir) of the server config contains a NUL byte. The operating
// system cannot pass such a string to a child process. A relative Dir is
// not checked, because stdioCommand does not use it.
var errInvalidArg = errors.New("inspect: invalid command, argument or work directory in server config")

// errNoWorkDir reports that the server needs the fallback work directory
// (the config sets no absolute Dir), but stdioOptions.FallbackDir is empty,
// not absolute or contains a NUL byte.
var errNoWorkDir = errors.New("inspect: no absolute work directory for the server")

// errRelativeCommand reports a relative command with a "/" (such as
// "./server" or "bin/server") in a config that sets no absolute Dir. The
// path is relative to a directory that mcpmoat does not know, so mcpmoat
// does not guess one.
var errRelativeCommand = errors.New("inspect: relative command path needs an absolute work directory in the server config")

// errCommandNotRunnable reports that exec.Command refused the command path.
// This should not happen after the checks in stdioCommand. It is a guard,
// because the exec error text includes the path.
var errCommandNotRunnable = errors.New("inspect: configured command cannot be run")

// stdioOptions holds the inputs of stdioCommand that do not come from the
// server config.
type stdioOptions struct {
	// Environ is the parent environment in the form of os.Environ:
	// "name=value" entries. The caller passes os.Environ(). Nil means an
	// empty parent. That fails safe, and it lets tests run in parallel
	// without t.Setenv.
	Environ []string

	// FallbackDir is the work directory of the child when the config sets no
	// absolute Dir. It must be absolute. The caller makes a private, empty
	// directory and removes it after the server stops (issue #25 owns that
	// lifecycle). stdioCommand does not check the directory on disk.
	//
	// The whole parent chain matters, not only the leaf. npm walks up the
	// parent directories from the work directory to find a local prefix (a
	// node_modules directory or a package.json file). Then it reads the
	// .npmrc and the node_modules/.bin of that prefix. uv also walks up to
	// find uv.toml and pyproject.toml. So every directory in the chain must
	// be writable only by the user or root. Another local user can plant
	// /tmp/node_modules, so a private leaf under /tmp does not protect the
	// user.
	//
	// So the caller makes a 0700 parent under os.UserCacheDir(), for example
	// <cache>/mcpmoat/, and then calls os.MkdirTemp(parent, ...). It never
	// uses os.MkdirTemp("", ...), because that uses os.TempDir(), which is
	// /tmp on Linux when TMPDIR is not set. Then the caller checks every
	// directory from the fallback up to "/" with os.Lstat. Each one must be
	// owned by the current user or by root, and must not be writable by the
	// group or by others. A sticky, world-writable directory such as /tmp
	// fails this check. On a failure, the caller refuses with a fixed error.
	// On Linux, os.UserCacheDir follows $XDG_CACHE_HOME, so the cache
	// directory can be anywhere. The chain check covers that case.
	//
	// HOME stays in the chain, because <cache> (~/.cache or
	// ~/Library/Caches) is under HOME. So npm and uv can still find
	// ~/node_modules, ~/package.json or ~/pyproject.toml. This is accepted:
	// HOME is owned by the user, and the client sees the same files. The rule
	// is that the work directory itself is never HOME.
	//
	// The work directory itself is never the mcpmoat work directory, HOME, a
	// project directory, or a directory under /tmp or os.TempDir(). In a
	// repository directory, npx and uvx read the node_modules/.bin, .npmrc and
	// pyproject.toml of the repository, so the repository could change what
	// runs.
	FallbackDir string

	// AllowUntrusted is the explicit opt-in of the user to start a server
	// from an untrusted project file (see the discover package doc,
	// Untrusted files). It is false by default, so stdioCommand fails
	// closed.
	AllowUntrusted bool
}

// stdioCommand builds the *exec.Cmd that starts the stdio server s
// (NFR-04). It does not start the process. The caller (issue #25) gives the
// result to the MCP SDK transport.
//
// Invariants:
//   - No shell. The child runs the configured command with the configured
//     args, and nothing expands globs, variables or quotes.
//   - The argv is exactly the config: Args[0] is s.Command as written, and
//     the other entries are s.Args.Values().
//   - cmd.Env is never nil, so the child never inherits the whole parent
//     environment. It has the allowlisted parent entries plus the config env
//     (see buildEnv).
//   - A server with s.Untrusted set needs opts.AllowUntrusted.
//   - A bare command name (no "/") is looked up in the PATH of the child
//     environment, not in the PATH of mcpmoat (see lookPath).
//   - Work directory: an absolute s.Dir as written, else
//     opts.FallbackDir. A relative s.Dir counts as no Dir, because it is
//     relative to where the user runs Codex, which mcpmoat does not know.
//   - Every error is, or wraps, a fixed sentinel with no command, arg, name
//     or value in it.
//   - On Unix, cmd.SysProcAttr comes from detachSysProcAttr.
//
// The checks run in this order, and the first failed check gives the error:
//  1. the transport is stdio, else errNotStdio;
//  2. the untrusted gate, else errUntrusted;
//  3. the command is not empty, else errEmptyCommand; then no NUL byte in
//     the command, in an arg or in an absolute s.Dir, else errInvalidArg;
//  4. the environment (buildEnv), which wraps errInvalidEnvName or
//     errInvalidEnvValue;
//  5. the work directory, else errNoWorkDir;
//  6. the command path, else errRelativeCommand or errCommandNotFound;
//  7. exec.Command, else errCommandNotRunnable.
//
// Stdin, Stdout and Stderr stay nil: the SDK transport makes its own pipes.
// The caller must never connect cmd.Stdout or cmd.Stderr to the terminal of
// the user. It pipes them and escapes the text with internal/termsafe, or it
// discards them.
//
// On Unix the child starts in a new session; see detachSysProcAttr. That
// comment explains what the new session blocks and what it does not block,
// and how the caller stops the process group.
//
// AllowUntrusted also trusts the absolute s.Dir of the server as written.
// The discover package checked that Dir only when it read the config file.
// So the caller must check the Dir again before cmd.Start (it must still be
// inside s.ProjectPath after symlinks are resolved), or accept that risk
// explicitly.
//
// The raw values from Secret.Reveal and Args.Values go only into cmd.Env and
// cmd.Args. So the returned *exec.Cmd holds secrets: callers must never
// print, log or encode cmd.String(), cmd.Env or cmd.Args. Callers must also
// never give the *exec.Cmd value itself to fmt (for example with %+v), to
// slog or to an encoder, because its exported Env and Args fields hold the
// raw values.
//
// Start errors are not safe to print either. cmd.Start can fail with an
// *os.PathError whose Path is cmd.Dir (Op "chdir") or cmd.Path (Op
// "fork/exec"). The go-sdk CommandTransport.Connect calls cmd.Start and
// returns that error unchanged. Both paths are untrusted config text and can
// hold terminal escape sequences. So the caller (issue #25) must replace
// such an error with fixed text and keep only its errors.Is class
// (fs.ErrNotExist, fs.ErrPermission). It must never print err.Error().
func stdioCommand(s discover.Server, opts stdioOptions) (*exec.Cmd, error) {
	if s.Transport != discover.TransportStdio {
		return nil, errNotStdio
	}
	if s.Untrusted && !opts.AllowUntrusted {
		return nil, errUntrusted
	}
	if s.Command == "" {
		return nil, errEmptyCommand
	}
	args := s.Args.Values()
	if hasNUL(s.Command) {
		return nil, errInvalidArg
	}
	for _, arg := range args {
		if hasNUL(arg) {
			return nil, errInvalidArg
		}
	}
	// Only an absolute Dir is used (see the work directory step below), so
	// only an absolute Dir is checked. This check covers only the NUL case: a
	// NUL byte would make cmd.Start fail with an os.PathError that holds the
	// Dir text. Other cmd.Start failures can still hold the Dir text (see the
	// note on Start errors in the doc comment above).
	if filepath.IsAbs(s.Dir) && hasNUL(s.Dir) {
		return nil, errInvalidArg
	}

	env, err := buildEnv(opts.Environ, s.Env)
	if err != nil {
		// buildEnv returns fixed sentinels only, so the wrap adds no value
		// from the config.
		return nil, fmt.Errorf("inspect: build server environment: %w", err)
	}
	if env == nil {
		// buildEnv never returns nil on success. This check keeps the
		// invariant local: a nil cmd.Env would give the child the whole
		// parent environment.
		env = []string{}
	}

	dir, configDir := s.Dir, true
	if !filepath.IsAbs(s.Dir) {
		dir, configDir = opts.FallbackDir, false
		// FallbackDir comes from the caller, not the config. A NUL byte in
		// it is a caller bug, but it gets the same fixed error.
		if !filepath.IsAbs(dir) || hasNUL(dir) {
			return nil, errNoWorkDir
		}
	}

	path, err := commandPath(s.Command, configDir, env)
	if err != nil {
		return nil, err
	}

	// exec.Command calls exec.LookPath only when filepath.Base(path) == path,
	// that is, for a bare name. Here path is absolute or holds a "/", so
	// exec.Command does no lookup in the PATH of mcpmoat. One odd case still
	// gets a lookup: the path "/" (its Base is "/"). That lookup fails and
	// sets cmd.Err, which the check below catches.
	cmd := exec.Command(path, args...) //nolint:gosec // G204: runs exactly the configured command without a shell (NFR-04); untrusted servers need opt-in.
	if cmd.Err != nil {
		// cmd.Err can include the path, so return a fixed error instead.
		return nil, errCommandNotRunnable
	}

	// exec.Command sets Args[0] to path. For a bare name, path is the full
	// path that lookPath found. The MCP clients pass the command as written
	// as argv[0] (for example "npx"), and some programs read argv[0]. So
	// Args[0] gets s.Command, and the argv is byte-for-byte the config.
	// cmd.Path still names the file to run.
	cmd.Args[0] = s.Command
	cmd.Dir = dir
	cmd.Env = env
	cmd.SysProcAttr = detachSysProcAttr()
	return cmd, nil
}

// commandPath returns the path that the child runs for command.
//
//   - An absolute command is used as written.
//   - A relative command with a "/" (such as "./server") is used as written,
//     but only when the config sets an absolute Dir (configDir). See the
//     note below.
//   - A bare name is looked up with lookPath in the PATH of the final child
//     environment env.
//
// Why a relative path is kept relative, with no filepath.Join: on Unix,
// Cmd.Start passes Cmd.Path unchanged to os.StartProcess, together with
// Cmd.Dir. In the child, syscall.forkExec first calls chdir(Dir) and then
// execve(Path) (see forkAndExecInChild in syscall/exec_libc2.go and
// syscall/exec_linux.go). So the kernel resolves a relative Path against
// Dir, not against the work directory of mcpmoat. Go does not make the path
// absolute in the parent. (Only Windows resolves the path in Cmd.Start, and
// Windows is a non-goal.) filepath.Join would also clean "a/.." pairs as
// text, which can name another file than the kernel finds after a symlink.
func commandPath(command string, configDir bool, env []string) (string, error) {
	if filepath.IsAbs(command) {
		return command, nil
	}
	if strings.Contains(command, "/") {
		if !configDir {
			return "", errRelativeCommand
		}
		return command, nil
	}
	return lookPath(command, pathFromEnv(env))
}

// pathFromEnv returns the value of the PATH entry in env, or "" when env has
// no PATH entry. env comes from buildEnv: it is sorted and has unique names,
// so it has at most one PATH entry. The loop still keeps the last match, the
// same as a later entry that overrides an earlier one.
func pathFromEnv(env []string) string {
	path := ""
	for _, entry := range env {
		if value, ok := strings.CutPrefix(entry, "PATH="); ok {
			path = value
		}
	}
	return path
}

// hasNUL reports whether s contains a NUL byte. A string with a NUL byte
// cannot be passed to the operating system as a C string.
func hasNUL(s string) bool {
	return strings.IndexByte(s, 0) >= 0
}
