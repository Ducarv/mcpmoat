package inspect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// errCommandNotFound reports that lookPath found no executable file for a
// bare command name. The text is fixed on purpose. The command name and the
// PATH value come from untrusted config text, so the error never includes
// them. The caller adds context in a safe way.
var errCommandNotFound = errors.New("inspect: command not found in PATH")

// lookPath finds the executable file for the bare command name file in the
// directories of pathList. pathList has the same format as the PATH
// environment variable: directories separated by the list separator (":" on
// Unix).
//
// Precondition: file is a bare name with no "/". The caller uses the
// configured command as it is when it contains a "/". If file is empty or
// contains a "/", lookPath returns errCommandNotFound and does not panic.
//
// Why mcpmoat does not use exec.LookPath: exec.LookPath (and exec.Command)
// search the PATH of the mcpmoat process. The server child gets a scrubbed
// environment, and the config can set its own PATH. The MCP clients search
// the PATH of the child environment (Node spawn uses options.env.PATH, Rust
// Command uses a PATH set with env). lookPath does the same with the final
// child PATH, so mcpmoat starts the same file as the client.
//
// Risks:
//   - The search uses the user's PATH (or the PATH from the config), the same
//     as the client. A directory early in PATH that others can write to is a
//     risk here too, but it is the same risk as in the client.
//   - The PATH of mcpmoat can differ from the PATH of a GUI client (for
//     example, a client started from the desktop does not read the shell
//     profile). Then mcpmoat can find a different file. This is a fidelity
//     limit.
//   - Only the first exec is protected from empty and relative PATH entries.
//     The child still gets PATH unchanged. So its own subprocesses (for
//     example "#!/usr/bin/env node" in npx) resolve empty and relative
//     entries against its work directory, the same as in the client.
//   - The file that os.Stat found can change before execve (TOCTOU). Only
//     someone with write access to that PATH directory can do that, and the
//     client has the same exposure. So this risk is accepted.
//
// Rules:
//   - Empty entries and relative entries (such as "." or "bin") are skipped.
//     This is stricter than POSIX execvp, which treats an empty entry as the
//     work directory. It follows the ErrDot rule of os/exec (Go 1.19 and
//     later): a relative entry makes the result depend on the work directory.
//   - If pathList has no usable entry, the command is not found. No default
//     PATH is used.
//   - The first candidate that is a regular file with an execute bit wins.
//     os.Stat follows symlinks. This check is modelled on the mode-bit
//     fallback of findExecutable in os/exec on Unix. It is not the same
//     check: findExecutable rejects only directories and then uses
//     unix.Eaccess(X_OK), and it uses the mode bits only as a fallback.
//     isExecutableFile needs a regular file and accepts any execute bit,
//     even one that the current user cannot use. Such a file is accepted
//     and then fails at Start. That fails closed: no other binary runs. But
//     execvp and libuv move on to the next PATH entry in that case. This is
//     a known fidelity gap.
//
// The semantics are Unix only. Windows is a non-goal (PRD section 2.2), so
// there is no PATHEXT handling and no search for ".exe" names.
func lookPath(file, pathList string) (string, error) {
	if file == "" || strings.Contains(file, "/") {
		return "", errCommandNotFound
	}
	for _, dir := range filepath.SplitList(pathList) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		// Build the candidate with plain string concatenation, not
		// filepath.Join. filepath.Join cleans the path lexically: it removes
		// "a/.." pairs as text. The kernel resolves ".." after it follows a
		// symlink, so a lexical clean can point to a different file. We keep
		// the directory text exactly as configured. We only trim one trailing
		// "/" to avoid "//" (a double slash is harmless on Unix, but the
		// result is easier to read).
		candidate := strings.TrimSuffix(dir, "/") + "/" + file
		if isExecutableFile(candidate) {
			return candidate, nil
		}
	}
	return "", errCommandNotFound
}

// isExecutableFile reports whether path names a regular file with at least
// one execute bit set. os.Stat follows symlinks, so a symlink to an
// executable file counts. The mask 0o111 selects the execute bits for owner,
// group and others.
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	mode := info.Mode()
	return mode.IsRegular() && mode&0o111 != 0
}
