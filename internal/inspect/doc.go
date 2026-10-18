// Package inspect connects to MCP servers over stdio or HTTP and lists their
// tools, prompts and resources. Protocol details stay behind an interface in
// this package so that MCP spec changes stay local.
//
// See docs/PRD.md, FR-04 to FR-06, NFR-04 and NFR-06.
//
// # Starting stdio servers
//
// stdioCommand builds the [os/exec.Cmd] for a stdio server (NFR-04). It
// never uses a shell. The command and the args go to the child byte-for-byte
// as configured, also argv[0]. Nothing expands globs, variables or quotes.
// The user-facing version of this section is docs/stdio-servers.md.
//
// The environment is built from scratch. The child gets a small allowlist
// from the mcpmoat environment, plus the variables that the server config
// declares. The allowlist is HOME, LANG, LC_ALL, LC_CTYPE, LOGNAME, PATH,
// SHELL, TERM, TMPDIR, TZ, USER and __CF_USER_TEXT_ENCODING. See isBaseEnv
// for the reason of each entry. Other variables are excluded on purpose:
// agent sockets (SSH_AUTH_SOCK), proxies (a proxy URL can hold credentials),
// CA overrides, tokens and cloud keys (AWS_*, *_TOKEN), loader hooks (LD_*,
// DYLD_*, NODE_OPTIONS) and PWD. A user who needs one of them declares it in
// the env of the server config.
//
// A config env entry overrides an allowlist entry with the same name. A
// ${VAR} placeholder is passed as written for now (issue #88). A bad name or
// a NUL byte refuses the server. The error text is fixed and holds no name
// and no value. The Env of the Cmd is never nil, because a nil Env makes the
// child inherit the whole parent environment.
//
// The work directory is the config Dir (the Codex cwd) when it is absolute.
// mcpmoat uses that Dir as written, so files in it can change what runs, the
// same as in the client. Else the work directory is stdioOptions.FallbackDir,
// a private, empty directory that the caller makes. The rules below are for
// the fallback only. npx and uvx read node_modules/.bin, .npmrc and
// pyproject.toml from the work directory and also from its parent
// directories, because npm and uv walk up the parent chain. So the fallback
// itself is never the mcpmoat work directory, HOME, a project directory, or
// any directory under /tmp or os.TempDir(). The caller makes the fallback
// with os.MkdirTemp under a 0700 directory in os.UserCacheDir() (for example
// <cache>/mcpmoat/). Then it checks every directory from the fallback up to
// "/": each must be writable only by the user or root (see
// stdioOptions.FallbackDir). HOME stays in that chain, which is accepted
// because the user owns HOME and the client sees the same files. A relative
// command with a "/" (such as "./server") needs an absolute config Dir. This
// is a fidelity limit: a client can start a project server in the project
// root, and mcpmoat does not.
//
// On Unix the child starts in a new session; see detachSysProcAttr. The
// caller never connects the stdout or stderr of the child to the terminal
// of the user.
//
// A bare command name (no "/") is looked up in the final PATH of the child,
// so a PATH from the config wins (see lookPath). Node spawn and Rust Command
// do the same. Empty and relative PATH entries are skipped, which is stricter
// than execvp. Risks:
//
//   - A directory early in PATH that others can write to is a risk. It is
//     the same risk as in the client.
//   - The PATH of mcpmoat can differ from the PATH of a GUI client. For
//     example, a macOS app started from the Dock gets the launchd PATH. Then
//     mcpmoat can run a different npx than the client.
//
// A server from an untrusted project file starts only with an explicit
// opt-in (stdioOptions.AllowUntrusted). See the discover package doc,
// Untrusted files.
//
// The returned Cmd holds revealed secrets. Never print, log or encode
// cmd.String(), cmd.Env or cmd.Args.
//
// The rules are for Unix only. Windows is a non-goal (PRD section 2.2).
package inspect
