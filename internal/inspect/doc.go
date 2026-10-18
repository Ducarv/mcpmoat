// Package inspect connects to MCP servers and lists their tools, prompts and
// resources. Protocol details stay behind the Inspector interface so that MCP
// spec changes stay local.
//
// # Running many servers
//
// Run inspects a list of servers through an Inspector, with a bounded pool of
// workers and a time limit for each server (see Options, DefaultConcurrency
// and DefaultTimeout). It returns one Outcome per server, in a stable order,
// with a Status of ok, timeout or failed. One broken, hung or panicking server
// does not stop the others. The Run doc has the full contract.
//
// An Inspector does the work for one server. Its doc lists what an
// implementation must do: honour the context, stop its child processes, close
// its pipes, refuse untrusted servers without an opt-in, and keep secrets out
// of its errors.
//
// # Starting stdio servers
//
// stdioCommand builds the [os/exec.Cmd] for a stdio server (NFR-04). It
// never uses a shell. The command and the args go to the child byte-for-byte
// as configured, also argv[0]. Nothing expands globs, variables or quotes.
// The user-facing version of this section is docs/stdio-servers.md.
//
// The environment is built from scratch (buildEnv). The child gets a small
// allowlist from the mcpmoat environment, plus the variables that the server
// config declares. isBaseEnv holds the allowlist and the reason for each
// entry. Agent sockets, proxies, tokens, cloud keys and loader hooks are
// excluded on purpose. A user who needs one of them declares it in the env
// of the server config.
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
// a private, empty directory that the caller makes. npm and uv read files
// from the work directory and from all its parent directories, so the
// caller must follow the rules in the FallbackDir comment. A relative command
// with a "/" (such as "./server") needs an absolute config Dir. This is a
// fidelity limit: a client can start a project server in the project root,
// and mcpmoat does not.
//
// On Unix the child starts in a new session; see detachSysProcAttr. The
// caller never connects the stdout or stderr of the child to the terminal
// of the user.
//
// A bare command name (no "/") is looked up in the final PATH of the child,
// so a PATH from the config wins. Node spawn and Rust Command do the same.
// lookPath lists the skip rules and the PATH risks.
//
// A server from an untrusted project file starts only with an explicit
// opt-in (stdioOptions.AllowUntrusted). See the discover package doc,
// Untrusted files.
//
// The returned Cmd holds revealed secrets. Never print, log or encode
// cmd.String(), cmd.Env or cmd.Args.
//
// The rules are for Unix only. Windows is a non-goal (PRD section 2.2).
//
// # Child processes
//
// configureProcessGroup puts a stdio server in its own process group, and
// killProcessGroup kills every process that is still in that group. With
// the Setsid of stdioCommand, the new session is already that group, and
// configureProcessGroup keeps it. The helpers are for the stdio Inspector of
// issue #25; today only the tests call them. stdioCommand returns a Cmd made
// with exec.Command, and exec refuses a Cancel on a Cmd without a context, so
// that Inspector must build the Cmd with a context before it calls
// configureProcessGroup. A process that leaves the group on purpose (with
// setsid, setpgid or a double fork) is not killed, so this is not a sandbox.
// The group kill works on Unix only (macOS and Linux). On other systems, only
// the direct child is killed.
//
// The text of Outcome.Err is untrusted (see Outcome).
//
// See docs/PRD.md, FR-04 to FR-06, NFR-03, NFR-04 and NFR-06.
package inspect
