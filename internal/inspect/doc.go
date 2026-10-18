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
// # Remote servers
//
// [Remote] connects to a remote server and lists its tools, prompts and
// resources. It refuses a server from an untrusted project file unless the
// caller sets [RemoteOptions].AllowUntrusted after the explicit opt-in of the
// user. The config type of the server picks the transport: http is
// streamable HTTP, and sse is the legacy HTTP+SSE transport. mcpmoat does not
// probe the other transport. If a server answers with an error that may mean
// the wrong transport, the error text tells the user to change the type.
//
// # Secrets
//
// The header values and the secrets in the URL (the userinfo and the query)
// go only to the configured origin. They never appear in an error. The
// package removes them from the error text before it builds a [ConnectError].
// The package never gives the userinfo of the URL to the SDK. It sends the
// userinfo as a Basic Authorization header, unless the config sets an
// Authorization header.
//
// The text of a [ConnectError] can still hold text that the server controls
// (see "Untrusted data" below).
//
// # Client identity
//
// The package does not tell the server that the client is mcpmoat. The
// default User-Agent is the net/http one, and the client name in the MCP
// initialize request is a generic one. A server that recognises the scanner
// could show it a clean tool list and show the real clients a poisoned one.
// A server can still tell clients apart in other ways (see docs/PRD.md,
// section 5.5).
//
// # Origin pin and redirects
//
// Every request must go to the configured scheme, host and port. The package
// refuses any other request before it sends anything. This also blocks an SSE
// server that announces its message endpoint on another host.
//
// A redirect is followed only when it stays on the same origin, and at most 3
// times. Any other redirect is an error.
//
// # Limits
//
// A hostile server can send endless data, so the package sets limits:
//
//   - Each HTTP response body has a size cap (8 MiB by default). The whole
//     SSE stream counts as one body.
//   - All bodies of one inspection share a total budget (64 MiB). Many bodies
//     that are each below the cap cannot add up to more than the budget.
//   - The response headers of one response have a size limit (64 KiB).
//   - A list has a cap on the number of pages (100) and the number of items
//     (10,000). A repeated cursor is an error.
//   - The SDK silently drops tools that have an invalid x-mcp-header
//     annotation. The package records the tools list as the server sent it and
//     reports every tool, because a scanner must see what the server sent.
//
// A cap breach is an error. The package never cuts a list and returns the
// rest, because the cut part could hide a malicious tool.
//
// The caps count bytes on the wire. The SDK decodes each page into Go values
// before the item cap applies, and decoded JSON can take many times its wire
// size (a schema of millions of empty objects, for example). So one page can
// use far more memory than the body cap. Issue #101 tracks a bounded decoder.
//
// # Network
//
// The package honours the proxy settings from the HTTP_PROXY, HTTPS_PROXY and
// NO_PROXY environment variables. It makes no other network access (NFR-01).
// Some clients ignore these variables, so a scan can take another route than
// the client does. Over an http:// URL, the proxy then sees the configured
// headers.
//
// TLS 1.2 or newer is required, and certificates are always verified. There is
// no option to skip the check: only tests in this package can replace the
// transport.
//
// # Untrusted data
//
// Every string in a [Result] comes from the server, and a malicious server
// controls it. Never execute it, never put it in a command or a format
// string, and escape it with internal/termsafe before you print it. The same
// is true for the text of a [ConnectError], which can hold a status text or a
// JSON-RPC message from the server, and for the text of Outcome.Err (see
// Outcome).
//
// See docs/PRD.md, FR-04 to FR-06, NFR-01, NFR-03, NFR-04 and NFR-06.
package inspect
