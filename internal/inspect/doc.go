// Package inspect connects to MCP servers and lists their tools, prompts and
// resources (FR-04). Protocol details stay behind an interface in this
// package so that MCP spec changes stay local.
//
// See docs/PRD.md, FR-04 to FR-06, NFR-04 and NFR-06.
//
// # Overview
//
// The rest of mcpmoat talks MCP only through the [Inspector] interface. Its
// one method, [Inspector.Inspect], takes one [discover.Server] and returns a
// [Result]. Result and the types it holds ([Tool], [Prompt],
// [PromptArgument], [Resource]) do not use types from the MCP SDK, so rules,
// pins and report do not depend on the SDK.
//
// [SDKInspector] is the real implementation. It uses the official MCP Go SDK
// (github.com/modelcontextprotocol/go-sdk). Make one with [New] and
// [Options]. Only this package imports the SDK, so MCP spec changes stay
// here (NFR-06). The depguard rule mcp-sdk-only-in-inspect in .golangci.yml
// enforces this.
//
// Tests in other packages must not start real servers. They use
// [github.com/Ducarv/mcpmoat/internal/inspect/inspecttest.Fake], an
// Inspector that returns canned results.
//
// # Error contract
//
// The full contract is on [Inspector]. In short:
//
//   - A non-nil error always comes with a zero Result.
//   - An error wraps one of the sentinel errors of this package
//     ([ErrUntrusted], [ErrUnsupportedTransport], [ErrInvalidServer],
//     [ErrStart], [ErrProtocol], [ErrTooManyItems]) or the context error.
//     Use errors.Is to test for them, also for context.DeadlineExceeded and
//     context.Canceled.
//   - mcpmoat never puts the values of Args, Env, Headers or URL of the
//     server in the error text, because they can hold secrets. Text that
//     the server sent can still hold them; see [Inspector].
//   - An error means that the server was not scanned. Callers must report it
//     as a finding about the server, never as a clean server; see
//     [Inspector].
//
// # Untrusted text
//
// A server can send any bytes. Every string in a Result is untrusted text
// from the server. An error text can hold text from the server too. That
// text can hold control characters, terminal escape sequences or a prompt
// injection. Callers must print it through package internal/termsafe, and
// must never execute or interpolate it.
//
// # Untrusted servers
//
// A server from a project file has [discover.Server.Untrusted] set, because
// a cloned repository can ship that file. [SDKInspector.Inspect] does not
// start such a server and returns [ErrUntrusted], unless
// [Options.AllowUntrusted] is true. AllowUntrusted is the explicit opt-in of
// the user.
//
// # Starting stdio servers
//
// stdioCommand builds the [os/exec.Cmd] for a stdio server (NFR-04), and
// [SDKInspector.Inspect] starts it. It never uses a shell. The command and
// the args go to the child byte-for-byte as configured, also argv[0].
// Nothing expands globs, variables or quotes. The user-facing version of
// this section is docs/stdio-servers.md.
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
// same as in the client. Else Inspect makes a new, empty directory below
// <user cache dir>/mcpmoat/run (workDir) and removes it after the stop. npm
// and uv read files from the work directory and from all its parent
// directories, so the run root and every parent up to "/" must be owned by
// the user or root and must not be writable by others (defaultRunRoot,
// checkPrivateChain). A relative command with a "/" (such as "./server")
// needs an absolute config Dir.
//
// On Unix the child starts in a new session and process group; see
// detachSysProcAttr. The stdout of the child is the MCP connection, and its
// stderr is discarded, so server output never reaches the terminal of the
// user unescaped.
//
// A bare command name (no "/") is looked up in the final PATH of the child,
// so a PATH from the config wins. Node spawn and Rust Command do the same.
// lookPath lists the skip rules and the PATH risks.
//
// A server from an untrusted project file starts only with an explicit
// opt-in (Options.AllowUntrusted). See the discover package doc, Untrusted
// files.
//
// The Cmd holds revealed secrets. Never print, log or encode cmd.String(),
// cmd.Env or cmd.Args.
//
// The rules are for Unix only. Windows is a non-goal (PRD section 2.2).
//
// # Child lifecycle
//
// When Inspect returns, on success and on every error, the child process was
// stopped and reaped. A normal stop has these steps:
//
//  1. Close the stdin of the child.
//  2. If the child still runs after a short grace period, send SIGTERM.
//  3. If the child still runs after one more grace period, send SIGKILL.
//
// When ctx is canceled or its deadline passes, the process group of the
// child gets SIGKILL at once. After the stop, the process group gets SIGKILL
// once more, so processes that the child started and that stayed in its
// group stop too (for example node, started by npx). A process that left
// the group, or that the operating system cannot kill, is the exception.
//
// # Limits
//
// A hostile server can send a next cursor forever, many items, or very long
// pages, to make mcpmoat loop or use all its memory. So Inspect applies a
// page cap and an item cap to each list kind (tools, prompts or resources),
// and two byte limits per server that the three kinds share. The page cap
// bounds the requests and the item cap bounds the items. The byte budget
// bounds the converted text that mcpmoat keeps. The raw byte limit bounds
// the JSON size of the pages as the SDK decoded them, also the fields that
// mcpmoat drops (for example _meta or icons), which the SDK keeps in its
// list cache until the session closes. Inspect stops at the first page that
// goes over a limit, so the limits also bound the pages that the SDK decodes
// and caches. A server that goes over a limit, or sends a cursor that it
// sent before, gives [ErrTooManyItems].
//
// The byte limits count JSON bytes and converted text, not memory. Decoded
// data can need many times more memory than its JSON: a page of many small
// empty objects needs about 20 times its JSON size. So the memory that the
// limits allow is many times the limits.
//
// The residual: the SDK decodes each frame, which can be up to its line
// limit (mcp.DefaultMaxLineLength), before mcpmoat can count it. Decoded
// JSON can need many times its size in memory, so one hostile frame can
// still cost a few hundred MiB. To measure a page, mcpmoat also encodes it
// again for a short time. A firm bound on memory needs a custom transport
// that limits the frame size and the total bytes read from the stdout of
// the server (a follow-up).
//
// The client of Inspect refuses every request of the server except ping: it
// answers completion/complete, roots/list, sampling/createMessage,
// elicitation/create and any other method with "method not found", at once.
// So no request of the server makes the client send a request back. Only a
// short allowlist of notifications passes. The SDK still decodes the params
// of a server request before mcpmoat refuses it, and it must write each reply
// to the stdin of the server. A server that floods requests and stops reading
// its stdin blocks those writes, so only the ctx deadline bounds the
// goroutines and params that they hold (see issue #28).
//
// Inspect lists a kind only when the server advertises its capability in the
// handshake. The slice of a kind that the server does not advertise stays
// nil; the slice of an advertised kind is never nil, also when it is empty.
//
// # Known limits
//
//   - The SDK silently drops some invalid tools before mcpmoat sees them
//     (filterValidTools in the SDK: a nil tool, or a tool with invalid
//     x-mcp-header annotations). mcpmoat cannot read such a tool. But it
//     counts the tools in each page before the SDK filters them, so a drop
//     is not silent: Inspect returns an error that wraps [ErrProtocol] and
//     gives the number of dropped tools. The detection depends on where
//     the SDK filters; a test fails if a new SDK version changes that.
//   - A server can tell mcpmoat apart from the real client and show it a
//     clean list: the handshake sends the client name "mcpmoat", and a
//     server can leave out the tools capability for mcpmoat only. A nil
//     [Result.Tools] shows the second case. See issue #97.
//   - A server without an absolute Dir runs in an empty directory, not in
//     the directory where the client starts it (for Claude Code, the
//     project of a project server). A launcher that reads its working
//     directory can then start a different program: for example "npx foo"
//     in a project runs the local node_modules/.bin/foo, but in the empty
//     directory npx installs foo from the public registry and runs it,
//     without a prompt, because stdin is not a terminal. That can be a
//     package that the user never configured. See issue #104.
//   - Resource templates are not listed.
//   - HTTP and SSE servers give [ErrUnsupportedTransport] until issue #26.
//   - There is no per-server timeout yet (issue #28). Until then, callers
//     must give a ctx with a deadline.
//   - The SDK client decodes the tool schemas and encodes them again. So
//     [Tool.InputSchema] and [Tool.OutputSchema] have sorted keys and
//     numbers as float64. They are not the exact bytes that the server sent.
package inspect
