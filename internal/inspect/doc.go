// Package inspect connects to MCP servers and lists their tools, prompts,
// resources and resource templates. Protocol details stay behind the
// Inspector interface so that MCP spec changes stay local.
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
// of its errors. [SDKInspector] is the implementation: it starts stdio
// servers itself and gives remote servers to [Remote]. Every error of it is a
// [ConnectError].
//
// Tests in other packages must not start real servers. They use
// [github.com/Ducarv/mcpmoat/internal/inspect/inspecttest.Fake], an
// Inspector that returns canned results. Only this package imports the MCP
// SDK; the depguard rule mcp-sdk-only-in-inspect in .golangci.yml enforces
// it (NFR-06).
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
// same as in the client. Else the work directory is stdioOptions.FallbackDir:
// SDKInspector makes a new, empty directory below <user cache
// dir>/mcpmoat/run (workDir) and removes it after the stop. npm and uv read
// files from the work directory and from all its parent directories, so the
// run root and every parent up to "/" must be owned by the user or root and
// must not be writable by others (defaultRunRoot, checkPrivateChain). A
// relative command with a "/" (such as "./server") needs an absolute config
// Dir. This is a fidelity limit: a client can start a project server in the
// project root, and mcpmoat does not. In the empty directory, "npx foo"
// installs foo from the public registry and runs it without a prompt, where
// the client would run the local node_modules/.bin/foo; issue #104 tracks
// this.
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
// opt-in (SDKOptions.AllowUntrusted, passed on to
// stdioOptions.AllowUntrusted). See the discover package doc, Untrusted
// files.
//
// The returned Cmd holds revealed secrets. Never print, log or encode
// cmd.String(), cmd.Env or cmd.Args.
//
// The rules are for Unix only. Windows is a non-goal (PRD section 2.2).
//
// # Child processes
//
// stdioProcess runs the Cmd of stdioCommand with its own stdin and stdout
// pipes, and gives them to the SDK as an IOTransport. It does not use the
// SDK CommandTransport, because that transport calls cmd.Wait itself. With
// the Setsid of stdioCommand, the child leads its own process group.
//
// The stop (stdioProcess.stop) closes the stdin of the server, waits up to
// stopGrace for the server to exit, kills the process group with
// killProcessGroup before cmd.Wait, as the Inspector contract asks, closes
// the read end of stdout and then calls Wait. stdioCommand returns a Cmd
// made with exec.Command, so stdioProcess does not use configureProcessGroup
// (exec refuses a Cancel on a Cmd without a context). Instead, when ctx
// ends, it kills the process group and closes both pipes at once.
// SDKInspector stops the child before it closes the MCP session, because the
// close of the session waits for replies that a server can block by not
// reading its stdin.
//
// A process that leaves the group on purpose (with setsid, setpgid or a
// double fork) is not killed, so this is not a sandbox. The group kill works
// on Unix only (macOS and Linux). On other systems, only the direct child is
// killed.
//
// # Stdio sessions
//
// The client of a stdio session offers no capabilities and refuses every
// request of the server except ping (refuseServerRequests). So no request of
// the server makes the client send a request back. The SDK still decodes the
// params of a request before mcpmoat refuses it, and it must write each reply
// to the stdin of the server. A server that floods requests and stops
// reading its stdin blocks those writes until the stop or ctx ends.
//
// The handshake result and all list pages of one stdio session share a raw
// size limit of 8 MiB, as JSON (rawLimit, maxRawBytes). The same value bounds
// one frame of the transport. A server that goes over it gives KindTooLarge.
//
// The SDK reads the stdout of the server through a shapeReader, so each
// frame (one top-level JSON value) also gets the JSON shape limits of
// jsonshape.go (see Limits) before the SDK decodes it. A frame over a shape
// limit gives KindTooLarge too.
//
// SDKInspector removes the configured env values of at least 8 bytes from
// the text of its errors: the server gets them and can echo them.
//
// # Remote servers
//
// [Remote] connects to a remote server and lists its tools, prompts,
// resources and resource templates. It refuses a server from an untrusted
// project file unless the caller sets [RemoteOptions].AllowUntrusted after
// the explicit opt-in of the user. The config type of the server picks the
// transport: http is streamable HTTP, and sse is the legacy HTTP+SSE
// transport. mcpmoat does not probe the other transport. If a server answers
// with an error that may mean the wrong transport, the error text tells the
// user to change the type.
//
// # Lists
//
// Both inspectors read four lists with listInto: tools (tools/list), prompts
// (prompts/list), resources (resources/list) and resource templates
// (resources/templates/list). Each tool keeps its annotations
// (readOnlyHint, destructiveHint, idempotentHint, openWorldHint and the
// annotation title; see ToolAnnotations). The annotations are part of the
// pin hash and of the rule input (PRD FR-11), so a server that flips a hint
// changes the pin.
//
// A list is nil when the server did not declare the capability and answered
// the first page with a JSON-RPC error. It is empty but not nil when the
// server sent an empty list (see Result). Any other error fails the
// inspection.
//
// Resource templates follow the resources capability, with one more case.
// The spec makes resources/templates/list optional, so a server that
// declares resources and answers the first page with JSON-RPC "method not
// found" (-32601) gives an empty template list, not an error. This is true
// only for a plain JSON-RPC error. Over streamable HTTP with protocol
// 2026-07-28, a server can send "method not found" with HTTP status 404.
// The SDK turns every non-2xx answer into its own rejection error (-32005),
// so such an answer fails the inspection. Failing closed is the safe choice
// when the answer is not a plain JSON-RPC error (see tolerateUndeclared and
// isMethodNotFound).
//
// # Secrets
//
// The header values and the secrets in the URL (the userinfo, the query and
// the secret path segments) go only to the configured origin. They never
// appear in an error. The package removes them from the error text before it
// builds a [ConnectError]. The package never gives the userinfo of the URL to
// the SDK. It sends the userinfo as a Basic Authorization header, unless the
// config sets an Authorization header.
//
// The text of a [ConnectError] can still hold text that the server controls
// (see "Untrusted data" below).
//
// Plain http:// has no encryption, so anyone on the network path can read
// the secrets. When Remote sends config headers, URL user info or secrets in
// the URL query or path over http:// to a host that is not loopback, it adds
// a Warning of kind [WarnCleartextSecrets] (cleartextWarnings). The URL
// secrets are the query and path parts that the redacted URL masks; every
// query value counts, even a short one. The warning goes to Result.Warnings
// on success, and to ConnectError.Warnings when the inspection fails after
// the connect started, because the secrets went out before the failure. A
// Warning holds the header keys, a user info flag and a URL secrets flag
// (Warning.URLSecrets) only, never a value or a part of the URL. This is a
// warning only: Remote still connects, because a local or test server can
// use plain HTTP on purpose.
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
//   - For a stdio server, the handshake and all lists share a raw size limit
//     (8 MiB of JSON), which also bounds one frame (see Stdio sessions).
//   - Each JSON message from a server has shape limits (jsonLimits in
//     jsonshape.go): at most 64 levels of nesting, at most 100,000 values,
//     and at most 1 MiB for one string or one run of number or literal
//     bytes. The limits apply to the HTTP bodies that the SDK decodes and
//     to each stdio frame. A message over a limit fails with KindTooLarge.
//   - The SDK silently drops tools that have an invalid x-mcp-header
//     annotation. The package records the tools list as the server sent it and
//     reports every tool, because a scanner must see what the server sent.
//
// A cap breach is an error. The package never cuts a list and returns the
// rest, because the cut part could hide a malicious tool.
//
// The size caps count bytes on the wire, and decoded JSON can take many times
// its wire size (a schema of millions of empty objects, for example). The
// shape limits bound the decoded size of one message. The check counts the
// bytes as they arrive, before the SDK decodes them, and keeps only counters,
// so its memory does not grow with the input.
//
// For HTTP, shapeFor picks the check as the SDK picks its parser. A 2xx body
// is one JSON message when its media type is application/json, and an SSE
// stream when it is text/event-stream. A 2xx body of any other type gets no
// check, because the SDK refuses it without reading it. The 2xx response to
// a GET is always an SSE stream. The method is the method of the first
// request in the redirect chain, so a 303 redirect that turns a POST into a
// GET does not escape the JSON check.
//
// A body with a non-2xx status gets the JSON check (one JSON-RPC message),
// whatever its Content-Type and the request method, GET included. The MCP
// SDK v1.8.0 reads such a body and decodes it as a JSON-RPC error. Some
// bodies get no check, because the SDK never reads them:
//
//   - a body with status 429, 500, 502, 503 or 504: the SDK treats these
//     statuses as temporary failures and returns before it reads the body;
//   - the response to a DELETE (the method of the first request in the
//     redirect chain);
//   - a redirect that the HTTP client follows.
//
// # Network
//
// The package honours the proxy settings from the HTTP_PROXY, HTTPS_PROXY and
// NO_PROXY environment variables. It makes no other network access (NFR-01).
// Some clients ignore these variables, so a scan can take another route than
// the client does. Over an http:// URL, the proxy then sees the configured
// headers.
//
// A hostile server controls the DNS answers for its own name. It can answer a
// later lookup with 127.0.0.1 or an internal address (DNS rebinding), and a
// later request would then take the config headers to a local service. So
// each inspection pins one IP address per host name: the first address that
// connects is used for all later connections to that host (pinnedDialer,
// newBaseTransport). The pin lasts for one inspection only. It changes only
// the IP address: TLS still verifies the certificate against the URL host.
//
// Each MCP call has its own record of its HTTP requests: the last status and
// the first error that the package raised on purpose, such as a refused
// redirect (requestRecorder, callRecords). The label of an error comes from
// the record of the call that failed. So a request that runs at the same time
// cannot give a wrong label to the error of another call. The requests that
// belong to no call, such as the legacy SSE GET stream, use a fallback record
// (see httpEvents).
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
// # Known limits
//
//   - The MCP SDK v1.8.0 decodes readOnlyHint and idempotentHint as plain
//     bool. For these two hints, an absent hint and false look the same, so
//     ToolAnnotations has nil for both. False is the spec default, so a flip
//     to true is always visible.
//   - The DNS pin does not cover a request through an HTTP(S) proxy. The
//     package dials the proxy, so it pins the address of the proxy, and the
//     proxy resolves the server name itself.
//   - The CLI does not show warnings (Result.Warnings and
//     ConnectError.Warnings) yet, because mcpmoat scan does not connect to
//     servers yet.
//   - The tool schemas are decoded and encoded again (see Tool.InputSchema).
//   - A server can still tell mcpmoat apart from a real client in other ways
//     than the name; see Client identity and issue #97.
//   - A stdio server that floods requests during the handshake and does not
//     read its stdin is bounded only by ctx: the SDK closes the session
//     inside Client.Connect, before SDKInspector can stop the child.
//   - A work directory that a process outside the group still uses stays
//     behind below the run root.
//
// See docs/PRD.md, FR-04 to FR-06, FR-11, NFR-01, NFR-03, NFR-04 and NFR-06.
package inspect
