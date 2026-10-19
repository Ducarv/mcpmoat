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
// its pipes, refuse untrusted servers and servers that are not enabled
// without an opt-in, and keep secrets out of its errors. [SDKInspector] is
// the implementation: it starts stdio servers itself and gives remote servers
// to [Remote]. Every error of it is a [ConnectError].
//
// Tests in other packages must not start real servers. They use
// [github.com/Ducarv/mcpmoat/internal/inspect/inspecttest.Fake], an
// Inspector that returns canned results. Only this package imports the MCP
// SDK; the depguard rule mcp-sdk-only-in-inspect in .golangci.yml enforces
// it (NFR-06).
//
// # Gates
//
// SDKInspector.Inspect checks two gates before it does anything else. When a
// gate fails, it starts nothing, sends nothing and returns a KindConfig error
// with a fixed reason. One function, checkGates in gate.go, checks them, in
// this order:
//
//  1. The state gate. A server whose State is not discover.StateEnabled is
//     refused unless SDKOptions.AllowDisabled is set. Such a server is
//     turned off in the client config (discover.StateDisabled), the user
//     did not approve it (discover.StateUnapproved), or only files from the
//     repository approve it (discover.StateProjectApproved). A cloned
//     repository can approve its own servers, so that approval does not
//     count. A State value that this package does not know is refused too,
//     as turned off (stateGate).
//  2. The untrusted gate. A server from an untrusted project file is refused
//     unless SDKOptions.AllowUntrusted is set. See the discover package doc,
//     Untrusted files.
//
// The two opt-ins are separate. A server that both gates refuse needs both.
// The caller must have the explicit opt-in of the user before it sets either
// one. Inspect passes both opt-ins on, and stdioCommand and [Remote] call
// checkGates again, so all three apply the same gates in the same order.
//
// # Placeholder expansion
//
// After the gates, Inspect replaces the ${...} placeholders of the server as
// the client does (discover.Expand): the Claude Code syntax, the Cursor
// syntax, and no expansion for Codex. It expands the command, the args, the
// URL and the values (not the names) of the env entries and the headers. The
// values come from the environment of mcpmoat (the environ hook, os.Environ
// by default), not from the scrubbed environment of the child. A placeholder
// that cannot be expanded refuses the server with KindConfig. The reason holds
// the field and the variable name only, never a value. It shows the name only
// when it is a plain variable name (ASCII letters, digits and "_", at most 64
// bytes), because the text inside ${...} of a secret value can be part of the
// secret. An expanded text over 64 KiB, or expanded texts of one server over
// 1 MiB together, also refuse the server with KindConfig.
//
// A server whose State is not discover.StateEnabled passes the gates only
// with AllowDisabled. The client does not run it, so it never gets the
// values of the user's environment there. Its placeholders read only the
// base variables of the child environment (HOME, PATH and the others of
// isBaseEnv). Any other variable counts as not set: a placeholder with a
// default gets the default, and one without a default refuses the server,
// with a reason that says why. So a config from a cloned repository cannot
// send a secret variable to a URL or a header that it chose.
//
// The expanded server stays inside Inspect. [Run] keeps the server as
// discovered in Outcome.Server, and the URL of a ConnectError is the
// redacted URL as discovered: Inspect also replaces the expanded URL with it
// in the reason and in the cause (see showDiscoveredURL). So no expanded
// value is shown in a URL.
//
// An expanded value can be a secret, and the server gets it and can echo it.
// So Inspect records each value that it looks up (lookupRecorder), and the
// scrub of error text removes every recorded value of at least
// minBareSecretLen (8) bytes. A shorter value is too likely to match
// ordinary words, so it is not removed: a server can echo it in its error
// text.
//
// The scrub covers error text only. The expanded values reach the server,
// and the text of a [Result] (the names and descriptions of tools, prompts
// and resources, and ServerName) is not scrubbed. So a server can echo a
// secret in its Result. When scan is wired to inspect (issues #28 and #29),
// the report and JSON writers must scrub the recorded values and the
// configured values from that text.
//
// # Starting stdio servers
//
// stdioCommand builds the [os/exec.Cmd] for a stdio server (NFR-04). It
// never uses a shell. The command and the args go to the child byte-for-byte
// as they are after the placeholder expansion, also argv[0]. Nothing expands
// globs, quotes or "~". The user-facing version of this section is
// docs/stdio-servers.md.
//
// The environment is built from scratch (buildEnv). The child gets a small
// allowlist from the mcpmoat environment, plus the variables that the server
// config declares. isBaseEnv holds the allowlist and the reason for each
// entry. Agent sockets, proxies, tokens, cloud keys and loader hooks are
// excluded on purpose. A user who needs one of them declares it in the env
// of the server config.
//
// A config env entry overrides an allowlist entry with the same name. A bad
// name or a NUL byte refuses the server. The error text is fixed and holds no
// name and no value. The Env of the Cmd is never nil, because a nil Env makes
// the child inherit the whole parent environment.
//
// The child also always gets npm_config_yes=false (noAutoInstallEnv). When
// stdin is not a terminal, npm exec and npx assume --yes, so "npx foo"
// installs foo from the public registry and runs it when foo is not
// installed. An attacker can publish a package with that name. With
// npm_config_yes=false, npx (npm 7 or later) stops with an error and installs
// nothing. The configured behaviour wins: a configured -y or --yes arg, or a
// config env entry named npm_config_yes in any letter case, still lets npx
// install, the same as in the client. Limits: pnpm dlx, bunx, uvx and the
// standalone npx from before npm 7 ignore this variable. The variable also
// reaches every npm process that the server starts itself, which is a small
// difference from the client.
//
// The work directory comes from projectRunDir:
//
//   - The config Dir (the Codex cwd), when it is absolute. mcpmoat uses that
//     Dir as written, so files in it can change what runs, the same as in
//     the client.
//   - Else the ProjectPath of a trusted project server (discover.ScopeProject,
//     not Untrusted), when it is absolute and an existing directory. The
//     client starts such a server in the project directory, so mcpmoat does
//     the same. The scan then runs code from the project tree, the same as
//     the client does. A server from an untrusted project file never gets
//     its project directory, because a cloned repository can ship that file.
//   - Else stdioOptions.FallbackDir: SDKInspector makes a new, empty
//     directory below <user cache dir>/mcpmoat/run (workDir) and removes it
//     after the stop. npm and uv read files from the work directory and from
//     all its parent directories, so the run root and every parent up to
//     "/" must be owned by the user or root and must not be writable by
//     others (defaultRunRoot, checkPrivateChain).
//
// A relative command with a "/" (such as "./server") needs one of the first
// two directories. Without one, mcpmoat does not guess a directory and
// refuses the server. A server that runs in the empty directory can act
// differently from the client, which can start it in another directory.
//
// On Unix the child starts in a new session; see detachSysProcAttr. The
// caller never connects the stdout or stderr of the child to the terminal
// of the user.
//
// A bare command name (no "/") is looked up in the final PATH of the child,
// so a PATH from the config wins. Node spawn and Rust Command do the same.
// lookPath lists the skip rules and the PATH risks.
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
// SDKInspector removes from the text of its errors the configured env values
// and the expanded variable values that have at least 8 bytes: the server
// gets them and can echo them.
//
// # Remote servers
//
// [Remote] connects to a remote server and lists its tools, prompts,
// resources and resource templates. It refuses a server from an untrusted
// project file unless the caller sets [RemoteOptions].AllowUntrusted, and a
// server that is not enabled unless the caller sets
// [RemoteOptions].AllowDisabled, both after the explicit opt-in of the user.
// Remote does not expand placeholders itself: SDKInspector gives it the
// expanded server. The config type of the server picks the transport: http
// is streamable HTTP, and sse is the legacy HTTP+SSE transport. mcpmoat does
// not probe the other transport. If a server answers with an error that may
// mean the wrong transport, the error text tells the user to change the type.
//
// # Lists
//
// SDKInspector (for a stdio server) and Remote read four lists with listInto:
// tools (tools/list), prompts (prompts/list), resources (resources/list) and
// resource templates (resources/templates/list). Each tool keeps its
// annotations (readOnlyHint, destructiveHint, idempotentHint, openWorldHint
// and the annotation title; see ToolAnnotations). The annotations are part of
// the pin hash and of the rule input (PRD FR-11), so a server that flips a
// hint changes the pin.
//
// mcpmoat always sends all four list requests, also for a capability that the
// server did not declare in the handshake (listAll). A hostile server can
// leave a capability out of the handshake and still answer the list request
// of a client that does not check it. When an undeclared list has at least
// one item, mcpmoat reports the items and listInto adds a Warning of kind
// [WarnUndeclaredCapability] to Result.Warnings. Its Capabilities field holds
// the fixed names of those lists ("tools", "prompts", "resources",
// "resource-templates"), never server text (undeclaredWarnings). An
// undeclared list that the server answers empty or refuses gets no warning:
// some servers, the SDK server for example, answer every list request.
//
// A list is nil when the server did not declare the capability and answered
// the first page with a JSON-RPC error. It is empty but not nil when the
// server sent an empty list (see Result). Any other error fails the
// inspection.
//
// A server that never answers a list request for a method that it does not
// know makes the call wait until ctx ends. Then the whole inspection of that
// server times out (StatusTimeout in Run), and mcpmoat returns no partial
// lists. This fails closed: a benign server with this bug shows as timed
// out.
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
// query value counts, even a short one. A Warning holds the header keys, a
// user info flag and a URL secrets flag (Warning.URLSecrets) only, never a
// value or a part of the URL. This is a warning only: Remote still connects,
// because a local or test server can use plain HTTP on purpose.
//
// This warning and the proxy warning (see Network) are the connection
// warnings of Remote. On success, Remote puts them first in Result.Warnings,
// before the warnings that listInto adds. When the inspection fails after
// the connect started, they go to ConnectError.Warnings, because the
// requests already went out before the failure.
//
// # Client identity
//
// The package does not tell the server that the client is mcpmoat. In the
// MCP initialize request, it sends the client name of the client that
// declared the server (clientIdentity): "claude-code" for Claude Code,
// "cursor-vscode" for Cursor, and "codex-mcp-client" (title "Codex") for
// Codex. For any other client, it sends the neutral name clientName. On the
// new protocol, the SDK also puts this clientInfo in the _meta of every
// request. A server that recognises the scanner could show it a clean tool
// list and show the real clients a poisoned one, and the pins would never
// see the difference.
//
// A server can still tell mcpmoat apart from the real client:
//
//   - The versions are fixed guesses. mcpmoat cannot know the installed
//     release, so a version can go stale, and a stale version is a sign
//     too.
//   - The client capabilities differ from the real client. Remote
//     advertises roots (the SDK default), and a stdio session advertises
//     none.
//   - The timing and the order of the requests: mcpmoat sends all the list
//     requests one after the other, right after the handshake.
//   - The HTTP User-Agent of a remote connection is the net/http one, not
//     the one of the real client.
//
// See docs/PRD.md, section 5.5.
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
// connects is used for all later connections to that host (pinnedDialer).
// Remote makes a new base transport, and so a new pinnedDialer, for each
// call (newBaseTransport), so the pin lasts for one inspection only. It
// changes only the IP address: TLS still verifies the certificate against
// the URL host.
//
// The pin alone does not stop a name that points to a local address from the
// first lookup on. So for the configured host name (the guarded host), the
// dialer drops these addresses from the DNS answer (refusedAddr):
//
//   - loopback (127.0.0.0/8, ::1);
//   - unspecified: all of 0.0.0.0/8, and ::;
//   - link-local unicast (169.254.0.0/16, fe80::/10), which holds the cloud
//     metadata address 169.254.169.254;
//   - multicast, with link-local and interface-local multicast;
//   - the Alibaba Cloud metadata address 100.100.100.200, which is not
//     link-local.
//
// An IPv4-mapped IPv6 address counts as its IPv4 address (usableAddrs). When
// the answer also holds other addresses, the dialer uses only those. When no
// address is left, it dials nothing and fails with errAddrRefused: KindNetwork,
// with a fixed text that holds no address and no host name. Private (RFC 1918)
// and unique local (ULA) addresses stay allowed, because company servers use
// them. The rest of 100.64.0.0/10 (shared address space, RFC 6598) also
// stays allowed, because Tailscale and other carrier-grade NAT networks use
// it for real servers. An IP literal in the URL is never resolved, so it is not checked: it
// is the choice of the user. The name "localhost", in any letter case, is not
// guarded: it always dials loopback addresses only. Other host names, such as
// the proxy host, are not guarded.
//
// The guard compares the host name in ASCII lower case, as http.Transport
// dials it. A host that is not ASCII (an IDN) would be dialled in its
// punycode form and miss the guard. So the guard relies on Remote, which
// refuses a URL whose host is not ASCII.
//
// With HTTP_PROXY or HTTPS_PROXY, the transport dials the proxy, so the pin
// holds the address of the proxy, and the proxy resolves the server name
// itself. The pin and the guard do not apply to that lookup. Then Remote adds
// one Warning of kind [WarnDNSPinUnavailable] for the inspection
// (dnsPinWarning), when the host is a DNS name. The warning holds no URL,
// because the proxy URL can hold a user name and a password.
//
// Each MCP call has its own record of its HTTP requests: the last status and
// the first error that the package raised on purpose, such as a refused
// redirect or a refused DNS answer (requestRecorder, callRecords). The label
// of an error comes from the record of the call that failed. So a request
// that runs at the same time cannot give a wrong label to the error of
// another call. The requests that belong to no call, such as the legacy SSE
// GET stream, use a fallback record (see httpEvents).
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
//   - The CLI does not show warnings (Result.Warnings and
//     ConnectError.Warnings) yet, and no CLI flag sets AllowUntrusted or
//     AllowDisabled yet, because mcpmoat scan does not connect to servers
//     yet.
//   - The tool schemas are decoded and encoded again (see Tool.InputSchema).
//   - A server can still tell mcpmoat apart from a real client by the
//     version, the capabilities, the timing and the User-Agent (see Client
//     identity).
//   - A server that never answers a list request that it does not support
//     makes the inspection time out (see Lists).
//   - An expanded variable value shorter than 8 bytes is not removed from
//     error text (see Placeholder expansion).
//   - The text of a Result is not scrubbed, so a server can echo an
//     expanded secret in it (see Placeholder expansion).
//   - npm_config_yes=false does not stop pnpm dlx, bunx, uvx or the
//     standalone npx from before npm 7 from installing a missing package
//     (see Starting stdio servers).
//   - The DNS pin and the address guard do not cover a request through an
//     HTTP(S) proxy; Remote warns instead (see Network).
//   - The address guard does not refuse an IPv4 address that is embedded in
//     another IPv6 form (NAT64, 6to4 or IPv4-compatible), or the IPv4
//     broadcast address. It refuses an mDNS name (".local") that resolves to
//     a link-local address, also when the user wants it. The IPv6 address of
//     the AWS metadata service is in the ULA range, so it is allowed. Of
//     100.64.0.0/10, only 100.100.100.200 (Alibaba Cloud metadata) is
//     refused. The rest stays allowed because Tailscale uses it, so a
//     metadata service of another provider in that range is not refused.
//   - A stdio server that floods requests during the handshake and does not
//     read its stdin is bounded only by ctx: the SDK closes the session
//     inside Client.Connect, before SDKInspector can stop the child.
//   - A work directory that a process outside the group still uses stays
//     behind below the run root.
//
// See docs/PRD.md, FR-03 to FR-06, FR-11, NFR-01, NFR-03, NFR-04, NFR-06 and
// sections 5.5 and 5.6.
package inspect
