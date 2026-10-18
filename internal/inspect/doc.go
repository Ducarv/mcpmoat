// Package inspect connects to MCP servers over stdio or HTTP and lists their
// tools, prompts and resources. Protocol details stay behind an interface in
// this package so that MCP spec changes stay local.
//
// See docs/PRD.md, FR-04 to FR-06, NFR-04 and NFR-06.
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
// The text of a [ConnectError] can still hold text that the server controls,
// for example a status text or a JSON-RPC message. Callers must escape the
// text with internal/termsafe before they print it.
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
// # Network
//
// The package honours the proxy settings from the HTTP_PROXY, HTTPS_PROXY and
// NO_PROXY environment variables. It makes no other network access (NFR-01).
// TLS 1.2 or newer is required, and certificates are always verified. There is
// no option to skip the check.
//
// # Untrusted data
//
// Every string in a [Result] comes from the server, and a malicious server
// controls it. Never execute it, never put it in a command or a format
// string, and escape it with internal/termsafe before you print it.
package inspect
