// Package inspect connects to MCP servers and lists their tools, prompts and
// resources. Protocol details stay behind the Inspector interface so that MCP
// spec changes stay local.
//
// # Running many servers
//
// Run inspects a list of servers through an Inspector. It uses a bounded pool
// of workers (Options.Concurrency, default 4). Each server has its own time
// limit (Options.Timeout, default 10s). The limit starts when the server
// starts, not while it waits in the queue.
//
// Run returns one Outcome per server, in a stable order: by client, source and
// name, then by more fields. Each Outcome has a Status of ok, timeout or
// failed. One broken, hung or panicking server does not stop the others.
//
// # The Inspector contract
//
// An Inspector must honour its context, must stop every child process it
// started, and must be safe for concurrent use. Run calls it from several
// goroutines at the same time.
//
// # Child processes
//
// ConfigureProcessGroup starts a stdio server in its own process group. When
// the timeout fires, the whole process tree is killed, not only the direct
// child. KillProcessGroup does the same kill on request. This works on Unix
// only (macOS and Linux). On other systems, only the direct child is killed.
//
// # Untrusted text
//
// The text of Outcome.Err can hold server output. Treat it as untrusted. Escape
// it with internal/termsafe before you print it.
//
// # Still to come
//
// The MCP connection over stdio and HTTP with the official Go SDK, the
// scrubbed environment for stdio servers, and result types that do not depend
// on the SDK.
//
// See docs/PRD.md, FR-04 to FR-06, NFR-03, NFR-04 and NFR-06.
package inspect
