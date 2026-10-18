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
// # Child processes
//
// configureProcessGroup starts a stdio server in its own process group, and
// killProcessGroup kills every process that is still in that group. They are
// for the stdio Inspector of issue #25; today only the tests call them. A process that
// leaves the group on purpose (with setsid, setpgid or a double fork) is not
// killed, so this is not a sandbox. The group kill works on Unix only (macOS
// and Linux). On other systems, only the direct child is killed.
//
// The text of Outcome.Err is untrusted (see Outcome).
//
// See docs/PRD.md, FR-04 to FR-06, NFR-03, NFR-04 and NFR-06.
package inspect
