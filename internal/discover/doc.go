// Package discover finds MCP server configurations for supported clients
// (Claude Code, Cursor, Codex) and reads them into a common [Server] model.
//
// The package only reads config files. It never starts a server and never
// connects to one. Package internal/inspect does that later.
//
// See docs/PRD.md, FR-01 to FR-03.
//
// # Server model
//
// A [Server] is one server entry from one config file. Its values are kept
// exactly as written in the config; see [Server] for the details.
//
// # Secrets
//
// Config values often hold credentials, so the types of the [Server] fields
// mask them in all output: fmt (every verb, including %p, and also when the
// value is in an unexported field of another struct), log/slog and
// encoders.
//
//   - Env and header values are [Secret] values in a [SecretMap]. They print
//     as [Mask]. Show the env and header names with [SecretMap.Keys].
//   - The remote endpoint is a [URL]. It prints as [RedactURL] of the value,
//     which masks the userinfo, the query values, the fragment and the path
//     segments that look like credentials (by heuristic rules).
//   - The stdio arguments are [Args]. They print as [RedactArgs] of the
//     values. RedactArgs is an allowlist: it masks every argument whose
//     shape is not known to be safe.
//   - Command is a plain string and prints as written. A secret in Command
//     itself is not masked.
//
// Only [Secret.Reveal], [URL.Reveal] and [Args.Values] return the values as
// written. Call them only where the value is used:
//
//   - in internal/inspect, for the command line and the environment of a
//     child process, the server endpoint and HTTP request headers;
//   - in internal/rules, for config rules.
//
// Never pass their results to fmt, a logger, an error or an encoder.
//
// Masking does not make text safe to print. Every string field of a Server
// and every map key (env and header names) is untrusted text from a config
// file and can hold control, bidi and non-ASCII characters. The output of
// URL and Args is printable ASCII, but display code must still escape every
// field before it prints it to a terminal.
//
// Config readers must return errors that name the file and the position in
// it, and never a value from the config.
//
// # Tests
//
// Package [github.com/Ducarv/mcpmoat/internal/discover/discovertest] has
// canary values for fixtures and AssertNoLeak. Use them to check that test
// output contains no secret value.
package discover
