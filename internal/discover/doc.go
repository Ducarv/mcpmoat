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
// Env and header values are [Secret] values in a [SecretMap], and the
// remote endpoint is a [URL]. Printing, logging or encoding a Secret gives
// [Mask]; for a URL it gives [RedactURL] of the value, the display form.
// Show the env and header names with [SecretMap.Keys].
//
// Only [Secret.Reveal] and [URL.Reveal] return the values. Call them only
// where the value is used:
//
//   - in internal/inspect, for the environment of a child process, the
//     server endpoint and HTTP request headers;
//   - in internal/rules, for config rules.
//
// Never pass the result of Reveal to fmt, a logger, an error or an encoder.
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
