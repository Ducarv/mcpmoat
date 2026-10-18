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
// # Reading configs
//
// [Discover] reads the config files of the three clients in this fixed order:
//
//  1. ~/.claude.json
//  2. <WorkDir>/.mcp.json
//  3. ~/.cursor/mcp.json
//  4. <WorkDir>/.cursor/mcp.json
//  5. ~/.codex/config.toml
//
// [Options] gives Home and WorkDir. The package never reads $HOME or the
// current directory by itself. An empty value skips the files that belong to
// it. If WorkDir and Home are the same directory, Discover reads the Cursor
// file once, as a global config. This check is lexical: Discover compares the
// cleaned paths as text. It does not detect a symlinked WorkDir, or a second
// name for the same directory (for example /var and /private/var on macOS, or
// a case-insensitive file system).
//
// [ReadClaudeCode], [ReadCursor] and [ReadCodex] read one file. Use them for
// a path that the user gives, for example with --config. They do not check
// that the file exists, because a missing file is not an error. A caller that
// needs the file must check it first.
//
// Each reader returns a [Result]. Servers come in a fixed order: file order,
// then ProjectPath, then Name.
//
// A problem in one file, or in one server entry, gives a [FileError]. It never
// hides the other servers. A FileError names the file, the position when it is
// known, the server name when it is known, and a fixed reason. It never holds
// a value from the config, and it never holds text from the JSON or TOML
// library, because that text can quote config bytes. Only an operating system
// error (for example a permission error) or the context error of a canceled
// read can be attached. An OS error holds an operation and an error number
// only.
//
// Claude Code and Cursor (JSON):
//
//   - The "type" field is stdio, http, streamable-http or sse. The value
//     streamable-http is the same as http. Any other value is an error.
//   - With no "type", a server with "command" is stdio. Else a server with
//     "url" is http. Else it is an error.
//   - If a server name appears twice in one "mcpServers" object, the last entry
//     wins. The clients do the same.
//   - For Claude Code, the projects key is read only from a global file
//     (~/.claude.json); a project .mcp.json cannot add servers for other paths.
//   - A JSON string with a lone UTF-16 surrogate escape (for example
//     "\ud800" with no low surrogate after it) in a server entry (the server
//     name and all keys and values of the entry) or in a project key is an
//     error ("invalid string"), and the file gives no servers. It has no
//     valid UTF-8 form, so two names could become one. The check covers the
//     server entries and the project keys only: a lone surrogate in another
//     part of the file, for example the chat history of ~/.claude.json, is
//     not an error.
//
// All readers:
//
//   - A field that does not belong to the transport is dropped. A stdio server
//     keeps command, args, env and, for Codex, cwd (as [Server.Dir]). A
//     remote server keeps url and headers.
//   - A file that is not a regular file (for example a directory or a pipe) is
//     rejected. The readers follow symlinks, so a project file can point to any
//     regular file that the user can read. An error never shows the content of
//     that file.
//   - A file larger than 32 MiB (~/.claude.json and the other global files),
//     4 MiB (project files: .mcp.json and .cursor/mcp.json) or 256 KiB (Codex
//     TOML) is rejected.
//   - A file with more than 10,000 entries in all (servers and projects
//     counted together) is rejected and gives no servers.
//   - Keys are matched exactly: "Command" is not "command". A key that
//     differs from a known key only by letter case is an error (the clients
//     match keys exactly). The reason is "ambiguous key".
//   - Codex TOML with nesting deeper than 16 levels, or a key path with more
//     than 16 dotted parts in all, is rejected. The path counts the parts of the
//     table header, of each open inline table key and of the key itself.
//
// Codex has more notes:
//
//   - The keys bearer_token_env_var, env_http_headers and env_vars hold the
//     names of environment variables. The reader does not map them yet. A
//     remote Codex server that uses only bearer_token_env_var is read without
//     its token.
//   - The home is always ~/.codex. The package never reads the environment, so
//     it does not read $CODEX_HOME. To read another Codex file, call
//     [ReadCodex] with an explicit path.
//
// # Tests
//
// Package [github.com/Ducarv/mcpmoat/internal/discover/discovertest] has
// canary values for fixtures and AssertNoLeak. Use them to check that test
// output contains no secret value.
package discover
