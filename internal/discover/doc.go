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
// [ReadConfig] is the entry point for a file that the user names, for example
// with --config. It detects the format with [DetectClient]:
//
//   - A file name that ends in .toml is Codex.
//   - A JSON file with a "projects" key is Claude Code.
//   - A JSON file with only an "mcpServers" key is Cursor when the file is in a
//     .cursor directory, and Claude Code otherwise.
//   - A JSON object with neither key is chosen by the file name: .claude.json
//     and .mcp.json are Claude Code, and mcp.json in a .cursor directory is
//     Cursor. Any other name is an unknown format.
//   - Anything else is an unknown format.
//
// Detection has known limits: see [DetectClient].
//
// ReadConfig then reads the file with ScopeGlobal. Unlike [Discover], it
// reports a missing file, with the reason "file not found".
//
// [ReadClaudeCode], [ReadCursor] and [ReadCodex] read one file in a known
// format. They do not check that the file exists, because a missing file is not
// an error for them.
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
//
// All readers:
//
//   - A field that does not belong to the transport is dropped. A stdio server
//     keeps command, args and env. A remote server keeps url and headers.
//   - A file that is not a regular file (for example a directory or a pipe) is
//     rejected. The readers follow symlinks, so a project file can point to any
//     regular file that the user can read. An error never shows the content of
//     that file.
//   - A file larger than 32 MiB (~/.claude.json and the other global files),
//     4 MiB (project files: .mcp.json and .cursor/mcp.json) or 256 KiB (Codex
//     TOML) is rejected.
//   - A file with more than 10,000 servers, or more than 10,000 projects, is
//     rejected.
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
