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
//   - in internal/rules, for config rules;
//   - in internal/report, Args.Values only as the input of [RedactArgs], to
//     show the command and the args through the allowlist as one command
//     line.
//
// Never pass their results to fmt, a logger, an error or an encoder.
//
// Masking does not make text safe to print. Every string field of a Server
// and every map key (env and header names) is untrusted text from a config
// file and can hold control, bidi and non-ASCII characters. The output of
// URL and Args is printable ASCII, but display code must still escape every
// field before it prints it to a terminal. Use internal/termsafe for that:
// FileError.Error and internal/report both do.
//
// Config readers must return errors that name the file and the position when
// it is known, and never a value from the config.
//
// # Reading configs
//
// [Discover] reads the config files of the three clients in a fixed order,
// below the Home and WorkDir directories that [Options] gives. See [Discover]
// for the files, their order and the case where WorkDir is Home.
//
// [ReadConfig] is the entry point for a file that the user names, for example
// with --config. A file that the user names can come from anywhere, for
// example from a cloned repository. So ReadConfig reads it as an untrusted
// project file: the read is confined to the directory of the file (see
// Symlinks), every server has ScopeProject and every server and error is
// Untrusted (see Untrusted files), the "projects" section of a Claude Code
// file is not read (a section that is there gives the error "projects
// section not read"), and the size limit is maxProjectConfigSize (4 MiB), or
// maxTOMLSize (256 KiB) for Codex. The file is read once, and the reader
// parses the bytes of that read. Unlike [Discover], ReadConfig reports a
// missing file, with the reason "file not found".
//
// The one exception is a path that names one of the user's own global files
// (~/.claude.json, ~/.cursor/mcp.json or ~/.codex/config.toml below the home
// directory that the caller gives): the same file by [os.SameFile].
// ReadConfig then reads the global path as a global file, with the reader
// that Discover uses for it. See [ReadConfig] for what "names" means.
//
// For any other file, ReadConfig detects the format with [DetectClient]:
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
// Then ReadConfig parses a JSON file as [ReadClaudeCode] or [ReadCursor] do
// with ScopeProject and an empty projectPath, and a Codex file with the
// Codex reader, through internal entries that take the bytes that ReadConfig
// read. [ReadCodex] always reads a file as a global file and has no untrusted
// mode, so ReadConfig does not use it for a Codex file that is not
// ~/.codex/config.toml. Its internal Codex entry gives the servers
// ScopeProject and marks every server and error Untrusted.
//
// [ReadClaudeCode], [ReadCursor] and [ReadCodex] read one file in a known
// format. They do not check that the file exists, because a missing file is
// not an error for them. A caller that needs the file must check it first.
//
// Each reader returns a [Result]. The servers of one file come in a fixed
// order: by ProjectPath, then by Name. The errors of one file come in a fixed
// order too: errors about the whole file (no server name) first, then by
// server name. Errors with the same server name keep the order in which the reader
// found them: in ~/.claude.json, the top level first, then the projects
// sorted by path.
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
// Every FileError means that servers which the client can load may be missing
// from the result: a refused file, project or server entry gives no servers.
// So a caller must not treat a FileError as a harmless warning, also for a
// global file. The scan command fails with exit code 2 when a reader returns
// a FileError. A missing file is not an error and gives no FileError.
//
// Claude Code and Cursor (JSON):
//
//   - The "type" field is stdio, http, streamable-http or sse. The value
//     streamable-http is the same as http. Any other value is an error.
//   - With no "type", a server with "command" is stdio. Else, for Cursor
//     only, a server with "url" is http. Claude Code treats an entry with no
//     "type" as stdio, so it refuses a url without "type" ("invalid server
//     entry"). Any other entry is an error.
//   - If a server name appears twice in one "mcpServers" object, the last entry
//     wins. The clients do the same.
//   - For Claude Code, the projects key is read only from a global file
//     (~/.claude.json); a project .mcp.json cannot add servers for other paths.
//   - A JSON string with a lone UTF-16 surrogate escape (for example
//     "\ud800" with no low surrogate after it) or a byte that is not valid
//     UTF-8, in a server entry (the server name and all keys and values of
//     the entry) or in a project key, is an error ("invalid string"), and
//     the file gives no servers. Go replaces each bad part with U+FFFD, so
//     two different names could become one. The check covers the server
//     entries and the project keys only: a bad string in another part of the
//     file, for example the chat history of ~/.claude.json, is not an error.
//   - A JSON null in a server entry is an error ("invalid server entry"):
//     as the value of type, command, url, args, env or headers, as an
//     element of args, or as a value in env or headers.
//   - A null server entry ("srv": null) is an error ("invalid server
//     entry"), as a null in a server entry is.
//   - An empty key under "projects" in ~/.claude.json is an error ("empty
//     project path"): it names no directory. That project gives no servers,
//     and the other projects are still read.
//   - A file that holds only JSON whitespace (space, tab, CR and LF) gives no
//     servers and no error. A file that holds only null is an error
//     ("unexpected structure").
//
// All readers:
//
//   - A stdio server keeps command, args, env and, for Codex, cwd (as
//     [Server.Dir], which tells how to treat a relative cwd). A remote server keeps url and headers. The JSON readers
//     drop a field that does not belong to the transport; the Codex reader
//     refuses it (see below).
//   - A file that is not a regular file (for example a directory or a pipe) is
//     rejected. The readers open the file first and then check its type, so
//     a pipe cannot block the read.
//   - A file larger than its size limit is rejected. The limits are
//     maxConfigSize (32 MiB) for ~/.claude.json and the other global files,
//     maxProjectConfigSize (4 MiB) for the project files (.mcp.json and
//     .cursor/mcp.json) and maxTOMLSize (256 KiB) for the Codex file.
//   - A file with more than maxServersPerFile (10,000) entries in all (servers
//     and projects counted together) is rejected ("too many servers") and
//     gives no servers. The cap bounds the result, not the decode: the
//     readers decode the whole map of entries before they count them, and
//     the size limits above bound that memory.
//   - Keys are matched exactly: "Command" is not "command". A key that
//     differs from a known key only by letter case is an error (the clients
//     match keys exactly). The reason is "ambiguous key".
//   - Codex TOML with nesting deeper than maxTOMLDepth (16) levels is
//     rejected ("nesting is too deep"). A key path with more than
//     maxTOMLKeyParts (16) dotted parts in all is rejected ("key path is too
//     long"). The path counts the parts of the table header, of each open
//     inline table key and of the key itself.
//
// Codex has more notes:
//
//   - An entry that mixes the keys of the two transports is an error
//     ("invalid server entry"), as in Codex: a stdio entry (with command)
//     with url, http_headers, env_http_headers or bearer_token_env_var, or a
//     remote entry (with url) with args, env, env_vars or cwd. Only the
//     presence of the key counts, so an empty value is an error too.
//   - The keys bearer_token_env_var, env_http_headers and env_vars hold the
//     names of environment variables. The reader does not map them yet. A
//     remote Codex server that uses only bearer_token_env_var is read without
//     its token.
//   - The home is always ~/.codex. The package never reads the environment, so
//     it does not read $CODEX_HOME. To read another Codex file, call
//     [ReadCodex] with an explicit path.
//
// For the same reason, the package does not read $CLAUDE_CONFIG_DIR: the
// Claude Code file is always Home/.claude.json. To read another Claude Code
// file, call [ReadClaudeCode] with an explicit path. When the user sets
// $CODEX_HOME or $CLAUDE_CONFIG_DIR, the client reads another file than
// Discover, so a scan can miss servers.
//
// # Symlinks
//
// For a global file, the readers follow symlinks, so the file can point to
// any regular file that the user can read. An error never shows the content
// of that file.
//
// [ReadConfig] confines a file that the user names as a project file, with
// the directory of the file as the project directory, unless the file is one
// of the user's own global files.
//
// A project file comes from a cloned repository, so the readers open it
// inside its project directory (with [os.Root]). For [Discover], the project
// directory is WorkDir. For [ReadClaudeCode] and [ReadCursor] with
// ScopeProject, it is projectPath, or the directory of the file when
// projectPath is empty. In that last case the servers can get another
// ProjectPath than the directory of the read: ReadCursor gives the servers of
// <project>/.cursor/mcp.json the ProjectPath <project>, but the read stays in
// .cursor. A symlink that stays inside the project directory is
// followed. A symlink that leads out of it, every absolute symlink, and a
// path that is not below it are refused with the reason "file is outside the
// project". Without this rule, a repository could make mcpmoat read a file
// of the user, for example ~/.claude.json, as its own project file.
//
// # Untrusted files
//
// A project file (<WorkDir>/.mcp.json, <WorkDir>/.cursor/mcp.json, a file
// read with [ReadClaudeCode] or [ReadCursor] and ScopeProject, or a file
// given to [ReadConfig] that is not one of the user's own global files) is
// untrusted: a cloned repository can ship it. Its servers and errors are
// marked:
//
//   - Every [Server] from such a file has [Server.Untrusted] set. Its command
//     and its URL are not the user's choice, so package internal/inspect must
//     not start or connect to an untrusted server, stdio or remote, without
//     an explicit opt-in from the user. A start runs code from the
//     repository. A connection is a network request to a host that the
//     repository picks: it can reach a loopback, link-local or intranet
//     address, or tell the author that the user scanned the repository (a
//     beacon).
//   - Every [FileError] about such a file has [FileError.Untrusted] set, a
//     read error too. An unreadable or refused project file can hide servers
//     that the client still loads. As for every FileError (see Reading
//     configs), a caller must not treat the error as a harmless warning, and
//     the scan command exits with code 2. The mark tells where the problem
//     is: in a file that a repository can ship, not a file of the user.
//
// The JSON readers set Untrusted by scope: with ScopeProject they mark every
// server and every error of the file. Discover sets it on the canceled error
// that it adds when ctx ends before a project file is read. ReadConfig sets
// it on its own errors ("file not found", "unknown config format" and the
// errors of its read) and, through its internal Codex entry, on the servers
// and errors of a Codex file. Its JSON files are parsed with ScopeProject,
// so the JSON rule marks them, the "projects section not read" error too.
//
// The user's own files are trusted: ~/.claude.json (also the servers under
// its projects.<path> keys, which Claude Code writes when the user adds a
// server), ~/.cursor/mcp.json and the Codex file.
//
// # Tests
//
// Package [github.com/Ducarv/mcpmoat/internal/discover/discovertest] has
// canary values for fixtures and AssertNoLeak. Use them to check that test
// output contains no secret value.
package discover
