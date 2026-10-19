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
// exactly as written in the config; see [Server] for the details. This
// includes ${...} placeholders: the readers never expand them (see
// Placeholders). [Server.State] tells whether the client turns the server
// on or off (see Server state).
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
// project file: the file itself is confined to its directory (see
// Symlinks), every server has ScopeProject and every server and error is
// Untrusted (see Untrusted files), the "projects" section of a JSON file is
// not read (a section that is there gives an error), and the size limit is
// maxProjectConfigSize (4 MiB), or maxTOMLSize (256 KiB) for Codex. The file
// is read once, and the reader parses the bytes of that read. Unlike
// [Discover], ReadConfig reports a missing file, with the reason "file not
// found". [ReadConfig] holds the full rules.
//
// The one exception is a path that names one of the user's own global files
// (~/.claude.json, ~/.cursor/mcp.json or ~/.codex/config.toml below the home
// directory that the caller gives): the same file by [os.SameFile].
// ReadConfig then reads the global path as a global file, with the reader
// that Discover uses for it. See [ReadConfig] for what "names" means. One
// difference: ReadConfig knows no WorkDir, so a top-level server of
// ~/.claude.json can have another State than in Discover (see Server state).
//
// For any other file, ReadConfig detects the format with [DetectClient],
// which gives the rules and their known limits. A file with no servers is
// accepted only under its known client name, for JSON and for TOML: a .toml
// file with no mcp_servers key, such as pyproject.toml, is an unknown format
// unless it is .codex/config.toml.
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
// server name. Errors with the same server name keep the order in which the
// reader found them: in ~/.claude.json, the top level first, then the
// projects sorted by path.
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
//     [Server.Dir], which tells how to treat a relative cwd). A remote
//     server keeps url and headers. The JSON readers drop a field that does
//     not belong to the transport; the Codex reader refuses it (see below).
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
// of the user's own global files. Only the file itself is confined: a
// symlink in a directory of the path that the user names is followed. See
// [ReadConfig].
//
// A project file comes from a cloned repository, so the readers open it
// inside its project directory (with [os.Root]). For [Discover], the project
// directory is WorkDir. For [ReadClaudeCode] and [ReadCursor] with
// ScopeProject, it is projectPath, or the directory of the file when
// projectPath is empty. In that last case the servers can get another
// ProjectPath than the directory of the read: ReadCursor gives the servers of
// <project>/.cursor/mcp.json the ProjectPath <project>, but the read stays in
// .cursor. A symlink that stays inside the project directory is
// followed. A symlink that leads out of it, every absolute symlink below it,
// and a path that is not below it are refused with the reason "file is
// outside the project". Without this rule, a repository could make mcpmoat
// read a file of the user, for example ~/.claude.json, as its own project
// file. The project directory itself is opened as the caller gives it, so a
// symlink in its own path is followed.
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
// An untrusted file must not choose a working directory outside its project,
// because inspect would start the server there. So ReadConfig drops, with an
// error, a server of an untrusted Codex file whose cwd fails its cwd check.
// The check sees the tree at read time only, so inspect must still not trust
// Dir blindly. See [ReadConfig] for the rules and their limits.
//
// The user's own files are trusted: ~/.claude.json (also the servers under
// its projects.<path> keys, which Claude Code writes when the user adds a
// server), ~/.cursor/mcp.json and the Codex file.
//
// # Server state
//
// [Server.State] tells whether the client config turns a server on or off.
// It has four values:
//
//   - [StateEnabled]: no config that mcpmoat reads turns the server off.
//   - [StateDisabled]: a client config turns the server off.
//   - [StateUnapproved]: the server comes from a Claude Code project
//     .mcp.json, and the user did not approve it. A top-level server of
//     ~/.claude.json also gets it when Discover cannot read the
//     projects.<WorkDir> state (see the rules below).
//   - [StateProjectApproved]: the server comes from a Claude Code project
//     .mcp.json, and Claude Code would run it, but only files from the
//     repository approved it. inspect treats it as StateUnapproved.
//
// The zero value is StateEnabled. This fails open: a reader that does not
// set State, and a client setting that mcpmoat does not read, give
// StateEnabled.
//
// State and Untrusted are separate. State is the on and off switch, or the
// approval, of the client. Untrusted tells where the config came from (see
// Untrusted files). A server can be untrusted and enabled, or trusted and
// disabled. Package internal/inspect must not start or connect to a server
// whose State is not StateEnabled (StateProjectApproved too) without an
// explicit opt-in. That opt-in is separate from the opt-in for untrusted
// servers, so a server that is both disabled and untrusted needs both.
//
// Codex: the enabled key of the server table. enabled = false gives
// StateDisabled. No key, or enabled = true, gives StateEnabled. A value that
// is not a TOML boolean (for example the string "false") makes the entry
// bad: a FileError with the reason "invalid server entry", and the server is
// dropped.
//
// Claude Code uses four exact keys:
//
//   - enabledMcpjsonServers: the names of the .mcp.json servers that the
//     user approved.
//   - disabledMcpjsonServers: the names of the .mcp.json servers that the
//     user rejected.
//   - disabledMcpServers: the names of the servers, of any scope, that the
//     user turned off for one project.
//   - enableAllProjectMcpServers: true approves all .mcp.json servers.
//
// The three lists are arrays of strings, and enableAllProjectMcpServers is a
// boolean. An absent key or a null value gives no setting. A key with the
// wrong type gives a FileError with the reason "invalid enabled or approval
// setting", and a name with a bad string gives "invalid string". The error
// holds no value. A key in another letter case is ignored, as in Claude
// Code.
//
// The keys can be in three kinds of places:
//
//   - the projects.<path> objects of ~/.claude.json (the legacy place,
//     trusted);
//   - Home/.claude/settings.json (the user file, trusted, size limit
//     maxConfigSize);
//   - WorkDir/.claude/settings.json and WorkDir/.claude/settings.local.json
//     (project files, untrusted: they are read inside WorkDir as other
//     project files are, see Symlinks, with the size limit
//     maxProjectConfigSize, and their errors have Untrusted set).
//
// The rules:
//
//   - A server of projects.<path>.mcpServers whose name is in
//     projects.<path>.disabledMcpServers gets StateDisabled. A bad state
//     key in projects.<path> gives a FileError with ProjectPath <path>, and
//     the servers of that project are dropped. This fails closed: a server
//     that the unreadable list can turn off never shows as StateEnabled.
//     The other projects are still read.
//   - In [Discover], the projects.<WorkDir>.disabledMcpServers list also
//     gives StateDisabled to the top-level servers of ~/.claude.json.
//     Discover looks up two keys for WorkDir: WorkDir as given, and WorkDir
//     with its symlinks resolved, because Claude Code writes the key with
//     the real path. The disabled lists of both keys apply. The approval
//     (enabledMcpjsonServers and enableAllProjectMcpServers) comes from one
//     key only: WorkDir as given if the file has it, else the resolved
//     WorkDir. A bad state under either key is a failure (see the next
//     rule). The joined disabled list, and the failure rule, apply also to
//     the servers of projects.<key>.mcpServers for both keys: the two keys
//     name the same directory.
//   - In Discover, this fails closed. When ~/.claude.json exists but its
//     projects section is not read to the end (a read error, a file refused
//     as a whole, also for a bad string in another project, a projects
//     value that is not an object, or a canceled read), or when a
//     projects.<WorkDir> object or its state has an error, a top-level
//     server, or a server of projects.<key>.mcpServers for a key of
//     WorkDir, with StateEnabled gets StateUnapproved. mcpmoat cannot confirm
//     that the lost disabledMcpServers list does not turn it off. A missing
//     file, and a file with no projects.<WorkDir> key, are not failures.
//   - In Discover, each .mcp.json server gets its State from the sources
//     below, in this order of precedence: settings.local.json, the project
//     settings.json, the user settings.json, then the projects.<WorkDir>
//     object of ~/.claude.json (legacy).
//
// For a .mcp.json server, the rule is:
//
//  1. A name in any disabledMcpjsonServers gives StateDisabled.
//  2. Else the server is approved when its name is in any
//     enabledMcpjsonServers, or when enableAllProjectMcpServers is true:
//     for this key the first source in the order above that has it decides,
//     and a later source cannot change it. The approval gives StateEnabled
//     when a trusted source (the user settings.json or the legacy
//     projects.<WorkDir> object) gives it. It gives StateProjectApproved
//     when only the untrusted project settings files give it. When the
//     first enableAllProjectMcpServers is true, a trusted source that also
//     has true gives the approval too.
//  3. Else the server gets StateUnapproved.
//  4. Last, a name in any disabledMcpServers gives StateDisabled, also when
//     step 2 approved the server.
//
// Steps 2 and 3 as a table, for a name that no disabled list holds.
// "Trusted list" and "untrusted list" are the enabledMcpjsonServers lists
// of the trusted and of the untrusted sources. "enableAll" is the first
// enableAllProjectMcpServers in the order above, and the kind of its source.
// "Trusted" also covers a first true from an untrusted source when a
// trusted source has true as well.
//
//	trusted list  untrusted list  enableAll          State
//	has name      any             any                StateEnabled
//	no name       any             true, trusted      StateEnabled
//	no name       any             true, untrusted    StateProjectApproved
//	no name       has name        absent or false    StateProjectApproved
//	no name       no name         absent or false    StateUnapproved
//
// Discover reads the settings files only when WorkDir/.mcp.json has
// servers. A missing settings file gives no setting. When Home and WorkDir
// are the same directory (the cleaned paths are equal as text),
// WorkDir/.claude/settings.json is the user file: Discover reads it once,
// as the trusted user file. It still reads
// WorkDir/.claude/settings.local.json as a project file.
//
// The approval fails closed. A source that failed loses its disabled lists,
// and another source could then approve a server that the lost list turns
// off. So when any settings file has a FileError, or when the
// projects.<WorkDir> state of ~/.claude.json could not be read (the same
// cases as for the top-level servers above), no .mcp.json server keeps an
// approval: a server with StateEnabled or StateProjectApproved gets
// StateUnapproved, and StateDisabled stays. A missing file is not a failure.
// The FileError tells the user why, and the scan fails.
//
// A cloned repository can ship a settings file that approves its own
// .mcp.json servers. So an approval in a project settings file is not a sign
// of trust: it gives only StateProjectApproved, which needs the same opt-in
// as StateUnapproved, and it never changes Untrusted. inspect still needs
// the untrusted opt-in for these servers too.
//
// Cursor keeps its on and off switch in its SQLite store. mcpmoat does not
// read that store, so every Cursor server has StateEnabled, also when the
// user turned it off in Cursor. This is a known limit.
//
// Other known limits:
//
//   - [ReadConfig] and a standalone [ReadClaudeCode] know no WorkDir and
//     read no settings file, so they have no approval data. The .mcp.json
//     servers get StateUnapproved (this fails closed: also a server that
//     the user approved or turned off), and no project state applies to the
//     top-level servers of ~/.claude.json. Only
//     projects.<path>.disabledMcpServers of a global ~/.claude.json applies,
//     to the servers of that same project. A file that turns a server off
//     itself (Codex enabled = false) still gives StateDisabled.
//   - The projects key of ~/.claude.json must match the cleaned WorkDir, as
//     given or with its symlinks resolved. Any other form of the same
//     directory does not match: for example another letter case on a
//     case-insensitive file system. Then no state of that project applies:
//     its disabled lists are lost (the top-level servers keep
//     StateEnabled), and its approvals are lost (the .mcp.json servers can
//     get StateUnapproved).
//   - A disabledMcpServers list in a settings file applies to the .mcp.json
//     servers only. It is not verified that Claude Code honours it there for
//     the servers of other scopes, so the top-level servers of
//     ~/.claude.json do not get StateDisabled from it.
//   - Managed settings files (set by an administrator) are not read.
//   - The rule above follows the keys that Claude Code writes. Its exact
//     merge order in Claude Code is not verified.
//
// # Placeholders
//
// The readers keep ${...} placeholders as written, and the output shows them
// as written. The readers never expand them. [Expand] replaces them, with the
// syntax of the client that declared the server. Package internal/inspect
// calls it just before it starts or connects to a server, after its state
// and untrusted checks.
//
// The syntax per client:
//
//   - Claude Code: ${VAR} and ${VAR:-default}. A set variable gives its
//     value, also when the value is empty: the default is only for an unset
//     variable. An unset variable with no default gives
//     [ErrMissingVariable]. "${}" and a "${" with no "}" after it stay as
//     written. The text splits at the first ":-", so ${X:-a:-b} reads the
//     variable X with the default "a:-b". This split is not verified
//     against Claude Code.
//   - Cursor: ${env:NAME}, ${userHome} (the HOME variable),
//     ${workspaceFolder} (ProjectPath), ${workspaceFolderBasename} (the last
//     element of ProjectPath), ${pathSeparator} and ${/} (the path separator
//     of this system). An unset variable gives ErrMissingVariable. A
//     workspace placeholder on a server with no ProjectPath (for example a
//     server of ~/.cursor/mcp.json) gives [ErrNoWorkspaceFolder]. Cursor
//     itself probably uses an empty value for an unset variable. Expand
//     fails closed instead, so inspect never runs a server with a value that
//     the user did not set. Other ${...} forms stay as written.
//   - Codex: no expansion. Expand returns a copy of the server.
//
// More rules:
//
//   - The values come only from the lookup function that the caller gives.
//     The package never reads the environment itself. inspect gives the
//     environment that mcpmoat runs in, which is the user's own.
//   - Expand replaces placeholders in Command, Args, the Env values, URL and
//     the Headers values. It never expands the env and header names (the
//     map keys) or another field.
//   - Expand makes one pass over each text. A value or a default text that
//     holds "${" is not expanded again.
//   - The result has new Env and Headers maps, and the expanded values are
//     in new [Args], [URL] and [Secret] values. They mask the values as
//     before, and the rules of Secrets apply to them.
//   - On a failure, Expand returns an *[ExpandError]. It holds the field
//     (fixed text such as "args") and at most the variable name. It never
//     holds a value, a default text or the text of the field. The name is
//     untrusted text from the config, so the error keeps it only when it is
//     a plain variable name: ASCII letters, digits and "_", not a digit
//     first, at most 64 bytes. For any other name, the error says "variable
//     with an invalid name" and holds no name.
//   - An expanded text can be at most 64 KiB long, and the expanded texts of
//     one server together at most 1 MiB. Only a text in which Expand
//     replaces a placeholder counts. Over a limit, Expand fails with
//     [ErrExpandedTooLong], and inspect does not start or connect to the
//     server.
//
// Expansion of an untrusted server sends values from the user's
// environment to a command or a host that a repository chose. The client
// does the same, but this is one more reason for the untrusted opt-in of
// inspect.
//
// # Tests
//
// Package [github.com/Ducarv/mcpmoat/internal/discover/discovertest] has
// canary values for fixtures and AssertNoLeak. Use them to check that test
// output contains no secret value.
package discover
