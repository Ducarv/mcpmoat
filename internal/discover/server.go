package discover

// Client identifies the AI client whose config declared a server.
//
// The string values are a stable contract: JSON output uses them.
type Client string

// Supported clients.
const (
	// ClientClaudeCode is Claude Code: ~/.claude.json and .mcp.json.
	ClientClaudeCode Client = "claude-code"
	// ClientCursor is Cursor: ~/.cursor/mcp.json and .cursor/mcp.json.
	ClientCursor Client = "cursor"
	// ClientCodex is the Codex CLI: ~/.codex/config.toml.
	ClientCodex Client = "codex"
)

// Scope tells whether a server applies to all projects or to one project.
//
// The string values are a stable contract: JSON output uses them.
type Scope string

// Supported scopes.
const (
	// ScopeGlobal is a server from a user-wide config.
	ScopeGlobal Scope = "global"
	// ScopeProject is a server for one project; see Server.ProjectPath.
	ScopeProject Scope = "project"
)

// Transport is how mcpmoat talks to a server.
//
// The string values are a stable contract: JSON output uses them.
type Transport string

// Supported transports.
const (
	// TransportStdio is a local child process. It uses Server.Command,
	// Server.Args and Server.Env.
	TransportStdio Transport = "stdio"
	// TransportHTTP is a remote server over streamable HTTP. It uses
	// Server.URL and Server.Headers.
	TransportHTTP Transport = "http"
	// TransportSSE is a remote server over the legacy HTTP+SSE transport.
	// It uses Server.URL and Server.Headers.
	TransportSSE Transport = "sse"
)

// IsRemote reports whether t connects over the network (TransportHTTP or
// TransportSSE).
func (t Transport) IsRemote() bool {
	return t == TransportHTTP || t == TransportSSE
}

// Server is one MCP server entry read from a client config file. All config
// readers return this common model.
//
// Values are kept exactly as written in the config. Variable references such
// as ${VAR} are not expanded. Command is not resolved against PATH, because
// the scanner later runs exactly the configured command (NFR-04).
//
// Env and Headers values print as [Mask] because they are [Secret] values,
// and URL prints through [RedactURL] because it is a [URL]. The types do the
// masking, so fmt (every verb, including %p, and also when a Server is in an
// unexported field of another struct), log/slog and encoders cannot show
// those values. Command and Args are plain strings: fmt shows them as written,
// so display code must show Args through [RedactArgs], which masks likely
// credentials (heuristic). A secret in Command itself is not masked.
//
// Server has no methods and no struct tags on purpose: output types live in
// internal/report.
type Server struct {
	// Name is the server key under mcpServers (JSON configs) or in
	// [mcp_servers.<name>] (Codex TOML config).
	Name string

	// Client is the AI client whose config declared the server.
	Client Client

	// Scope tells whether the server applies to all projects or to one.
	Scope Scope

	// ProjectPath is the project the server applies to when Scope is
	// ScopeProject: the projects.<path> key in ~/.claude.json, or the
	// directory that holds .mcp.json or .cursor/mcp.json. It is empty for
	// ScopeGlobal.
	ProjectPath string

	// Source is the path of the config file that declared the server.
	Source string

	// Transport is how mcpmoat talks to the server.
	Transport Transport

	// Command is the executable for TransportStdio.
	Command string

	// Args are the arguments for TransportStdio, as written. They can hold
	// credentials: display them with RedactArgs.
	Args []string

	// Env holds the environment variables for TransportStdio. Use Env.Keys
	// to show the names.
	Env SecretMap

	// URL is the endpoint for a remote transport. Use URL.Reveal only where
	// the value is used (internal/inspect).
	URL URL

	// Headers holds the HTTP headers for a remote transport. Use
	// Headers.Keys to show the names.
	Headers SecretMap
}
