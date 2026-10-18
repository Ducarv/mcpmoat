package discover

import "context"

// ReadClaudeCode reads one Claude Code config file: ~/.claude.json or a
// project .mcp.json.
//
// Servers under the top-level "mcpServers" get scope and projectPath as given.
// Servers under "projects.<path>.mcpServers" are read only from a global file
// (scope ScopeGlobal, that is ~/.claude.json). They always get ScopeProject,
// with ProjectPath set to <path>. In a project file (.mcp.json) the "projects"
// key is ignored: that file comes from a cloned repository and is untrusted, so
// it must not choose a ProjectPath. A missing file gives an empty Result.
// Errors never hold a config value.
//
// With ScopeProject, path is a project file, and it must be below
// projectPath. The reader opens it inside projectPath: a symlink that leads
// out of projectPath gives a FileError with the reason "file is outside the
// project". Every Server and every FileError of the file has Untrusted set.
// With ScopeProject and an empty projectPath, the reader has no directory to
// check against: it follows symlinks anywhere, but still sets Untrusted.
// With ScopeGlobal, Untrusted is false, also for the "projects" servers.
func ReadClaudeCode(ctx context.Context, path string, scope Scope, projectPath string) Result {
	withProjects := scope == ScopeGlobal
	servers, errs := parseJSONServers(ctx, path, ClientClaudeCode, scope, projectPath, withProjects)
	return Result{Servers: servers, Errors: errs}
}
