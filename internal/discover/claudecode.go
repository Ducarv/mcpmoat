package discover

import "context"

// ReadClaudeCode reads one Claude Code config file: ~/.claude.json or a
// project .mcp.json.
//
// Servers under the top-level "mcpServers" get scope. With ScopeProject they
// also get projectPath; with ScopeGlobal projectPath is ignored and their
// ProjectPath is "". Servers under "projects.<path>.mcpServers" are read only
// from a global file (scope ScopeGlobal, that is ~/.claude.json). They always
// get ScopeProject, with ProjectPath set to <path>. In a project file
// (.mcp.json) the "projects" key is ignored: that file comes from a cloned
// repository, so it must not choose a ProjectPath. A missing file gives an
// empty Result. Errors never hold a config value.
//
// With ScopeProject, the file is read below projectPath, or below the
// directory of path if projectPath is "". See the package doc, Untrusted files
// and Symlinks.
func ReadClaudeCode(ctx context.Context, path string, scope Scope, projectPath string) Result {
	withProjects := scope == ScopeGlobal
	servers, errs := parseJSONServers(ctx, path, ClientClaudeCode, scope, projectPath, withProjects)
	return Result{Servers: servers, Errors: errs}
}
