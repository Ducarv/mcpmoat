package discover

import "context"

// ReadClaudeCode reads one Claude Code config file: ~/.claude.json with
// ScopeGlobal, or a project .mcp.json with ScopeProject. Any scope other than
// ScopeGlobal is read as ScopeProject.
//
// The servers of the top-level "mcpServers" object get scope. With
// ScopeProject they get ProjectPath projectPath. If projectPath is "", they
// get the directory of the file, or for a file in a directory named ".cursor"
// or ".codex" the parent of that directory. With ScopeGlobal projectPath is
// ignored and ProjectPath is "".
//
// An entry with no "type" is a stdio entry, as in Claude Code, so an entry
// with a "url" and no "command" is an error: a remote entry needs "type".
//
// Only a global file has its "projects.<path>.mcpServers" servers read. They
// get ScopeProject and ProjectPath <path>. A project .mcp.json comes from a
// cloned repository, so its "projects" key is ignored: it must not choose a
// ProjectPath.
//
// See the package doc, Reading configs.
func ReadClaudeCode(ctx context.Context, path string, scope Scope, projectPath string) Result {
	projects := projectsSkip
	if scope == ScopeGlobal {
		projects = projectsRead
	}
	servers, errs := parseJSONServers(ctx, jsonFile{
		path:        path,
		client:      ClientClaudeCode,
		scope:       scope,
		projectPath: projectPath,
		projects:    projects,
	})
	return Result{Servers: servers, Errors: errs}
}
