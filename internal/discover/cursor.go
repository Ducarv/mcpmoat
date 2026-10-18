package discover

import "context"

// ReadCursor reads one Cursor config file: ~/.cursor/mcp.json with
// ScopeGlobal, or a project .cursor/mcp.json with ScopeProject. Any scope
// other than ScopeGlobal is read as ScopeProject.
//
// The servers of the file get scope. With ScopeProject they get ProjectPath
// projectPath. If projectPath is "", they get the directory of the file, or
// for a file in a directory named ".cursor" or ".codex" the parent of that
// directory: the servers of <project>/.cursor/mcp.json get <project>. With
// ScopeGlobal projectPath is ignored and ProjectPath is "". Cursor files have
// no "projects" section.
//
// See the package doc, Reading configs.
func ReadCursor(ctx context.Context, path string, scope Scope, projectPath string) Result {
	servers, errs := parseJSONServers(ctx, jsonFile{
		path:        path,
		client:      ClientCursor,
		scope:       scope,
		projectPath: projectPath,
	})
	return Result{Servers: servers, Errors: errs}
}
