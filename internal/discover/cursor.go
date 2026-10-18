package discover

import "context"

// ReadCursor reads one Cursor config file: ~/.cursor/mcp.json or a project
// .cursor/mcp.json.
//
// Servers under the top-level "mcpServers" get scope. With ScopeProject they
// also get projectPath; with ScopeGlobal projectPath is ignored and their
// ProjectPath is "". Cursor files have no per-project section. A missing file
// gives an empty Result. Errors never hold a config value.
//
// With ScopeProject, the file is read below projectPath, or below the
// directory of path if projectPath is "". See the package doc, Untrusted files
// and Symlinks.
func ReadCursor(ctx context.Context, path string, scope Scope, projectPath string) Result {
	servers, errs := parseJSONServers(ctx, path, ClientCursor, scope, projectPath, false)
	return Result{Servers: servers, Errors: errs}
}
