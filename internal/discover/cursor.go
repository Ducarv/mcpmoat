package discover

import "context"

// ReadCursor reads one Cursor config file: ~/.cursor/mcp.json or a project
// .cursor/mcp.json.
//
// Servers under the top-level "mcpServers" get scope and projectPath as given.
// Cursor files have no per-project section. A missing file gives an empty
// Result. Errors never hold a config value.
func ReadCursor(ctx context.Context, path string, scope Scope, projectPath string) Result {
	servers, errs := parseJSONServers(ctx, path, ClientCursor, scope, projectPath, false)
	return Result{Servers: servers, Errors: errs}
}
