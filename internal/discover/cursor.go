package discover

import "context"

// ReadCursor reads one Cursor config file: ~/.cursor/mcp.json or a project
// .cursor/mcp.json.
//
// Servers under the top-level "mcpServers" get scope and projectPath as given.
// Cursor files have no per-project section. A missing file gives an empty
// Result. Errors never hold a config value.
//
// With ScopeProject, path is a project file, and it must be below
// projectPath. The reader opens it inside projectPath: a symlink that leads
// out of projectPath gives a FileError with the reason "file is outside the
// project". Every Server and every FileError of the file has Untrusted set.
// With ScopeProject and an empty projectPath, the reader has no directory to
// check against: it follows symlinks anywhere, but still sets Untrusted.
// With ScopeGlobal, Untrusted is false.
func ReadCursor(ctx context.Context, path string, scope Scope, projectPath string) Result {
	servers, errs := parseJSONServers(ctx, path, ClientCursor, scope, projectPath, false)
	return Result{Servers: servers, Errors: errs}
}
