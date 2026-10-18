package discover

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

// DetectClient reports which client format a config file has, from the file
// name and its content. ok is false when the format is unknown.
//
// It does no I/O. The rules, in this order:
//
//  1. A file name that ends in .toml (any letter case) is Codex.
//  2. Otherwise, if the first byte that is not JSON white space (space, tab,
//     CR or LF) is '{', or the file name ends in .json (any letter case), the
//     file is read as JSON:
//     - A file with only JSON white space is chosen by its path (see below)
//     and has no servers.
//     - A file that is not valid JSON is chosen by its path. The reader then
//     reports the invalid JSON with the line and column.
//     - Valid JSON that is not an object (for example an array or a string)
//     is unknown.
//     - An object with a "projects" key is Claude Code. A JSON null counts as
//     no key.
//     - Else an object with an "mcpServers" key is chosen by its path.
//     - Else (an object with neither key, for example the "{}" of a fresh
//     install) the file name decides, but only for the known client files:
//     .claude.json and .mcp.json are Claude Code, and mcp.json in a
//     directory named ".cursor" is Cursor. Any other file name is unknown.
//  3. Anything else is unknown.
//
// "Chosen by its path" means Cursor when the parent directory is named
// ".cursor", and Claude Code otherwise.
//
// Known limits:
//   - TOML is detected by the .toml extension only. A Codex file with another
//     name is an unknown format.
//   - The ".cursor" check looks at the path as written. DetectClient does not
//     resolve a relative path or another spelling of the directory.
//   - A wrong guess between Claude Code and Cursor changes only the client
//     label, because both formats share the shape of a server entry.
func DetectClient(path string, data []byte) (client Client, ok bool) {
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		return ClientCodex, true
	}

	// Trim only the four JSON white space bytes, as loadJSONFile does.
	// bytes.TrimSpace would also trim Unicode spaces such as U+00A0, which
	// JSON does not allow.
	trimmed := bytes.Trim(data, " \t\r\n")
	isJSON := strings.EqualFold(filepath.Ext(path), ".json") ||
		(len(trimmed) > 0 && trimmed[0] == '{')
	if !isJSON {
		return "", false
	}
	if len(trimmed) == 0 {
		return clientByPath(path), true
	}

	// Decode the top level into a map, as the readers do. Map keys are matched
	// exactly (case-sensitive). A struct with json tags would also match
	// "MCPServers" or "Projects", and the readers would then ignore those keys.
	// A RawMessage keeps each value as bytes, so this does not build the whole
	// document.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return clientByPath(path), true
		}
		// Valid JSON of another shape, for example an array or a string.
		return "", false
	}

	switch {
	case hasJSONValue(top["projects"]):
		return ClientClaudeCode, true
	case hasJSONValue(top["mcpServers"]):
		return clientByPath(path), true
	default:
		return clientByKnownName(path)
	}
}

// clientByKnownName handles a JSON object with neither "projects" nor
// "mcpServers". Discover reads such a file without an error (it has no
// servers), so a file with a known client name is accepted. Other names, for
// example package.json, stay unknown.
func clientByKnownName(path string) (Client, bool) {
	switch filepath.Base(path) {
	case ".claude.json", ".mcp.json":
		return ClientClaudeCode, true
	case "mcp.json":
		if inCursorDir(path) {
			return ClientCursor, true
		}
	}
	return "", false
}

// hasJSONValue reports whether a key was present with a value that is not
// JSON null. A missing key leaves the RawMessage empty.
func hasJSONValue(raw json.RawMessage) bool {
	return len(raw) > 0 && !bytes.Equal(raw, []byte("null"))
}

// clientByPath picks Cursor for a file in a directory named ".cursor", and
// Claude Code for every other JSON file.
func clientByPath(path string) Client {
	if inCursorDir(path) {
		return ClientCursor
	}
	return ClientClaudeCode
}

// inCursorDir reports whether the parent directory of path is named
// ".cursor", as written in path. Cursor keeps its config in .cursor/mcp.json.
func inCursorDir(path string) bool {
	return filepath.Base(filepath.Dir(path)) == ".cursor"
}
