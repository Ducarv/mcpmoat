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
//  1. A file name that ends in .toml (any letter case) is Codex. DetectClient
//     does not look at the content of a TOML file. [ReadConfig] parses it and
//     then also applies the known-name rule below to it.
//  2. Otherwise, if the first byte that is not JSON white space (space, tab,
//     CR or LF) is '{', or the file name ends in .json (any letter case), the
//     file is read as JSON:
//     - A file that is not valid JSON is chosen by its path. The reader then
//     reports the invalid JSON with the line and column.
//     - Valid JSON that is not an object (for example an array or a string)
//     is unknown.
//     - An object with a "projects" key is Claude Code. A JSON null counts as
//     no key.
//     - Else an object with an "mcpServers" key is chosen by its path.
//     - Else the file is chosen by its known name (see below). This is an
//     object with neither key, for example the "{}" of a fresh install, or a
//     .json file with only JSON white space. The readers find no servers in
//     both, so both follow the same rule.
//  3. Anything else is unknown.
//
// "Chosen by its path" means Cursor when the parent directory is named
// ".cursor", and Claude Code otherwise.
//
// "Chosen by its known name" accepts only the known client files: .claude.json
// and .mcp.json are Claude Code, and mcp.json in a directory named ".cursor"
// is Cursor. Any other file name, for example package.json, is unknown, so a
// file that is not a client config does not give a clean scan. ReadConfig
// uses the same rule for a .toml file with no mcp_servers key: only
// config.toml in a directory named ".codex" is accepted.
//
// Known limits:
//   - TOML is detected by the .toml extension only. A Codex file with another
//     name is an unknown format.
//   - The ".cursor" check looks at the path as written. DetectClient does not
//     resolve a relative path or another spelling of the directory.
//   - A wrong guess between Claude Code and Cursor changes only the client
//     label and the rule for an entry with "url" and no "type": Cursor reads
//     it as http, and Claude Code refuses it with an error. The other fields
//     of a server entry have the same shape in both formats. The ProjectPath
//     comes from the path and not from the client (see [ReadConfig]).
func DetectClient(path string, data []byte) (client Client, ok bool) {
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		return ClientCodex, true
	}

	// Trim only the JSON white space bytes, as decodeJSONTop does (see
	// jsonSpace).
	trimmed := bytes.Trim(data, jsonSpace)
	isJSON := strings.EqualFold(filepath.Ext(path), ".json") ||
		(len(trimmed) > 0 && trimmed[0] == '{')
	if !isJSON {
		return "", false
	}
	if len(trimmed) == 0 {
		return clientByKnownName(path)
	}

	// Decode the top level into a map, as the readers do. Map keys are matched
	// exactly (case-sensitive). A struct with json tags would also match
	// "MCPServers" or "Projects", and the readers would then ignore those keys.
	// A RawMessage keeps each value as bytes, so this does not build the whole
	// document.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		if _, isSyntax := errors.AsType[*json.SyntaxError](err); isSyntax {
			return clientByPath(path), true
		}
		// Valid JSON of another shape, for example an array or a string.
		return "", false
	}

	switch {
	case !isNull(top[keyProjects]):
		return ClientClaudeCode, true
	case !isNull(top[keyMCPServers]):
		return clientByPath(path), true
	default:
		return clientByKnownName(path)
	}
}

// clientByKnownName handles a JSON file with no servers: an object with
// neither "projects" nor "mcpServers", or a .json file with only JSON white
// space. Discover reads such a file without an error, so a file with a known
// client name is accepted. Other names, for example package.json, stay
// unknown.
func clientByKnownName(path string) (Client, bool) {
	switch filepath.Base(path) {
	case globalClaudeCodeFile, projectClaudeCodeFile:
		return ClientClaudeCode, true
	case cursorFile:
		if inCursorDir(path) {
			return ClientCursor, true
		}
	}
	return "", false
}

// isCodexFileName reports whether path has the known name of a Codex config,
// config.toml in a directory named codexDir, as written in path. ReadConfig
// accepts a .toml file with no mcp_servers key only under this name, as
// clientByKnownName does for a JSON file with no servers.
func isCodexFileName(path string) bool {
	return filepath.Base(path) == codexFile && inCodexDir(path)
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
// cursorDir, as written in path. Cursor keeps its config in .cursor/mcp.json.
func inCursorDir(path string) bool {
	return parentDirIs(path, cursorDir)
}

// inCodexDir reports whether the parent directory of path is named codexDir,
// as written in path. Codex keeps its config in .codex/config.toml.
func inCodexDir(path string) bool {
	return parentDirIs(path, codexDir)
}

// parentDirIs reports whether the parent directory of path is named name, as
// written in path. It does not resolve a relative path or a symlink.
func parentDirIs(path, name string) bool {
	return filepath.Base(filepath.Dir(path)) == name
}
