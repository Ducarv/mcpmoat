package discover

import (
	"bytes"
	"context"
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
//  2. Otherwise, if the first byte that is not white space is '{', or the file
//     name ends in .json (any letter case), the file is read as JSON:
//     - A file with only white space is chosen by its path (see below) and
//     has no servers.
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

	trimmed := bytes.TrimSpace(data)
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
		if filepath.Base(filepath.Dir(path)) == ".cursor" {
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
	if filepath.Base(filepath.Dir(path)) == ".cursor" {
		return ClientCursor
	}
	return ClientClaudeCode
}

// ReadConfig reads one config file that the user named (for example with
// --config) and returns its servers and problems. home is the user's home
// directory, given by the caller as for [Options]; "" means no home.
//
// A file that the user names can come from anywhere, for example from a
// cloned repository. So ReadConfig reads it as an untrusted project file,
// as Discover reads <WorkDir>/.mcp.json:
//
//   - It picks the reader with [DetectClient].
//   - The read is confined to the directory of the file: a symlink that
//     leaves that directory, or an absolute symlink, is refused with the
//     reason "file is outside the project". See the package doc, Symlinks.
//   - Every server has ScopeProject and Untrusted set, and every error has
//     Untrusted set (see the package doc, Untrusted files). The ProjectPath of
//     the servers is the directory of the file, or the parent of that
//     directory when it is named ".cursor" (Cursor) or ".codex" (Codex).
//   - The "projects" section of a Claude Code file is not read.
//   - The size limit is maxProjectConfigSize (4 MiB), or maxTOMLSize
//     (256 KiB) for a Codex file.
//
// The one exception is a path that resolves to one of the user's own global
// files: home/.claude.json, home/.cursor/mcp.json or home/.codex/config.toml.
// ReadConfig reads that file as Discover does: with the reader of that file
// (no format detection), ScopeGlobal, no confinement, and trusted. A
// .claude.json then also gives the servers of its projects. "Resolves" means
// that filepath.EvalSymlinks of the absolute path is the same as
// filepath.EvalSymlinks of the global path. Both files must exist. For a
// relative path, filepath.Abs uses the current directory. On any error the
// file counts as not global, so it is read as untrusted, the safe side. The
// compare is of text: a second name for the same file that EvalSymlinks does
// not resolve (for example another letter case on a case-insensitive file
// system, or a hard link) is read as untrusted too.
//
// Unlike [Discover], ReadConfig treats a missing file as an error, because the
// user asked for this file: the result holds a [FileError] with the reason
// "file not found". A file with an unknown format gives a FileError with the
// reason "unknown config format". Every FileError names the file and never
// holds config text or text from a JSON or TOML library.
//
// The file is read twice: once here to detect the format, and once by the
// reader. Both reads have the same confinement. The file is small, and
// reading it twice keeps the readers unchanged. A change to the file between
// the two reads is harmless, because the second read has its own checks and
// limits.
func ReadConfig(ctx context.Context, path, home string) Result {
	if client, ok := globalClient(path, home); ok {
		return readGlobal(ctx, path, client)
	}

	// The detection read has the confinement and the size limit of the
	// project JSON readers. readUntrustedCodex has a smaller limit.
	data, found, fe := readConfigFile(ctx, path, maxProjectConfigSize, filepath.Dir(path))
	if fe != nil {
		return untrustedError(fe)
	}
	if !found {
		return untrustedError(newFileError(path, reasonNotFound))
	}

	client, ok := DetectClient(path, data)
	if !ok {
		return untrustedError(newFileError(path, reasonUnknownFormat))
	}

	switch client {
	case ClientClaudeCode:
		return ReadClaudeCode(ctx, path, ScopeProject, "")
	case ClientCursor:
		return ReadCursor(ctx, path, ScopeProject, "")
	case ClientCodex:
		return readUntrustedCodex(ctx, path)
	default:
		// DetectClient only returns the three clients above. Keep the error
		// fixed and free of config text if that ever changes.
		return untrustedError(newFileError(path, reasonUnknownFormat))
	}
}

// globalFile is one of the user's own config files, as Discover reads it.
type globalFile struct {
	rel    string // path below the home directory, with forward slashes
	client Client
}

// globalFiles lists the user's own config files, the global steps of
// Discover (see buildSteps). No code writes to it.
var globalFiles = [...]globalFile{
	{".claude.json", ClientClaudeCode},
	{".cursor/mcp.json", ClientCursor},
	{".codex/config.toml", ClientCodex},
}

// globalClient reports whether path resolves to one of the user's own global
// files below home, and the client of that file. See ReadConfig for what
// "resolves" means.
func globalClient(path, home string) (Client, bool) {
	if home == "" {
		return "", false
	}
	resolved, ok := resolvePath(path)
	if !ok {
		return "", false
	}
	for _, g := range globalFiles {
		if gr, ok := resolvePath(filepath.Join(home, filepath.FromSlash(g.rel))); ok && gr == resolved {
			return g.client, true
		}
	}
	return "", false
}

// resolvePath returns the absolute path of path with every symlink resolved.
// ok is false when the path cannot be resolved, for example when the file
// does not exist.
func resolvePath(path string) (resolved string, ok bool) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	resolved, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return "", false
	}
	return resolved, true
}

// readGlobal reads one of the user's own global files with the reader and the
// scope that Discover uses for it.
func readGlobal(ctx context.Context, path string, client Client) Result {
	switch client {
	case ClientClaudeCode:
		return ReadClaudeCode(ctx, path, ScopeGlobal, "")
	case ClientCursor:
		return ReadCursor(ctx, path, ScopeGlobal, "")
	default:
		return ReadCodex(ctx, path)
	}
}

// untrustedError returns a result that holds only fe, marked Untrusted.
func untrustedError(fe *FileError) Result {
	fe.Untrusted = true
	return Result{Errors: []*FileError{fe}}
}
