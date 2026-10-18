package discover

import (
	"context"
	"os"
	"path/filepath"
)

// ReadConfig reads one config file that the user named (for example with
// --config) and returns its servers and problems. home is the user's home
// directory, given by the caller as for [Options]; "" means no home.
//
// ReadConfig first cleans path with filepath.Clean. Every server and every
// error names the cleaned path (or the global path, see below), and the
// cleaned path decides the directory of the file: "x/.." is the directory
// ".", not an entry ".." in x.
//
// A file that the user names can come from anywhere, for example from a
// cloned repository. So ReadConfig reads it as an untrusted project file,
// as Discover reads <WorkDir>/.mcp.json:
//
//   - It picks the reader with [DetectClient].
//   - The read is confined to the directory of the file: a symlink that
//     leaves that directory, or an absolute symlink, is refused with the
//     reason "file is outside the project". See the package doc, Symlinks.
//     A path that names a directory, also "..", gives "not a regular file".
//   - Every server has ScopeProject and Untrusted set, and every error has
//     Untrusted set (see the package doc, Untrusted files). The ProjectPath of
//     the servers is the directory of the file, or the parent of that
//     directory when it is named ".cursor" (Cursor) or ".codex" (Codex).
//   - The "projects" section of a Claude Code file is not read, because a
//     repository file must not choose ProjectPath values. When the file has
//     a "projects" value that is not null (also an empty object, or a value
//     of the wrong type), ReadConfig adds one FileError with the reason
//     "projects section not read". The scan then fails, so the servers that
//     were not read do not look clean. The top-level servers are still
//     returned.
//   - The size limit is maxProjectConfigSize (4 MiB), or the smaller
//     maxTOMLSize (256 KiB) for a Codex file.
//   - The file is read once. The reader parses the bytes that the detection
//     read got, so a file that changes or goes away after that read cannot
//     change the result.
//
// The one exception is a path that names one of the user's own global files:
// home/.claude.json, home/.cursor/mcp.json or home/.codex/config.toml. Here
// "names" means that [os.Stat] of path and os.Stat of the global path give
// the same file by [os.SameFile]. Both files must exist. So a symlink to a
// global file, a hard link to it, and another letter case of its path on a
// case-insensitive file system all count. A relative path is relative to the
// current directory. On any error the file counts as not global, so it is
// read as untrusted, the safe side.
//
// ReadConfig then reads the global path, not path, with the reader that
// Discover uses for that file: no format detection, ScopeGlobal, no
// confinement, and trusted. So a path that changes after the check is never
// read as trusted. Every server and every error names the global path. A
// .claude.json also gives the servers of its projects.
//
// Unlike [Discover], ReadConfig treats a missing file as an error, because the
// user asked for this file: the result holds a [FileError] with the reason
// "file not found". This is also true for a global file that goes away after
// the check. A file with an unknown format gives a FileError with the reason
// "unknown config format". Every FileError names the file and never holds
// config text or text from a JSON or TOML library.
func ReadConfig(ctx context.Context, path, home string) Result {
	path = filepath.Clean(path)
	if g, ok := globalFor(path, home); ok {
		return readGlobal(ctx, g, home)
	}
	return readUntrusted(ctx, path)
}

// globalFile is one of the user's own config files, and the read that
// Discover does for it.
type globalFile struct {
	rel  string // one of the global file constants, such as globalCodexFile
	read func(ctx context.Context, path string) Result
}

// path returns the path of the global file below home.
func (g globalFile) path(home string) string {
	return homePath(home, g.rel)
}

// globalFiles lists the user's own config files, the global steps of
// Discover (see buildSteps), with the reader and the scope that Discover uses
// for each. No code writes to it.
var globalFiles = [...]globalFile{
	{globalClaudeCodeFile, readGlobalClaudeCode},
	{globalCursorFile, readGlobalCursor},
	{globalCodexFile, ReadCodex},
}

// readGlobalClaudeCode reads ~/.claude.json as Discover does.
func readGlobalClaudeCode(ctx context.Context, path string) Result {
	return ReadClaudeCode(ctx, path, ScopeGlobal, "")
}

// readGlobalCursor reads ~/.cursor/mcp.json as Discover does.
func readGlobalCursor(ctx context.Context, path string) Result {
	return ReadCursor(ctx, path, ScopeGlobal, "")
}

// globalFor returns the global file below home that path names, if any. See
// ReadConfig for what "names" means. ok is false when home is "", or when
// either os.Stat fails.
func globalFor(path, home string) (globalFile, bool) {
	if home == "" {
		return globalFile{}, false
	}
	info, err := os.Stat(path)
	if err != nil {
		return globalFile{}, false
	}
	for _, g := range globalFiles {
		gi, err := os.Stat(g.path(home))
		if err == nil && os.SameFile(info, gi) {
			return g, true
		}
	}
	return globalFile{}, false
}

// readGlobal reads the global file g below home with the reader that Discover
// uses for it. The readers give an empty result for a missing file, so a file
// that went away after the check in globalFor is reported as not found.
func readGlobal(ctx context.Context, g globalFile, home string) Result {
	path := g.path(home)
	res := g.read(ctx, path)
	if len(res.Servers) == 0 && len(res.Errors) == 0 && isMissingFile(path) {
		return Result{Errors: []*FileError{newFileError(path, reasonNotFound)}}
	}
	return res
}

// isMissingFile reports whether no file exists at path now. A dangling
// symlink counts as missing, as in readConfigFile.
func isMissingFile(path string) bool {
	_, err := os.Stat(path)
	return isMissing(err)
}

// readUntrusted reads the file at path, which is not one of the user's own
// global files, as an untrusted project file. It reads the file once, detects
// the format from those bytes and gives the same bytes to readUntrustedJSON
// or readUntrustedCodex. See ReadConfig.
//
// This is the one place that picks the size limit of an untrusted file. The
// read comes before the detection, so it uses maxProjectConfigSize, the limit
// of the project JSON files. After the detection, a Codex file over the
// smaller maxTOMLSize gets the same "file too large" error as ReadCodex gives.
// The read also has the confinement of the project files.
func readUntrusted(ctx context.Context, path string) Result {
	data, found, fe := readConfigFile(ctx, path, maxProjectConfigSize, confineDir(path))
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
	case ClientClaudeCode, ClientCursor:
		return readUntrustedJSON(ctx, path, client, data)
	case ClientCodex:
		if len(data) > maxTOMLSize {
			return untrustedError(readError(path, reasonTooLarge, nil))
		}
		return readUntrustedCodex(ctx, path, data)
	default:
		// DetectClient only returns the three clients above. Keep the error
		// fixed and free of config text if that ever changes.
		return untrustedError(newFileError(path, reasonUnknownFormat))
	}
}

// readUntrustedJSON parses data, the content of the untrusted Claude Code or
// Cursor file at path, as ReadClaudeCode and ReadCursor do with ScopeProject
// and an empty projectPath. It does not read the file again. For Claude Code
// it also reports a "projects" section, which it does not read (see
// ReadConfig). parseJSONServers marks every server and every error Untrusted.
func readUntrustedJSON(ctx context.Context, path string, client Client, data []byte) Result {
	servers, errs := parseJSONServers(ctx, jsonFile{
		path:           path,
		client:         client,
		scope:          ScopeProject,
		reportProjects: client == ClientClaudeCode,
		data:           data,
		hasData:        true,
	})
	return Result{Servers: servers, Errors: errs}
}

// readUntrustedCodex parses data, the content of the untrusted Codex file at
// path, with the rules of ReadCodex. It does not read the file again.
// ReadCodex itself has no untrusted mode, because Discover reads only the
// user's own Codex file.
//
// Every server gets ScopeProject, and the ProjectPath that projectDirOf
// gives: the directory of the file, or the parent of a directory named
// ".codex" (<project>/.codex/config.toml). Every server and every error gets
// Untrusted.
func readUntrustedCodex(ctx context.Context, path string, data []byte) Result {
	servers, errs := parseCodex(ctx, path, data)
	projectPath := projectDirOf(path, ClientCodex)
	for i := range servers {
		servers[i].Scope = ScopeProject
		servers[i].ProjectPath = projectPath
	}
	markUntrusted(servers, errs)
	return Result{Servers: servers, Errors: errs}
}

// confineDir returns the directory that the read of the cleaned path is
// confined to: the directory of path.
//
// A cleaned path whose last part is ".." (for example ".." or "../..") names
// a directory above the current one. Its filepath.Dir does not hold it, so
// the read would be refused as "file is outside the project". Such a path is
// its own root instead: the read opens that directory, and readConfigFile
// refuses it as "not a regular file".
func confineDir(path string) string {
	if filepath.Base(path) == ".." {
		return path
	}
	return filepath.Dir(path)
}

// untrustedError returns a result that holds only fe, marked Untrusted.
func untrustedError(fe *FileError) Result {
	fe.Untrusted = true
	return Result{Errors: []*FileError{fe}}
}
