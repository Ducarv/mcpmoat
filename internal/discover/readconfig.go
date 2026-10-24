package discover

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/safefile"
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
// as Discover reads <WorkDir>/.mcp.json. This doc holds the full rules for
// such a file; other docs refer to it.
//
//   - The file is read once. ReadConfig picks the reader with [DetectClient]
//     from the bytes of that read, and the reader parses the same bytes. So a
//     file that changes or goes away after the read cannot change the result.
//   - Only the last element of the path, the file, is confined. ReadConfig
//     opens the directory of the file with [os.Root] and opens the file
//     through it. A symlink at the file that leaves that directory, or an
//     absolute symlink, is refused with the reason "file is outside the
//     project". See the package doc, Symlinks. A path that names a
//     directory, also "..", gives "not a regular file".
//   - The directories in the path are the user's choice, so ReadConfig
//     follows a symlink in them. For example, when repo/.cursor is a
//     symlink to /elsewhere, ReadConfig("repo/.cursor/mcp.json") reads
//     /elsewhere/mcp.json. The file is still untrusted, and its ProjectPath
//     comes from the path as written (repo), not from the symlink target.
//   - The size limit is maxProjectConfigSize (4 MiB), or the smaller
//     maxTOMLSize (256 KiB) for a Codex file.
//   - Every server has ScopeProject and Untrusted set, and every error has
//     Untrusted set (see the package doc, Untrusted files). The ProjectPath of
//     the servers is the directory of the file, or the parent of that
//     directory when it is named ".cursor" or ".codex". Only the path decides,
//     not the detected client, so a wrong guess of DetectClient does not
//     change the ProjectPath.
//   - The "projects" section of a JSON file is not read, because a
//     repository file must not choose ProjectPath values. When the file has
//     a "projects" value that is not null (also an empty object, or a value
//     of the wrong type), ReadConfig adds one FileError with the reason
//     "projects section not read". A key that differs from "projects" only by
//     letter case (for example "Projects") adds one FileError with the reason
//     "ambiguous key", as in a global file. Both rules apply to every JSON
//     file, whether DetectClient says Claude Code or Cursor. The scan then
//     fails, so the servers that were not read do not look clean. The
//     top-level servers are still returned.
//   - A .toml file that is valid TOML with no top-level mcp_servers key (for
//     example an empty file, a file with only comments, pyproject.toml or
//     Cargo.toml) has no servers. As for a JSON file with no servers (see
//     DetectClient), only the known name is accepted: config.toml in a
//     directory named ".codex" gives an empty result. Any other name gives
//     the reason "unknown config format", so a file that is not a Codex
//     config does not give a clean scan. A .toml file with an mcp_servers key
//     is read as Codex under any name.
//   - A Codex file must not choose a working directory outside its project:
//     inspect would start the server there. A server whose cwd fails the cwd
//     check below is dropped. It gives a FileError for the server with the
//     reason "working directory is outside the project or cannot be
//     checked". An empty cwd sets no working directory and is kept.
//   - The cwd check has two steps. First a lexical step: a cwd with a ".."
//     element fails (for example "a/../b" or "<project>/link/.."), because
//     the kernel resolves ".." after it follows a symlink, so the text cannot
//     tell where ".." leads. A "." element is accepted. Then an absolute cwd
//     must be the ProjectPath or below it, and a relative cwd must be local
//     (see [filepath.IsLocal]). An absolute cwd always fails when the
//     ProjectPath is relative, because the package does not read the current
//     directory to make it absolute. Then a symlink step: ReadConfig opens
//     the ProjectPath with [os.Root] and looks the cwd up through it, so it
//     follows the symlinks that stay inside the project. A cwd that leads out
//     of the project through a symlink, that passes an absolute symlink (as
//     for the read of the file), that is not a directory, or that cannot be
//     checked (for example a symlink loop or a permission error) fails. A cwd
//     that does not exist, or a ProjectPath that went away, is kept: inspect
//     cannot start a server in a directory that is not there.
//   - A kept cwd stays as written; see [Server.Dir] for how inspect treats a
//     relative Dir. The check sees the tree at read time only, and the tree
//     can change after it (a directory can become a symlink). So inspect
//     must still not trust Dir blindly.
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

// readGlobalClaudeCode reads ~/.claude.json for ReadConfig. Discover reads
// this file with readGlobalClaudeCodeState instead, which also knows WorkDir.
// The servers and the errors are the same, but the State of a top-level
// server can differ (see globalClaudeCode).
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

// readGlobal reads the global file g below home with the reader of g, the
// one that Discover uses for it. For ~/.claude.json, Discover uses
// readGlobalClaudeCodeState instead: the servers and the errors are the
// same, but the State of a top-level server can differ (see
// globalClaudeCode). The readers give an empty result for a missing file, so
// readGlobal turns an empty result for a file that went away after the check
// in globalFor into "file not found". See ReadConfig.
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
	return safefile.IsMissing(err)
}

// readUntrusted reads the file at path, which is not one of the user's own
// global files, as an untrusted project file. See ReadConfig.
//
// This is the one place that picks the size limit of an untrusted file. The
// read comes before the detection, so it uses maxProjectConfigSize, the limit
// of the project JSON files. After the detection, a Codex file over the
// smaller maxTOMLSize gets the same "file too large" error as ReadCodex gives.
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
// Cursor file at path, with parseJSONBytes, the parse step of ReadClaudeCode
// and ReadCursor, with ScopeProject, an empty projectPath and projectsReport
// for both clients. parseJSONBytes marks every server and every error
// Untrusted. See ReadConfig.
func readUntrustedJSON(ctx context.Context, path string, client Client, data []byte) Result {
	servers, errs := parseJSONBytes(ctx, jsonFile{
		path:     path,
		client:   client,
		scope:    ScopeProject,
		projects: projectsReport,
	}, data)
	return Result{Servers: servers, Errors: errs}
}

// readUntrustedCodex parses data, the content of the untrusted Codex file at
// path, with parseCodex, the parse step of ReadCodex, which has no untrusted
// mode. Then it applies the untrusted Codex rules of ReadConfig (the
// known-name rule, ScopeProject, the ProjectPath of projectDirOf, the cwd
// check and the Untrusted mark). See ReadConfig.
func readUntrustedCodex(ctx context.Context, path string, data []byte) Result {
	parsed, errs, noServersKey := parseCodex(ctx, path, data)
	if noServersKey && !isCodexFileName(path) {
		return untrustedError(newFileError(path, reasonUnknownFormat))
	}

	project := openProjectDir(projectDirOf(path))
	defer project.close()
	var servers []Server
	for _, s := range parsed {
		if !project.holdsDir(s.Dir) {
			errs = append(errs, newFileError(path, reasonCwdOutsideProject).forServer(s.Name))
			continue
		}
		s.Scope = ScopeProject
		s.ProjectPath = project.path
		servers = append(servers, s)
	}
	// Keep the error order of parseCodex: errors for the whole file first,
	// then by server name.
	sortErrors(errs)
	markUntrusted(servers, errs)
	return Result{Servers: servers, Errors: errs}
}

// projectDir is the project directory of an untrusted Codex file, opened
// once for the cwd check of all its servers. See ReadConfig for the rule.
type projectDir struct {
	path string   // the ProjectPath of the file
	root *os.Root // nil when err is set
	err  error    // the error of os.OpenRoot
}

// openProjectDir opens the project directory at path. An error is kept for
// holdsDir, which decides what it means for a cwd.
func openProjectDir(path string) projectDir {
	root, err := os.OpenRoot(path)
	return projectDir{path: path, root: root, err: err}
}

// close closes the root. The root is only read, so a close error loses
// nothing.
func (p projectDir) close() {
	if p.root != nil {
		_ = p.root.Close()
	}
}

// holdsDir reports whether dir, the cwd of a server, stays in the project:
// the lexical step (localDir), then the symlink step (resolvesInside).
func (p projectDir) holdsDir(dir string) bool {
	rel, ok := localDir(dir, p.path)
	switch {
	case !ok:
		return false
	case rel == "":
		return true
	}
	return p.resolvesInside(rel)
}

// localDir does the lexical step of the cwd check: it returns dir relative
// to projectPath ("" for an empty dir), or ok false when dir fails the step.
// See ReadConfig. The ".." test comes first because filepath.Rel removes
// "link/.." as text, so the symlink step would check "." for an absolute
// "<proj>/link/..", while the kernel goes up from the target of link.
func localDir(dir, projectPath string) (rel string, ok bool) {
	switch {
	case dir == "":
		return "", true
	case hasDotDot(dir):
		return "", false
	case filepath.IsAbs(dir):
		if !filepath.IsAbs(projectPath) {
			return "", false
		}
		r, err := filepath.Rel(projectPath, dir)
		if err != nil || !filepath.IsLocal(r) {
			return "", false
		}
		return r, true
	case filepath.IsLocal(dir):
		return dir, true
	}
	return "", false
}

// hasDotDot reports whether a path element of dir is "..". It splits dir at
// "/" and at the separator of the OS (filepath.ToSlash turns a Windows "\"
// into "/").
func hasDotDot(dir string) bool {
	return slices.Contains(strings.Split(filepath.ToSlash(dir), "/"), "..")
}

// resolvesInside does the symlink step of the cwd check: it looks up rel, a
// local path, through the root. The root follows symlinks that stay in the
// project and refuses one that leads out of it.
func (p projectDir) resolvesInside(rel string) bool {
	err := p.err
	var info os.FileInfo
	if err == nil {
		info, err = p.root.Stat(rel)
	}
	switch {
	case err == nil:
		return info.IsDir()
	case errors.Is(err, fs.ErrNotExist):
		// Nothing is there (or the project went away), so no symlink leads
		// out, and inspect cannot start a server there.
		return true
	default:
		// os.Root refuses a path that leaves the root with an error that is
		// not exported. Any other error (not a directory, a symlink loop, a
		// permission error) means the cwd cannot be checked: fail closed.
		return false
	}
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
