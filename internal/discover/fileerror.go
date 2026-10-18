package discover

import (
	"bytes"
	"errors"
	"io/fs"
	"strconv"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// reason is the type of the fixed reason texts of a FileError. Helpers that
// pick a reason return a reason, not a string. Then a helper cannot return a
// string that is not a constant, for example the text of a library error,
// without an explicit conversion that a reviewer can see.
type reason string

// Fixed reasons for a FileError. They are plain text and never contain a value
// from a config file, so an error message cannot leak a secret.
//
// The constants are untyped on purpose. An untyped constant fits both the
// reason type of the helpers and the string field FileError.Reason, which
// callers outside the package read. Do not set FileError.Reason by hand:
// build every FileError with newFileError, which takes a reason.
//
// Add every new reason to allReasons in helpers_internal_test.go too.
const (
	reasonCannotRead       = "cannot read file"
	reasonNotRegular       = "not a regular file"
	reasonTooLarge         = "file is too large"
	reasonOutsideProject   = "file is outside the project" // a project file that is a symlink out of the project directory
	reasonInvalidJSON      = "invalid JSON"
	reasonInvalidTOML      = "invalid TOML"
	reasonBadShape         = "unexpected structure"
	reasonBadServers       = "mcpServers is not an object"
	reasonBadEntry         = "invalid server entry"
	reasonUnknownTransport = "unknown transport type"
	reasonNoCommandOrURL   = "server has no command or url"
	reasonStdioNoCommand   = "stdio server has no command"
	reasonRemoteNoURL      = "remote server has no url"
	reasonCanceled         = "canceled"
	reasonTooDeep          = "nesting is too deep"  // too deep nesting of [ ] and { }
	reasonKeyTooLong       = "key path is too long" // a TOML key path with too many dotted parts
	reasonTooManyServers   = "too many servers"
	reasonAmbiguousKey     = "ambiguous key"         // two keys that differ only by letter case
	reasonEmptyName        = "empty server name"     // a server key that is the empty string
	reasonEmptyProject     = "empty project path"    // an empty key under "projects" in ~/.claude.json
	reasonBadString        = "invalid string"        // a lone UTF-16 surrogate escape or invalid UTF-8
	reasonNotFound         = "file not found"        // ReadConfig: a file the user named does not exist
	reasonUnknownFormat    = "unknown config format" // ReadConfig: a file the user named has no known client format

	// reasonProjectsNotRead is for an untrusted Claude Code file named with
	// --config (see ReadConfig) that has a "projects" section. Its projects
	// are not read, because a repository file must not choose ProjectPath
	// values. The error makes the scan fail, so the servers that were not
	// read do not look clean.
	reasonProjectsNotRead = "projects section not read"

	// reasonCwdOutsideProject is for a server of an untrusted Codex file
	// named with --config (see ReadConfig) whose cwd is outside the project.
	// An untrusted file must not choose a working directory outside its
	// project: inspect would start the server there. The server is dropped.
	reasonCwdOutsideProject = "working directory is outside the project"
)

// FileError describes a problem with one config file or with one server entry
// in it. Its message holds the file path, an optional position, an optional
// server name and a fixed reason. It never holds a value from the config.
type FileError struct {
	// Path is the config file path.
	Path string
	// ProjectPath is the projects.<path> key of ~/.claude.json that the
	// entry came from. It is empty otherwise.
	ProjectPath string
	// Server is the server name. It is empty for a problem with the whole file.
	Server string
	// Line is the 1-based line of the problem, or 0 if unknown.
	Line int
	// Col is the 1-based byte column of the problem, or 0 if unknown.
	Col int
	// Reason is fixed text, one of the reason constants.
	Reason string
	// Err is the underlying error: an OS error for an IO problem, or the
	// context error for a canceled read. It is nil for parse problems.
	Err error
	// Untrusted is true when the problem is in a project file, which a cloned
	// repository can ship. See the package doc, Untrusted files.
	Untrusted bool
}

var _ error = (*FileError)(nil)

// Error returns the message in the form
// "<path>[:<line>[:<col>]]: [project <path>: ][server <name>: ]<reason>[: <Err>]".
// Path, project path and server name are untrusted text. termsafe.Quote
// quotes them when they hold characters that are not visible, and displayText
// cuts a long project path or server name first. The path is never cut: the
// user needs it in full to find the file.
func (e *FileError) Error() string {
	var b strings.Builder
	b.WriteString(termsafe.Quote(e.Path))
	if e.Line > 0 {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(e.Line))
		if e.Col > 0 {
			b.WriteByte(':')
			b.WriteString(strconv.Itoa(e.Col))
		}
	}
	b.WriteString(": ")
	if e.ProjectPath != "" {
		b.WriteString("project ")
		b.WriteString(displayText(e.ProjectPath))
		b.WriteString(": ")
	}
	if e.Server != "" {
		b.WriteString("server ")
		b.WriteString(displayText(e.Server))
		b.WriteString(": ")
	}
	b.WriteString(e.Reason)
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(errText(e.Err))
	}
	return b.String()
}

// Unwrap returns the underlying error (Err), so errors.Is and errors.As work.
func (e *FileError) Unwrap() error {
	return e.Err
}

// newFileError returns a FileError for the config file at path with the
// fixed reason r. Every FileError of the package is built here, so its
// Reason is always a fixed reason: the reason type does not accept the text
// of a library error or a value from a config file without a conversion that
// a reviewer can see.
//
// Set the other fields with the methods inProject, forServer and atOffset,
// which chain:
//
//	newFileError(path, reasonBadEntry).inProject(key).forServer(name)
//
// Use readError for an OS error and canceledError for a context error. The
// readers and ReadConfig set Untrusted.
func newFileError(path string, r reason) *FileError {
	return &FileError{Path: path, Reason: string(r)}
}

// inProject sets ProjectPath to project, the projects.<path> key of
// ~/.claude.json, and returns e. It changes e: call it only on a FileError
// that newFileError just returned.
func (e *FileError) inProject(project string) *FileError {
	e.ProjectPath = project
	return e
}

// forServer sets Server to name and returns e. It changes e: call it only on
// a FileError that newFileError just returned.
func (e *FileError) forServer(name string) *FileError {
	e.Server = name
	return e
}

// atOffset sets Line and Col to the position of the byte at offset in data
// (see lineCol) and returns e. It changes e: call it only on a FileError that
// newFileError just returned.
func (e *FileError) atOffset(data []byte, offset int) *FileError {
	e.Line, e.Col = lineCol(data, offset)
	return e
}

// readError returns the FileError of a read of path with the reason r and
// the OS error err (nil for none).
func readError(path string, r reason, err error) *FileError {
	fe := newFileError(path, r)
	fe.Err = err
	return fe
}

// canceledError returns the FileError for a read of path that stopped because
// the context ended. err is the context error, so errors.Is(fe,
// context.Canceled) and errors.Is(fe, context.DeadlineExceeded) work.
func canceledError(path string, err error) *FileError {
	return readError(path, reasonCanceled, err)
}

// errText returns the text of err for use in a FileError message. An
// *fs.PathError prints as "op path: errno", and the path is untrusted text
// that could hold terminal escape codes. So for a PathError we keep only the
// operation and the OS error. The path is already in FileError.Path, where
// termsafe.Quote quotes it. Other errors (for example context errors) have
// fixed text.
func errText(err error) string {
	if pe, ok := errors.AsType[*fs.PathError](err); ok && pe.Err != nil {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}

// maxDisplayRunes is the largest number of runes of a server name or a
// project key that a FileError message shows. A config file can hold a name
// of many KiB, and one such error must not fill the terminal.
const maxDisplayRunes = 200

// displayText returns a server name or a project key for a FileError
// message: termsafe.QuoteCut with the cap maxDisplayRunes. A longer text is
// cut, quoted when needed, and ends with termsafe.CutMarker.
func displayText(s string) string {
	return termsafe.QuoteCut(s, maxDisplayRunes)
}

// lineCol converts a byte offset in data to a 1-based line and a 1-based
// column. The column counts bytes, not characters. An offset outside data is
// clamped to the start or the end of data.
func lineCol(data []byte, offset int) (line, col int) {
	offset = min(max(offset, 0), len(data))
	before := data[:offset]
	line = bytes.Count(before, []byte{'\n'}) + 1
	col = offset - (bytes.LastIndexByte(before, '\n') + 1) + 1
	return line, col
}
