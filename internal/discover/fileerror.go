package discover

import (
	"bytes"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
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
// callers outside the package read. Convert a reason value with string(r)
// when you set FileError.Reason.
//
// Add every new reason to allReasons in fileerror_test.go too.
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
	reasonBadString        = "invalid string"        // a lone UTF-16 surrogate escape or invalid UTF-8
	reasonNotFound         = "file not found"        // ReadConfig: a file the user named does not exist
	reasonUnknownFormat    = "unknown config format" // ReadConfig: a file the user named has no known client format
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
	// Untrusted is true when the problem is in a project file that Discover
	// read from the working directory (<WorkDir>/.mcp.json or
	// <WorkDir>/.cursor/mcp.json). A cloned repository can ship that file. If
	// mcpmoat cannot read it, it can hide servers that the client still loads.
	// So a caller must not treat such an error as a harmless warning: the
	// scan command exits with code 2. Untrusted is false for the user's own
	// files: ~/.claude.json (also for its projects.<path> entries), the
	// global Cursor file and the Codex file.
	Untrusted bool
}

var _ error = (*FileError)(nil)

// Error returns the message in the form
// "<path>[:<line>[:<col>]]: [project <path>: ][server <name>: ]<reason>[: <Err>]".
// Path, project path and server name are untrusted text, so displayText quotes them when
// they hold unprintable characters.
func (e *FileError) Error() string {
	var b strings.Builder
	b.WriteString(displayText(e.Path))
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

// canceledError returns the FileError for a read of path that stopped because
// the context ended. err is the context error, so errors.Is(fe,
// context.Canceled) and errors.Is(fe, context.DeadlineExceeded) work.
func canceledError(path string, err error) *FileError {
	return &FileError{Path: path, Reason: reasonCanceled, Err: err}
}

// errText returns the text of err for use in a FileError message.
// An *fs.PathError prints as "op path: errno", and the path is untrusted text
// that could hold terminal escape codes. So for a PathError we keep only the
// operation and the OS error. The path is already in FileError.Path, where
// displayText quotes it. Other errors (for example context errors) have fixed text.
func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) && pe.Err != nil {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}

// displayText returns s unchanged if every rune is printable and none is a
// format or bidi control character. Otherwise it returns s as a quoted Go
// string, which escapes those characters.
//
// Keep in sync with report.Escape (checked by a test in internal/report).
func displayText(s string) string {
	// Ranging over bad bytes yields U+FFFD, which is printable, so check validity first.
	if !utf8.ValidString(s) {
		return strconv.Quote(s)
	}
	for _, r := range s {
		if !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) {
			return strconv.Quote(s)
		}
	}
	return s
}

// lineCol converts a byte offset in data to a 1-based line and a 1-based
// column. The column counts bytes, not characters. An offset outside data is
// clamped to the start or the end of data.
func lineCol(data []byte, offset int64) (line, col int) {
	if offset < 0 {
		offset = 0
	}
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	before := data[:offset]
	line = bytes.Count(before, []byte{'\n'}) + 1
	col = int(offset) - (bytes.LastIndexByte(before, '\n') + 1) + 1
	return line, col
}
