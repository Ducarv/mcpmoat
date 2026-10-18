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
	// repository can ship. The readers set it by scope, and Discover sets it
	// on the canceled error of a project step. See the package doc, Untrusted
	// files. Like every FileError, it means that servers may be missing.
	Untrusted bool
}

var _ error = (*FileError)(nil)

// Error returns the message in the form
// "<path>[:<line>[:<col>]]: [project <path>: ][server <name>: ]<reason>[: <Err>]".
// Path, project path and server name are untrusted text. displayPath and
// displayText quote them when they hold characters that are not visible, and
// displayText cuts a long project path or server name.
func (e *FileError) Error() string {
	var b strings.Builder
	b.WriteString(displayPath(e.Path))
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
// readers set Untrusted.
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

// canceledError returns the FileError for a read of path that stopped because
// the context ended. err is the context error, so errors.Is(fe,
// context.Canceled) and errors.Is(fe, context.DeadlineExceeded) work.
func canceledError(path string, err error) *FileError {
	fe := newFileError(path, reasonCanceled)
	fe.Err = err
	return fe
}

// errText returns the text of err for use in a FileError message.
// An *fs.PathError prints as "op path: errno", and the path is untrusted text
// that could hold terminal escape codes. So for a PathError we keep only the
// operation and the OS error. The path is already in FileError.Path, where
// displayPath quotes it. Other errors (for example context errors) have fixed text.
func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) && pe.Err != nil {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}

// maxDisplayRunes is the largest number of runes of a server name or a
// project key that a FileError message shows. A config file can hold a name
// of many KiB, and one such error must not fill the terminal.
const maxDisplayRunes = 200

// cutMark ends a text that displayText cut.
const cutMark = "..."

// displayText returns a server name or a project key for a FileError
// message. A text with more than maxDisplayRunes runes is cut to that many
// runes, and cutMark is added at the end. The cut is made before the quoting,
// at a rune boundary, so it never splits an escape. Then the text is quoted
// as displayPath does it. cutMark comes after the closing quote of a quoted
// text. An invalid UTF-8 byte counts as one rune.
func displayText(s string) string {
	s, cut := cutRunes(s, maxDisplayRunes)
	s = displayPath(s)
	if cut {
		s += cutMark
	}
	return s
}

// displayPath returns s unchanged if every rune of s is visible. Otherwise it
// returns s as a quoted Go string in which every rune that is not visible is
// escaped (see needsEscape). It does not cut s: the path is needed in full to
// find the file.
func displayPath(s string) string {
	if !needsQuote(s) {
		return s
	}
	return quoteText(s)
}

// cutRunes returns the first n runes of s, and true if s had more runes.
// An invalid UTF-8 byte counts as one rune.
func cutRunes(s string, n int) (string, bool) {
	i := 0
	for count := 0; i < len(s); count++ {
		if count == n {
			return s[:i], true
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return s, false
}

// needsQuote reports whether s holds invalid UTF-8 or a rune for which
// needsEscape is true.
func needsQuote(s string) bool {
	// Ranging over bad bytes yields U+FFFD, which is printable, so check validity first.
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if needsEscape(r) {
			return true
		}
	}
	return false
}

// needsEscape reports whether r is not visible, or can change how the text
// around it looks: a rune that is not printable, a format or bidi control
// character (Cf), or a rune for which isBlank is true.
func needsEscape(r rune) bool {
	return !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) || isBlank(r)
}

// isBlank reports whether r is printable for unicode.IsPrint but shows as
// nothing, or changes the rune before it: a Hangul filler (U+115F, U+1160,
// U+3164, U+FFA0), the blank braille pattern (U+2800), or a combining mark
// (categories Mn and Me, which hold the variation selectors). strconv.Quote
// keeps these runes as they are, so quoteText escapes them itself.
func isBlank(r rune) bool {
	switch r {
	case '\u115f', '\u1160', '\u3164', '\uffa0', '\u2800':
		return true
	}
	return unicode.In(r, unicode.Mn, unicode.Me)
}

// quoteText returns s as a quoted Go string. It escapes like strconv.Quote,
// and it also escapes every rune for which isBlank is true as \uXXXX or
// \UXXXXXXXX.
func quoteText(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	start := 0 // start of the part that is not written yet
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		// An invalid byte gives utf8.RuneError, which isBlank rejects, so a
		// split is always at a full rune.
		if isBlank(r) {
			writeQuotedPart(&b, s[start:i])
			writeRuneEscape(&b, r)
			start = i + size
		}
		i += size
	}
	writeQuotedPart(&b, s[start:])
	b.WriteByte('"')
	return b.String()
}

// writeQuotedPart writes s as strconv.Quote escapes it, without the quotes.
// strconv.Quote escapes each rune on its own, so the parts of a text that is
// split at rune boundaries give the same escapes as the whole text.
func writeQuotedPart(b *strings.Builder, s string) {
	if s == "" {
		return
	}
	q := strconv.Quote(s)
	b.WriteString(q[1 : len(q)-1])
}

// writeRuneEscape writes r as \uXXXX, or as \UXXXXXXXX for a rune above
// U+FFFF, with lowercase hex digits as strconv.Quote writes them.
func writeRuneEscape(b *strings.Builder, r rune) {
	prefix, width := `\u`, 4
	if r > 0xffff {
		prefix, width = `\U`, 8
	}
	hex := strconv.FormatInt(int64(r), 16)
	b.WriteString(prefix)
	b.WriteString(strings.Repeat("0", width-len(hex)))
	b.WriteString(hex)
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
