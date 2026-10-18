package report

import (
	"strconv"
	"unicode"
	"unicode/utf8"
)

// Escape returns s in a form that is safe to print in a terminal table cell.
//
// Config files are untrusted: a cloned repository can ship one. A server name,
// a command or a path from such a file can hold terminal escape sequences (ESC
// or C1 control characters), bidi or zero-width characters, tabs or newlines
// that would break a table cell, or invalid UTF-8. Escape returns s unchanged
// when it is valid UTF-8 and every rune is printable and is not a format
// character (Unicode category Cf). Otherwise it returns s as a quoted Go
// string, so each unsafe character shows as a visible escape such as \x1b or
// \u0085.
//
// unicode.IsPrint accepts only the ASCII space as a space. So a tab, a newline
// and a no-break space (U+00A0) also count as unsafe and cause quoting.
//
// Escape prevents terminal control. It does not prevent visual spoofing:
// combining marks (Unicode categories Mn and Me) and look-alike letters from
// other scripts (homoglyphs) pass unchanged.
//
// This is the same rule as displayText in internal/discover, which quotes the
// path and the server name in a FileError message. The two are copies, because
// discover must not import report. Keep the two in sync: TestEscapeMatchesFileError
// checks it.
func Escape(s string) string {
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
