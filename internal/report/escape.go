package report

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Escape returns s in a form that is safe to print in a terminal table cell.
//
// Config files are untrusted: a cloned repository can ship one. A server name,
// a command or a path from such a file can hold terminal escape sequences (ESC
// or C1 control characters), bidi or zero-width characters, tabs or newlines
// that would break a table cell, invisible runes, or invalid UTF-8. Escape
// returns s unchanged when it is valid UTF-8 and every rune is visible (see
// needsEscape). Otherwise it returns s as a quoted Go string, so each unsafe
// character shows as a visible escape such as \x1b, \u0085 or ㅤ.
//
// unicode.IsPrint accepts only the ASCII space as a space. So a tab, a newline
// and a no-break space (U+00A0) also count as unsafe and cause quoting.
//
// Escape prevents terminal control and makes invisible runes visible. It does
// not prevent visual spoofing with look-alike letters from other scripts
// (homoglyphs): they pass unchanged.
//
// Escape does not cut s: the caller cuts a cell before it escapes it.
//
// This is the same rule as displayPath in internal/discover, which quotes the
// path, and the server name after a cut, in a FileError message. The two are
// copies, because discover must not import report. Keep the two in sync:
// TestEscapeMatchesFileError checks it.
func Escape(s string) string {
	if !needsQuote(s) {
		return s
	}
	return quoteText(s)
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
	case 'ᅟ', 'ᅠ', 'ㅤ', 'ﾠ', '⠀':
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
