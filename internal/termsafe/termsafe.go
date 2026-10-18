// Package termsafe makes untrusted text safe to print in a terminal.
//
// Config files are untrusted: a cloned repository can ship one. A server name,
// a command, a project key or a path from such a file can hold terminal escape
// sequences (ESC or C1 control characters), bidi or zero-width characters,
// tabs or newlines, runes that show as nothing, or invalid UTF-8.
//
// This package holds the one rule for every place that prints such text.
// internal/discover uses it for the paths, project keys and server names in a
// FileError message, internal/report uses it for every cell of the server
// table, and cmd/mcpmoat uses it for the arguments in an error message. Keep
// the rule here only, so these places cannot drift apart.
//
// The package uses only the standard library and imports no other package of
// this module, so every package can import it.
package termsafe

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Quote returns s unchanged when s is valid UTF-8, every rune of s is safe to
// print, and s does not start with a double quote ("). Otherwise it returns s
// as a quoted Go string, so each unsafe character shows as a visible escape
// such as \x1b, \u0085 or \u3164.
//
// A text that starts with a double quote is quoted too, and its quotes show
// as \". So an output that starts with a double quote is always a quoted
// text, and a plain text can never look like a quoted one. A backslash alone
// does not make s quoted, so a Windows path stays as it is.
//
// A rune is not safe when it:
//
//   - is not printable for unicode.IsPrint: a control character (C0 such as
//     a tab or a newline, C1, DEL), an unassigned or private-use code point,
//     or a space other than the ASCII space (Zs, Zl, Zp: for example U+00A0,
//     U+3000 or U+2028);
//   - is a format character (Cf), which holds the bidi controls, the
//     zero-width characters and the tag characters;
//   - is a combining mark (Mn or Me, which hold the variation selectors);
//   - is a blank rune that unicode.IsPrint accepts but that shows as nothing:
//     a Hangul filler (U+115F, U+1160, U+3164, U+FFA0) or the blank braille
//     pattern (U+2800).
//
// The quoted form escapes like strconv.Quote, and it also escapes the
// combining marks and the blank runes, which strconv.Quote keeps as they are,
// as \uXXXX or \UXXXXXXXX.
//
// The output maps back to s in one way only: strconv.Unquote of a quoted
// result gives s back, and an unquoted result is s itself.
//
// Quote prevents terminal control and makes invisible runes visible. It does
// not prevent visual spoofing with look-alike letters from other scripts
// (homoglyphs): they pass unchanged.
//
// Quote does not cut s. Use QuoteCut to cut and quote in one step.
func Quote(s string) string {
	return QuoteIf(s, false)
}

// QuoteIf returns Quote(s), and it also quotes a safe s when force is true.
// So the result is s unchanged only when force is false and Quote keeps s.
//
// Use it when a caller has its own reason to quote a safe text: for example,
// to show where a command-line argument starts and ends, or to keep a table
// cell with a space from looking like two cells. A forced result is never
// mixed up with a plain one: it starts with a double quote, and a plain
// result never does.
//
// A forced quote of a safe text escapes only the double quotes and the
// backslashes in it. A safe text is valid UTF-8 with no rune that needs an
// escape, so the quoted form is the same as strconv.Quote gives, and
// strconv.Unquote gives s back. The caller does not need strconv.Quote.
func QuoteIf(s string, force bool) string {
	if force || needsQuote(s) {
		return quoteText(s)
	}
	return s
}

// CutMarker ends a text that QuoteCut cut. It is plain ASCII, so it shows the
// same in every terminal. A text can also end with "..." when it was not cut,
// but the marker can never hide text.
const CutMarker = "..."

// QuoteCut returns s cut to n runes (see Cut) and then quoted (see Quote).
// When s had more than n runes, CutMarker comes after the result, after the
// closing quote of a quoted text.
//
// The cut is made before Quote, so it never splits an escape, and Quote
// never escapes the marker. The part of s after the cut is not shown, so it
// does not make the text quoted.
//
// A caller that quotes with QuoteIf cuts with Cut, and adds CutMarker itself
// when Cut reports a cut, in the same order: cut, quote, marker.
func QuoteCut(s string, n int) string {
	short, cut := Cut(s, n)
	if cut {
		return Quote(short) + CutMarker
	}
	return Quote(short)
}

// Cut returns the first n runes of s, and true if s had more than n runes.
// The cut is always at a rune boundary. An invalid UTF-8 byte counts as one
// rune, as Quote shows it as one \xNN escape.
//
// Cut adds no marker and does not quote. QuoteCut cuts, quotes and adds
// CutMarker.
func Cut(s string, n int) (string, bool) {
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

// needsQuote reports whether s starts with a double quote, holds invalid
// UTF-8, or holds a rune for which needsEscape is true.
func needsQuote(s string) bool {
	if strings.HasPrefix(s, `"`) {
		return true
	}
	// Ranging over bad bytes yields U+FFFD, which is printable, so check
	// validity first.
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
	if r > 0xffff {
		_, _ = fmt.Fprintf(b, `\U%08x`, r) // a strings.Builder write never fails
		return
	}
	_, _ = fmt.Fprintf(b, `\u%04x`, r)
}
