package rules

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

// mixedScript flags each word of raw that mixes Latin letters with Cyrillic
// or Greek letters. normalizeForMatch does not fold look-alike letters from
// other scripts, so "Ignore" with a Cyrillic "I" (U+0406) gets past the regex
// rules. This heuristic flags such a word.
//
// It reads the full raw text in one pass, with no size cut. A word is a
// longest run of letters, marks (see unicode.IsMark) and invisible runes (see
// isInvisible). Any other rune ends a word: a digit, '_', '-', an apostrophe,
// a punctuation rune or a space. An invalid UTF-8 byte also ends a word. So a
// ZWSP or a combining mark cannot split a word in two.
//
// A JSON escape also ends a word, so the heuristic works on the raw JSON of a
// schema too. A JSON escape here is a backslash and one of b, f, n, r, t,
// '\\', '"' and '/', or a backslash, a 'u' and exactly 4 hex digits (see
// jsonEscapeLen). The whole escape is skipped. So in the raw JSON text
// a\\nb (an escaped backslash, then "nb") the "n" stays in the word "nb".
// Any other backslash is a normal rune that ends a word.
//
// Each letter counts for its own script (unicode.Latin, unicode.Cyrillic or
// unicode.Greek), read from the raw rune, not from a folded rune. A letter of
// any other script, or of the Common or Inherited script, counts for no
// script but stays part of the word. So U+00B5 (micro sign, Common) is not
// Greek.
//
// A word is flagged when it has:
//
//   - Latin and Cyrillic letters, always;
//   - Latin and Greek letters, except when the word has exactly one Greek
//     letter, that letter is the first or the last letter of the word (marks
//     and invisible runes do not count), and it is a symbol letter that does
//     not look like a Latin letter (see isGreekSymbol). So "10k" + U+03A9 and
//     U+0394 + "x" are not flagged, but U+0391 (Greek capital alpha) +
//     "dmin" is.
//
// Cyrillic and Greek letters without a Latin letter are not flagged. The
// Detail names Greek only when the Greek letters count toward the flag. So
// a word with Latin, Cyrillic and one excused Greek letter gives "Latin and
// Cyrillic".
//
// The hit is at the byte offset of the first rune of the word. The Detail
// never holds the word: the terminal-safe output does not change look-alike
// letters, so the word would show as normal Latin text.
//
// Limits. These are not flagged:
//
//   - a word written fully in look-alikes of one script, such as Cyrillic
//     "copy" (U+0441 U+043E U+0440 U+0443);
//   - a word of one letter, as it cannot mix two scripts;
//   - Latin-script look-alikes, such as U+0131 (dotless i), U+0261 (script
//     g) and the small capitals from U+1D00;
//   - look-alikes from other scripts, such as Armenian, Cherokee and Coptic;
//   - one allowlisted Greek letter at the start or the end of a word;
//   - mathematical letters of the Common script, such as U+1D400. They count
//     for no script, but the regex fold already maps them to ASCII.
func mixedScript(raw string) []Hit {
	var l hitList
	var w wordState
	// end flags the current word when it mixes scripts. Then it clears w for
	// the next word.
	end := func() {
		if scripts := w.mixedScripts(); scripts != "" && l.keep(w.start) {
			l.hits = append(l.hits, Hit{Offset: w.start, Detail: fmt.Sprintf("word at offset %d mixes %s letters", w.start, scripts)})
		}
		w = wordState{}
	}
	for i := 0; i < len(raw); {
		if n := jsonEscapeLen(raw[i:]); n > 0 {
			end()
			i += n
			continue
		}
		r, size := utf8.DecodeRuneInString(raw[i:])
		invalid := r == utf8.RuneError && size == 1
		if !invalid && (unicode.IsLetter(r) || unicode.IsMark(r) || isInvisible(r)) {
			w.add(i, r)
		} else {
			end()
		}
		i += size
	}
	end()
	return l.result("mixed-script words")
}

// wordState holds what mixedScript knows about the current word. It uses
// counts and fixed fields, not a slice, so a word costs no memory.
type wordState struct {
	started bool // the word has at least one rune
	start   int  // byte offset of the first rune of the word

	letters  int // letters of any script
	latin    int // Latin letters
	cyrillic int // Cyrillic letters
	greek    int // Greek letters

	greekLetter      rune // the last Greek letter; the only one when greek == 1
	firstLetterGreek bool // the first letter of the word is Greek
	lastLetterGreek  bool // the last letter so far is Greek
}

// add adds the rune r at byte offset i to the word. r is a letter, a mark or
// an invisible rune. Only a letter counts for a script.
func (w *wordState) add(i int, r rune) {
	if !w.started {
		w.started = true
		w.start = i
	}
	if !unicode.IsLetter(r) {
		return // a mark or an invisible rune joins the word but is not a letter
	}
	isGreek := false
	switch {
	case unicode.Is(unicode.Latin, r):
		w.latin++
	case unicode.Is(unicode.Cyrillic, r):
		w.cyrillic++
	case unicode.Is(unicode.Greek, r):
		w.greek++
		w.greekLetter = r
		isGreek = true
	}
	if w.letters == 0 {
		w.firstLetterGreek = isGreek
	}
	w.lastLetterGreek = isGreek
	w.letters++
}

// mixedScripts returns the scripts that make the word suspect, such as
// "Latin and Cyrillic", or "" when the word is not flagged.
func (w *wordState) mixedScripts() string {
	if w.latin == 0 {
		return ""
	}
	greekCounts := w.greek > 0 && !w.greekExcused()
	switch {
	case w.cyrillic > 0 && greekCounts:
		return "Latin, Cyrillic and Greek"
	case w.cyrillic > 0:
		return "Latin and Cyrillic"
	case greekCounts:
		return "Latin and Greek"
	}
	return ""
}

// greekExcused reports whether the Greek letters of the word are one symbol
// letter at the start or the end of the word, such as the ohm (U+03A9) in
// "10k" + U+03A9.
func (w *wordState) greekExcused() bool {
	atEdge := w.firstLetterGreek || w.lastLetterGreek
	return w.greek == 1 && atEdge && isGreekSymbol(w.greekLetter)
}

// isGreekSymbol reports whether r is a Greek letter that texts often use as
// a unit or a math symbol and that does not look like a Latin letter. Alpha
// (U+03B1) is not one: it looks like a Latin "a".
func isGreekSymbol(r rune) bool {
	switch r {
	case '\u03BC', // small mu: micro, as in "5us"
		'\u03A9', // capital omega: ohm
		'\u2126', // ohm sign (Greek script)
		'\u0394', // capital delta
		'\u03B4', // small delta
		'\u03BB', // small lambda
		'\u03C0', // small pi
		'\u03B8', // small theta
		'\u03C3', // small sigma
		'\u03A3', // capital sigma
		'\u03C6', // small phi
		'\u03C9', // small omega
		'\u03B2', // small beta
		'\u03B3': // small gamma
		return true
	}
	return false
}

// jsonEscapeLen returns the length in bytes of the JSON escape at the start of
// s, or 0 when s does not start with one. A JSON escape here is a backslash
// and one of b, f, n, r, t, '\\', '"' and '/' (2 bytes), or a backslash, a
// 'u' and exactly 4 hex digits (6 bytes). The escaped backslash is an escape
// too, so the caller skips both of its bytes: the second backslash cannot
// start a new escape with the byte after it.
func jsonEscapeLen(s string) int {
	if len(s) < 2 || s[0] != '\\' {
		return 0
	}
	switch s[1] {
	case 'b', 'f', 'n', 'r', 't', '\\', '"', '/':
		return 2
	case 'u':
		if len(s) >= 6 && isHexDigit(s[2]) && isHexDigit(s[3]) && isHexDigit(s[4]) && isHexDigit(s[5]) {
			return 6
		}
	}
	return 0
}
