package rules

import (
	"fmt"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// mixedScript flags each word of raw that mixes Latin letters with letters
// of a script that has look-alikes of Latin letters, such as Cyrillic or
// Greek. normalizeForMatch does not fold look-alike letters from other
// scripts, so "Ignore" with a Cyrillic "I" (U+0406) gets past the regex
// rules. This heuristic flags such a word.
//
// It reads the full raw text in one pass, with no size cut. A word is a
// longest run of letters, marks (see unicode.IsMark) and invisible runes (see
// isInvisible). Any other rune ends a word: a digit, '_', '-', an apostrophe,
// a punctuation rune or a space. An invalid UTF-8 byte decodes to U+FFFD,
// which is not a letter, so it also ends a word. So a ZWSP or a combining
// mark cannot split a word in two.
//
// JSON escapes are decoded, so the heuristic reads the raw JSON of a schema
// as it reads the decoded text. A JSON escape here is a backslash and one of
// b, f, n, r, t, '\\', '"' and '/', or a backslash, a 'u' and exactly 4 hex
// digits (see jsonEscape). A high surrogate escape directly followed by a
// low surrogate escape is one rune. A lone surrogate escape decodes to
// U+FFFD, so it ends a word. The decoded rune counts as a raw rune at the
// offset of the backslash, and all bytes of the escape are skipped. So the
// escape of U+0406 is a Cyrillic letter in the word, the escape of U+0001
// (an invisible rune) joins the word, and the escapes of a newline and of a
// backslash end the word. Any other backslash is a normal rune that ends a
// word.
//
// Each letter counts for its own script: unicode.Latin, unicode.Cyrillic,
// unicode.Greek, or one of the other look-alike scripts (see
// lookalikeScript): unicode.Armenian, unicode.Cherokee, unicode.Lisu,
// unicode.Coptic, unicode.Canadian_Aboriginal and unicode.Tifinagh. So
// Armenian small oh (U+0585), Coptic small o (U+2C9F), Lisu letter ga
// (U+A4D6) and Cherokee letter v (U+13A5) count for their scripts. A
// letter of the Common or Inherited script counts by its fold, the same
// fold the regex rules use (see appendFold). Each letter of
// the fold counts for its own script. So the mathematical Greek letters
// (U+1D6A8 to U+1D7CB) and the double-struck Greek letters (U+213C to
// U+213F) count as Greek, the mathematical Latin letters (such as U+1D400)
// count as Latin, and U+00B5 (micro sign) counts as Greek small mu. A letter
// of the Common or Inherited script with no usable fold, and a letter of a
// script not in the list above, count for no script but stay part of the
// word.
//
// A word is flagged when it has:
//
//   - Latin and Cyrillic letters, always;
//   - Latin letters and letters of one of the other look-alike scripts,
//     always;
//   - Latin and Greek letters, except for a unit (see
//     wordState.greekExcused): exactly one Greek letter, that letter is small
//     mu (U+03BC), capital Omega (U+03A9) or the ohm sign (U+2126), it is the
//     first or the last letter of the word, and the word comes directly after
//     an ASCII digit, or after one space rune that comes directly after an
//     ASCII digit. So "5" + mu + "s", "5 " + mu + "s" and "10k" + Omega are
//     not flagged. But mu + "s" with no digit before it, "D" + small sigma
//     and U+0394 (capital Delta) + "t" are flagged.
//
// A word with no Latin letter is never flagged. The Detail names the
// scripts that count toward the flag in this order: Latin, Cyrillic, Greek,
// then the first other look-alike script of the word, such as "Latin and
// Lisu" or "Latin, Cyrillic and Armenian". It names Greek only when the
// Greek letters count toward the flag. So a word with Latin, Cyrillic and
// one excused Greek letter gives "Latin and Cyrillic".
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
//   - Latin-script look-alikes that do not fold, such as U+0131 (dotless i),
//     U+0261 (script g) and the small capitals from U+1D00;
//   - look-alikes from scripts that are not in the list above, such as the
//     Ethiopic syllable U+12D0, which looks like an "O";
//   - one mu or Omega at the start or the end of a word that comes after a
//     digit, such as "5" + mu + "ser";
//   - a visible rune that is not a letter between the two parts of a word,
//     as it splits the word. Examples are U+FFFD from an invalid UTF-8 byte
//     and U+2800 (braille pattern blank), which is not a letter.
//
// The escape decoding also runs on description text. So a literal
// backslash sequence in a description, such as a backslash and a "t", is
// read as a tab.
func mixedScript(raw string) []Hit {
	var l hitList
	var w wordState
	// end flags the current word when it mixes scripts. Then it clears w for
	// the next word.
	end := func() {
		if scripts := w.mixedScripts(); scripts != "" && l.keep(w.start) {
			l.hits = append(l.hits, Hit{Offset: w.start, Detail: fmt.Sprintf("word at offset %d mixes %s letters", w.start, scripts)})
		}
		w = wordState{fold: w.fold[:0]} // keep the fold buffer for the next word
	}
	// prev1 is the rune just before offset i, and prev2 is the rune before
	// prev1. They tell whether a word comes after a number (see
	// followsDigit). -1 means no rune.
	prev1, prev2 := rune(-1), rune(-1)
	for i := 0; i < len(raw); {
		var r rune
		size := 0
		if raw[i] == '\\' {
			r, size = jsonEscape(raw[i:])
		}
		if size == 0 {
			// An invalid byte gives utf8.RuneError (U+FFFD), which ends a word.
			r, size = utf8.DecodeRuneInString(raw[i:])
		}
		if unicode.IsLetter(r) || unicode.IsMark(r) || isInvisible(r) {
			if !w.started {
				w.afterDigit = followsDigit(prev1, prev2)
			}
			w.add(i, r)
		} else {
			end()
		}
		prev2, prev1 = prev1, r
		i += size
	}
	end()
	return l.result("mixed-script words")
}

// followsDigit reports whether a word whose two previous runes are prev1
// (the nearer one) and prev2 comes directly after an ASCII digit, or after
// one space rune that comes directly after an ASCII digit. A space rune is a
// rune of unicode.IsSpace. It covers the no-break space (U+00A0), the thin
// space (U+2009) and the narrow no-break space (U+202F), which texts put
// between a number and its unit.
func followsDigit(prev1, prev2 rune) bool {
	return isASCIIDigit(prev1) || unicode.IsSpace(prev1) && isASCIIDigit(prev2)
}

// isASCIIDigit reports whether r is 0-9.
func isASCIIDigit(r rune) bool {
	return '0' <= r && r <= '9'
}

// wordState holds what mixedScript knows about the current word. It uses
// counts and fixed fields, not a slice per word, so a word costs no memory.
type wordState struct {
	started    bool // the word has at least one rune
	start      int  // byte offset of the first rune of the word
	afterDigit bool // the word comes after a digit (see followsDigit)

	letters  int // letters of any script
	latin    int // Latin letters
	cyrillic int // Cyrillic letters
	greek    int // Greek letters

	// other counts the letters of the other look-alike scripts (see
	// lookalikeScript), and otherName is the name of the first such script
	// in the word.
	other     int
	otherName string

	greekLetter      rune // the last Greek letter; the only one when greek == 1
	firstLetterGreek bool // the first letter of the word is Greek
	lastLetterGreek  bool // the last letter so far is Greek

	// fold is a scratch buffer for addFolded. mixedScript keeps it from one
	// word to the next, so a scan allocates it at most once.
	fold []byte
}

// add adds the rune r at byte offset i to the word. r is a letter, a mark or
// an invisible rune. Only a letter counts for a script (see addLetter).
func (w *wordState) add(i int, r rune) {
	if !w.started {
		w.started = true
		w.start = i
	}
	if unicode.IsLetter(r) { // a mark or an invisible rune joins the word but is not a letter
		w.addLetter(r, true)
	}
}

// addLetter counts the letter r for its own script, if that script is
// Latin, Cyrillic, Greek or one of the other look-alike scripts (see
// lookalikeScript). When fold is true and r is of the Common or Inherited
// script, r counts by its fold instead (see addFolded).
func (w *wordState) addLetter(r rune, fold bool) {
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
	case lookalikeScript(r) != "":
		if w.other == 0 {
			w.otherName = lookalikeScript(r)
		}
		w.other++
	case fold && unicode.In(r, unicode.Common, unicode.Inherited):
		w.addFolded(r)
		return
	}
	if w.letters == 0 {
		w.firstLetterGreek = isGreek
	}
	w.lastLetterGreek = isGreek
	w.letters++
}

// addFolded adds the letter r of the Common or Inherited script by its fold
// (see appendFold). Each letter of the fold counts as one letter of its own
// script. When the fold does not change r, or holds no letter, r counts as
// one letter of no script.
func (w *wordState) addFolded(r rune) {
	var enc [utf8.UTFMax]byte
	rs := enc[:utf8.EncodeRune(enc[:], r)]
	fold := appendFold(w.fold[:0], r, string(rs))
	w.fold = fold
	if string(fold) == string(rs) {
		w.addLetter(r, false)
		return
	}
	counted := false
	for _, f := range string(fold) {
		if unicode.IsLetter(f) {
			w.addLetter(f, false)
			counted = true
		}
	}
	if !counted {
		w.addLetter(r, false)
	}
}

// lookalikeScript returns the name of the script of the letter r when that
// script is one of the other scripts with letters that look like Latin
// letters: Armenian, Cherokee, Lisu, Coptic, Canadian Aboriginal or
// Tifinagh. It returns "" for any other rune.
func lookalikeScript(r rune) string {
	switch {
	case unicode.Is(unicode.Armenian, r):
		return "Armenian"
	case unicode.Is(unicode.Cherokee, r):
		return "Cherokee"
	case unicode.Is(unicode.Lisu, r):
		return "Lisu"
	case unicode.Is(unicode.Coptic, r):
		return "Coptic"
	case unicode.Is(unicode.Canadian_Aboriginal, r):
		return "Canadian Aboriginal"
	case unicode.Is(unicode.Tifinagh, r):
		return "Tifinagh"
	}
	return ""
}

// mixedScripts returns the scripts that make the word suspect, such as
// "Latin and Cyrillic" or "Latin, Cyrillic and Coptic", or "" when the word
// is not flagged. The names come in this order: Latin, Cyrillic, Greek, then
// the first other look-alike script of the word.
func (w *wordState) mixedScripts() string {
	if w.latin == 0 {
		return ""
	}
	names := [4]string{"Latin"}
	n := 1
	if w.cyrillic > 0 {
		names[n] = "Cyrillic"
		n++
	}
	if w.greek > 0 && !w.greekExcused() {
		names[n] = "Greek"
		n++
	}
	if w.other > 0 {
		names[n] = w.otherName
		n++
	}
	if n < 2 {
		return ""
	}
	return joinNames(names[:n])
}

// joinNames joins two or more script names: "A and B", "A, B and C".
func joinNames(names []string) string {
	s := names[0]
	for i := 1; i < len(names); i++ {
		sep := ", "
		if i == len(names)-1 {
			sep = " and "
		}
		s += sep + names[i]
	}
	return s
}

// greekExcused reports whether the Greek letters of the word are one unit
// letter (see isUnitGreek) at the start or the end of a word that comes
// after a digit (see followsDigit), such as the ohm (U+03A9) in "10k" +
// U+03A9.
func (w *wordState) greekExcused() bool {
	atEdge := w.firstLetterGreek || w.lastLetterGreek
	return w.greek == 1 && atEdge && w.afterDigit && isUnitGreek(w.greekLetter)
}

// isUnitGreek reports whether r is a Greek letter that texts use as a unit
// after a number: small mu (U+03BC, micro, also the fold of the micro sign
// U+00B5), capital Omega (U+03A9, ohm) or the ohm sign (U+2126).
func isUnitGreek(r rune) bool {
	return r == '\u03BC' || r == '\u03A9' || r == '\u2126'
}

// jsonEscape decodes the JSON escape at the start of s. It returns the rune
// and the length of the escape in bytes, or a length of 0 when s does not
// start with an escape. A JSON escape here is:
//
//   - a backslash and one of b, f, n, r, t, '\\', '"' and '/' (2 bytes),
//     which gives U+0008, U+000C, a newline, a carriage return, a tab, or
//     the ASCII rune itself;
//   - a backslash, a 'u' and exactly 4 hex digits (6 bytes), which gives
//     that code point;
//   - a high surrogate escape (D800 to DBFF) directly followed by a low
//     surrogate escape (DC00 to DFFF) (12 bytes), which gives the rune of the
//     pair. Any other surrogate escape is a lone surrogate. It gives
//     utf8.RuneError (6 bytes).
//
// The escaped backslash is an escape too, so the caller skips both of its
// bytes: the second backslash cannot start a new escape with the byte after
// it.
func jsonEscape(s string) (rune, int) {
	if len(s) < 2 || s[0] != '\\' {
		return 0, 0
	}
	switch s[1] {
	case 'b':
		return '\b', 2
	case 'f':
		return '\f', 2
	case 'n':
		return '\n', 2
	case 'r':
		return '\r', 2
	case 't':
		return '\t', 2
	case '\\', '"', '/':
		return rune(s[1]), 2
	case 'u':
		hi, ok := hex4(s[2:])
		if !ok {
			return 0, 0
		}
		if !utf16.IsSurrogate(hi) {
			return hi, 6
		}
		if hi < 0xDC00 && len(s) >= 12 && s[6] == '\\' && s[7] == 'u' {
			if lo, ok := hex4(s[8:]); ok && 0xDC00 <= lo && lo <= 0xDFFF {
				return utf16.DecodeRune(hi, lo), 12
			}
		}
		return utf8.RuneError, 6 // a lone surrogate
	}
	return 0, 0
}

// hex4 reads the first 4 bytes of s as hex digits. It returns false when s
// is shorter than 4 bytes or one of the 4 bytes is not a hex digit.
func hex4(s string) (rune, bool) {
	if len(s) < 4 {
		return 0, false
	}
	var v rune
	for _, c := range []byte(s[:4]) {
		var d byte
		switch {
		case '0' <= c && c <= '9':
			d = c - '0'
		case 'a' <= c && c <= 'f':
			d = c - 'a' + 10
		case 'A' <= c && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		v = v<<4 | rune(d)
	}
	return v, true
}
