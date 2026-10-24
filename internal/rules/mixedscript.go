package rules

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// mixedScript flags each word of raw that mixes letters of two or more
// look-alike scripts (see lookalikeScripts), such as "Ignore" with a Cyrillic
// "I" (U+0406). normalizeForMatch does not fold look-alike letters from other
// scripts, so such a word gets past the regex rules. The package doc
// (doc.go) holds the full rules for users: the unit exemption and the limits.
// This comment holds the implementation contract.
//
// It reads the full raw text in one pass, with no size cut. A word is a
// longest run of letters and of the runes that isWordFiller accepts: marks,
// invisible runes, private-use runes and unassigned code points. Any other
// rune ends a word. An invalid UTF-8 byte decodes to U+FFFD, a symbol, so it
// also ends a word.
//
// JSON escapes are decoded (see jsonEscape), so the heuristic reads the raw
// JSON of a schema as it reads the decoded text. The decoded rune counts as
// a raw rune at the offset of the backslash, and all bytes of the escape are
// skipped. Any other backslash is a normal rune that ends a word.
//
// Each letter counts for its own script. A letter of the Common or
// Inherited script counts by its fold (see wordState.addFolded). A letter of
// any other script counts for no script but stays part of the word. A word is
// flagged when its letters count for two or more scripts, after the unit
// exemption (see wordState.greekExcused).
//
// The hit is at the byte offset of the first rune of the word. The Detail
// names the scripts in the order of lookalikeScripts. It never holds the
// word: the terminal-safe output does not change look-alike letters, so the
// word would show as normal Latin text.
func mixedScript(raw string) []Hit {
	var l hitList
	var w wordState
	// end flags the current word when it mixes scripts. Then it clears w for
	// the next word.
	end := func() {
		if scripts := w.flaggedScripts(); scripts != "" && l.keep(w.start) {
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
		escaped := size > 0
		if !escaped {
			// An invalid byte gives utf8.RuneError (U+FFFD), which ends a word.
			r, size = utf8.DecodeRuneInString(raw[i:])
		}
		if isLetter := unicode.IsLetter(r); isLetter || isWordFiller(r) {
			if !w.started {
				w.started, w.start, w.afterDigit = true, i, followsDigit(prev1, prev2)
			}
			if isLetter {
				w.addLetter(r)
			}
		} else {
			end()
		}
		if escaped && isASCIIDigit(r) {
			// An escaped digit never comes before a unit. In a description
			// the model reads the escape text, such as \u0035, and the
			// schema JSON from the inspect package never escapes a digit.
			r = -1
		}
		prev2, prev1 = prev1, r
		i += size
	}
	end()
	return l.result("mixed-script words")
}

// isWordFiller reports whether r, a rune that is not a letter, joins a word:
// a mark (see unicode.IsMark), an invisible rune (see isInvisible), a
// private-use rune or an unassigned code point. Many fonts draw a private-use
// or unassigned rune as nothing, so it must not split a word either.
func isWordFiller(r rune) bool {
	if unicode.IsMark(r) || isInvisible(r) {
		return true
	}
	return r > unicode.MaxASCII && unicode.In(r, unicode.Co, unicode.Cn)
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

// lookalikeScripts lists the scripts that mixedScript counts, in the order
// that a Detail names them. Each has letters that look like Latin letters.
var lookalikeScripts = [...]struct {
	name  string
	table *unicode.RangeTable
}{
	{"Latin", unicode.Latin},
	{"Cyrillic", unicode.Cyrillic},
	{"Greek", unicode.Greek},
	{"Armenian", unicode.Armenian},
	{"Cherokee", unicode.Cherokee},
	{"Lisu", unicode.Lisu},
	{"Coptic", unicode.Coptic},
	{"Canadian Aboriginal", unicode.Canadian_Aboriginal},
	{"Tifinagh", unicode.Tifinagh},
}

// The indexes of Latin and Greek in lookalikeScripts.
const (
	latinScript = 0
	greekScript = 2
)

// scriptOf returns the index in lookalikeScripts of the script of r, or -1
// when r is of no script in the list.
func scriptOf(r rune) int {
	for i, s := range lookalikeScripts {
		if unicode.Is(s.table, r) {
			return i
		}
	}
	return -1
}

// wordState holds what mixedScript knows about the current word. It uses
// counts and fixed fields, not a slice per word, so a word costs no memory.
type wordState struct {
	started    bool // the word has at least one rune
	start      int  // byte offset of the first rune of the word
	afterDigit bool // the word comes after a digit (see followsDigit)

	letters int    // letters of any script
	scripts uint16 // bit i is set when a letter counts for lookalikeScripts[i]

	greek            int  // Greek letters
	greekLetter      rune // the last Greek letter; the only one when greek == 1
	firstLetterGreek bool // the first letter of the word is Greek
	lastLetterGreek  bool // the last letter so far is Greek

	// latin holds the first Latin letters of the word, for greekExcused.
	// nLatin counts all Latin letters. When it is more than len(latin), the
	// word is too long to be a unit.
	latin  [3]rune
	nLatin int

	// fold is a scratch buffer for addFolded. mixedScript keeps it from one
	// word to the next, so a scan allocates it at most once.
	fold []byte
}

// addLetter adds the letter r to the word. A letter of the Common or
// Inherited script counts by its fold (see addFolded). Any other letter
// counts for its own script (see countLetter).
func (w *wordState) addLetter(r rune) {
	i := scriptOf(r)
	if i < 0 && unicode.In(r, unicode.Common, unicode.Inherited) {
		w.addFolded(r)
		return
	}
	w.countLetter(r, i)
}

// addFolded adds the letter r of the Common or Inherited script by its fold
// (see appendFold). Each letter of the fold counts as one letter of its own
// script, with no second fold. When the fold does not change r, or holds no
// letter, r counts as one letter of no script.
func (w *wordState) addFolded(r rune) {
	rs := string(r)
	w.fold = appendFold(w.fold[:0], r, rs)
	if string(w.fold) == rs {
		w.countLetter(r, -1)
		return
	}
	counted := false
	for _, f := range string(w.fold) {
		if unicode.IsLetter(f) {
			w.countLetter(f, scriptOf(f))
			counted = true
		}
	}
	if !counted {
		w.countLetter(r, -1)
	}
}

// countLetter counts the letter r for the script lookalikeScripts[i], or
// for no script when i is -1.
func (w *wordState) countLetter(r rune, i int) {
	if i >= 0 {
		w.scripts |= 1 << i
	}
	if i == latinScript {
		if w.nLatin < len(w.latin) {
			w.latin[w.nLatin] = r
		}
		w.nLatin++
	}
	isGreek := i == greekScript
	if isGreek {
		w.greek++
		w.greekLetter = r
	}
	if w.letters == 0 {
		w.firstLetterGreek = isGreek
	}
	w.lastLetterGreek = isGreek
	w.letters++
}

// flaggedScripts returns the scripts that make the word suspect, such as
// "Latin and Cyrillic" or "Latin, Cyrillic and Coptic", or "" when the word
// is not flagged. The names come in the order of lookalikeScripts. Greek is
// left out when greekExcused excuses it.
func (w *wordState) flaggedScripts() string {
	if bits.OnesCount16(w.scripts) < 2 {
		return ""
	}
	var names [len(lookalikeScripts)]string
	n := 0
	for i, s := range lookalikeScripts {
		if w.scripts&(1<<i) == 0 || i == greekScript && w.greekExcused() {
			continue
		}
		names[n] = s.name
		n++
	}
	if n < 2 {
		return ""
	}
	return joinNames(names[:n])
}

// joinNames joins two or more script names: "A and B", "A, B and C".
func joinNames(names []string) string {
	last := len(names) - 1
	return strings.Join(names[:last], ", ") + " and " + names[last]
}

// greekExcused reports whether the Greek letter of the word is a unit
// letter in a unit after a number (see followsDigit). The word must be one
// Greek letter at its start or end and up to 3 Latin letters, with no
// other letter, and the two parts must form a unit (see isUnit). So "5" + mu
// + "s" and "10k" + Omega are excused, but "2" + mu + "ser" is not.
func (w *wordState) greekExcused() bool {
	if w.greek != 1 || !w.afterDigit || w.nLatin > len(w.latin) || w.letters != 1+w.nLatin {
		return false
	}
	if !w.firstLetterGreek && !w.lastLetterGreek {
		return false
	}
	return isUnit(w.greekLetter, w.firstLetterGreek, string(w.latin[:w.nLatin]))
}

// isUnit reports whether the Greek letter g and the Latin letters latin
// form a unit. When first is true, g comes before latin, else after
// it. The units are micro (small mu, U+03BC, also the fold of the micro sign
// U+00B5) before an SI unit in microUnits, such as mu + "s", and ohm
// (capital Omega U+03A9 or the ohm sign U+2126) after the prefix "k", "M",
// "G" or "m", or before "m" or "cm" (ohm metre).
func isUnit(g rune, first bool, latin string) bool {
	switch g {
	case '\u03BC':
		return first && microUnits[latin]
	case '\u03A9', '\u2126':
		if first {
			return latin == "m" || latin == "cm"
		}
		return latin == "k" || latin == "M" || latin == "G" || latin == "m"
	}
	return false
}

// microUnits holds the units that come after micro (mu) in a unit, such as
// "s" for microseconds and "mol" for micromoles.
var microUnits = map[string]bool{
	"s": true, "m": true, "g": true, "l": true, "L": true, "A": true,
	"V": true, "W": true, "F": true, "H": true, "C": true, "J": true,
	"K": true, "M": true, "N": true, "S": true, "T": true,
	"Hz": true, "Pa": true, "mol": true, "sec": true,
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
//   - a high surrogate escape directly followed by a low surrogate escape
//     (12 bytes), which gives the rune of the pair (see utf16.DecodeRune).
//     Any other surrogate escape is a lone surrogate. It gives
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
		if len(s) >= 12 && s[6] == '\\' && s[7] == 'u' {
			if lo, ok := hex4(s[8:]); ok {
				if pair := utf16.DecodeRune(hi, lo); pair != utf8.RuneError {
					return pair, 12
				}
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
	var b [2]byte
	if _, err := hex.Decode(b[:], []byte(s[:4])); err != nil {
		return 0, false
	}
	return rune(b[0])<<8 | rune(b[1]), true
}
