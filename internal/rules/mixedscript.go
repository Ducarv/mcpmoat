package rules

import (
	"cmp"
	"fmt"
	"math/bits"
	"slices"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// mixedScript flags each word of raw that mixes letters of two or more
// look-alike scripts (see lookalikeScripts), such as "Ignore" with a Cyrillic
// "I" (U+0406). The regex forms read most such letters as ASCII (see
// skeleton), but a word that mixes scripts is suspect also when no regex
// matches it: a letter can be missing from the table, and a keyword form has
// no skeleton fold. The package doc (doc.go) holds the full rules for users:
// the unit exemption and the limits. This comment holds the implementation
// contract.
//
// It reads the full raw text in one pass, with no size cut. A word is a
// longest run of letters, of marks, of the runes that isWordFiller accepts
// (invisible runes, private-use runes, unassigned code points and U+FFFD) and
// of the runes that fold to letters only (see wordState.foldIsLetters), such
// as U+216E (Roman numeral D) and U+24D6 (circled g). Any other rune ends a
// word. An invalid UTF-8 byte and a lone surrogate escape decode to U+FFFD,
// so they join a word.
//
// When jsonEscapes is true, JSON escapes are decoded (see jsonEscape), so the
// heuristic reads the raw JSON of a schema as it reads the decoded text. The
// decoded rune counts as a raw rune at the offset of the backslash, and all
// bytes of the escape are skipped. Any other backslash is a normal rune that
// ends a word. When jsonEscapes is false, as for a description, which is
// decoded text, every backslash is a normal rune.
//
// Each letter counts for its own script. A letter of the Common or
// Inherited script counts by its fold (see wordState.addFolded). A mark
// counts for its own script too, with no fold (see wordState.addMark). A
// letter or mark of a script outside the list counts for no script but
// stays part of the word. A rune of an edge-tier script (see edgeTier)
// counts when Latin letters come before it and after it in the word. At the
// start or the end of the word it counts only in the cases that edgeTier
// gives. A word is flagged when its letters and marks count for two or more
// scripts, after the unit exemption (see wordState.greekExcused).
//
// The hit is at the byte offset of the first rune of the word. The Detail
// names the scripts in the order of lookalikeScripts. It never holds the
// word: the terminal-safe output does not change look-alike letters, so the
// word would show as normal Latin text.
func mixedScript(raw string, jsonEscapes bool) []Hit {
	var l hitList
	var w wordState
	// end flags the current word when it mixes scripts. Then it clears w for
	// the next word.
	end := func() {
		if !w.started {
			return // no word, so w is already clear
		}
		if m := w.flagged(); m != 0 && l.keep(w.start) {
			l.hits = append(l.hits, Hit{Offset: w.start, Detail: fmt.Sprintf("word at offset %d mixes %s letters", w.start, scriptNames(m))})
		}
		w = wordState{fold: w.fold[:0]} // keep the fold buffer for the next word
	}
	// prev1 is the rune just before offset i, and prev2 is the rune before
	// prev1. They tell whether a word comes after a number (see
	// followsDigit).
	prev1, prev2 := noRune, noRune
	// The decode and the ASCII fast path below stay in this loop on purpose.
	// A helper function for the decode was not inlined and made 10 MB of
	// ASCII text 10% slower (68 ms to 75 ms, Apple M1 Pro, go1.27.3).
	for i := 0; i < len(raw); {
		var r rune
		size := 0
		if jsonEscapes && raw[i] == '\\' {
			r, size = jsonEscape(raw[i:])
		}
		escaped := size > 0
		switch {
		case escaped: // jsonEscape gave r and size
		case raw[i] < utf8.RuneSelf:
			r, size = rune(raw[i]), 1 // ASCII needs no decode
		default:
			// An invalid byte gives utf8.RuneError (U+FFFD).
			r, size = utf8.DecodeRuneInString(raw[i:])
		}
		switch {
		case r <= unicode.MaxASCII:
			// The fast path for ASCII, the most common case: a letter is
			// Latin, a control rune that is not a space is invisible and
			// joins the word (see isWordFiller), and any other rune ends
			// the word.
			switch {
			case isASCIILetter(byte(r)):
				w.begin(i, prev1, prev2)
				w.countLetter(r, latinScript)
			case (r < ' ' || r == 0x7F) && isInvisible(r):
				// Only a control rune (category Cc) can be an invisible
				// ASCII rune, so the check skips the other runes.
				w.begin(i, prev1, prev2)
			default:
				end()
			}
		case unicode.IsLetter(r):
			w.begin(i, prev1, prev2)
			w.addLetter(r)
		case unicode.IsMark(r):
			// A mark counts for its own script, as in TR39 section 5.1 (see
			// wordState.addMark). A mark of the Common or Inherited script
			// counts for no script (scriptOf returns -1), but it still joins
			// the word.
			w.begin(i, prev1, prev2)
			w.addMark(r, scriptOf(r))
		case isWordFiller(r):
			w.begin(i, prev1, prev2)
		case w.setFold(r) && w.foldIsLetters():
			// The regexes read this rune as the letters of its fold.
			w.begin(i, prev1, prev2)
			w.countFold()
		default:
			end()
		}
		prev := r
		if escaped && isASCIIDigit(r) {
			// An escaped digit never comes before a unit: the schema JSON
			// from the inspect package never escapes a digit.
			prev = noRune
		}
		prev2, prev1 = prev1, prev
		i += size
	}
	end()
	return l.result("mixed-script words")
}

// noRune stands for "no rune" before the start of the text (see
// followsDigit).
const noRune rune = -1

// isWordFiller reports whether r, a rune that is neither a letter nor a mark
// (mixedScript handles those first), joins a word: an invisible rune (see
// isInvisible), a private-use rune, an unassigned code point or U+FFFD. Many
// fonts draw a
// private-use or unassigned rune as nothing, and a client may drop U+FFFD,
// so they must not split a word either. To join runes into one word can only
// add hits. No ASCII rune is private-use or unassigned.
func isWordFiller(r rune) bool {
	if isInvisible(r) || r == utf8.RuneError {
		return true
	}
	return unicode.In(r, unicode.Co, unicode.Cn)
}

// followsDigit reports whether a word whose two previous runes are prev1
// (the nearer one) and prev2 comes directly after an ASCII digit, or after
// one space rune that comes directly after an ASCII digit. A space rune is a
// rune of unicode.IsSpace. It covers the no-break space (U+00A0), the thin
// space (U+2009) and the narrow no-break space (U+202F), which texts put
// between a number and its unit.
func followsDigit(prev1, prev2 rune) bool {
	return isASCIIDigit(prev1) || (unicode.IsSpace(prev1) && isASCIIDigit(prev2))
}

// isASCIIDigit reports whether r is 0-9.
func isASCIIDigit(r rune) bool {
	return '0' <= r && r <= '9'
}

// scriptTier says where in a word a rune of a look-alike script counts (see
// wordState.countLetter and wordState.addMark).
type scriptTier uint8

const (
	// strictTier: a letter or mark of the script counts wherever it is in
	// the word.
	strictTier scriptTier = iota
	// edgeTier: a letter or mark of the script counts when Latin letters
	// come before it and after it in the same word. Real text attaches
	// these scripts to a Latin name: Thai has no spaces between words (a
	// Thai verb then "Google"), and a Hebrew or Arabic prefix and an Indic
	// suffix attach to the name. So a run of these runes at the start or
	// the end of a word is excused (see wordState.edgeRun), with two
	// exceptions:
	//
	//   - A run that holds only one letter counts when that letter is in
	//     edgeLookalikes, as the letter then reads as a Latin letter of the
	//     word: Hebrew vav (U+05D5) + "gnore" reads as "lgnore". The marks
	//     after the letter are part of the run. A run of two or more
	//     letters is excused, so Arabic U+0627 U+0644 + "Google" is not
	//     flagged, but Hebrew vav + "Google" ("and Google") is.
	//   - A mark that reads as a Latin letter (it is in skeletonTable) and
	//     does not come after a letter of its own script counts at once (see
	//     wordState.addMark): "hell" + U+0C02 (Telugu anusvara) reads as
	//     "hello".
	edgeTier
)

// arabicHighHamza is U+0674 ARABIC LETTER HIGH HAMZA, a small hamza that
// Unicode makes a letter (category Lo). TR39 maps U+0672 and U+0675 to "l" and
// then U+0674, and it is the part of U+0675 that NFKD splits off. The edge run
// does not count it as a visible letter, as it does not count a mark.
const arabicHighHamza = '\u0674'

// edgeLookalikes holds the edge-tier letters (see edgeTier) that read as one
// Latin letter, sorted by code point for isEdgeLookalike. It holds two
// groups:
//
//   - The letters that TR39 confusables.txt 18.0.0 (see confusablesVersion)
//     maps to one Latin letter, or to one Latin letter and then only
//     non-spacing marks (Mn) or U+0674 (Arabic letter high hamza, see
//     arabicHighHamza). The comment of each entry gives that letter. So
//     U+0673 (alef with wavy hamza below, TR39 "l" + U+0655) and U+0675 (high
//     hamza alef, TR39 "l" + U+0674) are in the table, as U+0625 is.
//   - The composed and compatibility forms of those letters. A form is an
//     edge-tier letter whose NFKD decomposition, with its marks (Mn, Mc and
//     Me) and U+0674 removed, is exactly one letter of the first group. The
//     comment of each entry gives that letter. TR39 applies NFD before it
//     maps a letter, so confusables.txt does not list most of these forms,
//     but they read as their base letter: U+0623 (alef with hamza above) +
//     "gnore" reads as "lgnore", as U+0627 U+0654 does.
//
// The second group comes from the Unicode 17.0.0 tables of Go (see
// scriptTablesVersion, unicode.Version) and of
// golang.org/x/text/unicode/norm. A test walks all edge-tier letters and
// checks that the table holds each such form, and that it holds every edge-tier
// letter of skeletonTable. The table holds letters only: a mark is handled by
// wordState.addMark, and a digit or a punctuation rune is not part of a word.
// It leaves out the letters that TR39 maps to two or more Latin letters, such
// as U+11EE (oo) and U+1EE64 (ARABIC MATHEMATICAL STRETCHED HEH: ol), whose
// NFKD base is U+0647, and the letters that TR39 maps to a Latin letter and a
// spacing mark (Mc), such as Myanmar U+1010 ("o" + U+102C): the visible sign
// shows that the letter is not a Latin one. When confusablesVersion or
// scriptTablesVersion changes, make the list again (issue #152 tracks a
// generator).
//
// The comments of U+0629, U+06C3, U+FE93 and U+FE94 call the letter TAA
// MARBUTA, its common name: the misspell linter rejects the Unicode name.
var edgeLookalikes = [...]rune{
	0x05D5,  // HEBREW LETTER VAV: l
	0x05D8,  // HEBREW LETTER TET: v
	0x05DF,  // HEBREW LETTER FINAL NUN: l
	0x05E1,  // HEBREW LETTER SAMEKH: o
	0x0622,  // ARABIC LETTER ALEF WITH MADDA ABOVE: NFKD U+0627
	0x0623,  // ARABIC LETTER ALEF WITH HAMZA ABOVE: NFKD U+0627
	0x0625,  // ARABIC LETTER ALEF WITH HAMZA BELOW: NFKD U+0627
	0x0627,  // ARABIC LETTER ALEF: l
	0x0629,  // ARABIC LETTER TAA MARBUTA: o
	0x0647,  // ARABIC LETTER HEH: o
	0x0672,  // ARABIC LETTER ALEF WITH WAVY HAMZA ABOVE: l
	0x0673,  // ARABIC LETTER ALEF WITH WAVY HAMZA BELOW: l
	0x0675,  // ARABIC LETTER HIGH HAMZA ALEF: l
	0x06BE,  // ARABIC LETTER HEH DOACHASHMEE: o
	0x06C0,  // ARABIC LETTER HEH WITH YEH ABOVE: NFKD U+06D5
	0x06C1,  // ARABIC LETTER HEH GOAL: o
	0x06C2,  // ARABIC LETTER HEH GOAL WITH HAMZA ABOVE: NFKD U+06C1
	0x06C3,  // ARABIC LETTER TAA MARBUTA GOAL: o
	0x06D5,  // ARABIC LETTER AE: o
	0x06FF,  // ARABIC LETTER HEH WITH INVERTED V: o
	0x0B20,  // ORIYA LETTER TTHA: O
	0x0D1F,  // MALAYALAM LETTER TTA: s
	0x0D20,  // MALAYALAM LETTER TTHA: o
	0x1004,  // MYANMAR LETTER NGA: c
	0x101D,  // MYANMAR LETTER WA: o
	0x105A,  // MYANMAR LETTER MON NGA: c
	0x110B,  // HANGUL CHOSEONG IEUNG: o
	0x11BC,  // HANGUL JONGSEONG IEUNG: o
	0x1A45,  // TAI THAM LETTER WA: o
	0x3112,  // BOPOMOFO LETTER X: T
	0x311A,  // BOPOMOFO LETTER A: Y
	0x3147,  // HANGUL LETTER IEUNG: o
	0xFB35,  // HEBREW LETTER VAV WITH DAGESH: NFKD U+05D5
	0xFB38,  // HEBREW LETTER TET WITH DAGESH: NFKD U+05D8
	0xFB41,  // HEBREW LETTER SAMEKH WITH DAGESH: NFKD U+05E1
	0xFB4B,  // HEBREW LETTER VAV WITH HOLAM: NFKD U+05D5
	0xFBA4,  // ARABIC LETTER HEH WITH YEH ABOVE ISOLATED FORM: NFKD U+06D5
	0xFBA5,  // ARABIC LETTER HEH WITH YEH ABOVE FINAL FORM: NFKD U+06D5
	0xFBA6,  // ARABIC LETTER HEH GOAL ISOLATED FORM: o
	0xFBA7,  // ARABIC LETTER HEH GOAL FINAL FORM: o
	0xFBA8,  // ARABIC LETTER HEH GOAL INITIAL FORM: o
	0xFBA9,  // ARABIC LETTER HEH GOAL MEDIAL FORM: o
	0xFBAA,  // ARABIC LETTER HEH DOACHASHMEE ISOLATED FORM: o
	0xFBAB,  // ARABIC LETTER HEH DOACHASHMEE FINAL FORM: o
	0xFBAC,  // ARABIC LETTER HEH DOACHASHMEE INITIAL FORM: o
	0xFBAD,  // ARABIC LETTER HEH DOACHASHMEE MEDIAL FORM: o
	0xFCD9,  // ARABIC LIGATURE HEH WITH SUPERSCRIPT ALEF INITIAL FORM: NFKD U+0647
	0xFD3C,  // ARABIC LIGATURE ALEF WITH FATHATAN FINAL FORM: NFKD U+0627
	0xFD3D,  // ARABIC LIGATURE ALEF WITH FATHATAN ISOLATED FORM: NFKD U+0627
	0xFE81,  // ARABIC LETTER ALEF WITH MADDA ABOVE ISOLATED FORM: NFKD U+0627
	0xFE82,  // ARABIC LETTER ALEF WITH MADDA ABOVE FINAL FORM: NFKD U+0627
	0xFE83,  // ARABIC LETTER ALEF WITH HAMZA ABOVE ISOLATED FORM: NFKD U+0627
	0xFE84,  // ARABIC LETTER ALEF WITH HAMZA ABOVE FINAL FORM: NFKD U+0627
	0xFE87,  // ARABIC LETTER ALEF WITH HAMZA BELOW ISOLATED FORM: NFKD U+0627
	0xFE88,  // ARABIC LETTER ALEF WITH HAMZA BELOW FINAL FORM: NFKD U+0627
	0xFE8D,  // ARABIC LETTER ALEF ISOLATED FORM: l
	0xFE8E,  // ARABIC LETTER ALEF FINAL FORM: l
	0xFE93,  // ARABIC LETTER TAA MARBUTA ISOLATED FORM: NFKD U+0629
	0xFE94,  // ARABIC LETTER TAA MARBUTA FINAL FORM: NFKD U+0629
	0xFEE9,  // ARABIC LETTER HEH ISOLATED FORM: o
	0xFEEA,  // ARABIC LETTER HEH FINAL FORM: o
	0xFEEB,  // ARABIC LETTER HEH INITIAL FORM: o
	0xFEEC,  // ARABIC LETTER HEH MEDIAL FORM: o
	0xFFB7,  // HALFWIDTH HANGUL LETTER IEUNG: o
	0x1EE00, // ARABIC MATHEMATICAL ALEF: l
	0x1EE24, // ARABIC MATHEMATICAL INITIAL HEH: o
	0x1EE80, // ARABIC MATHEMATICAL LOOPED ALEF: l
	0x1EE84, // ARABIC MATHEMATICAL LOOPED HEH: o
}

// isEdgeLookalike reports whether r is in edgeLookalikes.
func isEdgeLookalike(r rune) bool {
	_, ok := slices.BinarySearch(edgeLookalikes[:], r)
	return ok
}

// lookalikeScript is one script that mixedScript counts.
type lookalikeScript struct {
	name  string // the name in a Detail: printable ASCII
	table *unicode.RangeTable
	tier  scriptTier
}

// lookalikeScripts lists the scripts that mixedScript counts, in the order
// that a Detail names them. The first nine are Latin, Cyrillic, Greek,
// Armenian, Cherokee, Lisu, Coptic, Canadian Aboriginal and Tifinagh. The
// others are each script of the Go unicode tables with a letter or mark that
// maps to a Latin letter in TR39 confusables.txt (see confusablesVersion),
// and Gothic, which has Latin look-alikes that TR39 does not list.
//
// The edge tier also holds Thai, Lao and Khmer, whose only Latin
// confusables in TR39 are digits (issue #139).
//
// Out of scope: a Latin-script look-alike (such as U+0261) is Latin, so it
// cannot mix scripts. Not listed: scripts whose only Latin confusables are
// digits or punctuation (such as Devanagari U+0966), since mixedScript
// counts letters and marks only, and Han. Chinese and Japanese text puts Han
// letters next to Latin names with no space, and even between two names, so
// no tier fits Han. TR39 also allows Latin with Han (the Highly Restrictive
// level). Code points that are new in TR39 but not yet in the Go tables are
// unassigned for Go, so they join a word (see isWordFiller) but count for no
// script.
var lookalikeScripts = [...]lookalikeScript{
	latinScript: {"Latin", unicode.Latin, strictTier},
	{"Cyrillic", unicode.Cyrillic, strictTier},
	greekScript: {"Greek", unicode.Greek, strictTier},
	{"Armenian", unicode.Armenian, strictTier},
	{"Cherokee", unicode.Cherokee, strictTier},
	{"Lisu", unicode.Lisu, strictTier},
	{"Coptic", unicode.Coptic, strictTier},
	{"Canadian Aboriginal", unicode.Canadian_Aboriginal, strictTier},
	{"Tifinagh", unicode.Tifinagh, strictTier},

	// The strict tier from TR39, in alphabetical order.
	{"Ahom", unicode.Ahom, strictTier},
	{"Bamum", unicode.Bamum, strictTier},
	{"Bassa Vah", unicode.Bassa_Vah, strictTier},
	{"Batak", unicode.Batak, strictTier},
	{"Beria Erfe", unicode.Beria_Erfe, strictTier},
	{"Carian", unicode.Carian, strictTier},
	{"Chakma", unicode.Chakma, strictTier},
	{"Deseret", unicode.Deseret, strictTier},
	{"Elbasan", unicode.Elbasan, strictTier},
	{"Ethiopic", unicode.Ethiopic, strictTier},
	{"Georgian", unicode.Georgian, strictTier},
	{"Gothic", unicode.Gothic, strictTier},
	{"Grantha", unicode.Grantha, strictTier},
	{"Hanifi Rohingya", unicode.Hanifi_Rohingya, strictTier},
	{"Kirat Rai", unicode.Kirat_Rai, strictTier},
	{"Lycian", unicode.Lycian, strictTier},
	{"Lydian", unicode.Lydian, strictTier},
	{"Mandaic", unicode.Mandaic, strictTier},
	{"Miao", unicode.Miao, strictTier},
	{"NKo", unicode.Nko, strictTier},
	{"Old Hungarian", unicode.Old_Hungarian, strictTier},
	{"Old Italic", unicode.Old_Italic, strictTier},
	{"Old Turkic", unicode.Old_Turkic, strictTier},
	{"Osage", unicode.Osage, strictTier},
	{"Runic", unicode.Runic, strictTier},
	{"Tagbanwa", unicode.Tagbanwa, strictTier},
	{"Tirhuta", unicode.Tirhuta, strictTier},
	{"Tolong Siki", unicode.Tolong_Siki, strictTier},
	{"Vai", unicode.Vai, strictTier},
	{"Warang Citi", unicode.Warang_Citi, strictTier},

	// The edge tier, in alphabetical order. Bopomofo (Taiwanese text writes
	// phonetic letters and particles next to a name, with no spaces, as Han
	// text does), Hangul (a Korean particle after a name), Oriya (Indic
	// suffixes) and Tai Tham (no spaces, as Thai) attach to Latin names too.
	{"Arabic", unicode.Arabic, edgeTier},
	{"Bopomofo", unicode.Bopomofo, edgeTier},
	{"Hangul", unicode.Hangul, edgeTier},
	{"Hebrew", unicode.Hebrew, edgeTier},
	{"Kannada", unicode.Kannada, edgeTier},
	{"Khmer", unicode.Khmer, edgeTier},
	{"Lao", unicode.Lao, edgeTier},
	{"Malayalam", unicode.Malayalam, edgeTier},
	{"Myanmar", unicode.Myanmar, edgeTier},
	{"Oriya", unicode.Oriya, edgeTier},
	{"Sinhala", unicode.Sinhala, edgeTier},
	{"Tai Tham", unicode.Tai_Tham, edgeTier},
	{"Telugu", unicode.Telugu, edgeTier},
	{"Thai", unicode.Thai, edgeTier},
}

// The indexes of Latin and Greek in lookalikeScripts. The array literal of
// lookalikeScripts uses them as keys, and TestLookalikeScripts checks that
// they point at the right tables.
const (
	latinScript = 0
	greekScript = 2
)

// scriptMask is a set of scripts: bit i is set for lookalikeScripts[i].
type scriptMask uint64

// The build fails here when lookalikeScripts has more scripts than
// scriptMask has bits: the constant is then negative, and a uint constant
// cannot be negative.
const _ = uint(64 - len(lookalikeScripts))

// scriptRange says that the code points lo to hi are of the script
// lookalikeScripts[script]. The code points are uint32, as in the
// unicode.Range32 of a table, so no conversion can overflow.
type scriptRange struct {
	lo, hi uint32
	script int
}

// scriptRanges holds the ranges of all tables of lookalikeScripts, sorted by
// lo, so scriptOf finds the script of a rune with one binary search instead
// of one search in each table. It is built once and never changed.
var scriptRanges = buildScriptRanges()

// buildScriptRanges returns the ranges for scriptRanges. A table range with
// a stride other than 1 holds only every stride-th rune, so each of its runes
// becomes a range of its own. Two scripts never share a rune, so the ranges
// do not overlap.
func buildScriptRanges() []scriptRange {
	var rs []scriptRange
	add := func(lo, hi, stride uint32, script int) {
		if stride == 1 {
			rs = append(rs, scriptRange{lo, hi, script})
			return
		}
		for c := lo; c <= hi; c += stride {
			rs = append(rs, scriptRange{c, c, script})
		}
	}
	for i, s := range lookalikeScripts {
		for _, r := range s.table.R16 {
			add(uint32(r.Lo), uint32(r.Hi), uint32(r.Stride), i)
		}
		for _, r := range s.table.R32 {
			add(r.Lo, r.Hi, r.Stride, i)
		}
	}
	slices.SortFunc(rs, func(a, b scriptRange) int { return cmp.Compare(a.lo, b.lo) })
	return rs
}

// scriptOf returns the index in lookalikeScripts of the script of r, or -1
// when r is of no script in the list. An ASCII rune needs no lookup: a
// letter is Latin, and any other ASCII rune is Common.
func scriptOf(r rune) int {
	switch {
	case r < 0:
		return -1 // not a code point
	case r <= unicode.MaxASCII:
		if isASCIILetter(byte(r)) {
			return latinScript
		}
		return -1
	}
	// A binary search for the first range that ends at c or after c: the
	// ranges before lo end before c, and the ranges from hi on end at c or
	// after c. It is written by hand on purpose: slices.BinarySearchFunc with
	// a comparison function was 29% to 43% slower on 10 MB of Cyrillic and
	// mixed text (135 ms to 193 ms, Apple M1 Pro, go1.27.3), because the
	// function call is not inlined.
	c := uint32(r)
	lo, hi := 0, len(scriptRanges)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1) // the shift halves the sum with no overflow
		if scriptRanges[mid].hi < c {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(scriptRanges) && scriptRanges[lo].lo <= c {
		return scriptRanges[lo].script
	}
	return -1
}

// wordState holds what mixedScript knows about the current word. It uses
// counts and fixed fields, not a slice per word, so a word costs no memory.
type wordState struct {
	started    bool // the word has at least one rune
	start      int  // byte offset of the first rune of the word
	afterDigit bool // the word comes after a digit (see followsDigit)

	letters int        // letters of any script
	scripts scriptMask // the scripts that a letter or mark counts for
	// lastScript is the index in lookalikeScripts of the script of the last
	// letter that has a script in the list. It is 0 (latinScript) until such
	// a letter comes. Latin is never an edge-tier script, so addMark does not
	// take that zero for the script of a mark (see addMark and countLetter).
	lastScript int

	// The edge run is the edge-tier letters and marks (see edgeTier) since
	// the last Latin letter, or since the start of the word when no Latin
	// letter came yet. edgeRun holds their scripts. edgeLetters counts the
	// visible letters of the run, up to 2, and edgeLetter is the only one
	// when edgeLetters is 1. An invisible letter (see isInvisible), such as
	// the Hangul filler U+3164, U+0674 and a modifier letter (Lm) are not
	// counted, so they cannot make a run of one letter look like a run of
	// two (see countLetter). The next Latin letter ends the run
	// (see countLetter), and so does the end of the word (see flagged). A
	// run between two Latin letters counts. A run at the start or the end of
	// a word counts only when runCounts says so.
	edgeRun     scriptMask
	edgeLetters int
	edgeLetter  rune

	greek            int  // Greek letters
	greekLetter      rune // the last Greek letter; the only one when greek == 1
	firstLetterGreek bool // the first letter of the word is Greek
	lastLetterGreek  bool // the last letter so far is Greek

	// latin holds the first Latin letters of the word, for greekExcused.
	// nLatin counts all Latin letters. When it is more than len(latin), the
	// word is too long to be a unit.
	latin  [3]rune
	nLatin int

	// fold is a scratch buffer for setFold. mixedScript keeps it from one
	// word to the next, so a scan allocates it at most once.
	fold []byte
}

// begin starts a word at byte offset i, unless a word is started. prev1 and
// prev2 are the two runes before i (see followsDigit).
func (w *wordState) begin(i int, prev1, prev2 rune) {
	if !w.started {
		w.started, w.start, w.afterDigit = true, i, followsDigit(prev1, prev2)
	}
}

// addLetter adds the letter r, which is not ASCII, to the word. A letter of
// the Common or Inherited script, or a Latin letter, counts by its fold (see
// addFolded). So the mathematical Greek letters count as Greek, and the
// fullwidth "s" and the Kelvin sign count as "s" and "K". Any other letter
// counts for its own script (see countLetter).
func (w *wordState) addLetter(r rune) {
	i := scriptOf(r)
	if (i < 0 && unicode.In(r, unicode.Common, unicode.Inherited)) || i == latinScript {
		w.addFolded(r)
		return
	}
	w.countLetter(r, i)
}

// addFolded adds the letter r by its fold (see setFold and countFold). When
// the fold does not change r, or holds no letter, r counts as one letter of
// its own script (see scriptOf).
func (w *wordState) addFolded(r rune) {
	if !w.setFold(r) || !w.countFold() {
		w.countLetter(r, scriptOf(r))
	}
}

// setFold sets the scratch buffer w.fold to the fold of r (see appendFold).
// It reports whether the fold differs from r.
func (w *wordState) setFold(r rune) bool {
	rs := string(r)
	w.fold = appendFold(w.fold[:0], r, rs)
	return string(w.fold) != rs
}

// countFold counts each letter of w.fold (see setFold) as one letter of its
// own script, with no second fold. It reports whether w.fold holds a letter.
func (w *wordState) countFold() bool {
	counted := false
	for _, f := range string(w.fold) {
		if unicode.IsLetter(f) {
			w.countLetter(f, scriptOf(f))
			counted = true
		}
	}
	return counted
}

// foldIsLetters reports whether w.fold (see setFold) is not empty and holds
// only letters. A rune that is not a letter but has such a fold joins a word,
// as the regexes read it as letters: a Roman numeral such as U+216E
// (category Nl), or a circled or squared letter such as U+24D6 (category
// So).
func (w *wordState) foldIsLetters() bool {
	if len(w.fold) == 0 {
		return false
	}
	for _, f := range string(w.fold) {
		if !unicode.IsLetter(f) {
			return false
		}
	}
	return true
}

// addMark counts the mark r for the script lookalikeScripts[i], or for no
// script when i is -1. A strict-tier mark counts at once. An edge-tier mark
// that comes after a letter of its own script joins the edge run of that
// letter (see edgeRun), as the marks of real Thai, Hebrew or Indic text do.
// Any other edge-tier mark counts at once when it reads as a Latin letter
// (it is in skeletonTable): real text does not put such a mark at the start
// of a word or after a Latin letter, and U+0C02 (Telugu anusvara) looks like
// "o". A mark that does not read as a letter joins the edge run too, with no
// letter of its own: Burmese text in the Zawgyi encoding puts U+1031 before
// its consonant. The run counts between two Latin letters, and it is
// excused at a word edge.
func (w *wordState) addMark(r rune, i int) {
	switch {
	case i < 0: // no script
	case lookalikeScripts[i].tier != edgeTier:
		w.scripts |= 1 << i
	case w.letters > 0 && w.lastScript == i:
		w.edgeRun |= 1 << i
	default:
		if _, ok := skeletonOf(r); ok {
			w.scripts |= 1 << i
		} else {
			w.edgeRun |= 1 << i
		}
	}
}

// countLetter counts the letter r for the script lookalikeScripts[i], or
// for no script when i is -1. A Latin letter or a letter of a strict-tier
// script counts at once. A letter of an edge-tier script joins the edge run
// (see edgeRun), which counts or is excused when it ends.
func (w *wordState) countLetter(r rune, i int) {
	switch {
	case i < 0: // no script
	case i == latinScript:
		w.scripts |= 1 << latinScript
		// The Latin letter ends the edge run. A run after an earlier Latin
		// letter is inside the word, so it counts. A run before the first
		// Latin letter is at the start of the word. An empty run (the
		// common case) also has no letters, so the check skips it.
		if w.edgeRun != 0 {
			if w.nLatin > 0 || w.runCounts() {
				w.scripts |= w.edgeRun
			}
			w.edgeRun, w.edgeLetters = 0, 0
		}
		if w.nLatin < len(w.latin) {
			w.latin[w.nLatin] = r
		}
		w.nLatin++
	case lookalikeScripts[i].tier == edgeTier:
		w.edgeRun |= 1 << i
		// U+0674 (see arabicHighHamza), a modifier letter (category Lm, such
		// as the small Arabic waw U+06E5, a small sign above the letter
		// before it) and an invisible letter (see isInvisible) are not
		// counted. For a letter, isInvisible reads only the
		// Other_Default_Ignorable_Code_Point table (a letter is never Cc, Cf
		// or a variation selector), so the check reads that table alone. It
		// stops at the second letter of the run, so a long run costs no more
		// than a short one.
		if w.edgeLetters < 2 && r != arabicHighHamza && !unicode.Is(unicode.Lm, r) && !unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) {
			w.edgeLetters++
			w.edgeLetter = r // read only when edgeLetters is 1
		}
	default:
		w.scripts |= 1 << i
	}
	if i >= 0 {
		// A letter of no listed script, such as the Arabic tatweel (U+0640),
		// is transparent: a mark after it still belongs to the letter before.
		w.lastScript = i
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

// runCounts reports whether the edge run (see edgeRun) counts when it is at
// the start or the end of the word: it holds only one visible letter, and
// that letter is in edgeLookalikes (see edgeTier).
func (w *wordState) runCounts() bool {
	return w.edgeLetters == 1 && isEdgeLookalike(w.edgeLetter)
}

// flagged returns the scripts that make the word suspect, as a mask like
// w.scripts, or 0 when the word is not flagged. Greek is left out when
// greekExcused excuses it. It does not allocate, so mixedScript calls it
// before the hit cap check.
func (w *wordState) flagged() scriptMask {
	m := w.scripts
	if w.edgeRun != 0 && w.nLatin > 0 && w.runCounts() {
		// The edge run is at the end of the word. In a word with no Latin
		// letter, the run is the full word, and it never counts.
		m |= w.edgeRun
	}
	if bits.OnesCount64(uint64(m)) < 2 {
		return 0
	}
	if m&(1<<greekScript) != 0 && w.greekExcused() {
		m &^= 1 << greekScript
	}
	if bits.OnesCount64(uint64(m)) < 2 {
		return 0
	}
	return m
}

// scriptNames returns the names of the scripts in the mask m, which has two
// or more bits, in the order of lookalikeScripts: "Latin and Cyrillic" or
// "Latin, Cyrillic and Coptic".
func scriptNames(m scriptMask) string {
	var names [len(lookalikeScripts)]string
	n := 0
	for i, s := range lookalikeScripts {
		if m&(1<<i) != 0 {
			names[n] = s.name
			n++
		}
	}
	list := names[:n]
	last := len(list) - 1
	return strings.Join(list[:last], ", ") + " and " + list[last]
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
	case '\u03BC': // small mu
		return first && microUnits[latin]
	case '\u03A9', '\u2126': // capital Omega, ohm sign
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
	var v rune
	for i := range 4 {
		if !isHexDigit(s[i]) {
			return 0, false
		}
		v = v<<4 | rune(unhexByte(s[i]))
	}
	return v, true
}
