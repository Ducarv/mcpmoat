package rules

import (
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// MaxMatchInputBytes is the largest part of a text, in bytes, that the regex
// and keyword matchers read: 32 KiB, counted after normalizeForMatch has
// dropped or replaced the invisible runes and mapped each ANSI escape
// sequence and each space that RE2 \s does not match to U+0020. Text after it
// is not regex-matched or keyword-matched. This keeps the cost of one match
// small when a server sends a very long text. Real tool descriptions are a
// few KB long, so the cap does not cut them.
//
// The text heuristics (max_length, invisible_unicode, base64_blob and
// mixed_script) see the full raw text, so a very long text is still flagged.
const MaxMatchInputBytes = 32 << 10

// maxRawScanBytes is the largest part of the raw text that normalizeForMatch
// reads: 128 KiB. The invisible runes are dropped from this part, so padding
// of up to 96 KiB of invisible runes cannot push a payload out of the
// MaxMatchInputBytes window.
const maxRawScanBytes = 4 * MaxMatchInputBytes

// isInvisible reports whether r is a rune that shows as nothing but can split
// a keyword: a format character (Cf), a variation selector, another
// default-ignorable code point, or a control rune (Cc) that is not white
// space. The few Cf runes that show as a mark (the prepended concatenation
// marks, such as the Arabic number sign U+0600) are not invisible.
//
// This covers the zero-width characters (ZWSP, ZWNJ, ZWJ, word joiner), LRM
// and RLM, the bidi embeddings, overrides and isolates, the BOM, the soft
// hyphen, the tag characters (U+E0000 to U+E007F), the variation selectors
// (VS1 to VS256), the combining grapheme joiner (CGJ, U+034F) and the Hangul
// fillers. ZWNJ and ZWJ are also a normal part of Persian and Indic text, so
// invisible_unicode flags such text too.
//
// It also covers the control runes (U+0000 to U+001F and U+007F to U+009F),
// such as NUL, U+0001, ESC, BEL and DEL. So "Ig" + U+0001 + "nore" and "Ig" +
// BEL + "nore" are "Ignore" for the matchers, as they are for a model. The
// white space of unicode.IsSpace (tab, LF, VT, FF, CR and NEL) is not
// invisible: it separates words, and spacesToASCII maps the white space that
// RE2 \s does not match.
//
// normalizeForMatch, the invisible_unicode heuristic and the base64_blob
// heuristic share this one predicate, so they cannot disagree about which
// runes are invisible.
func isInvisible(r rune) bool {
	if unicode.IsControl(r) { // category Cc
		return !unicode.IsSpace(r)
	}
	return unicode.In(r,
		unicode.Cf,
		unicode.Variation_Selector,
		unicode.Other_Default_Ignorable_Code_Point,
	) && !unicode.Is(unicode.Prepended_Concatenation_Mark, r)
}

// isInvisibleControl reports whether r is an invisible rune (see isInvisible)
// that is also a control rune (category Cc), such as U+0001 or ESC.
func isInvisibleControl(r rune) bool {
	return unicode.IsControl(r) && isInvisible(r)
}

// isInvisibleFormat reports whether r is an invisible rune (see isInvisible)
// that is not a control rune, such as ZWSP, a bidi control or a variation
// selector. The comments of this package call such a rune a format rune.
func isInvisibleFormat(r rune) bool {
	return !unicode.IsControl(r) && isInvisible(r)
}

// matchForms returns the base forms of s: the forms that the regex and
// keyword matchers read before the fold (see preparedText). A matcher reports
// a match when one form matches. Each form is at most MaxMatchInputBytes
// long, and equal forms are kept only once (see appendNew), so there are at
// most maxBaseForms forms. The conditions below look only at the part of s
// that normalizeForMatch reads (the first maxRawScanBytes).
//
// The forms 1 to 3 read the escape sequences with ansiSeq, which takes no C0
// control rune inside a CSI. The forms 4 to 7 read them with ansiSeqC0,
// which does, as a terminal does. ansiSeqC0 can take more of the text into a
// sequence: ESC [ LF "<IMPORTANT>" is the CSI ESC [ LF < I for ansiSeqC0,
// and the text "MPORTANT>". ansiSeq does not read it as a CSI, so the forms 1
// to 3 keep "[" LF "<IMPORTANT>". So the forms 4 to 7 only add matches: a
// text that the forms 1 to 3 match is not lost.
//
//  1. Always: normalizeForMatch(s). The invisible runes are dropped, so "ign"
//     + ZWSP + "ore" is "ignore" (see dropInvisible).
//  2. When s holds an invisible rune: each run of invisible runes is one
//     space instead, so "ignore" + ZWSP + "previous" is "ignore previous"
//     and a keyword edge next to a ZWSP still holds (see spaceInvisible).
//  3. When s holds an invisible control rune (see isInvisibleControl): the
//     format runes are dropped and each run of control runes is one space
//     (see spaceControls). So "Ig" + ZWSP + "nore" + U+0001 + "previous" is
//     "Ignore previous": the ZWSP joins a word and the control rune splits
//     two words.
//  4. When s holds an invisible control rune and a format rune (see
//     isInvisibleFormat): the control runes are dropped and each run that
//     holds a format rune is one space (see spaceFormats). So "Ig" + U+0001
//     + "nore" + ZWSP + "all" is "Ignore all": the control rune joins a word
//     and the ZWSP splits two words. In ESC + ZWSP + "[8mIgnore" + ZWSP +
//     "all", the space goes before the ESC, so ESC [ 8 m is still a CSI and
//     the form is "  Ignore all".
//  5. When s holds ESC, U+009B (CSI) or U+009D (OSC) (see hasSeqStart): as
//     the first form, but the sequences are read with ansiSeqC0 and a
//     sequence gives back the text that it takes (see keepSeqText and
//     seqText). A CSI whose final byte is an ASCII letter other than 'm'
//     becomes a space, its parameter bytes < = > ? and its intermediate
//     bytes (such as "." and "/"), and its final letter. So ESC [ "Ignore"
//     is " Ignore", ESC [ "<IMPORTANT>" is " <IMPORTANT>" and ESC [ ".env"
//     is " .env". Its numeric parameter bytes (digits, ";" and ":") are
//     dropped, so ESC [ 2 K is " K". A CSI with the final 'm' is SGR (colour
//     and bold): it becomes nothing, as a terminal shows it. So ESC [ 1 m
//     "iPhone" is "iPhone", not "miPhone", and "Ig" + ESC [ 0 m + "nore" is
//     "Ignore". An OSC becomes its text between two spaces, with each CSI
//     in that text read in the same way: ESC ] "Ignore all" BEL is
//     " Ignore all ", and ESC ] + U+009B + "8mIgnore" BEL is " Ignore ".
//  6. When s holds ESC or U+009B and a C0 control rune of csiC0 (see
//     hasSeqC0): as the first form, but a CSI can hold C0 control runes (see
//     dropSeqC0). So ESC + U+0001 + "[8mIgnore" is " Ignore": the first form
//     keeps "[8mIgnore", which has no word edge before "Ignore".
//  7. When s holds ESC, U+009B or U+009D (see hasSeqStart): the ANSI step of
//     the fifth form with the runs of the second form (see
//     keepSeqTextSpaced). So each run of invisible runes is a space, also
//     inside the text that a sequence gives back: ESC ] "Ignore" + ZWSP +
//     "all" BEL is " Ignore all ", and ESC [ "Ignore" + U+0001 + "all" is
//     " Ignore all". An ESC or U+009D that starts no sequence is such a run
//     too, so ESC [ "Ignore" + ESC + "all" is " Ignore all". As in the
//     fourth form, the space of a run goes before an ESC at its end (see
//     placeOnce), so "run" + ZWSP + ESC [ 1 m + "ning" is "run ning", not
//     "running".
//
// In the forms 2 to 4 and 7, at most two spaces stand for a whole run of
// invisible runes (two only in the second form, for a run that has a
// control rune and ends with a format rune, and in the seventh form, for a
// run that has a control rune and a format rune, see replaceRuns). So
// invisible padding cannot push a payload out of the MaxMatchInputBytes
// window of these forms either.
//
// Some texts still defeat all the forms, and the fifth form can make a
// token from a rare CSI that a terminal does not show (a false positive).
// docs/writing-rules.md ("How mcpmoat prepares the text") is the one list of both,
// with examples. The "known limit" cases of TestMatchForms pin them, and the
// invisible_unicode heuristic flags each such text in a description.
//
// An OSC with more than 256 runes of text is not an OSC for ansiSeq or
// ansiSeqC0. So its ESC and its end are dropped, and its text stays in every
// form, after its "]": the matchers read that text.
//
// A text without invisible runes and escape sequences has one form, so it
// costs no more. A text with them is matched up to maxBaseForms times, which
// is maxBaseForms times the cost bound in match.go. The regex matchers also
// read the folds (see preparedText.regexForms).
func matchForms(s string) []string {
	forms := make([]string, 0, maxBaseForms)
	for _, mode := range formModes(s) {
		forms = appendNew(forms, buildForm(s, mode))
	}
	return forms
}

// maxBaseForms is the largest number of base forms that matchForms returns:
// one form for each formMode, 7 in all.
const maxBaseForms = int(keepSeqTextSpaced) + 1

// formModes returns the modes of the forms that matchForms builds for s:
// dropInvisible always, and then each other mode that s needs. The order of
// the list sets the form numbers of matchForms, so it follows the order of
// the formMode constants.
func formModes(s string) []formMode {
	raw := cutAtRune(s, maxRawScanBytes)
	hasControl := strings.ContainsFunc(raw, isInvisibleControl)
	hasFormat := strings.ContainsFunc(raw, isInvisibleFormat)
	seqStart := hasSeqStart(raw)
	modes := []formMode{dropInvisible}
	if hasControl || hasFormat {
		modes = append(modes, spaceInvisible)
	}
	if hasControl {
		modes = append(modes, spaceControls)
	}
	if hasControl && hasFormat {
		modes = append(modes, spaceFormats)
	}
	if seqStart {
		modes = append(modes, keepSeqText)
	}
	if hasSeqC0(raw) {
		modes = append(modes, dropSeqC0)
	}
	if seqStart {
		modes = append(modes, keepSeqTextSpaced)
	}
	return modes
}

// matchWindowCut reports whether the regex and keyword matchers can miss a
// part of s because of a byte cap. That is so when s is longer than
// maxRawScanBytes, or when step 6 or step 9 of normalizeForMatch cuts a form
// of matchForms at MaxMatchInputBytes (see buildFormCut).
//
// It checks each form, not only the first, also a form that is equal to an
// earlier one. The other forms can be longer than the first: in the second
// form each run of invisible runes becomes a space instead of nothing. So
// invisible padding can push a payload out of the window of one form only.
//
// For a mode that keeps the text of escape sequences (see keepsSeqText), it
// checks the form without the text of each OSC (see ansiKeepCSIText). So the
// letters that a CSI gives back and the spaces around an OSC count, and
// padding with ESC [ A or with empty OSCs cannot push a payload out of the
// window of these forms. The text of an OSC does not count: a benign text
// near MaxMatchInputBytes with OSC 8 links (each link URL is OSC text) is
// longer than the window in these forms only. A payload that only these forms
// show, after more than MaxMatchInputBytes of OSC text, is a known limit of
// matchForms.
func matchWindowCut(s string) bool {
	if len(s) > maxRawScanBytes {
		return true
	}
	for _, mode := range formModes(s) {
		ansi := mode.ansiStep
		if mode.keepsSeqText() {
			ansi = ansiKeepCSIText
		}
		if _, cut := buildFormCut(s, mode, ansi); cut {
			return true
		}
	}
	return false
}

// hasSeqStart reports whether s holds a rune that can start an ANSI escape
// sequence in ansiSeqC0: ESC, U+009B (CSI) or U+009D (OSC) (see startsSeq).
// matchForms adds the fifth and the seventh form only then. Such a rune is
// also an invisible control rune, so the seventh form can differ from the
// fifth even when s holds no other invisible rune: a lone ESC is dropped in
// the fifth form and is a space in the seventh. appendNew drops the seventh
// form when it equals another form.
func hasSeqStart(s string) bool {
	return strings.ContainsFunc(s, startsSeq)
}

// hasSeqC0 reports whether s holds ESC or U+009B, which start a CSI, and a C0
// control rune of csiC0. matchForms adds the sixth form only then. Without
// both, ansiSeqC0 finds the same CSIs as ansiSeq. It is a cheap check: the
// two runes need not be in the same sequence, and appendNew drops the sixth
// form when it equals another form.
//
// ansiSeq and ansiSeqC0 differ in one more way: in ansiSeqC0, a U+009D ends
// the text of an OSC (see oscExprC0). So without a C0 rune, the sixth form
// can still differ from the first, when an OSC text holds U+009D. It is not
// built then, but the fifth and the seventh form read the same sequences
// with ansiSeqC0 and keep more of the text, so no match is lost.
func hasSeqC0(s string) bool {
	return strings.ContainsFunc(s, startsCSI) && csiC0Rune.MatchString(s)
}

// appendNew appends f to forms when forms does not hold it yet.
func appendNew(forms []string, f string) []string {
	if slices.Contains(forms, f) {
		return forms
	}
	return append(forms, f)
}

// isASCII reports whether every byte of s is ASCII (less than 0x80).
func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// normalizeForMatch returns the form of s that the regex and keyword matchers
// read. So "ign" + ZWSP (U+200B) + "ore previous" still matches the keyword
// "ignore previous". It is buildForm(s, dropInvisible), the first
// form of matchForms.
//
// It works in nine steps:
//
//  1. Cut s to maxRawScanBytes, at a rune boundary.
//  2. Drop the invisible runes that are not control runes, such as ZWSP
//     (see replaceFormatRuns).
//  3. Replace each ANSI escape sequence (see ansiToSpace) with U+0020.
//  4. Drop the invisible control runes that are left, such as U+0001 and an
//     ESC that does not start an escape sequence (see isInvisibleControl).
//  5. Replace each white-space rune that RE2 \s does not match (see
//     spacesToASCII) with U+0020.
//  6. Cut the result to MaxMatchInputBytes, at a rune boundary.
//  7. Apply Unicode normalization form NFC, which joins a letter and its
//     combining marks into one rune where one exists.
//  8. Drop the invisible runes again.
//  9. Cut to MaxMatchInputBytes again, because NFC can make some text up to
//     three times longer (U+1D160 becomes three runes).
//
// Steps 2 and 4 come before step 6, so invisible padding does not use up the
// MaxMatchInputBytes window. Steps 3 and 5 come before step 6 too, so an
// escape sequence or a space of up to 3 bytes counts as 1 byte in the window.
// Step 9 keeps the regexes at MaxMatchInputBytes, so the cost bound in
// match.go holds.
//
// Step 2 comes before step 3, so a ZWSP inside ESC [ 8 m does not stop the
// sequence from being found. Step 4 comes after step 3, so step 3 still sees
// the control runes that start, end or cancel a sequence (see ansiToSpace),
// and a dropped control rune cannot join the parts of an ansiSeq match: if
// U+0001 were dropped before step 3, ESC [ U+0001 "Ignore" would become ESC
// [ I, which ansiSeq reads as a CSI that hides the "I". A terminal reads a
// C0 rune inside a CSI in another way: it runs the rune and goes on with the
// sequence, so ESC [ U+0001 8 m still hides the text after it. ansiSeq does
// not match such a sequence, so this form keeps "[8m". The forms 4 to 7 of
// matchForms read it with ansiSeqC0 (see dropSeqC0). The invisible_unicode
// heuristic flags its ESC in a description.
//
// Step 2 comes before NFC, so an invisible rune cannot block composition:
// "e" + ZWSP + U+0301 becomes U+00E9 (e with acute), the same as "e" + U+0301.
//
// Step 8 exists because the norm package follows the Stream-Safe Text Format:
// after 30 or more combining marks in a row, it inserts a CGJ (U+034F), which
// is invisible. The second pass removes it.
//
// Invalid UTF-8 does not cause a panic: each bad byte becomes U+FFFD
// (utf8.RuneError), as with strings.Map.
func normalizeForMatch(s string) string {
	return buildForm(s, dropInvisible)
}

// formMode tells buildForm what to do with the invisible runes
// (see isInvisible) and with the ANSI escape sequences. Each mode builds one
// form of matchForms.
type formMode int

const (
	// dropInvisible drops every invisible rune. It builds the first form,
	// the form of normalizeForMatch.
	dropInvisible formMode = iota
	// spaceInvisible replaces each run of invisible runes, of any kind, with
	// one U+0020, or with two when the run has a control rune and ends with
	// a format rune (see replaceRuns). It builds the second form.
	spaceInvisible
	// spaceControls drops the format runes (see isInvisibleFormat), and
	// replaces each run of invisible control runes with one U+0020. The
	// dropped runes do not end a run, so U+0001 + ZWSP + U+0001 is one
	// space. It builds the third form.
	spaceControls
	// spaceFormats replaces each run of invisible runes that holds a format
	// rune with one U+0020, and drops the control runes. A run of only
	// control runes becomes nothing. The control runes of a run stay in the
	// text until the ANSI step, and the space goes before them when one of
	// them is ESC, U+009B or U+009D, so that the sequence it starts is still
	// found (see placeOnce). Its ANSI step reads the sequences with
	// ansiSeqC0. It builds the fourth form.
	spaceFormats
	// keepSeqText drops every invisible rune, as dropSeqC0 does, but it
	// keeps the text that an escape sequence takes (see seqText): a CSI
	// whose final byte is a letter gives back that letter and its parameter
	// bytes < = > ? and its intermediate bytes, an SGR (final 'm') becomes
	// nothing, and an OSC becomes its text between two U+0020. Its ANSI
	// step reads the sequences with ansiSeqC0 (see ansiKeepText). It builds
	// the fifth form.
	keepSeqText
	// dropSeqC0 drops every invisible rune, as dropInvisible does, but its
	// ANSI step reads the sequences with ansiSeqC0, so a CSI can hold C0
	// control runes, and it replaces each sequence with one U+0020 (see
	// ansiC0ToSpace). It builds the sixth form.
	dropSeqC0
	// keepSeqTextSpaced handles the runs of invisible runes as
	// spaceInvisible does, and the escape sequences as keepSeqText does
	// (see ansiKeepText). So a run that holds a format rune gets one U+0020
	// before the ANSI step, and a control run becomes one U+0020 after it,
	// also inside the text of an OSC. The U+0020 of a run goes as in
	// spaceFormats (see placeOnce): before the control runes of the run
	// when one of them is ESC, U+009B or U+009D, and after them otherwise.
	// So ZWSP + ESC + "[1m" is U+0020 + ESC + "[1m", and the SGR does not
	// join the words around it. It builds the seventh form.
	keepSeqTextSpaced
)

// String returns the name of the constant of m, such as "spaceInvisible", so
// a test can print a mode. A value that is not a mode gives
// "formMode(N)".
func (m formMode) String() string {
	switch m {
	case dropInvisible:
		return "dropInvisible"
	case spaceInvisible:
		return "spaceInvisible"
	case spaceControls:
		return "spaceControls"
	case spaceFormats:
		return "spaceFormats"
	case keepSeqText:
		return "keepSeqText"
	case dropSeqC0:
		return "dropSeqC0"
	case keepSeqTextSpaced:
		return "keepSeqTextSpaced"
	}
	return "formMode(" + strconv.Itoa(int(m)) + ")"
}

// formatRepl returns what a run of invisible runes that holds a format rune
// becomes in mode m: U+0020, or -1 when its format runes are dropped.
func (m formMode) formatRepl() rune {
	switch m {
	case spaceInvisible, spaceFormats, keepSeqTextSpaced:
		return ' '
	}
	return -1
}

// controlRepl returns what a run of invisible control runes becomes in mode
// m after the ANSI step: U+0020, or -1 when the run is dropped.
func (m formMode) controlRepl() rune {
	switch m {
	case spaceInvisible, spaceControls, keepSeqTextSpaced:
		return ' '
	}
	return -1
}

// runPlace returns where replaceFormatRuns puts the repl of a run in mode m:
// placeOnce for spaceFormats and keepSeqTextSpaced, and placeAtTail for the
// other modes. In keepSeqTextSpaced, placeAtTail would write no space for a
// run such as ZWSP + ESC, which ends with a kept rune. Then the SGR that the
// ESC starts becomes nothing, and two words join: "run" + ZWSP + ESC +
// "ning" would be "running". placeOnce writes the space before the ESC.
func (m formMode) runPlace() runPlace {
	if m == spaceFormats || m == keepSeqTextSpaced {
		return placeOnce
	}
	return placeAtTail
}

// keepsSeqText reports whether mode m keeps the text of escape sequences:
// true for keepSeqText and keepSeqTextSpaced, which build the fifth and the
// seventh form of matchForms. matchWindowCut reads these modes with
// ansiKeepCSIText.
func (m formMode) keepsSeqText() bool {
	return m == keepSeqText || m == keepSeqTextSpaced
}

// ansiStep runs step 3 of normalizeForMatch on s for mode m: ansiKeepText
// for keepSeqText and keepSeqTextSpaced, ansiC0ToSpace for spaceFormats and
// dropSeqC0, and ansiToSpace for the other modes. So the forms 1 to 3 of
// matchForms read the sequences with ansiSeq, and the forms 4 to 7 with
// ansiSeqC0.
func (m formMode) ansiStep(s string) string {
	switch m {
	case keepSeqText, keepSeqTextSpaced:
		return ansiKeepText(s)
	case spaceFormats, dropSeqC0:
		return ansiC0ToSpace(s)
	}
	return ansiToSpace(s)
}

// buildForm runs the steps of normalizeForMatch, with the invisible
// runes and the escape sequences handled as mode says. In each mode, the
// white space is mapped as in normalizeForMatch.
func buildForm(s string, mode formMode) string {
	out, _ := buildFormCut(s, mode, mode.ansiStep)
	return out
}

// buildFormCut is buildForm with ansi as its ANSI step
// (step 3), and it also reports whether step 6 or step 9 of
// normalizeForMatch cut the text at MaxMatchInputBytes. When the flag is
// true, the form misses the end of the text, so a matcher cannot see a
// payload there. The cut of step 1 (maxRawScanBytes) is not in the flag:
// matchWindowCut checks the raw length itself.
func buildFormCut(s string, mode formMode, ansi func(string) string) (string, bool) {
	s = cutAtRune(s, maxRawScanBytes)
	s = replaceFormatRuns(s, mode)
	s = ansi(s)
	s = replaceInvisible(s, mode.controlRepl()) // only invisible control runes are left
	s = spacesToASCII(s)
	cut := len(s) > MaxMatchInputBytes // step 6 cuts the text
	s = cutAtRune(s, MaxMatchInputBytes)
	s = norm.NFC.String(s)
	s = replaceInvisible(s, mode.formatRepl())
	if len(s) > MaxMatchInputBytes { // step 9 cuts the text
		cut = true
	}
	return cutAtRune(s, MaxMatchInputBytes), cut
}

// re2SpaceRunes are the runes that RE2 \s matches.
const re2SpaceRunes = "\t\n\f\r "

// spacesToASCII replaces with U+0020 each rune that separates two words for a
// reader or a model but that RE2 \s does not match: the white space of
// isKeywordSpace that is not in re2SpaceRunes, such as VT, NEL (U+0085), the
// Z categories (NBSP, the em space, U+2028, U+2029 and others) and U+2800,
// the Braille blank that looks like a space.
//
// In RE2, \s is only [\t\n\f\r ], so without this step "ignore" + NBSP +
// "previous" would not match `ignore\s+previous`. The runes in re2SpaceRunes
// stay as they are, so a newline is still a newline.
//
// NFC never makes such a rune from other runes (it maps U+2000 and U+2001
// only to other spaces, which this step has already removed), so one pass
// before NFC is enough. Every mapped rune is at least 1 byte long, so the
// text does not grow.
func spacesToASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if isKeywordSpace(r) && !strings.ContainsRune(re2SpaceRunes, r) {
			return ' '
		}
		return r
	}, s)
}

// foldMarks folds s, which comes from normalizeForMatch, for the keyword and
// regex matchers. It applies the compatibility forms of Unicode (NFKD and
// NFKC) and removes the combining marks (category M: non-spacing, spacing
// and enclosing). The keyword matcher applies it to the keyword and to the
// text, so:
//
//   - a mark cannot hide a keyword: "ig" + U+0336 + "nore" and "previou" +
//     U+015B (s with acute) still match "ignore previous";
//   - fullwidth letters (U+FF49 for "i") and mathematical letters (U+1D422
//     for bold "i") match the plain letters;
//   - accents are folded, so the keyword "caf" + U+00E9 matches "cafe", and in
//     scripts such as Devanagari the vowel signs are dropped.
//
// The regex matchers apply it only to the text, not to the pattern, and they
// keep the forms before the fold too (see preparedText.regexForms).
//
// foldMarks and appendFold fold only what NFKD and the mark rules above
// fold. They do not fold homoglyphs from other scripts (Cyrillic U+0430 for
// Latin "a"). The regex forms add the confusable skeleton of confusables.go
// (foldSkeleton) to this fold, so the regexes read U+0430 as "a". The
// keyword matcher does not get the skeleton: its text and its keywords are
// folded with foldMarks only. mixedScript counts the scripts of each word
// with appendFold, so the skeleton does not change it: the mixed_script
// heuristic still flags a word that mixes letters of two or more look-alike
// scripts, such as Latin and Cyrillic.
//
// It folds s one rune at a time (see appendFold), and it uses the fold of a
// rune only when the fold is not longer, in bytes, than the rune. Otherwise
// the rune stays as it is. So the result is never longer than s, and it
// covers at least the same part of the raw text as s: padding with a rune
// that folds to many letters, such as the ligature U+FDFA, cannot push a
// payload out of the MaxMatchInputBytes window. Fullwidth letters (3 bytes
// to 1), mathematical letters (4 bytes to 1), precomposed accents and the
// ligature U+FB03 ("ffi", 3 bytes to 3) are folded, and the combining marks
// are dropped. U+FDFA (3 bytes to 33) and a few other runes, such as the
// fraction U+00BD ("1/2" with U+2044) and the roman numeral U+2177 ("viii"),
// are not folded.
//
// Because the runes are folded one at a time, two runes that NFKC would join
// across a rune edge (such as the halfwidth Hangul letters U+FFA1 and
// U+FFC2) stay apart. The input is NFC, so such pairs are rare.
//
// An invalid byte stays as it is, so the result is valid UTF-8 when s is.
// The result is cut to MaxMatchInputBytes, as defence in depth for the cost
// bound in match.go; the rule above already keeps a form within it.
func foldMarks(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if size == 1 { // ASCII folds to itself; keep an invalid byte too
			out = append(out, s[i])
		} else {
			out = appendFold(out, r, s[i:i+size])
		}
		i += size
	}
	return cutAtRune(string(out), MaxMatchInputBytes)
}

// appendFold appends the fold of the rune r, whose UTF-8 bytes are rs, to dst
// and returns the extended slice, as append does. The fold splits the rune
// into its compatibility parts (NFKD), drops the combining marks and the
// invisible runes, and joins the rest again (NFKC). So U+00E9 (e with
// acute) becomes "e", U+FF49 becomes "i", U+0336 becomes nothing, and the
// Hangul syllable U+D55C stays U+D55C. When the fold is longer than rs,
// appendFold appends rs instead (see foldMarks).
//
// Most runes have no compatibility decomposition. Such a rune is its own NFKD
// and NFKC, so it is appended as it is, or not at all for a mark or an
// invisible rune.
func appendFold(dst []byte, r rune, rs string) []byte {
	parts := norm.NFKD.PropertiesString(rs).Decomposition()
	if parts == nil {
		if unicode.Is(unicode.M, r) || isInvisible(r) {
			return dst
		}
		return append(dst, rs...)
	}
	start := len(dst) // the fold is dst[start:]
	for _, r := range string(parts) {
		if !unicode.Is(unicode.M, r) && !isInvisible(r) {
			dst = utf8.AppendRune(dst, r)
		}
	}
	if !norm.NFKC.IsNormal(dst[start:]) { // rare: Hangul letters to join
		joined := norm.NFKC.Bytes(dst[start:])
		dst = append(dst[:start], joined...)
	}
	if len(dst)-start > len(rs) {
		dst = append(dst[:start], rs...)
	}
	return dst
}

// replaceFormatRuns is step 2 of normalizeForMatch. It rewrites each run of
// invisible runes in s for mode (see replaceRuns): it keeps the invisible
// control runes of the run for step 4, which runs after the ANSI step (see
// normalizeForMatch for why), and it writes mode.formatRepl() for the format
// runes of the run, or drops them when that is -1. mode.runPlace() says where
// the repl goes. Step 4 then replaces the kept control runes with one rune or
// drops them.
func replaceFormatRuns(s string, mode formMode) string {
	return replaceRuns(s, isInvisibleControl, mode.formatRepl(), mode.runPlace())
}

// replaceInvisible returns s with each run of runes for which isInvisible is
// true replaced by one repl. A repl of -1 drops the runes.
func replaceInvisible(s string, repl rune) string {
	return replaceRuns(s, keepNone, repl, placeAtTail)
}

// keepNone returns false for every rune. replaceInvisible uses it to keep no
// rune of a run.
func keepNone(rune) bool { return false }

// runPlace tells replaceRuns when and where it writes the repl of a run of
// invisible runes, relative to the runes of the run that it keeps.
type runPlace int

const (
	// placeAtTail writes one repl after the kept runes, and only when the
	// run ends with runes that are not kept. So a kept ESC does not join the
	// rune after the run: in the second form of matchForms, ESC + ZWSP +
	// "[" is ESC + U+0020 + "[", not a CSI.
	placeAtTail runPlace = iota
	// placeOnce writes one repl when the run has a rune that is not kept,
	// wherever that rune is. The repl goes before the kept runes when one of
	// them is ESC, U+009B or U+009D (see startsSeq), and after them
	// otherwise. So in the fourth form of matchForms, ESC + ZWSP + "[8m" and
	// ESC + ZWSP + U+0001 + "[8m" keep their CSI after the U+0020, and
	// U+0001 + ZWSP + "all" is U+0001 + U+0020 + "all".
	placeOnce
)

// replaceRuns rewrites each run of runes in s for which isInvisible is true.
// It writes the runes of the run for which keep is true, in order and with
// nothing between them, and at most one repl, as place says (see runPlace).
// A repl of -1 writes nothing. So a run with no kept rune becomes one repl
// in both places. The other runes of s stay as they are.
//
// A run holds at least one rune that is not kept when it gets a repl, and a
// repl is 1 byte, so a run never grows. So valid UTF-8 text does not grow;
// in invalid UTF-8, each bad byte becomes 3 bytes (see below).
//
// Invalid UTF-8 becomes U+FFFD, as with strings.Map. U+FFFD is not
// invisible, so it ends a run.
func replaceRuns(s string, keep func(rune) bool, repl rune, place runPlace) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !isInvisible(r) {
			b.WriteRune(r)
			i += size
			continue
		}
		end := i + size // the run is s[i:end]
		for end < len(s) {
			r, size := utf8.DecodeRuneInString(s[end:])
			if !isInvisible(r) {
				break
			}
			end += size
		}
		writeRun(&b, s[i:end], keep, repl, place)
		i = end
	}
	return b.String()
}

// writeRun writes run, a run of invisible runes, to b for replaceRuns: the
// runes of run for which keep is true, and repl as place says. The runes of
// a run are invisible, so they are valid UTF-8.
func writeRun(b *strings.Builder, run string, keep func(rune) bool, repl rune, place runPlace) {
	seqKept := false // a kept rune of the run starts a sequence
	dropped := false // the run has a rune that is not kept
	tail := false    // the run ends with runes that are not kept
	for _, r := range run {
		if keep(r) {
			seqKept, tail = seqKept || startsSeq(r), false
		} else {
			dropped, tail = true, true
		}
	}
	var space, before bool
	switch place {
	case placeAtTail:
		space = tail
	case placeOnce:
		space, before = dropped, seqKept
	}
	space = space && repl >= 0
	if space && before {
		b.WriteRune(repl)
	}
	for _, r := range run {
		if keep(r) {
			b.WriteRune(r)
		}
	}
	if space && !before {
		b.WriteRune(repl)
	}
}

// startsSeq reports whether r is ESC, U+009B (CSI) or U+009D (OSC), a rune
// that starts an ANSI escape sequence in ansiSeq and ansiSeqC0.
func startsSeq(r rune) bool {
	return startsCSI(r) || r == '\u009d'
}

// startsCSI reports whether r is ESC or U+009B, a rune that starts a CSI in
// ansiSeq and ansiSeqC0.
func startsCSI(r rune) bool {
	return r == '\x1b' || r == '\u009b'
}

// cutAtRune returns at most the first n bytes of s. It never splits a
// multi-byte rune: when byte n is inside a rune, the cut moves back to the
// start of that rune. A rune is at most utf8.UTFMax bytes long, so the cut
// moves back at most utf8.UTFMax-1 bytes, also for invalid UTF-8.
func cutAtRune(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := n
	for i > 0 && i > n-(utf8.UTFMax-1) && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i]
}
