package rules

import (
	"regexp"
	"slices"
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
// most seven forms. The conditions below look only at the part of s that
// normalizeForMatch reads (the first maxRawScanBytes).
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
//     bytes (such as "." and "/"), and its final letter. So ESC [ "Ignore" is " Ignore", ESC [ "<IMPORTANT>" is
//     " <IMPORTANT>" and ESC [ ".env" is " .env". Its numeric parameter bytes
//     (digits, ";" and ":") are dropped, so ESC [ 2 K is " K". A CSI with the
//     final 'm' is SGR (colour and bold): it becomes nothing, as a terminal
//     shows it. So ESC [ 1 m "iPhone" is "iPhone", not "miPhone", and "Ig" +
//     ESC [ 0 m + "nore" is "Ignore". An OSC becomes its text between two
//     spaces: ESC ] "Ignore all" BEL is " Ignore all ".
//  6. When s holds ESC or U+009B and a C0 control rune of csiC0 (see
//     hasSeqC0): as the first form, but a CSI can hold C0 control runes (see
//     dropSeqC0). So ESC + U+0001 + "[8mIgnore" is " Ignore": the first form
//     keeps "[8mIgnore", which has no word edge before "Ignore".
//  7. When s holds a sequence start (see hasSeqStart) and an invisible rune
//     that is not ESC, U+009B or U+009D (see hasPlainInvisible): the ANSI
//     step of the fifth form with the runs of the second form (see
//     keepSeqTextSpaced). So each run of invisible runes is a space, also
//     inside the text that a sequence gives back: ESC ] "Ignore" + ZWSP +
//     "all" BEL is " Ignore all ", and ESC [ "Ignore" + U+0001 + "all" is
//     " Ignore all". As in the fourth form, the space of a run goes before
//     an ESC at its end (see placeOnce), so "run" + ZWSP + ESC [ 1 m +
//     "ning" is "run ning", not "running".
//
// In the forms 2 to 4 and 7, at most two spaces stand for a whole run of
// invisible runes (two only in the second form, for a run that has a
// control rune and ends with a format rune, and in the seventh form, for a
// run that has a control rune and a format rune, see replaceRuns). So
// invisible padding cannot push a payload out of the MaxMatchInputBytes
// window of these forms either.
//
// These texts still defeat all the forms. The invisible_unicode heuristic
// flags each of them in a description:
//
//   - one kind of invisible rune both inside a word and between words, such
//     as a ZWSP in both places, or U+0001 in both places;
//   - text that only a sequence gives back (an OSC text or a CSI letter)
//     together with two kinds of invisible runes, one inside a word and the
//     other between words: in ESC [ "Ig" + ZWSP + "nore" + U+0001 + "all",
//     the fifth form joins "Ignoreall", the seventh form splits "Ig nore",
//     and the other forms lose the "I";
//   - a control rune between ESC (or U+009B, U+009D) and a format rune: the
//     fourth form puts its space before the controls of a run only when the
//     last of them is ESC, U+009B or U+009D. So in ESC + U+0001 + ZWSP +
//     "[8mIgnore" + ZWSP + "all", the fourth form keeps "[8m" before
//     "Ignore", and the other forms join "Ignoreall" or keep "[8m";
//   - a CSI that takes a character of the text that no form gives back: the
//     "m" of a word, as in ESC [ 1 "make" (the CSI ESC [ 1 m and the text
//     "ake") or "you " + ESC [ "must" (an SGR and the text "ust"), a digit,
//     ";" or ":", or a final byte that is not a letter, as in ESC [ "~/.ssh"
//     (the CSI ESC [ ~ and the text "/.ssh");
//   - a payload that only the fifth or the seventh form shows, after more
//     than MaxMatchInputBytes of text that these forms keep from escape
//     sequences (OSC text and CSI bytes). The match_window heuristic flags
//     such a text, because the window cuts the fifth or the seventh form
//     (see matchWindowCut).
//
// The fifth form can also make a token that neither the raw text nor a
// terminal shows, from a rare CSI: it writes a space and gives back the
// kept bytes and the final letter. So "<system" + ESC [ > c + "-info>" (a
// DA2) is "<system >c-info>", ESC [ SP q + ESC [ 1 m + "iPhone" (a
// DECSCUSR before an SGR) gives the word "qiPhone". Such a hit can be a
// false positive. The invisible_unicode heuristic flags the ESC at medium in
// either case.
//
// An OSC with more than 256 runes of text is not an OSC for ansiSeq or
// ansiSeqC0. So its ESC and its end are dropped, and its text stays in every
// form, after its "]": the matchers read that text.
//
// A text without invisible runes and escape sequences has one form, so it
// costs no more. A text with them is matched up to seven times, which is
// seven times the cost bound in match.go. The regex matchers also read the
// folds (see preparedText.regexForms).
func matchForms(s string) []string {
	forms, _ := matchFormsCut(s)
	return forms
}

// matchWindowCut reports whether the regex and keyword matchers can miss a
// part of s because of a byte cap. That is so when s is longer than
// maxRawScanBytes, or when step 6 or step 9 of normalizeForMatch cuts one of
// the forms of matchForms at MaxMatchInputBytes.
//
// It checks every form, not only the first. The other forms can be longer
// than the first: in the second form each run of invisible runes becomes a
// space instead of nothing, and the fifth and the seventh form keep the text
// of escape sequences. So invisible padding or OSC text can push a payload
// out of the window of one of these forms only.
func matchWindowCut(s string) bool {
	if len(s) > maxRawScanBytes {
		return true
	}
	_, cut := matchFormsCut(s)
	return cut
}

// matchFormsCut returns the forms of matchForms, and true when step 6 or
// step 9 of normalizeForMatch cut one of them (see normalizeInvisibleCut).
// The flag covers each form that it builds, also a form that is equal to an
// earlier form and so is not added to the list.
func matchFormsCut(s string) ([]string, bool) {
	first, cut := normalizeInvisibleCut(s, dropInvisible)
	forms := []string{first}
	raw := cutAtRune(s, maxRawScanBytes)
	hasControl := strings.ContainsFunc(raw, isInvisibleControl)
	hasFormat := strings.ContainsFunc(raw, isInvisibleFormat)
	seqStart := hasSeqStart(raw)
	var modes []invisibleMode
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
	if seqStart && hasPlainInvisible(raw) {
		modes = append(modes, keepSeqTextSpaced)
	}
	for _, mode := range modes {
		f, fCut := normalizeInvisibleCut(s, mode)
		forms = appendNew(forms, f)
		cut = cut || fCut
	}
	return forms, cut
}

// hasSeqStart reports whether s holds a rune that can start an ANSI escape
// sequence in ansiSeqC0: ESC, U+009B (CSI) or U+009D (OSC) (see startsSeq).
// matchForms adds the fifth form only then, and the seventh form only then
// and with hasPlainInvisible.
func hasSeqStart(s string) bool {
	return strings.ContainsFunc(s, startsSeq)
}

// hasPlainInvisible reports whether s holds an invisible rune (see
// isInvisible) that is not ESC, U+009B or U+009D (see startsSeq). Without
// one, the seventh form of matchForms is the fifth form. It is a cheap check:
// the rune can also be a part of a sequence, such as the BEL that ends an
// OSC, and appendNew drops the seventh form when it equals another form.
func hasPlainInvisible(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool {
		return isInvisible(r) && !startsSeq(r)
	})
}

// hasSeqC0 reports whether s holds ESC or U+009B, which start a CSI, and a C0
// control rune of csiC0. matchForms adds the sixth form only then. Without
// both, ansiSeqC0 finds the same sequences as ansiSeq, so the sixth form is
// the first form. It is a cheap check: the two runes need not be in the same
// sequence, and appendNew drops the sixth form when it equals another form.
// U+009D starts only an OSC, and ansiSeq and ansiSeqC0 read an OSC the same
// way, so it does not count here.
func hasSeqC0(s string) bool {
	return strings.ContainsAny(s, "\x1b\u009b") && csiC0Rune.MatchString(s)
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
// "ignore previous". It is normalizeInvisible(s, dropInvisible), the first
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
	return normalizeInvisible(s, dropInvisible)
}

// invisibleMode tells normalizeInvisible what to do with the invisible runes
// (see isInvisible) and with the ANSI escape sequences. Each mode builds one
// form of matchForms.
type invisibleMode int

const (
	// dropInvisible drops every invisible rune. It builds the first form,
	// the form of normalizeForMatch.
	dropInvisible invisibleMode = iota
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
	// text until the ANSI step, and the space goes before them when the last
	// of them is ESC, U+009B or U+009D, so that the sequence it starts is
	// still found (see placeOnce). Its ANSI step reads the sequences with
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
	// when the last of them is ESC, U+009B or U+009D, and after them
	// otherwise. So ZWSP + ESC + "[1m" is U+0020 + ESC + "[1m", and the SGR
	// does not join the words around it. It builds the seventh form.
	keepSeqTextSpaced
)

// formatRepl returns what a run of invisible runes that holds a format rune
// becomes in mode m: U+0020, or -1 when its format runes are dropped.
func (m invisibleMode) formatRepl() rune {
	switch m {
	case spaceInvisible, spaceFormats, keepSeqTextSpaced:
		return ' '
	}
	return -1
}

// controlRepl returns what a run of invisible control runes becomes in mode
// m after the ANSI step: U+0020, or -1 when the run is dropped.
func (m invisibleMode) controlRepl() rune {
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
func (m invisibleMode) runPlace() runPlace {
	if m == spaceFormats || m == keepSeqTextSpaced {
		return placeOnce
	}
	return placeAtTail
}

// ansiStep runs step 3 of normalizeForMatch on s for mode m: ansiKeepText
// for keepSeqText and keepSeqTextSpaced, ansiC0ToSpace for spaceFormats and
// dropSeqC0, and ansiToSpace for the other modes. So the forms 1 to 3 of
// matchForms read the sequences with ansiSeq, and the forms 4 to 7 with
// ansiSeqC0.
func (m invisibleMode) ansiStep(s string) string {
	switch m {
	case keepSeqText, keepSeqTextSpaced:
		return ansiKeepText(s)
	case spaceFormats, dropSeqC0:
		return ansiC0ToSpace(s)
	}
	return ansiToSpace(s)
}

// normalizeInvisible runs the steps of normalizeForMatch, with the invisible
// runes and the escape sequences handled as mode says. In each mode, the
// white space is mapped as in normalizeForMatch. It is normalizeInvisibleCut
// without the cut flag.
func normalizeInvisible(s string, mode invisibleMode) string {
	out, _ := normalizeInvisibleCut(s, mode)
	return out
}

// normalizeInvisibleCut is normalizeInvisible, and it also reports whether
// step 6 or step 9 of normalizeForMatch cut the text at MaxMatchInputBytes.
// When the flag is true, the form misses the end of the text, so a matcher
// cannot see a payload there. The cut of step 1 (maxRawScanBytes) is not in
// the flag: matchWindowCut checks the raw length itself.
func normalizeInvisibleCut(s string, mode invisibleMode) (string, bool) {
	s = cutAtRune(s, maxRawScanBytes)
	s = replaceFormatRuns(s, mode)
	s = mode.ansiStep(s)
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

// oscExpr matches an OSC: ESC ] (or U+009D), at most 256 runes of text, and
// BEL, ESC \ or U+009C. ansiSeq and ansiSeqC0 share it.
const oscExpr = `(?:\x1b\]|\x{9d})[^\x07\x1b\x{9c}]{0,256}(?:\x07|\x1b\\|\x{9c})`

// ansiSeq matches an ANSI escape sequence that a terminal runs and does not
// show:
//
//   - CSI: ESC [ (or U+009B), parameter and intermediate bytes, and a final
//     byte, such as ESC [ 8 m (SGR 8, which hides the text after it);
//   - OSC: ESC ] (or U+009D), at most 256 runes of text, and BEL, ESC \ or
//     U+009C (see oscExpr).
//
// An OSC with no end, or with more than 256 runes of text, does not match,
// so it cannot swallow the rest of the text; its ESC is an invisible control
// rune, so step 4 of normalizeForMatch drops it, and its text stays.
//
// A CSI here holds no C0 control rune. The forms 1 to 3 of matchForms read
// the sequences with ansiSeq. The forms 4 to 7 read them with ansiSeqC0.
var ansiSeq = regexp.MustCompile(`(?:\x1b\[|\x{9b})[0-?]*[ -/]*[@-~]|` + oscExpr)

// csiC0 is the content of a regex class: the C0 control runes that a
// terminal (VT500 and xterm) runs inside a CSI and then goes on with the
// sequence. It is U+0000 to U+001F and DEL (U+007F), but not CAN (U+0018) and
// SUB (U+001A), which cancel the sequence, and not ESC (U+001B), which starts
// a new one. It holds TAB, LF and CR too.
const csiC0 = `\x00-\x17\x19\x1c-\x1f\x7f`

// csiC0Rune matches one rune of csiC0 (see hasSeqC0).
var csiC0Rune = regexp.MustCompile(`[` + csiC0 + `]`)

// ansiSeqC0 is ansiSeq, but a CSI can hold C0 control runes (see csiC0), as
// in a terminal: between ESC and "[", and among the parameter and
// intermediate bytes. So ESC + U+0001 + "[8m" and U+009B + U+0001 + "8m" are
// a CSI too. The OSC is the same as in ansiSeq (oscExpr).
//
// The final byte of a CSI can be a letter of the text: in ESC [ "Ignore",
// the CSI is ESC [ I, as for a terminal. And a C0 rune lets a CSI take
// parameter bytes of the text: ESC [ LF "<IMPORTANT>" is the CSI ESC [ LF < I.
// So only the forms 4 to 7 of matchForms read the sequences with ansiSeqC0,
// and the fifth and the seventh form give back the text of a CSI with a
// letter final byte (see ansiKeepText).
var ansiSeqC0 = regexp.MustCompile(
	`(?:\x1b[` + csiC0 + `]*\[|\x{9b})[0-?` + csiC0 + `]*[ -/` + csiC0 + `]*[@-~]` +
		`|` + oscExpr)

// ansiToSpace replaces each ANSI escape sequence (see ansiSeq) with U+0020.
// Without this step, ESC [ 8 m before "Ignore" leaves "[8mIgnore", and the
// word edge before "Ignore" is lost. A sequence is at least 2 bytes long, so
// the text does not grow.
//
// These control runes change how a sequence is read, and they are invisible
// control runes (see isInvisible). So normalizeInvisible drops or replaces
// them only after this step:
//
//   - ESC (U+001B) and the C1 controls CSI (U+009B), ST (U+009C) and OSC
//     (U+009D) start or end a sequence in ansiSeq;
//   - BEL (U+0007) ends an OSC in ansiSeq;
//   - the other C0 control runes (see csiC0) can stand inside a CSI of
//     ansiSeqC0 (see ansiC0ToSpace);
//   - CAN (U+0018) and SUB (U+001A) cancel a sequence in a terminal, and the
//     terminal shows the text after them. They are still in the text here,
//     so ESC [ CAN "Ignore" is not read as ESC [ I, a CSI that hides the "I".
func ansiToSpace(s string) string {
	return ansiSeq.ReplaceAllLiteralString(s, " ")
}

// ansiC0ToSpace is ansiToSpace with ansiSeqC0: it replaces each ANSI escape
// sequence, also a CSI that holds C0 control runes, with U+0020. It is the
// ANSI step of the fourth and the sixth form of matchForms. A sequence is at
// least 2 bytes long, so the text does not grow.
func ansiC0ToSpace(s string) string {
	return ansiSeqC0.ReplaceAllLiteralString(s, " ")
}

// ansiKeepText is the ANSI step of the fifth and the seventh form of
// matchForms (see keepSeqText and keepSeqTextSpaced). It replaces each ANSI
// escape sequence (see ansiSeqC0) with the text that seqText gives for it.
// So a CSI that takes characters of the text gives them back, and the text
// of an OSC, which a terminal does not show but a model reads, is matched.
//
// No replacement is longer than its sequence, so the text does not grow:
//
//   - a CSI with a letter other than 'm' as its final byte becomes 1 byte
//     (U+0020), its kept parameter and intermediate bytes, and its final
//     byte. It is at least 2 bytes (ESC [ or U+009B), the same kept bytes
//     and more, and its final byte;
//   - an SGR (a CSI with the final byte 'm') becomes nothing;
//   - an OSC becomes its text and 2 bytes, and it is its text and at least 3
//     bytes long (ESC ] and BEL; U+009D is 2 bytes, and its end is 1 or 2
//     bytes);
//   - each other sequence becomes 1 byte, and it is at least 2 bytes long.
func ansiKeepText(s string) string {
	return ansiSeqC0.ReplaceAllStringFunc(s, seqText)
}

// seqText returns what ansiKeepText puts in place of seq, a match of
// ansiSeqC0:
//
//   - for an OSC: U+0020, its text and U+0020;
//   - for a CSI whose final byte is 'm' (SGR: colour and bold): nothing, as a
//     terminal shows it. So "Ig" + ESC [ 0 m + "nore" is "Ignore", and
//     ESC [ 1 m "iPhone" is "iPhone", not "miPhone";
//   - for a CSI whose final byte is another ASCII letter: U+0020, the bytes
//     of csiText, and the final byte. So ESC [ "<IMPORTANT>" (the CSI
//     ESC [ < I) is " <IMPORTANT>", and ESC [ 2 K is " K";
//   - for each other sequence: one U+0020.
func seqText(seq string) string {
	if text, ok := oscText(seq); ok {
		return " " + text + " "
	}
	final := seq[len(seq)-1]
	switch {
	case final == 'm':
		return ""
	case isASCIILetter(final):
		return " " + csiText(seq[:len(seq)-1]) + string(final)
	}
	return " "
}

// csiText returns the bytes of head that a CSI takes from the text: head is
// a CSI of ansiSeqC0 without its final byte. They are its parameter bytes
// < = > ? (0x3C to 0x3F) and its intermediate bytes (0x20 to 0x2F, such as
// "." and "/"), in order. The introducer (ESC, its C0 runes and "[", or
// U+009B), the numeric parameter bytes (digits, ";" and ":") and the C0 runes
// are dropped: a numeric parameter is mostly a real SGR or cursor parameter,
// not text.
func csiText(head string) string {
	if body, ok := strings.CutPrefix(head, "\u009b"); ok {
		head = body
	} else {
		// ESC, C0 runes and "[": the first "[" ends the introducer,
		// because no rune before it and no parameter or intermediate
		// byte is "[".
		_, head, _ = strings.Cut(head, "[")
	}
	kept := make([]byte, 0, len(head))
	for i := range len(head) {
		if c := head[i]; ' ' <= c && c <= '/' || '<' <= c && c <= '?' {
			kept = append(kept, c)
		}
	}
	return string(kept)
}

// oscText returns the text of seq, a match of ansiSeqC0, when seq is an OSC:
// the part between ESC ] (or U+009D) and its end (BEL, ESC \ or U+009C). It
// returns false when seq is a CSI. The text of an OSC holds no BEL, ESC or
// U+009C (see ansiSeqC0), so the end is not ambiguous.
func oscText(seq string) (string, bool) {
	var text string
	switch {
	case strings.HasPrefix(seq, "\x1b]"):
		text = seq[len("\x1b]"):]
	case strings.HasPrefix(seq, "\u009d"):
		text = seq[len("\u009d"):]
	default:
		return "", false
	}
	for _, end := range []string{"\x07", "\x1b\\", "\u009c"} {
		if t, ok := strings.CutSuffix(text, end); ok {
			return t, true
		}
	}
	return text, true // not reached: ansiSeqC0 ends each OSC with one of them
}

// isASCIILetter reports whether c is an ASCII letter, A to Z or a to z.
func isASCIILetter(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
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
// keep the forms before the fold too (see regexForms). Homoglyphs from other
// scripts (Cyrillic U+0430 for Latin "a") are not folded. The mixed_script
// heuristic flags a word that mixes letters of two or more look-alike
// scripts, such as Latin and Cyrillic, instead.
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
// and returns the extended slice, as append does. The fold splits the rune into its
// compatibility parts (NFKD), drops the combining marks and the invisible
// runes, and joins the rest again (NFKC). So U+00E9 (e with acute) becomes
// "e", U+FF49 becomes "i", U+0336 becomes nothing, and the Hangul syllable
// U+D55C stays U+D55C. When the fold is longer than rs, appendFold appends rs
// instead (see foldMarks).
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
func replaceFormatRuns(s string, mode invisibleMode) string {
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
	// wherever that rune is. The repl goes before the kept runes when the
	// last kept rune is ESC, U+009B or U+009D (see startsSeq), and after
	// them otherwise. So in the fourth form of matchForms, ESC + ZWSP + "[8m"
	// is U+0020 + ESC + "[8m", a CSI, and U+0001 + ZWSP + "all" is U+0001 +
	// U+0020 + "all".
	placeOnce
)

// replaceRuns rewrites each run of runes in s for which isInvisible is true.
// It writes the runes of the run for which keep is true, in order and with
// nothing between them, and at most one repl, as place says (see runPlace).
// A repl of -1 writes nothing. So a run with no kept rune becomes one repl
// in both places. The other runes of s stay as they are.
//
// A run holds at least one rune that is not kept when it gets a repl, and a
// repl is 1 byte, so the text does not grow.
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
	lastKept := rune(-1) // the last kept rune of the run, or -1
	dropped := false     // the run has a rune that is not kept
	tail := false        // the run ends with runes that are not kept
	for _, r := range run {
		if keep(r) {
			lastKept, tail = r, false
		} else {
			dropped, tail = true, true
		}
	}
	var space, before bool
	switch place {
	case placeAtTail:
		space = tail
	case placeOnce:
		space = dropped
		before = startsSeq(lastKept)
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
	return r == '\x1b' || r == '\u009b' || r == '\u009d'
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
