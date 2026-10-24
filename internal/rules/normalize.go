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
// The heuristics (max_length, invisible_unicode, base64_blob) see the full raw
// text, so a very long text is still flagged.
const MaxMatchInputBytes = 32 << 10

// maxRawScanBytes is the largest part of the raw text that normalizeForMatch
// reads: 128 KiB. The invisible runes are dropped from this part, so padding
// of up to 96 KiB of invisible runes cannot push a payload out of the
// MaxMatchInputBytes window.
const maxRawScanBytes = 4 * MaxMatchInputBytes

// isInvisible reports whether r is a rune that shows as nothing but can split
// a keyword: a format character (Cf), a variation selector, another
// default-ignorable code point, or a control rune (Cc) that is not white
// space and not one of ansiControls. The few Cf runes that show as a mark
// (the prepended concatenation marks, such as the Arabic number sign U+0600)
// are not invisible.
//
// This covers the zero-width characters (ZWSP, ZWNJ, ZWJ, word joiner), LRM
// and RLM, the bidi embeddings, overrides and isolates, the BOM, the soft
// hyphen, the tag characters (U+E0000 to U+E007F), the variation selectors
// (VS1 to VS256), the combining grapheme joiner (CGJ, U+034F) and the Hangul
// fillers. ZWNJ and ZWJ are also a normal part of Persian and Indic text, so
// invisible_unicode flags such text too.
//
// It also covers the control runes (U+0000 to U+001F and U+007F to U+009F),
// such as NUL, U+0001 and DEL. So "Ig" + U+0001 + "nore" is "Ignore" for the
// matchers, as it is for a model. These control runes are not invisible:
//
//   - the white space of unicode.IsSpace. It separates words, and
//     spacesToASCII maps the white space that RE2 \s does not match;
//   - the runes of ansiControls, which change how an ANSI escape sequence is
//     read, so ansiToSpace must still see them.
//
// normalizeForMatch, the invisible_unicode heuristic and the base64_blob
// heuristic share this one predicate, so they cannot disagree about which
// runes are invisible. The invisible_unicode heuristic also flags the runes
// of ansiControls (see invisibleUnicode).
func isInvisible(r rune) bool {
	if unicode.IsControl(r) { // category Cc
		return !unicode.IsSpace(r) && !isANSIControl(r)
	}
	return unicode.In(r,
		unicode.Cf,
		unicode.Variation_Selector,
		unicode.Other_Default_Ignorable_Code_Point,
	) && !unicode.Is(unicode.Prepended_Concatenation_Mark, r)
}

// isInvisibleControl reports whether r is an invisible rune (see isInvisible)
// that is also a control rune (category Cc), such as U+0000 or U+0001.
func isInvisibleControl(r rune) bool {
	return unicode.IsControl(r) && isInvisible(r)
}

// matchForms returns the forms of s that the regex and keyword matchers read.
// A matcher reports a match when one form matches. Each form is at most
// MaxMatchInputBytes long, and equal forms are kept only once.
//
// The first form is normalizeForMatch(s): the invisible runes are dropped, so
// "ign" + ZWSP + "ore" is "ignore".
//
// When s holds an invisible rune in the part that normalizeForMatch reads,
// the second form replaces each run of invisible runes with one space
// instead, so "ignore" + ZWSP + "previous" is "ignore previous" and a keyword
// edge next to a ZWSP still holds. One space for a whole run means that
// invisible padding cannot push a payload out of the MaxMatchInputBytes
// window of this form either.
//
// When that part also holds an invisible control rune (see
// isInvisibleControl), the third form drops the other invisible runes and
// replaces each invisible control rune with one space. So "Ig" + ZWSP +
// "nore" + U+0001 + "previous" is "Ignore previous": the ZWSP joins a word
// and the control rune splits two words. The first form joins all the words,
// and the second form splits the first word.
//
// A text that uses one kind of invisible rune both inside a word and between
// words defeats all the forms; the invisible_unicode heuristic flags it in a
// description.
//
// A text without invisible runes has one form, so it costs no more. A text
// with them is matched up to three times, which triples the cost bound in
// match.go. The regex matchers read more forms (see regexForms).
func matchForms(s string) []string {
	forms := []string{normalizeForMatch(s)}
	raw := cutAtRune(s, maxRawScanBytes)
	if !strings.ContainsFunc(raw, isInvisible) {
		return forms
	}
	forms = appendNew(forms, normalizeInvisible(s, ' ', false))
	if strings.ContainsFunc(raw, isInvisibleControl) {
		forms = appendNew(forms, normalizeInvisible(s, -1, true))
	}
	return forms
}

// appendNew appends f to forms when forms does not hold it yet.
func appendNew(forms []string, f string) []string {
	if slices.Contains(forms, f) {
		return forms
	}
	return append(forms, f)
}

// regexForms returns the forms of s that the regex matchers (any_regex and
// all_regex) read: the forms of matchForms, and then foldMarks of each of
// them when the fold changes it. A regex matches when it matches in one form.
// So the regex `ignore` also matches the fullwidth "ignore" (U+FF49 ...),
// the mathematical bold "ignore" (U+1D422 ...) and "ig" + U+0336 + "nore".
//
// Only the text is folded, not the pattern. So a pattern with an accent or a
// mark matches only in the forms of matchForms, as before.
//
// A form that is only ASCII does not change in foldMarks, so it is not
// folded, and a plain ASCII text costs no more. Equal forms are kept only
// once: a folded form that is equal to a form in the list is not added. So a
// text has at most six forms: the three of matchForms and their three folds.
// This doubles the cost bound of matchForms in match.go.
func regexForms(s string) []string {
	forms := matchForms(s)
	n := len(forms) // fold only the forms of matchForms, not the folds
	for i := range n {
		if isASCII(forms[i]) {
			continue
		}
		forms = appendNew(forms, foldMarks(forms[i]))
	}
	return forms
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
// "ignore previous".
//
// It works in nine steps:
//
//  1. Cut s to maxRawScanBytes, at a rune boundary.
//  2. Drop the invisible runes that are not control runes, such as ZWSP
//     (see replaceFormatRuns).
//  3. Replace each ANSI escape sequence (see ansiToSpace) with U+0020.
//  4. Drop the invisible control runes, such as U+0001 (see
//     isInvisibleControl).
//  5. Replace each white-space or control rune that RE2 \s does not match
//     (see spacesToASCII) with U+0020.
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
// sequence from being found. Step 4 comes after step 3, so a control rune
// cannot make an escape sequence: if U+0001 were dropped before step 3,
// ESC [ U+0001 "Ignore" would become ESC [ I, a CSI that hides the "I".
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
	return normalizeInvisible(s, -1, false)
}

// normalizeInvisible runs the steps of normalizeForMatch, but replaces each
// run of invisible runes with repl. A repl of -1 drops the runes, as in
// normalizeForMatch. The white space is mapped as in normalizeForMatch,
// whatever repl is.
//
// When controlsToSpace is true, step 4 is skipped, so step 5 replaces each
// invisible control rune with U+0020, one space for each rune. matchForms
// uses this, with a repl of -1, for its third form.
func normalizeInvisible(s string, repl rune, controlsToSpace bool) string {
	s = cutAtRune(s, maxRawScanBytes)
	s = ansiToSpace(replaceFormatRuns(s, repl))
	if !controlsToSpace {
		s = replaceInvisible(s, repl) // only invisible control runes are left
	}
	s = spacesToASCII(s)
	s = cutAtRune(s, MaxMatchInputBytes)
	s = norm.NFC.String(s)
	return cutAtRune(replaceInvisible(s, repl), MaxMatchInputBytes)
}

// ansiSeq matches an ANSI escape sequence that a terminal runs and does not
// show:
//
//   - CSI: ESC [ (or U+009B), parameter and intermediate bytes, and a final
//     byte, such as ESC [ 8 m (SGR 8, which hides the text after it);
//   - OSC: ESC ] (or U+009D), at most 256 bytes, and BEL, ESC \ or U+009C.
//
// The schema target is JSON text, where ESC is the escape \u001b, so a CSI
// that starts with that escape matches too. An OSC with no end does not
// match, so it cannot swallow the rest of the text; its ESC still becomes a
// space in spacesToASCII.
var ansiSeq = regexp.MustCompile(`(?:\x1b\[|\x{9b}|\\u001[bB]\[)[0-?]*[ -/]*[@-~]|(?:\x1b\]|\x{9d})[^\x07\x1b\x{9c}]{0,256}(?:\x07|\x1b\\|\x{9c})`)

// ansiControls are the control runes that change how an ANSI escape sequence
// is read: ESC, BEL, CAN, SUB, U+009B, U+009C and U+009D. isInvisible keeps
// them, so ansiToSpace still sees them:
//
//   - ESC (U+001B) and the C1 controls CSI (U+009B), ST (U+009C) and OSC
//     (U+009D) start or end a sequence in ansiSeq;
//   - BEL (U+0007) ends an OSC in ansiSeq;
//   - CAN (U+0018) and SUB (U+001A) cancel a sequence in a terminal, and the
//     terminal shows the text after them. They stay in the text, so ESC [
//     CAN "Ignore" is not read as ESC [ I, a CSI that hides the "I".
//
// spacesToASCII maps the ones that are left after ansiToSpace to U+0020.
const ansiControls = "\x1b\x07\x18\x1a\u009b\u009c\u009d"

// isANSIControl reports whether r is one of ansiControls.
func isANSIControl(r rune) bool {
	return strings.ContainsRune(ansiControls, r)
}

// ansiToSpace replaces each ANSI escape sequence (see ansiSeq) with U+0020.
// Without this step, ESC [ 8 m before "Ignore" leaves "[8mIgnore", and the
// word edge before "Ignore" is lost. A sequence is at least 2 bytes long, so
// the text does not grow.
func ansiToSpace(s string) string {
	return ansiSeq.ReplaceAllLiteralString(s, " ")
}

// re2SpaceRunes are the runes that RE2 \s matches.
const re2SpaceRunes = "\t\n\f\r "

// spacesToASCII replaces with U+0020 each rune that separates two words for a
// reader or a model but that RE2 \s does not match:
//
//   - the white space of isKeywordSpace that is not in re2SpaceRunes, such as
//     VT, NEL (U+0085), the Z categories (NBSP, the em space, U+2028, U+2029
//     and others) and U+2800, the Braille blank that looks like a space;
//   - the control runes (category Cc) that are left: the runes of
//     ansiControls that ansiToSpace did not replace, such as the ESC of an
//     OSC with no end, and, in the third form of matchForms, the invisible
//     control runes (see normalizeInvisible).
//
// In RE2, \s is only [\t\n\f\r ], so without this step "ignore" + NBSP +
// "previous" would not match `ignore\s+previous`. The runes in re2SpaceRunes
// stay as they are, so a newline is still a newline.
//
// NFC never makes such a rune from other runes (it maps U+2000 and U+2001
// only to other spaces, which this step has already removed), so one pass
// before NFC is enough. Every mapped rune is at least 1
// byte long, so the text does not grow.
func spacesToASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if (isKeywordSpace(r) || unicode.Is(unicode.Cc, r)) && !strings.ContainsRune(re2SpaceRunes, r) {
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
// scripts (Cyrillic U+0430 for Latin "a") are not folded.
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
		_, size := utf8.DecodeRuneInString(s[i:])
		if size == 1 { // ASCII folds to itself; keep an invalid byte too
			out = append(out, s[i])
		} else {
			out = appendFold(out, s[i:i+size])
		}
		i += size
	}
	return cutAtRune(string(out), MaxMatchInputBytes)
}

// appendFold appends the fold of the one rune in rs to dst and returns the
// longer slice, as append does. The fold splits the rune into its
// compatibility parts (NFKD), drops the combining marks and the invisible
// runes, and joins the rest again (NFKC). So U+00E9 (e with acute) becomes
// "e", U+FF49 becomes "i", U+0336 becomes nothing, and the Hangul syllable
// U+D55C stays U+D55C. When the fold is longer than rs, appendFold appends rs
// instead (see foldMarks).
//
// Most runes have no compatibility decomposition. Such a rune is its own NFKD
// and NFKC, so it is appended as it is, or not at all for a mark or an
// invisible rune.
func appendFold(dst []byte, rs string) []byte {
	parts := norm.NFKD.PropertiesString(rs).Decomposition()
	if parts == nil {
		if r, _ := utf8.DecodeRuneInString(rs); unicode.Is(unicode.M, r) || isInvisible(r) {
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

// replaceFormatRuns is step 2 of normalizeForMatch. It drops the invisible
// runes that are not control runes, and it keeps the invisible control runes
// for step 4, which runs after ansiToSpace (see normalizeForMatch for why).
//
// A repl of -1 only drops the runes. Otherwise, a run of invisible runes that
// holds no control rune becomes one repl, as in replaceInvisible. A run that
// holds a control rune keeps only its control runes, and step 4 replaces
// them with one repl. So each run of invisible runes becomes one repl in the
// end, whatever runes it holds.
//
// Invalid UTF-8 becomes U+FFFD, as with strings.Map.
func replaceFormatRuns(s string, repl rune) string {
	var b strings.Builder
	b.Grow(len(s))
	inRun := false      // the rune before r is invisible
	hasControl := false // the current run holds an invisible control rune
	endRun := func() {
		if inRun && !hasControl && repl >= 0 {
			b.WriteRune(repl)
		}
		inRun, hasControl = false, false
	}
	for _, r := range s {
		if !isInvisible(r) {
			endRun()
			b.WriteRune(r)
			continue
		}
		inRun = true
		if unicode.IsControl(r) {
			hasControl = true
			b.WriteRune(r)
		}
	}
	endRun()
	return b.String()
}

// replaceInvisible returns s with each run of runes for which isInvisible is
// true replaced by one repl. A repl of -1 drops the runes. strings.Map drops
// a rune when the mapping function returns -1.
//
// Invalid UTF-8 becomes U+FFFD, as with strings.Map.
func replaceInvisible(s string, repl rune) string {
	if repl < 0 {
		return strings.Map(func(r rune) rune {
			if isInvisible(r) {
				return -1
			}
			return r
		}, s)
	}
	var b strings.Builder
	b.Grow(len(s))
	inRun := false
	for _, r := range s {
		if isInvisible(r) {
			if !inRun {
				b.WriteRune(repl)
			}
			inRun = true
			continue
		}
		inRun = false
		b.WriteRune(r)
	}
	return b.String()
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
