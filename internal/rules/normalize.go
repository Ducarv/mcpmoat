package rules

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// MaxMatchInputBytes is the largest part of a text, in bytes, that the regex
// and keyword matchers read: 32 KiB, counted after the invisible runes are
// dropped. Text after it is not regex-matched or keyword-matched. This keeps
// the cost of one match small when a server sends a very long text. Real
// tool descriptions are a few KB long, so the cap does not cut them.
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
// a keyword: a format character (Cf), a variation selector, or another
// default-ignorable code point. The few Cf runes that show as a mark (the
// prepended concatenation marks, such as the Arabic number sign U+0600) are
// not invisible.
//
// This covers the zero-width characters (ZWSP, ZWNJ, ZWJ, word joiner), LRM
// and RLM, the bidi embeddings, overrides and isolates, the BOM, the soft
// hyphen, the tag characters (U+E0000 to U+E007F), the variation selectors
// (VS1 to VS256), the combining grapheme joiner (CGJ, U+034F) and the Hangul
// fillers. ZWNJ and ZWJ are also a normal part of Persian and Indic text, so
// invisible_unicode flags such text too.
//
// normalizeForMatch and the invisible_unicode heuristic share this one
// predicate, so they cannot disagree about which runes are invisible.
func isInvisible(r rune) bool {
	return unicode.In(r,
		unicode.Cf,
		unicode.Variation_Selector,
		unicode.Other_Default_Ignorable_Code_Point,
	) && !unicode.Is(unicode.Prepended_Concatenation_Mark, r)
}

// matchForms returns the forms of s that the regex and keyword matchers read.
// A matcher reports a match when one form matches.
//
// The first form is normalizeForMatch(s): the invisible runes are dropped, so
// "ign" + ZWSP + "ore" is "ignore". When s holds an invisible rune in the
// part that normalizeForMatch reads, the second form replaces each invisible
// rune with a space instead, so "ignore" + ZWSP + "previous" is "ignore
// previous" and a keyword edge next to a ZWSP still holds. A text that uses
// invisible runes both inside a word and between words defeats both forms;
// the invisible_unicode heuristic flags it.
//
// A text without invisible runes has one form, so it costs no more. A text
// with them is matched twice, which doubles the cost bound in match.go.
func matchForms(s string) []string {
	joined := normalizeForMatch(s)
	if !strings.ContainsFunc(cutAtRune(s, maxRawScanBytes), isInvisible) {
		return []string{joined}
	}
	return []string{joined, normalizeInvisible(s, ' ')}
}

// normalizeForMatch returns the form of s that the regex and keyword matchers
// read. So "ign" + ZWSP (U+200B) + "ore previous" still matches the keyword
// "ignore previous".
//
// It works in six steps:
//
//  1. Cut s to maxRawScanBytes, at a rune boundary.
//  2. Drop the invisible runes (see isInvisible).
//  3. Cut the result to MaxMatchInputBytes, at a rune boundary.
//  4. Apply Unicode normalization form NFC, which joins a letter and its
//     combining marks into one rune where one exists.
//  5. Drop the invisible runes again.
//  6. Cut to MaxMatchInputBytes again, because NFC can make some text up to
//     three times longer (U+1D160 becomes three runes).
//
// Step 2 comes before step 3, so invisible padding does not use up the
// MaxMatchInputBytes window. Step 6 keeps the regexes at MaxMatchInputBytes,
// so the cost bound in match.go holds.
//
// Step 2 comes before NFC, so an invisible rune cannot block composition:
// "e" + ZWSP + U+0301 becomes U+00E9 (e with acute), the same as "e" + U+0301.
//
// Step 5 exists because the norm package follows the Stream-Safe Text Format:
// after 30 or more combining marks in a row, it inserts a CGJ (U+034F), which
// is invisible. The second pass removes it.
//
// Invalid UTF-8 does not cause a panic: strings.Map reads each bad byte as
// U+FFFD (utf8.RuneError) and writes U+FFFD in its place.
func normalizeForMatch(s string) string {
	return normalizeInvisible(s, -1)
}

// normalizeInvisible runs the steps of normalizeForMatch, but replaces each
// invisible rune with repl. A repl of -1 drops the rune, as in
// normalizeForMatch.
func normalizeInvisible(s string, repl rune) string {
	s = cutAtRune(s, maxRawScanBytes)
	s = replaceInvisible(s, repl)
	s = cutAtRune(s, MaxMatchInputBytes)
	s = norm.NFC.String(s)
	return cutAtRune(replaceInvisible(s, repl), MaxMatchInputBytes)
}

// foldMarks removes the combining marks (category M: non-spacing, spacing
// and enclosing) from s, which comes from normalizeForMatch. The keyword
// matcher applies it to the keyword and to the text, so a mark cannot hide a
// keyword: "ig" + U+0336 + "nore" and "previou" + U+015B (s with acute) still
// match "ignore previous". It also folds accents, so the keyword "caf" +
// U+00E9 matches "cafe", and in scripts such as Devanagari it drops the vowel
// signs. Regexes do not get it: their patterns are not folded.
//
// It splits each letter from its marks (NFD), drops the marks, and joins the
// rest again (NFC). The NFC step can add a CGJ (see normalizeForMatch),
// so the invisible runes are dropped again. The result is cut to
// MaxMatchInputBytes again, so the cost bound in match.go holds whatever the
// Unicode tables do.
func foldMarks(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.M, r) {
			return -1
		}
		return r
	}, norm.NFD.String(s))
	return cutAtRune(replaceInvisible(norm.NFC.String(s), -1), MaxMatchInputBytes)
}

// replaceInvisible returns s with each rune for which isInvisible is true
// replaced by repl. strings.Map drops a rune when the mapping function
// returns -1, so a repl of -1 drops the invisible runes.
func replaceInvisible(s string, repl rune) string {
	return strings.Map(func(r rune) rune {
		if isInvisible(r) {
			return repl
		}
		return r
	}, s)
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
