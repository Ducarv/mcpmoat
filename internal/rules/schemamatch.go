package rules

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Cost caps for one tool schema in matchSchema. A description is one text, and
// the regex and keyword matchers read at most MaxMatchInputBytes of it. A
// schema is many short texts, so it gets its own caps.
//
// In the schemaBudget mode, the matchers read one schema in three passes:
//
//   - the strings one by one, at most maxSchemaMatchBytes;
//   - the seams of neighbour strings, at most maxSeamBytes, in texts of at
//     most 2*seamSideBytes+len(seamSep) bytes (544 bytes);
//   - the raw text once, when the decode is not complete.
//
// So one schema costs about twice as much as the first pass alone: about nine
// descriptions.
const (
	// maxSchemaMatchBytes caps the bytes of one schema that the regex and
	// keyword matchers read, summed over its strings. A string counts for the
	// bytes that the matcher reads of it: its length, but at most
	// MaxMatchInputBytes. So a very long string still gets matched, in the
	// window of the matcher.
	maxSchemaMatchBytes = 128 << 10

	// maxSchemaMatchStrings caps the number of strings of one schema that the
	// regex and keyword matchers read. Each match call has a fixed cost, so
	// this cap bounds a schema made of many tiny strings.
	maxSchemaMatchStrings = 4096
)

// Seam caps and separator for matchSeams. A seam is one short text made of the
// end of one schema string, seamSep, and the start of the next string.
const (
	// seamSideBytes caps the bytes that a seam takes from each of its two
	// strings: the last bytes of the first string and the first bytes of the
	// second string.
	seamSideBytes = 256

	// maxSeamBytes caps the bytes of all the seam texts of one schema
	// together.
	maxSeamBytes = maxSchemaMatchBytes

	// seamSep goes between the two sides of a seam. It is 32 newlines, in
	// four groups of 8. A bounded gap of at most 31 characters, such as the
	// [\s\S]{0,30} of MOAT-T1-009 and MOAT-T1-014, cannot cross 32
	// newlines. Longer or unbounded gaps, such as the [^<>]{0,100} and
	// [\s\S]+? of MOAT-T1-013, and \s+ and \s* can cross a seam. \b works at
	// a newline. ^ and $ match only at the start and the end of the whole
	// seam text, unless the regex has the (?m) flag. When a side is cut at
	// seamSideBytes, the cut point acts like the start or the end of the
	// text, so ^, $ and \b can match there although the full string has no
	// edge at that place. So a seam can give a rare hit that the string
	// alone does not give. The separator is not an invisible
	// rune, because normalization drops those runes and would glue the two
	// words together. It is not a space, because an escape sequence (CSI) at
	// the end of one string could eat the first rune of the next string.
	seamSep = "\n\n\n\n\n\n\n\n" +
		"\n\n\n\n\n\n\n\n" +
		"\n\n\n\n\n\n\n\n" +
		"\n\n\n\n\n\n\n\n"
)

// jsonSpace holds the four white-space characters of JSON.
const jsonSpace = " \t\r\n"

// schemaMode tells matchSchema how to read the strings of a schema. The zero
// value is schemaBudget, the mode of the regex and keyword kinds.
type schemaMode int

const (
	// schemaBudget reads the strings in document order until a cap stops it
	// (see schemaFit). Use it for any_regex, all_regex and keywords.
	schemaBudget schemaMode = iota
	// schemaAll reads every string. Use it for the text heuristics: their
	// cost is linear in the input, so they need no cap.
	schemaAll
	// schemaWindow is for the match_window heuristic. It reports the schemas
	// that the schemaBudget mode cannot read in full (see matchSchema).
	schemaWindow
)

// String returns the name of the mode, for test names and messages.
func (m schemaMode) String() string {
	switch m {
	case schemaBudget:
		return "budget"
	case schemaAll:
		return "all"
	case schemaWindow:
		return "window"
	}
	return fmt.Sprintf("schemaMode(%d)", int(m))
}

// matchSchema runs match on a tool schema, raw, and returns the hits.
//
// The schema is decoded with schemaStrings. match runs on each key and string
// value alone. Each hit gets the offset NoOffset and the detail
// "schema string N: <inner detail>", where N is the 1-based place of the
// string in the list of schemaStrings.
//
// The seams: in the schemaBudget mode, and only when no string matched, match
// then runs on each seam of two neighbour strings (see matchSeams). A seam hit
// gets the detail "schema strings N and N+1: <inner detail>". So an
// instruction that is split over two neighbour strings is still found. For
// all_regex, all the regexes must match in one string or all in one seam. For
// keywords, a keyword of several words can cross a seam, but one word cannot
// be built from the parts of two strings. The seams do not catch:
//
//   - a split with one benign string between the two halves;
//   - a split over strings that are not neighbours in the list, also when a
//     string is a copy of an earlier string: the list keeps only the first
//     copy, so an early copy of the second half removes it from its place;
//   - a split over three or more strings;
//   - a split with more than seamSideBytes on one side of the seam;
//   - a split between the name and the description of the first property.
//     The key "description" is usually listed there for the first time, so it
//     sits between the two halves. In the next properties, the list drops
//     the repeated key, so the halves are neighbours;
//   - an indirection, such as a $ref that points to the other half.
//
// The seam pass has its own budget, maxSeamBytes. When the budget is used up,
// the seam pass stops silently and does not set the window rule. A split
// beyond that point needs a large schema, and one benign string between the
// two halves already defeats any join in document order. So a window hit there
// gives a false positive on large benign schemas, with no gain in security.
//
// The detail never holds input text, because the label and the inner detail
// do not. The hits of all the strings and seams share one hitList, so the
// result has at most MaxHits hits and one summary hit "and N more schema
// hits".
//
// Empty or whitespace-only raw has nothing to scan and gives no hits.
//
// Fail closed: when the decode is not complete (malformed JSON, data after
// the first value, or a decode cap), match also runs once on the whole raw
// text. Its hits get the detail "schema raw text: <inner detail>". So a broken
// schema is still scanned. This extra run is not in the budget below, and the
// inner matcher applies its own window to it.
//
// The budget: in the schemaBudget mode, match reads the strings in document
// order and stops at the first string that does not fit in the caps of
// schemaFit. The seams use only these strings. So one schema costs at most
// maxSchemaMatchBytes of regex input for the strings, maxSeamBytes for the
// seams, plus one description for the raw text. In the schemaAll mode, match
// reads every string and no seam.
//
// The window rule: in the schemaWindow mode, matchSchema does not return the
// hits of match. It returns one hit when the regex and keyword rules can miss
// a part of the schema:
//
//   - the decode is not complete, so the rules read only a part of the
//     strings, and the raw text in a window;
//   - the caps of schemaFit cut the strings;
//   - match reports a hit for one string. For match_window, that means the
//     string is longer than the window of the matcher.
//
// Otherwise it returns nil. This mode reads every string.
func matchSchema(raw string, mode schemaMode, match func(string) []Hit) []Hit {
	if strings.Trim(raw, jsonSpace) == "" {
		return nil
	}
	strs, complete := schemaStrings([]byte(raw))
	var n int
	var cut bool
	if mode != schemaAll { // the all mode has no caps
		n, cut = schemaFit(strs)
	}

	if mode == schemaWindow {
		return schemaWindowHit(strs, complete, cut, match)
	}
	if mode == schemaBudget {
		strs = strs[:n]
	}

	var l hitList
	for i, s := range strs {
		if hits := match(s); len(hits) > 0 {
			keepSchemaHits(&l, fmt.Sprintf("schema string %d", i+1), hits)
		}
	}
	// In the schemaBudget mode, strs holds only the strings that fit the
	// budget, so the seams never read past it.
	if mode == schemaBudget && len(l.hits) == 0 {
		label, hits := matchSeams(strs, match)
		keepSchemaHits(&l, label, hits)
	}
	if !complete {
		// The raw text is JSON text: an escape such as \u001b is not decoded
		// here. MOAT-T1-018 flags every schema that cannot be read in full,
		// so this pass is the second line, not the only one.
		keepSchemaHits(&l, "schema raw text", match(raw))
	}
	return l.result("schema hits")
}

// schemaFit returns how many strings of strs, from the start, fit in the
// caps. A string fits when it is one of the first maxSchemaMatchStrings
// strings, and when the sum of the costs up to and including it is at most
// maxSchemaMatchBytes. The cost of a string is its length, but at most
// MaxMatchInputBytes. cut is true when n is less than len(strs).
func schemaFit(strs []string) (n int, cut bool) {
	total := 0
	for i, s := range strs {
		if i == maxSchemaMatchStrings {
			return i, true
		}
		total += min(len(s), MaxMatchInputBytes)
		if total > maxSchemaMatchBytes {
			return i, true
		}
	}
	return len(strs), false
}

// schemaWindowHit returns the one hit of the schemaWindow mode of
// matchSchema, or nil. It stops at the first reason it finds.
func schemaWindowHit(strs []string, complete, cut bool, match func(string) []Hit) []Hit {
	switch {
	case !complete:
		return []Hit{{Offset: NoOffset, Detail: "schema JSON cannot be read in full"}}
	case cut:
		return []Hit{{Offset: NoOffset, Detail: fmt.Sprintf(
			"schema is longer than the match window: over %d strings or %d bytes",
			maxSchemaMatchStrings, maxSchemaMatchBytes)}}
	}
	for i, s := range strs {
		if hits := match(s); len(hits) > 0 {
			return []Hit{{Offset: NoOffset, Detail: fmt.Sprintf("schema string %d: %s", i+1, hits[0].Detail)}}
		}
	}
	return nil
}

// keepSchemaHits adds hits to l, with the offset NoOffset and the detail
// "<label>: <inner detail>". label must not hold input text.
func keepSchemaHits(l *hitList, label string, hits []Hit) {
	for _, h := range hits {
		if l.keep(NoOffset) {
			l.hits = append(l.hits, Hit{Offset: NoOffset, Detail: label + ": " + h.Detail})
		}
	}
}

// matchSeams runs match on the seam of each pair of neighbour strings in strs,
// in document order. A seam is one text: the last seamSideBytes of the first
// string, then seamSep, then the first seamSideBytes of the second string. So
// a seam is at most 2*seamSideBytes+len(seamSep) bytes long.
//
// It stops at the first seam that matches. It returns the hits of that seam
// and the label "schema strings N and N+1", where N is the 1-based place of
// the first string in strs. This is the same numbering as
// "schema string N" in matchSchema. The label holds no input text. When no
// seam matches, it returns "" and nil.
//
// The sum of the lengths of the seam texts is at most maxSeamBytes. When the
// next seam does not fit, matchSeams stops silently and reports nothing. That
// is on purpose: one benign string between the two halves of a split already
// defeats any join in document order. So a report here would be a false
// positive on large benign schemas, with no gain in security.
func matchSeams(strs []string, match func(string) []Hit) (label string, hits []Hit) {
	total := 0
	for i := 1; i < len(strs); i++ {
		seam := lastAtRune(strs[i-1], seamSideBytes) + seamSep + cutAtRune(strs[i], seamSideBytes)
		total += len(seam)
		if total > maxSeamBytes {
			return "", nil
		}
		if hits := match(seam); len(hits) > 0 {
			// strs[i-1] is string i and strs[i] is string i+1, 1-based.
			return fmt.Sprintf("schema strings %d and %d", i, i+1), hits
		}
	}
	return "", nil
}

// lastAtRune returns at most the last n bytes of s. It is the mirror of
// cutAtRune. When the start falls inside a UTF-8 encoded rune, it moves
// forward to the start of the next rune, so the result never starts with a
// part of a rune. It moves at most utf8.UTFMax-1 bytes. So the result stays
// short when s is invalid UTF-8, for example a long run of continuation
// bytes. When n is at least len(s), it returns s. When n is 0 or less, it
// returns "".
func lastAtRune(s string, n int) string {
	if n >= len(s) {
		return s
	}
	if n <= 0 {
		return ""
	}
	start := len(s) - n
	i := start
	for i < len(s) && i < start+(utf8.UTFMax-1) && !utf8.RuneStart(s[i]) {
		i++
	}
	return s[i:]
}
