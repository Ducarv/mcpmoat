package rules

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"
)

// Cost caps for one tool schema in matchSchemaPrepared. A description is one
// text, and the regex and keyword matchers read at most MaxMatchInputBytes of
// it. A schema is many short texts, so it gets its own caps.
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

// A seam holds at most 2*seamSideBytes bytes of its two strings, and U+009D
// is 2 bytes long in UTF-8, so a seam holds at most seamSideBytes U+009D. So
// a seam never holds more than maxStrictOSCStarts U+009D, and the forms 1 to
// 3 of each seam read with the strict ansiSeq, not with ansiSeqFast (see
// baseFormsCut). Then the cut flag of a seam does not come from its count of
// U+009D. This constant fails to compile (a negative constant does not
// convert to uint) when seamSideBytes grows so that a seam can hold more
// U+009D than maxStrictOSCStarts.
const _ = uint(maxStrictOSCStarts - 2*seamSideBytes/len("\u009d"))

// jsonSpace holds the four white-space characters of JSON.
const jsonSpace = " \t\r\n"

// schemaMode tells matchSchemaPrepared how to read the strings of a schema.
// The zero value is schemaBudget, the mode of the regex and keyword kinds.
type schemaMode int

const (
	// schemaBudget reads the strings in document order until a cap stops it
	// (see schemaFit). Use it for any_regex, all_regex and keywords.
	schemaBudget schemaMode = iota
	// schemaAll reads every string. Use it for the text heuristics: their
	// cost is linear in the input, so they need no cap.
	schemaAll
	// schemaWindow is for the match_window heuristic. It reports the schemas
	// that the schemaBudget mode cannot read in full (see
	// matchSchemaPrepared).
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

// preparedSchema is one tool schema, decoded once, with the preparedText of
// each text that the schema rules read in it. prepareSchemaFrom decodes the
// schema with schemaStrings and applies the caps of schemaFit once. The
// preparedText of each string that fits in the caps, and of each seam, is
// made on its first use and then kept. So when the rules of one tool share
// one preparedSchema, each of these strings and seams is normalized at most
// once, whatever the number of rules that read it. The raw text has one
// preparedText too, for the raw text pass (see matchSchemaPrepared). For a
// schema that preparedText.schema decodes, it is that preparedText itself.
//
// The strings after the first fit strings are not kept (see text). Only the
// heuristics read them, and the heuristics read only the raw text of a
// string, so a kept preparedText would only hold memory: a schema can have up
// to maxSchemaValues strings.
//
// A preparedSchema is safe for concurrent use. The fields above mu do not
// change after prepareSchemaFrom. mu guards texts and seams. The forms of each
// preparedText are built outside mu, under the sync.Once of that
// preparedText. Do not copy a preparedSchema (it holds a sync.Mutex); pass
// the pointer.
type preparedSchema struct {
	raw      *preparedText // the whole schema text, for the raw text pass
	empty    bool          // raw is empty or holds only JSON white space
	strs     []string      // the keys and string values (schemaStrings)
	complete bool          // the decode read the whole schema (schemaStrings)
	fit      int           // how many strings fit in the caps (schemaFit)
	cut      bool          // the caps cut the strings (schemaFit)

	mu    sync.Mutex      // guards texts and seams
	texts []*preparedText // texts[i] is for strs[i], i < fit; nil until its first use
	seams []*preparedText // seams[i-1] joins strs[i-1] and strs[i]; nil until its first use
}

// prepareSchemaFrom decodes p.raw and returns its preparedSchema. The raw
// text pass reads p itself, so it shares the forms of p with the other
// rules that read p, and the raw text is not prepared twice.
// preparedText.schema calls it.
//
// It does not make the preparedText of the strings and seams yet, and it
// builds no forms (see preparedSchema). An empty or whitespace-only raw is
// not decoded: it has no strings, and matchSchemaPrepared gives no hits for
// it. p must not be nil.
func prepareSchemaFrom(p *preparedText) *preparedSchema {
	raw := p.raw
	ps := &preparedSchema{raw: p}
	if strings.Trim(raw, jsonSpace) == "" {
		ps.empty = true
		return ps
	}
	ps.strs, ps.complete = schemaStrings([]byte(raw))
	ps.fit, ps.cut = schemaFit(ps.strs)
	ps.texts = make([]*preparedText, ps.fit)
	return ps
}

// text returns the preparedText of strs[i]. For i < fit, the first call for
// i makes it, and the next calls return the same one. For i >= fit, each call
// makes a new preparedText that ps does not keep. Only the schemaAll mode
// reads these strings, and its heuristics read only p.raw, so they do not
// share forms (see preparedSchema).
func (ps *preparedSchema) text(i int) *preparedText {
	if i >= ps.fit {
		// strs and fit do not change after prepareSchemaFrom, so this needs
		// no lock.
		return prepareText(ps.strs[i])
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.texts[i] == nil {
		ps.texts[i] = prepareText(ps.strs[i])
	}
	return ps.texts[i]
}

// seam returns the preparedText of the seam of strs[i-1] and strs[i], for i
// from 1 to fit-1: the last seamSideBytes of strs[i-1], then seamSep, then
// the first seamSideBytes of strs[i]. So a seam is at most
// 2*seamSideBytes+len(seamSep) bytes long. The first call for i makes it,
// and the next calls return the same one. Only the strings that fit in the
// caps have seams, so there are at most maxSchemaMatchStrings-1 of them.
func (ps *preparedSchema) seam(i int) *preparedText {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.seams == nil {
		ps.seams = make([]*preparedText, max(ps.fit-1, 0))
	}
	if ps.seams[i-1] == nil {
		ps.seams[i-1] = prepareText(lastAtRune(ps.strs[i-1], seamSideBytes) + seamSep + cutAtRune(ps.strs[i], seamSideBytes))
	}
	return ps.seams[i-1]
}

// schemaMatchFunc is the inner matcher of matchSchemaPrepared. It returns the
// hits of one rule in p.raw, read as one text. It must not change p.
type schemaMatchFunc func(ctx context.Context, p *preparedText) ([]Hit, error)

// matchSchemaPrepared runs match on a tool schema, ps, and returns the hits.
//
// The schema is decoded with schemaStrings (see prepareSchemaFrom). match
// runs on each key and string value alone, with the preparedText that
// preparedSchema.text gives for it. So the rules that share ps also share the
// forms of each string that fits in the caps, of each seam and of the raw
// text. Each hit gets the offset NoOffset and the detail
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
// The window rule: in the schemaWindow mode, matchSchemaPrepared does not
// return the hits of match. It returns one hit when the regex and keyword
// rules can miss a part of the schema:
//
//   - the decode is not complete, so the rules read only a part of the
//     strings, and the raw text in a window;
//   - the caps of schemaFit cut the strings;
//   - match reports a hit for one string. For match_window, that means the
//     string is longer than the window of the matcher.
//
// Otherwise it returns nil. This mode reads every string.
//
// The context: matchSchemaPrepared checks ctx before each string, before each
// seam and before the raw text. When ctx is done, it stops and returns the
// hits that it found so far, and an error that wraps ctx.Err(). In the
// schemaWindow mode it then returns no hit. When match returns an error,
// matchSchemaPrepared stops in the same way, drops the hits of that call, and
// wraps the error with the label of the text. The error holds no input text,
// unless the error of match does. With a context that is never done and a
// match that never fails, the error is nil.
//
// ps and match must not be nil.
func matchSchemaPrepared(ctx context.Context, ps *preparedSchema, mode schemaMode, match schemaMatchFunc) ([]Hit, error) {
	if ps.empty {
		return nil, nil
	}
	if mode == schemaWindow {
		return schemaWindowHit(ctx, ps, match)
	}
	n := len(ps.strs) // the all mode has no caps
	if mode == schemaBudget {
		n = ps.fit
	}

	var l hitList
	for i := range n {
		if err := ctx.Err(); err != nil {
			return l.result("schema hits"), fmt.Errorf("match schema strings: %w", err)
		}
		hits, err := match(ctx, ps.text(i))
		if err != nil {
			return l.result("schema hits"), fmt.Errorf("schema string %d: %w", i+1, err)
		}
		if len(hits) > 0 {
			keepSchemaHits(&l, fmt.Sprintf("schema string %d", i+1), hits)
		}
	}
	// The seams use only the strings that fit the budget (see matchSeams).
	if mode == schemaBudget && len(l.hits) == 0 {
		label, hits, err := matchSeams(ctx, ps, match)
		if err != nil {
			return l.result("schema hits"), err
		}
		keepSchemaHits(&l, label, hits)
	}
	if !ps.complete {
		if err := ctx.Err(); err != nil {
			return l.result("schema hits"), fmt.Errorf("match schema raw text: %w", err)
		}
		// The raw text is JSON text: an escape such as \u001b is not decoded
		// here. MOAT-T1-018 flags every schema that cannot be read in full,
		// so this pass is the second line, not the only one.
		hits, err := match(ctx, ps.raw)
		if err != nil {
			return l.result("schema hits"), fmt.Errorf("schema raw text: %w", err)
		}
		keepSchemaHits(&l, "schema raw text", hits)
	}
	return l.result("schema hits"), nil
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
// matchSchemaPrepared, or nil. It stops at the first reason it finds. It
// checks ctx before each string. When ctx is done or match fails, it returns
// no hit and an error (see matchSchemaPrepared).
func schemaWindowHit(ctx context.Context, ps *preparedSchema, match schemaMatchFunc) ([]Hit, error) {
	switch {
	case !ps.complete:
		return []Hit{{Offset: NoOffset, Detail: "schema JSON cannot be read in full"}}, nil
	case ps.cut:
		return []Hit{{Offset: NoOffset, Detail: fmt.Sprintf(
			"schema is longer than the match window: over %d strings or %d bytes",
			maxSchemaMatchStrings, maxSchemaMatchBytes)}}, nil
	}
	for i := range ps.strs {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("match schema strings: %w", err)
		}
		hits, err := match(ctx, ps.text(i))
		if err != nil {
			return nil, fmt.Errorf("schema string %d: %w", i+1, err)
		}
		if len(hits) > 0 {
			return []Hit{{Offset: NoOffset, Detail: fmt.Sprintf("schema string %d: %s", i+1, hits[0].Detail)}}, nil
		}
	}
	return nil, nil
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

// matchSeams runs match on the seam of each pair of neighbour strings of ps,
// in document order. It reads only the strings that fit in the caps of
// schemaFit (the first ps.fit strings), so the seams never read past the
// budget of the strings. A seam is one text: the last seamSideBytes of the
// first string, then seamSep, then the first seamSideBytes of the second
// string (see preparedSchema.seam).
//
// It stops at the first seam that matches. It returns the hits of that seam
// and the label "schema strings N and N+1", where N is the 1-based place of
// the first string in ps.strs. This is the same numbering as
// "schema string N" in matchSchemaPrepared. The label holds no input text.
// When no seam matches, it returns "" and nil.
//
// The sum of the lengths of the seam texts is at most maxSeamBytes. When the
// next seam does not fit, matchSeams stops silently and reports nothing. That
// is on purpose: one benign string between the two halves of a split already
// defeats any join in document order. So a report here would be a false
// positive on large benign schemas, with no gain in security.
//
// It checks ctx before it matches each seam, after the byte cap. When ctx is
// done or match fails, it returns no hit and an error (see
// matchSchemaPrepared).
func matchSeams(ctx context.Context, ps *preparedSchema, match schemaMatchFunc) (string, []Hit, error) {
	total := 0
	for i := 1; i < ps.fit; i++ {
		// The byte cap comes before the ctx check: when no work is left, a
		// deadline that passes now must not make the tool count as not fully
		// checked.
		seam := ps.seam(i)
		total += len(seam.raw)
		if total > maxSeamBytes {
			return "", nil, nil
		}
		if err := ctx.Err(); err != nil {
			return "", nil, fmt.Errorf("match schema seams: %w", err)
		}
		// strs[i-1] is string i and strs[i] is string i+1, 1-based.
		hits, err := match(ctx, seam)
		if err != nil {
			return "", nil, fmt.Errorf("schema strings %d and %d: %w", i, i+1, err)
		}
		if len(hits) > 0 {
			return fmt.Sprintf("schema strings %d and %d", i, i+1), hits, nil
		}
	}
	return "", nil, nil
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
