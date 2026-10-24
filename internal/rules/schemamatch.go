package rules

import (
	"fmt"
	"strings"
)

// Cost caps for one tool schema in matchSchema. A description is one text, and
// the regex and keyword matchers read at most MaxMatchInputBytes of it. A
// schema is many short texts, so it gets its own caps. They make one schema
// cost about four times as much as one description.
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

// jsonSpace holds the four white-space characters of JSON.
const jsonSpace = " \t\r\n"

// schemaMode tells matchSchema how to read the strings of a schema.
type schemaMode int

const (
	// schemaAll reads every string. Use it for the text heuristics: their
	// cost is linear in the input, so they need no cap.
	schemaAll schemaMode = iota
	// schemaBudget reads the strings in document order until a cap stops it
	// (see schemaFit). Use it for any_regex, all_regex and keywords.
	schemaBudget
	// schemaWindow is for the match_window heuristic. It reports the schemas
	// that the schemaBudget mode cannot read in full (see matchSchema).
	schemaWindow
)

// matchSchema runs match on a tool schema, raw, and returns the hits.
//
// The schema is decoded with schemaStrings. match runs on each key and string
// value alone. The strings are never joined, so an all_regex rule matches only
// when all its regexes match in one string. Each hit gets the offset NoOffset
// and the detail "schema string N: <inner detail>", where N is the 1-based
// place of the string in the list of schemaStrings. The detail never holds
// input text, because the inner detail does not. The hits of all the strings
// share one hitList, so the result has at most MaxHits hits and one summary
// hit "and N more schema hits".
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
// schemaFit. So one schema costs at most maxSchemaMatchBytes of regex input,
// plus one description for the raw text. In the schemaAll mode, match reads
// every string.
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
	n, cut := schemaFit(strs)

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
	if !complete {
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
