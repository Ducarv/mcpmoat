package discover

import (
	"strings"
	"unicode/utf8"
)

// This file removes secret values from untrusted text, such as the name or
// the description of a tool that a server sends. A server that got a token
// can echo it in that text. internal/llm uses it for the LLM request (FR-17),
// and the report layer can use it for the local output, because only
// cmd/mcpmoat may import internal/llm.

// SecretTextValues returns the values that [RedactText] and
// [RedactTextPrefix] must remove for secrets: each secret value of at least
// [MinSecretBytes] bytes and, for a value that is not valid UTF-8, also its
// decoded form (see decodedPerByte). It skips shorter values (see
// MinSecretBytes) and a value that is in the result already. The minimum
// applies to the raw configured value, so a raw value shorter than
// MinSecretBytes gives no decoded form either, even when that form is
// longer. The result keeps the order of the first occurrence.
//
// The result holds secret values: pass it only to RedactText or
// RedactTextPrefix, never to fmt, a logger, an error or an encoder.
//
// The decoded form is necessary because a value from the OS environment can
// hold bytes that are not valid UTF-8. A server sends its tool text as JSON.
// The JSON decoder of the MCP SDK (github.com/segmentio/encoding/json), and
// encoding/json for both decoding and encoding, write one U+FFFD for each
// invalid byte. So the tool text of a server that echoes the value holds the
// decoded form, never the raw bytes, and a match of the raw value only would
// leave every valid byte of the secret in the text. strings.ToValidUTF8 does
// not give that form: it writes one U+FFFD for a whole run of invalid bytes.
// A server that encodes the value in another way (for example with one
// U+FFFD for a run) can still send it, as with any other encoded form.
func SecretTextValues(secrets []Secret) []string {
	var values []string
	// seen holds the values in the result. A map lookup keeps the dedupe
	// linear in the number of secrets. A search of values for each value
	// would be quadratic: seconds for each tool with tens of thousands of argv
	// secrets. redactWindow still reads each value once for each window: see
	// its doc for why that cost is accepted.
	//
	// map[string]struct{} is the usual Go set: the empty struct takes no
	// memory, only the keys matter.
	seen := make(map[string]struct{})
	add := func(v string) {
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		values = append(values, v)
	}
	for _, s := range secrets {
		v := s.Reveal()
		if len(v) < MinSecretBytes {
			continue
		}
		add(v)
		if !utf8.ValidString(v) {
			add(decodedPerByte(v))
		}
	}
	return values
}

// RedactText replaces each occurrence of each value in values with [Mask] in
// all of s, and reports whether it wrote a Mask. The values normally come
// from [SecretTextValues]. See redactWindow for how the occurrences are found
// and replaced.
//
// RedactText reads all of s. For a long text of which only the start is
// shown, use [RedactTextPrefix], which bounds the work.
//
// The values must not be empty (SecretTextValues gives only values of at
// least [MinSecretBytes] bytes). An empty value is skipped.
func RedactText(s string, values []string) (string, bool) {
	if len(values) == 0 || s == "" {
		return s, false
	}
	return redactWindow(s, values, len(s), -1)
}

// RedactTextPrefix replaces each occurrence of each value in values with
// [Mask] in s, and returns the start of the result, and whether that start
// holds a Mask. The values normally come from [SecretTextValues]. "The whole
// result" below is RedactText(s, values). A negative limit counts as 0.
//
// The start is the whole result when the result has at most limit bytes, and
// otherwise a prefix of the result with more than limit bytes. So a cut of
// the start to limit bytes gives the same text as a cut of the whole result,
// and the start is longer than limit exactly when the whole result is. A cut
// that reads only the first limit+1 bytes and the length (such as the
// rune-boundary cut of internal/llm) gives the same result for both. redacted
// is true when a Mask starts in the first limit+1 bytes of the result. A Mask
// that starts after them is not written and does not set redacted. See
// redactWindow for how the occurrences are found and replaced.
//
// This bounds the work. A pre-cut of s (for example to limit plus the
// length of the longest value) does not give the same result: one Mask can
// replace more bytes than it has, so the redacted text can be shorter than
// limit although the uncut redacted text is longer, and a value that crosses
// the pre-cut would not match and could leave a part of a secret. Instead,
// RedactTextPrefix redacts a window s[:end] with redactWindow, which also
// finds the occurrences that go on past end, so the result of the window is
// always a prefix of the whole result. The first window has limit+1 bytes.
// When its result has limit bytes or less (the Masks made it shorter) and s
// goes on, the window doubles. For text with no secret in its first limit+1
// bytes, the work is one window: the search for each value reads at most
// limit+1 bytes plus the length of the value. Only text that holds secrets
// can make the window grow, at most to all of s.
//
// The values must not be empty (SecretTextValues gives only values of at
// least [MinSecretBytes] bytes). An empty value is skipped.
func RedactTextPrefix(s string, values []string, limit int) (string, bool) {
	if len(values) == 0 || s == "" {
		return s, false
	}
	limit = max(limit, 0)
	end := min(len(s), limit+1)
	for {
		out, redacted := redactWindow(s, values, end, limit)
		if len(out) > limit || end == len(s) {
			return out, redacted
		}
		end = min(len(s), 2*end)
	}
}

// decodedPerByte returns s with each byte that is not part of a valid UTF-8
// rune replaced with U+FFFD: one U+FFFD for each byte, the same as the JSON
// decoders (see SecretTextValues). A range loop over a string gives
// utf8.RuneError (U+FFFD) for each such byte, and the rune as it is for
// valid UTF-8.
func decodedPerByte(s string) string {
	var b strings.Builder
	b.Grow(3 * len(s)) // at most 3 bytes (one U+FFFD) for each byte of s
	for _, r := range s {
		b.WriteRune(r)
	}
	return b.String()
}

// redactWindow replaces each occurrence of each value in values with Mask in
// s[:end], and reports whether it wrote a Mask. It stops the write when the
// result has more than limit bytes; a negative limit means no stop. It
// compares bytes, so invalid UTF-8 outside a match stays as it is.
//
// It first marks every byte that is inside an occurrence of any value,
// overlapping occurrences included, so the order of values does not matter:
// a value inside a longer one, or two values that overlap, are removed
// whole. Then it writes the text once, with one Mask for each run of marked
// bytes. A run can hold more than one secret.
//
// It finds every occurrence that starts in s[:end], also one that goes on
// past end, so the result is always a prefix of the redaction of all of s
// (see RedactTextPrefix).
//
// The search reads each value once for each window, and for each value it
// reads at most end+len(value)-1 bytes of s, each byte once (see markValue).
// So the work is linear in the length of the window and of the values, also
// for a periodic value (such as 4096 times "a") that the text repeats (NFR-03).
// There is no cap on the number of values. This is accepted: the window is
// bounded (see RedactTextPrefix).
//
// The values must not be empty (SecretTextValues gives only values of at
// least MinSecretBytes bytes). An empty value is skipped: it would match at
// every byte, and it marks nothing.
func redactWindow(s string, values []string, end, limit int) (string, bool) {
	var marked []bool // nil until the first match
	var border []int  // one buffer for the border table of each value
	for _, v := range values {
		if v == "" {
			continue
		}
		// An occurrence that starts before end ends at end+len(v)-1 or
		// before. So the search reads only that part of s, and every
		// occurrence that it finds starts before end.
		window := s[:min(len(s), end+len(v)-1)]
		if len(window) < len(v) {
			continue // no occurrence is possible
		}
		border = borders(v, border)
		marked = markValue(window, v, border, marked, end)
	}
	if marked == nil {
		return s[:end], false
	}
	// One pass over the marks: each run of unmarked input bytes is whole and
	// has no match, so a value can show up in the output only across a Mask.
	// That needs a value that starts with "*", ends with "*" or holds a whole
	// Mask: for example the value "abcdefg*" comes back when the text holds
	// "abcdefg" just before another secret. The bytes next to the Mask are
	// text that the server wrote itself, so this is the same limit as a
	// secret that the server sends in parts.
	var b strings.Builder
	if limit < 0 {
		b.Grow(end)
	} else {
		b.Grow(min(end, limit+len(Mask)))
	}
	masked := false
	for i := 0; i < end && (limit < 0 || b.Len() <= limit); {
		if !marked[i] {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteString(Mask)
		masked = true
		for i < end && marked[i] {
			i++
		}
	}
	return b.String(), masked
}

// borders returns the border table of v (the "prefix function" of the
// Knuth-Morris-Pratt search). border[i] is the length of the longest proper
// prefix of v[:i+1] that is also a suffix of v[:i+1]. For example, for
// v = "abcab" the table is [0 0 0 1 2]: "abcab" ends with "ab", which is
// also its start. v must not be empty.
//
// The table tells markValue where a partial match can go on. When k bytes of
// v match the text and the next byte does not, or when all of v matches, the
// last border[k-1] bytes of the text are still the start of v, so the search
// goes on from there and never reads a byte of the text again.
//
// borders writes the table into buf when buf has the capacity, so one buffer
// serves all values. The table has one int for each byte of v.
func borders(v string, buf []int) []int {
	if cap(buf) < len(v) {
		buf = make([]int, len(v))
	}
	border := buf[:len(v)]
	border[0] = 0
	k := 0 // the length of the border of v[:i]
	for i := 1; i < len(v); i++ {
		for k > 0 && v[i] != v[k] {
			k = border[k-1] // try the next shorter border
		}
		if v[i] == v[k] {
			k++
		}
		border[i] = k
	}
	return border
}

// markValue marks in marked each byte of s[:end] that is inside an
// occurrence of v in window, overlapping occurrences ("abab" in "ababab")
// included, and returns marked. It makes marked (with end bytes) at the first
// match when marked is nil. border is borders(v).
//
// It reads each byte of window once. k goes up by at most one for each byte
// and each step back to a border makes it smaller, so the steps back are at
// most len(window) in total too. This is the Knuth-Morris-Pratt search, with
// the change that it goes on after a match to find all occurrences.
func markValue(window, v string, border []int, marked []bool, end int) []bool {
	k := 0    // the number of bytes of v that match the text before window[i]
	last := 0 // the bytes before last are marked for v already
	for i := 0; i < len(window); i++ {
		if k == 0 {
			// No partial match: go to the next byte that can start v.
			// strings.IndexByte also reads each byte once, and it is much
			// faster than this loop for text that holds no secret.
			j := strings.IndexByte(window[i:], v[0])
			if j < 0 {
				break
			}
			i += j
		}
		for k > 0 && window[i] != v[k] {
			k = border[k-1]
		}
		if window[i] == v[k] {
			k++
		}
		if k < len(v) {
			continue
		}
		start := i + 1 - len(v)
		if marked == nil {
			marked = make([]bool, end)
		}
		for j := max(start, last); j < min(start+len(v), end); j++ {
			marked[j] = true
		}
		last = start + len(v)
		// Keep the border of v as the match so far: the next occurrence can
		// start inside this one.
		k = border[k-1]
	}
	return marked
}
