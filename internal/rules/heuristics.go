package rules

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Names of the native heuristics, for `match: {heuristic: <name>}`.
const (
	// HeuristicInvisibleUnicode flags runes that show as nothing: zero-width
	// and bidi controls, tag characters and other format characters. It has
	// no parameters.
	HeuristicInvisibleUnicode = "invisible_unicode"
	// HeuristicMaxLength flags a text with more than max_runes characters.
	// Parameter: max_runes (default 4096, 1 to 1<<24).
	HeuristicMaxLength = "max_length"
	// HeuristicBase64Blob flags a long base64 run that decodes to text.
	// Parameters: min_length, the shortest run in characters (default 32,
	// 8 to 4096), and min_text, the shortest decoded text in bytes (default
	// 24, 4 to 3072).
	HeuristicBase64Blob = "base64_blob"
)

// heuristicNames lists the valid heuristic names for an error message.
const heuristicNames = HeuristicBase64Blob + ", " + HeuristicInvisibleUnicode + ", " + HeuristicMaxLength

// paramSpec describes one integer parameter of a heuristic.
type paramSpec struct {
	name     string
	def      int // value when the rule does not set it
	min, max int // allowed range, both included
}

// compileHeuristic returns the function of the heuristic name, with its
// parameters checked and set. The function reads the raw text. Every error
// is a *FieldError.
func compileHeuristic(name string, params map[string]int) (func(raw string) []Hit, error) {
	switch name {
	case HeuristicInvisibleUnicode:
		if _, err := readParams(params); err != nil {
			return nil, err
		}
		return invisibleUnicode, nil
	case HeuristicMaxLength:
		v, err := readParams(params, paramSpec{name: "max_runes", def: 4096, min: 1, max: 1 << 24})
		if err != nil {
			return nil, err
		}
		maxRunes := v[0]
		return func(raw string) []Hit { return maxLength(raw, maxRunes) }, nil
	case HeuristicBase64Blob:
		v, err := readParams(params,
			paramSpec{name: "min_length", def: 32, min: 8, max: 4096},
			paramSpec{name: "min_text", def: 24, min: 4, max: 3072},
		)
		if err != nil {
			return nil, err
		}
		minLength, minText := v[0], v[1]
		return func(raw string) []Hit { return base64Blob(raw, minLength, minText) }, nil
	}
	// The given name is not echoed: it comes from the rule file.
	return nil, &FieldError{Field: "heuristic", Msg: "unknown heuristic; valid: " + heuristicNames}
}

// readParams checks params against specs and returns the value of each spec,
// in the order of specs.
//
// An unknown key comes from the rule file, so the error does not echo it. It
// lists the valid keys instead.
func readParams(params map[string]int, specs ...paramSpec) ([]int, error) {
	for key := range params {
		known := slices.ContainsFunc(specs, func(s paramSpec) bool { return s.name == key })
		if !known {
			return nil, unknownParamError(specs)
		}
	}
	values := make([]int, len(specs))
	for i, s := range specs {
		v, ok := params[s.name]
		if !ok {
			v = s.def
		}
		if v < s.min || v > s.max {
			return nil, &FieldError{Field: "params." + s.name, Msg: fmt.Sprintf("must be between %d and %d", s.min, s.max)}
		}
		values[i] = v
	}
	return values, nil
}

// unknownParamError returns the error for a key that is not in specs. The
// message lists the valid keys, sorted, so it is the same on every run.
func unknownParamError(specs []paramSpec) error {
	if len(specs) == 0 {
		return &FieldError{Field: "params", Msg: "takes no parameters"}
	}
	names := make([]string, 0, len(specs))
	for _, s := range specs {
		names = append(names, s.name)
	}
	slices.Sort(names)
	return &FieldError{Field: "params", Msg: "unknown parameter; valid: " + strings.Join(names, ", ")}
}

// Runes that are invisible but are a normal part of an emoji.
const (
	zeroWidthJoiner = '\u200D' // joins emoji: man + ZWJ + laptop
	textStyle       = '\uFE0E' // VS15: show the symbol before it as text
	emojiStyle      = '\uFE0F' // VS16: show the symbol before it as emoji
	keycapMark      = '\u20E3' // visible; "1" + VS16 + U+20E3 is the keycap 1
)

// invisibleUnicode flags every rune of raw for which isInvisible is true.
//
// An emoji can hold a VS15 or VS16 and a ZWJ (see isPictograph), so some of
// these runes are not flagged:
//
//   - one VS15 or VS16 directly after a pictograph;
//   - one VS15 or VS16 between a keycap base (0-9, '#' or '*') and U+20E3;
//   - one ZWJ between two pictographs, with at most that one VS15 or VS16
//     after the first one.
//
// So U+2764 VS16 ZWJ U+1F525, the "heart on fire" emoji, gives no hit. A
// second VS in a row, and a ZWJ that no pictograph follows, are flagged, so
// they cannot carry hidden data. The tag characters (U+E0000 to U+E007F) can
// hide a full ASCII text, and they are never excused.
func invisibleUnicode(raw string) []Hit {
	var l hitList
	prev := rune(-1)    // the rune before r
	afterEmoji := false // prev is a pictograph, or the one VS after a pictograph
	for i, r := range raw {
		excused := false
		switch r {
		case textStyle, emojiStyle:
			excused = isPictograph(prev) || isKeycapBase(prev) && runeAt(raw, i+utf8.RuneLen(r)) == keycapMark
		case zeroWidthJoiner:
			excused = afterEmoji && isPictograph(runeAt(raw, i+utf8.RuneLen(r)))
		}
		if isInvisible(r) && !excused && l.keep(i) {
			l.hits = append(l.hits, Hit{Offset: i, Detail: fmt.Sprintf("U+%04X at offset %d", r, i)})
		}
		afterEmoji = isPictograph(r) || excused && r != zeroWidthJoiner && isPictograph(prev)
		prev = r
	}
	return l.result("invisible characters")
}

// isPictograph reports whether r is an emoji that a VS or a ZWJ can follow: a
// non-ASCII rune in the category So (other symbols, which holds most emoji,
// and also U+00A9 and U+00AE), a skin-tone modifier, or one of the few emoji
// in another category. ASCII and the other Sk runes (such as '^' and U+02D8)
// are not, so they excuse nothing.
func isPictograph(r rune) bool {
	switch r {
	case utf8.RuneError: // also what range gives for an invalid byte
		return false
	case 0x203C, 0x2049, 0x2139, 0x2194, 0x2934, 0x2935, 0x3030, 0x303D:
		return true // the emoji that are not So: Po, Ll, Sm and Pd runes
	}
	return r >= 0x80 && unicode.Is(unicode.So, r) || 0x1F3FB <= r && r <= 0x1F3FF
}

// isKeycapBase reports whether r can start a keycap emoji: 0-9, '#' or '*'.
func isKeycapBase(r rune) bool {
	return '0' <= r && r <= '9' || r == '#' || r == '*'
}

// runeAt returns the rune at byte i of s, or -1 at the end of s or at an
// invalid byte.
func runeAt(s string, i int) rune {
	r, size := utf8.DecodeRuneInString(s[i:])
	if r == utf8.RuneError && size <= 1 {
		return -1
	}
	return r
}

// maxLength flags raw when it has more than maxRunes runes. The hit is at the
// first rune over the limit. An invalid UTF-8 byte counts as one rune.
func maxLength(raw string, maxRunes int) []Hit {
	n := utf8.RuneCountInString(raw)
	if n <= maxRunes {
		return nil
	}
	offset, count := 0, 0
	for i := range raw { // i is the byte offset of each rune
		if count == maxRunes {
			offset = i
			break
		}
		count++
	}
	return []Hit{{Offset: offset, Detail: fmt.Sprintf("text has %d characters, over the limit of %d", n, maxRunes)}}
}

// base64Blob flags each run of base64 characters in raw that is at least
// minLength characters long and decodes to at least minText printable bytes
// in a row.
//
// A run is a longest sequence of [A-Za-z0-9+/_-]. A run can mix the standard
// and the URL-safe alphabets, so a "-" or "_" glued to a payload cannot hide
// it. An invisible rune inside a run is skipped, so a ZWSP cannot split a
// payload. A '=' ends a run: base64 padding comes only at the end, and the
// decoder does not need it.
func base64Blob(raw string, minLength, minText int) []Hit {
	var l hitList
	var run []byte // characters of the current run, without invisible runes
	var dst []byte // decode buffer, reused for every run
	start := 0     // byte offset in raw of the current run
	// check flags the current run when it is long enough and decodes to
	// text. Then it empties run for the next one.
	check := func() {
		if len(run) >= minLength {
			var ok bool
			ok, dst = decodesToText(run, minText, dst)
			if ok && l.keep(start) {
				l.hits = append(l.hits, Hit{Offset: start, Detail: fmt.Sprintf("base64 run of %d characters at offset %d decodes to text", len(run), start)})
			}
		}
		run = run[:0]
	}
	for i, r := range raw {
		switch {
		case isBase64Char(r):
			if len(run) == 0 {
				start = i
			}
			run = append(run, raw[i]) // r is ASCII, so it is the byte raw[i]
		case len(run) > 0 && isInvisible(r):
			// Skip it and keep the run going.
		default:
			check()
		}
	}
	check()
	return l.result("base64 runs")
}

// isBase64Char reports whether r is in the standard or the URL-safe base64
// alphabet.
func isBase64Char(r rune) bool {
	return 'A' <= r && r <= 'Z' || 'a' <= r && r <= 'z' || '0' <= r && r <= '9' ||
		r == '+' || r == '/' || r == '-' || r == '_'
}

// decodesToText reports whether run decodes to at least minText printable
// bytes in a row. dst is a buffer that decodesToText can reuse; it returns
// the buffer for the next call.
//
// decodesToText changes run: it maps the URL-safe '-' and '_' to the
// standard '+' and '/', so one decoder reads both alphabets, also when they
// are mixed in one run.
//
// The run can start in the middle of a base64 text, for example when a word
// is glued to it, so each of the 4 possible alignments is tried.
func decodesToText(run []byte, minText int, dst []byte) (bool, []byte) {
	// A hex hash or a UUID is made of hex digits (and '-'). A base64 text
	// almost always holds other letters too.
	onlyHex := true
	for _, c := range run {
		if !isHexDigit(c) && c != '-' {
			onlyHex = false
			break
		}
	}
	if onlyHex {
		return false, dst
	}
	for i, c := range run {
		switch c {
		case '-':
			run[i] = '+'
		case '_':
			run[i] = '/'
		}
	}
	enc := base64.RawStdEncoding

	for drop := range 4 {
		s := run[drop:]
		// A raw base64 text cannot have a length of 4n+1: 1 character holds
		// only 6 bits, less than a byte.
		if len(s)%4 == 1 {
			s = s[:len(s)-1]
		}
		dst = slices.Grow(dst[:0], enc.DecodedLen(len(s)))
		n, err := enc.Decode(dst[:cap(dst)], s)
		if err != nil {
			continue
		}
		if hasTextRun(dst[:n], minText) {
			return true, dst
		}
	}
	return false, dst
}

// isHexDigit reports whether c is 0-9, a-f or A-F.
func isHexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// hasTextRun reports whether b holds at least n printable bytes in a row. A
// printable byte is part of a valid UTF-8 rune that unicode.IsPrint accepts
// (this includes printable ASCII), or a tab, a newline or a carriage return.
func hasTextRun(b []byte, n int) bool {
	count := 0
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		valid := r != utf8.RuneError || size > 1
		if valid && (unicode.IsPrint(r) || r == '\t' || r == '\n' || r == '\r') {
			count += size
			if count >= n {
				return true
			}
			continue
		}
		count = 0
	}
	return false
}
