package rules

import (
	"bytes"
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
	// 8 to 4096), min_text, the shortest decoded text in bytes (default 24,
	// 4 to 3072), and min_words, the fewest words in a row that the decoded
	// text must hold (default 0, which turns the check off, 0 to 64). See
	// hasWordRun for what a word is.
	HeuristicBase64Blob = "base64_blob"
	// HeuristicMatchWindow flags a text that the regex and keyword matchers
	// do not read in full: the text is longer than the raw scan limit, or a
	// match form is cut at MaxMatchInputBytes (see matchWindowCut). So a
	// payload that padding pushes out of the match window still gives a hit.
	// It has no parameters.
	HeuristicMatchWindow = "match_window"
	// HeuristicTagBidiOverride flags the Unicode tag characters (U+E0000 to
	// U+E007F), which can hide a full ASCII text, and the bidi overrides LRO
	// (U+202D) and RLO (U+202E), which reverse the text a reader sees. It
	// excuses only the three emoji flags that use tag characters: England,
	// Scotland and Wales. It does not flag the other invisible runes, such as
	// ZWJ, ZWNJ, RLM or the bidi isolates. It has no parameters.
	HeuristicTagBidiOverride = "tag_or_bidi_override"

	// The five heuristics below run the native config checks on one case line
	// of a built-in config rule (target: config). The line is text, read by the
	// adapters in textcheck.go. Each one has no parameters.

	// HeuristicInsecureURL flags an http:// URL to a host that is not loopback
	// (MOAT-T4-001). The text is one URL.
	HeuristicInsecureURL = "insecure_url"
	// HeuristicPlaintextSecret flags a literal secret in plain text
	// (MOAT-T4-002). A case line can be an env entry "KEY=VALUE", a header entry
	// "Name: value", a URL, or a command line (the args of a stdio server). The
	// check looks at env values, header values, command args and URLs. The value
	// is never reported.
	HeuristicPlaintextSecret = "plaintext_secret"
	// HeuristicUnpinnedPackage flags a package in a command line that is not
	// pinned to a version (MOAT-T4-003). The text is a command line. It covers
	// a registry package and also a git, tarball, URL or GitHub-shorthand spec
	// (npx, bunx, uvx --from, pipx --spec) and a "pipx run" script URL. A git or
	// GitHub spec is unpinned unless it pins a full 40-hex commit. A tarball,
	// URL or script spec is always unpinned, except the https URL of a
	// repository on a known git host, which counts as a git spec.
	HeuristicUnpinnedPackage = "unpinned_package"
	// HeuristicAutoInstall flags a command line that runs npx with its yes
	// option on, such as -y or --yes before the package (MOAT-T4-004). The
	// text is a command line.
	HeuristicAutoInstall = "auto_install"
	// HeuristicTyposquat flags a package whose name is close to a popular MCP
	// server name (MOAT-T5-001). The text is a command line or a bare package
	// name.
	HeuristicTyposquat = "typosquat"
)

// heuristicNames lists the valid heuristic names for an error message, in
// alphabetical order.
const heuristicNames = HeuristicAutoInstall + ", " + HeuristicBase64Blob + ", " +
	HeuristicInsecureURL + ", " + HeuristicInvisibleUnicode + ", " +
	HeuristicMatchWindow + ", " + HeuristicMaxLength + ", " +
	HeuristicPlaintextSecret + ", " + HeuristicTagBidiOverride + ", " +
	HeuristicTyposquat + ", " + HeuristicUnpinnedPackage

// paramSpec describes one integer parameter of a heuristic.
type paramSpec struct {
	name     string
	def      int // value when the rule does not set it
	min, max int // allowed range, both included
}

// compileHeuristic returns the function of the heuristic name, with its
// parameters checked and set. The function reads the raw text. Every error
// is a *FieldError.
func compileHeuristic(name string, params map[string]any) (func(raw string) []Hit, error) {
	switch name {
	case HeuristicInvisibleUnicode:
		if _, err := readParams(params); err != nil {
			return nil, err
		}
		return invisibleUnicode, nil
	case HeuristicMatchWindow:
		if _, err := readParams(params); err != nil {
			return nil, err
		}
		return matchWindow, nil
	case HeuristicTagBidiOverride:
		if _, err := readParams(params); err != nil {
			return nil, err
		}
		return tagBidiOverride, nil
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
			paramSpec{name: "min_words", def: 0, min: 0, max: 64},
		)
		if err != nil {
			return nil, err
		}
		minLength, minText, minWords := v[0], v[1], v[2]
		return func(raw string) []Hit { return base64Blob(raw, minLength, minText, minWords) }, nil
	case HeuristicTyposquat:
		if _, err := readParams(params); err != nil {
			return nil, err
		}
		fn, err := newTyposquatText()
		if err != nil {
			// The popular list is built in, so its text is safe to show.
			return nil, &FieldError{Field: "heuristic", Msg: "load popular server list: " + err.Error()}
		}
		return fn, nil
	}
	if fn, ok := configTextChecks[name]; ok {
		if _, err := readParams(params); err != nil {
			return nil, err
		}
		return fn, nil
	}
	// The given name is not echoed: it comes from the rule file.
	return nil, &FieldError{Field: "heuristic", Msg: "unknown heuristic; valid: " + heuristicNames}
}

// readParams checks params against specs and returns the value of each spec,
// in the order of specs.
//
// An unknown key comes from the rule file, so the error does not echo it. It
// lists the valid keys instead.
func readParams(params map[string]any, specs ...paramSpec) ([]int, error) {
	for key := range params {
		known := slices.ContainsFunc(specs, func(s paramSpec) bool { return s.name == key })
		if !known {
			return nil, unknownParamError(specs)
		}
	}
	values := make([]int, len(specs))
	for i, s := range specs {
		v := s.def
		if raw, ok := params[s.name]; ok {
			// YAML decodes an integer as int; any other type is a mistake.
			n, isInt := raw.(int)
			if !isInt {
				return nil, rangeError(s)
			}
			v = n
		}
		if v < s.min || v > s.max {
			return nil, rangeError(s)
		}
		values[i] = v
	}
	return values, nil
}

// rangeError returns the error for a value of s that is not an integer in
// its range.
func rangeError(s paramSpec) error {
	return &FieldError{Field: "params." + s.name, Msg: fmt.Sprintf("must be an integer between %d and %d", s.min, s.max)}
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

// invisibleUnicode flags every rune of raw for which isInvisible is true. So
// it flags every control rune except the white space, also the runes that
// start, end or cancel an ANSI escape sequence (see ansiToSpace): they show
// as nothing, and a terminal runs them. A raw ESC before a letter can make
// the letter the final byte of a CSI, so "\x1b[Ignore" hides the "I" from the
// regexes; this heuristic flags the ESC.
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
			excused = isPictograph(prev) || (isKeycapBase(prev) && runeAt(raw, i+utf8.RuneLen(r)) == keycapMark)
		case zeroWidthJoiner:
			excused = afterEmoji && isPictograph(runeAt(raw, i+utf8.RuneLen(r)))
		}
		if isInvisible(r) && !excused && l.keep(i) {
			l.hits = append(l.hits, Hit{Offset: i, Detail: fmt.Sprintf("U+%04X at offset %d", r, i)})
		}
		excusedVS := excused && r != zeroWidthJoiner && isPictograph(prev)
		afterEmoji = isPictograph(r) || excusedVS
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
	isSkinTone := 0x1F3FB <= r && r <= 0x1F3FF
	return (r >= 0x80 && unicode.Is(unicode.So, r)) || isSkinTone
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

// matchWindow flags raw when the regex and keyword matchers do not read all
// of it (see matchWindowCut). The hit is about the whole text, so it has the
// offset NoOffset.
func matchWindow(raw string) []Hit {
	if !matchWindowCut(raw) {
		return nil
	}
	return []Hit{{Offset: NoOffset, Detail: "text is longer than the match window"}}
}

// Runes that tag_or_bidi_override flags, and the base of the tag flags.
const (
	tagFirst            = '\U000E0000' // the first tag character
	tagLast             = '\U000E007F' // the last tag character, CANCEL TAG
	leftToRightOverride = '\u202D'     // LRO
	rightToLeftOverride = '\u202E'     // RLO
	blackFlag           = '\U0001F3F4' // the base of the tag flags
)

// The tag characters after blackFlag in the three emoji flags that use them.
// Each one is a tag letter (its ASCII letter plus U+E0000) and then the
// CANCEL TAG. The letters are a region code, such as "gbeng" for England.
const (
	flagTagsEngland  = "\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F" // gbeng
	flagTagsScotland = "\U000E0067\U000E0062\U000E0073\U000E0063\U000E0074\U000E007F" // gbsct
	flagTagsWales    = "\U000E0067\U000E0062\U000E0077\U000E006C\U000E0073\U000E007F" // gbwls
)

// tagBidiOverride flags each run of tag characters and bidi overrides (see
// isTagOrOverride) in raw. One hit stands for a whole run, at the offset of
// its first rune. The Detail gives the length of the run but not its runes:
// the code points of tag characters are the hidden text.
//
// The tag characters of the England, Scotland and Wales flags (see
// flagTagsLen) are excused only directly after U+1F3F4. Any other tag
// character is flagged, also in a sequence that looks like a flag but has
// other letters, and also a tag character right after an excused flag.
func tagBidiOverride(raw string) []Hit {
	var l hitList
	runStart, runLen := 0, 0 // byte offset and rune count of the current run
	endRun := func() {
		if runLen > 0 && l.keep(runStart) {
			l.hits = append(l.hits, Hit{Offset: runStart, Detail: fmt.Sprintf("tag or bidi override run of %d runes at offset %d", runLen, runStart)})
		}
		runLen = 0
	}
	// The loop uses a byte index instead of range, so it can skip the tag
	// characters of an excused flag.
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRuneInString(raw[i:])
		switch {
		case isTagOrOverride(r):
			if runLen == 0 {
				runStart = i
			}
			runLen++
		case r == blackFlag:
			endRun()
			size += flagTagsLen(raw[i+size:])
		default:
			endRun()
		}
		i += size
	}
	endRun()
	return l.result("tag or bidi override runs")
}

// isTagOrOverride reports whether r is a tag character (U+E0000 to U+E007F)
// or a bidi override (U+202D or U+202E).
func isTagOrOverride(r rune) bool {
	return tagFirst <= r && r <= tagLast || r == leftToRightOverride || r == rightToLeftOverride
}

// flagTagsLen returns the length in bytes of the tag characters of the
// England, Scotland or Wales flag at the start of s, or 0 when s does not
// start with one of them.
func flagTagsLen(s string) int {
	for _, tags := range []string{flagTagsEngland, flagTagsScotland, flagTagsWales} {
		if strings.HasPrefix(s, tags) {
			return len(tags)
		}
	}
	return 0
}

// base64Blob flags each run of base64 characters in raw that is at least
// minLength characters long and decodes to at least minText printable bytes
// in a row. When minWords is more than 0, the decoded text must also hold at
// least minWords words in a row (see hasWordRun). So a JWT, which decodes to
// JSON, does not count, but an encoded sentence does.
//
// A run is a longest sequence of [A-Za-z0-9+/_-]. A run can mix the standard
// and the URL-safe alphabets, so a "-" or "_" glued to a payload cannot hide
// it. An invisible rune inside a run is skipped, so a ZWSP or a control rune
// such as ESC cannot split a payload. A '=' ends a run: base64 padding comes
// only at the end, and the decoder does not need it.
func base64Blob(raw string, minLength, minText, minWords int) []Hit {
	var l hitList
	var run []byte // characters of the current run, without invisible runes
	var dst []byte // decode buffer, reused for every run
	start := 0     // byte offset in raw of the current run
	// check flags the current run when it is long enough and decodes to
	// text. Then it empties run for the next one.
	check := func() {
		if len(run) >= minLength {
			var ok bool
			ok, dst = decodesToText(run, minText, minWords, dst)
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
// bytes in a row and, when minWords is more than 0, to at least minWords
// words in a row (see hasWordRun). dst is a buffer that decodesToText can
// reuse; it returns the buffer for the next call.
//
// decodesToText changes run: it maps the URL-safe '-' and '_' to the
// standard '+' and '/', so one decoder reads both alphabets, also when they
// are mixed in one run.
//
// The run can start in the middle of a base64 text, for example when a word
// is glued to it, so each of the 4 possible alignments is tried.
func decodesToText(run []byte, minText, minWords int, dst []byte) (bool, []byte) {
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
		text := dst[:n]
		if hasTextRun(text, minText) && (minWords == 0 || hasWordRun(text, minWords)) {
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

// hasWordRun reports whether b holds at least n words in a row. The words
// are the fields of b between white space (see bytes.FieldsSeq). Any field
// that is not a word (see isWord) ends the run.
//
// JSON, such as the decoded parts of a JWT ({"alg":"HS256",...}), has its
// quotes, colons and digits inside the fields, so its fields are not words.
// A sentence such as "ignore all previous instructions" is a run of words.
func hasWordRun(b []byte, n int) bool {
	count := 0
	for field := range bytes.FieldsSeq(b) {
		if !isWord(field) {
			count = 0
			continue
		}
		count++
		if count >= n {
			return true
		}
	}
	return false
}

// isWord reports whether field is a word: after the punctuation at its two
// ends is removed (such as the comma in "file," or the quotes in "\"read\""),
// it is not empty and every rune of it is a letter. An invalid byte is not a
// letter.
func isWord(field []byte) bool {
	field = bytes.TrimFunc(field, unicode.IsPunct)
	if len(field) == 0 {
		return false
	}
	for len(field) > 0 {
		r, size := utf8.DecodeRune(field)
		if !unicode.IsLetter(r) {
			return false
		}
		field = field[size:]
	}
	return true
}
