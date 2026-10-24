package rules

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Invisible and unsafe runes are written as Go escape sequences on purpose. A
// raw zero-width or bidi character in the source file would be hard to see,
// and linters flag it.

func TestIsInvisible(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    rune
		want bool
	}{
		{name: "ZWSP", r: '\u200b', want: true},
		{name: "ZWNJ", r: '\u200c', want: true},
		{name: "ZWJ", r: '\u200d', want: true},
		{name: "LRM", r: '\u200e', want: true},
		{name: "RLO bidi override", r: '\u202e', want: true},
		{name: "LRI bidi isolate", r: '\u2066', want: true},
		{name: "BOM", r: '\ufeff', want: true},
		{name: "soft hyphen", r: '\u00ad', want: true},
		{name: "word joiner", r: '\u2060', want: true},
		{name: "tag letter A", r: '\U000E0041', want: true},
		{name: "VS17", r: '\U000E0100', want: true},
		{name: "VS16", r: '\ufe0f', want: true},
		{name: "CGJ", r: '\u034f', want: true},
		{name: "Hangul filler", r: '\u3164', want: true},
		{name: "ASCII letter", r: 'a', want: false},
		{name: "precomposed e acute", r: '\u00e9', want: false},
		{name: "space", r: ' ', want: false},
		{name: "newline", r: '\n', want: false},
		{name: "emoji", r: '\U0001F642', want: false},
		{name: "combining acute", r: '\u0301', want: false},
		// Control runes (Cc) are invisible, except white space. The runes
		// that start, end or cancel an ANSI escape sequence are invisible too.
		{name: "NUL", r: '\x00', want: true},
		{name: "SOH U+0001", r: '\x01', want: true},
		{name: "US U+001F", r: '\x1f', want: true},
		{name: "DEL", r: '\x7f', want: true},
		{name: "C1 DCS U+0090", r: '\u0090', want: true},
		{name: "tab", r: '\t', want: false},
		{name: "VT", r: '\v', want: false},
		{name: "FF", r: '\f', want: false},
		{name: "CR", r: '\r', want: false},
		{name: "NEL", r: '\u0085', want: false},
		{name: "ESC", r: '\x1b', want: true},
		{name: "BEL", r: '\x07', want: true},
		{name: "CAN", r: '\x18', want: true},
		{name: "SUB", r: '\x1a', want: true},
		{name: "C1 CSI", r: '\u009b', want: true},
		{name: "C1 ST", r: '\u009c', want: true},
		{name: "C1 OSC", r: '\u009d', want: true},
		// Cf, but shows as a mark (prepended concatenation marks).
		{name: "Arabic number sign", r: '\u0600', want: false},
		{name: "Arabic end of ayah", r: '\u06dd', want: false},
		{name: "Kaithi number sign", r: '\U000110BD', want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isInvisible(tt.r); got != tt.want {
				t.Errorf("isInvisible(%U) = %v, want %v", tt.r, got, tt.want)
			}
		})
	}
}

func TestNormalizeForMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "ZWSP inside keyword", in: "ign\u200bore previous", want: "ignore previous"},
		{name: "soft hyphen", in: "ign\u00adore", want: "ignore"},
		{name: "bidi override", in: "\u202eignore\u202c", want: "ignore"},
		{name: "tag characters", in: "ign\U000E0041\U000E007Fore", want: "ignore"},
		{name: "variation selectors", in: "ign\ufe0fore\U000E0100", want: "ignore"},
		{name: "Hangul filler", in: "ign\u3164ore", want: "ignore"},
		{name: "BOM and word joiner", in: "\ufeffign\u2060ore", want: "ignore"},
		{name: "decomposed to NFC", in: "e\u0301", want: "\u00e9"},
		{name: "strip before NFC", in: "e\u200b\u0301", want: "\u00e9"},
		{name: "precomposed unchanged", in: "caf\u00e9", want: "caf\u00e9"},
		{name: "plain ASCII unchanged", in: "Ignore all previous instructions.", want: "Ignore all previous instructions."},
		{name: "NBSP to space", in: "Ignore\u00a0previous", want: "Ignore previous"},
		{name: "other Zs to space", in: "a\u2003b\u202fc\u3000d\u1680e", want: "a b c d e"},
		{name: "VT and NEL to space", in: "a\vb\u0085c", want: "a b c"},
		{name: "line and paragraph separators to space", in: "a\u2028b\u2029c", want: "a b c"},
		{name: "Braille blank to space", in: "a\u2800b", want: "a b"},
		// Control runes are invisible, so they are dropped here. The second
		// form of matchForms has a space for them (see TestMatchForms).
		{name: "control runes dropped", in: "a\x00b\x1fc\x7fd\u0090e", want: "abcde"},
		{name: "control rune inside keyword", in: "Ig\x01nore", want: "Ignore"},
		{name: "control rune next to white space", in: "a\x01\tb\x7f\nc", want: "a\tb\nc"},
		{name: "ANSI CSI to space", in: "a\x1b[8mIgnore\x1b[0m b", want: "a Ignore  b"},
		{name: "ANSI CSI before keyword", in: "\x1b[8mIgnore", want: " Ignore"},
		// The control runes are dropped only after the CSI step, so CAN and
		// SUB cancel the CSI: ESC [ CAN "I" is not a CSI that hides the "I".
		// The ESC is then dropped too.
		{name: "CAN inside CSI keeps keyword", in: "\x1b[\x18Ignore", want: "[Ignore"},
		{name: "SUB inside CSI keeps keyword", in: "\x1b[\x1aIgnore", want: "[Ignore"},
		{name: "CAN between ESC and [ cancels the CSI and [8m stays", in: "\x1b\x18[8mIgnore", want: "[8mIgnore"},
		{name: "SUB between ESC and [ cancels the CSI and [8m stays", in: "\x1b\x1a[8mIgnore", want: "[8mIgnore"},
		// ansiSeq is strict: a C0 control rune inside ESC [ ends the CSI, so
		// ansiSeq finds no CSI, and step 4 drops the ESC and the control
		// rune. A terminal goes on with the CSI; the forms 4 to 7 of
		// matchForms read it that way (see TestMatchForms).
		{name: "control rune inside CSI is not a CSI", in: "\x1b[\x01Ignore", want: "[Ignore"},
		{name: "DEL inside CSI is not a CSI", in: "\x1b[\x7fIgnore", want: "[Ignore"},
		{name: "DEL among CSI parameters is not a CSI", in: "\x1b[8\x7fmIgnore", want: "[8mIgnore"},
		{name: "control rune between ESC and [ is not a CSI", in: "\x1b\x01[8mIgnore", want: "[8mIgnore"},
		{name: "control rune after C1 CSI is not a CSI", in: "\u009b\x018mIgnore", want: "8mIgnore"},
		{name: "BEL inside keyword", in: "Ig\x07nore", want: "Ignore"},
		{name: "ESC inside keyword", in: "Ig\x1bnore", want: "Ignore"},
		{name: "C1 CSI before keyword", in: "\u009b8mIgnore", want: " Ignore"},
		{name: "C1 CSI to space", in: "a\u009b1;31mb", want: "a b"},
		{name: "JSON-escaped CSI to space", in: "a\\u001b[8mb", want: "a b"},
		{name: "ANSI OSC to space", in: "a\x1b]0;title\x07b", want: "a b"},
		{name: "ANSI OSC with BEL before keyword", in: "\x1b]0;title\x07Ignore", want: " Ignore"},
		{name: "C1 OSC with C1 ST", in: "a\u009d0;title\u009cb", want: "a b"},
		{name: "OSC with no end keeps the text", in: "a\x1b]0;title b", want: "a]0;title b"},
		{name: "ASCII white space kept", in: "a\tb\nc\rd\fe", want: "a\tb\nc\rd\fe"},
		{name: "VT FF and NEL not dropped", in: "a\vb\fc\u0085d", want: "a b\fc d"},
		{name: "emoji kept", in: "hi \U0001F642", want: "hi \U0001F642"},
		{name: "only invisible", in: "\u200b\u200c\u200d", want: ""},
		{name: "empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeForMatch(tt.in); got != tt.want {
				t.Errorf("normalizeForMatch(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizeForMatchCap checks that a long input is cut to at most
// MaxMatchInputBytes bytes, at a rune boundary, for runes of 1 to 4 bytes.
func TestNormalizeForMatchCap(t *testing.T) {
	t.Parallel()

	const n = MaxMatchInputBytes
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "1-byte runes cut at the limit",
			in:   strings.Repeat("a", n+100),
			want: strings.Repeat("a", n),
		},
		{
			name: "2-byte rune straddles the limit",
			in:   strings.Repeat("a", n-1) + "\u00e9" + "tail",
			want: strings.Repeat("a", n-1),
		},
		{
			name: "3-byte rune straddles after 1 byte",
			in:   strings.Repeat("a", n-1) + "\u20ac" + "tail",
			want: strings.Repeat("a", n-1),
		},
		{
			name: "3-byte rune straddles after 2 bytes",
			in:   strings.Repeat("a", n-2) + "\u20ac" + "tail",
			want: strings.Repeat("a", n-2),
		},
		{
			name: "4-byte rune straddles after 1 byte",
			in:   strings.Repeat("a", n-1) + "\U0001F642" + "tail",
			want: strings.Repeat("a", n-1),
		},
		{
			name: "4-byte rune straddles after 2 bytes",
			in:   strings.Repeat("a", n-2) + "\U0001F642" + "tail",
			want: strings.Repeat("a", n-2),
		},
		{
			name: "4-byte rune straddles after 3 bytes",
			in:   strings.Repeat("a", n-3) + "\U0001F642" + "tail",
			want: strings.Repeat("a", n-3),
		},
		{
			name: "4-byte rune ends at the limit is kept",
			in:   strings.Repeat("a", n-4) + "\U0001F642" + "tail",
			want: strings.Repeat("a", n-4) + "\U0001F642",
		},
		{
			// Invisible runes are dropped before the cut to n.
			name: "invisible padding does not use the window",
			in:   strings.Repeat("\u200b", n/3+100) + strings.Repeat("a", n+10),
			want: strings.Repeat("a", n),
		},
		{
			// The raw text is cut to maxRawScanBytes first: after 43690
			// ZWSPs (131070 bytes), only "ab" fits.
			name: "raw window cut before the invisible runes are dropped",
			in:   strings.Repeat("\u200b", maxRawScanBytes/3) + "abcd",
			want: "ab",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeForMatch(tt.in)
			if len(got) > n {
				t.Errorf("len(normalizeForMatch()) = %d, want <= %d", len(got), n)
			}
			if !utf8.ValidString(got) {
				t.Errorf("normalizeForMatch() is not valid UTF-8")
			}
			if got != tt.want {
				t.Errorf("normalizeForMatch() = %d bytes ending %q, want %d bytes ending %q",
					len(got), normTestTail(got), len(tt.want), normTestTail(tt.want))
			}
		})
	}
}

func TestCutAtRune(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{name: "shorter than n", in: "abc", n: 10, want: "abc"},
		{name: "exactly n", in: "abc", n: 3, want: "abc"},
		{name: "empty", in: "", n: 0, want: ""},
		{name: "n zero", in: "abc", n: 0, want: ""},
		{name: "ASCII cut", in: "abcdef", n: 3, want: "abc"},
		{name: "2-byte rune split", in: "a\u00e9", n: 2, want: "a"},
		{name: "3-byte rune split after 2 bytes", in: "a\u20ac", n: 3, want: "a"},
		{name: "4-byte rune split after 3 bytes", in: "a\U0001F642", n: 4, want: "a"},
		{name: "rune at the boundary kept", in: "\u00e9x", n: 2, want: "\u00e9"},
		{name: "only a split rune", in: "\U0001F642", n: 2, want: ""},
		// Invalid UTF-8: continuation bytes only. The cut moves back at most
		// utf8.UTFMax-1 bytes, then stops.
		{name: "continuation bytes", in: strings.Repeat("\x80", 10), n: 8, want: strings.Repeat("\x80", 5)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := cutAtRune(tt.in, tt.n); got != tt.want {
				t.Errorf("cutAtRune(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
			}
		})
	}
}

// TestNormalizeForMatchLongCombiningRun checks that the CGJ that the norm
// package inserts after 30 combining marks (Stream-Safe Text Format) is
// removed again.
func TestNormalizeForMatchLongCombiningRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		marks int
	}{
		{name: "40 marks", marks: 40},
		{name: "100 marks", marks: 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := "a" + strings.Repeat("\u0301", tt.marks) + "b"
			// Guard: without the second pass, NFC alone puts a CGJ in.
			if !strings.ContainsRune(norm.NFC.String(in), '\u034f') {
				t.Fatal("norm.NFC.String() inserted no CGJ; the test input no longer checks the second pass")
			}
			got := normalizeForMatch(in)
			if strings.ContainsRune(got, '\u034f') {
				t.Errorf("normalizeForMatch() = %q, want no U+034F", got)
			}
			if !strings.HasPrefix(got, "\u00e1") || !strings.HasSuffix(got, "b") {
				t.Errorf("normalizeForMatch() = %q, want it to start with %q and end with %q", got, "\u00e1", "b")
			}
		})
	}
}

func TestNormalizeForMatchInvalidUTF8(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string // empty means: check only that the output is valid UTF-8
	}{
		{name: "bad leading bytes", in: "\xff\xfe abc", want: "\ufffd\ufffd abc"},
		{name: "truncated rune", in: "abc\xe2\x82", want: "abc\ufffd\ufffd"},
		{name: "long run of continuation bytes", in: strings.Repeat("\x80", MaxMatchInputBytes+10)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeForMatch(tt.in)
			if !utf8.ValidString(got) {
				t.Errorf("normalizeForMatch(%d bytes) is not valid UTF-8", len(tt.in))
			}
			if tt.want != "" && got != tt.want {
				t.Errorf("normalizeForMatch(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// normTestTail returns the last few bytes of s, to keep failure messages short.
func normTestTail(s string) string {
	const k = 8
	if len(s) <= k {
		return s
	}
	return s[len(s)-k:]
}

// TestFoldMarks checks the marks that foldMarks drops and the ones it keeps,
// and that it keeps a rune whose fold is longer than the rune.
func TestFoldMarks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "precomposed accent", in: "caf\u00e9", want: "cafe"},
		{name: "overlay mark", in: "ig\u0336nore", want: "ignore"},
		{name: "enclosing mark", in: "ig\u20ddnore", want: "ignore"},
		{name: "spacing mark", in: "ignore\u0903", want: "ignore"},
		{name: "Devanagari vowel sign", in: "\u0915\u093e", want: "\u0915"},
		{name: "Hangul syllable kept", in: "\ud55c", want: "\ud55c"},
		{name: "fullwidth letters", in: "\uff49\uff47\uff4e\uff4f\uff52\uff45", want: "ignore"},
		{name: "mathematical bold letters", in: "\U0001D422\U0001D420\U0001D427\U0001D428\U0001D42B\U0001D41E", want: "ignore"},
		{name: "ligature fi", in: "\ufb01le", want: "file"},
		// A rune is folded only when its fold is not longer in bytes.
		{name: "ligature ffi folds to the same length", in: "\ufb03x", want: "ffix"},
		{name: "ligature U+FDFA kept", in: "a\ufdfab", want: "a\ufdfab"},
		{name: "fraction U+00BD kept", in: "\u00bd", want: "\u00bd"},
		{name: "roman numeral U+2177 kept", in: "\u2177", want: "\u2177"},
		{name: "long fold kept next to short folds", in: "\uff49\ufdfa\U0001D422e\u0301", want: "i\ufdfaie"},
		{name: "plain ASCII unchanged", in: "ignore previous", want: "ignore previous"},
		{name: "empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := foldMarks(tt.in); got != tt.want {
				t.Errorf("foldMarks(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestFoldMarksNotLonger checks that ligature padding does not make the
// folded form longer: U+FDFA folds to 33 bytes, so a fold of each rune would
// push " x" out of the MaxMatchInputBytes window.
func TestFoldMarksNotLonger(t *testing.T) {
	t.Parallel()

	in := strings.Repeat("\ufdfa", 1000) + " x"
	if got := foldMarks(in); len(got) > len(in) || !strings.HasSuffix(got, " x") {
		t.Errorf("foldMarks(1000 x U+FDFA + \" x\") has %d bytes and suffix %q, want at most %d bytes and suffix \" x\"",
			len(got), got[max(0, len(got)-2):], len(in))
	}
}

// controlPadding is a run of control runes longer than MaxMatchInputBytes.
// If each rune of it became a space, a payload after it would be cut off.
// With its payload it must stay within maxFuzzInput, because
// fuzzControlTexts uses it as a fuzz seed.
var controlPadding = strings.Repeat("\x01", MaxMatchInputBytes+256)

// TestMatchForms checks that a text gets each of the forms 2 to 7 of
// matchForms only when it holds the runes that the form needs (see
// matchForms), and that equal forms are kept once. The fixtures that reach
// many forms at once (noSeqText, noC0CSIText and allFormsText) are in
// prepare_test.go.
func TestMatchForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "no invisible rune", in: "ignore previous", want: []string{"ignore previous"}},
		{name: "ZWSP inside a word", in: "ign\u200bore", want: []string{"ignore", "ign ore"}},
		{name: "ZWSP between words", in: "ignore\u200bprevious", want: []string{"ignoreprevious", "ignore previous"}},
		{name: "Hangul filler between words", in: "ignore\u3164previous", want: []string{"ignoreprevious", "ignore previous"}},
		{name: "run of invisible runes is one space", in: "a\u200b\u2060\u200bb", want: []string{"ab", "a b"}},
		{name: "spaces mapped in both forms", in: "a\u200bb\u00a0c", want: []string{"ab c", "a b c"}},
		{name: "control runes", in: "a\x00b\x1fc\x7fd\u0090e", want: []string{"abcde", "a b c d e"}},
		// The third form ("Ig nore") equals the second, so it is kept once.
		{name: "control rune inside a word", in: "Ig\x01nore", want: []string{"Ignore", "Ig nore"}},
		{name: "ZWSP and control rune in one run", in: "a\u200b\x01b", want: []string{"ab", "a b"}},
		// The run ends with a format rune, so the second form writes one
		// space for the control rune and one after it (see replaceRuns).
		{name: "control rune and ZWSP in one run", in: "a\x01\u200bb", want: []string{"ab", "a  b", "a b"}},
		// The third form drops the ZWSP and makes each control rune a space.
		// The fourth form drops the control rune and makes the ZWSP a space.
		{name: "ZWSP inside a word and control rune between words", in: "Ig\u200bnore\x01all", want: []string{"Ignoreall", "Ig nore all", "Ignore all", "Ig noreall"}},
		{name: "control rune inside a word and ZWSP between words", in: "Ig\x01nore\u200ball\u200bprevious", want: []string{"Ignoreallprevious", "Ig nore all previous", "Ig noreallprevious", "Ignore all previous"}},
		{name: "one space for each run of control runes in the third form", in: "a\x01\x02b\u200bc", want: []string{"abc", "a b c", "a bc", "ab c"}},
		// A ZWSP inside a run of control runes does not end the run. The
		// fourth form gives one space for the run, so it equals the second.
		{name: "ZWSP inside a run of control runes", in: "a\x01\u200b\x01b\u200bc", want: []string{"abc", "a b c", "a bc"}},
		// For ansiSeq (forms 1 to 3) a C0 control rune ends a CSI, so they
		// keep the "[". For ansiSeqC0 (forms 4 to 7) it does not, so the CSI
		// takes the "I": the fifth form gives the "I" back, and the sixth
		// form (dropSeqC0) loses it.
		{name: "control rune inside CSI", in: "\x1b[\x01Ignore", want: []string{"[Ignore", " [ Ignore", " Ignore", " gnore"}},
		// The fifth form drops the SGR, so it gives "Ignore all" with no
		// space. The sixth form makes the SGR a space.
		{name: "control rune between ESC and [", in: "\x1b\x01[8mIgnore all", want: []string{"[8mIgnore all", " [8mIgnore all", "Ignore all", " Ignore all"}},
		{name: "control rune after C1 CSI", in: "\u009b\x018mIgnore all", want: []string{"8mIgnore all", " 8mIgnore all", "Ignore all", " Ignore all"}},
		{name: "CSI takes the first letter", in: "\x1b[Ignore all", want: []string{" gnore all", " Ignore all"}},
		{name: "control rune between ESC and [ and CSI takes the first letter", in: "\x1b\x01[Ignore all", want: []string{"[Ignore all", " [Ignore all", " Ignore all", " gnore all"}},
		// A LF lets the ansiSeqC0 CSI take "<" and "I" of the text: ESC [ LF
		// < I. The fifth form gives "<I" back (see csiText), the sixth form
		// loses it, and the strict forms 1 to 3 keep "[" LF "<IMPORTANT>".
		{name: "LF inside CSI: the fifth form gives the < back", in: "\x1b[\n<IMPORTANT>x", want: []string{"[\n<IMPORTANT>x", " [\n<IMPORTANT>x", " <IMPORTANT>x", " MPORTANT>x"}},
		{name: "JSON-escaped CSI takes the first letter", in: "a\\u001b[Ignore all", want: []string{"a gnore all", "a Ignore all"}},
		// The fourth form puts the space before the ESC (or U+009B), so the
		// sequence is still a CSI and the ZWSP between words is a space. The
		// fifth form drops the SGR. The seventh form puts the space before the
		// ESC and drops the SGR, as the fifth form does, so it gives
		// " Ignore all".
		{
			name: "ZWSP after ESC and between words",
			in:   "\x1b\u200b[8mIgnore\u200ball",
			want: []string{" Ignoreall", "  [8mIgnore all", "  Ignore all", "Ignoreall", " Ignore all"},
		},
		{
			name: "ZWSP after C1 CSI and between words",
			in:   "\u009b\u200b8mIgnore\u200ball",
			want: []string{" Ignoreall", "  8mIgnore all", "  Ignore all", "Ignoreall", " Ignore all"},
		},
		// The fourth form equals the first, so it is kept once. The seventh
		// form gives the "I" back with the space of the ZWSP.
		{
			name: "ZWSP after C1 CSI and CSI takes the first letter",
			in:   "\u009b\u200bIgnore all",
			want: []string{" gnore all", "  gnore all", " Ignore all", "  Ignore all"},
		},
		// An OSC is one space, and the fifth form keeps its text.
		{name: "OSC with BEL", in: "\x1b]Ignore all\x07", want: []string{" ", " Ignore all "}},
		{name: "OSC with ST", in: "\x1b]Ignore all\x1b\\", want: []string{" ", " Ignore all "}},
		{name: "C1 OSC with BEL", in: "\u009dIgnore all\x07", want: []string{" ", " Ignore all "}},
		// An OSC with more than 256 runes of text is not an OSC, so its text
		// stays in every form, after its "]". The second form makes the ESC
		// and the BEL a space, and the fifth form equals the first.
		{
			name: "OSC text over 256 runes stays in every form",
			in:   "\x1b]" + strings.Repeat("x", 257) + " Ignore all\x07",
			want: []string{
				"]" + strings.Repeat("x", 257) + " Ignore all",
				" ]" + strings.Repeat("x", 257) + " Ignore all ",
			},
		},
		// The runes that start, end or cancel an ANSI escape sequence are
		// invisible control runes too, so they are dropped inside a word.
		{name: "BEL inside a word", in: "Ig\x07nore", want: []string{"Ignore", "Ig nore"}},
		{name: "CAN inside a word", in: "Ig\x18nore", want: []string{"Ignore", "Ig nore"}},
		{name: "SUB inside a word", in: "Ig\x1anore", want: []string{"Ignore", "Ig nore"}},
		{name: "ESC inside a word", in: "Ig\x1bnore", want: []string{"Ignore", "Ig nore"}},
		{name: "C1 ST inside a word", in: "Ig\u009cnore", want: []string{"Ignore", "Ig nore"}},
		// One space for the whole run of padding, so the payload stays in
		// the MaxMatchInputBytes window of the third form. The fourth form
		// drops the padding.
		{
			name: "control rune padding is one space in the third form",
			in:   controlPadding + "Ig\u200bnore\x01all\x01previous",
			want: []string{"Ignoreallprevious", " Ig nore all previous", " Ignore all previous", "Ig noreallprevious"},
		},
		{name: "white space only is one form", in: "a\tb\nc\rd\fe\vf\u0085g", want: []string{"a\tb\nc\rd\fe f g"}},
		// The fifth form drops an SGR (final 'm'), so it has no space before
		// "Ignore" (#133).
		{name: "ANSI CSI", in: "\x1b[8mIgnore", want: []string{" Ignore", "Ignore"}},
		// A CSI ends at its first letter, so in ESC [ 1 "make" the "m" of
		// "make" is the SGR final. The fifth form drops an SGR, so no form
		// gives "make" back (#133).
		{name: "known limit: m final takes the m of a word", in: "\x1b[1make", want: []string{" ake", "ake"}},
		// Gaps that the fifth and the seventh form close (#133). The fifth
		// form gives back the parameter bytes < = > ? and the intermediate
		// bytes of a CSI (see csiText), and it drops an SGR inside a word.
		{name: "CSI takes the < of a tag", in: "\x1b[<IMPORTANT>x", want: []string{" MPORTANT>x", " <IMPORTANT>x"}},
		{name: "CSI takes the . of a file name", in: "Read \x1b[.env", want: []string{"Read  nv", "Read  .env"}},
		{name: "SGR inside a word", in: "\x1b[1mIg\x1b[0mnore all", want: []string{" Ig nore all", "Ignore all"}},
		// The seventh form makes each invisible run a space, also inside the
		// text of an OSC and after the letter that a CSI takes.
		{
			name: "ZWSP between words in OSC text",
			in:   "\x1b]Ignore\u200ball\u200bprevious\x07",
			want: []string{" ", " Ignoreallprevious ", " Ignore all previous "},
		},
		{
			name: "control rune between words in OSC text",
			in:   "\x1b]Ignore\x01all\x01previous\x07",
			want: []string{" ", " Ignoreallprevious ", " Ignore all previous "},
		},
		{
			name: "CSI takes the first letter and control rune between words",
			in:   "\x1b[Ignore\x01all previous",
			want: []string{" gnoreall previous", " gnore all previous", " Ignoreall previous", " Ignore all previous"},
		},
		// Known limits, listed in the matchForms doc. The invisible_unicode
		// heuristic flags each of them in a description.
		//
		// A CSI letter with a ZWSP inside the word and a control rune between
		// words: the fifth form joins "Ignoreall", the seventh splits "Ig
		// nore", and the other forms lose the "I".
		{
			name: "known limit: CSI letter with two kinds of invisible runes",
			in:   "\x1b[Ig\u200bnore\x01all",
			want: []string{" gnoreall", " g nore all", " gnore all", " g noreall", " Ignoreall", " Ig nore all"},
		},
		// A control rune between ESC and a format rune: the fourth form keeps
		// "[8m" before "Ignore", and the other forms join "Ignoreall" or
		// keep "[8m".
		{
			name: "known limit: control rune between ESC and ZWSP",
			in:   "\x1b\x01\u200b[8mIgnore\u200ball",
			want: []string{"[8mIgnoreall", "  [8mIgnore all", " [8mIgnoreall", " [8mIgnore all", "Ignoreall", " Ignoreall"},
		},
		// The final byte "~" is not a letter, so no form gives it back.
		{name: "known limit: CSI takes a ~ final", in: "\x1b[~/.ssh", want: []string{" /.ssh"}},
		// The final byte "@" is not a letter, so the fifth form equals the
		// first and is kept once.
		{name: "CSI with no letter is one form", in: "\x1b[1@x", want: []string{" x"}},
		{name: "empty", in: "", want: []string{""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := matchForms(tt.in); !slices.Equal(got, tt.want) {
				t.Errorf("matchForms(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizeInvisibleModes checks that each mode of normalizeInvisible
// builds its form of matchForms for one input.
func TestNormalizeInvisibleModes(t *testing.T) {
	t.Parallel()

	in := "Ig\u200bnore\x01\x02all\u200b\u200cprevious"
	tests := []struct {
		name string
		mode invisibleMode
		want string
	}{
		{name: "dropInvisible", mode: dropInvisible, want: "Ignoreallprevious"},
		{name: "spaceInvisible", mode: spaceInvisible, want: "Ig nore all previous"},
		{name: "spaceControls", mode: spaceControls, want: "Ignore allprevious"},
		{name: "spaceFormats", mode: spaceFormats, want: "Ig noreall previous"},
		{name: "keepSeqText", mode: keepSeqText, want: "Ignoreallprevious"},
		{name: "dropSeqC0", mode: dropSeqC0, want: "Ignoreallprevious"},
		{name: "keepSeqTextSpaced", mode: keepSeqTextSpaced, want: "Ig nore all previous"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeInvisible(in, tt.mode); got != tt.want {
				t.Errorf("normalizeInvisible(%q, %s) = %q, want %q", in, tt.name, got, tt.want)
			}
		})
	}
	// The input has no ESC, so hasSeqStart and hasSeqC0 are false: it has
	// only the forms 1 to 4.
	want := []string{"Ignoreallprevious", "Ig nore all previous", "Ignore allprevious", "Ig noreall previous"}
	if got := matchForms(in); !slices.Equal(got, want) {
		t.Errorf("matchForms(%q) = %q, want %q", in, got, want)
	}
}

// TestNormalizeInvisibleDropSeqC0 checks the sixth form of matchForms: it
// reads a CSI that holds C0 control runes as one sequence, where the first
// form (strict ansiSeq) does not.
func TestNormalizeInvisibleDropSeqC0(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		in        string
		want      string
		wantFirst string // normalizeForMatch(in), the first form
	}{
		{name: "control rune between ESC and [", in: "\x1b\x01[8mIgnore", want: " Ignore", wantFirst: "[8mIgnore"},
		{name: "control rune after C1 CSI", in: "\u009b\x018mIgnore", want: " Ignore", wantFirst: "8mIgnore"},
		{name: "DEL among CSI parameters", in: "\x1b[8\x7fmIgnore", want: " Ignore", wantFirst: "[8mIgnore"},
		{name: "CAN cancels the CSI in both", in: "\x1b\x18[8mIgnore", want: "[8mIgnore", wantFirst: "[8mIgnore"},
		{name: "invisible runes dropped", in: "Ig\u200bnore\x01all", want: "Ignoreall", wantFirst: "Ignoreall"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeInvisible(tt.in, dropSeqC0); got != tt.want {
				t.Errorf("normalizeInvisible(%+q, dropSeqC0) = %+q, want %+q", tt.in, got, tt.want)
			}
			if got := normalizeForMatch(tt.in); got != tt.wantFirst {
				t.Errorf("normalizeForMatch(%+q) = %+q, want %+q", tt.in, got, tt.wantFirst)
			}
		})
	}
}

// TestStrictFormsUnchanged checks the forms 1 to 3 of matchForms for texts
// with a C0 control rune inside a CSI. These forms must stay byte for byte
// the strict ansiSeq forms. The newer forms only add to them, so the form
// set keeps every earlier form and no match of an earlier form is lost.
func TestStrictFormsUnchanged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want [3]string // dropInvisible, spaceInvisible, spaceControls
	}{
		{name: "control rune inside CSI", in: "\x1b[\x01Ignore", want: [3]string{"[Ignore", " [ Ignore", " [ Ignore"}},
		{name: "control rune between ESC and [", in: "\x1b\x01[8mIgnore all", want: [3]string{"[8mIgnore all", " [8mIgnore all", " [8mIgnore all"}},
		{name: "control rune after C1 CSI", in: "\u009b\x018mIgnore all", want: [3]string{"8mIgnore all", " 8mIgnore all", " 8mIgnore all"}},
		{name: "DEL among CSI parameters", in: "\x1b[8\x7fmIgnore", want: [3]string{"[8mIgnore", " [8 mIgnore", " [8 mIgnore"}},
		{name: "LF inside CSI", in: "\x1b[\n<IMPORTANT>x", want: [3]string{"[\n<IMPORTANT>x", " [\n<IMPORTANT>x", " [\n<IMPORTANT>x"}},
		{name: "ZWSP and control rune after ESC", in: "\x1b\u200b\x01[8m\u200bIgnore", want: [3]string{"[8mIgnore", " [8m Ignore", " [8mIgnore"}},
	}
	modes := [3]invisibleMode{dropInvisible, spaceInvisible, spaceControls}
	modeNames := [3]string{"dropInvisible", "spaceInvisible", "spaceControls"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for i, mode := range modes {
				if got := normalizeInvisible(tt.in, mode); got != tt.want[i] {
					t.Errorf("normalizeInvisible(%+q, %s) = %+q, want %+q (the strict ansiSeq form)",
						tt.in, modeNames[i], got, tt.want[i])
				}
			}
		})
	}
}

// TestNormalizeInvisibleKeepSeqText checks the fifth form of matchForms: it
// keeps the letter that a CSI takes and the text of an OSC.
func TestNormalizeInvisibleKeepSeqText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "CSI letter and OSC text kept", in: "\x1b[Ignore\x1b]0;all\x07b", want: " Ignore 0;all b"},
		{name: "C1 OSC with C1 ST", in: "\u009dall\u009cb", want: " all b"},
		{name: "JSON-escaped CSI letter kept", in: "a\\u001B[Ignore", want: "a Ignore"},
		{name: "CSI with no letter is one space", in: "\x1b[1@x", want: " x"},
		{name: "invisible runes dropped", in: "Ig\u200bnore\x01all", want: "Ignoreall"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeInvisible(tt.in, keepSeqText); got != tt.want {
				t.Errorf("normalizeInvisible(%q, keepSeqText) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizeInvisibleKeepSeqTextSpaced checks the seventh form of
// matchForms: the escape sequences as in the fifth form, and each run of
// invisible runes as one space, as in the second form. wantFifth is the fifth
// form, which joins the words.
func TestNormalizeInvisibleKeepSeqTextSpaced(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		in        string
		want      string
		wantFifth string // normalizeInvisible(in, keepSeqText)
	}{
		{name: "ZWSP in OSC text", in: "\x1b]Ignore\u200ball\x07", want: " Ignore all ", wantFifth: " Ignoreall "},
		{name: "control rune in OSC text", in: "\x1b]Ignore\x01all\x07", want: " Ignore all ", wantFifth: " Ignoreall "},
		{name: "control rune after a CSI letter", in: "\x1b[Ignore\x01all", want: " Ignore all", wantFifth: " Ignoreall"},
		{name: "ZWSP after a CSI letter", in: "\x1b[Ignore\u200ball", want: " Ignore all", wantFifth: " Ignoreall"},
		{name: "SGR dropped and ZWSP a space", in: "\x1b[1mIgnore\u200ball", want: "Ignore all", wantFifth: "Ignoreall"},
		// A control run that ends with a format rune is two spaces, as in the
		// second form (see replaceRuns).
		{name: "control rune and ZWSP in one run", in: "\x1b[Ig\x01\u200bnore", want: " Ig  nore", wantFifth: " Ignore"},
		{name: "C1 CSI letter and ZWSP", in: "\u009bIgnore\u200ball", want: " Ignore all", wantFifth: " Ignoreall"},
		{name: "JSON-escaped CSI letter and ZWSP", in: "\\u001b[Ignore\u200ball", want: " Ignore all", wantFifth: " Ignoreall"},
		{name: "no invisible run", in: "\x1b[Ignore all", want: " Ignore all", wantFifth: " Ignore all"},
		// A ZWSP before an ESC must not join "ning" and "jQuery" (#133).
		{
			name:      "ZWSP before bold text",
			in:        "When\u200brun\x1bning\u200b\x1b[1mjQuery\x1b[0m\u200bcode",
			want:      "When run ning jQuery code",
			wantFifth: "WhenrunningjQuerycode",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeInvisible(tt.in, keepSeqTextSpaced); got != tt.want {
				t.Errorf("normalizeInvisible(%+q, keepSeqTextSpaced) = %+q, want %+q", tt.in, got, tt.want)
			}
			if got := normalizeInvisible(tt.in, keepSeqText); got != tt.wantFifth {
				t.Errorf("normalizeInvisible(%+q, keepSeqText) = %+q, want %+q", tt.in, got, tt.wantFifth)
			}
		})
	}
}

// TestReplaceFormatRuns checks where step 2 puts the space of a run of
// invisible runes. In spaceFormats (placeOnce), the space goes before the
// control runes of the run when the last of them starts a sequence, and
// after them otherwise. In spaceInvisible (placeAtTail), it goes after them,
// and only when the run ends with a format rune.
func TestReplaceFormatRuns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode invisibleMode
		in   string
		want string
	}{
		{name: "ESC and ZWSP", mode: spaceFormats, in: "a\x1b\u200b[b", want: "a \x1b[b"},
		{name: "ZWSP and ESC", mode: spaceFormats, in: "a\u200b\x1b[b", want: "a \x1b[b"},
		{name: "C1 CSI and ZWSP", mode: spaceFormats, in: "a\u009b\u200bb", want: "a \u009bb"},
		{name: "C1 OSC and ZWSP", mode: spaceFormats, in: "a\u009d\u200bb", want: "a \u009db"},
		{name: "U+0001 and ZWSP", mode: spaceFormats, in: "a\x01\u200bb", want: "a\x01 b"},
		{name: "ZWSP and U+0001", mode: spaceFormats, in: "a\u200b\x01b", want: "a\x01 b"},
		// The last control rune is U+0001, not ESC, so the space goes after.
		{name: "ESC U+0001 and ZWSP", mode: spaceFormats, in: "a\x1b\x01\u200bb", want: "a\x1b\x01 b"},
		{name: "run of only control runes gets no space", mode: spaceFormats, in: "a\x01\x02b", want: "a\x01\x02b"},
		{name: "run of only format runes", mode: spaceFormats, in: "a\u200b\u200cb", want: "a b"},
		{name: "ESC and ZWSP at the tail", mode: spaceInvisible, in: "a\x1b\u200b[b", want: "a\x1b [b"},
		{name: "ZWSP and ESC with no tail", mode: spaceInvisible, in: "a\u200b\x1b[b", want: "a\x1b[b"},
		{name: "format runes dropped", mode: spaceControls, in: "a\x1b\u200b[b", want: "a\x1b[b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := replaceFormatRuns(tt.in, tt.mode); got != tt.want {
				t.Errorf("%s: replaceFormatRuns(%+q) = %+q, want %+q", tt.name, tt.in, got, tt.want)
			}
		})
	}
}

// TestSeqText checks what the fifth and the seventh form put in place of each
// kind of escape sequence. Each input is one whole match of ansiSeqC0, the
// regex whose matches ansiKeepText passes to seqText.
func TestSeqText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		seq  string
		want string
	}{
		{name: "CSI with letter", seq: "\x1b[I", want: " I"},
		{name: "SGR m final is removed", seq: "\x1b[8m", want: ""},
		{name: "CSI with a non-m letter final keeps it", seq: "\x1b[2K", want: " K"},
		{name: "C1 CSI with letter", seq: "\u009bI", want: " I"},
		{name: "CSI with control rune and letter", seq: "\x1b[\x01z", want: " z"},
		{name: "JSON-escaped CSI with letter", seq: "\\u001b[I", want: " I"},
		{name: "CSI with no letter", seq: "\x1b[1@", want: " "},
		{name: "CSI with a ~ final", seq: "\x1b[~", want: " "},
		// csiText: the bytes 0x20 to 0x2F and 0x3C to 0x3F are kept, and the
		// introducer, the digits, ";", ":" and the C0 runes are dropped.
		{name: "CSI keeps a < parameter byte", seq: "\x1b[<I", want: " <I"},
		{name: "CSI keeps a . intermediate byte", seq: "\x1b[.e", want: " .e"},
		{name: "CSI drops a digit", seq: "\x1b[1I", want: " I"},
		{name: "CSI drops digits and ;", seq: "\x1b[1;2I", want: " I"},
		{name: "CSI keeps ? and drops digits", seq: "\x1b[?25l", want: " ?l"},
		{name: "CSI drops : and keeps =", seq: "\x1b[=1:2>K", want: " =>K"},
		{name: "CSI drops a C0 rune", seq: "\x1b[\x01<I", want: " <I"},
		{name: "CSI drops C0 runes between ESC and [", seq: "\x1b\x01\n[<I", want: " <I"},
		{name: "C1 CSI keeps a < parameter byte", seq: "\u009b<I", want: " <I"},
		{name: "JSON-escaped CSI keeps a < parameter byte", seq: "\\u001b[<I", want: " <I"},
		{name: "JSON-escaped CSI with upper case B", seq: "\\u001B[/.e", want: " /.e"},
		// The OSC text stays as it is, also its digits and "<".
		{name: "OSC with BEL", seq: "\x1b]0;t\x07", want: " 0;t "},
		{name: "OSC keeps < and digits", seq: "\x1b]<1>\x07", want: " <1> "},
		{name: "OSC with ST", seq: "\x1b]t\x1b\\", want: " t "},
		{name: "C1 OSC with C1 ST", seq: "\u009dt\u009c", want: " t "},
		{name: "empty OSC", seq: "\u009d\x07", want: "  "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if m := ansiSeqC0.FindString(tt.seq); m != tt.seq {
				t.Fatalf("ansiSeqC0.FindString(%+q) = %+q, want the whole input", tt.seq, m)
			}
			if got := seqText(tt.seq); got != tt.want {
				t.Errorf("seqText(%+q) = %+q, want %+q", tt.seq, got, tt.want)
			}
		})
	}
}

func TestHasSeqStart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "ESC", in: "a\x1bb", want: true},
		{name: "C1 CSI", in: "a\u009bb", want: true},
		{name: "C1 OSC", in: "a\u009db", want: true},
		{name: "JSON escape lower case", in: "a\\u001b[", want: true},
		{name: "JSON escape upper case", in: "a\\u001B[", want: true},
		{name: "C1 ST alone", in: "a\u009cb", want: false},
		{name: "other control rune", in: "a\x01b", want: false},
		{name: "other JSON escape", in: "a\\u0001b", want: false},
		{name: "empty", in: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasSeqStart(tt.in); got != tt.want {
				t.Errorf("hasSeqStart(%+q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestHasPlainInvisible(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "ESC only", in: "a\x1b[8mb", want: false},
		{name: "ESC and ZWSP", in: "a\x1b[8m\u200bb", want: true},
		{name: "C1 CSI and U+0001", in: "a\u009b\x018mb", want: true},
		{name: "U+0001 alone", in: "a\x01b", want: true},
		{name: "ZWSP alone", in: "a\u200bb", want: true},
		{name: "C1 CSI only", in: "a\u009b8mb", want: false},
		{name: "C1 OSC only", in: "a\u009dtitle", want: false},
		// The BEL that ends an OSC counts (see hasPlainInvisible).
		{name: "OSC with BEL", in: "\x1b]t\x07", want: true},
		{name: "white space is not invisible", in: "a\tb\nc\u0085d", want: false},
		{name: "plain ASCII", in: "Ignore all", want: false},
		{name: "empty", in: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasPlainInvisible(tt.in); got != tt.want {
				t.Errorf("hasPlainInvisible(%+q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestHasSeqC0(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "ESC and U+0001", in: "a\x1b\x01[8mb", want: true},
		{name: "C1 CSI and LF", in: "a\u009b\n8mb", want: true},
		{name: "ESC and DEL", in: "a\x1b[\x7fb", want: true},
		{name: "runes far apart", in: "\x01" + strings.Repeat("a", 100) + "\x1b", want: true},
		// U+009D starts only an OSC, which ansiSeq and ansiSeqC0 read the
		// same way.
		{name: "C1 OSC and U+0001", in: "a\u009d\x01b", want: false},
		// CAN and SUB cancel a CSI and ESC starts a new one, so they are not
		// in csiC0.
		{name: "ESC and CAN only", in: "a\x1b\x18[8mb", want: false},
		{name: "ESC and SUB only", in: "a\x1b\x1a[8mb", want: false},
		{name: "U+0001 alone", in: "a\x01b", want: false},
		{name: "ESC alone", in: "a\x1b[8mb", want: false},
		{name: "plain ASCII", in: "Ignore all", want: false},
		{name: "empty", in: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasSeqC0(tt.in); got != tt.want {
				t.Errorf("hasSeqC0(%+q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsInvisibleFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    rune
		want bool
	}{
		{name: "ZWSP", r: '\u200b', want: true},
		{name: "RLO", r: '\u202e', want: true},
		{name: "VS16", r: '\ufe0f', want: true},
		{name: "U+0001 is a control rune", r: '\x01', want: false},
		{name: "ESC is a control rune", r: '\x1b', want: false},
		{name: "C1 CSI is a control rune", r: '\u009b', want: false},
		{name: "Arabic number sign is not invisible", r: '\u0600', want: false},
		{name: "letter", r: 'a', want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isInvisibleFormat(tt.r); got != tt.want {
				t.Errorf("isInvisibleFormat(%U) = %v, want %v", tt.r, got, tt.want)
			}
		})
	}
}

// TestRegexForms checks the forms that the regex matchers read: the forms of
// matchForms, and their folds when a form is not only ASCII.
func TestRegexForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "plain ASCII is one form", in: "Ignore previous", want: []string{"Ignore previous"}},
		{name: "empty", in: "", want: []string{""}},
		// The forms of matchForms are ASCII, so they are not folded.
		{name: "ASCII with control rune", in: "Ig\x01nore", want: []string{"Ignore", "Ig nore"}},
		{name: "fullwidth letter", in: "\uff29gnore", want: []string{"\uff29gnore", "Ignore"}},
		{name: "mathematical bold letter", in: "\U0001D408gnore", want: []string{"\U0001D408gnore", "Ignore"}},
		{name: "overlay mark", in: "Ig\u0336nore", want: []string{"Ig\u0336nore", "Ignore"}},
		{
			name: "invisible rune and fullwidth letter",
			in:   "\uff29g\u200bnore",
			want: []string{"\uff29gnore", "\uff29g nore", "Ignore", "Ig nore"},
		},
		// Documented limit: homoglyphs from other scripts are not folded.
		{name: "Cyrillic homoglyph not folded", in: "\u0406gnore", want: []string{"\u0406gnore"}},
		// The ZWSP is past the MaxMatchInputBytes cut, so the two forms of
		// matchForms are equal, and appendNew keeps one.
		{
			name: "equal forms kept once",
			in:   strings.Repeat("a", MaxMatchInputBytes) + "\u200b",
			want: []string{strings.Repeat("a", MaxMatchInputBytes)},
		},
		// The fold does not change the text, so it is not added.
		{name: "Hangul syllable not folded again", in: "\ud55c", want: []string{"\ud55c"}},
		// The forms 1 to 5 and 7 of matchForms and their six folds. The
		// sixth form equals the first, so it is kept once.
		{
			name: "no C0 in a CSI",
			in:   noC0CSIText,
			want: []string{
				"b c\ufb03", " b  c\ufb03", "b  c\ufb03", " b c\ufb03", "b Ic\ufb03", " b  Ic\ufb03",
				"b cffi", " b  cffi", "b  cffi", " b cffi", "b Icffi", " b  Icffi",
			},
		},
		// The most forms: the seven of matchForms and their seven folds.
		{
			name: "all forms",
			in:   allFormsText,
			want: []string{
				"b c\ufb03[8m", " b  c\ufb03 [8m", "b  c\ufb03 [8m", " b c\ufb03 ", "b Ic\ufb03", "b c\ufb03 ", " b  Ic\ufb03",
				"b cffi[8m", " b  cffi [8m", "b  cffi [8m", " b cffi ", "b Icffi", "b cffi ", " b  Icffi",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := regexForms(tt.in); !slices.Equal(got, tt.want) {
				t.Errorf("regexForms(%+q) = %+q, want %+q", tt.in, got, tt.want)
			}
		})
	}
}
