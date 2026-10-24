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
		// The control runes are dropped only after the CSI step, so CAN, SUB
		// or U+0001 cannot make ESC [ I, a CSI that hides the "I". The ESC is
		// then dropped too.
		{name: "CAN inside CSI keeps keyword", in: "\x1b[\x18Ignore", want: "[Ignore"},
		{name: "SUB inside CSI keeps keyword", in: "\x1b[\x1aIgnore", want: "[Ignore"},
		{name: "control rune inside CSI keeps keyword", in: "\x1b[\x01Ignore", want: "[Ignore"},
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
var controlPadding = strings.Repeat("\x01", 33000)

// TestMatchForms checks that a text gets the spaced second form only when it
// holds an invisible rune, and the third form only when one of them is a
// control rune.
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
		// The third form drops the ZWSP and makes each control rune a space.
		{name: "ZWSP inside a word and control rune between words", in: "Ig\u200bnore\x01all", want: []string{"Ignoreall", "Ig nore all", "Ignore all"}},
		{name: "one space for each run of control runes in the third form", in: "a\x01\x02b\u200bc", want: []string{"abc", "a b c", "a bc"}},
		// A ZWSP inside a run of control runes does not end the run.
		{name: "ZWSP inside a run of control runes", in: "a\x01\u200b\x01b\u200bc", want: []string{"abc", "a b c", "a bc"}},
		{name: "control rune inside CSI", in: "\x1b[\x01Ignore", want: []string{"[Ignore", " [ Ignore"}},
		// The runes that start, end or cancel an ANSI escape sequence are
		// invisible control runes too, so they are dropped inside a word.
		{name: "BEL inside a word", in: "Ig\x07nore", want: []string{"Ignore", "Ig nore"}},
		{name: "CAN inside a word", in: "Ig\x18nore", want: []string{"Ignore", "Ig nore"}},
		{name: "SUB inside a word", in: "Ig\x1anore", want: []string{"Ignore", "Ig nore"}},
		{name: "ESC inside a word", in: "Ig\x1bnore", want: []string{"Ignore", "Ig nore"}},
		{name: "C1 ST inside a word", in: "Ig\u009cnore", want: []string{"Ignore", "Ig nore"}},
		// One space for the whole run of padding, so the payload stays in
		// the MaxMatchInputBytes window of the third form.
		{
			name: "control rune padding is one space in the third form",
			in:   controlPadding + "Ig\u200bnore\x01all\x01previous",
			want: []string{"Ignoreallprevious", " Ig nore all previous", " Ignore all previous"},
		},
		{name: "white space only is one form", in: "a\tb\nc\rd\fe\vf\u0085g", want: []string{"a\tb\nc\rd\fe f g"}},
		{name: "ANSI CSI is one form", in: "\x1b[8mIgnore", want: []string{" Ignore"}},
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeInvisible(in, tt.mode); got != tt.want {
				t.Errorf("normalizeInvisible(%q, %s) = %q, want %q", in, tt.name, got, tt.want)
			}
		})
	}
	if got := normalizeForMatch(in); got != normalizeInvisible(in, dropInvisible) {
		t.Errorf("normalizeForMatch(%q) = %q, want the dropInvisible form", in, got)
	}
	want := []string{"Ignoreallprevious", "Ig nore all previous", "Ignore allprevious"}
	if got := matchForms(in); !slices.Equal(got, want) {
		t.Errorf("matchForms(%q) = %q, want %q", in, got, want)
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
		// The most forms: the three of matchForms and their three folds.
		{
			name: "six forms",
			in:   "\u200bb\x01\ufb03",
			want: []string{"b\ufb03", " b \ufb03", "b \ufb03", "bffi", " b ffi", "b ffi"},
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
