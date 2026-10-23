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
		{name: "control runes to space", in: "a\x00b\x1fc\x7fd\u0090e", want: "a b c d e"},
		{name: "ANSI CSI to space", in: "a\x1b[8mIgnore\x1b[0m b", want: "a Ignore  b"},
		{name: "C1 CSI to space", in: "a\u009b1;31mb", want: "a b"},
		{name: "JSON-escaped CSI to space", in: "a\\u001b[8mb", want: "a b"},
		{name: "ANSI OSC to space", in: "a\x1b]0;title\x07b", want: "a b"},
		{name: "OSC with no end keeps the text", in: "a\x1b]0;title b", want: "a ]0;title b"},
		{name: "ASCII white space kept", in: "a\tb\nc\rd\fe", want: "a\tb\nc\rd\fe"},
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

// TestFoldMarks checks the marks that foldMarks drops and the ones it keeps.
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

// TestMatchForms checks that a text gets the spaced second form only when it
// holds an invisible rune.
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
