package termsafe_test

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// Unsafe characters are written as Go escape sequences on purpose. A raw bidi,
// control or blank character in the source file would be hard to see, and
// linters flag it.

func TestQuoteUnchanged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
	}{
		{name: "plain ASCII", in: "my-server_1.0"},
		{name: "empty", in: ""},
		{name: "ASCII spaces", in: "a b  c "},
		{name: "accented letter", in: "caf\u00e9"},
		{name: "Japanese path", in: "/tmp/\u30d7\u30ed\u30b8\u30a7\u30af\u30c8"},
		{name: "command line", in: "npx -y @scope/pkg"},
		{name: "emoji", in: "rocket \U0001F680"},
		{name: "quote and backslash", in: "a\"b\\c"},
		{name: "quote at the end", in: "a\""},
		{name: "Windows path", in: `C:\Users\me\.cursor\mcp.json`},
		{name: "backslash first", in: `\\server\share`},
		{name: "precomposed letter", in: "\u00e9t\u00e9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := termsafe.Quote(tt.in)
			if got != tt.in {
				t.Errorf("Quote(%q) = %q, want it unchanged", tt.in, got)
			}
			assertSafe(t, tt.in, got)
		})
	}
}

// TestQuoteMatchesStrconv checks the unsafe runes that strconv.Quote already
// escapes, and a double quote at the start of the text. For a text with no
// blank rune (see TestQuoteBlankRunes), Quote gives the same result as
// strconv.Quote.
func TestQuoteMatchesStrconv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		class string
		name  string
		in    string
	}{
		{class: "C0 control", name: "tab", in: "a\tb"},
		{class: "C0 control", name: "newline", in: "a\nb"},
		{class: "C0 control", name: "carriage return", in: "a\rb"},
		{class: "C0 control", name: "NUL", in: "a\x00b"},
		{class: "C0 control", name: "ANSI escape sequence", in: "\x1b[31mred"},
		{class: "C0 control", name: "OSC hyperlink", in: "\x1b]8;;http://x\x07link"},
		{class: "C0 control", name: "DEL", in: "a\x7fb"},
		{class: "C1 control", name: "CSI", in: "\u009b"},
		{class: "C1 control", name: "NEL", in: "a\u0085b"},
		{class: "Cf", name: "bidi override", in: "\u202e"},
		{class: "Cf", name: "bidi override inside text", in: "evil\u202egnp.exe"},
		{class: "Cf", name: "bidi isolate", in: "a\u2066b\u2069"},
		{class: "Cf", name: "left-to-right mark", in: "a\u200eb"},
		{class: "Cf", name: "zero width space", in: "a\u200bb"},
		{class: "Cf", name: "zero width joiner", in: "a\u200db"},
		{class: "Cf", name: "byte order mark", in: "\ufeffa"},
		{class: "Cf", name: "tag character", in: "a\U000e0041b"},
		{class: "Zs", name: "no-break space", in: "a\u00a0b"},
		{class: "Zs", name: "ideographic space", in: "a\u3000b"},
		{class: "Zl", name: "line separator", in: "a\u2028b"},
		{class: "Zp", name: "paragraph separator", in: "a\u2029b"},
		{class: "unassigned", name: "unassigned code point", in: "a\U000e0080b"},
		{class: "invalid UTF-8", name: "invalid byte", in: "a\xffb"},
		{class: "invalid UTF-8", name: "truncated sequence", in: "a\xe3\x81"},
		{class: "invalid UTF-8", name: "mixed escapes", in: "\x1b[31m\"x\"\\\xff"},
		// A text that starts with a double quote is quoted, so a plain text
		// can never look like a quoted one.
		{class: "leading quote", name: "quote only", in: `"`},
		{class: "leading quote", name: "looks quoted", in: `"name"`},
		{class: "leading quote", name: "looks quoted with an escape", in: `"a\x1bb"`},
		{class: "leading quote", name: "looks quoted and cut", in: `"abc"...`},
		{class: "leading quote", name: "quote and backslash", in: `"C:\x"`},
	}
	for _, tt := range tests {
		t.Run(tt.class+"/"+tt.name, func(t *testing.T) {
			t.Parallel()
			got := termsafe.Quote(tt.in)
			if want := strconv.Quote(tt.in); got != want {
				t.Errorf("Quote(%q) = %q, want %q", tt.in, got, want)
			}
			assertSafe(t, tt.in, got)
		})
	}
}

// TestQuoteBlankRunes checks the runes that strconv.Quote keeps as they are
// but that show as nothing or change the rune before them. Quote quotes the
// text and writes each such rune as \uXXXX or \UXXXXXXXX.
func TestQuoteBlankRunes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		class string
		name  string
		in    string
		want  string
	}{
		{class: "Hangul filler", name: "U+115F", in: "a\u115fz", want: `"a\u115fz"`},
		{class: "Hangul filler", name: "U+1160", in: "a\u1160z", want: `"a\u1160z"`},
		{class: "Hangul filler", name: "U+3164", in: "a\u3164z", want: `"a\u3164z"`},
		{class: "Hangul filler", name: "U+FFA0", in: "a\uffa0z", want: `"a\uffa0z"`},
		{class: "braille", name: "blank pattern U+2800", in: "x\u2800", want: `"x\u2800"`},
		{class: "Mn", name: "combining acute accent", in: "e\u0301", want: `"e\u0301"`},
		{class: "Mn", name: "combining grapheme joiner", in: "a\u034fz", want: `"a\u034fz"`},
		{class: "Mn", name: "variation selector 16", in: "a\ufe0f", want: `"a\ufe0f"`},
		{class: "Mn", name: "variation selector supplement", in: "a\U000e0100", want: `"a\U000e0100"`},
		{class: "Me", name: "enclosing circle", in: "1\u20dd", want: `"1\u20dd"`},
		{class: "mixed", name: "blank rune and control character", in: "\u3164\x1b", want: `"\u3164\x1b"`},
		{class: "mixed", name: "blank rune and invalid UTF-8", in: "\u3164\xff", want: `"\u3164\xff"`},
		{
			// The blank runes are escaped, and the other parts are escaped as
			// strconv.Quote does it.
			class: "mixed",
			name:  "blank runes with other escapes",
			in:    "\x1b\u3164\"\xff\u3164\u00e9",
			want:  `"\x1b\u3164\"\xff\u3164` + "\u00e9" + `"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.class+"/"+tt.name, func(t *testing.T) {
			t.Parallel()
			got := termsafe.Quote(tt.in)
			if got != tt.want {
				t.Errorf("Quote(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if back, err := strconv.Unquote(got); err != nil || back != tt.in {
				t.Errorf("Unquote(Quote(%q)) = %q, %v, want the input", tt.in, back, err)
			}
			assertSafe(t, tt.in, got)
		})
	}
}

func TestQuoteCut(t *testing.T) {
	t.Parallel()

	const m = termsafe.CutMarker
	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{name: "empty", in: "", n: 3, want: ""},
		{name: "short plain text is kept", in: "ab", n: 3, want: "ab"},
		{name: "exactly n runes are kept", in: "abc", n: 3, want: "abc"},
		{name: "one rune over n is cut", in: "abcd", n: 3, want: "abc" + m},
		{name: "counts runes not bytes", in: "\u00e9\u00e9\u00e9\u00e9", n: 3, want: "\u00e9\u00e9\u00e9" + m},
		{name: "short unsafe text is quoted, not cut", in: "a\x1bb", n: 3, want: `"a\x1bb"`},
		{
			// The marker comes after the closing quote, and the cut never
			// splits an escape.
			name: "cut text with a control character",
			in:   "a\x1bbcd",
			n:    3,
			want: `"a\x1bb"` + m,
		},
		{name: "cut blank runes", in: "\u3164\u3164\u3164", n: 2, want: `"\u3164\u3164"` + m},
		{name: "invalid byte counts as one rune", in: "\xff\xff\xff\xff", n: 3, want: `"\xff\xff\xff"` + m},
		{
			// The part after the cut is not shown, so it does not make the
			// text quoted.
			name: "unsafe rune after the cut",
			in:   "abc\x1b",
			n:    3,
			want: "abc" + m,
		},
		{
			// Content can end with "..." too: the marker is added once, after
			// it.
			name: "text that ends with the marker",
			in:   "ab...x",
			n:    5,
			want: "ab..." + m,
		},
		{name: "n is zero", in: "a", n: 0, want: m},
		{name: "leading quote is quoted", in: `"ab"`, n: 5, want: `"\"ab\""`},
		{name: "cut text with a leading quote is quoted", in: `"abcdef"`, n: 3, want: `"\"ab"` + m},
		{
			// The quote after the cut is not shown, so it does not make the
			// text quoted.
			name: "quote after the cut",
			in:   `abc"`,
			n:    3,
			want: "abc" + m,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := termsafe.QuoteCut(tt.in, tt.n)
			if got != tt.want {
				t.Errorf("QuoteCut(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
			}
			assertSafe(t, tt.in, got)
		})
	}
}

func TestCut(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		n       int
		want    string
		wantCut bool
	}{
		{name: "empty", in: "", n: 3, want: "", wantCut: false},
		{name: "shorter than n", in: "ab", n: 3, want: "ab", wantCut: false},
		{name: "exactly n", in: "abc", n: 3, want: "abc", wantCut: false},
		{name: "one over n", in: "abcd", n: 3, want: "abc", wantCut: true},
		{name: "n is zero", in: "a", n: 0, want: "", wantCut: true},
		{name: "n is zero and empty text", in: "", n: 0, want: "", wantCut: false},
		{name: "counts runes not bytes", in: "\u00e9\u00e9\u00e9\u00e9", n: 3, want: "\u00e9\u00e9\u00e9", wantCut: true},
		{name: "cuts at a rune boundary", in: "a\U0001F680b", n: 2, want: "a\U0001F680", wantCut: true},
		{name: "invalid byte counts as one rune", in: "\xff\xff\xff\xff", n: 3, want: "\xff\xff\xff", wantCut: true},
		{name: "valid and invalid runes", in: "\u00e9\xffa\u00e9", n: 3, want: "\u00e9\xffa", wantCut: true},
		{name: "truncated sequence counts per byte", in: "\xe3\x81a", n: 2, want: "\xe3\x81", wantCut: true},
		{name: "adds no marker", in: "abc\x1b", n: 4, want: "abc\x1b", wantCut: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, cut := termsafe.Cut(tt.in, tt.n)
			if got != tt.want || cut != tt.wantCut {
				t.Errorf("Cut(%q, %d) = %q, %v, want %q, %v", tt.in, tt.n, got, cut, tt.want, tt.wantCut)
			}
		})
	}
}

func TestQuoteIf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		in    string
		force bool
		want  string
	}{
		{name: "safe text, no force", in: "a b", force: false, want: "a b"},
		{name: "empty text, no force", in: "", force: false, want: ""},
		{name: "safe text, force", in: "a b", force: true, want: `"a b"`},
		{name: "empty text, force", in: "", force: true, want: `""`},
		{name: "inner quote and backslash, force", in: `a"b\c`, force: true, want: `"a\"b\\c"`},
		{name: "Windows path, force", in: `C:\x`, force: true, want: `"C:\\x"`},
		{name: "unsafe text, no force", in: "a\x1bb", force: false, want: `"a\x1bb"`},
		{name: "unsafe text, force", in: "a\x1bb", force: true, want: `"a\x1bb"`},
		{name: "blank rune, force", in: "a\u3164", force: true, want: `"a\u3164"`},
		{name: "leading quote, no force", in: `"a`, force: false, want: `"\"a"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := termsafe.QuoteIf(tt.in, tt.force)
			if got != tt.want {
				t.Errorf("QuoteIf(%q, %v) = %q, want %q", tt.in, tt.force, got, tt.want)
			}
			// QuoteIf with force false is Quote.
			if !tt.force {
				if q := termsafe.Quote(tt.in); got != q {
					t.Errorf("QuoteIf(%q, false) = %q, but Quote gives %q", tt.in, got, q)
				}
			}
			// A forced quote of a safe text is what strconv.Quote gives.
			if tt.force && termsafe.Quote(tt.in) == tt.in {
				if q := strconv.Quote(tt.in); got != q {
					t.Errorf("QuoteIf(%q, true) = %q, but strconv.Quote gives %q", tt.in, got, q)
				}
			}
			assertSafe(t, tt.in, got)
		})
	}
}

func TestCutMarkerIsASCII(t *testing.T) {
	t.Parallel()
	for i := range len(termsafe.CutMarker) {
		if c := termsafe.CutMarker[i]; c < 0x20 || c > 0x7e {
			t.Fatalf("CutMarker = %q has the byte 0x%02x, want printable ASCII only", termsafe.CutMarker, c)
		}
	}
}

// assertSafe checks the output rules that hold for every input.
func assertSafe(t *testing.T, in, out string) {
	t.Helper()
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("Quote(%q) = %q contains a raw ESC byte", in, out)
	}
	if strings.ContainsRune(out, '\u202e') {
		t.Errorf("Quote(%q) = %q contains a raw bidi override", in, out)
	}
	if !utf8.ValidString(out) {
		t.Errorf("Quote(%q) = %q is not valid UTF-8", in, out)
	}
}

func FuzzQuote(f *testing.F) {
	seeds := []string{
		"", "plain", "a b", "caf\u00e9", "a\tb", "a\nb", "\x1b[31mred", "\u009b", "\u0085",
		"\u202e", "\u200b", "\u00a0", "a\xffb", "a\xe3\x81", "a\x00b", "\"quoted\"", "\U0001F680",
		"e\u0301", "\u3164", "\u2800", "a\ufe0f", "\U000e0100\xff", `"`, `"a"`, `C:\x\y`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		// A forced quote always decodes back to the input and has no control
		// byte. For a safe input it is what strconv.Quote gives.
		forced := termsafe.QuoteIf(in, true)
		if back, err := strconv.Unquote(forced); err != nil || back != in {
			t.Fatalf("Unquote(QuoteIf(%q, true)) = %q, %v, want the input", in, back, err)
		}
		if strings.ContainsFunc(forced, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			t.Fatalf("QuoteIf(%q, true) = %q has a control byte", in, forced)
		}
		if termsafe.Quote(in) == in && forced != strconv.Quote(in) {
			t.Fatalf("QuoteIf(%q, true) = %q, want strconv.Quote %q for a safe input", in, forced, strconv.Quote(in))
		}

		out := termsafe.Quote(in)
		if !utf8.ValidString(out) {
			t.Fatalf("Quote(%q) = %q is not valid UTF-8", in, out)
		}
		for i := 0; i < len(out); i++ {
			if out[i] < 0x20 || out[i] == 0x7f {
				t.Fatalf("Quote(%q) = %q has control byte 0x%02x at %d", in, out, out[i], i)
			}
		}
		// No rune of the output may be one that Quote would escape: a quoted
		// output is all visible.
		if out != in && termsafe.Quote(out[1:len(out)-1]) != out[1:len(out)-1] {
			t.Fatalf("Quote(%q) = %q still holds a rune that needs an escape", in, out)
		}
		if out == in {
			// An unquoted output must never look like a quoted one, so the
			// output maps back to one input only.
			if strings.HasPrefix(out, `"`) {
				t.Fatalf("Quote(%q) = %q is unchanged but starts with a double quote", in, out)
			}
			return
		}
		// Changed output must be a quoted string that decodes back to the input.
		back, err := strconv.Unquote(out)
		if err != nil {
			t.Fatalf("Quote(%q) = %q is neither the input nor a quoted string: %v", in, out, err)
		}
		if back != in {
			t.Fatalf("Unquote(Quote(%q)) = %q, want the input", in, back)
		}
	})
}
