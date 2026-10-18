package report_test

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// Unsafe characters are written as Go escape sequences on purpose. A raw bidi
// or control character in the source file would be hard to see and linters flag it.

func TestEscapeUnchanged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
	}{
		{name: "plain ASCII", in: "my-server_1.0"},
		{name: "empty", in: ""},
		{name: "spaces", in: "a b  c "},
		{name: "accented letter", in: "caf\u00e9"},
		{name: "Japanese path", in: "/tmp/\u30d7\u30ed\u30b8\u30a7\u30af\u30c8"},
		{name: "command line", in: "npx -y @scope/pkg"},
		{name: "emoji", in: "rocket \U0001F680"},
		{name: "quote and backslash", in: "a\"b\\c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := report.Escape(tt.in)
			if got != tt.in {
				t.Errorf("Escape(%q) = %q, want it unchanged", tt.in, got)
			}
			assertSafe(t, tt.in, got)
		})
	}
}

func TestEscapeQuoted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
	}{
		{name: "tab", in: "a\tb"},
		{name: "newline", in: "a\nb"},
		{name: "carriage return", in: "a\rb"},
		{name: "ANSI escape sequence", in: "\x1b[31mred"},
		{name: "C1 control CSI", in: "\u009b"},
		{name: "C1 control NEL", in: "\u0085"},
		{name: "bidi override", in: "\u202e"},
		{name: "bidi override inside text", in: "evil\u202egnp.exe"},
		{name: "zero width space", in: "\u200b"},
		{name: "no-break space", in: "\u00a0"},
		{name: "invalid UTF-8 byte", in: "a\xffb"},
		{name: "truncated UTF-8 sequence", in: "a\xe3\x81"},
		{name: "NUL", in: "a\x00b"},
		{name: "DEL", in: "a\x7fb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := report.Escape(tt.in)
			want := strconv.Quote(tt.in)
			if got != want {
				t.Errorf("Escape(%q) = %q, want %q", tt.in, got, want)
			}
			assertSafe(t, tt.in, got)
		})
	}
}

// TestEscapeMatchesFileError checks that report.Escape and the unexported
// displayText in internal/discover (used by FileError.Error) stay the same rule.
// They are two copies, because discover must not import report.
func TestEscapeMatchesFileError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
	}{
		{name: "plain ASCII", in: "/home/u/.claude.json"},
		{name: "empty", in: ""},
		{name: "spaces", in: "my dir/a b.json"},
		{name: "accented letter", in: "caf\u00e9"},
		{name: "emoji", in: "rocket \U0001F680"},
		{name: "quote and backslash", in: "a\"b\\c"},
		{name: "tab", in: "a\tb"},
		{name: "newline", in: "a\nb"},
		{name: "ANSI escape sequence", in: "\x1b[31mred"},
		{name: "OSC hyperlink", in: "\x1b]8;;http://x\x07link"},
		{name: "C1 control CSI", in: "\u009b"},
		{name: "C1 control NEL", in: "\u0085"},
		{name: "bidi override", in: "evil\u202egnp.exe"},
		{name: "zero width space", in: "a\u200bb"},
		{name: "no-break space", in: "a\u00a0b"},
		{name: "invalid UTF-8", in: "a\xffb"},
		{name: "truncated UTF-8", in: "a\xe3\x81"},
		{name: "NUL", in: "a\x00b"},
		{name: "DEL", in: "a\x7fb"},
		{name: "combining mark", in: "e\u0301"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// With no Line, no Col and no Err, the message is "<path>: <reason>".
			got := (&discover.FileError{Path: tt.in, Reason: "x"}).Error()
			want := report.Escape(tt.in) + ": "
			if !strings.HasPrefix(got, want) {
				t.Errorf("FileError.Error() = %q, want the prefix %q", got, want)
			}
			// The server name goes through the same rule. An empty name is
			// left out of the message on purpose.
			if tt.in == "" {
				return
			}
			got = (&discover.FileError{Path: "p", Server: tt.in, Reason: "x"}).Error()
			want = "p: server " + report.Escape(tt.in) + ": "
			if !strings.HasPrefix(got, want) {
				t.Errorf("FileError.Error() with a server = %q, want the prefix %q", got, want)
			}
		})
	}
}

// assertSafe checks the output rules that hold for every input.
func assertSafe(t *testing.T, in, out string) {
	t.Helper()
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("Escape(%q) = %q contains a raw ESC byte", in, out)
	}
	if strings.ContainsRune(out, '\u202e') {
		t.Errorf("Escape(%q) = %q contains a raw bidi override", in, out)
	}
	if !utf8.ValidString(out) {
		t.Errorf("Escape(%q) = %q is not valid UTF-8", in, out)
	}
}

func FuzzEscape(f *testing.F) {
	seeds := []string{
		"", "plain", "a b", "caf\u00e9", "a\tb", "a\nb", "\x1b[31mred", "\u009b", "\u0085",
		"\u202e", "\u200b", "\u00a0", "a\xffb", "a\xe3\x81", "a\x00b", "\"quoted\"", "\U0001F680",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out := report.Escape(in)
		if !utf8.ValidString(out) {
			t.Fatalf("Escape(%q) = %q is not valid UTF-8", in, out)
		}
		for i := 0; i < len(out); i++ {
			if out[i] < 0x20 {
				t.Fatalf("Escape(%q) = %q has control byte 0x%02x at %d", in, out, out[i], i)
			}
		}
		if out == in {
			return
		}
		// Changed output must be a quoted string that decodes back to the input.
		back, err := strconv.Unquote(out)
		if err != nil {
			t.Fatalf("Escape(%q) = %q is neither the input nor a quoted string: %v", in, out, err)
		}
		if back != in {
			t.Fatalf("Unquote(Escape(%q)) = %q, want the input", in, back)
		}
	})
}
