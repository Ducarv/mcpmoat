package report_test

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// noDiffNote is the fixed line under the header of a tool with no diff text.
const noDiffNote = "  (no diff text available)"

// errWriter fails every write with err.
type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

// failAfterWriter accepts the first ok writes and then fails with err. It
// counts the writes it has seen.
type failAfterWriter struct {
	ok     int
	err    error
	writes int
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes > w.ok {
		return 0, w.err
	}
	return len(p), nil
}

// writeDiffs returns the text that report.WriteDiffs writes for diffs. It
// fails the test if WriteDiffs returns an error.
func writeDiffs(t *testing.T, diffs ...report.ToolDiff) string {
	t.Helper()
	var sb strings.Builder
	if err := report.WriteDiffs(&sb, diffs); err != nil {
		t.Fatalf("WriteDiffs() error = %v, want nil", err)
	}
	return sb.String()
}

// assertTerminalSafe fails the test if out holds a byte below 0x20 other than
// "\n", a DEL byte, a raw bidi override, a raw zero-width space or invalid
// UTF-8.
func assertTerminalSafe(t *testing.T, out string) {
	t.Helper()
	for i := 0; i < len(out); i++ {
		if c := out[i]; (c < 0x20 && c != '\n') || c == 0x7f {
			t.Errorf("output has raw control byte 0x%02x at %d: %q", c, i, out)
		}
	}
	for _, r := range []rune{'\u202e', '\u200b'} {
		if strings.ContainsRune(out, r) {
			t.Errorf("output has raw %U: %q", r, out)
		}
	}
	if !utf8.ValidString(out) {
		t.Errorf("output is not valid UTF-8: %q", out)
	}
}

func TestWriteDiffsExact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		diffs []report.ToolDiff
		want  string
	}{
		{name: "nil diffs", diffs: nil, want: ""},
		{name: "empty diffs", diffs: []report.ToolDiff{}, want: ""},
		{
			name:  "empty Diff writes the header and the note",
			diffs: []report.ToolDiff{{Server: "fs", Tool: "read", Diff: ""}},
			want:  "\nChanged tool read on server fs:\n  (no diff text available)\n",
		},
		{
			name:  "Diff of only a newline writes the note",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "\n"}},
			want:  "\nChanged tool t on server s:\n  (no diff text available)\n",
		},
		{
			name:  "Diff of only whitespace and newlines writes the note",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: " \n\t\r\n\n"}},
			want:  "\nChanged tool t on server s:\n  (no diff text available)\n",
		},
		{
			name: "clean unified diff keeps its shape",
			diffs: []report.ToolDiff{{
				Server: "fs", Tool: "read",
				Diff: "--- pinned\n+++ current\n@@ -1,2 +1,2 @@\n context\n-old text\n+new text\n",
			}},
			want: "\nChanged tool read on server fs:\n" +
				"--- pinned\n+++ current\n@@ -1,2 +1,2 @@\n context\n-old text\n+new text\n",
		},
		{
			name:  "final newline adds no extra line",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "+a\n"}},
			want:  "\nChanged tool t on server s:\n+a\n",
		},
		{
			name:  "no final newline still ends the line",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "+a"}},
			want:  "\nChanged tool t on server s:\n+a\n",
		},
		{
			// Only one "\n" is trimmed: a second one is an empty line.
			name:  "double final newline keeps one empty line",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "+a\n\n"}},
			want:  "\nChanged tool t on server s:\n+a\n\n",
		},
		{
			name:  "empty line in the middle stays empty",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "+a\n\n-b\n"}},
			want:  "\nChanged tool t on server s:\n+a\n\n-b\n",
		},
		{
			name:  "empty names show as dash",
			diffs: []report.ToolDiff{{Server: "", Tool: "", Diff: "+a\n"}},
			want:  "\nChanged tool - on server -:\n+a\n",
		},
		{
			name:  "literal dash name is quoted",
			diffs: []report.ToolDiff{{Server: "-", Tool: "-", Diff: ""}},
			want:  "\nChanged tool \"-\" on server \"-\":\n  (no diff text available)\n",
		},
		{
			name:  "server name with a space is quoted",
			diffs: []report.ToolDiff{{Server: "my server", Tool: "read file", Diff: "+a\n"}},
			want:  "\nChanged tool \"read file\" on server \"my server\":\n+a\n",
		},
		{
			name:  "hostile names are escaped",
			diffs: []report.ToolDiff{{Server: "evil\x1b[2J", Tool: "t\x1b]0;x\a", Diff: ""}},
			want:  "\nChanged tool \"t\\x1b]0;x\\a\" on server \"evil\\x1b[2J\":\n  (no diff text available)\n",
		},
		{
			name:  "ESC in a plus line is escaped",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "+a\x1b[31mred\x1b[0m\n"}},
			want:  "\nChanged tool t on server s:\n+\"a\\x1b[31mred\\x1b[0m\"\n",
		},
		{
			name:  "control characters in a minus line are escaped",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "-a\x00b\tc\rd\x7fe\n"}},
			want:  "\nChanged tool t on server s:\n-\"a\\x00b\\tc\\rd\\x7fe\"\n",
		},
		{
			name:  "control characters in a context line are escaped",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: " a\x1bb\n"}},
			want:  "\nChanged tool t on server s:\n \"a\\x1bb\"\n",
		},
		{
			name:  "ESC in a hunk header is escaped",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "@@ -1 +1 @@\x1b[2J\n"}},
			want:  "\nChanged tool t on server s:\n@@\" -1 +1 @@\\x1b[2J\"\n",
		},
		{
			name:  "ESC in a file header is escaped",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "--- a\x1bb\n+++ c\x1bd\n"}},
			want:  "\nChanged tool t on server s:\n---\" a\\x1bb\"\n+++\" c\\x1bd\"\n",
		},
		{
			name:  "bidi override is shown as an escape",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "+abc\u202edef\n"}},
			want:  "\nChanged tool t on server s:\n+\"abc\\u202edef\"\n",
		},
		{
			name:  "zero-width space is shown as an escape",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "-ab\u200bcd\n"}},
			want:  "\nChanged tool t on server s:\n-\"ab\\u200bcd\"\n",
		},
		{
			name:  "invalid UTF-8 is escaped",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "+a\xff\xfeb\n"}},
			want:  "\nChanged tool t on server s:\n+\"a\\xff\\xfeb\"\n",
		},
		{
			name:  "marker line without prefix is escaped as a whole",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "\\ No newline at end of file\n"}},
			want:  "\nChanged tool t on server s:\n\\ No newline at end of file\n",
		},
		{
			name:  "hostile marker line is quoted",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "\\ x\x1b[2J\n"}},
			want:  "\nChanged tool t on server s:\n\"\\\\ x\\x1b[2J\"\n",
		},
		{
			name:  "unknown prefix line is not trusted",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "x\x1b[2J\n"}},
			want:  "\nChanged tool t on server s:\n\"x\\x1b[2J\"\n",
		},
		{
			// A bare "\r" is not a line end: it is escaped.
			name:  "carriage return does not split a line",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "+a\rb\n"}},
			want:  "\nChanged tool t on server s:\n+\"a\\rb\"\n",
		},
		{
			// The text after the prefix starts with a quote: it is quoted so it
			// cannot look like an escaped text.
			name:  "text that starts with a double quote is quoted",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "+\"hi\"\n"}},
			want:  "\nChanged tool t on server s:\n+\"\\\"hi\\\"\"\n",
		},
		{
			name:  "bare prefix lines",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "+\n-\n \n@@\n---\n+++\n"}},
			want:  "\nChanged tool t on server s:\n+\n-\n \n@@\n---\n+++\n",
		},
		{
			// "---" must win over "-", "+++" over "+": the rest is " x", with
			// no stray dashes inside the quotes.
			name:  "longer prefix wins over a single character",
			diffs: []report.ToolDiff{{Server: "s", Tool: "t", Diff: "--- a\x1b\n+++ b\x1b\n-- c\x1b\n"}},
			want: "\nChanged tool t on server s:\n" +
				"---\" a\\x1b\"\n+++\" b\\x1b\"\n-\"- c\\x1b\"\n",
		},
		{
			name:  "new tool gets the New tool header",
			diffs: []report.ToolDiff{{Server: "fs", Tool: "write", New: true, Diff: "+++ current\n+a\n"}},
			want:  "\nNew tool write on server fs:\n+++ current\n+a\n",
		},
		{
			name:  "new tool with empty Diff writes the note",
			diffs: []report.ToolDiff{{Server: "fs", Tool: "write", New: true}},
			want:  "\nNew tool write on server fs:\n  (no diff text available)\n",
		},
		{
			name:  "hostile names are escaped in the New header",
			diffs: []report.ToolDiff{{Server: "evil\x1b[2J", Tool: "t\x1b]0;x\a", New: true, Diff: "+a\n"}},
			want:  "\nNew tool \"t\\x1b]0;x\\a\" on server \"evil\\x1b[2J\":\n+a\n",
		},
		{
			name: "new and changed diffs keep their own headers",
			diffs: []report.ToolDiff{
				{Server: "a", Tool: "t1", Diff: "+x\n"},
				{Server: "a", Tool: "t2", New: true, Diff: "+y\n"},
			},
			want: "\nChanged tool t1 on server a:\n+x\n" +
				"\nNew tool t2 on server a:\n+y\n",
		},
		{
			name:  "not verified tool gets its own header",
			diffs: []report.ToolDiff{{Server: "fs", Tool: "read", Unverified: true, Diff: "+++ current\n+a\n"}},
			want:  "\nNot verified tool read on server fs (current text):\n+++ current\n+a\n",
		},
		{
			name:  "not verified tool with hostile names",
			diffs: []report.ToolDiff{{Server: "evil\x1b[2J", Tool: "t\x1b]0;x\a", Unverified: true, Diff: "+a\n"}},
			want:  "\nNot verified tool \"t\\x1b]0;x\\a\" on server \"evil\\x1b[2J\" (current text):\n+a\n",
		},
		{
			name: "two diffs in order, each with a blank line before",
			diffs: []report.ToolDiff{
				{Server: "a", Tool: "t1", Diff: "+x\n"},
				{Server: "b", Tool: "t2", Diff: "-y\n"},
			},
			want: "\nChanged tool t1 on server a:\n+x\n" +
				"\nChanged tool t2 on server b:\n-y\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := writeDiffs(t, tt.diffs...)
			if got != tt.want {
				t.Errorf("WriteDiffs() =\n%q\nwant\n%q", got, tt.want)
			}
			assertTerminalSafe(t, got)
		})
	}
}

func TestWriteDiffsNeverWritesRawHostileBytes(t *testing.T) {
	t.Parallel()

	hostile := "a\x1b[31m\x1b]0;title\a\u202e\u200b\u2066\ufeff\u0085\x00\x7f\xff\r\tz"
	tests := []struct {
		name string
		diff report.ToolDiff
	}{
		{name: "plus", diff: report.ToolDiff{Server: "s", Tool: "t", Diff: "+" + hostile + "\n"}},
		{name: "minus", diff: report.ToolDiff{Server: "s", Tool: "t", Diff: "-" + hostile + "\n"}},
		{name: "context", diff: report.ToolDiff{Server: "s", Tool: "t", Diff: " " + hostile + "\n"}},
		{name: "hunk", diff: report.ToolDiff{Server: "s", Tool: "t", Diff: "@@" + hostile + "\n"}},
		{name: "old file", diff: report.ToolDiff{Server: "s", Tool: "t", Diff: "---" + hostile + "\n"}},
		{name: "new file", diff: report.ToolDiff{Server: "s", Tool: "t", Diff: "+++" + hostile + "\n"}},
		{name: "marker", diff: report.ToolDiff{Server: "s", Tool: "t", Diff: "\\" + hostile + "\n"}},
		{name: "no prefix", diff: report.ToolDiff{Server: "s", Tool: "t", Diff: hostile + "\n"}},
		{name: "server", diff: report.ToolDiff{Server: hostile, Tool: "t", Diff: "+a\n"}},
		{name: "tool", diff: report.ToolDiff{Server: "s", Tool: hostile, Diff: "+a\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := writeDiffs(t, tt.diff)
			assertTerminalSafe(t, out)
			// The output is the header, then exactly one line for the one
			// diff line: a hostile "\r" or "\n" must not add lines.
			if n := strings.Count(out, "\n"); n != 3 {
				t.Errorf("output has %d newlines, want 3: %q", n, out)
			}
			for _, esc := range []string{`\x1b`, `\u202e`, `\u200b`} {
				if !strings.Contains(out, esc) {
					t.Errorf("output lacks visible escape %s: %q", esc, out)
				}
			}
		})
	}
}

func TestWriteDiffsCutsLongLine(t *testing.T) {
	t.Parallel()

	const limit = 2000 // maxDiffLineRunes
	tests := []struct {
		name    string
		line    string // text after the prefix
		prefix  string
		wantCut bool
		wantRun int // runes of the rest, without the cut marker
	}{
		{name: "exactly at the limit is not cut", prefix: "+", line: strings.Repeat("a", limit)},
		{name: "one over the limit is cut", prefix: "+", line: strings.Repeat("a", limit+1), wantCut: true},
		{name: "very long minus line is cut", prefix: "-", line: strings.Repeat("b", 100_000), wantCut: true},
		{name: "long line without prefix is cut", prefix: "", line: strings.Repeat("c", limit+5), wantCut: true},
		{name: "multi-byte runes count as runes", prefix: "+", line: strings.Repeat("é", limit), wantCut: false},
		{name: "multi-byte runes over the limit", prefix: "+", line: strings.Repeat("é", limit+1), wantCut: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := writeDiffs(t, report.ToolDiff{Server: "s", Tool: "t", Diff: tt.prefix + tt.line + "\n"})
			body := strings.TrimPrefix(out, "\nChanged tool t on server s:\n")
			body = strings.TrimSuffix(body, "\n")
			if strings.Contains(body, "\n") {
				t.Fatalf("diff line was split into several lines")
			}
			if got := strings.HasSuffix(body, termsafe.CutMarker); got != tt.wantCut {
				t.Errorf("has cut marker = %v, want %v", got, tt.wantCut)
			}
			text := strings.TrimPrefix(body, tt.prefix)
			if tt.wantCut {
				text = strings.TrimSuffix(text, termsafe.CutMarker)
			}
			// A line with no known prefix starts with the text itself. The
			// prefix of a known line is written raw and is not counted.
			if n := utf8.RuneCountInString(text); n != min(limit, utf8.RuneCountInString(tt.line)) {
				t.Errorf("shown text has %d runes, want %d", n, min(limit, utf8.RuneCountInString(tt.line)))
			}
		})
	}

	t.Run("cut is made before the escape", func(t *testing.T) {
		t.Parallel()
		// 1999 safe runes, then an ESC (rune 2000), then more text. The ESC is
		// inside the limit, so it shows as an escape and the rest is cut.
		line := strings.Repeat("a", limit-1) + "\x1b" + "tail"
		out := writeDiffs(t, report.ToolDiff{Server: "s", Tool: "t", Diff: "+" + line + "\n"})
		assertTerminalSafe(t, out)
		if !strings.Contains(out, `a\x1b"`+termsafe.CutMarker+"\n") {
			t.Errorf("output does not end with the escape and the cut marker: %q", out[len(out)-20:])
		}
		if strings.Contains(out, "tail") {
			t.Error("text after the cut is shown")
		}
	})

	t.Run("cut line does not hide the next line", func(t *testing.T) {
		t.Parallel()
		out := writeDiffs(t, report.ToolDiff{
			Server: "s", Tool: "t",
			Diff: "+" + strings.Repeat("a", limit+10) + "\n-next\n",
		})
		if !strings.HasSuffix(out, termsafe.CutMarker+"\n-next\n") {
			t.Errorf("next line is missing after a cut line: %q", out[len(out)-30:])
		}
	})
}

func TestWriteDiffsCutsLongNames(t *testing.T) {
	t.Parallel()

	const limit = 80 // maxShortCellRunes
	long := strings.Repeat("n", limit+20)
	out := writeDiffs(t, report.ToolDiff{Server: long, Tool: long})
	header, note, ok := strings.Cut(strings.TrimPrefix(out, "\n"), "\n")
	if !ok || note != noDiffNote+"\n" {
		t.Errorf("note = %q, want %q", note, noDiffNote+"\n")
	}
	if strings.Contains(header, long) {
		t.Errorf("long name is not cut: %q", header)
	}
	want := "Changed tool " + strings.Repeat("n", limit) + termsafe.CutMarker +
		" on server " + strings.Repeat("n", limit) + termsafe.CutMarker + ":"
	if header != want {
		t.Errorf("header = %q, want %q", header, want)
	}
}

func TestWriteDiffsWriteError(t *testing.T) {
	t.Parallel()

	errBoom := errors.New("boom")
	diffs := []report.ToolDiff{
		{Server: "a", Tool: "t1", Diff: "+x\n"},
		{Server: "b", Tool: "t2", Diff: "-y\n"},
	}

	t.Run("first write fails", func(t *testing.T) {
		t.Parallel()
		err := report.WriteDiffs(errWriter{err: errBoom}, diffs)
		if !errors.Is(err, errBoom) {
			t.Fatalf("WriteDiffs() error = %v, want %v", err, errBoom)
		}
	})

	t.Run("later write fails and stops", func(t *testing.T) {
		t.Parallel()
		w := &failAfterWriter{ok: 1, err: errBoom}
		err := report.WriteDiffs(w, diffs)
		if !errors.Is(err, errBoom) {
			t.Fatalf("WriteDiffs() error = %v, want %v", err, errBoom)
		}
		if w.writes != 2 {
			t.Errorf("writes = %d, want 2 (stop at the first error)", w.writes)
		}
	})

	t.Run("empty diffs never write", func(t *testing.T) {
		t.Parallel()
		if err := report.WriteDiffs(errWriter{err: errBoom}, nil); err != nil {
			t.Errorf("WriteDiffs(nil) error = %v, want nil", err)
		}
	})
}
