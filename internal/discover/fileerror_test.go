package discover

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

func TestFileErrorError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		fe   *FileError
		want string
	}{
		{
			name: "path and reason only",
			fe:   &FileError{Path: "/home/u/.claude.json", Reason: reasonInvalidJSON},
			want: "/home/u/.claude.json: invalid JSON",
		},
		{
			name: "path, line and reason",
			fe:   &FileError{Path: "/home/u/.claude.json", Line: 12, Reason: reasonInvalidJSON},
			want: "/home/u/.claude.json:12: invalid JSON",
		},
		{
			name: "path, line, column and reason",
			fe:   &FileError{Path: "/home/u/.claude.json", Line: 12, Col: 7, Reason: reasonInvalidJSON},
			want: "/home/u/.claude.json:12:7: invalid JSON",
		},
		{
			name: "server name",
			fe:   &FileError{Path: "/w/.mcp.json", Server: "github", Reason: reasonNoCommandOrURL},
			want: "/w/.mcp.json: server github: server has no command or url",
		},
		{
			name: "line, column and server name",
			fe:   &FileError{Path: "/w/.mcp.json", Server: "github", Line: 3, Col: 5, Reason: reasonBadEntry},
			want: "/w/.mcp.json:3:5: server github: invalid server entry",
		},
		{
			name: "line and server name without column",
			fe:   &FileError{Path: "/w/.mcp.json", Server: "github", Line: 3, Reason: reasonBadEntry},
			want: "/w/.mcp.json:3: server github: invalid server entry",
		},
		{
			name: "OS error is appended",
			fe: &FileError{
				Path:   "/home/u/.cursor/mcp.json",
				Reason: reasonCannotRead,
				Err:    errors.New("permission denied"),
			},
			want: "/home/u/.cursor/mcp.json: cannot read file: permission denied",
		},
		{
			name: "OS error with server name and position",
			fe: &FileError{
				Path:   "/p",
				Server: "s",
				Line:   2,
				Col:    4,
				Reason: reasonCannotRead,
				Err:    errors.New("boom"),
			},
			want: "/p:2:4: server s: cannot read file: boom",
		},
		{
			name: "column without line shows no position",
			fe:   &FileError{Path: "/p", Col: 9, Reason: reasonInvalidTOML},
			want: "/p: invalid TOML",
		},
		{
			name: "column without line keeps the server name",
			fe:   &FileError{Path: "/p", Server: "s", Col: 9, Reason: reasonInvalidTOML},
			want: "/p: server s: invalid TOML",
		},
		{
			name: "negative line shows no position",
			fe:   &FileError{Path: "/p", Line: -1, Col: 3, Reason: reasonInvalidTOML},
			want: "/p: invalid TOML",
		},
		{
			name: "unprintable path is quoted",
			fe:   &FileError{Path: "/tmp/a\nb", Reason: reasonCannotRead},
			want: `"/tmp/a\nb": cannot read file`,
		},
		{
			name: "path with invalid UTF-8 is quoted",
			fe:   &FileError{Path: "/tmp/a\xffb", Reason: reasonCannotRead},
			want: `"/tmp/a\xffb": cannot read file`,
		},
		{
			name: "server name with invalid UTF-8 is quoted",
			fe:   &FileError{Path: "/p", Server: "s\xc3", Reason: reasonBadEntry},
			want: `/p: server "s\xc3": invalid server entry`,
		},
		{
			name: "project path before server name",
			fe:   &FileError{Path: "/home/u/.claude.json", ProjectPath: "/w/app", Server: "github", Reason: reasonBadEntry},
			want: "/home/u/.claude.json: project /w/app: server github: invalid server entry",
		},
		{
			name: "project path without server name",
			fe:   &FileError{Path: "/home/u/.claude.json", ProjectPath: "/w/app", Line: 2, Col: 3, Reason: reasonBadShape},
			want: "/home/u/.claude.json:2:3: project /w/app: unexpected structure",
		},
		{
			name: "unprintable project path is quoted",
			fe:   &FileError{Path: "/p", ProjectPath: "/w/\x1b[31m", Server: "s", Reason: reasonBadEntry},
			want: `/p: project "/w/\x1b[31m": server s: invalid server entry`,
		},
		{
			name: "project path with invalid UTF-8 is quoted",
			fe:   &FileError{Path: "/p", ProjectPath: "/w/a\xffb", Reason: reasonAmbiguousKey},
			want: `/p: project "/w/a\xffb": ambiguous key`,
		},
		{
			name: "unprintable server name is quoted",
			fe:   &FileError{Path: "/p", Server: "x\x1b[31m", Reason: reasonBadEntry},
			want: `/p: server "x\x1b[31m": invalid server entry`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.fe.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFileErrorErrorNoRawControlBytes(t *testing.T) {
	t.Parallel()
	fe := &FileError{
		Path:   "/tmp/\x1b]0;pwned\x07",
		Server: "a\r\nb\u202e",
		Line:   1,
		Col:    1,
		Reason: reasonBadEntry,
	}
	got := fe.Error()
	for _, r := range got {
		if r == '\x1b' || r == '\x07' || r == '\r' || r == '\n' || r == '\u202e' {
			t.Errorf("Error() = %q contains raw control rune %U", got, r)
		}
	}
}

func TestFileErrorErrorPathError(t *testing.T) {
	t.Parallel()

	t.Run("PathError path is not printed raw", func(t *testing.T) {
		t.Parallel()
		const path = "/tmp/\x1b[31mred"
		fe := &FileError{
			Path:   path,
			Reason: reasonCannotRead,
			Err:    &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission},
		}
		got := fe.Error()
		if n := strings.Count(got, strconv.Quote(path)); n != 1 {
			t.Errorf("Error() = %q holds the quoted path %d times, want 1", got, n)
		}
		for _, want := range []string{"open", "permission denied"} {
			if !strings.Contains(got, want) {
				t.Errorf("Error() = %q, want it to contain %q", got, want)
			}
		}
		if strings.Contains(got, "\x1b") {
			t.Errorf("Error() = %q contains a raw escape byte", got)
		}
		if !errors.Is(fe, fs.ErrPermission) {
			t.Error("errors.Is(fe, fs.ErrPermission) = false, want true")
		}
	})

	t.Run("context error keeps its text", func(t *testing.T) {
		t.Parallel()
		fe := &FileError{Path: "/p", Reason: reasonCanceled, Err: context.Canceled}
		want := "/p: canceled: context canceled"
		if got := fe.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})
}

func TestCanceledError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		err     error
		wantIs  error
		wantNot error
		want    string
	}{
		{
			name:    "canceled",
			err:     context.Canceled,
			wantIs:  context.Canceled,
			wantNot: context.DeadlineExceeded,
			want:    "/p: canceled: context canceled",
		},
		{
			name:    "deadline exceeded",
			err:     context.DeadlineExceeded,
			wantIs:  context.DeadlineExceeded,
			wantNot: context.Canceled,
			want:    "/p: canceled: context deadline exceeded",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fe := canceledError("/p", tt.err)
			if fe.Path != "/p" || fe.Reason != reasonCanceled {
				t.Errorf("canceledError() = {Path: %q, Reason: %q}, want {Path: %q, Reason: %q}",
					fe.Path, fe.Reason, "/p", reasonCanceled)
			}
			if !errors.Is(fe, tt.wantIs) {
				t.Errorf("errors.Is(fe, %v) = false, want true", tt.wantIs)
			}
			if errors.Is(fe, tt.wantNot) {
				t.Errorf("errors.Is(fe, %v) = true, want false", tt.wantNot)
			}
			if got := fe.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAllReasonsUnique(t *testing.T) {
	t.Parallel()
	seen := make(map[reason]bool, len(allReasons))
	for _, r := range allReasons {
		if r == "" {
			t.Error("allReasons holds an empty reason")
		}
		if seen[r] {
			t.Errorf("allReasons holds %q twice", r)
		}
		seen[r] = true
	}
}

// TestAllReasonsInSync parses fileerror.go and checks that allReasons holds
// the value of every constant whose name starts with "reason", and nothing
// else.
func TestAllReasonsInSync(t *testing.T) {
	t.Parallel()
	file, err := parser.ParseFile(token.NewFileSet(), "fileerror.go", nil, 0)
	if err != nil {
		t.Fatalf("parse fileerror.go: %v", err)
	}
	declared := make(map[reason]string) // value -> constant name
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "reason") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Errorf("constant %s is not a string literal", name.Name)
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote %s: %v", name.Name, err)
				}
				declared[reason(v)] = name.Name
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("found no reason constants in fileerror.go")
	}
	listed := make(map[reason]bool, len(allReasons))
	for _, r := range allReasons {
		listed[r] = true
		if _, ok := declared[r]; !ok {
			t.Errorf("allReasons holds %q, which is not a reason constant", r)
		}
	}
	for v, name := range declared {
		if !listed[v] {
			t.Errorf("constant %s (%q) is missing from allReasons", name, v)
		}
	}
}

func TestReadError(t *testing.T) {
	t.Parallel()
	fe := readError("/p", reasonCannotRead, fs.ErrPermission)
	if fe.Path != "/p" || fe.Reason != reasonCannotRead || fe.Untrusted {
		t.Errorf("readError() = {Path: %q, Reason: %q, Untrusted: %v}, want {Path: %q, Reason: %q, Untrusted: false}",
			fe.Path, fe.Reason, fe.Untrusted, "/p", reasonCannotRead)
	}
	if !errors.Is(fe, fs.ErrPermission) {
		t.Error("readError(): errors.Is(fe, fs.ErrPermission) = false")
	}
}

func TestDisplayText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain ASCII", in: "/tmp/config.json", want: "/tmp/config.json"},
		{name: "empty", in: "", want: ""},
		{name: "spaces are printable", in: "my server", want: "my server"},
		{name: "accented letters", in: "café", want: "café"},
		{name: "CJK path", in: "/tmp/プロジェクト", want: "/tmp/プロジェクト"},
		{name: "emoji", in: "srv-🚀", want: "srv-🚀"},
		{name: "newline", in: "a\nb", want: strconv.Quote("a\nb")},
		{name: "tab", in: "a\tb", want: strconv.Quote("a\tb")},
		{name: "ANSI escape", in: "\x1b[31mred", want: strconv.Quote("\x1b[31mred")},
		{name: "right-to-left override", in: "gpj.\u202eevil", want: strconv.Quote("gpj.\u202eevil")},
		{name: "zero width space", in: "a\u200bb", want: strconv.Quote("a\u200bb")},
		{name: "C1 control CSI", in: "a\u009bb", want: strconv.Quote("a\u009bb")},
		{name: "NUL byte", in: "a\x00b", want: strconv.Quote("a\x00b")},
		{name: "unassigned code point", in: "a\U000e0080b", want: strconv.Quote("a\U000e0080b")},
		{name: "invalid UTF-8 byte", in: "a\xffb", want: strconv.Quote("a\xffb")},
		{name: "truncated UTF-8 sequence", in: "a\xe3\x81", want: strconv.Quote("a\xe3\x81")},

		// Runes that unicode.IsPrint accepts but that show as nothing, or
		// change the rune before them. strconv.Quote keeps them as they are,
		// so displayText escapes them itself.
		{name: "Hangul choseong filler U+115F", in: "a\u115fz", want: `"a\u115fz"`},
		{name: "Hangul jungseong filler U+1160", in: "a\u1160z", want: `"a\u1160z"`},
		{name: "Hangul filler U+3164", in: "a\u3164z", want: `"a\u3164z"`},
		{name: "halfwidth Hangul filler U+FFA0", in: "a\uffa0z", want: `"a\uffa0z"`},
		{name: "braille pattern blank U+2800", in: "a\u2800z", want: `"a\u2800z"`},
		{name: "nonspacing mark Mn", in: "cafe\u0301", want: `"cafe\u0301"`},
		{name: "enclosing mark Me", in: "a\u20ddz", want: `"a\u20ddz"`},
		{name: "variation selector", in: "a\ufe0fz", want: `"a\ufe0fz"`},
		{name: "supplementary variation selector", in: "a\U000e0100z", want: `"a\U000e0100z"`},
		{name: "combining grapheme joiner", in: "a\u034fz", want: `"a\u034fz"`},
		{
			// The blank rune is escaped, and the other parts are escaped as
			// strconv.Quote does it.
			name: "blank rune with other escapes",
			in:   "\x1b\u3164\"\xff\u3164é",
			want: `"\x1b\u3164\"\xff\u3164é"`,
		},

		// Long text is cut to maxDisplayRunes runes and ends with cutMark.
		{name: "exactly at the cap", in: strings.Repeat("a", maxDisplayRunes), want: strings.Repeat("a", maxDisplayRunes)},
		{name: "one rune over the cap", in: strings.Repeat("a", maxDisplayRunes+1), want: strings.Repeat("a", maxDisplayRunes) + cutMark},
		{name: "4 KiB name", in: strings.Repeat("a", 4096), want: strings.Repeat("a", maxDisplayRunes) + cutMark},
		{name: "cap counts runes not bytes", in: strings.Repeat("é", 300), want: strings.Repeat("é", maxDisplayRunes) + cutMark},
		{
			// The cut is made before the quoting, so it never splits an escape.
			name: "long quoted text",
			in:   strings.Repeat("\x1b", 4096),
			want: `"` + strings.Repeat(`\x1b`, maxDisplayRunes) + `"` + cutMark,
		},
		{
			name: "long text with blank runes",
			in:   strings.Repeat("\u3164", 4096),
			want: `"` + strings.Repeat(`\u3164`, maxDisplayRunes) + `"` + cutMark,
		},
		{
			// An invalid byte counts as one rune.
			name: "long invalid UTF-8",
			in:   strings.Repeat("\xff", 4096),
			want: `"` + strings.Repeat(`\xff`, maxDisplayRunes) + `"` + cutMark,
		},
		{
			// The part after the cut is not shown, so it does not make the
			// text quoted.
			name: "control character after the cut",
			in:   strings.Repeat("a", maxDisplayRunes) + "\x1b",
			want: strings.Repeat("a", maxDisplayRunes) + cutMark,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := displayText(tt.in); got != tt.want {
				t.Errorf("displayText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestDisplayTextMatchesQuote checks that displayText quotes as strconv.Quote
// does when the text holds no blank rune (see isBlank).
func TestDisplayTextMatchesQuote(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"a\nb", "\x1b[31m\"x\"\\", "a\xffb\xe3\x81", "gpj.\u202eevil", "\u00a0\u3000"} {
		if got, want := displayText(in), strconv.Quote(in); got != want {
			t.Errorf("displayText(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDisplayPath checks that a path is quoted as displayText quotes, but is
// never cut: the user needs the full path to find the file.
func TestDisplayPath(t *testing.T) {
	t.Parallel()
	long := "/" + strings.Repeat("d", 4096)
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain path", in: "/tmp/config.json", want: "/tmp/config.json"},
		{name: "long path is not cut", in: long, want: long},
		{name: "control character", in: "/tmp/\x1b.json", want: strconv.Quote("/tmp/\x1b.json")},
		{name: "blank rune", in: "/tmp/\u3164.json", want: `"/tmp/\u3164.json"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := displayPath(tt.in); got != tt.want {
				t.Errorf("displayPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestFileErrorLongNames checks that a FileError message stays short when the
// server name and the project key are very long.
func TestFileErrorLongNames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		fe   *FileError
	}{
		{
			name: "long server name",
			fe:   &FileError{Path: "/w/.mcp.json", Server: strings.Repeat("s", 4096), Reason: reasonBadEntry},
		},
		{
			name: "long project key",
			fe:   &FileError{Path: "/h/.claude.json", ProjectPath: strings.Repeat("p", 4096), Reason: reasonBadEntry},
		},
		{
			name: "long quoted name and key",
			fe: &FileError{
				Path:        "/h/.claude.json",
				ProjectPath: strings.Repeat("\x1b", 4096),
				Server:      strings.Repeat("\u3164", 4096),
				Reason:      reasonBadEntry,
			},
		},
	}
	// Each name or key shows at most maxDisplayRunes escapes of at most 10
	// bytes (\U0010ffff), plus the quotes and cutMark.
	const maxLen = 2*(maxDisplayRunes*10+2+len(cutMark)) + 100
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.fe.Error()
			if len(got) > maxLen {
				t.Errorf("len(Error()) = %d, want at most %d", len(got), maxLen)
			}
			if !strings.Contains(got, cutMark+": ") {
				t.Errorf("Error() = %q, want a cut name that ends with %q", got, cutMark)
			}
			if !strings.HasSuffix(got, reasonBadEntry) {
				t.Errorf("Error() = %q, want it to end with the reason %q", got, reasonBadEntry)
			}
		})
	}
}

func TestFileErrorUnwrap(t *testing.T) {
	t.Parallel()

	t.Run("errors.As finds a wrapped FileError", func(t *testing.T) {
		t.Parallel()
		fe := &FileError{Path: "/p", Reason: reasonInvalidJSON}
		wrapped := fmt.Errorf("x: %w", fe)
		var got *FileError
		if !errors.As(wrapped, &got) {
			t.Fatal("errors.As() = false, want true")
		}
		if got != fe {
			t.Errorf("errors.As() found %p, want %p", got, fe)
		}
	})

	t.Run("errors.Is reaches fs.ErrNotExist through a PathError", func(t *testing.T) {
		t.Parallel()
		fe := &FileError{
			Path:   "/p",
			Reason: reasonCannotRead,
			Err:    &fs.PathError{Op: "open", Path: "/p", Err: fs.ErrNotExist},
		}
		if !errors.Is(fe, fs.ErrNotExist) {
			t.Error("errors.Is(fe, fs.ErrNotExist) = false, want true")
		}
		if errors.Is(fe, fs.ErrPermission) {
			t.Error("errors.Is(fe, fs.ErrPermission) = true, want false")
		}
		var pe *fs.PathError
		if !errors.As(fe, &pe) {
			t.Error("errors.As(fe, *fs.PathError) = false, want true")
		}
	})

	t.Run("errors.Is reaches context.Canceled", func(t *testing.T) {
		t.Parallel()
		fe := &FileError{Path: "/p", Reason: reasonCanceled, Err: context.Canceled}
		if !errors.Is(fe, context.Canceled) {
			t.Error("errors.Is(fe, context.Canceled) = false, want true")
		}
		if errors.Is(fe, context.DeadlineExceeded) {
			t.Error("errors.Is(fe, context.DeadlineExceeded) = true, want false")
		}
	})

	t.Run("nil Err unwraps to nil", func(t *testing.T) {
		t.Parallel()
		fe := &FileError{Path: "/p", Reason: reasonInvalidJSON}
		if got := fe.Unwrap(); got != nil {
			t.Errorf("Unwrap() = %v, want nil", got)
		}
		if errors.Is(fe, fs.ErrNotExist) {
			t.Error("errors.Is(fe, fs.ErrNotExist) = true, want false")
		}
	})
}

func TestLineCol(t *testing.T) {
	t.Parallel()
	const data = "ab\ncde\n\nfg"
	// Offsets: a=0 b=1 \n=2 c=3 d=4 e=5 \n=6 \n=7 f=8 g=9, len=10.
	tests := []struct {
		name     string
		data     string
		offset   int64
		wantLine int
		wantCol  int
	}{
		{name: "offset 0", data: data, offset: 0, wantLine: 1, wantCol: 1},
		{name: "inside first line", data: data, offset: 1, wantLine: 1, wantCol: 2},
		{name: "on the first newline", data: data, offset: 2, wantLine: 1, wantCol: 3},
		{name: "right after a newline", data: data, offset: 3, wantLine: 2, wantCol: 1},
		{name: "inside a later line", data: data, offset: 5, wantLine: 2, wantCol: 3},
		{name: "on the second newline", data: data, offset: 6, wantLine: 2, wantCol: 4},
		{name: "empty line", data: data, offset: 7, wantLine: 3, wantCol: 1},
		{name: "start of last line", data: data, offset: 8, wantLine: 4, wantCol: 1},
		{name: "last byte", data: data, offset: 9, wantLine: 4, wantCol: 2},
		{name: "offset equals len", data: data, offset: 10, wantLine: 4, wantCol: 3},
		{name: "offset past len is clamped", data: data, offset: 999, wantLine: 4, wantCol: 3},
		{name: "huge offset is clamped", data: data, offset: 1 << 62, wantLine: 4, wantCol: 3},
		{name: "negative offset is clamped", data: data, offset: -5, wantLine: 1, wantCol: 1},
		{name: "offset equals len after trailing newline", data: "a\n", offset: 2, wantLine: 2, wantCol: 1},
		{name: "empty data offset 0", data: "", offset: 0, wantLine: 1, wantCol: 1},
		{name: "empty data offset past end", data: "", offset: 4, wantLine: 1, wantCol: 1},
		{name: "empty data negative offset", data: "", offset: -1, wantLine: 1, wantCol: 1},
		{name: "column counts bytes not runes", data: "é{", offset: 2, wantLine: 1, wantCol: 3},
		{name: "CRLF counts the carriage return in the column", data: "a\r\nb", offset: 4, wantLine: 2, wantCol: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			line, col := lineCol([]byte(tt.data), tt.offset)
			if line != tt.wantLine || col != tt.wantCol {
				t.Errorf("lineCol(%q, %d) = (%d, %d), want (%d, %d)",
					tt.data, tt.offset, line, col, tt.wantLine, tt.wantCol)
			}
		})
	}
}

func TestLineColNilData(t *testing.T) {
	t.Parallel()
	line, col := lineCol(nil, 3)
	if line != 1 || col != 1 {
		t.Errorf("lineCol(nil, 3) = (%d, %d), want (1, 1)", line, col)
	}
}

func TestFileErrorHoldsNoCanary(t *testing.T) {
	t.Parallel()
	fe := &FileError{
		Path:   "/home/dev/.claude.json",
		Server: "github",
		Line:   4,
		Col:    9,
		Reason: reasonInvalidJSON,
	}
	discovertest.AssertNoLeak(t, "FileError.Error()", fe.Error())

	// Sanity check for the helper: it must catch a canary if one gets in.
	if leaks := discovertest.Leaks(
		(&FileError{Path: "/p", Server: discovertest.CanaryEnv, Reason: reasonBadEntry}).Error(),
		discovertest.Canaries()...,
	); len(leaks) == 0 {
		t.Error("Leaks() found nothing in an error that holds a canary; the leak check is blind")
	}
}
