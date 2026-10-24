package report_test

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// writeFindings returns the text that report.WriteFindings writes for rows.
// It fails the test if WriteFindings returns an error.
func writeFindings(t *testing.T, rows ...report.FindingRow) string {
	t.Helper()
	var sb strings.Builder
	if err := report.WriteFindings(&sb, rows); err != nil {
		t.Fatalf("WriteFindings() error = %v, want nil", err)
	}
	return sb.String()
}

// findingRows returns two rows: one with a Key and one with only a Related.
func findingRows() []report.FindingRow {
	return []report.FindingRow{
		{RuleID: "T1-001", Severity: "high", Server: "fs", Field: "env", Key: "API_KEY"},
		{RuleID: "T2-002", Severity: "medium", Server: "remote", Field: "args", Related: "other"},
	}
}

func TestWriteFindingsExact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rows []report.FindingRow
		want string
	}{
		{name: "nil rows", rows: nil, want: ""},
		{name: "empty rows", rows: []report.FindingRow{}, want: ""},
		{
			// A blank first line, then columns padded to the widest cell + 3.
			name: "two rows",
			rows: findingRows(),
			want: "\n" +
				"RULE     SEVERITY   SERVER   FIELD   KEY/RELATED\n" +
				"T1-001   high       fs       env     API_KEY\n" +
				"T2-002   medium     remote   args    other\n",
		},
		{
			name: "key wins over related",
			rows: []report.FindingRow{
				{RuleID: "R", Severity: "low", Server: "s", Field: "f", Key: "KEY", Related: "REL"},
			},
			want: "\n" +
				"RULE   SEVERITY   SERVER   FIELD   KEY/RELATED\n" +
				"R      low        s        f       KEY\n",
		},
		{
			name: "related used when key is empty",
			rows: []report.FindingRow{
				{RuleID: "R", Severity: "low", Server: "s", Field: "f", Related: "REL"},
			},
			want: "\n" +
				"RULE   SEVERITY   SERVER   FIELD   KEY/RELATED\n" +
				"R      low        s        f       REL\n",
		},
		{
			name: "dash for every empty cell",
			rows: []report.FindingRow{{}},
			want: "\n" +
				"RULE   SEVERITY   SERVER   FIELD   KEY/RELATED\n" +
				"-      -          -        -       -\n",
		},
		{
			name: "dash for empty key and related",
			rows: []report.FindingRow{
				{RuleID: "R", Severity: "low", Server: "s", Field: "f"},
			},
			want: "\n" +
				"RULE   SEVERITY   SERVER   FIELD   KEY/RELATED\n" +
				"R      low        s        f       -\n",
		},
		{
			// A space in a name could look like a column gap, so it is quoted.
			name: "name with a space is quoted",
			rows: []report.FindingRow{
				{RuleID: "R", Severity: "low", Server: "my server", Field: "f", Key: "K"},
			},
			want: "\n" +
				"RULE   SEVERITY   SERVER        FIELD   KEY/RELATED\n" +
				"R      low        \"my server\"   f       K\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var sb strings.Builder
			if err := report.WriteFindings(&sb, tt.rows); err != nil {
				t.Fatalf("WriteFindings() error = %v, want nil", err)
			}
			if got := sb.String(); got != tt.want {
				t.Errorf("WriteFindings() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

func TestWriteFindingsEscapesHostileText(t *testing.T) {
	t.Parallel()

	// None of these values holds a space, so termsafe.Quote is the exact cell.
	hostile := []struct {
		name  string
		value string
	}{
		{name: "ESC", value: "a\x1b[31mb"},
		{name: "newline", value: "a\nb"},
		{name: "tab", value: "a\tb"},
		{name: "bidi override", value: "a\u202eb"},
	}
	// Each hostile value goes into Server, Key and Related, one field at a time.
	places := []struct {
		name string
		row  func(v string) report.FindingRow
	}{
		{name: "Server", row: func(v string) report.FindingRow {
			return report.FindingRow{RuleID: "R", Severity: "low", Server: v, Field: "f", Key: "K"}
		}},
		{name: "Key", row: func(v string) report.FindingRow {
			return report.FindingRow{RuleID: "R", Severity: "low", Server: "s", Field: "f", Key: v}
		}},
		{name: "Related", row: func(v string) report.FindingRow {
			return report.FindingRow{RuleID: "R", Severity: "low", Server: "s", Field: "f", Related: v}
		}},
	}
	for _, h := range hostile {
		for _, p := range places {
			t.Run(p.name+"/"+h.name, func(t *testing.T) {
				t.Parallel()
				out := writeFindings(t, p.row(h.value))

				if want := termsafe.Quote(h.value); !strings.Contains(out, want) {
					t.Errorf("output does not hold the escaped cell %s:\n%q", want, out)
				}
				// The only control bytes left are the row separators: the
				// blank line, the header and the one data row.
				if got := strings.Count(out, "\n"); got != 3 {
					t.Errorf("output has %d newlines, want 3:\n%q", got, out)
				}
				for i := 0; i < len(out); i++ {
					if out[i] < 0x20 && out[i] != '\n' {
						t.Errorf("output holds raw control byte 0x%02x at %d:\n%q", out[i], i, out)
						break
					}
				}
				if strings.ContainsRune(out, '\u202e') {
					t.Errorf("output holds a raw U+202E:\n%q", out)
				}
				if !utf8.ValidString(out) {
					t.Errorf("output is not valid UTF-8:\n%q", out)
				}
			})
		}
	}
}

func TestWriteFindingsLongCellIsCut(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", maxShortCellRunes*3)
	out := writeFindings(t, report.FindingRow{
		RuleID: "R", Severity: "low", Server: long, Field: "f", Key: long,
	})

	// The shown part is the first maxShortCellRunes runes and the marker.
	// Server is padded, so check it on its own. Key is the last column.
	wantCell := strings.Repeat("x", maxShortCellRunes) + termsafe.CutMarker
	if got := strings.Count(out, wantCell); got != 2 {
		t.Errorf("output holds the cut cell %d times, want 2 (SERVER and KEY/RELATED):\n%q", got, out)
	}
	if strings.Contains(out, strings.Repeat("x", maxShortCellRunes+1)) {
		t.Errorf("output holds more than %d runes of one cell:\n%q", maxShortCellRunes, out)
	}
}

func TestWriteFindingsWriteError(t *testing.T) {
	t.Parallel()

	errBoom := errors.New("boom")

	tests := []struct {
		name  string
		limit int
	}{
		{name: "fails at once", limit: 0},
		{name: "fails on the second write", limit: 1},
		{name: "fails after some bytes", limit: 10},
		{name: "fails near the end", limit: 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := &failingWriter{limit: tt.limit, err: errBoom}
			err := report.WriteFindings(w, findingRows())
			if err == nil {
				t.Fatal("WriteFindings() error = nil, want a write error")
			}
			if !errors.Is(err, errBoom) {
				t.Errorf("WriteFindings() error = %v, want it to be %v", err, errBoom)
			}
		})
	}

	t.Run("empty rows never write", func(t *testing.T) {
		t.Parallel()
		w := &failingWriter{limit: 0, err: errBoom}
		if err := report.WriteFindings(w, nil); err != nil {
			t.Errorf("WriteFindings(nil) error = %v, want nil", err)
		}
	})
}
