package rules

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

// exfilCase is one parsed line of the exfil corpus.
type exfilCase struct {
	line  int    // 1-based line number in the file
	label string // ok, hit, fp or miss
	text  string // the description text, escapes already decoded
}

// exfilID is the rule that the exfil corpus measures.
const exfilID = "MOAT-T1-005"

// matches reports whether the rule is expected to match the text of the case.
// hit and fp match today. ok and miss do not.
func (c exfilCase) matches() bool { return c.label == "hit" || c.label == "fp" }

// unescapeExfil decodes the escapes of a corpus text: \n, \t, \r and \\.
// Any other backslash sequence, or a trailing lone backslash, is an error.
func unescapeExfil(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		i++
		if i == len(s) {
			return "", errors.New("trailing backslash")
		}
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\\':
			b.WriteByte('\\')
		default:
			return "", fmt.Errorf("bad escape \\%c", s[i])
		}
	}
	return b.String(), nil
}

// parseExfilCorpus reads the exfil corpus. Each line is "<label> <text>".
// It skips blank lines and lines that start with "#". It strips a trailing
// \r and trailing spaces and tabs. A malformed line is an error that names
// its line number.
func parseExfilCorpus(r io.Reader) ([]exfilCase, error) {
	var cases []exfilCase
	sc := bufio.NewScanner(r)
	// The default 64 KB line limit is close: the longest real description is about 18 KB.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), "\r \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		label, raw, found := strings.Cut(line, " ")
		if !found || raw == "" {
			return nil, fmt.Errorf("line %d: want a label, one space and a text", n)
		}
		switch label {
		case "ok", "hit", "fp", "miss": // a known label
		default:
			return nil, fmt.Errorf("line %d: unknown label %q", n, label)
		}
		text, err := unescapeExfil(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		cases = append(cases, exfilCase{line: n, label: label, text: text})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan corpus: %w", err)
	}
	return cases, nil
}

// clipExfil cuts s to at most 120 bytes so a failure message stays short.
// It drops a rune that the cut splits.
func clipExfil(s string) string {
	const maxLen = 120
	if len(s) > maxLen {
		return strings.ToValidUTF8(s[:maxLen], "")
	}
	return s
}

// exfilRule returns the built-in rule exfilID or stops the test.
func exfilRule(t *testing.T) *Rule {
	t.Helper()
	rs := mustBuiltin(t, WithCompiler(builtinCompiler()))
	for i := range rs {
		if rs[i].ID == exfilID {
			return &rs[i]
		}
	}
	t.Fatalf("built-in rule %s not found", exfilID)
	return nil
}

// TestExfilPrefixesAgree checks that the URL and email regexes of the rule
// differ only in the address part. They are one form split in two to stay
// under the instruction limit, so an edit to the verbs, nouns or wording of
// only one of them would make the URL and email forms disagree.
func TestExfilPrefixesAgree(t *testing.T) {
	t.Parallel()
	res := exfilRule(t).Match.AnyRegex
	if len(res) < 2 {
		t.Fatalf("%s has %d any_regex entries, want at least 2", exfilID, len(res))
	}
	// "<?" is the optional angle bracket that starts the address part. It must
	// not occur earlier in the regex. [0] is the URL and phone form, [1] the
	// email form.
	url, urlAddr, okURL := strings.Cut(res[0], "<?")
	email, emailAddr, okEmail := strings.Cut(res[1], "<?")
	if !okURL || !okEmail {
		t.Fatalf("%s any_regex[0] or [1] has no \"<?\" before the address", exfilID)
	}
	if !strings.HasPrefix(urlAddr, "(?:https?://") || !strings.HasPrefix(emailAddr, `[\w.+%-]`) {
		t.Fatalf("%s any_regex[0] must be the URL form and [1] the email form, each with its first \"<?\" before the address", exfilID)
	}
	if url != email {
		t.Errorf("%s any_regex[0] and [1] differ before the address:\n[0] %s\n[1] %s", exfilID, url, email)
	}
}

// TestParseExfilCorpus checks the corpus parser: good lines, each escape,
// the text trimming and each error case. The error cases must name the line.
func TestParseExfilCorpus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    []exfilCase
		wantErr string // substring of the error, empty for no error
	}{
		{name: "empty file", in: "", want: nil},
		{name: "comment and blank lines", in: "# note\n\n   \n#ok x\n", want: nil},
		{
			name: "four labels",
			in:   "ok a\nhit b\nfp c\nmiss d\n",
			want: []exfilCase{{1, "ok", "a"}, {2, "hit", "b"}, {3, "fp", "c"}, {4, "miss", "d"}},
		},
		{
			name: "line numbers count skipped lines",
			in:   "# c\n\nhit x\n",
			want: []exfilCase{{3, "hit", "x"}},
		},
		{name: "newline escape", in: `ok a\nb`, want: []exfilCase{{1, "ok", "a\nb"}}},
		{name: "tab escape", in: `ok a\tb`, want: []exfilCase{{1, "ok", "a\tb"}}},
		{name: "carriage return escape", in: `ok a\rb`, want: []exfilCase{{1, "ok", "a\rb"}}},
		{name: "backslash escape", in: `ok a\\nb`, want: []exfilCase{{1, "ok", `a\nb`}}},
		{name: "text ends in escaped backslash", in: `ok a\\`, want: []exfilCase{{1, "ok", `a\`}}},
		{name: "extra spaces in text are literal", in: "ok  a  b\n", want: []exfilCase{{1, "ok", " a  b"}}},
		{name: "hash inside text", in: "ok a # b\n", want: []exfilCase{{1, "ok", "a # b"}}},
		{name: "trailing CR, spaces and tabs are cut", in: "hit a b \t \r\n", want: []exfilCase{{1, "hit", "a b"}}},
		{name: "CRLF file", in: "ok a\r\nhit b\r\n", want: []exfilCase{{1, "ok", "a"}, {2, "hit", "b"}}},
		{name: "non-ASCII is literal", in: "ok caf\u00e9 \u202e\n", want: []exfilCase{{1, "ok", "caf\u00e9 \u202e"}}},
		{name: "unknown label", in: "ok a\nbad b\n", wantErr: "line 2: unknown label"},
		{name: "label is case sensitive", in: "OK a\n", wantErr: "line 1: unknown label"},
		{name: "no space after label", in: "ok\n", wantErr: "line 1: want a label"},
		{name: "tab after label", in: "ok\ta\n", wantErr: "line 1: want a label"},
		{name: "empty text", in: "# c\nhit \n", wantErr: "line 2: want a label"},
		{name: "text of spaces only", in: "hit    \n", wantErr: "line 1: want a label"},
		{name: "leading space before label", in: " ok a\n", wantErr: "line 1: unknown label"},
		{name: "bad escape", in: `ok a\xb`, wantErr: "line 1: bad escape"},
		{name: "bad escape digit", in: `ok a\0`, wantErr: "line 1: bad escape"},
		{name: "trailing lone backslash", in: `ok a\`, wantErr: "line 1: trailing backslash"},
		{name: "lone backslash after escaped one", in: `ok a\\\`, wantErr: "line 1: trailing backslash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseExfilCorpus(strings.NewReader(tt.in))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseExfilCorpus(%q) error = nil, want one containing %q", tt.in, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("parseExfilCorpus(%q) error = %q, want it to contain %q", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseExfilCorpus(%q) error = %v, want nil", tt.in, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseExfilCorpus(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

// TestExfilCorpus runs rule MOAT-T1-005 over testdata/exfil/descriptions.txt.
// An ok line must not match and a hit line must match. The fp and miss labels
// pin accepted limits of the rule. An fp line is benign text that matches
// today, and the test asserts that it still matches. A miss line is malicious
// text that the rule does not match today, and the test asserts that it still
// does not. A rule change that fixes one of them fails the test on purpose, so
// the author must relabel the line (fp to ok, miss to hit). To add a case, add
// one line to that file. Its header explains the line format.
func TestExfilCorpus(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../testdata/exfil/descriptions.txt")
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer func() { _ = f.Close() }() // read-only file: a close error loses no data
	cases, err := parseExfilCorpus(f)
	if err != nil {
		t.Fatalf("parse corpus: %v", err)
	}

	count := map[string]int{}
	for _, c := range cases {
		count[c.label]++
	}
	// A corpus without both sides would make the test pass for nothing.
	if count["ok"] == 0 {
		t.Fatal("corpus has no ok line")
	}
	if count["hit"] == 0 {
		t.Fatal("corpus has no hit line")
	}
	t.Logf("exfil corpus: %d cases (ok %d, hit %d, fp %d, miss %d), false-positive rate %.1f%%",
		len(cases), count["ok"], count["hit"], count["fp"], count["miss"],
		100*float64(count["fp"])/float64(count["ok"]+count["fp"]))

	m, err := exfilRule(t).Match.Compile()
	if err != nil {
		t.Fatalf("compile %s: %v", exfilID, err)
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%03d_%s", c.line, c.label), func(t *testing.T) {
			t.Parallel()
			got := len(m.Match(c.text)) > 0
			if got == c.matches() {
				return
			}
			want := "not match"
			if c.matches() {
				want = "match"
			}
			hint := ""
			switch c.label {
			case "fp":
				hint = " (the rule no longer matches this accepted false positive: relabel the line ok)"
			case "miss":
				hint = " (the rule now matches this accepted gap: relabel the line hit)"
			}
			t.Errorf("line %d (%s): rule %s matched = %v, want it to %s%s: %q",
				c.line, c.label, exfilID, got, want, hint, clipExfil(c.text))
		})
	}
}
