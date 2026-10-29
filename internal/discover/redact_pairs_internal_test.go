package discover

import (
	"slices"
	"strings"
	"testing"
)

// TestQuotedSpan pins how quotedSpan reads a quoted value: the span with
// its quotes, the text between them and that text with its escapes removed.
func TestQuotedSpan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in                 string
		span, inner, plain string
	}{
		{in: `''`, span: `''`, inner: ``, plain: ``},
		{in: `'a b' c`, span: `'a b'`, inner: `a b`, plain: `a b`},
		{in: `"a;b",x`, span: `"a;b"`, inner: `a;b`, plain: `a;b`},
		{in: `'it\'s' x`, span: `'it\'s'`, inner: `it\'s`, plain: `it's`},
		{in: `"a\\b"`, span: `"a\\b"`, inner: `a\\b`, plain: `a\b`},
		{in: `'it''s' x`, span: `'it''s'`, inner: `it''s`, plain: `it's`},
		{in: `"a""b"`, span: `"a""b"`, inner: `a""b`, plain: `a"b`},
		{in: `"a'b"`, span: `"a'b"`, inner: `a'b`, plain: `a'b`},
		// No closing quote: the value runs to the end.
		{in: `'a b`, span: `'a b`, inner: `a b`, plain: `a b`},
		// A "\" at the very end is dropped from plain.
		{in: `'a\`, span: `'a\`, inner: `a\`, plain: `a`},
		{in: `'`, span: `'`, inner: ``, plain: ``},
	}
	for _, tt := range tests {
		span, inner, plain := quotedSpan(tt.in)
		if span != tt.span || inner != tt.inner || plain != tt.plain {
			t.Errorf("quotedSpan(%q) = (%q, %q, %q), want (%q, %q, %q)", tt.in, span, inner, plain, tt.span, tt.inner, tt.plain)
		}
	}
}

// TestPairKey pins which key pairKey finds in front of a "=" or a ":".
func TestPairKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		before, want string
	}{
		{before: "", want: ""},
		{before: "  ", want: ""},
		{before: "Server=h;Password", want: "Password"},
		{before: "host=h password ", want: "password"},
		{before: "--password", want: "--password"},
		{before: `{"token"`, want: "token"},
		{before: `{"a":"x","api key" `, want: "api key"},
		{before: `'pwd'`, want: "pwd"},
		{before: `x"`, want: ""}, // no quote opens the key
		{before: "a;", want: ""},
	}
	for _, tt := range tests {
		if got := pairKey(tt.before); got != tt.want {
			t.Errorf("pairKey(%q) = %q, want %q", tt.before, got, tt.want)
		}
	}
}

// TestSecretPairValues pins the values of secretPairValues for the formats
// that it reads.
func TestSecretPairValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want []string
	}{
		{in: "", want: nil},
		{in: "host=localhost dbname=production user=postgres", want: nil},
		{in: "password=", want: nil},
		{in: "password=''", want: nil},
		{in: "host=db password='a b' user=x", want: []string{"'a b'", "a b"}},
		{in: "host=db password = 'a b'", want: []string{"'a b'", "a b"}},
		{in: "host=db password=ab user=x", want: []string{"ab"}},
		{in: `Server=h;Password="a;b";User=x`, want: []string{`"a;b"`, "a;b"}},
		{in: "Server=h;Password=a b c;User=x", want: []string{"a", "a b c"}},
		{in: "Server=h;Password=a:b,c;", want: []string{"a:b,c"}},
		{in: `{"token":"a:b,c","user":"u"}`, want: []string{`"a:b,c"`, "a:b,c"}},
		{in: `{"token": "a\"b"}`, want: []string{`"a\"b"`, `a\"b`, `a"b`}},
		{in: `token: 'a b'`, want: []string{"'a b'", "a b"}},
		// After a ":", a value with no quotes is read by other code.
		{in: "token:abc", want: nil},
		{in: `{"pin":1234}`, want: nil},
		// A plain key gives nothing, also with a quoted value.
		{in: `{"user":"a b"}`, want: nil},
		{in: "host='my db'", want: nil},
	}
	for _, tt := range tests {
		if got := secretPairValues(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("secretPairValues(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestSecretPairValuesLinear checks that the total length of the values of
// secretPairValues stays linear in the length of the text, also for text
// with many secret-like keys. A caller searches for each value in other
// text, so a quadratic total would make that search slow (NFR-03).
func TestSecretPairValuesLinear(t *testing.T) {
	t.Parallel()

	const n = 20000
	texts := []string{
		strings.Repeat("password=", n),
		strings.Repeat("password=a ", n) + ";",
		strings.Repeat("password=a;", n),
		strings.Repeat("password = ", n),
		strings.Repeat(`"token":"`, n),
		strings.Repeat(`"token":"a",`, n),
		strings.Repeat(`'key'=`, n),
		"password='" + strings.Repeat(`a\'`, n),
	}
	for _, s := range texts {
		total := 0
		for _, v := range secretPairValues(s) {
			total += len(v)
		}
		if total > 4*len(s) {
			t.Errorf("secretPairValues(%d bytes of %q...) gives %d bytes of values, want at most %d", len(s), s[:12], total, 4*len(s))
		}
	}
}
