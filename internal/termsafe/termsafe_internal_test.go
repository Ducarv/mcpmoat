package termsafe

import "testing"

// This file tests the unexported cutRunes. The other tests use only the
// exported API, in package termsafe_test.

func TestCutRunes(t *testing.T) {
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, cut := cutRunes(tt.in, tt.n)
			if got != tt.want || cut != tt.wantCut {
				t.Errorf("cutRunes(%q, %d) = %q, %v, want %q, %v", tt.in, tt.n, got, cut, tt.want, tt.wantCut)
			}
		})
	}
}
