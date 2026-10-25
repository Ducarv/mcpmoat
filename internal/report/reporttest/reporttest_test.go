package reporttest_test

import (
	"testing"

	"github.com/Ducarv/mcpmoat/internal/report/reporttest"
)

// TestUnsafeBytes checks which raw bytes UnsafeBytes reports. The unsafe
// runes are written as Go escapes, so the source holds no raw control
// character.
func TestUnsafeBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want int // number of problems
	}{
		{name: "plain JSON with newlines and spaces", in: "{\n  \"a\": \"b c\"\n}\n"},
		{name: "printable non-ASCII", in: "caf\u00e9 \u4e16"},
		{name: "escaped forms are safe", in: `"\u001b \u202e \u00a0"`},
		{name: "ESC", in: "a\x1bb", want: 1},
		{name: "tab", in: "a\tb", want: 1},
		{name: "DEL", in: "a\x7fb", want: 1},
		{name: "C1 CSI", in: "a\u009bb", want: 1},
		{name: "bidi override", in: "a\u202eb", want: 1},
		{name: "zero-width space", in: "a\u200bb", want: 1},
		{name: "tag character", in: "a\U000e0041b", want: 1},
		{name: "invalid UTF-8", in: "a\xffb", want: 1},
		{name: "two problems", in: "\x1b\u202e", want: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := reporttest.UnsafeBytes([]byte(tt.in)); len(got) != tt.want {
				t.Errorf("UnsafeBytes(%q) = %q, want %d problems", tt.in, got, tt.want)
			}
		})
	}
}

// TestSchema checks that the schema file of the current version loads and
// resolves from this package, one level deeper than the other callers.
func TestSchema(t *testing.T) {
	t.Parallel()
	if reporttest.Schema(t) == nil {
		t.Fatal("Schema() = nil")
	}
}
