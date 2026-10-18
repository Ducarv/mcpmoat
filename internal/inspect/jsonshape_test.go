package inspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
)

// shapeBig is a limit that the small test inputs never reach.
const shapeBig = 1 << 30

// shapeUEsc is the start of a JSON unicode escape: a backslash and a "u".
// It is built with string concatenation so that the source holds no
// unicode escape that a tool could decode.
const shapeUEsc = "\\" + "u"

// shapeLimits returns jsonLimits with the given depth, values and
// stringBytes. It keeps the test tables short.
func shapeLimits(depth, values, stringBytes int) jsonLimits {
	return jsonLimits{depth: depth, values: values, stringBytes: stringBytes}
}

// shapeFeed writes in to c in chunks of chunk bytes and returns the first
// error. A chunk of 0 or less, or larger than in, writes in with one call.
func shapeFeed(c shapeChecker, in []byte, chunk int) error {
	if chunk <= 0 || chunk > len(in) {
		return c.write(in)
	}
	for len(in) > 0 {
		n := min(chunk, len(in))
		if err := c.write(in[:n]); err != nil {
			return err
		}
		in = in[n:]
	}
	return nil
}

// shapeErrText returns the text of err, or "" for a nil error. Two runs that
// fail on the same limit give the same text.
func shapeErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// shapeChunkSizes returns the chunk sizes to try for an input of n bytes:
// every size from 1 to n for short inputs, and a few sizes for long inputs,
// so that the loop stays fast.
func shapeChunkSizes(n int) []int {
	if n > 256 {
		return []int{1, 2, 7, 4096}
	}
	sizes := make([]int, 0, n)
	for i := 1; i <= n; i++ {
		sizes = append(sizes, i)
	}
	return sizes
}

// shapeCase is one row of the jsonShape and sseShape tables.
type shapeCase struct {
	name   string
	limits jsonLimits
	input  string
	// wantIn is "" when the input must pass. Else the input must fail with
	// an error that wraps errJSONTooComplex and whose text contains wantIn:
	// "levels", "values" or "bytes", which tells the limit that failed.
	wantIn string
}

// runShapeCase checks tc against a new checker from newChecker: first with
// one write of the whole input, then split at every byte boundary. The split
// runs must give the same result as the single write.
func runShapeCase(t *testing.T, newChecker func(jsonLimits) shapeChecker, tc shapeCase) {
	t.Helper()
	in := []byte(tc.input)
	whole := newChecker(tc.limits).write(in)
	switch {
	case tc.wantIn == "" && whole != nil:
		t.Fatalf("write(%.80q) error = %v, want nil", tc.input, whole)
	case tc.wantIn != "" && whole == nil:
		t.Fatalf("write(%.80q) error = nil, want an error about %s", tc.input, tc.wantIn)
	case tc.wantIn != "" && !errors.Is(whole, errJSONTooComplex):
		t.Fatalf("write(%.80q) error = %v, want errors.Is errJSONTooComplex", tc.input, whole)
	case tc.wantIn != "" && !strings.Contains(whole.Error(), tc.wantIn):
		t.Fatalf("write(%.80q) error = %v, want text with %q", tc.input, whole, tc.wantIn)
	}
	for _, size := range shapeChunkSizes(len(in)) {
		got := shapeFeed(newChecker(tc.limits), in, size)
		if shapeErrText(got) != shapeErrText(whole) {
			t.Fatalf("write(%.80q) in chunks of %d: error = %v, want %v (as one write)",
				tc.input, size, got, whole)
		}
	}
}

// jsonShapeCases are the table for jsonShape. FuzzJSONShape uses the inputs
// as seeds.
var jsonShapeCases = []shapeCase{
	// Depth.
	{name: "depth at limit", limits: shapeLimits(2, shapeBig, shapeBig), input: `[[1]]`},
	{name: "depth over limit", limits: shapeLimits(2, shapeBig, shapeBig), input: `[[[1]]]`, wantIn: "levels"},
	{name: "object depth at limit", limits: shapeLimits(3, shapeBig, shapeBig), input: `{"a":{"b":{}}}`},
	{name: "object depth over limit", limits: shapeLimits(2, shapeBig, shapeBig), input: `{"a":{"b":{}}}`, wantIn: "levels"},
	{name: "mixed depth at limit", limits: shapeLimits(2, shapeBig, shapeBig), input: `[{"a":1}]`},
	{name: "siblings do not add depth", limits: shapeLimits(2, shapeBig, shapeBig), input: `[[1],[2],[3]]`},
	{name: "deep sibling over limit", limits: shapeLimits(2, shapeBig, shapeBig), input: `[[1],[2],[[3]]]`, wantIn: "levels"},
	{name: "extra closers make no room", limits: shapeLimits(2, shapeBig, shapeBig), input: `]]]]}}[[[`, wantIn: "levels"},
	{name: "extra closers then depth at limit", limits: shapeLimits(2, shapeBig, shapeBig), input: `]]]]}}[[`},
	{name: "depth 0 allows scalars", limits: shapeLimits(0, shapeBig, shapeBig), input: `1 "a" true`},
	{name: "depth 0 refuses arrays", limits: shapeLimits(0, shapeBig, shapeBig), input: `[]`, wantIn: "levels"},

	// Values.
	{name: "values at limit", limits: shapeLimits(shapeBig, 3, shapeBig), input: `[1,2]`},
	{name: "values over limit", limits: shapeLimits(shapeBig, 3, shapeBig), input: `[1,2,3]`, wantIn: "values"},
	{name: "object key counts", limits: shapeLimits(shapeBig, 3, shapeBig), input: `{"a":1}`},
	{name: "object key over limit", limits: shapeLimits(shapeBig, 2, shapeBig), input: `{"a":1}`, wantIn: "values"},
	{name: "empty object counts", limits: shapeLimits(shapeBig, 0, shapeBig), input: `{}`, wantIn: "values"},
	{name: "empty objects at limit", limits: shapeLimits(shapeBig, 3, shapeBig), input: `[{},{}]`},
	{name: "empty objects over limit", limits: shapeLimits(shapeBig, 3, shapeBig), input: `[{},{},{}]`, wantIn: "values"},
	{name: "empty arrays over limit", limits: shapeLimits(shapeBig, 3, shapeBig), input: `[[],[],[]]`, wantIn: "values"},
	{name: "strings at limit", limits: shapeLimits(shapeBig, 3, shapeBig), input: `["a","b"]`},
	{name: "strings over limit", limits: shapeLimits(shapeBig, 2, shapeBig), input: `["a","b"]`, wantIn: "values"},
	{name: "empty string counts", limits: shapeLimits(shapeBig, 2, shapeBig), input: `["",""]`, wantIn: "values"},
	{name: "literals at limit", limits: shapeLimits(shapeBig, 4, shapeBig), input: `[true,false,null]`},
	{name: "literals over limit", limits: shapeLimits(shapeBig, 3, shapeBig), input: `[true,false,null]`, wantIn: "values"},
	{name: "number is one value", limits: shapeLimits(shapeBig, 3, shapeBig), input: `[-1.5e+10,0]`},
	{name: "numbers over limit", limits: shapeLimits(shapeBig, 2, shapeBig), input: `[-1.5e+10,0]`, wantIn: "values"},
	{name: "brackets in a string are not values", limits: shapeLimits(1, 2, shapeBig), input: `["[,{:}]"]`},
	{name: "garbage run counts", limits: shapeLimits(shapeBig, 2, shapeBig), input: `[abc def]`, wantIn: "values"},

	// String length.
	{name: "string at limit", limits: shapeLimits(shapeBig, shapeBig, 4), input: `"abcd"`},
	{name: "string over limit", limits: shapeLimits(shapeBig, shapeBig, 4), input: `"abcde"`, wantIn: "bytes"},
	{name: "string in array over limit", limits: shapeLimits(shapeBig, shapeBig, 4), input: `["ab","abcde"]`, wantIn: "bytes"},
	{name: "key over limit", limits: shapeLimits(shapeBig, shapeBig, 4), input: `{"abcde":1}`, wantIn: "bytes"},
	{name: "empty string with limit 0", limits: shapeLimits(shapeBig, shapeBig, 0), input: `""`},
	{name: "multi-byte UTF-8 counts bytes", limits: shapeLimits(shapeBig, shapeBig, 2), input: `"é"`},
	{name: "multi-byte UTF-8 over limit", limits: shapeLimits(shapeBig, shapeBig, 1), input: `"é"`, wantIn: "bytes"},
	{name: "unterminated string counts", limits: shapeLimits(shapeBig, shapeBig, 4), input: `"abcde`, wantIn: "bytes"},

	// Escapes.
	{name: "escaped quote counts raw bytes", limits: shapeLimits(shapeBig, shapeBig, 5), input: `"ab\"c"`},
	{name: "escaped quote over limit", limits: shapeLimits(shapeBig, shapeBig, 4), input: `"ab\"c"`, wantIn: "bytes"},
	{name: "escaped quote does not end the string", limits: shapeLimits(1, 1, shapeBig), input: `"\" [[[ "`},
	{name: "unterminated after escaped quote", limits: shapeLimits(1, 1, shapeBig), input: `"\"[[[[`},
	{name: "escaped backslash counts raw bytes", limits: shapeLimits(shapeBig, shapeBig, 2), input: `"\\"`},
	{name: "escaped backslash over limit", limits: shapeLimits(shapeBig, shapeBig, 1), input: `"\\"`, wantIn: "bytes"},
	{name: "escaped backslash then quote ends the string", limits: shapeLimits(1, shapeBig, shapeBig), input: `"\\" [[1]]`, wantIn: "levels"},
	{name: "escaped backslash then array", limits: shapeLimits(1, shapeBig, shapeBig), input: `"\\"[1]`},
	{name: "unicode escape counts raw bytes", limits: shapeLimits(shapeBig, shapeBig, 6), input: `"` + shapeUEsc + `0041"`},
	{name: "unicode escape over limit", limits: shapeLimits(shapeBig, shapeBig, 5), input: `"` + shapeUEsc + `0041"`, wantIn: "bytes"},
	{name: "unicode escaped quote does not end the string", limits: shapeLimits(1, 1, shapeBig), input: `"` + shapeUEsc + `0022[[["`},
	{name: "unicode escaped backslash is no escape", limits: shapeLimits(1, shapeBig, shapeBig), input: `"` + shapeUEsc + `005c" [[1]]`, wantIn: "levels"},

	// Number and literal runs.
	{name: "number run at limit", limits: shapeLimits(shapeBig, shapeBig, 5), input: `12345`},
	{name: "number run over limit", limits: shapeLimits(shapeBig, shapeBig, 4), input: `12345`, wantIn: "bytes"},
	{name: "number in array over limit", limits: shapeLimits(shapeBig, shapeBig, 5), input: `[123456]`, wantIn: "bytes"},
	{name: "long number run over limit", limits: shapeLimits(shapeBig, shapeBig, 64), input: "[" + strings.Repeat("9", 65) + "]", wantIn: "bytes"},
	{name: "literal over limit", limits: shapeLimits(shapeBig, shapeBig, 3), input: `true`, wantIn: "bytes"},
	{name: "literal at limit", limits: shapeLimits(shapeBig, shapeBig, 4), input: `null`},
	{name: "garbage run over limit", limits: shapeLimits(shapeBig, shapeBig, 5), input: `[abcdef]`, wantIn: "bytes"},
	{name: "runs end at whitespace", limits: shapeLimits(shapeBig, 3, 4), input: `[1234 5678]`},
	{name: "runs end at delimiters", limits: shapeLimits(shapeBig, shapeBig, 4), input: `[1234,5678,{"k":1234}]`},
	{name: "run ends at a quote", limits: shapeLimits(shapeBig, 1, 4), input: `1234"ab"`},

	// Whitespace, commas and colons.
	{name: "whitespace and commas do not count", limits: shapeLimits(1, 4, 1), input: "[ 1 ,\t2 ,\r\n 3 ]"},
	{name: "colons do not count", limits: shapeLimits(1, 5, 1), input: `{ "a" : 1 , "b" : 2 }`},
	{name: "long whitespace does not count", limits: shapeLimits(1, 1, 1), input: "[" + strings.Repeat(" \t\r\n", 300) + "]"},
	{name: "many commas do not count", limits: shapeLimits(1, 1, 1), input: `[,,,,,,,,,,::::]`},

	// Counters reset when a top-level value ends.
	{name: "two arrays each at limit", limits: shapeLimits(shapeBig, 3, shapeBig), input: `[1,2][3,4]`},
	{name: "one array with both", limits: shapeLimits(shapeBig, 3, shapeBig), input: `[1,2,3,4]`, wantIn: "values"},
	{name: "two objects each at limit", limits: shapeLimits(shapeBig, 3, shapeBig), input: `{"a":1}{"b":2}`},
	{name: "newline framed messages", limits: shapeLimits(1, 2, shapeBig), input: "[1]\n[2]\n[3]\n"},
	{name: "top-level strings", limits: shapeLimits(shapeBig, 1, 4), input: `"abcd" "efgh""ijkl"`},
	{name: "top-level numbers", limits: shapeLimits(shapeBig, 1, 3), input: `123 456 789`},
	{name: "top-level literals", limits: shapeLimits(shapeBig, 1, 5), input: `true false null`},
	{name: "top-level run then array", limits: shapeLimits(shapeBig, 2, shapeBig), input: `123[1]`},
	{name: "inner close does not reset", limits: shapeLimits(shapeBig, 4, shapeBig), input: `[[1,2][3,4]]`, wantIn: "values"},
	{name: "second message over limit", limits: shapeLimits(shapeBig, 3, shapeBig), input: `[1,2][3,4,5]`, wantIn: "values"},
	{name: "depth resets with the message", limits: shapeLimits(2, shapeBig, shapeBig), input: `[[1]][[2]]`},
}

func TestJSONShape(t *testing.T) {
	t.Parallel()
	newChecker := func(l jsonLimits) shapeChecker { return newJSONShape(l) }
	for _, tc := range jsonShapeCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runShapeCase(t, newChecker, tc)
		})
	}
}

// TestJSONShapeHugeRun checks a string and a number run far over the limit:
// the failure comes at the first byte over the limit, whatever the chunks.
func TestJSONShapeHugeRun(t *testing.T) {
	t.Parallel()
	newChecker := func(l jsonLimits) shapeChecker { return newJSONShape(l) }
	tests := []shapeCase{
		{name: "huge string", limits: shapeLimits(shapeBig, shapeBig, 1024), input: `"` + strings.Repeat("a", 1<<20) + `"`, wantIn: "bytes"},
		{name: "huge number", limits: shapeLimits(shapeBig, shapeBig, 1024), input: strings.Repeat("7", 1<<20), wantIn: "bytes"},
		{name: "many values", limits: shapeLimits(shapeBig, 1000, shapeBig), input: "[" + strings.Repeat("{},", 1<<15) + "{}]", wantIn: "values"},
		{name: "deep nesting", limits: shapeLimits(64, shapeBig, shapeBig), input: strings.Repeat("[", 1<<15), wantIn: "levels"},
		{name: "string just at limit", limits: shapeLimits(shapeBig, shapeBig, 1<<16), input: `"` + strings.Repeat("a", 1<<16) + `"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runShapeCase(t, newChecker, tc)
		})
	}
}

func TestJSONShapeStickyError(t *testing.T) {
	t.Parallel()
	s := newJSONShape(shapeLimits(1, shapeBig, shapeBig))
	first := s.write([]byte(`[[`))
	if !errors.Is(first, errJSONTooComplex) {
		t.Fatalf("write([[) error = %v, want errors.Is errJSONTooComplex", first)
	}
	s.reset()
	if err := s.write([]byte(`1`)); !errors.Is(err, first) {
		t.Errorf("write after reset error = %v, want the first error %v", err, first)
	}
	if err := s.writeByte('1'); !errors.Is(err, first) {
		t.Errorf("writeByte after reset error = %v, want the first error %v", err, first)
	}
	if err := s.write(nil); !errors.Is(err, first) {
		t.Errorf("write(nil) after failure error = %v, want the first error %v", err, first)
	}
}

func TestJSONShapeResetClearsState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		limits  jsonLimits
		before  string
		after   string
		wantErr bool
	}{
		// Without the reset, the depth would be 2.
		{name: "depth", limits: shapeLimits(1, shapeBig, shapeBig), before: `[`, after: `[`},
		// Without the reset, the 4 values together would go over 3.
		{name: "values", limits: shapeLimits(shapeBig, 3, shapeBig), before: `[1,`, after: `[2,3`},
		// Without the reset, "[[" would be bytes in the open string.
		{name: "open string", limits: shapeLimits(1, shapeBig, shapeBig), before: `"abc`, after: `[[`, wantErr: true},
		// Without the reset, '"' would be an escaped byte in the string.
		{name: "open escape", limits: shapeLimits(1, shapeBig, shapeBig), before: `"\`, after: `"" [[`, wantErr: true},
		// Without the reset, the run would be 6 bytes long.
		{name: "open run", limits: shapeLimits(shapeBig, shapeBig, 3), before: `[123`, after: `456`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newJSONShape(tt.limits)
			if err := s.write([]byte(tt.before)); err != nil {
				t.Fatalf("write(%q) error = %v, want nil", tt.before, err)
			}
			s.reset()
			err := s.write([]byte(tt.after))
			if (err != nil) != tt.wantErr {
				t.Errorf("write(%q) after reset error = %v, want error %v", tt.after, err, tt.wantErr)
			}
		})
	}
}

// shapeRandomInput returns a random input of up to 64 bytes. Most bytes come
// from the JSON and SSE syntax, so that the state machines reach all their
// states. The other bytes are any byte from src.
func shapeRandomInput(r *rand.Rand, src *rand.ChaCha8) []byte {
	const alphabet = "{}[]\"\\:, \t\r\n0123456789aeflnrstudx-+.Eé"
	in := make([]byte, r.IntN(65))
	// ChaCha8.Read fills in with random bytes and never fails.
	_, _ = src.Read(in)
	for i := range in {
		if r.IntN(8) != 0 {
			in[i] = alphabet[r.IntN(len(alphabet))]
		}
	}
	return in
}

// TestShapeGarbageNeverPanics feeds random bytes to jsonShape and sseShape.
// A panic fails the test. The error must also not depend on the chunks.
func TestShapeGarbageNeverPanics(t *testing.T) {
	t.Parallel()
	// A fixed seed makes every run test the same inputs, so a failure can
	// be repeated.
	src := rand.NewChaCha8([32]byte{101, 18})
	r := rand.New(src) //nolint:gosec // G404: test inputs, not a secret; a fixed seed keeps runs repeatable.
	checkers := map[string]func(jsonLimits) shapeChecker{
		"json": func(l jsonLimits) shapeChecker { return newJSONShape(l) },
		"sse":  func(l jsonLimits) shapeChecker { return newSSEShape(l) },
	}
	for i := range 2000 {
		in := shapeRandomInput(r, src)
		limits := shapeLimits(r.IntN(5), r.IntN(10), r.IntN(10))
		chunk := 1 + r.IntN(8)
		for kind, newChecker := range checkers {
			whole := newChecker(limits).write(in)
			if whole != nil && !errors.Is(whole, errJSONTooComplex) {
				t.Fatalf("%s input %d %q: error = %v, want errors.Is errJSONTooComplex", kind, i, in, whole)
			}
			parts := shapeFeed(newChecker(limits), in, chunk)
			if shapeErrText(parts) != shapeErrText(whole) {
				t.Fatalf("%s input %d %q in chunks of %d: error = %v, want %v", kind, i, in, chunk, parts, whole)
			}
		}
	}
}

// sseShapeCases are the table for sseShape. FuzzJSONShape also uses the
// inputs as seeds.
var sseShapeCases = []shapeCase{
	// Data lines.
	{name: "data with space", limits: shapeLimits(shapeBig, 3, shapeBig), input: "data: [1,2]\n\n"},
	{name: "data with space over limit", limits: shapeLimits(shapeBig, 2, shapeBig), input: "data: [1,2]\n\n", wantIn: "values"},
	{name: "data without space", limits: shapeLimits(shapeBig, 4, shapeBig), input: "data:[1,2,3]\n\n"},
	{name: "data without space over limit", limits: shapeLimits(shapeBig, 3, shapeBig), input: "data:[1,2,3]\n\n", wantIn: "values"},
	{name: "data depth over limit", limits: shapeLimits(2, shapeBig, shapeBig), input: "data: [[[1]]]\n\n", wantIn: "levels"},
	{name: "data string over limit", limits: shapeLimits(shapeBig, shapeBig, 4), input: "data: \"abcde\"\n\n", wantIn: "bytes"},
	{name: "colon in data value", limits: shapeLimits(3, shapeBig, shapeBig), input: "data: {\"a\":[[1]]}\n\n"},
	{name: "colon in data value over limit", limits: shapeLimits(2, shapeBig, shapeBig), input: "data: {\"a\":[[1]]}\n\n", wantIn: "levels"},
	{name: "data at end without newline", limits: shapeLimits(2, shapeBig, shapeBig), input: "data: [[[", wantIn: "levels"},
	{name: "empty data", limits: shapeLimits(1, 1, 1), input: "data:\ndata: \n\n"},

	// Multi-line data is one message.
	{name: "multi-line data at limit", limits: shapeLimits(shapeBig, 4, shapeBig), input: "data: [1,\ndata: 2,\ndata: 3]\n\n"},
	{name: "multi-line data over limit", limits: shapeLimits(shapeBig, 3, shapeBig), input: "data: [1,\ndata: 2,\ndata: 3]\n\n", wantIn: "values"},
	{name: "multi-line depth over limit", limits: shapeLimits(2, shapeBig, shapeBig), input: "data: [[\ndata: [1]]]\n\n", wantIn: "levels"},
	// The SDK joins the lines to "abc\ndef", 7 bytes. sseShape feeds the
	// untrimmed value and a '\n', 8 bytes. It must never count fewer.
	{name: "multi-line string never undercounts", limits: shapeLimits(shapeBig, shapeBig, 6), input: "data: \"abc\ndata: def\"\n\n", wantIn: "bytes"},
	{name: "multi-line string with fed bytes", limits: shapeLimits(shapeBig, shapeBig, 8), input: "data: \"abc\ndata: def\"\n\n"},
	// The SDK joins the lines to "[12\n34]": two numbers, three values.
	// Without the '\n' between the lines, sseShape would see one run.
	{name: "data line end splits a run", limits: shapeLimits(shapeBig, 2, shapeBig), input: "data:[12\ndata:34]\n\n", wantIn: "values"},
	{name: "data line end splits a run at limit", limits: shapeLimits(shapeBig, 3, 2), input: "data:[12\ndata:34]\n\n"},
	{name: "other field between data lines", limits: shapeLimits(shapeBig, 3, shapeBig), input: "data: [1,\nevent: x\nid: 7\n: note\ndata: 2]\n\n"},

	// Line ends as the SDK frames them.
	{name: "CRLF data", limits: shapeLimits(shapeBig, 3, shapeBig), input: "data: [1,2]\r\n\r\n"},
	{name: "CRLF data over limit", limits: shapeLimits(shapeBig, 2, shapeBig), input: "data: [1,2]\r\n\r\n", wantIn: "values"},
	{name: "CRLF event end resets", limits: shapeLimits(shapeBig, 3, shapeBig), input: "data: [1,2\r\n\r\ndata: [3,4\r\n\r\n"},
	{name: "CR CR LF line ends the event", limits: shapeLimits(shapeBig, 3, shapeBig), input: "data: [1,2\r\n\r\r\ndata: [3,4\r\n\r\n"},
	{name: "lone CR does not end a skipped line", limits: shapeLimits(2, shapeBig, shapeBig), input: "x: [[[\rdata: [[[\n\n"},
	{name: "lone CR does not end a data line", limits: shapeLimits(2, shapeBig, shapeBig), input: "data: [1]\rx: [[[\n\n", wantIn: "levels"},
	{name: "lone CR does not end the event", limits: shapeLimits(shapeBig, 3, shapeBig), input: "data: [1,2\n\rx\ndata: [3,4\n\n", wantIn: "values"},

	// Event end resets the counters.
	{name: "two events each under the limit", limits: shapeLimits(shapeBig, 3, shapeBig), input: "data: [1,2\n\ndata: [3,4\n\n"},
	{name: "one event with both", limits: shapeLimits(shapeBig, 3, shapeBig), input: "data: [1,2\ndata: [3,4\n\n", wantIn: "values"},
	{name: "depth resets per event", limits: shapeLimits(3, shapeBig, shapeBig), input: "data: [[[\n\ndata: [\n\n"},
	// Without the reset, "[[1]]" would be bytes in the open string.
	{name: "event end closes an open string", limits: shapeLimits(1, shapeBig, shapeBig), input: "data: \"abc\n\ndata: [[1]]\n\n", wantIn: "levels"},
	{name: "space line does not end the event", limits: shapeLimits(shapeBig, 3, shapeBig), input: "data: [1,2\n \ndata: [3,4\n\n", wantIn: "values"},
	{name: "event end at stream start", limits: shapeLimits(shapeBig, 3, shapeBig), input: "\n\n\r\ndata: [1,2]\n\n"},

	// Comments and other fields feed nothing.
	{name: "comment", limits: shapeLimits(1, 1, 1), input: ": [[[[[ \"abcdef\"\n\n"},
	{name: "comment that starts like data", limits: shapeLimits(1, 1, 1), input: ":data: [[[[\n\n"},
	{name: "event field", limits: shapeLimits(1, 1, 1), input: "event: [[[[\n\n"},
	{name: "id field", limits: shapeLimits(1, 1, 1), input: "id: [[[[\n\n"},
	{name: "retry field", limits: shapeLimits(1, 1, 1), input: "retry: [[[[\n\n"},
	{name: "longer name", limits: shapeLimits(1, 1, 1), input: "dataX: [[[[\n\n"},
	{name: "repeated name", limits: shapeLimits(1, 1, 1), input: "datadata: [[[[\n\n"},
	{name: "shorter name", limits: shapeLimits(1, 1, 1), input: "dat: [[[[\n\n"},
	{name: "prefixed name", limits: shapeLimits(1, 1, 1), input: "xdata: [[[[\n\n"},
	{name: "upper case name", limits: shapeLimits(1, 1, 1), input: "Data: [[[[\n\n"},
	{name: "space before name", limits: shapeLimits(1, 1, 1), input: " data: [[[[\n\n"},
	{name: "CR in name", limits: shapeLimits(1, 1, 1), input: "data\r: [[[[\n\n"},
	{name: "line without colon", limits: shapeLimits(1, 1, 1), input: "data [[[[\n\n"},
	{name: "name only", limits: shapeLimits(1, 1, 1), input: "data\n\n"},
	{name: "skipped line then data", limits: shapeLimits(1, shapeBig, 1), input: "event: [[[[\ndata: [[\n\n", wantIn: "levels"},
}

func TestSSEShape(t *testing.T) {
	t.Parallel()
	newChecker := func(l jsonLimits) shapeChecker { return newSSEShape(l) }
	for _, tc := range sseShapeCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runShapeCase(t, newChecker, tc)
		})
	}
}

// TestSSEShapeHugeNonData checks that a huge value of a field that is not
// data feeds nothing, even with the smallest limits.
func TestSSEShapeHugeNonData(t *testing.T) {
	t.Parallel()
	newChecker := func(l jsonLimits) shapeChecker { return newSSEShape(l) }
	huge := strings.Repeat(`[{"a":"`, 1<<17)
	tests := []shapeCase{
		{name: "huge event field", limits: shapeLimits(1, 1, 1), input: "event: " + huge + "\n\n"},
		{name: "huge comment", limits: shapeLimits(1, 1, 1), input: ": " + huge + "\r\n\r\n"},
		{name: "huge longer name", limits: shapeLimits(1, 1, 1), input: "data" + huge + ": " + huge + "\n\n"},
		{name: "huge line without colon", limits: shapeLimits(1, 1, 1), input: "data " + strings.Repeat("[", 1<<20) + "\n\n"},
		{name: "huge data", limits: shapeLimits(shapeBig, shapeBig, 1024), input: "data: \"" + strings.Repeat("a", 1<<20) + "\"\n\n", wantIn: "bytes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runShapeCase(t, newChecker, tc)
		})
	}
}

func TestSSEShapeStickyError(t *testing.T) {
	t.Parallel()
	s := newSSEShape(shapeLimits(1, shapeBig, shapeBig))
	first := s.write([]byte("data: [[\n"))
	if !errors.Is(first, errJSONTooComplex) {
		t.Fatalf("write error = %v, want errors.Is errJSONTooComplex", first)
	}
	// An event end resets the jsonShape counters, but not its error.
	if err := s.write([]byte("\n\n")); !errors.Is(err, first) {
		t.Errorf("write of an event end error = %v, want the first error %v", err, first)
	}
	if err := s.write([]byte("event: x\n")); !errors.Is(err, first) {
		t.Errorf("write of a skipped line error = %v, want the first error %v", err, first)
	}
}

// shapeTestRC is an io.ReadCloser for the shapeReader tests. Each Read
// returns at most the rest of the first chunk. After the chunks it returns
// io.EOF. It records the number of Read and Close calls.
type shapeTestRC struct {
	chunks   [][]byte
	reads    int
	closes   int
	closeErr error
}

func (r *shapeTestRC) Read(p []byte) (int, error) {
	r.reads++
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks[0] = r.chunks[0][n:]
	if len(r.chunks[0]) == 0 {
		r.chunks = r.chunks[1:]
	}
	return n, nil
}

func (r *shapeTestRC) Close() error {
	r.closes++
	return r.closeErr
}

// newShapeTestRC returns a shapeTestRC that returns in, split in chunks of
// chunk bytes.
func newShapeTestRC(in string, chunk int) *shapeTestRC {
	rc := &shapeTestRC{}
	for len(in) > 0 {
		n := min(chunk, len(in))
		rc.chunks = append(rc.chunks, []byte(in[:n]))
		in = in[n:]
	}
	return rc
}

// shapeReaderCtor is a shapeReader constructor: newJSONShapeReader or
// newSSEShapeReader.
type shapeReaderCtor func(rc io.ReadCloser, limits jsonLimits, onFail func(error) error) *shapeReader

func TestShapeReaderPassesThrough(t *testing.T) {
	t.Parallel()
	jsonIn := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","description":"Echo \"text\" back.","inputSchema":{"type":"object","properties":{"text":{"type":"string"}}}}]}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":[1,2.5,true,null]}}` + "\n"
	sseIn := ": keep-alive\r\n\r\n" +
		"event: message\r\nid: 1\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\r\ndata: \"result\":{\"tools\":[]}}\r\n\r\n" +
		"event: message\ndata:{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n"
	tests := []struct {
		name  string
		ctor  shapeReaderCtor
		input string
	}{
		{name: "json", ctor: newJSONShapeReader, input: jsonIn},
		{name: "sse", ctor: newSSEShapeReader, input: sseIn},
		{name: "json empty", ctor: newJSONShapeReader, input: ""},
		{name: "sse empty", ctor: newSSEShapeReader, input: ""},
	}
	for _, tt := range tests {
		for _, chunk := range []int{1, 3, 64, 1 << 20} {
			t.Run(fmt.Sprintf("%s/chunk %d", tt.name, chunk), func(t *testing.T) {
				t.Parallel()
				calls := 0
				onFail := func(err error) error {
					calls++
					return err
				}
				r := tt.ctor(newShapeTestRC(tt.input, chunk), defaultJSONLimits(), onFail)
				got, err := io.ReadAll(r)
				if err != nil {
					t.Fatalf("ReadAll() error = %v, want nil", err)
				}
				if string(got) != tt.input {
					t.Errorf("ReadAll() = %q, want %q", got, tt.input)
				}
				if r.exceeded() {
					t.Error("exceeded() = true, want false")
				}
				if calls != 0 {
					t.Errorf("onFail calls = %d, want 0", calls)
				}
			})
		}
	}
}

// TestShapeReaderKeepsReadError checks that Read returns the data and the
// error of the wrapped Read together and unchanged, as io.Reader allows.
func TestShapeReaderKeepsReadError(t *testing.T) {
	t.Parallel()
	r := newJSONShapeReader(io.NopCloser(iotest.DataErrReader(strings.NewReader(`[1]`))), shapeLimits(2, shapeBig, shapeBig), nil)
	buf := make([]byte, 16)
	n, err := r.Read(buf)
	if n != 3 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read() = %d, %v, want 3, io.EOF", n, err)
	}
	if string(buf[:n]) != `[1]` {
		t.Errorf("Read() data = %q, want %q", buf[:n], `[1]`)
	}

	// A violation in the last chunk replaces io.EOF and returns no data.
	r = newJSONShapeReader(io.NopCloser(iotest.DataErrReader(strings.NewReader(`[[[`))), shapeLimits(2, shapeBig, shapeBig), nil)
	n, err = r.Read(buf)
	if n != 0 || !errors.Is(err, errJSONTooComplex) {
		t.Fatalf("Read() = %d, %v, want 0 and errors.Is errJSONTooComplex", n, err)
	}
}

func TestShapeReaderViolation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		ctor   shapeReaderCtor
		chunks []string
	}{
		{name: "json", ctor: newJSONShapeReader, chunks: []string{`[1]`, `[[[`, `1]]]`}},
		{name: "sse", ctor: newSSEShapeReader, chunks: []string{"data: [1]\n\n", "data: [[[", "1]]]\n\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rc := &shapeTestRC{}
			for _, c := range tt.chunks {
				rc.chunks = append(rc.chunks, []byte(c))
			}
			r := tt.ctor(rc, shapeLimits(2, shapeBig, shapeBig), nil)
			buf := make([]byte, 64)

			n, err := r.Read(buf)
			if err != nil || string(buf[:n]) != tt.chunks[0] {
				t.Fatalf("first Read() = %q, %v, want %q, nil", buf[:n], err, tt.chunks[0])
			}
			if r.exceeded() {
				t.Fatal("exceeded() before the violation = true, want false")
			}

			n, err = r.Read(buf)
			if n != 0 {
				t.Errorf("Read() at the violation n = %d, want 0", n)
			}
			if !errors.Is(err, errJSONTooComplex) {
				t.Fatalf("Read() at the violation error = %v, want errors.Is errJSONTooComplex", err)
			}
			if !r.exceeded() {
				t.Error("exceeded() after the violation = false, want true")
			}

			readsBefore := rc.reads
			for i := range 3 {
				n2, err2 := r.Read(buf)
				if n2 != 0 || !errors.Is(err2, err) {
					t.Errorf("Read() %d after the violation = %d, %v, want 0, %v", i, n2, err2, err)
				}
			}
			if rc.reads != readsBefore {
				t.Errorf("wrapped Read calls after the violation = %d, want 0", rc.reads-readsBefore)
			}
		})
	}
}

func TestShapeReaderOnFail(t *testing.T) {
	t.Parallel()
	errRecorded := errors.New("recorded by the test")
	tests := []struct {
		name string
		ctor shapeReaderCtor
		in   string
		// ret is what onFail returns for its argument.
		ret func(error) error
		// check tells whether the Read error is right.
		check func(error) bool
	}{
		{
			name:  "json nil return keeps the shape error",
			ctor:  newJSONShapeReader,
			in:    `[[[`,
			ret:   func(error) error { return nil },
			check: func(err error) bool { return errors.Is(err, errJSONTooComplex) },
		},
		{
			name:  "json error replaces the shape error",
			ctor:  newJSONShapeReader,
			in:    `[[[`,
			ret:   func(error) error { return errRecorded },
			check: func(err error) bool { return errors.Is(err, errRecorded) && !errors.Is(err, errJSONTooComplex) },
		},
		{
			name:  "json wrapped error",
			ctor:  newJSONShapeReader,
			in:    `[[[`,
			ret:   func(err error) error { return fmt.Errorf("%w: %w", errRecorded, err) },
			check: func(err error) bool { return errors.Is(err, errRecorded) && errors.Is(err, errJSONTooComplex) },
		},
		{
			name:  "sse error replaces the shape error",
			ctor:  newSSEShapeReader,
			in:    "data: [[[\n\n",
			ret:   func(error) error { return errRecorded },
			check: func(err error) bool { return errors.Is(err, errRecorded) && !errors.Is(err, errJSONTooComplex) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			var got error
			onFail := func(err error) error {
				calls++
				got = err
				return tt.ret(err)
			}
			r := tt.ctor(newShapeTestRC(tt.in, 1), shapeLimits(2, shapeBig, shapeBig), onFail)
			buf := make([]byte, 8)
			var err error
			for range 64 {
				if _, err = r.Read(buf); err != nil {
					break
				}
			}
			if !tt.check(err) {
				t.Fatalf("Read() error = %v, not the expected error", err)
			}
			for range 3 {
				if _, err2 := r.Read(buf); !errors.Is(err2, err) {
					t.Errorf("later Read() error = %v, want %v", err2, err)
				}
			}
			if calls != 1 {
				t.Errorf("onFail calls = %d, want 1", calls)
			}
			if !errors.Is(got, errJSONTooComplex) {
				t.Errorf("onFail argument = %v, want errors.Is errJSONTooComplex", got)
			}
			if !r.exceeded() {
				t.Error("exceeded() = false, want true")
			}
		})
	}
}

func TestShapeReaderClose(t *testing.T) {
	t.Parallel()
	errClose := errors.New("close failed")
	tests := []struct {
		name     string
		ctor     shapeReaderCtor
		in       string
		closeErr error
	}{
		{name: "json nil", ctor: newJSONShapeReader, in: `[1]`},
		{name: "json error", ctor: newJSONShapeReader, in: `[1]`, closeErr: errClose},
		{name: "sse error", ctor: newSSEShapeReader, in: "data: [1]\n\n", closeErr: errClose},
		{name: "json after violation", ctor: newJSONShapeReader, in: `[[[[`, closeErr: errClose},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rc := newShapeTestRC(tt.in, 1<<10)
			rc.closeErr = tt.closeErr
			r := tt.ctor(rc, shapeLimits(2, shapeBig, shapeBig), nil)
			_, _ = io.ReadAll(r)
			if err := r.Close(); !errors.Is(err, tt.closeErr) {
				t.Errorf("Close() error = %v, want %v", err, tt.closeErr)
			}
			if rc.closes != 1 {
				t.Errorf("wrapped Close calls = %d, want 1", rc.closes)
			}
		})
	}
}

// TestShapeReaderExceededConcurrent calls exceeded from another goroutine
// while Read runs. The race detector (go test -race) fails the test if the
// flag is not safe for concurrent use.
func TestShapeReaderExceededConcurrent(t *testing.T) {
	t.Parallel()
	r := newJSONShapeReader(newShapeTestRC(strings.Repeat("[1]", 200)+"[[[", 2), shapeLimits(2, shapeBig, shapeBig), nil)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for !r.exceeded() {
			select {
			case <-done:
				return
			default:
				runtime.Gosched()
			}
		}
	})
	_, err := io.ReadAll(r)
	close(done)
	wg.Wait()
	if !errors.Is(err, errJSONTooComplex) {
		t.Fatalf("ReadAll() error = %v, want errors.Is errJSONTooComplex", err)
	}
	if !r.exceeded() {
		t.Error("exceeded() = false, want true")
	}
}

// shapeTokenStats returns the number of JSON values in data and its deepest
// nesting, as encoding/json sees them. Closing brackets are not values.
// ok is false when the decoder fails.
func shapeTokenStats(data []byte) (values, maxDepth int, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	// UseNumber keeps a number such as 1e999 as text, so the decoder does
	// not fail on it.
	dec.UseNumber()
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return values, maxDepth, true
		}
		if err != nil {
			return 0, 0, false
		}
		// tok.(json.Delim) is a type assertion: isDelim is true when the
		// dynamic type of tok is json.Delim, a bracket or a brace.
		if d, isDelim := tok.(json.Delim); isDelim && (d == '}' || d == ']') {
			depth--
			continue
		} else if isDelim {
			depth++
			maxDepth = max(maxDepth, depth)
		}
		values++
	}
}

// FuzzJSONShape checks two properties of jsonShape (and that sseShape never
// panics):
//
//  1. For any input and any chunking, write never panics, and the result
//     does not depend on the chunks.
//  2. For valid JSON, jsonShape never counts fewer values or levels than
//     encoding/json builds: with the limits one below the real count, the
//     input fails. With the limits at the real count, it passes.
//
// Run it with: go test -run '^$' -fuzz=FuzzJSONShape -fuzztime=30s ./internal/inspect/
func FuzzJSONShape(f *testing.F) {
	for _, tc := range jsonShapeCases {
		f.Add([]byte(tc.input), uint8(1))
	}
	for _, tc := range sseShapeCases {
		f.Add([]byte(tc.input), uint8(3))
	}
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","inputSchema":{"type":"object"}}]}}`), uint8(7))
	f.Add([]byte(`[1e999, -0.0, "`+shapeUEsc+`d800", "`+shapeUEsc+`00e9"]`), uint8(2))

	small := shapeLimits(3, 8, 8)
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8) {
		// Property 1.
		whole := newJSONShape(small).write(data)
		if whole != nil && !errors.Is(whole, errJSONTooComplex) {
			t.Fatalf("write(%q) error = %v, want errors.Is errJSONTooComplex", data, whole)
		}
		parts := shapeFeed(newJSONShape(small), data, int(chunk))
		if shapeErrText(parts) != shapeErrText(whole) {
			t.Fatalf("write(%q) in chunks of %d: error = %v, want %v", data, chunk, parts, whole)
		}
		_ = shapeFeed(newSSEShape(small), data, int(chunk))

		// Property 2.
		if !json.Valid(data) {
			return
		}
		values, depth, ok := shapeTokenStats(data)
		if !ok {
			return
		}
		long := len(data) + 1
		if err := newJSONShape(shapeLimits(depth, values, long)).write(data); err != nil {
			t.Fatalf("valid %q with values %d and depth %d at the limits: error = %v, want nil", data, values, depth, err)
		}
		if err := newJSONShape(shapeLimits(shapeBig, values-1, long)).write(data); !errors.Is(err, errJSONTooComplex) {
			t.Fatalf("valid %q with %d values and limit %d: error = %v, want errJSONTooComplex", data, values, values-1, err)
		}
		if depth > 0 {
			if err := newJSONShape(shapeLimits(depth-1, shapeBig, long)).write(data); !errors.Is(err, errJSONTooComplex) {
				t.Fatalf("valid %q with depth %d and limit %d: error = %v, want errJSONTooComplex", data, depth, depth-1, err)
			}
		}
	})
}
