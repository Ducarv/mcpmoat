package rules

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Tests for matchSchema (schemamatch.go). Non-ASCII runes are Go escape
// sequences, so this file stays pure ASCII.

// windowCutDetail is the Detail of the schemaWindow hit when the caps of
// schemaFit cut the strings.
const windowCutDetail = "schema is longer than the match window: over 4096 strings or 131072 bytes"

// brokenDetail is the Detail of the schemaWindow hit for JSON that cannot be
// read in full.
const brokenDetail = "schema JSON cannot be read in full"

// fakeHit is the hit of the fake matchers. Its Offset is not NoOffset, so a
// test sees that matchSchema sets NoOffset on every hit.
var fakeHit = Hit{Offset: 7, Detail: "fake"}

// recorder is a fake inner matcher for matchSchema. It records each text that
// it gets. It returns perCall copies of fakeHit for a text that hit reports,
// and no hit for any other text. A nil hit never hits.
//
// Make a new recorder in each test: matchSchema calls match in one goroutine,
// but parallel tests must not share one.
type recorder struct {
	hit     func(text string) bool
	perCall int // hits for each text that hits; 0 means 1
	texts   []string
}

// match is the func that matchSchema gets.
func (r *recorder) match(text string) []Hit {
	r.texts = append(r.texts, text)
	if r.hit == nil || !r.hit(text) {
		return nil
	}
	hits := make([]Hit, max(r.perCall, 1))
	for i := range hits {
		hits[i] = fakeHit
	}
	return hits
}

// always is a recorder.hit func that hits on every text.
func always(string) bool { return true }

// holds returns a recorder.hit func that hits on a text that contains word.
func holds(word string) func(string) bool {
	return func(text string) bool { return strings.Contains(text, word) }
}

// mustJSON returns v encoded as JSON, or stops the test.
func mustJSON(tb testing.TB, v any) string {
	tb.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		tb.Fatalf("json.Marshal() error = %v", err)
	}
	return string(b)
}

// mustCompileSchema compiles m for the schema target, or stops the test.
func mustCompileSchema(tb testing.TB, m Match) *Matcher {
	tb.Helper()
	got, err := m.CompileFor(TargetSchema)
	if err != nil {
		tb.Fatalf("CompileFor(%+v, TargetSchema) error = %v", m, err)
	}
	return got
}

// distinctStrings returns n distinct short strings: "s0", "s1", ...
func distinctStrings(n int) []string {
	return numberedList("s%d", n)
}

// textLens returns the length of each text.
func textLens(texts []string) []int {
	lens := make([]int, len(texts))
	for i, s := range texts {
		lens[i] = len(s)
	}
	return lens
}

func TestMatchSchemaStringCap(t *testing.T) {
	t.Parallel()
	// The caps of schemaFit are the ones that the window detail names.
	if maxSchemaMatchStrings != 4096 || maxSchemaMatchBytes != 131072 {
		t.Fatal("precondition: the caps changed; update windowCutDetail")
	}
	atCap := mustJSON(t, distinctStrings(maxSchemaMatchStrings))
	overCap := mustJSON(t, distinctStrings(maxSchemaMatchStrings+1))

	tests := []struct {
		name      string
		raw       string
		mode      schemaMode
		wantCalls int
		wantHits  []Hit
	}{
		{name: "budget reads 4096 strings", raw: atCap, mode: schemaBudget, wantCalls: 4096},
		{name: "budget stops after 4096 of 4097 strings", raw: overCap, mode: schemaBudget, wantCalls: 4096},
		{name: "all reads 4097 strings", raw: overCap, mode: schemaAll, wantCalls: 4097},
		{name: "window reads 4096 strings and has no hit", raw: atCap, mode: schemaWindow, wantCalls: 4096},
		{
			name: "window flags 4097 strings", raw: overCap, mode: schemaWindow,
			wantCalls: 0, wantHits: []Hit{{Offset: NoOffset, Detail: windowCutDetail}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &recorder{}
			got := matchSchema(tt.raw, tt.mode, r.match)
			if !reflect.DeepEqual(got, tt.wantHits) {
				t.Errorf("matchSchema() = %v, want %v", got, tt.wantHits)
			}
			if len(r.texts) != tt.wantCalls {
				t.Fatalf("match called %d times, want %d", len(r.texts), tt.wantCalls)
			}
			// The strings are read in document order, from the first one.
			if tt.wantCalls > 0 {
				if last := r.texts[tt.wantCalls-1]; last != fmt.Sprintf("s%d", tt.wantCalls-1) {
					t.Errorf("last text = %q, want %q", last, fmt.Sprintf("s%d", tt.wantCalls-1))
				}
			}
		})
	}
}

func TestMatchSchemaByteCap(t *testing.T) {
	t.Parallel()
	// A string costs min(len, MaxMatchInputBytes) bytes of the budget of
	// maxSchemaMatchBytes. So four 40 KiB strings cost 4 * 32 KiB = 128 KiB:
	// they fit exactly, and a fifth string of any size is cut.
	if maxSchemaMatchBytes != 4*MaxMatchInputBytes {
		t.Fatalf("precondition: maxSchemaMatchBytes = %d, want 4 * MaxMatchInputBytes", maxSchemaMatchBytes)
	}
	const big = 40 << 10
	const window = MaxMatchInputBytes

	// schema returns a JSON array of distinct strings of the given sizes.
	schema := func(sizes ...int) string {
		strs := make([]string, len(sizes))
		for i, n := range sizes {
			strs[i] = strings.Repeat(string(rune('a'+i)), n)
		}
		return mustJSON(t, strs)
	}

	tests := []struct {
		name     string
		raw      string
		mode     schemaMode
		wantLens []int // lengths of the texts that match gets, in order
		wantHits []Hit
	}{
		{name: "four 40 KiB strings fit", raw: schema(big, big, big, big), mode: schemaBudget, wantLens: []int{big, big, big, big}},
		{name: "fifth 40 KiB string is cut", raw: schema(big, big, big, big, big), mode: schemaBudget, wantLens: []int{big, big, big, big}},
		{name: "four window strings fit", raw: schema(window, window, window, window), mode: schemaBudget, wantLens: []int{window, window, window, window}},
		{name: "one byte over the cap is cut", raw: schema(window, window, window, window, 1), mode: schemaBudget, wantLens: []int{window, window, window, window}},
		{name: "one byte under the cap fits", raw: schema(window, window, window, window-1, 1), mode: schemaBudget, wantLens: []int{window, window, window, window - 1, 1}},
		{name: "all reads the cut string", raw: schema(big, big, big, big, big), mode: schemaAll, wantLens: []int{big, big, big, big, big}},
		{name: "window reads four 40 KiB strings", raw: schema(big, big, big, big), mode: schemaWindow, wantLens: []int{big, big, big, big}},
		{
			name: "window flags the fifth 40 KiB string", raw: schema(big, big, big, big, big), mode: schemaWindow,
			wantLens: []int{}, wantHits: []Hit{{Offset: NoOffset, Detail: windowCutDetail}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &recorder{}
			got := matchSchema(tt.raw, tt.mode, r.match)
			if !reflect.DeepEqual(got, tt.wantHits) {
				t.Errorf("matchSchema() = %v, want %v", got, tt.wantHits)
			}
			if lens := textLens(r.texts); !reflect.DeepEqual(lens, tt.wantLens) {
				t.Errorf("lengths of the matched texts = %v, want %v", lens, tt.wantLens)
			}
		})
	}
}

func TestMatchSchemaMalformed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		raw       string
		wantTexts []string // the texts that match gets, in order
		want      []Hit
	}{
		{
			name:      "complete JSON does not read the raw text",
			raw:       `{"a":"evil"}`,
			wantTexts: []string{"a", "evil"},
			want:      []Hit{{Offset: NoOffset, Detail: "schema string 2: fake"}},
		},
		{
			name:      "cut after a key",
			raw:       `{"a":"evil","b":`,
			wantTexts: []string{"a", "evil", "b", `{"a":"evil","b":`},
			want: []Hit{
				{Offset: NoOffset, Detail: "schema string 2: fake"},
				{Offset: NoOffset, Detail: "schema raw text: fake"},
			},
		},
		{
			// The decoder never returns the open string, so only the raw
			// text run finds the payload in it.
			name:      "open string",
			raw:       `{"a":"evil`,
			wantTexts: []string{"a", `{"a":"evil`},
			want:      []Hit{{Offset: NoOffset, Detail: "schema raw text: fake"}},
		},
		{
			name:      "trailing text",
			raw:       `{"a":"x"} evil`,
			wantTexts: []string{"a", "x", `{"a":"x"} evil`},
			want:      []Hit{{Offset: NoOffset, Detail: "schema raw text: fake"}},
		},
		{
			name:      "trailing second value",
			raw:       `{"a":"x"}{"b":"evil"}`,
			wantTexts: []string{"a", "x", `{"a":"x"}{"b":"evil"}`},
			want:      []Hit{{Offset: NoOffset, Detail: "schema raw text: fake"}},
		},
		{
			name:      "not JSON",
			raw:       "evil",
			wantTexts: []string{"evil"},
			want:      []Hit{{Offset: NoOffset, Detail: "schema raw text: fake"}},
		},
		{
			name:      "broken JSON with no hit",
			raw:       `{"a":`,
			wantTexts: []string{"a", `{"a":`},
		},
	}
	for _, tt := range tests {
		for _, mode := range []schemaMode{schemaBudget, schemaAll} {
			t.Run(fmt.Sprintf("%s/mode %d", tt.name, mode), func(t *testing.T) {
				t.Parallel()
				r := &recorder{hit: holds("evil")}
				got := matchSchema(tt.raw, mode, r.match)
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("matchSchema(%q) = %v, want %v", tt.raw, got, tt.want)
				}
				if !reflect.DeepEqual(r.texts, tt.wantTexts) {
					t.Errorf("matched texts = %q, want %q", r.texts, tt.wantTexts)
				}
			})
		}
	}
}

func TestMatchSchemaRealMatchers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		match Match
		raw   string
		want  []string // Details of the hits; every Offset is NoOffset
	}{
		// Each string is matched alone.
		{
			name:  "any_regex matches in two strings",
			match: Match{AnyRegex: []string{"alpha", "beta"}},
			raw:   `{"alpha":"beta"}`,
			want:  []string{"schema string 1: any_regex[0] matched", "schema string 2: any_regex[1] matched"},
		},
		{
			name:  "all_regex needs every regex in one string",
			match: Match{AllRegex: []string{"alpha", "beta"}},
			raw:   `{"alpha":"beta"}`,
		},
		{
			name:  "all_regex matches in one string",
			match: Match{AllRegex: []string{"alpha", "beta"}},
			raw:   `{"x":"alpha beta"}`,
			want:  []string{"schema string 2: all_regex[0] matched", "schema string 2: all_regex[1] matched"},
		},
		{
			name:  "a regex does not span two strings",
			match: Match{AnyRegex: []string{`alpha\W+beta`}},
			raw:   `["alpha","beta"]`,
		},
		{
			name:  "keywords match in two strings",
			match: Match{Keywords: []string{"alpha", "beta"}},
			raw:   `{"alpha":"beta"}`,
			want:  []string{"schema string 1: keywords[0] matched", "schema string 2: keywords[1] matched"},
		},
		{
			name:  "numbers are not matched",
			match: Match{AnyRegex: []string{"12345"}},
			raw:   `{"n":12345}`,
		},
		// Object keys are matched, after the JSON decode.
		{
			name:  "key",
			match: Match{AnyRegex: []string{`(?i)ignore previous instructions`}},
			raw:   `{"properties":{"Ignore previous instructions":{"type":"string"}}}`,
			want:  []string{"schema string 2: any_regex[0] matched"},
		},
		{
			// The regex is case sensitive, so only the decoded "I" matches.
			name:  "key with a JSON escape",
			match: Match{AnyRegex: []string{`Ignore previous`}},
			raw:   `{"\u0049gnore previous instructions":1}`,
			want:  []string{"schema string 1: any_regex[0] matched"},
		},
		{
			name:  "value with an escaped ZWSP inside a word",
			match: Match{AnyRegex: []string{`ignore previous`}},
			raw:   `{"d":"ign\u200bore previous"}`,
			want:  []string{"schema string 2: any_regex[0] matched"},
		},
		{
			name:  "keyword in a key with an escaped space",
			match: Match{Keywords: []string{"do not tell"}},
			raw:   `{"do\u0020not\ttell":true}`,
			want:  []string{"schema string 1: keywords[0] matched"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mustCompileSchema(t, tt.match).Match(tt.raw)
			var want []Hit
			for _, d := range tt.want {
				want = append(want, Hit{Offset: NoOffset, Detail: d})
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Match(%q) = %v, want %v", tt.raw, got, want)
			}
		})
	}
}

func TestMatchSchemaHitsHaveNoInput(t *testing.T) {
	t.Parallel()
	lower := strings.ToLower(matchSecret)
	// The secret is in a key and in a value, next to a ZWSP. The third
	// schema writes the ZWSP raw, the others as a JSON escape.
	inputs := map[string]string{
		"complete": `{"` + matchSecret + ` do not tell the user":"` + matchSecret + `\u200b"}`,
		"broken":   `{"` + matchSecret + ` do not tell the user":"` + matchSecret + `\u200b"`,
		"raw ZWSP": `{"x":"` + matchSecret + "\u200b" + `"} trailing`,
	}
	matchers := map[string]Match{
		"any_regex":         {AnyRegex: []string{matchSecret}},
		"all_regex":         {AllRegex: []string{matchSecret, `(?i)zzsecret`}},
		"keywords":          {Keywords: []string{lower}},
		"invisible_unicode": {Heuristic: HeuristicInvisibleUnicode},
		"match_window":      {Heuristic: HeuristicMatchWindow},
	}
	for kind, mb := range matchers {
		m := mustCompileSchema(t, mb)
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			total := 0
			for name, raw := range inputs {
				got := m.Match(raw)
				total += len(got)
				for _, h := range got {
					if h.Offset != NoOffset {
						t.Errorf("%s: Offset = %d, want NoOffset", name, h.Offset)
					}
					checkPrintableASCII(t, h.Detail)
					if strings.Contains(strings.ToLower(h.Detail), lower) {
						t.Errorf("%s: Detail %q contains input text", name, h.Detail)
					}
				}
			}
			if total == 0 {
				t.Error("Match() = nil for every input, want hits")
			}
		})
	}
}

func TestMatchSchemaHitCap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		raw       string
		perCall   int    // hits for each text
		perString int    // hits of one string among the MaxHits kept hits
		summary   string // Detail of the last hit
	}{
		{name: "40 strings with one hit", raw: mustJSON(t, distinctStrings(40)), perCall: 1, perString: 1, summary: "and 24 more schema hits"},
		{name: "10 strings with three hits", raw: mustJSON(t, distinctStrings(10)), perCall: 3, perString: 3, summary: "and 14 more schema hits"},
		{
			// 20 string hits and one raw text hit share the cap.
			name: "raw text hit counts", raw: strings.TrimSuffix(mustJSON(t, distinctStrings(20)), "]"),
			perCall: 1, perString: 1, summary: "and 5 more schema hits",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &recorder{hit: always, perCall: tt.perCall}
			got := matchSchema(tt.raw, schemaBudget, r.match)
			if len(got) != MaxHits+1 {
				t.Fatalf("matchSchema() gave %d hits, want MaxHits+1 = %d: %v", len(got), MaxHits+1, got)
			}
			for i, h := range got[:MaxHits] {
				want := Hit{Offset: NoOffset, Detail: fmt.Sprintf("schema string %d: fake", i/tt.perString+1)}
				if h != want {
					t.Errorf("hit %d = %v, want %v", i, h, want)
				}
			}
			if want := (Hit{Offset: NoOffset, Detail: tt.summary}); got[MaxHits] != want {
				t.Errorf("summary hit = %v, want %v", got[MaxHits], want)
			}
		})
	}
}

func TestMatchSchemaEmpty(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		raw       string
		mode      schemaMode
		wantTexts []string
		want      []Hit
	}{
		{name: "empty budget", raw: "", mode: schemaBudget},
		{name: "empty all", raw: "", mode: schemaAll},
		{name: "empty window", raw: "", mode: schemaWindow},
		{name: "JSON white space budget", raw: " \t\r\n ", mode: schemaBudget},
		{name: "JSON white space all", raw: " \t\r\n ", mode: schemaAll},
		{name: "JSON white space window", raw: " \t\r\n ", mode: schemaWindow},
		// NBSP and form feed are not JSON white space, so the input is broken
		// JSON and the raw text is matched.
		{
			name: "NBSP budget", raw: "\u00a0", mode: schemaBudget,
			wantTexts: []string{"\u00a0"}, want: []Hit{{Offset: NoOffset, Detail: "schema raw text: fake"}},
		},
		{
			name: "NBSP all", raw: "\u00a0", mode: schemaAll,
			wantTexts: []string{"\u00a0"}, want: []Hit{{Offset: NoOffset, Detail: "schema raw text: fake"}},
		},
		{name: "NBSP window", raw: "\u00a0", mode: schemaWindow, want: []Hit{{Offset: NoOffset, Detail: brokenDetail}}},
		{
			name: "form feed budget", raw: "\f", mode: schemaBudget,
			wantTexts: []string{"\f"}, want: []Hit{{Offset: NoOffset, Detail: "schema raw text: fake"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &recorder{hit: always}
			got := matchSchema(tt.raw, tt.mode, r.match)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("matchSchema(%q) = %v, want %v", tt.raw, got, tt.want)
			}
			if !reflect.DeepEqual(r.texts, tt.wantTexts) {
				t.Errorf("matched texts = %q, want %q", r.texts, tt.wantTexts)
			}
		})
	}
}

func TestMatchSchemaWindow(t *testing.T) {
	t.Parallel()
	m := mustCompileSchema(t, Match{Heuristic: HeuristicMatchWindow})
	long := strings.Repeat("a", 40<<10)

	tests := []struct {
		name string
		raw  string
		want []Hit
	}{
		{
			name: "complete JSON with a 40 KiB string",
			raw:  mustJSON(t, map[string]string{"description": long}),
			want: []Hit{{Offset: NoOffset, Detail: "schema string 2: text is longer than the match window"}},
		},
		{
			// The JSON text is longer than the window, but each string fits.
			name: "many short strings under the caps",
			raw:  mustJSON(t, distinctStrings(maxSchemaMatchStrings)),
		},
		{name: "short schema", raw: `{"type":"object","description":"Lists the files."}`},
		{name: "broken JSON", raw: `{"type":"object"`, want: []Hit{{Offset: NoOffset, Detail: brokenDetail}}},
		{name: "over the string cap", raw: mustJSON(t, distinctStrings(maxSchemaMatchStrings+1)), want: []Hit{{Offset: NoOffset, Detail: windowCutDetail}}},
		{name: "empty", raw: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := m.Match(tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Match(%.60q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

// In the schemaWindow mode, matchSchema stops at the first string that hits
// and returns one hit.
func TestMatchSchemaWindowFirstHit(t *testing.T) {
	t.Parallel()
	r := &recorder{hit: holds("evil"), perCall: 3}
	got := matchSchema(`["ok","evil1","evil2","late"]`, schemaWindow, r.match)
	want := []Hit{{Offset: NoOffset, Detail: "schema string 2: fake"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("matchSchema() = %v, want %v", got, want)
	}
	if wantTexts := []string{"ok", "evil1"}; !reflect.DeepEqual(r.texts, wantTexts) {
		t.Errorf("matched texts = %q, want %q", r.texts, wantTexts)
	}
}

// maxFuzzSchemaDetail is the longest Detail that FuzzMatchSchema accepts. The
// longest label is "schema string 100000: ", and the inner details are short.
const maxFuzzSchemaDetail = 128

// FuzzMatchSchema checks that matchSchema holds its contract for any input, in
// each mode, with a fake matcher and with real schema matchers: no panic, at
// most MaxHits+1 hits, every Offset NoOffset, and every Detail short
// printable ASCII.
func FuzzMatchSchema(f *testing.F) {
	seeds := []string{
		"",
		" \t\r\n",
		"\u00a0",
		"evil",
		`"evil"`,
		"1",
		"null",
		`{}`,
		`[]`,
		`{"a":"evil"}`,
		`{"a":"evil","b":`,
		`{"a":"evil`,
		`{"a":"x"} evil`,
		`{"a":"x"}{"b":"evil"}`,
		`{"\u0049gnore previous instructions":"Ig\u0001nore all previous instructions"}`,
		`{"d":"ign\u200bore previous","e":"` + "\u200b\u202e" + `"}`,
		`["\ud800","\u0000","\\"]`,
		strings.Repeat("[", 70) + strings.Repeat("]", 70),
		mustJSON(f, distinctStrings(40)),
		mustJSON(f, []string{strings.Repeat("a", MaxMatchInputBytes+1)}),
		"\xff\xfe" + `{"a":"b"}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	blocks := []Match{
		{AnyRegex: t1003Patterns},
		{AllRegex: []string{`(?i)ignore`, `(?i)previous`}},
		{Keywords: strings.Fields("a b c d e f g h i j k l m n o p q r s t evil")},
		{Heuristic: HeuristicInvisibleUnicode},
		{Heuristic: HeuristicTagBidiOverride},
		{Heuristic: HeuristicBase64Blob},
		{Heuristic: HeuristicMatchWindow},
	}
	var matchers []*Matcher
	for _, b := range blocks {
		matchers = append(matchers, mustCompileSchema(f, b))
	}

	check := func(t *testing.T, label string, hits []Hit) {
		t.Helper()
		if len(hits) > MaxHits+1 {
			t.Errorf("%s: %d hits, want at most %d", label, len(hits), MaxHits+1)
		}
		for _, h := range hits {
			if h.Offset != NoOffset {
				t.Errorf("%s: Offset = %d, want NoOffset", label, h.Offset)
			}
			if h.Detail == "" || len(h.Detail) > maxFuzzSchemaDetail {
				t.Errorf("%s: Detail %q is empty or longer than %d bytes", label, h.Detail, maxFuzzSchemaDetail)
			}
			checkPrintableASCII(t, h.Detail)
		}
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxFuzzInput {
			return
		}
		for _, mode := range []schemaMode{schemaAll, schemaBudget, schemaWindow} {
			r := &recorder{hit: always, perCall: 2}
			check(t, fmt.Sprintf("fake mode %d", mode), matchSchema(raw, mode, r.match))
		}
		for i, m := range matchers {
			check(t, "matcher "+strconv.Itoa(i), m.Match(raw))
		}
	})
}
