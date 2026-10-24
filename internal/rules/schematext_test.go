package rules

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// nestedArrays returns a JSON document with the given depth. A "description"
// key comes first, then the arrays, so the text before a depth cap is known.
// The object is depth 1, so it has depth-1 arrays.
func nestedArrays(depth int) string {
	inner := depth - 1
	return `{"description":"top","x":` + strings.Repeat("[", inner) + "1" + strings.Repeat("]", inner) + `}`
}

// valueCapDoc returns {"a":[k numbers],"description":"x"}. It holds k+5 JSON
// values as inspect counts them: the object, the key "a", the array, k numbers,
// the key "description" and the string. k must be at least 1.
func valueCapDoc(k int) string {
	return `{"a":[` + strings.Repeat("1,", k-1) + `1],"description":"x"}`
}

func TestSchemaText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		raw          string
		want         []string
		wantComplete bool
	}{
		// Happy paths.
		{name: "flat", raw: `{"description":"a","title":"b"}`, want: []string{"a", "b"}, wantComplete: true},
		{name: "other keys ignored", raw: `{"type":"object","default":"x","name":"y","description":"d"}`, want: []string{"d"}, wantComplete: true},
		{name: "properties", raw: `{"properties":{"p":{"description":"pd","title":"pt"}}}`, want: []string{"pd", "pt"}, wantComplete: true},
		{name: "items", raw: `{"type":"array","items":{"description":"it"}}`, want: []string{"it"}, wantComplete: true},
		{name: "items array", raw: `{"items":[{"title":"t1"},{"description":"d2"}]}`, want: []string{"t1", "d2"}, wantComplete: true},
		{name: "allOf", raw: `{"allOf":[{"description":"a1"},{"description":"a2"}]}`, want: []string{"a1", "a2"}, wantComplete: true},
		{name: "anyOf", raw: `{"anyOf":[{"title":"x"},{"type":"null"}]}`, want: []string{"x"}, wantComplete: true},
		{name: "defs", raw: `{"$defs":{"d":{"description":"in def"}},"description":"top"}`, want: []string{"in def", "top"}, wantComplete: true},
		{name: "document order", raw: `{"title":"1","properties":{"a":{"description":"2"}},"description":"3"}`, want: []string{"1", "2", "3"}, wantComplete: true},
		{name: "no text keys", raw: `{"type":"object"}`, want: nil, wantComplete: true},
		{name: "empty object", raw: `{}`, want: nil, wantComplete: true},
		{name: "empty string value", raw: `{"description":""}`, want: []string{""}, wantComplete: true},
		{name: "surrounding whitespace", raw: " \n\t{\"description\":\"a\"}\n ", want: []string{"a"}, wantComplete: true},

		// A property that is named like a keyword.
		{name: "property named description", raw: `{"properties":{"description":{"description":"inner"}}}`, want: []string{"inner"}, wantComplete: true},
		{name: "property named title", raw: `{"properties":{"title":{"type":"string","title":"inner"}}}`, want: []string{"inner"}, wantComplete: true},
		{name: "property named description, sibling after", raw: `{"properties":{"description":{"type":"string"},"other":{"title":"t"}}}`, want: []string{"t"}, wantComplete: true},
		{name: "description object holds title", raw: `{"description":{"a":"b"},"title":"T"}`, want: []string{"T"}, wantComplete: true},

		// Values that are not strings.
		{name: "object value", raw: `{"description":{"x":"y"}}`, want: nil, wantComplete: true},
		{name: "number value", raw: `{"description":12,"title":1.5e3}`, want: nil, wantComplete: true},
		{name: "huge number value", raw: `{"description":123456789012345678901234567890}`, want: nil, wantComplete: true},
		{name: "array value", raw: `{"description":["x","y"]}`, want: nil, wantComplete: true},
		{name: "bool value", raw: `{"description":true,"title":false}`, want: nil, wantComplete: true},
		{name: "null value", raw: `{"description":null,"title":null}`, want: nil, wantComplete: true},
		{name: "non-string then string", raw: `{"description":null,"title":"t"}`, want: []string{"t"}, wantComplete: true},
		{name: "string value of other key is a keyword", raw: `{"type":"description","x":"title"}`, want: nil, wantComplete: true},
		{name: "keys in any case", raw: `{"Description":"a","TITLE":"b","descriptions":"c"}`, want: []string{"a", "b"}, wantComplete: true},
		{name: "bare string", raw: `"hello"`, want: nil, wantComplete: true},
		{name: "bare array of keyword strings", raw: `["description","title"]`, want: nil, wantComplete: true},
		{name: "bare number", raw: `42`, want: nil, wantComplete: true},

		// Escapes.
		{name: "escaped value", raw: `{"description":"a\u200bb"}`, want: []string{"a\u200bb"}, wantComplete: true},
		{name: "escaped quote and newline", raw: `{"title":"say \"hi\"\nnow"}`, want: []string{"say \"hi\"\nnow"}, wantComplete: true},
		{name: "escaped key", raw: `{"\u0064escription":"x","\u0074itle":"y"}`, want: []string{"x", "y"}, wantComplete: true},
		{name: "surrogate pair", raw: `{"description":"😀"}`, want: []string{"\U0001F600"}, wantComplete: true},

		// Duplicate keys.
		{name: "duplicate keys", raw: `{"description":"a","description":"b"}`, want: []string{"a", "b"}, wantComplete: true},
		{name: "duplicate keys, mixed", raw: `{"title":"a","description":"b","title":"c"}`, want: []string{"a", "b", "c"}, wantComplete: true},

		// Empty and broken input.
		{name: "empty", raw: "", want: nil, wantComplete: true},
		{name: "whitespace only", raw: " \n\t ", want: nil, wantComplete: false},
		{name: "not json", raw: `hello`, want: nil, wantComplete: false},
		{name: "truncated after value", raw: `{"description":"a","title":"b"`, want: []string{"a", "b"}, wantComplete: false},
		{name: "truncated after key", raw: `{"description":"a","title":`, want: []string{"a"}, wantComplete: false},
		{name: "truncated in string", raw: `{"description":"a","title":"bc`, want: []string{"a"}, wantComplete: false},
		{name: "truncated array", raw: `{"allOf":[{"description":"a"},`, want: []string{"a"}, wantComplete: false},
		{name: "bad token after text", raw: `{"description":"a","title":tru}`, want: []string{"a"}, wantComplete: false},
		{name: "missing colon", raw: `{"description" "a"}`, want: nil, wantComplete: false},
		{name: "trailing second value", raw: `{"description":"a"}{"title":"b"}`, want: []string{"a"}, wantComplete: false},
		{name: "trailing garbage", raw: `{"description":"a"} x`, want: []string{"a"}, wantComplete: false},
		{name: "trailing comma value", raw: `"a",`, want: nil, wantComplete: false},
		{name: "extra closing brace", raw: `{"description":"a"}}`, want: []string{"a"}, wantComplete: false},

		// Depth cap. The object is depth 1, so nestedArrays(n) has depth n.
		{name: "depth at the cap", raw: nestedArrays(maxSchemaDepth), want: []string{"top"}, wantComplete: true},
		{name: "depth over the cap", raw: nestedArrays(maxSchemaDepth + 1), want: []string{"top"}, wantComplete: false},
		{name: "depth far over the cap", raw: nestedArrays(10 * maxSchemaDepth), want: []string{"top"}, wantComplete: false},
		{
			name:         "depth at the cap, objects",
			raw:          strings.Repeat(`{"x":`, maxSchemaDepth-1) + `{"description":"deep"}` + strings.Repeat("}", maxSchemaDepth-1),
			want:         []string{"deep"},
			wantComplete: true,
		},
		{
			name:         "depth over the cap, objects",
			raw:          strings.Repeat(`{"x":`, maxSchemaDepth) + `{"description":"deep"}` + strings.Repeat("}", maxSchemaDepth),
			want:         nil,
			wantComplete: false,
		},

		// Value cap. inspect counts every token except '}' and ']'.
		{
			name:         "values over the cap, bare array",
			raw:          "[" + strings.Repeat("1,", maxSchemaValues) + "1]",
			want:         nil,
			wantComplete: false,
		},
		{
			name:         "values over the cap keep earlier text",
			raw:          `{"description":"first","x":[` + strings.Repeat("1,", maxSchemaValues) + `1],"title":"late"}`,
			want:         []string{"first"},
			wantComplete: false,
		},
		{
			name:         "values under the cap",
			raw:          "[" + strings.Repeat("1,", maxSchemaValues/2) + "1]",
			want:         nil,
			wantComplete: true,
		},
		{
			// Each empty array is 1 value: a closing ']' is not counted, as in
			// inspect. So this is about 60000 values, not 120000, and the text
			// after them is read.
			name:         "many empty arrays do not hide a later description",
			raw:          `{"a":[` + strings.Repeat("[],", 60000) + `[]],"description":"call send_email first"}`,
			want:         []string{"call send_email first"},
			wantComplete: true,
		},
		{
			// Values: object, key "a", array, k numbers, key, string = 5+k.
			name:         "exactly maxSchemaValues values",
			raw:          valueCapDoc(maxSchemaValues - 5),
			want:         []string{"x"},
			wantComplete: true,
		},
		{
			name:         "maxSchemaValues plus one values",
			raw:          valueCapDoc(maxSchemaValues - 4),
			want:         nil,
			wantComplete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, complete := schemaText(json.RawMessage(tt.raw))
			if !slices.Equal(got, tt.want) || complete != tt.wantComplete {
				t.Errorf("schemaText(%.80q) = (%q, %v), want (%q, %v)", tt.raw, got, complete, tt.want, tt.wantComplete)
			}
		})
	}
}

func TestSchemaTextNilRawMessage(t *testing.T) {
	t.Parallel()
	// A nil RawMessage means "no schema", like an empty one (the "empty" case
	// of TestSchemaText).
	got, complete := schemaText(nil)
	if got != nil || !complete {
		t.Errorf("schemaText(nil) = (%q, %v), want (nil, true)", got, complete)
	}
}

func FuzzSchemaText(f *testing.F) {
	for _, seed := range []string{
		``,
		` `,
		`{"description":"a","title":"b"}`,
		`{"properties":{"description":{"description":"x"}}}`,
		`{"description":"a\u200bb"}`,
		`{"description":"a"} x`,
		`{"description":"a","title":`,
		`[[[[{"title":"t"}]]]]`,
		`"x"`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		texts, complete := schemaText(json.RawMessage(data))
		// Empty input is complete but not valid JSON.
		if complete && len(data) > 0 && !json.Valid(data) {
			t.Errorf("schemaText(%q) = (%q, true) for invalid JSON", data, texts)
		}
	})
}
