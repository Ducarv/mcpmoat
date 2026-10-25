package pins

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

func TestCanonicalExactBytes(t *testing.T) {
	t.Parallel()
	const want = `{"_meta":null,"annotations":{"destructiveHint":null,"idempotentHint":null,"openWorldHint":null,"readOnlyHint":null,"title":""},"description":"","icons":null,"inputSchema":null,"name":"x","outputSchema":null,"title":""}`
	if got := mustCanonical(t, inspect.Tool{Name: "x"}); got != want {
		t.Errorf("Canonical(Tool{Name: \"x\"}) =\n%s\nwant\n%s", got, want)
	}
}

// TestCanonicalToolFields guards the field set of the canonical form. It
// fails when inspect.Tool gets a new field, because Canonical builds
// canonicalTool field by field and would silently drop the new one.
func TestCanonicalToolFields(t *testing.T) {
	t.Parallel()
	if n := reflect.TypeFor[inspect.Tool]().NumField(); n != 8 {
		t.Errorf("inspect.Tool has %d fields, want 8. A new inspect.Tool field needs a decision: "+
			"add it to the hash with a new HashVersion, or document why the hash leaves it out "+
			"(see the Canonical doc). Then update this test.", n)
	}
}

// TestCanonicalEqual lists pairs of tools that must have the same canonical
// form.
func TestCanonicalEqual(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a, b inspect.Tool
	}{
		{
			name: "nil annotations equal empty annotations",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", Annotations: &inspect.ToolAnnotations{}},
		},
		{
			name: "empty bytes equal nil input schema",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", InputSchema: []byte{}},
		},
		{
			name: "empty bytes equal nil output schema",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", OutputSchema: []byte{}},
		},
		{
			name: "literal null equals nil input schema",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", InputSchema: []byte(`null`)},
		},
		{
			name: "literal null equals nil output schema",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", OutputSchema: []byte(` null `)},
		},
		{
			name: "schema key order does not matter",
			a:    inspect.Tool{Name: "x", InputSchema: []byte(`{"type":"object","properties":{"b":{},"a":{}}}`)},
			b:    inspect.Tool{Name: "x", InputSchema: []byte(`{"properties":{"a":{},"b":{}},"type":"object"}`)},
		},
		{
			name: "schema whitespace does not matter",
			a:    inspect.Tool{Name: "x", OutputSchema: []byte("{ \"type\" :\n\t\"object\" , \"required\": [ \"a\" ] }")},
			b:    inspect.Tool{Name: "x", OutputSchema: []byte(`{"required":["a"],"type":"object"}`)},
		},
		{
			name: "_meta key order does not matter",
			a:    inspect.Tool{Name: "x", Meta: []byte(`{"ui":{"visibility":["model"],"resourceUri":"ui://a"},"a":1}`)},
			b:    inspect.Tool{Name: "x", Meta: []byte(`{"a":1,"ui":{"resourceUri":"ui://a","visibility":["model"]}}`)},
		},
		{
			name: "_meta whitespace does not matter",
			a:    inspect.Tool{Name: "x", Meta: []byte("{ \"a\" :\n\t[ 1 , 2 ] }")},
			b:    inspect.Tool{Name: "x", Meta: []byte(`{"a":[1,2]}`)},
		},
		{
			name: "empty bytes equal nil _meta",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", Meta: []byte{}},
		},
		{
			name: "literal null equals nil _meta",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", Meta: []byte(` null `)},
		},
		{
			name: "icon key order does not matter",
			a:    inspect.Tool{Name: "x", Icons: []byte(`[{"src":"a","mimeType":"image/png","sizes":["1x1"]}]`)},
			b:    inspect.Tool{Name: "x", Icons: []byte(`[ { "sizes": ["1x1"], "mimeType": "image/png", "src": "a" } ]`)},
		},
		{
			name: "empty bytes equal nil icons",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", Icons: []byte{}},
		},
		{
			name: "literal null equals nil icons",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", Icons: []byte(`null`)},
		},
		{
			// Known limit (FR-11, canonical.go): JCS writes one number format.
			name: "1.0 equals 1 (documented limit)",
			a:    inspect.Tool{Name: "x", InputSchema: []byte(`{"a":1.0}`)},
			b:    inspect.Tool{Name: "x", InputSchema: []byte(`{"a":1}`)},
		},
		{
			// Known limit (FR-11, canonical.go): numbers pass through float64,
			// so integers above 2^53 can collide. This is accepted and
			// documented; the test pins the behaviour so a change is seen.
			name: "integer above 2^53 collides (documented float64 limit)",
			a:    inspect.Tool{Name: "x", InputSchema: []byte(`{"a":9007199254740993}`)},
			b:    inspect.Tool{Name: "x", InputSchema: []byte(`{"a":9007199254740992}`)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, b := mustCanonical(t, tt.a), mustCanonical(t, tt.b)
			if a != b {
				t.Errorf("Canonical() differs, want equal:\n a = %s\n b = %s", a, b)
			}
		})
	}
}

// TestCanonicalDiffer lists pairs of tools that must have different
// canonical forms.
func TestCanonicalDiffer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a, b inspect.Tool
	}{
		{
			name: "nil input schema differs from empty object",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", InputSchema: []byte(`{}`)},
		},
		{
			name: "nil output schema differs from empty object",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", OutputSchema: []byte(`{}`)},
		},
		{
			name: "input and output schema are not swapped",
			a:    inspect.Tool{Name: "x", InputSchema: []byte(`{}`)},
			b:    inspect.Tool{Name: "x", OutputSchema: []byte(`{}`)},
		},
		{
			name: "title and annotations title are not mixed",
			a:    inspect.Tool{Name: "x", Title: "t"},
			b:    inspect.Tool{Name: "x", Annotations: &inspect.ToolAnnotations{Title: "t"}},
		},
		{
			// No Unicode normalisation: NFC U+00E9 against NFD e + U+0301.
			name: "NFC differs from NFD",
			a:    inspect.Tool{Name: "x", Description: "caf\u00e9"},
			b:    inspect.Tool{Name: "x", Description: "cafe\u0301"},
		},
		{
			name: "NFC differs from NFD in a schema",
			a:    inspect.Tool{Name: "x", InputSchema: []byte("{\"d\":\"caf\u00e9\"}")},
			b:    inspect.Tool{Name: "x", InputSchema: []byte("{\"d\":\"cafe\u0301\"}")},
		},
		{
			name: "nil _meta differs from empty object",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", Meta: []byte(`{}`)},
		},
		{
			name: "nil icons differ from empty array",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", Icons: []byte(`[]`)},
		},
		{
			name: "changed _meta value",
			a:    inspect.Tool{Name: "x", Meta: []byte(`{"ui":{"resourceUri":"ui://a"}}`)},
			b:    inspect.Tool{Name: "x", Meta: []byte(`{"ui":{"resourceUri":"ui://b"}}`)},
		},
		{
			name: "changed _meta key",
			a:    inspect.Tool{Name: "x", Meta: []byte(`{"a":1}`)},
			b:    inspect.Tool{Name: "x", Meta: []byte(`{"b":1}`)},
		},
		{
			name: "invisible character in _meta",
			a:    inspect.Tool{Name: "x", Meta: []byte(`{"a":"ab"}`)},
			b:    inspect.Tool{Name: "x", Meta: []byte("{\"a\":\"a\u200bb\"}")},
		},
		{
			name: "changed icon src",
			a:    inspect.Tool{Name: "x", Icons: []byte(`[{"src":"https://example.com/a.png"}]`)},
			b:    inspect.Tool{Name: "x", Icons: []byte(`[{"src":"https://example.com/b.png"}]`)},
		},
		{
			name: "swapped icon order",
			a:    inspect.Tool{Name: "x", Icons: []byte(`[{"src":"a"},{"src":"b"}]`)},
			b:    inspect.Tool{Name: "x", Icons: []byte(`[{"src":"b"},{"src":"a"}]`)},
		},
		{
			name: "same JSON in _meta and in icons",
			a:    inspect.Tool{Name: "x", Meta: []byte(`{"src":"a"}`)},
			b:    inspect.Tool{Name: "x", Icons: []byte(`{"src":"a"}`)},
		},
		{
			name: "_meta and input schema are not swapped",
			a:    inspect.Tool{Name: "x", Meta: []byte(`{"a":1}`)},
			b:    inspect.Tool{Name: "x", InputSchema: []byte(`{"a":1}`)},
		},
		{
			name: "no trimming",
			a:    inspect.Tool{Name: "x", Description: "a"},
			b:    inspect.Tool{Name: "x", Description: "a "},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, b := mustCanonical(t, tt.a), mustCanonical(t, tt.b)
			if a == b {
				t.Errorf("Canonical() equal, want different: %s", a)
			}
		})
	}
}

// TestCanonicalHints checks the output for nil, true and false of each of the
// four hints. readOnlyHint and idempotentHint write false as null, so nil and
// false are equal for them. destructiveHint and openWorldHint keep all three
// values distinct.
func TestCanonicalHints(t *testing.T) {
	t.Parallel()
	for _, h := range hashHints {
		t.Run(h.field, func(t *testing.T) {
			t.Parallel()
			falseJSON := "false"
			if h.falseIsNull {
				falseJSON = "null"
			}
			// new(true) (Go 1.26+) returns a pointer to a new bool set to true.
			values := []struct {
				label string
				v     *bool
				want  string // the JSON value of the hint in the output
			}{
				{"nil", nil, "null"},
				{"true", new(true), "true"},
				{"false", new(false), falseJSON},
			}
			outputs := map[string]string{} // JSON value of the hint -> output
			for _, val := range values {
				a := &inspect.ToolAnnotations{}
				*h.ptr(a) = val.v
				got := mustCanonical(t, inspect.Tool{Name: "x", Annotations: a})
				if want := `"` + h.field + `":` + val.want; !strings.Contains(got, want) {
					t.Errorf("%s = %s: Canonical() = %s, want it to contain %s", h.field, val.label, got, want)
				}
				if prev, ok := outputs[val.want]; ok && prev != got {
					t.Errorf("%s: two values give %s but different outputs:\n%s\n%s", h.field, val.want, prev, got)
				}
				outputs[val.want] = got
			}
			// Distinct JSON values must give distinct outputs.
			seen := map[string]bool{}
			for _, out := range outputs {
				if seen[out] {
					t.Errorf("%s: different hint values give the same output %s", h.field, out)
				}
				seen[out] = true
			}
		})
	}
}

// TestCanonicalNumbers checks schema numbers at the edges of the float64
// range that Canonical accepts. Out of range numbers are in
// TestCanonicalErrors.
func TestCanonicalNumbers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		schema string
		want   string // the canonical schema
	}{
		{name: "underflow to zero", schema: `{"a":1e-400}`, want: `{"a":0}`},
		{name: "negative underflow to zero", schema: `{"a":[-1e-400]}`, want: `{"a":[0]}`},
		{name: "largest float64", schema: `{"a":1.7976931348623157e308}`, want: `{"a":1.7976931348623157e+308}`},
		{name: "most negative float64", schema: `{"a":-1.7976931348623157e308}`, want: `{"a":-1.7976931348623157e+308}`},
		{name: "out of range text in a string", schema: `{"1e400":"1e400"}`, want: `{"1e400":"1e400"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := mustCanonical(t, inspect.Tool{Name: "x", InputSchema: []byte(tt.schema)})
			if want := `"inputSchema":` + tt.want; !strings.Contains(in, want) {
				t.Errorf("Canonical() = %s, want it to contain %s", in, want)
			}
			out := mustCanonical(t, inspect.Tool{Name: "x", OutputSchema: []byte(tt.schema)})
			if want := `"outputSchema":` + tt.want; !strings.Contains(out, want) {
				t.Errorf("Canonical() = %s, want it to contain %s", out, want)
			}
		})
	}
}

// TestCanonicalIdempotent checks that the output is valid JSON and already in
// JCS form.
func TestCanonicalIdempotent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		tool inspect.Tool
	}{
		{name: "minimal", tool: inspect.Tool{Name: "x"}},
		{name: "full", tool: inspect.Tool{
			Name:         "read_file",
			Title:        "Read file",
			Description:  "Reads a file.\n\t\"quoted\" \\ \u0001 \u200b",
			InputSchema:  []byte(`{ "type": "object", "properties": { "path": { "type": "string", "maxLength": 1.5e2 } } }`),
			OutputSchema: []byte(`[1, "aA", null, true]`),
			Meta:         []byte(`{ "z": 1.0, "ui": { "resourceUri": "ui://a\u200b" } }`),
			Icons:        []byte(`[ { "src": "a", "sizes": [ "1x1" ] }, { "src": "b" } ]`),
			Annotations: &inspect.ToolAnnotations{
				Title: "Reader", ReadOnlyHint: new(true), DestructiveHint: new(false),
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mustCanonical(t, tt.tool)
			// canonicalForm fails the test when got is not valid JSON.
			if again := canonicalForm(t, []byte(got)); again != got {
				t.Errorf("Canonicalize(output) =\n%s\nwant unchanged\n%s", again, got)
			}
		})
	}
}

// TestCanonicalDoesNotChangeInput checks that Canonical does not rewrite the
// caller's schema bytes. The schemas have whitespace and unsorted keys, so an
// in-place Canonicalize would change them.
func TestCanonicalDoesNotChangeInput(t *testing.T) {
	t.Parallel()
	in := []byte("{ \"z\": 1.0,\n  \"a\": [ 2 , 3 ] }")
	out := []byte(`{"type" : "object" , "additionalProperties" : false}`)
	meta := []byte(`{ "z": 1.0, "a": { "y": 1, "b": 2 } }`)
	icons := []byte(`[ { "src" : "a", "mimeType" : "image/png" } ]`)
	inCopy, outCopy := bytes.Clone(in), bytes.Clone(out)
	metaCopy, iconsCopy := bytes.Clone(meta), bytes.Clone(icons)

	tool := inspect.Tool{Name: "x", InputSchema: in, OutputSchema: out, Meta: meta, Icons: icons}
	if _, err := Canonical(tool); err != nil {
		t.Fatalf("Canonical() error = %v", err)
	}
	if !bytes.Equal(in, inCopy) {
		t.Errorf("InputSchema changed: got %q, want %q", in, inCopy)
	}
	if !bytes.Equal(out, outCopy) {
		t.Errorf("OutputSchema changed: got %q, want %q", out, outCopy)
	}
	if !bytes.Equal(meta, metaCopy) {
		t.Errorf("Meta changed: got %q, want %q", meta, metaCopy)
	}
	if !bytes.Equal(icons, iconsCopy) {
		t.Errorf("Icons changed: got %q, want %q", icons, iconsCopy)
	}
}

// TestCanonicalErrors checks the invalid inputs of Canonical and Hash. Each
// input holds the marker SECRET, which must never reach the error message.
func TestCanonicalErrors(t *testing.T) {
	t.Parallel()
	const marker = "SECRET"
	input := func(s string) inspect.Tool { return inspect.Tool{Name: "x", InputSchema: []byte(s)} }
	output := func(s string) inspect.Tool { return inspect.Tool{Name: "x", OutputSchema: []byte(s)} }
	meta := func(s string) inspect.Tool { return inspect.Tool{Name: "x", Meta: []byte(s)} }
	icons := func(s string) inspect.Tool { return inspect.Tool{Name: "x", Icons: []byte(s)} }
	tests := []struct {
		name   string
		tool   inspect.Tool
		reason string // the fixed reason in the error message
	}{
		{name: "truncated input schema", tool: input(`{"SECRET":"a`), reason: "invalid JSON in inputSchema"},
		{name: "trailing data in input schema", tool: input(`{"a":1} "SECRET"`), reason: "invalid JSON in inputSchema"},
		{name: "two values in output schema", tool: output(`{} {"SECRET":1}`), reason: "invalid JSON in outputSchema"},
		// A trailing value is invalid JSON, whatever it holds.
		{name: "out of range number in a trailing value", tool: input(`{} {"SECRET":1e400}`), reason: "invalid JSON in inputSchema"},
		{name: "duplicate key in a trailing value", tool: input(`{} {"SECRET":1,"SECRET":2}`), reason: "invalid JSON in inputSchema"},
		{name: "not JSON", tool: input(`SECRET`), reason: "invalid JSON in inputSchema"},
		{name: "only whitespace in input schema", tool: input(" \t\n"), reason: "invalid JSON in inputSchema"},
		{name: "duplicate top-level key", tool: input(`{"SECRET":1,"SECRET":2}`), reason: "duplicate object key in inputSchema"},
		{name: "duplicate nested key", tool: input(`{"a":{"SECRET":1,"b":2,"SECRET":3}}`), reason: "duplicate object key in inputSchema"},
		{name: "duplicate key in output schema", tool: output(`{"SECRET":1,"SECRET":1}`), reason: "duplicate object key in outputSchema"},
		{name: "invalid UTF-8 in name", tool: inspect.Tool{Name: "SECRET\xff"}, reason: "invalid UTF-8 in name"},
		{name: "invalid UTF-8 in title", tool: inspect.Tool{Name: "x", Title: "SECRET\xc3"}, reason: "invalid UTF-8 in title"},
		{name: "invalid UTF-8 in description", tool: inspect.Tool{Name: "x", Description: "SECRET\xed\xa0\x80"}, reason: "invalid UTF-8 in description"},
		{
			name:   "invalid UTF-8 in annotations title",
			tool:   inspect.Tool{Name: "x", Annotations: &inspect.ToolAnnotations{Title: "SECRET\xfe"}},
			reason: "invalid UTF-8 in annotations title",
		},
		{name: "invalid UTF-8 in schema string", tool: input("{\"a\":\"SECRET\xff\"}"), reason: "invalid JSON in inputSchema"},
		{name: "invalid UTF-8 in schema key", tool: input("{\"SECRET\xff\":1}"), reason: "invalid JSON in inputSchema"},
		{name: "lone surrogate in schema", tool: input(`{"a":"SECRET\ud800"}`), reason: "invalid JSON in inputSchema"},
		{name: "lone low surrogate in schema", tool: input(`{"a":"\udc00SECRET"}`), reason: "invalid JSON in inputSchema"},
		{name: "1e400 in input schema", tool: input(`{"SECRET":1e400}`), reason: "number out of range in inputSchema"},
		{name: "-1e400 in input schema", tool: input(`{"a":[-1e400],"SECRET":1}`), reason: "number out of range in inputSchema"},
		{name: "1e400 in output schema", tool: output(`{"SECRET":[1e400]}`), reason: "number out of range in outputSchema"},
		{name: "-1e400 in output schema", tool: output(`{"SECRET":-1e400}`), reason: "number out of range in outputSchema"},
		{name: "truncated _meta", tool: meta(`{"SECRET":"a`), reason: "invalid JSON in _meta"},
		{name: "trailing data in _meta", tool: meta(`{"a":1} "SECRET"`), reason: "invalid JSON in _meta"},
		{name: "only whitespace in _meta", tool: meta(" \t\n"), reason: "invalid JSON in _meta"},
		{name: "lone surrogate in _meta", tool: meta(`{"a":"SECRET\ud800"}`), reason: "invalid JSON in _meta"},
		{name: "duplicate key in _meta", tool: meta(`{"SECRET":1,"SECRET":2}`), reason: "duplicate object key in _meta"},
		{name: "duplicate nested key in _meta", tool: meta(`{"a":{"SECRET":1,"SECRET":3}}`), reason: "duplicate object key in _meta"},
		{name: "1e400 in _meta", tool: meta(`{"SECRET":1e400}`), reason: "number out of range in _meta"},
		{name: "-1e400 in _meta", tool: meta(`{"a":[-1e400],"SECRET":1}`), reason: "number out of range in _meta"},
		{name: "truncated icons", tool: icons(`[{"SECRET":"a`), reason: "invalid JSON in icons"},
		{name: "trailing data in icons", tool: icons(`[] "SECRET"`), reason: "invalid JSON in icons"},
		{name: "not JSON in icons", tool: icons(`SECRET`), reason: "invalid JSON in icons"},
		{name: "invalid UTF-8 in icons", tool: icons("[{\"src\":\"SECRET\xff\"}]"), reason: "invalid JSON in icons"},
		{name: "duplicate key in an icon", tool: icons(`[{"src":"SECRET","src":"b"}]`), reason: "duplicate object key in icons"},
		{name: "1e400 in icons", tool: icons(`[{"SECRET":1e400}]`), reason: "number out of range in icons"},
		{
			name:   "just above the largest float64",
			tool:   input(`{"SECRET":1.797693134862316e308}`),
			reason: "number out of range in inputSchema",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Canonical(tt.tool)
			if !errors.Is(err, ErrInvalidTool) {
				t.Fatalf("Canonical() error = %v, want ErrInvalidTool", err)
			}
			if got != nil {
				t.Errorf("Canonical() = %q, want nil bytes on error", got)
			}
			if want := "canonical form of tool: " + tt.reason + ": " + ErrInvalidTool.Error(); err.Error() != want {
				t.Errorf("Canonical() error = %q, want %q", err, want)
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("Canonical() error %q contains the input marker %q", err, marker)
			}

			h, err := Hash(tt.tool)
			if !errors.Is(err, ErrInvalidTool) {
				t.Errorf("Hash() error = %v, want an error that wraps ErrInvalidTool", err)
			}
			if h != "" {
				t.Errorf("Hash() = %q, want \"\" on error", h)
			}
			if err != nil && strings.Contains(err.Error(), marker) {
				t.Errorf("Hash() error %q contains the input marker %q", err, marker)
			}
		})
	}
}

// TestCanonicalKeepsInvisible checks that invisible characters stay byte for
// byte in the output, in the description and inside a schema string.
func TestCanonicalKeepsInvisible(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		char string
	}{
		{name: "zero width space U+200B", char: "\u200b"},
		{name: "byte order mark U+FEFF", char: "\ufeff"},
		{name: "right-to-left override U+202E", char: "\u202e"},
		{name: "tag latin capital A U+E0041", char: "\U000e0041"},
		{name: "soft hyphen U+00AD", char: "\u00ad"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			plain := mustCanonical(t, inspect.Tool{Name: "x", Description: "ab", InputSchema: []byte(`{"d":"ab"}`)})

			desc := mustCanonical(t, inspect.Tool{Name: "x", Description: "a" + tt.char + "b", InputSchema: []byte(`{"d":"ab"}`)})
			if want := `"description":"a` + tt.char + `b"`; !strings.Contains(desc, want) {
				t.Errorf("Canonical() = %+q, want it to contain %+q", desc, want)
			}
			if desc == plain {
				t.Errorf("character in description does not change the output")
			}

			sch := mustCanonical(t, inspect.Tool{Name: "x", Description: "ab", InputSchema: []byte(`{"d":"a` + tt.char + `b"}`)})
			if want := `"inputSchema":{"d":"a` + tt.char + `b"}`; !strings.Contains(sch, want) {
				t.Errorf("Canonical() = %+q, want it to contain %+q", sch, want)
			}
			if sch == plain {
				t.Errorf("character in schema does not change the output")
			}
		})
	}
}
