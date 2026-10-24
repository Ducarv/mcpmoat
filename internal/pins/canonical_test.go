package pins

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// canonMust returns Canonical(tool) and fails the test on an error.
func canonMust(t *testing.T, tool inspect.Tool) string {
	t.Helper()
	got, err := Canonical(tool)
	if err != nil {
		t.Fatalf("Canonical() error = %v, want nil", err)
	}
	return string(got)
}

func TestCanonicalExactBytes(t *testing.T) {
	t.Parallel()
	const want = `{"annotations":{"destructiveHint":null,"idempotentHint":null,"openWorldHint":null,"readOnlyHint":null,"title":""},"description":"","inputSchema":null,"name":"x","outputSchema":null,"title":""}`
	if got := canonMust(t, inspect.Tool{Name: "x"}); got != want {
		t.Errorf("Canonical(Tool{Name: \"x\"}) =\n%s\nwant\n%s", got, want)
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
			name: "empty RawMessage equals nil input schema",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", InputSchema: json.RawMessage{}},
		},
		{
			name: "empty RawMessage equals nil output schema",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", OutputSchema: json.RawMessage{}},
		},
		{
			name: "schema key order does not matter",
			a:    inspect.Tool{Name: "x", InputSchema: json.RawMessage(`{"type":"object","properties":{"b":{},"a":{}}}`)},
			b:    inspect.Tool{Name: "x", InputSchema: json.RawMessage(`{"properties":{"a":{},"b":{}},"type":"object"}`)},
		},
		{
			name: "schema whitespace does not matter",
			a:    inspect.Tool{Name: "x", OutputSchema: json.RawMessage("{ \"type\" :\n\t\"object\" , \"required\": [ \"a\" ] }")},
			b:    inspect.Tool{Name: "x", OutputSchema: json.RawMessage(`{"required":["a"],"type":"object"}`)},
		},
		{
			// Known limit (FR-11, canonical.go): JCS writes one number format.
			name: "1.0 equals 1 (documented limit)",
			a:    inspect.Tool{Name: "x", InputSchema: json.RawMessage(`{"a":1.0}`)},
			b:    inspect.Tool{Name: "x", InputSchema: json.RawMessage(`{"a":1}`)},
		},
		{
			// Known limit (FR-11, canonical.go): numbers pass through float64,
			// so integers above 2^53 can collide. This is accepted and
			// documented; the test pins the behaviour so a change is seen.
			name: "integer above 2^53 collides (documented float64 limit)",
			a:    inspect.Tool{Name: "x", InputSchema: json.RawMessage(`{"a":9007199254740993}`)},
			b:    inspect.Tool{Name: "x", InputSchema: json.RawMessage(`{"a":9007199254740992}`)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, b := canonMust(t, tt.a), canonMust(t, tt.b)
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
			b:    inspect.Tool{Name: "x", InputSchema: json.RawMessage(`{}`)},
		},
		{
			name: "nil output schema differs from empty object",
			a:    inspect.Tool{Name: "x"},
			b:    inspect.Tool{Name: "x", OutputSchema: json.RawMessage(`{}`)},
		},
		{
			name: "input and output schema are not swapped",
			a:    inspect.Tool{Name: "x", InputSchema: json.RawMessage(`{}`)},
			b:    inspect.Tool{Name: "x", OutputSchema: json.RawMessage(`{}`)},
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
			a:    inspect.Tool{Name: "x", InputSchema: json.RawMessage("{\"d\":\"caf\u00e9\"}")},
			b:    inspect.Tool{Name: "x", InputSchema: json.RawMessage("{\"d\":\"cafe\u0301\"}")},
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
			a, b := canonMust(t, tt.a), canonMust(t, tt.b)
			if a == b {
				t.Errorf("Canonical() equal, want different: %s", a)
			}
		})
	}
}

// TestCanonicalHints checks that nil, true and false give three different
// outputs for each of the four hints.
func TestCanonicalHints(t *testing.T) {
	t.Parallel()
	// set returns annotations with one hint set to v.
	tests := []struct {
		name string
		set  func(v *bool) *inspect.ToolAnnotations
	}{
		{"readOnlyHint", func(v *bool) *inspect.ToolAnnotations { return &inspect.ToolAnnotations{ReadOnlyHint: v} }},
		{"destructiveHint", func(v *bool) *inspect.ToolAnnotations { return &inspect.ToolAnnotations{DestructiveHint: v} }},
		{"idempotentHint", func(v *bool) *inspect.ToolAnnotations { return &inspect.ToolAnnotations{IdempotentHint: v} }},
		{"openWorldHint", func(v *bool) *inspect.ToolAnnotations { return &inspect.ToolAnnotations{OpenWorldHint: v} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// new(true) (Go 1.26+) returns a pointer to a new bool set to true.
			values := map[string]*bool{"null": nil, "true": new(true), "false": new(false)}
			seen := map[string]string{}
			for label, v := range values {
				got := canonMust(t, inspect.Tool{Name: "x", Annotations: tt.set(v)})
				if prev, ok := seen[got]; ok {
					t.Errorf("%s = %s and %s give the same output: %s", tt.name, prev, label, got)
				}
				seen[got] = label
				if want := `"` + tt.name + `":` + label; !strings.Contains(got, want) {
					t.Errorf("Canonical() = %s, want it to contain %s", got, want)
				}
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
			InputSchema:  json.RawMessage(`{ "type": "object", "properties": { "path": { "type": "string", "maxLength": 1.5e2 } } }`),
			OutputSchema: json.RawMessage(`[1, "aA", null, true]`),
			Annotations: &inspect.ToolAnnotations{
				Title: "Reader", ReadOnlyHint: new(true), DestructiveHint: new(false),
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Canonical(tt.tool)
			if err != nil {
				t.Fatalf("Canonical() error = %v", err)
			}
			if !json.Valid(got) {
				t.Fatalf("Canonical() = %s, not valid JSON", got)
			}
			again := jsontext.Value(bytes.Clone(got))
			if err := again.Canonicalize(); err != nil {
				t.Fatalf("Canonicalize(output) error = %v", err)
			}
			if !bytes.Equal(again, got) {
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
	in := json.RawMessage("{ \"z\": 1.0,\n  \"a\": [ 2 , 3 ] }")
	out := json.RawMessage(`{"type" : "object" , "additionalProperties" : false}`)
	inCopy, outCopy := bytes.Clone(in), bytes.Clone(out)

	tool := inspect.Tool{Name: "x", InputSchema: in, OutputSchema: out}
	if _, err := Canonical(tool); err != nil {
		t.Fatalf("Canonical() error = %v", err)
	}
	if !bytes.Equal(in, inCopy) {
		t.Errorf("InputSchema changed: got %q, want %q", in, inCopy)
	}
	if !bytes.Equal(out, outCopy) {
		t.Errorf("OutputSchema changed: got %q, want %q", out, outCopy)
	}
}

// TestCanonicalErrors checks the invalid inputs. Each input holds the marker
// SECRET, which must never reach the error message.
func TestCanonicalErrors(t *testing.T) {
	t.Parallel()
	const marker = "SECRET"
	schema := func(s string) inspect.Tool { return inspect.Tool{Name: "x", InputSchema: json.RawMessage(s)} }
	tests := []struct {
		name string
		tool inspect.Tool
	}{
		{name: "truncated input schema", tool: schema(`{"SECRET":"a`)},
		{name: "trailing data in input schema", tool: schema(`{"a":1} "SECRET"`)},
		{name: "two values in output schema", tool: inspect.Tool{Name: "x", OutputSchema: json.RawMessage(`{} {"SECRET":1}`)}},
		{name: "not JSON", tool: schema(`SECRET`)},
		{name: "duplicate top-level key", tool: schema(`{"SECRET":1,"SECRET":2}`)},
		{name: "duplicate nested key", tool: schema(`{"a":{"SECRET":1,"b":2,"SECRET":3}}`)},
		{name: "duplicate key in output schema", tool: inspect.Tool{Name: "x", OutputSchema: json.RawMessage(`{"SECRET":1,"SECRET":1}`)}},
		{name: "invalid UTF-8 in name", tool: inspect.Tool{Name: "SECRET\xff"}},
		{name: "invalid UTF-8 in title", tool: inspect.Tool{Name: "x", Title: "SECRET\xc3"}},
		{name: "invalid UTF-8 in description", tool: inspect.Tool{Name: "x", Description: "SECRET\xed\xa0\x80"}},
		{name: "invalid UTF-8 in annotations title", tool: inspect.Tool{Name: "x", Annotations: &inspect.ToolAnnotations{Title: "SECRET\xfe"}}},
		{name: "invalid UTF-8 in schema string", tool: schema("{\"a\":\"SECRET\xff\"}")},
		{name: "invalid UTF-8 in schema key", tool: schema("{\"SECRET\xff\":1}")},
		{name: "lone surrogate in schema", tool: schema(`{"a":"SECRET\ud800"}`)},
		{name: "lone low surrogate in schema", tool: schema(`{"a":"\udc00SECRET"}`)},
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
			if strings.Contains(err.Error(), marker) {
				t.Errorf("error %q contains the input marker %q", err, marker)
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
			plain := canonMust(t, inspect.Tool{Name: "x", Description: "ab", InputSchema: json.RawMessage(`{"d":"ab"}`)})

			desc := canonMust(t, inspect.Tool{Name: "x", Description: "a" + tt.char + "b", InputSchema: json.RawMessage(`{"d":"ab"}`)})
			if want := `"description":"a` + tt.char + `b"`; !strings.Contains(desc, want) {
				t.Errorf("Canonical() = %+q, want it to contain %+q", desc, want)
			}
			if desc == plain {
				t.Errorf("character in description does not change the output")
			}

			sch := canonMust(t, inspect.Tool{Name: "x", Description: "ab", InputSchema: json.RawMessage(`{"d":"a` + tt.char + `b"}`)})
			if want := `"inputSchema":{"d":"a` + tt.char + `b"}`; !strings.Contains(sch, want) {
				t.Errorf("Canonical() = %+q, want it to contain %+q", sch, want)
			}
			if sch == plain {
				t.Errorf("character in schema does not change the output")
			}
		})
	}
}
