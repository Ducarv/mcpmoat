package pins

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"math/rand/v2"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// FuzzCanonical checks the properties of Canonical for any schema and name:
// it never panics, it fails only with ErrInvalidTool and no output, and a
// success gives valid JCS that does not depend on key order or whitespace.
func FuzzCanonical(f *testing.F) {
	schemas := []string{
		`{"type":"object","properties":{"path":{"type":"string","description":"File path"},` +
			`"opts":{"type":"object","properties":{"mode":{"enum":["r","w"]}}}},"required":["path"]}`,
		`{}`,
		`null`,
		``,
		`{"n":[1.0,1e2,-0,9007199254740993]}`,
		`{"d":"zero\u200bwidth"}`,     // JSON escape
		"{\"d\":\"zero\u200bwidth\"}", // raw U+200B bytes
		`{not json`,
		`{"a":1,"a":2}`,
		`{"s":"\ud800"}`,
		"{\"s\":\"\xff\"}",
	}
	names := []string{"", "read_file", "\xff"}
	for i, s := range schemas {
		for _, n := range names {
			f.Add([]byte(s), n, uint64(i))
		}
	}

	f.Fuzz(func(t *testing.T, schema []byte, name string, seed uint64) {
		if len(schema) > 64<<10 {
			t.Skip("schema larger than 64 KiB")
		}
		orig := bytes.Clone(schema)
		tool := inspect.Tool{Name: name, InputSchema: schema}

		got, err := Canonical(tool)
		if !bytes.Equal(schema, orig) {
			t.Fatalf("Canonical changed the caller's schema: %q, was %q", schema, orig)
		}
		if err != nil {
			if !errors.Is(err, ErrInvalidTool) {
				t.Fatalf("Canonical() error = %v, want it to wrap ErrInvalidTool", err)
			}
			if got != nil {
				t.Fatalf("Canonical() = %q with error %v, want nil output", got, err)
			}
			return
		}
		if !utf8.ValidString(name) {
			t.Fatalf("Canonical() error = nil for name %q with invalid UTF-8", name)
		}
		if !jsontext.Value(got).IsValid() {
			t.Fatalf("Canonical() = %q, not valid JSON", got)
		}
		again := jsontext.Value(bytes.Clone(got))
		if err := again.Canonicalize(); err != nil {
			t.Fatalf("Canonicalize(Canonical()) error = %v", err)
		}
		if !bytes.Equal(again, got) {
			t.Fatalf("Canonical() = %q is not idempotent: Canonicalize gives %q", got, again)
		}

		want, err := Hash(tool)
		if err != nil {
			t.Fatalf("Hash() error = %v after Canonical succeeded", err)
		}
		if len(schema) == 0 {
			return // nil or empty schema is null; there is nothing to shuffle
		}
		r := rand.New(rand.NewPCG(seed, seed)) //nolint:gosec // seeded shuffle for a reproducible fuzz case, not for security
		shuffled := inspect.Tool{Name: name, InputSchema: shuffleJSON(t, schema, r)}
		gotHash, err := Hash(shuffled)
		if err != nil {
			t.Fatalf("Hash(shuffled %q) error = %v", shuffled.InputSchema, err)
		}
		if gotHash != want {
			t.Fatalf("Hash(shuffled %q) = %s, want %s (schema %q)", shuffled.InputSchema, gotHash, want, schema)
		}
	})
}
