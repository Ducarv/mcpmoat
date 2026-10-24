package pins

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"math"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// hashFormat is the exact form of a hash of version sha256-v1.
var hashFormat = regexp.MustCompile(`^sha256-v1:[0-9a-f]{64}$`)

func TestHashFormat(t *testing.T) {
	t.Parallel()
	for _, f := range loadHashFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			t.Parallel()
			h, err := Hash(f.Tool)
			if err != nil {
				t.Fatalf("Hash() error = %v", err)
			}
			if !hashFormat.MatchString(h) || !strings.HasPrefix(h, HashVersion+":") {
				t.Errorf("Hash() = %q, want %s:<64 lowercase hex digits>", h, HashVersion)
			}
			canon, err := Canonical(f.Tool)
			if err != nil {
				t.Fatalf("Canonical() error = %v", err)
			}
			sum := sha256.Sum256(canon)
			if want := HashVersion + ":" + hex.EncodeToString(sum[:]); h != want {
				t.Errorf("Hash() = %q, want HashVersion:hex(sha256(Canonical())) = %q", h, want)
			}
		})
	}
}

func TestHashKnownAnswer(t *testing.T) {
	t.Parallel()
	// Computed outside Go with:
	//   printf '%s' '{"annotations":{"destructiveHint":null,"idempotentHint":null,"openWorldHint":null,"readOnlyHint":null,"title":""},"description":"","inputSchema":null,"name":"x","outputSchema":null,"title":""}' | shasum -a 256
	const want = "sha256-v1:fc7144327c0193d2cddd15ff7bdd991773e2166f3b837e24ee1999631ff22423"
	got, err := Hash(inspect.Tool{Name: "x"})
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if got != want {
		t.Errorf("Hash(Tool{Name: \"x\"}) = %q, want %q", got, want)
	}
}

// TestHashKeyOrder checks that the hash does not depend on the key order or
// the whitespace of the schemas.
func TestHashKeyOrder(t *testing.T) {
	t.Parallel()
	for i, f := range loadHashFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			t.Parallel()
			want, err := Hash(f.Tool)
			if err != nil {
				t.Fatalf("Hash() error = %v", err)
			}
			r := rand.New(rand.NewPCG(58, uint64(i))) //nolint:gosec // G404: fixed seed for a reproducible test shuffle, not for security
			for n := range 200 {
				shuffled := f.Tool
				if shuffled.InputSchema != nil {
					shuffled.InputSchema = shuffleJSON(t, f.Tool.InputSchema, r)
				}
				if shuffled.OutputSchema != nil {
					shuffled.OutputSchema = shuffleJSON(t, f.Tool.OutputSchema, r)
				}
				got, err := Hash(shuffled)
				if err != nil {
					t.Fatalf("shuffle %d: Hash() error = %v", n, err)
				}
				if got != want {
					t.Fatalf("shuffle %d: Hash() = %q, want %q\ninputSchema: %q\noutputSchema: %q",
						n, got, want, shuffled.InputSchema, shuffled.OutputSchema)
				}
			}
		})
	}
}

// TestHashMutations checks that every small change to a tool changes its
// hash: one character in a text field or a schema, an invisible character,
// a hint, and the order of a schema array.
func TestHashMutations(t *testing.T) {
	t.Parallel()
	for _, f := range loadHashFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			t.Parallel()
			orig, err := Hash(f.Tool)
			if err != nil {
				t.Fatalf("Hash() error = %v", err)
			}
			muts := hashMutations(t, f.Tool)
			for _, m := range muts {
				got, err := Hash(m.tool)
				if err != nil {
					t.Errorf("%s: Hash() error = %v", m.name, err)
					continue
				}
				if got == orig {
					t.Errorf("%s: Hash() = %q, the same as for the original tool", m.name, got)
				}
			}
			// The mutations must not change the fixture through shared memory.
			if again, _ := Hash(f.Tool); again != orig {
				t.Errorf("Hash() of the original tool changed to %q, want %q", again, orig)
			}
			t.Logf("%d mutations", len(muts))
		})
	}
}

func TestHashInvalidTool(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		tool inspect.Tool
	}{
		{name: "invalid UTF-8 in name", tool: inspect.Tool{Name: "a\xffb"}},
		{name: "invalid UTF-8 in description", tool: inspect.Tool{Name: "x", Description: "\xc3"}},
		{name: "invalid UTF-8 in annotations title", tool: inspect.Tool{Name: "x", Annotations: &inspect.ToolAnnotations{Title: "\xff"}}},
		{name: "invalid JSON in inputSchema", tool: inspect.Tool{Name: "x", InputSchema: []byte(`{`)}},
		{name: "duplicate key in outputSchema", tool: inspect.Tool{Name: "x", OutputSchema: []byte(`{"a":1,"a":2}`)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h, err := Hash(tt.tool)
			if !errors.Is(err, ErrInvalidTool) {
				t.Errorf("Hash() error = %v, want an error that wraps ErrInvalidTool", err)
			}
			if h != "" {
				t.Errorf("Hash() = %q, want \"\" on error", h)
			}
		})
	}
}

// hashMutation is one changed copy of a tool.
type hashMutation struct {
	name string
	tool inspect.Tool
}

// hashInvisible are invisible characters that an attacker can add to hide a
// change: zero width space, byte order mark and the tag character "A".
var hashInvisible = []string{"\u200b", "\ufeff", "\U000E0041"}

// hashMutations returns changed copies of tool. None of them changes tool.
func hashMutations(t *testing.T, tool inspect.Tool) []hashMutation {
	t.Helper()
	var muts []hashMutation
	add := func(name string, change func(*inspect.Tool)) {
		c := tool
		if tool.Annotations != nil {
			ann := *tool.Annotations
			c.Annotations = &ann
		}
		change(&c)
		muts = append(muts, hashMutation{name: name, tool: c})
	}
	annotations := func(c *inspect.Tool) *inspect.ToolAnnotations {
		if c.Annotations == nil {
			c.Annotations = &inspect.ToolAnnotations{}
		}
		return c.Annotations
	}

	texts := []struct {
		field string
		ptr   func(*inspect.Tool) *string
	}{
		{"name", func(c *inspect.Tool) *string { return &c.Name }},
		{"title", func(c *inspect.Tool) *string { return &c.Title }},
		{"description", func(c *inspect.Tool) *string { return &c.Description }},
		{"annotations title", func(c *inspect.Tool) *string { return &annotations(c).Title }},
	}
	for _, tf := range texts {
		add(tf.field+": one character changed", func(c *inspect.Tool) {
			p := tf.ptr(c)
			*p = hashChangeOneChar(*p)
		})
		for _, inv := range hashInvisible {
			add(tf.field+": "+strconv.QuoteToASCII(inv)+" at the start", func(c *inspect.Tool) {
				p := tf.ptr(c)
				*p = inv + *p
			})
			add(tf.field+": "+strconv.QuoteToASCII(inv)+" at the end", func(c *inspect.Tool) {
				p := tf.ptr(c)
				*p += inv
			})
		}
	}

	hints := []struct {
		field string
		ptr   func(*inspect.ToolAnnotations) **bool
	}{
		{"readOnlyHint", func(a *inspect.ToolAnnotations) **bool { return &a.ReadOnlyHint }},
		{"destructiveHint", func(a *inspect.ToolAnnotations) **bool { return &a.DestructiveHint }},
		{"idempotentHint", func(a *inspect.ToolAnnotations) **bool { return &a.IdempotentHint }},
		{"openWorldHint", func(a *inspect.ToolAnnotations) **bool { return &a.OpenWorldHint }},
	}
	yes, no := true, false
	for _, hf := range hints {
		var cur *bool
		if tool.Annotations != nil {
			cur = *hf.ptr(tool.Annotations)
		}
		for _, v := range []*bool{nil, &yes, &no} {
			if hashSameHint(cur, v) {
				continue
			}
			add(hf.field+": "+hashHintString(cur)+" to "+hashHintString(v), func(c *inspect.Tool) {
				*hf.ptr(annotations(c)) = v
			})
		}
	}

	schemas := []struct {
		field string
		ptr   func(*inspect.Tool) *[]byte
	}{
		{"inputSchema", func(c *inspect.Tool) *[]byte { return (*[]byte)(&c.InputSchema) }},
		{"outputSchema", func(c *inspect.Tool) *[]byte { return (*[]byte)(&c.OutputSchema) }},
	}
	for _, sf := range schemas {
		raw := *sf.ptr(&tool)
		if raw == nil {
			// No schema and the empty schema {} must have different hashes.
			add(sf.field+": absent to {}", func(c *inspect.Tool) { *sf.ptr(c) = []byte(`{}`) })
			continue
		}
		add(sf.field+": removed", func(c *inspect.Tool) { *sf.ptr(c) = nil })
		for _, sm := range hashSchemaMutations(t, raw) {
			add(sf.field+": "+sm.name, func(c *inspect.Tool) { *sf.ptr(c) = sm.schema })
		}
	}
	return muts
}

// hashSchemaMutation is one changed copy of a schema.
type hashSchemaMutation struct {
	name   string
	schema []byte
}

// hashSchemaMutations returns changed copies of the schema raw: each string
// and key with one character changed and with each invisible character added,
// each number below 2^53 plus one, each bool flipped, and each pair of
// adjacent, different array elements swapped. Numbers at or above 2^53 are
// left alone, because the canonical form cannot tell them apart (see the
// known limits in canonical.go).
func hashSchemaMutations(t *testing.T, raw []byte) []hashSchemaMutation {
	t.Helper()
	var p hashSchemaParts
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	if _, err := hashWalk(dec, &p); err != nil {
		t.Fatalf("walk schema %q: %v", raw, err)
	}

	var muts []hashSchemaMutation
	for _, s := range p.strings {
		tok := raw[s.start:s.end]
		str, err := jsontext.AppendUnquote(nil, tok)
		if err != nil {
			t.Fatalf("unquote %s: %v", tok, err)
		}
		quote := func(v string) []byte {
			q, err := jsontext.AppendQuote(nil, v)
			if err != nil {
				t.Fatalf("quote %q: %v", v, err)
			}
			return q
		}
		muts = append(muts, hashSchemaMutation{
			name:   "string " + string(tok) + ": one character changed",
			schema: hashSplice(raw, s, quote(hashChangeOneChar(string(str)))),
		})
		for _, inv := range hashInvisible {
			muts = append(muts, hashSchemaMutation{
				name:   "string " + string(tok) + ": " + strconv.QuoteToASCII(inv) + " added",
				schema: hashSplice(raw, s, quote(inv+string(str))),
			})
		}
	}
	for _, s := range p.numbers {
		tok := raw[s.start:s.end]
		f, err := strconv.ParseFloat(string(tok), 64)
		if err != nil {
			t.Fatalf("parse number %s: %v", tok, err)
		}
		if math.Abs(f) >= 1<<53 {
			continue
		}
		muts = append(muts, hashSchemaMutation{
			name:   "number " + string(tok) + " plus one",
			schema: hashSplice(raw, s, strconv.AppendFloat(nil, f+1, 'g', -1, 64)),
		})
	}
	for _, s := range p.bools {
		repl := []byte("true")
		if string(raw[s.start:s.end]) == "true" {
			repl = []byte("false")
		}
		muts = append(muts, hashSchemaMutation{
			name:   "bool " + string(raw[s.start:s.end]) + " flipped",
			schema: hashSplice(raw, s, repl),
		})
	}
	for _, elems := range p.arrays {
		for i := 0; i+1 < len(elems); i++ {
			a, b := elems[i], elems[i+1]
			if canonicalForm(t, raw[a.start:a.end]) == canonicalForm(t, raw[b.start:b.end]) {
				continue
			}
			var out []byte
			out = append(out, raw[:a.start]...)
			out = append(out, raw[b.start:b.end]...)
			out = append(out, raw[a.end:b.start]...)
			out = append(out, raw[a.start:a.end]...)
			out = append(out, raw[b.end:]...)
			muts = append(muts, hashSchemaMutation{
				name:   "array elements " + string(raw[a.start:a.end]) + " and " + string(raw[b.start:b.end]) + " swapped",
				schema: out,
			})
		}
	}
	return muts
}

// hashSpan is the byte range [start, end) of one JSON value in a schema.
type hashSpan struct{ start, end int64 }

// hashSchemaParts are the places in a schema that hashSchemaMutations changes.
type hashSchemaParts struct {
	strings []hashSpan   // string values and object keys
	numbers []hashSpan   // number values
	bools   []hashSpan   // true and false
	arrays  [][]hashSpan // the elements of each array
}

// hashWalk reads the next JSON value from dec, adds its parts to p and
// returns its span.
func hashWalk(dec *jsontext.Decoder, p *hashSchemaParts) (hashSpan, error) {
	kind := dec.PeekKind()
	if kind != '{' && kind != '[' {
		val, err := dec.ReadValue()
		if err != nil {
			return hashSpan{}, err
		}
		// InputOffset is the offset just after the value that was read.
		s := hashSpan{dec.InputOffset() - int64(len(val)), dec.InputOffset()}
		switch val.Kind() {
		case '"':
			p.strings = append(p.strings, s)
		case '0':
			p.numbers = append(p.numbers, s)
		case 't', 'f':
			p.bools = append(p.bools, s)
		}
		return s, nil
	}

	if _, err := dec.ReadToken(); err != nil {
		return hashSpan{}, err
	}
	start := dec.InputOffset() - 1 // the '{' or '['
	end := jsontext.Kind('}')
	if kind == '[' {
		end = ']'
	}
	var elems []hashSpan
	for dec.PeekKind() != end {
		if kind == '{' {
			name, err := dec.ReadValue()
			if err != nil {
				return hashSpan{}, err
			}
			p.strings = append(p.strings, hashSpan{dec.InputOffset() - int64(len(name)), dec.InputOffset()})
		}
		s, err := hashWalk(dec, p)
		if err != nil {
			return hashSpan{}, err
		}
		elems = append(elems, s)
	}
	if _, err := dec.ReadToken(); err != nil {
		return hashSpan{}, err
	}
	if kind == '[' {
		p.arrays = append(p.arrays, elems)
	}
	return hashSpan{start, dec.InputOffset()}, nil
}

// hashSplice returns a copy of raw with the span s replaced by repl.
func hashSplice(raw []byte, s hashSpan, repl []byte) []byte {
	out := append([]byte(nil), raw[:s.start]...)
	out = append(out, repl...)
	return append(out, raw[s.end:]...)
}

// hashChangeOneChar returns s with its first character replaced by another
// one, or "a" when s is empty.
func hashChangeOneChar(s string) string {
	r, size := utf8.DecodeRuneInString(s)
	if size == 0 {
		return "a"
	}
	repl := "a"
	if r == 'a' {
		repl = "b"
	}
	return repl + s[size:]
}

// hashSameHint reports whether a and b are the same hint value.
func hashSameHint(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// hashHintString returns "nil", "true" or "false".
func hashHintString(b *bool) string {
	if b == nil {
		return "nil"
	}
	return strconv.FormatBool(*b)
}
