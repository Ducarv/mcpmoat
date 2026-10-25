package pins

// This file holds the mutation generators of TestHashMutations, and the JSON
// span walker that finds the parts of a schema to change.

import (
	"bytes"
	"encoding/json/jsontext"
	"math"
	"slices"
	"strconv"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// hashMutation is one changed copy of a tool.
type hashMutation struct {
	name string
	tool inspect.Tool
}

// hashInvisible are invisible characters that an attacker can add to hide a
// change: zero width space, byte order mark and the tag character "A".
var hashInvisible = []string{"\u200b", "\ufeff", "\U000E0041"}

// hashMutations returns changed copies of tool. Each one must have another
// hash than tool. None of them changes tool.
func hashMutations(t testing.TB, tool inspect.Tool) []hashMutation {
	t.Helper()
	muts := hashTextMutations(tool)
	muts = append(muts, hashHintMutations(tool)...)
	return append(muts, hashJSONFieldMutations(t, tool)...)
}

// hashMutated returns a copy of tool (see cloneTool), changed by change.
// change must replace a schema, never write into its bytes.
func hashMutated(tool inspect.Tool, name string, change func(*inspect.Tool)) hashMutation {
	c := cloneTool(tool)
	change(&c)
	return hashMutation{name: name, tool: c}
}

// hashTextMutations changes one character of each text field, and adds each
// invisible character at its start and at its end.
func hashTextMutations(tool inspect.Tool) []hashMutation {
	texts := []struct {
		field string
		ptr   func(*inspect.Tool) *string
	}{
		{"name", func(c *inspect.Tool) *string { return &c.Name }},
		{"title", func(c *inspect.Tool) *string { return &c.Title }},
		{"description", func(c *inspect.Tool) *string { return &c.Description }},
		{"annotations title", func(c *inspect.Tool) *string { return &ensureAnnotations(c).Title }},
	}
	var muts []hashMutation
	for _, tf := range texts {
		muts = append(muts, hashMutated(tool, tf.field+": one character changed", func(c *inspect.Tool) {
			p := tf.ptr(c)
			*p = hashChangeOneChar(*p)
		}))
		for _, inv := range hashInvisible {
			muts = append(muts,
				hashMutated(tool, tf.field+": "+strconv.QuoteToASCII(inv)+" at the start", func(c *inspect.Tool) {
					p := tf.ptr(c)
					*p = inv + *p
				}),
				hashMutated(tool, tf.field+": "+strconv.QuoteToASCII(inv)+" at the end", func(c *inspect.Tool) {
					p := tf.ptr(c)
					*p += inv
				}),
			)
		}
	}
	return muts
}

// hashHintMutations sets each hint to each value of nil, true and false that
// gives another canonical form. For readOnlyHint and idempotentHint, nil and
// false are the same (TestHashFalseHintIsNil checks this), so only a change
// to or from true is a mutation.
func hashHintMutations(tool inspect.Tool) []hashMutation {
	var muts []hashMutation
	for _, hf := range hashHints {
		var cur *bool
		if tool.Annotations != nil {
			cur = *hf.ptr(tool.Annotations)
		}
		for _, v := range []*bool{nil, new(true), new(false)} {
			if hashHintJSON(cur, hf.falseIsNull) == hashHintJSON(v, hf.falseIsNull) {
				continue
			}
			name := hf.field + ": " + hashHintString(cur) + " to " + hashHintString(v)
			muts = append(muts, hashMutated(tool, name, func(c *inspect.Tool) {
				*hf.ptr(ensureAnnotations(c)) = v
			}))
		}
	}
	return muts
}

// hashJSONFieldMutations removes each schema, _meta and icons, or, when the
// field is absent, sets it to each value in whenAbsent, and adds the changes of
// hashSchemaMutations.
func hashJSONFieldMutations(t testing.TB, tool inspect.Tool) []hashMutation {
	t.Helper()
	fields := []struct {
		name       string
		ptr        func(*inspect.Tool) *[]byte
		whenAbsent []string // the values that replace an absent field
	}{
		// json.RawMessage is defined as []byte, so Go allows the pointer conversion.
		{"inputSchema", func(c *inspect.Tool) *[]byte { return (*[]byte)(&c.InputSchema) }, []string{`{}`}},
		{"outputSchema", func(c *inspect.Tool) *[]byte { return (*[]byte)(&c.OutputSchema) }, []string{`{}`}},
		{"_meta", func(c *inspect.Tool) *[]byte { return (*[]byte)(&c.Meta) }, []string{`{}`}},
		{"icons", func(c *inspect.Tool) *[]byte { return (*[]byte)(&c.Icons) }, []string{`[]`, `[{"src":"x"}]`}},
	}
	var muts []hashMutation
	for _, f := range fields {
		raw := *f.ptr(&tool)
		if raw == nil {
			// An absent field and an empty value such as {} must have different hashes.
			for _, v := range f.whenAbsent {
				muts = append(muts, hashMutated(tool, f.name+": absent to "+v, func(c *inspect.Tool) { *f.ptr(c) = []byte(v) }))
			}
			continue
		}
		muts = append(muts, hashMutated(tool, f.name+": removed", func(c *inspect.Tool) { *f.ptr(c) = nil }))
		for _, sm := range hashSchemaMutations(t, raw) {
			muts = append(muts, hashMutated(tool, f.name+": "+sm.name, func(c *inspect.Tool) { *f.ptr(c) = sm.schema }))
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
func hashSchemaMutations(t testing.TB, raw []byte) []hashSchemaMutation {
	t.Helper()
	var p hashSchemaParts
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	if _, err := walkSchemaParts(dec, &p); err != nil {
		t.Fatalf("walk schema %q: %v", raw, err)
	}
	muts := hashStringMutations(t, raw, p.strings)
	muts = append(muts, hashNumberMutations(t, raw, p.numbers)...)
	muts = append(muts, hashBoolMutations(raw, p.bools)...)
	return append(muts, hashArraySwaps(t, raw, p.arrays)...)
}

// hashStringMutations changes one character of each string or key in spans,
// and adds each invisible character at its start. It skips a changed key
// that matches a sibling key: a duplicate key has no canonical form.
func hashStringMutations(t testing.TB, raw []byte, spans []hashSpan) []hashSchemaMutation {
	t.Helper()
	quote := func(v string) []byte {
		q, err := jsontext.AppendQuote(nil, v)
		if err != nil {
			t.Fatalf("quote %q: %v", v, err)
		}
		return q
	}
	var muts []hashSchemaMutation
	add := func(name string, schema []byte) {
		// The default options of IsValid reject a duplicate key.
		if jsontext.Value(schema).IsValid() {
			muts = append(muts, hashSchemaMutation{name: name, schema: schema})
		}
	}
	for _, s := range spans {
		tok := raw[s.start:s.end]
		str, err := jsontext.AppendUnquote(nil, tok)
		if err != nil {
			t.Fatalf("unquote %s: %v", tok, err)
		}
		add("string "+string(tok)+": one character changed", hashSplice(raw, s, quote(hashChangeOneChar(string(str)))))
		for _, inv := range hashInvisible {
			add("string "+string(tok)+": "+strconv.QuoteToASCII(inv)+" added", hashSplice(raw, s, quote(inv+string(str))))
		}
	}
	return muts
}

// hashNumberMutations adds one to each number in spans that is below 2^53.
func hashNumberMutations(t testing.TB, raw []byte, spans []hashSpan) []hashSchemaMutation {
	t.Helper()
	var muts []hashSchemaMutation
	for _, s := range spans {
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
	return muts
}

// hashBoolMutations flips each bool in spans.
func hashBoolMutations(raw []byte, spans []hashSpan) []hashSchemaMutation {
	var muts []hashSchemaMutation
	for _, s := range spans {
		repl := []byte("true")
		if string(raw[s.start:s.end]) == "true" {
			repl = []byte("false")
		}
		muts = append(muts, hashSchemaMutation{
			name:   "bool " + string(raw[s.start:s.end]) + " flipped",
			schema: hashSplice(raw, s, repl),
		})
	}
	return muts
}

// hashArraySwaps swaps each pair of adjacent array elements that have
// different canonical forms. arrays holds the element spans of each array.
func hashArraySwaps(t testing.TB, raw []byte, arrays [][]hashSpan) []hashSchemaMutation {
	t.Helper()
	var muts []hashSchemaMutation
	for _, elems := range arrays {
		for i := range len(elems) - 1 {
			a, b := elems[i], elems[i+1]
			if canonicalForm(t, raw[a.start:a.end]) == canonicalForm(t, raw[b.start:b.end]) {
				continue
			}
			muts = append(muts, hashSchemaMutation{
				name:   "array elements " + string(raw[a.start:a.end]) + " and " + string(raw[b.start:b.end]) + " swapped",
				schema: slices.Concat(raw[:a.start], raw[b.start:b.end], raw[a.end:b.start], raw[a.start:a.end], raw[b.end:]),
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

// walkSchemaParts reads the next JSON value from dec, adds its parts to p and
// returns its span.
func walkSchemaParts(dec *jsontext.Decoder, p *hashSchemaParts) (hashSpan, error) {
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
		s, err := walkSchemaParts(dec, p)
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
	return slices.Concat(raw[:s.start], repl, raw[s.end:])
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

// hashHintJSON returns the JSON value of the hint b in the canonical form:
// "null", "true" or "false". falseIsNull is the falseIsNull of the hint in
// hashHints.
func hashHintJSON(b *bool, falseIsNull bool) string {
	if b == nil || (!*b && falseIsNull) {
		return "null"
	}
	return strconv.FormatBool(*b)
}

// hashHintString returns "nil", "true" or "false".
func hashHintString(b *bool) string {
	if b == nil {
		return "nil"
	}
	return strconv.FormatBool(*b)
}
