package pins

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"io"
	"math/rand/v2"
	"testing"
)

// shuffleJSON returns v with the members of every object in a random order and
// random insignificant whitespace between tokens. Array order and the raw bytes
// of every string and number (escapes, 1.0, 1e2, -0) stay exactly as in v, so
// the result has the same meaning and the same canonical form as v.
func shuffleJSON(t testing.TB, v []byte, r *rand.Rand) []byte {
	t.Helper()
	dec := jsontext.NewDecoder(bytes.NewReader(v))
	out, err := shuffleValue(nil, dec, r)
	if err != nil {
		t.Fatalf("shuffleJSON(%q): %v", v, err)
	}
	// The input must hold exactly one JSON value.
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		t.Fatalf("shuffleJSON(%q): want one JSON value, trailing read error = %v", v, err)
	}
	return appendSpace(out, r)
}

// shuffleValue reads the next JSON value from dec and appends its shuffled form
// to dst.
func shuffleValue(dst []byte, dec *jsontext.Decoder, r *rand.Rand) ([]byte, error) {
	dst = appendSpace(dst, r)
	// PeekKind returns the first byte of the next token ('{', '[', '"', '0', ...)
	// without consuming it.
	switch dec.PeekKind() {
	case '{':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		var members [][]byte
		for dec.PeekKind() != '}' {
			// ReadValue on a name gives its raw bytes, escapes included. The
			// bytes are only valid until the next read, so copy them now.
			name, err := dec.ReadValue()
			if err != nil {
				return nil, err
			}
			m := append(appendSpace(nil, r), name...)
			m = append(appendSpace(m, r), ':')
			if m, err = shuffleValue(m, dec, r); err != nil {
				return nil, err
			}
			members = append(members, m)
		}
		if _, err := dec.ReadToken(); err != nil { // '}'
			return nil, err
		}
		r.Shuffle(len(members), func(i, j int) { members[i], members[j] = members[j], members[i] })
		dst = append(dst, '{')
		for i, m := range members {
			if i > 0 {
				dst = append(appendSpace(dst, r), ',')
			}
			dst = append(dst, m...)
		}
		return append(appendSpace(dst, r), '}'), nil
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		dst = append(dst, '[')
		for i := 0; dec.PeekKind() != ']'; i++ {
			if i > 0 {
				dst = append(appendSpace(dst, r), ',')
			}
			var err error
			if dst, err = shuffleValue(dst, dec, r); err != nil {
				return nil, err
			}
		}
		if _, err := dec.ReadToken(); err != nil { // ']'
			return nil, err
		}
		return append(appendSpace(dst, r), ']'), nil
	default:
		// A scalar (string, number, true, false, null): keep its raw bytes.
		// An invalid token also lands here and ReadValue reports the error.
		val, err := dec.ReadValue()
		if err != nil {
			return nil, err
		}
		return append(dst, val...), nil
	}
}

// appendSpace appends zero to two random JSON whitespace bytes to dst.
func appendSpace(dst []byte, r *rand.Rand) []byte {
	const ws = " \t\n\r"
	for range r.IntN(3) {
		dst = append(dst, ws[r.IntN(len(ws))])
	}
	return dst
}

func TestShuffleJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		in       string
		reorders bool // the input has an object with two or more members
	}{
		{name: "null", in: `null`},
		{name: "empty object", in: `{}`},
		{name: "empty array", in: `[]`},
		{name: "numbers", in: `[1.0, 1e2, -0, 0.1, 12345678901234567890]`},
		{name: "flat object", in: `{"b":1,"a":2,"c":3,"d":true,"e":false}`, reorders: true},
		{
			name:     "escaped strings",
			in:       `{"z\u200bkey":"zero\u200bwidth", "a":"tab\tquote\"slash\/", "m":"` + "\u200b" + `"}`,
			reorders: true,
		},
		{
			name: "nested",
			in: `{"name":"read_file","inputSchema":{"type":"object","properties":` +
				`{"path":{"type":"string"},"mode":{"enum":["r","w"],"default":1.0}},` +
				`"required":["path","mode"]},"annotations":[{"y":null,"x":{}},[],[[1e2]]]}`,
			reorders: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := []byte(tt.in)
			wantCanon := canonicalForm(t, in)
			wantSorted := sortedRawForm(t, in)
			r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // G404: fixed seed for a reproducible test shuffle, not for security
			reordered := false
			for range 16 {
				out := shuffleJSON(t, in, r)
				if !jsontext.Value(out).IsValid() {
					t.Fatalf("shuffleJSON(%q) = %q, not valid JSON", in, out)
				}
				if got := canonicalForm(t, out); got != wantCanon {
					t.Errorf("canonical(shuffleJSON(%q)) = %q, want %q", in, got, wantCanon)
				}
				// Same members and same raw tokens: catches a changed 1.0 or escape,
				// which the canonical form hides.
				if got := sortedRawForm(t, out); got != wantSorted {
					t.Errorf("sorted raw form of %q = %q, want %q", out, got, wantSorted)
				}
				if compactForm(t, out) != compactForm(t, in) {
					reordered = true
				}
			}
			if reordered != tt.reorders {
				t.Errorf("member order changed = %v, want %v", reordered, tt.reorders)
			}
		})
	}
}

// canonicalForm returns the RFC 8785 (JCS) form of v.
func canonicalForm(t testing.TB, v []byte) string {
	t.Helper()
	c := jsontext.Value(bytes.Clone(v))
	if err := c.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize(%q): %v", v, err)
	}
	return string(c)
}

// compactForm returns v without whitespace and with raw tokens and member
// order unchanged.
func compactForm(t testing.TB, v []byte, opts ...jsontext.Options) string {
	t.Helper()
	c := jsontext.Value(bytes.Clone(v))
	if err := c.Compact(opts...); err != nil {
		t.Fatalf("Compact(%q): %v", v, err)
	}
	return string(c)
}

// sortedRawForm is compactForm with object members sorted by name.
func sortedRawForm(t testing.TB, v []byte) string {
	t.Helper()
	return compactForm(t, v, jsontext.ReorderRawObjects(true))
}
