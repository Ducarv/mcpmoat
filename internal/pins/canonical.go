package pins

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// ErrInvalidTool is the error that Canonical and Hash wrap when a tool has no
// canonical form. Canonical lists the cases.
var ErrInvalidTool = errors.New(ReasonInvalidTool)

// canonicalTool is the fixed shape of the canonical form. The field order
// does not matter, because JCS sorts the keys. The json tags have no
// omitempty or omitzero on purpose: every key must always be present.
type canonicalTool struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	// A jsontext.Value is raw JSON. Marshal writes it as it is, after it
	// checks that it is valid JSON.
	InputSchema  jsontext.Value       `json:"inputSchema"`
	OutputSchema jsontext.Value       `json:"outputSchema"`
	Meta         jsontext.Value       `json:"_meta"`
	Icons        jsontext.Value       `json:"icons"`
	Annotations  canonicalAnnotations `json:"annotations"`
}

// canonicalAnnotations is the fixed shape of the annotations. json/v2 writes
// a nil *bool as null, not as an absent key.
//
// It has exactly the fields of inspect.ToolAnnotations, with the same names,
// types and order, because Canonical builds it with a type conversion. A
// conversion ignores struct tags, but it does not compile when the fields
// differ. So a change to inspect.ToolAnnotations breaks the build here, and
// forces a decision about a new HashVersion.
type canonicalAnnotations struct {
	Title           string `json:"title"`
	ReadOnlyHint    *bool  `json:"readOnlyHint"`
	DestructiveHint *bool  `json:"destructiveHint"`
	IdempotentHint  *bool  `json:"idempotentHint"`
	OpenWorldHint   *bool  `json:"openWorldHint"`
}

// Canonical returns the canonical form of t: the bytes that Hash hashes
// (PRD FR-11, threat T2). Canonical does not change t.
//
// Rug-pull detection depends on the canonical form: it must change when, and
// only when, the tool changes. The notes below are its contract. Any change
// to them needs a new HashVersion.
//
// Field set. The canonical form holds all eight fields of inspect.Tool: name,
// title, description, inputSchema, outputSchema, _meta, icons and
// annotations. The annotations hold their title and the four hints.
//
// Shape. The canonical form is one JSON object with a fixed shape. Every key
// is always present, also when the server did not send the field:
//
//	{"_meta":<obj>|null,"annotations":{"destructiveHint":null|bool,
//	 "idempotentHint":null|bool,"openWorldHint":null|bool,
//	 "readOnlyHint":null|bool,"title":""},"description":"",
//	 "icons":<array>|null,"inputSchema":<schema>|null,"name":"",
//	 "outputSchema":<schema>|null,"title":""}
//
// The line breaks are for this comment only: the real form has no
// whitespace. The whole document is in the JSON Canonicalization Scheme (JCS,
// RFC 8785): keys sorted, no whitespace, minimal string escapes and one
// number format.
//
// Absent values. A nil hint is null. Nil annotations give the same bytes as
// empty annotations. A nil or zero-length schema and the JSON literal null
// are all null, so "no schema" is different from the empty object schema {}.
// A schema of only whitespace is not "no schema": it is invalid JSON. _meta
// and icons follow the same rules as the schemas: nil, zero-length and the
// literal null are null. A {} or [] given directly is different from null,
// but inspect turns an empty _meta or icons into nil, so a tool from inspect
// never has that difference. JCS sorts the keys of _meta. The order of the
// icons array is kept, so a reordered array changes the hash.
// readOnlyHint and idempotentHint map false to null, so false and absent are
// the same for these two hints: the SDK cannot tell them apart (see
// inspect.ToolAnnotations). A change to true always changes the hash.
// destructiveHint and openWorldHint keep null, true and false distinct.
//
// No normalisation. Strings stay byte for byte as the server sent them. There
// is no Unicode normalisation (NFC or NFKC), no trimming and no escaping for
// the terminal. Invisible characters, bidi controls, tag characters and NFC
// against NFD forms all change the hash. An attacker can hide a change in
// such characters, so the hash must see them.
//
// Known limits:
//   - Every schema number passes through an IEEE 754 double (float64): in the
//     SDK decode, and in JCS, which converts every number. This is also true
//     for raw bytes from a source other than the SDK. A number that a float64
//     cannot hold exactly is rounded: integers above 2^53 can collapse, long
//     decimals round (0.1000000000000000000001 is equal to 0.1), very small
//     numbers underflow to zero (1e-400 is equal to 0), and -0 is equal to 0.
//     Two schemas that differ only there get the same hash. For the same
//     reason, 1, 1.0 and 1e0 are equal. They are the same value in JSON
//     Schema.
//   - Only overflow is an error: a number beyond the float64 range, such as
//     1e400, because JCS would silently change it to the largest float64.
//   - The SDK keeps the last value of a duplicate object key, and replaces
//     invalid UTF-8 and lone surrogates with U+FFFD, when it decodes the
//     server message. A schema from the SDK therefore has no duplicate keys
//     and no invalid UTF-8. Canonical still rejects them for tools from other
//     sources.
//   - The numbers in _meta pass through float64 too: inspect re-encodes the
//     _meta of the SDK, so the limits of the first bullet apply to it.
//   - The SDK drops the unknown keys inside an icon, so a change in such a key
//     does not change the hash. The known icon fields (src, mimeType, sizes
//     and theme) are part of the hash.
//
// Canonical returns an error that wraps ErrInvalidTool when a string field
// holds invalid UTF-8, or when a schema, _meta or icons is not valid JSON
// (this includes invalid UTF-8 and lone surrogates), has a duplicate object
// key or has a number out of range. The error message names the field but
// never holds server text or _meta values.
func Canonical(t inspect.Tool) ([]byte, error) {
	// Nil annotations and empty annotations must give the same bytes, so use
	// the zero value when there are none.
	var ann inspect.ToolAnnotations
	if t.Annotations != nil {
		ann = *t.Annotations
	}

	// json/v2 also rejects invalid UTF-8, but its error message quotes the
	// place in the JSON. Check first, so that the error names only the field.
	strs := []struct{ field, value string }{
		{"name", t.Name},
		{"title", t.Title},
		{"description", t.Description},
		{"annotations title", ann.Title},
	}
	for _, s := range strs {
		if !utf8.ValidString(s.value) {
			return nil, invalidTool("invalid UTF-8 in " + s.field)
		}
	}

	in, err := canonicalSchema("inputSchema", t.InputSchema)
	if err != nil {
		return nil, err
	}
	out, err := canonicalSchema("outputSchema", t.OutputSchema)
	if err != nil {
		return nil, err
	}
	// _meta and icons use the same checks as the schemas. The error names only
	// the field, never a value.
	meta, err := canonicalSchema("_meta", t.Meta)
	if err != nil {
		return nil, err
	}
	icons, err := canonicalSchema("icons", t.Icons)
	if err != nil {
		return nil, err
	}

	// The type conversion copies every field, and stops compiling when
	// inspect.ToolAnnotations changes (see canonicalAnnotations).
	a := canonicalAnnotations(ann)
	a.ReadOnlyHint = falseToNil(a.ReadOnlyHint)
	a.IdempotentHint = falseToNil(a.IdempotentHint)

	doc, err := json.Marshal(&canonicalTool{
		Name:         t.Name,
		Title:        t.Title,
		Description:  t.Description,
		InputSchema:  in,
		OutputSchema: out,
		Meta:         meta,
		Icons:        icons,
		Annotations:  a,
	})
	if err != nil {
		// Very deep schemas can reach this: the outer object adds one level,
		// so a schema at the jsontext depth limit (about 10000) fails here.
		// inspect caps the depth at inspect.MaxJSONDepth (64), so a tool from
		// inspect does not. The json/v2 error can quote server text, so it is
		// not wrapped. Any partial output is dropped: Canonical fails closed.
		return nil, invalidTool("cannot encode the tool")
	}

	// Canonicalize rewrites the value in place. doc is a new buffer from
	// Marshal, so this does not touch t.
	v := jsontext.Value(doc)
	if err := v.Canonicalize(); err != nil {
		return nil, invalidTool("cannot canonicalize the tool")
	}
	return v, nil
}

// falseToNil returns nil when p points to false, else p.
func falseToNil(p *bool) *bool {
	if p != nil && !*p {
		return nil
	}
	return p
}

// canonicalSchema returns the JCS form of one schema, or null when raw is nil
// or zero-length. field is the fixed key name for the error message.
func canonicalSchema(field string, raw []byte) (jsontext.Value, error) {
	if len(raw) == 0 {
		return jsontext.Value("null"), nil
	}
	// Canonicalize rewrites the bytes in place. raw shares its backing array
	// with the caller's Tool, so work on a copy: the Tool must not change.
	v := jsontext.Value(bytes.Clone(raw))
	// By default, Canonicalize rejects invalid JSON (a trailing value
	// included), duplicate object keys, invalid UTF-8 and lone surrogates.
	// This pass puts the field name in the error; the final Canonicalize of
	// the whole document makes the bytes canonical.
	if err := v.Canonicalize(); err != nil {
		return nil, schemaError(field, err)
	}
	// Canonicalize changes a number out of range to the largest float64, with
	// no error. So check the numbers as the server wrote them, in raw.
	if err := checkNumbers(field, raw); err != nil {
		return nil, err
	}
	return v, nil
}

// checkNumbers returns an error when a number in raw overflows a float64.
// raw must be one valid JSON value.
func checkNumbers(field string, raw []byte) error {
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return schemaError(field, err)
		}
		if tok.Kind() != '0' {
			continue
		}
		// For a number, tok.String is the number as written. ParseFloat
		// returns an error (ErrRange) only when it overflows a float64; it
		// rounds other numbers and underflows tiny ones to zero, with no error.
		if _, err := strconv.ParseFloat(tok.String(), 64); err != nil {
			return invalidTool("number out of range in " + field)
		}
	}
}

// schemaError maps a jsontext error for a schema to a fixed reason. The
// jsontext error message can quote the schema (key names, string parts), so
// it is not wrapped.
func schemaError(field string, err error) error {
	if errors.Is(err, jsontext.ErrDuplicateName) {
		return invalidTool("duplicate object key in " + field)
	}
	return invalidTool("invalid JSON in " + field)
}

// invalidTool returns an error that wraps ErrInvalidTool. reason must be a
// fixed text from this package, never server text.
func invalidTool(reason string) error {
	return fmt.Errorf("canonical form of tool: %s: %w", reason, ErrInvalidTool)
}
