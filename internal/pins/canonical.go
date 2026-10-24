package pins

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// Canonical form of a tool (PRD FR-11, threat T2)
//
// The pin of a tool is the hash of its canonical form. Rug-pull detection
// depends on it: the canonical form must change when, and only when, the tool
// changes. The notes below are the contract of the canonical form. Any change
// to them needs a new HashVersion (see hash.go).
//
// Field set. The canonical form holds all six fields of inspect.Tool: name,
// title, description, inputSchema, outputSchema and annotations. The
// annotations hold their title and the four hints. inspect drops the MCP
// fields _meta and icons, so they are not part of the hash.
//
// Shape. The canonical form is one JSON object with a fixed shape. Every key
// is always present, also when the server did not send the field:
//
//	{"annotations":{"destructiveHint":null|bool,"idempotentHint":null|bool,
//	 "openWorldHint":null|bool,"readOnlyHint":null|bool,"title":""},
//	 "description":"","inputSchema":<schema>|null,"name":"",
//	 "outputSchema":<schema>|null,"title":""}
//
// (The line breaks are for this comment only. The real form has no
// whitespace.) A nil hint is null. Nil annotations give the same bytes as
// empty annotations. A nil or empty schema is null, so "no schema" is
// different from the empty schema {}. The whole document is in the JSON
// Canonicalization Scheme (JCS, RFC 8785): keys sorted, no whitespace,
// minimal string escapes and one number format.
//
// No normalisation. Strings stay byte for byte as the server sent them. There
// is no Unicode normalisation (NFC or NFKC), no trimming and no escaping for
// the terminal. Invisible characters, bidi controls, tag characters and NFC
// against NFD forms all change the hash. An attacker can hide a change in
// such characters, so the hash must see them.
//
// Known limits. These come from the MCP SDK or from JCS, before or outside
// the hash:
//   - The SDK decodes schema numbers as float64, so integers above 2^53 can
//     change before pins sees them. Two schemas that differ only there can get
//     the same hash.
//   - JCS writes every number in one format, so 1, 1.0 and 1e0 are equal. They
//     are the same value in JSON Schema.
//   - The SDK keeps the last value of a duplicate object key, and replaces
//     invalid UTF-8 and lone surrogates with U+FFFD, when it decodes the
//     server message. A schema from the SDK therefore has no duplicate keys
//     and no invalid UTF-8. Canonical still rejects them for tools from other
//     sources.
//   - The SDK decodes readOnlyHint and idempotentHint as plain bool, so false
//     and absent are the same for these two hints (see inspect.ToolAnnotations).
//     A change to true always changes the hash.

// ErrInvalidTool is the error that Canonical and Hash wrap when a tool has no
// canonical form: a string field holds invalid UTF-8, or a schema is not
// valid JSON or has a duplicate object key.
var ErrInvalidTool = errors.New("invalid tool data")

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
	Annotations  canonicalAnnotations `json:"annotations"`
}

// canonicalAnnotations is the fixed shape of the annotations. json/v2 writes
// a nil *bool as null, not as an absent key.
type canonicalAnnotations struct {
	Title           string `json:"title"`
	ReadOnlyHint    *bool  `json:"readOnlyHint"`
	DestructiveHint *bool  `json:"destructiveHint"`
	IdempotentHint  *bool  `json:"idempotentHint"`
	OpenWorldHint   *bool  `json:"openWorldHint"`
}

// jsonNull is the JSON literal null.
const jsonNull = "null"

// Canonical returns the canonical form of t: the bytes that Hash hashes. See
// the notes at the top of this file for the field set, the shape and the
// limits. Canonical does not change t.
//
// Canonical returns an error that wraps ErrInvalidTool when a string field
// holds invalid UTF-8, or when a schema is not valid JSON (this includes
// invalid UTF-8 and lone surrogates in the schema) or has a duplicate object
// key. The error message names the field but never holds server text.
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

	doc, err := json.Marshal(&canonicalTool{
		Name:         t.Name,
		Title:        t.Title,
		Description:  t.Description,
		InputSchema:  in,
		OutputSchema: out,
		Annotations: canonicalAnnotations{
			Title:           ann.Title,
			ReadOnlyHint:    ann.ReadOnlyHint,
			DestructiveHint: ann.DestructiveHint,
			IdempotentHint:  ann.IdempotentHint,
			OpenWorldHint:   ann.OpenWorldHint,
		},
	})
	if err != nil {
		// The checks above make this unexpected. The json/v2 error can quote
		// server text, so it is not wrapped. Any partial output is dropped.
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

// canonicalSchema returns the JCS form of one schema, or null when raw is nil
// or empty. field is the fixed key name for the error message.
func canonicalSchema(field string, raw []byte) (jsontext.Value, error) {
	if len(raw) == 0 {
		return jsontext.Value(jsonNull), nil
	}
	// Canonicalize rewrites the bytes in place. raw shares its backing array
	// with the caller's Tool, so work on a copy: the Tool must not change.
	v := jsontext.Value(bytes.Clone(raw))
	// By default, Canonicalize rejects duplicate object keys, invalid UTF-8,
	// lone surrogates and invalid JSON. Its error message can quote the schema
	// (key names, string parts), so return a fixed message instead.
	if err := v.Canonicalize(); err != nil {
		if errors.Is(err, jsontext.ErrDuplicateName) {
			return nil, invalidTool("duplicate object key in " + field)
		}
		return nil, invalidTool("invalid JSON in " + field)
	}
	return v, nil
}

// invalidTool returns an error that wraps ErrInvalidTool. reason must be a
// fixed text from this package, never server text.
func invalidTool(reason string) error {
	return fmt.Errorf("pins: canonical form of tool: %s: %w", reason, ErrInvalidTool)
}
