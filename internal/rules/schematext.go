package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

const (
	// maxSchemaDepth is the deepest nesting of objects and arrays that
	// walkSchema reads: the inspect cap, so a schema that inspect accepts is
	// read in full. json.Decoder.Token has no depth limit, so walkSchema counts
	// the depth itself.
	maxSchemaDepth = inspect.MaxJSONDepth

	// maxSchemaValues is the most JSON values that walkSchema reads: the
	// inspect cap. walkSchema counts the same things as inspect: objects,
	// arrays, object keys, strings, numbers, true, false and null. Closing '}'
	// and ']' are not counted. So a schema that inspect accepts never goes
	// over this cap. The cap keeps the work bounded for any input.
	maxSchemaValues = inspect.MaxJSONValues
)

// schemaFrame is one open object or array while walkSchema reads a schema.
type schemaFrame struct {
	isObject  bool   // true for an object, false for an array
	expectKey bool   // object only: the next string token is a key
	key       string // object only: the key of the value that comes next
}

// take reads the next token inside the frame. In an object, tokens are a key,
// then its value, then a key again. take reports isKey for a key. For a value,
// it returns the key of that value; in an array, the key is "".
func (f *schemaFrame) take(tok json.Token) (key string, isKey bool) {
	if !f.isObject {
		return "", false
	}
	if f.expectKey {
		f.key, _ = tok.(string) // the decoder checks that a key is a string
		f.expectKey = false
		return "", true
	}
	f.expectKey = true
	return f.key, false
}

// schemaVisitor gets one token from walkSchema. tok is an object key, a scalar
// value (a string, a json.Number, a bool or nil), or a json.Delim. isKey is
// true for an object key. For a value, key is the object key of that value; in
// an array or at the top level, key is "". An opening '{' or '[' is a value
// too, so it has the key of the object or array that it opens. A closing '}'
// or ']' has the key "".
type schemaVisitor func(tok json.Token, key string, isKey bool)

// walkSchema reads the first JSON value in raw, token by token, and calls
// visit for each object key, each scalar value and each delimiter, in
// document order. visit gets an opening '{' or '[' after the frame opens and a
// closing '}' or ']' after the frame closes. So the opening and closing
// delimiters that visit sees always match, even when the walk stops at a
// bound. A visitor that does not need the delimiters can skip every token that
// is not a string.
//
// The decoder resolves JSON escapes first. So the key written as
// "\u0064escription" arrives as "description", and the text "\u200b" arrives
// as the rune U+200B. Numbers arrive as json.Number, so a huge number is not
// an error.
//
// The read is bounded by maxSchemaDepth and maxSchemaValues. A string has no
// size cap. The caller bounds the input size.
//
// complete is false when the walk may be partial: the JSON is malformed, has
// data after the first value, or went over a bound. visit has then seen the
// tokens before the stop. Empty or whitespace-only input is malformed.
func walkSchema(raw []byte, visit schemaVisitor) (complete bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // a huge number is not an error for this function

	var stack []schemaFrame
	values := 0
tokens:
	for {
		tok, err := dec.Token()
		if err != nil {
			return false // malformed JSON, or EOF before a full value
		}

		// A closing '}' or ']' is not a value, as in inspect. The decoder
		// checks that it matches an open frame.
		if tok == json.Delim('}') || tok == json.Delim(']') {
			stack = stack[:len(stack)-1]
			visit(tok, "", false)
			if len(stack) == 0 {
				break tokens // the first top-level value is complete
			}
			continue
		}

		// Every other token is a value, and it is counted as inspect counts it.
		values++
		if values > maxSchemaValues {
			return false
		}

		key := ""
		if n := len(stack); n > 0 {
			var isKey bool
			if key, isKey = stack[n-1].take(tok); isKey {
				visit(tok, "", true)
				continue
			}
		}

		if v, ok := tok.(json.Delim); ok { // '{' or '['
			if len(stack) >= maxSchemaDepth {
				return false
			}
			stack = append(stack, schemaFrame{isObject: v == '{', expectKey: v == '{'})
		}
		visit(tok, key, false)

		if len(stack) == 0 {
			break tokens // a top-level scalar is the whole value
		}
	}

	// Only the end of the input may follow the first value.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return false
	}
	return true
}

// schemaStrings returns every object key and every string value of a JSON
// schema, decoded, in document order. Each distinct string is returned once,
// at its first place. Numbers, booleans and null are skipped.
//
// The decoder resolves JSON escapes first. So the text "\u001b" is returned as
// the ESC rune U+001B, and a rule sees the same text that a model reads.
//
// The read is bounded by maxSchemaDepth and maxSchemaValues. A string has no
// size cap. The caller bounds the input size. complete is true only when the
// JSON is valid, has no data after the first value, and no bound cut the
// read. Otherwise strs holds what the function read before it stopped. Empty
// or whitespace-only input is not valid JSON: it gives (nil, false).
func schemaStrings(raw []byte) (strs []string, complete bool) {
	seen := make(map[string]struct{})
	complete = walkSchema(raw, func(tok json.Token, _ string, _ bool) {
		s, ok := tok.(string)
		if !ok {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		strs = append(strs, s)
	})
	return strs, complete
}

// shadowKind is the role of one open object or array while schemaShadowTexts
// reads a schema.
type shadowKind uint8

const (
	// shadowData is any JSON data, such as the value of default, enum or a
	// vendor key. Every key and every string is scanned.
	shadowData shadowKind = iota
	// shadowSchema is a schema object. Its keys that are keyword names
	// (see isSchemaKeyword) are skipped, and so are a format value that is a
	// registered format name and a $schema value that is a standard
	// meta-schema URI.
	shadowSchema
	// shadowNames is an object whose keys are names that the server chose,
	// such as the value of properties. Every key is scanned, and each value
	// is a schema.
	shadowNames
	// shadowSchemaList is an array of schemas, such as the value of allOf.
	shadowSchemaList
)

// schemaShadowTexts returns the texts of a JSON schema that CheckShadowing
// scans: every string value and every object key, decoded, in document order.
// Each distinct string is returned once, at its first place. Numbers,
// booleans and null are skipped.
//
// Three kinds of string are not returned, because they are fixed words of JSON
// Schema and not text of the server. foldText turns them into compound names
// (readOnly is read_only, anyOf is any_of, the format date-time is date_time,
// the URI "http://json-schema.org/draft-07/schema#" holds json_schema) that
// can equal the name of a tool of another server, so every schema would
// mention that tool:
//   - a key of a schema object that is a keyword name of JSON Schema 2020-12,
//     2019-09 or draft-07 (see isSchemaKeyword). The match is exact and case
//     sensitive. The value of the keyword is still read: the text of
//     description, title, $comment, default, enum, const and examples is
//     returned.
//   - the value of the format key of a schema object, when it is exactly a
//     registered format name (see isRegisteredFormat), such as "date-time",
//     "uuid" or "int64". The list is fixed, so the value is not text of the
//     server. Any other format value is returned, also one word such as
//     "send_email" or "sendEmail": the server chose it.
//   - the value of the $schema key of a schema object, when the whole value
//     is a standard meta-schema URI (see isMetaSchemaURI), such as
//     "http://json-schema.org/draft-07/schema#", which zod-to-json-schema
//     writes. The match is exact and case sensitive. Any other $schema value
//     is returned, also a json-schema.org URI with another path, such as
//     "https://json-schema.org/send_email": a path can hold an instruction.
//
// A key is a keyword only in a schema object. The function follows the
// keywords that hold schemas: the top-level object is a schema; the value of
// items, additionalProperties, not, if, then, else and the like is a schema;
// the items of allOf, anyOf, oneOf and prefixItems (and of items in the
// draft-07 array form) are schemas; and the values of properties,
// patternProperties, $defs, definitions, dependentSchemas and dependencies
// are schemas. The keys of these last objects are names that the server
// chose, so they are returned even when a name is a keyword word, such as a
// property named "readOnly". Any other object or array is data (the value of
// default, enum, const, examples, a vendor key such as x-* or
// markdownDescription, or an unknown key): all of its keys and strings are
// returned. A top-level string is returned too.
//
// The decoder resolves JSON escapes first. So the key written as
// "\u0074ype" is the keyword "type", and the text "\u200b" is returned as the
// rune U+200B.
//
// The read has the bounds of walkSchema: maxSchemaDepth and maxSchemaValues. A
// string has no size cap, so padding cannot hide a mention. The caller bounds
// the input size. The cost is linear in the size of raw.
//
// complete is false when the texts may be partial: the JSON is malformed, has
// data after the first value, or went over a bound. texts then holds what the
// function read before it stopped. Empty input gives (nil, true), and
// whitespace-only input is malformed: (nil, false).
func schemaShadowTexts(raw json.RawMessage) (texts []string, complete bool) {
	if len(raw) == 0 {
		return nil, true
	}
	seen := make(map[string]struct{})
	var kinds []shadowKind // the kind of each open object and array
	complete = walkSchema(raw, func(tok json.Token, key string, isKey bool) {
		parent := shadowData // the kind of the object or array that holds tok
		if n := len(kinds); n > 0 {
			parent = kinds[n-1]
		}
		switch v := tok.(type) {
		case json.Delim:
			switch {
			case v == '}' || v == ']':
				if len(kinds) > 0 {
					kinds = kinds[:len(kinds)-1]
				}
			case len(kinds) == 0:
				kinds = append(kinds, shadowRootKind(v))
			default:
				kinds = append(kinds, shadowChildKind(parent, key, v))
			}
		case string:
			if parent == shadowSchema && skipSchemaString(v, key, isKey) {
				return
			}
			if _, dup := seen[v]; dup {
				return
			}
			seen[v] = struct{}{}
			texts = append(texts, v)
		}
	})
	return texts, complete
}

// skipSchemaString reports whether schemaShadowTexts skips the string s of a
// schema object: a keyword key, a format value that is a registered format
// name, or a $schema value that is a standard meta-schema URI. key is the key
// of the value s, and isKey is true when s is itself a key.
func skipSchemaString(s, key string, isKey bool) bool {
	if isKey {
		return isSchemaKeyword(s)
	}
	switch key {
	case "format":
		return isRegisteredFormat(s)
	case "$schema":
		return isMetaSchemaURI(s)
	}
	return false
}

// isRegisteredFormat reports whether s is exactly a format name of JSON
// Schema 2020-12 (such as "date-time" or "uuid") or of OpenAPI (such as
// "int64" or "password"). The match is case sensitive. foldText turns some of
// these names into compound names (date-time is date_time), so a skip keeps a
// tool of another server with such a name from being mentioned by every
// schema. Any other value is text of the server.
func isRegisteredFormat(s string) bool {
	switch s {
	case
		// JSON Schema 2020-12.
		"date-time", "date", "time", "duration", "email", "idn-email",
		"hostname", "idn-hostname", "ipv4", "ipv6", "uri", "uri-reference",
		"iri", "iri-reference", "uuid", "uri-template", "json-pointer",
		"relative-json-pointer", "regex",
		// OpenAPI.
		"int32", "int64", "float", "double", "byte", "binary", "password":
		return true
	}
	return false
}

// metaSchemaURI matches a whole value that is a standard meta-schema URI:
// "http://" or "https://", then "json-schema.org/", then "draft-03/schema" to
// "draft-07/schema", "draft/2019-09/schema" or "draft/2020-12/schema", then
// an optional "#". Nothing can come before or after it, so the value holds no
// text of the server.
var metaSchemaURI = regexp.MustCompile(`^https?://json-schema\.org/(draft-0[3-7]/schema|draft/20(19-09|20-12)/schema)#?$`)

// isMetaSchemaURI reports whether the whole of s is a standard meta-schema URI
// (see metaSchemaURI). The match is exact and case sensitive. A json-schema.org
// URI with any other path, query or text is not a meta-schema URI.
func isMetaSchemaURI(s string) bool {
	return metaSchemaURI.MatchString(s)
}

// shadowRootKind returns the kind of the top-level object or array that open
// starts: an object is a schema, and an array is data.
func shadowRootKind(open json.Delim) shadowKind {
	if open == '{' {
		return shadowSchema
	}
	return shadowData
}

// shadowChildKind returns the kind of the object or array that open starts.
// parent is the kind of the object or array that holds it, and key is its key
// in parent ("" in an array).
func shadowChildKind(parent shadowKind, key string, open json.Delim) shadowKind {
	switch parent {
	case shadowNames, shadowSchemaList:
		if open == '{' {
			return shadowSchema
		}
	case shadowSchema:
		switch {
		case open == '{' && holdsSchema(key):
			return shadowSchema
		case open == '{' && holdsNames(key):
			return shadowNames
		case open == '[' && holdsSchemaList(key):
			return shadowSchemaList
		}
	}
	return shadowData
}

// holdsSchema reports whether the keyword key has one schema as its value.
func holdsSchema(key string) bool {
	switch key {
	case "items", "additionalItems", "unevaluatedItems", "contains",
		"additionalProperties", "unevaluatedProperties", "propertyNames",
		"not", "if", "then", "else", "contentSchema":
		return true
	}
	return false
}

// holdsSchemaList reports whether the keyword key has an array of schemas as
// its value. items has this form in draft-07.
func holdsSchemaList(key string) bool {
	switch key {
	case "allOf", "anyOf", "oneOf", "prefixItems", "items":
		return true
	}
	return false
}

// holdsNames reports whether the keyword key has as its value an object whose
// keys are names that the server chose and whose values are schemas. In
// draft-07, a value of dependencies can also be an array of names; an array
// is data, so its names are returned.
func holdsNames(key string) bool {
	switch key {
	case "properties", "patternProperties", "$defs", "definitions",
		"dependentSchemas", "dependencies":
		return true
	}
	return false
}

// isSchemaKeyword reports whether key is a keyword name of JSON Schema
// 2020-12, 2019-09 or draft-07: the core, applicator, unevaluated,
// validation, meta-data, format and content vocabularies, and the draft-07
// keywords that 2020-12 renamed or removed. The match is case sensitive, as in
// JSON Schema.
func isSchemaKeyword(key string) bool {
	switch key {
	// Core.
	case "$schema", "$id", "$ref", "$anchor", "$dynamicRef", "$dynamicAnchor",
		"$recursiveRef", "$recursiveAnchor", "$vocabulary", "$comment", "$defs":
		return true
	// Applicator and unevaluated.
	case "prefixItems", "items", "additionalItems", "contains", "properties",
		"patternProperties", "additionalProperties", "dependentSchemas",
		"propertyNames", "if", "then", "else", "allOf", "anyOf", "oneOf", "not",
		"unevaluatedItems", "unevaluatedProperties":
		return true
	// Validation.
	case "type", "enum", "const", "multipleOf", "maximum", "exclusiveMaximum",
		"minimum", "exclusiveMinimum", "maxLength", "minLength", "pattern",
		"maxItems", "minItems", "uniqueItems", "maxContains", "minContains",
		"maxProperties", "minProperties", "required", "dependentRequired":
		return true
	// Meta-data, format and content.
	case "title", "description", "default", "deprecated", "readOnly",
		"writeOnly", "examples", "format", "contentEncoding", "contentMediaType",
		"contentSchema":
		return true
	// Draft-07 keywords that 2020-12 renamed or removed.
	case "definitions", "dependencies":
		return true
	}
	return false
}
