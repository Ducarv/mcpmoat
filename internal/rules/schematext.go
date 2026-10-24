package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

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

// schemaVisitor gets one token from walkSchema. tok is an object key, or a
// scalar value: a string, a json.Number, a bool or nil. isKey is true for an
// object key. For a value, key is the object key of that value; in an array or
// at the top level, key is "".
type schemaVisitor func(tok json.Token, key string, isKey bool)

// walkSchema reads the first JSON value in raw, token by token, and calls
// visit for each object key and each scalar value, in document order. It does
// not call visit for the '{', '[', '}' and ']' delimiters.
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
		} else {
			visit(tok, key, false)
		}

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

// schemaText returns the decoded text of every "description" and "title"
// string in a JSON schema, in document order. A string is collected when it is
// the value of a key named "description" or "title", in any case, at any
// depth.
//
// The decoder resolves JSON escapes first. So the key written as
// "\u0064escription" matches "description", and the text "\u200b" is returned
// as the rune U+200B.
//
// The function does not model schema keywords on purpose. A property that is
// named "description" and has an object as value is not collected, but the
// description strings inside that object are. Every other value is read too,
// so the function may collect more than a schema validator would. That is
// safe for text rules. A repeated key is collected each time. A string with no
// key, such as a top-level string, is not collected.
//
// The read is bounded by maxSchemaDepth and maxSchemaValues. A string has no
// size cap, so padding cannot hide a mention. The caller bounds the input
// size.
//
// complete is false when the text may be partial: the JSON is malformed, has
// data after the first value, or went over a bound. texts then holds what the
// function read before it stopped. Empty input gives (nil, true), and
// whitespace-only input is malformed: (nil, false).
func schemaText(raw json.RawMessage) (texts []string, complete bool) {
	if len(raw) == 0 {
		return nil, true
	}
	complete = walkSchema(raw, func(tok json.Token, key string, isKey bool) {
		s, ok := tok.(string)
		if !ok || isKey {
			return
		}
		// A model reads "Description" as well as "description".
		if strings.EqualFold(key, "description") || strings.EqualFold(key, "title") {
			texts = append(texts, s)
		}
	})
	return texts, complete
}

// schemaStrings returns every object key and every string value of a JSON
// schema, decoded, in document order. Each distinct string is returned once,
// at its first place. Numbers, booleans and null are skipped.
//
// The decoder resolves JSON escapes first. So the text "\u001b" is returned as
// the ESC rune U+001B, and a rule sees the same text that a model reads.
//
// The read has the same bounds as schemaText. complete is true only when the
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
