package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

const (
	// maxSchemaDepth is the deepest nesting of objects and arrays that
	// schemaText reads: the inspect cap, so a schema that inspect accepts is
	// read in full. json.Decoder.Token has no depth limit, so schemaText counts
	// the depth itself.
	maxSchemaDepth = inspect.MaxJSONDepth

	// maxSchemaValues is the most JSON values that schemaText reads: the
	// inspect cap. schemaText counts the same things as inspect: objects,
	// arrays, object keys, strings, numbers, true, false and null. Closing '}'
	// and ']' are not counted. So a schema that inspect accepts never goes
	// over this cap. The cap keeps the work bounded for any input.
	maxSchemaValues = inspect.MaxJSONValues
)

// schemaFrame is one open object or array while schemaText reads a schema.
type schemaFrame struct {
	isObject  bool   // true for an object, false for an array
	expectKey bool   // object only: the next string token is a key
	key       string // object only: the key of the value that comes next
}

// schemaText returns the decoded text of every "description" and "title"
// string in a JSON schema, in document order. A string is collected when it is
// the value of a key named exactly "description" or "title", at any depth.
// The decoder resolves JSON escapes, so the key "description" and the
// text "\u200b" are returned as the characters that they stand for.
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

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // a huge number is not an error for this function

	var stack []schemaFrame
	values := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return texts, false // malformed JSON, or EOF before a full value
		}

		// A closing delimiter is not a value. Every other token is one: it is
		// counted, as inspect counts it. Then find the key of this value, and
		// mark the parent as ready for the next key.
		key := ""
		if d, isDelim := tok.(json.Delim); !isDelim || d == '{' || d == '[' {
			values++
			if values > maxSchemaValues {
				return texts, false
			}
			if n := len(stack); n > 0 && stack[n-1].isObject {
				top := &stack[n-1]
				if top.expectKey {
					// A string here is a key (the decoder checks that it is one).
					if s, ok := tok.(string); ok {
						top.key = s
						top.expectKey = false
					}
					continue
				}
				key = top.key
				top.expectKey = true
			}
		}

		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if len(stack) >= maxSchemaDepth {
					return texts, false
				}
				stack = append(stack, schemaFrame{isObject: v == '{', expectKey: v == '{'})
			default: // '}' or ']'
				stack = stack[:len(stack)-1]
			}
		case string:
			if key == "description" || key == "title" {
				texts = append(texts, v)
			}
		}

		if len(stack) == 0 {
			break // the first top-level value is complete
		}
	}

	// Only the end of the input may follow the first value.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return texts, false
	}
	return texts, true
}
