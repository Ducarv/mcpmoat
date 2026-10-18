package inspect

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This file converts MCP SDK types to the SDK-free types in result.go, so
// that no SDK type leaves this package (NFR-06).

// toTools converts the tools of one list. It skips nil elements and keeps the
// order of the others.
func toTools(in []*mcp.Tool) ([]Tool, error) {
	out := make([]Tool, 0, len(in))
	for i, t := range in {
		if t == nil {
			continue
		}
		tool, err := toTool(t)
		if err != nil {
			// The index, not the name: the name is untrusted server text.
			return nil, fmt.Errorf("tool %d: %w", i, err)
		}
		out = append(out, tool)
	}
	return out, nil
}

// toPrompts converts the prompts of one list. It skips nil elements and keeps
// the order of the others.
func toPrompts(in []*mcp.Prompt) []Prompt {
	out := make([]Prompt, 0, len(in))
	for _, p := range in {
		if p == nil {
			continue
		}
		out = append(out, toPrompt(p))
	}
	return out
}

// toResources converts the resources of one list. It skips nil elements and
// keeps the order of the others.
func toResources(in []*mcp.Resource) []Resource {
	out := make([]Resource, 0, len(in))
	for _, r := range in {
		if r == nil {
			continue
		}
		out = append(out, toResource(r))
	}
	return out
}

// toTool converts one SDK tool. t must not be nil.
//
// Title is the top-level title field of the tool. The SDK also has
// t.Annotations.Title, a display hint; toTool does not copy it.
//
// On the client side the SDK decodes inputSchema and outputSchema with
// encoding/json into an any, usually a map[string]any. toTool encodes them
// again with [rawJSON]. An absent or null schema (also a typed nil map)
// gives a nil json.RawMessage. An error wraps [ErrProtocol].
func toTool(t *mcp.Tool) (Tool, error) {
	in, err := rawJSON(t.InputSchema)
	if err != nil {
		return Tool{}, fmt.Errorf("input schema: %w", err)
	}
	out, err := rawJSON(t.OutputSchema)
	if err != nil {
		return Tool{}, fmt.Errorf("output schema: %w", err)
	}
	return Tool{
		Name:         t.Name,
		Title:        t.Title,
		Description:  t.Description,
		InputSchema:  in,
		OutputSchema: out,
	}, nil
}

// toPrompt converts one SDK prompt. p must not be nil. It skips nil
// arguments and keeps the order of the others.
func toPrompt(p *mcp.Prompt) Prompt {
	var args []PromptArgument
	for _, a := range p.Arguments {
		if a == nil {
			continue
		}
		args = append(args, PromptArgument{
			Name:        a.Name,
			Title:       a.Title,
			Description: a.Description,
			Required:    a.Required,
		})
	}
	return Prompt{
		Name:        p.Name,
		Title:       p.Title,
		Description: p.Description,
		Arguments:   args,
	}
}

// toResource converts one SDK resource. r must not be nil.
func toResource(r *mcp.Resource) Resource {
	return Resource{
		URI:         r.URI,
		Name:        r.Name,
		Title:       r.Title,
		Description: r.Description,
		MIMEType:    r.MIMEType,
	}
}

// rawJSON encodes v as JSON. A value that is JSON null gives a nil result,
// not the bytes "null". This covers a nil v, a typed nil such as
// map[string]any(nil), and a json.RawMessage that holds null with optional
// white space around it, such as " null ".
//
// A json.RawMessage is checked and copied, not encoded again. Any other value
// is encoded with encoding/json: map keys come out sorted, so the same schema
// always gives the same bytes, which pins need for a stable hash. HTML
// escaping is off, so text such as "<IMPORTANT>" stays readable and rules
// can match it. encoding/json still writes U+2028 and U+2029 as the escapes
// \u2028 and \u2029, writes control characters as escapes, and replaces
// invalid UTF-8 with U+FFFD. So the bytes are not exactly what the server
// sent: a rule that looks for hidden characters must decode the schema
// strings, not match the raw bytes. An error wraps [ErrProtocol].
func rawJSON(v any) (json.RawMessage, error) {
	switch v := v.(type) {
	case nil:
		return nil, nil
	case json.RawMessage:
		if v == nil {
			return nil, nil
		}
		if !json.Valid(v) {
			return nil, fmt.Errorf("%w: schema is not valid JSON", ErrProtocol)
		}
		if isNull(v) {
			return nil, nil
		}
		return bytes.Clone(v), nil
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("%w: encode schema: %w", ErrProtocol, err)
	}
	// Encode adds a newline after the value; the raw JSON does not keep it.
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if isNull(out) {
		return nil, nil
	}
	return out, nil
}

// isNull reports whether b is the JSON literal null, with optional white
// space around it.
func isNull(b []byte) bool {
	return bytes.Equal(bytes.TrimSpace(b), []byte("null"))
}
