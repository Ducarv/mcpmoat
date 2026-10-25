package pins

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	// maxLineRunes is the longest text, in runes, that one rendered line holds
	// after its prefix or indentation. A longer line is wrapped into chunks.
	// The report cuts each diff line at a far larger length, so without
	// wrapping a payload at the end of one long line would not show in the diff.
	maxLineRunes = 200

	// maxChunkIndent is the most indentation that a wrapped chunk after the
	// first one keeps, in spaces. It stops a deeply nested JSON line from
	// repeating a huge indentation on each of its chunks.
	maxChunkIndent = 200
)

// renderedTool is the shape of the canonical form that render reads. The
// schemas and the annotations stay raw JSON, because render only re-indents
// them. The field names are the keys that Canonical writes.
type renderedTool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title"`
	Description  string          `json:"description"`
	Annotations  json.RawMessage `json:"annotations"`
	InputSchema  json.RawMessage `json:"inputSchema"`
	OutputSchema json.RawMessage `json:"outputSchema"`
}

// render turns the canonical form of a tool (the output of Canonical, one line
// of JCS) into text with one item per line, so that a line diff is useful.
//
// Each line of the text is one of these:
//
//	name: <line of the name>
//	title: <line of the title>
//	description: <line of the description>
//	annotations:
//	  <line of the indented JSON>
//	inputSchema:
//	  <line of the indented JSON>
//	outputSchema:
//	  <line of the indented JSON>
//
// A name, a title or a description with line breaks gives one line for each of
// its lines, and each line has the prefix. So text from a server can not make
// a line that looks like another field.
//
// A line with more than maxLineRunes runes after its prefix or indentation is
// wrapped: it becomes several lines of at most maxLineRunes runes, cut on rune
// boundaries. Each chunk keeps the prefix, or the indentation, of the line. So
// a line diff shows the chunk that changed, also in a very long line. The JSON parts have two spaces of
// indent for each level, and the key order of the canonical form. A schema
// that the server did not send is null.
//
// render keeps every byte of the strings as the server sent them. It does not
// escape or normalise anything, so an added invisible character is a changed
// line. The caller must escape the text before it writes it to a terminal.
// render returns an error, and never panics, when canonical is not the
// canonical form of a tool.
func render(canonical string) (string, error) {
	var t renderedTool
	if err := json.Unmarshal([]byte(canonical), &t); err != nil {
		return "", fmt.Errorf("render tool: parse canonical form: %w", err)
	}

	var b strings.Builder
	writePrefixed(&b, "name: ", t.Name)
	writePrefixed(&b, "title: ", t.Title)
	writePrefixed(&b, "description: ", t.Description)

	sections := []struct {
		label string
		raw   json.RawMessage
	}{
		{"annotations:", t.Annotations},
		{"inputSchema:", t.InputSchema},
		{"outputSchema:", t.OutputSchema},
	}
	for _, s := range sections {
		if err := writeIndented(&b, s.label, s.raw); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// writePrefixed writes value to b, one line for each line of value, and puts
// prefix at the start of every line. A long line is wrapped (see writeWrapped).
func writePrefixed(b *strings.Builder, prefix, value string) {
	for line := range strings.SplitSeq(value, "\n") {
		writeWrapped(b, prefix, line)
	}
}

// writeWrapped writes text to b as one or more lines. Each line is lead, then
// at most maxLineRunes runes of text. It cuts only between runes, so a valid
// UTF-8 character never splits. An empty text gives one line with only lead.
// The work is linear in len(text).
//
// The chunks after the first keep lead, but at most maxChunkIndent bytes of it.
// A lead is a short prefix or spaces, so a cut inside it is safe.
func writeWrapped(b *strings.Builder, lead, text string) {
	b.WriteString(lead)
	nextLead := lead[:min(len(lead), maxChunkIndent)]
	runes := 0
	for i := 0; i < len(text); {
		if runes == maxLineRunes {
			b.WriteByte('\n')
			b.WriteString(nextLead)
			runes = 0
		}
		// For invalid UTF-8 the size is 1, so the loop always moves forward.
		_, size := utf8.DecodeRuneInString(text[i:])
		b.WriteString(text[i : i+size])
		i += size
		runes++
	}
	b.WriteByte('\n')
}

// writeIndented writes label, then the JSON in raw with two spaces of indent
// for each level, and two more spaces at the start of every line. A missing
// value is null. The key order does not change.
func writeIndented(b *strings.Builder, label string, raw json.RawMessage) error {
	if len(raw) == 0 {
		raw = json.RawMessage("null")
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "  ", "  "); err != nil {
		// The error can quote server text, so it is not wrapped.
		return fmt.Errorf("render tool: indent %s", strings.TrimSuffix(label, ":"))
	}
	b.WriteString(label)
	b.WriteByte('\n')
	// json.Indent does not indent the first line, so add the two spaces. Each
	// line is wrapped on its text, after its indentation.
	for line := range strings.SplitSeq("  "+buf.String(), "\n") {
		text := strings.TrimLeft(line, " ")
		writeWrapped(b, line[:len(line)-len(text)], text)
	}
	return nil
}
