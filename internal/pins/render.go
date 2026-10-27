package pins

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	// maxLineRunes is the longest text, in runes, that one rendered line holds
	// after its prefix or indentation. A longer line is wrapped into chunks.
	// The report cuts each diff line at a far larger length, so without
	// wrapping a payload at the end of one long line would not show in the diff.
	maxLineRunes = 200

	// maxIndent is the most indentation that a rendered line keeps, in bytes.
	// A deeply nested JSON line would else start with so many spaces that the
	// report cuts the line before its text, and its change would not show.
	maxIndent = 200

	// contMarker ends the lead of a wrapped chunk after the first one (see
	// render). No real line has it at that place.
	contMarker = "+ "
)

// renderedTool is the shape of the canonical form that render reads. The
// schemas, _meta, icons and the annotations stay raw JSON, because render only
// re-indents them. The field names are the keys that Canonical writes.
type renderedTool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title"`
	Description  string          `json:"description"`
	Annotations  json.RawMessage `json:"annotations"`
	Meta         json.RawMessage `json:"_meta"`
	Icons        json.RawMessage `json:"icons"`
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
//	_meta:
//	  <line of the indented JSON>
//	icons:
//	  <line of the indented JSON>
//	inputSchema:
//	  <line of the indented JSON>
//	outputSchema:
//	  <line of the indented JSON>
//
// A name, a title or a description with line breaks gives one line for each of
// its lines, and each line has the prefix. So text from a server cannot make
// a line that looks like another field.
//
// A line with more than maxLineRunes runes after its prefix or indentation is
// wrapped: it becomes several lines of at most maxLineRunes runes, cut on rune
// boundaries. So a line diff shows the chunk that changed, also in a very long
// line. The first chunk keeps the prefix, or the indentation, of the line. The
// next chunks have a continuation lead: the field name and "+ " (for example
// "description+ "), or the indentation and "+ ". A real line never starts like
// that (a field line has ": ", and a JSON line never starts with "+"), so a
// wrapped line and a line break in the text never render the same.
//
// The JSON parts have two spaces of indent for each level, and the key order
// of the canonical form. A schema, _meta or icons value that the server did not
// send is null.
//
// mask, when it is not nil, hides secret values (see CompareMasked). render
// applies it to the decoded text before it wraps the lines: to the name, the
// title and the description, and to every string (object keys included) and
// every number in the JSON parts (see maskJSON). So a secret that would be
// split over two wrapped lines is still found. A secret that the server writes
// with a JSON escape (such as \" or \u0041) is also found, because the decode
// removes the escape. The mask does not find a configured value that holds a
// backslash sequence as plain characters (such as the \t and \n of the Windows
// path C:\tools\new_dir) when the server sends the real characters (a tab, a
// newline). The output then escapes those characters, so the value can show.
// docs/limits.md lists this limit. A nil mask changes nothing.
//
// Apart from the mask, render keeps every byte of the strings as the server
// sent them. It does not escape or normalise anything, so an added invisible
// character is a changed line. The caller must escape the text before it
// writes it to a terminal. render returns an error, and never panics, when
// canonical is not the canonical form of a tool.
func render(canonical string, mask func(string) string) (string, error) {
	var t renderedTool
	if err := json.Unmarshal([]byte(canonical), &t); err != nil {
		// The error of encoding/json can quote input, so it is not wrapped,
		// like the error of json.Indent below. The caller adds the context.
		return "", errors.New("parse canonical form")
	}
	if mask != nil {
		if err := maskTool(&t, mask); err != nil {
			return "", err
		}
	}

	var b strings.Builder
	writePrefixed(&b, "name: ", t.Name)
	writePrefixed(&b, "title: ", t.Title)
	writePrefixed(&b, "description: ", t.Description)

	// annotations, _meta and icons come before the schemas, so a large unchanged
	// schema cannot push a change in them out of a cut diff. The server controls
	// the size of _meta, so a large _meta change, or a large _meta or icons
	// value in a new tool, can still push the schemas out (issue #162).
	sections := []struct {
		label string
		raw   json.RawMessage
	}{
		{"annotations:", t.Annotations},
		{"_meta:", t.Meta},
		{"icons:", t.Icons},
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

// maskTool applies mask to the text fields of t and to the strings and
// numbers of its JSON parts. mask must not be nil. The error names only the
// part, never server text.
func maskTool(t *renderedTool, mask func(string) string) error {
	t.Name = mask(t.Name)
	t.Title = mask(t.Title)
	t.Description = mask(t.Description)

	// A pointer to each field lets one loop change the field in place.
	parts := []struct {
		label string
		raw   *json.RawMessage
	}{
		{"annotations", &t.Annotations},
		{"_meta", &t.Meta},
		{"icons", &t.Icons},
		{"inputSchema", &t.InputSchema},
		{"outputSchema", &t.OutputSchema},
	}
	for _, p := range parts {
		masked, err := maskJSON(*p.raw, mask)
		if err != nil {
			return fmt.Errorf("mask %s: %w", p.label, err)
		}
		*p.raw = masked
	}
	return nil
}

// maskJSON returns raw with mask applied to the decoded text of every string,
// object keys included, and of every number. A string or a number that mask
// changes is written again as a JSON string with the minimal escapes of JCS. A
// number becomes a string, because the masked text is no longer a number. All
// other bytes stay as they are, so the result equals raw when mask changes
// nothing. An empty raw stays empty. mask must not be nil.
//
// The mask works on the decoded text, not on the escaped JSON. So a JSON
// escape that the server writes (such as \" or \u0041) cannot hide a secret.
// A configured value that holds a backslash sequence as plain characters
// (such as \t, \n or \uXXXX) is not found when the server sends the real
// characters (see render). maskJSON returns an error when raw is not one
// valid JSON value. The error holds no server text.
func maskJSON(raw json.RawMessage, mask func(string) string) (json.RawMessage, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	var out []byte // nil until mask changes a token
	copied := 0    // raw[:copied] is in out already
	for {
		// InputOffset is the end of the last token read, so before ReadToken
		// it is where the separators before the next token start.
		prevEnd := int(dec.InputOffset())
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// The jsontext error can quote raw, so it is not wrapped.
			return nil, errors.New("parse JSON")
		}
		if k := tok.Kind(); k != '"' && k != '0' {
			continue
		}
		// For a string, tok.String is the decoded text. For a number, it is
		// the number as written.
		text := tok.String()
		masked := mask(text)
		if masked == text {
			continue
		}
		end := int(dec.InputOffset())
		start := tokenStart(raw, prevEnd, end)
		out = append(out, raw[copied:start]...)
		// The input of AppendQuote must be valid UTF-8, or it returns an
		// error. mask may give invalid UTF-8, so replace it first.
		out, err = jsontext.AppendQuote(out, strings.ToValidUTF8(masked, "\uFFFD"))
		if err != nil {
			return nil, errors.New("quote masked text")
		}
		copied = end
	}
	if out == nil {
		return raw, nil
	}
	return append(out, raw[copied:]...), nil
}

// tokenStart returns the index in raw where the string or number token that
// ends at end starts. Between the end of the token before it (prevEnd) and the
// token, raw can hold only white space, a comma and a colon.
func tokenStart(raw []byte, prevEnd, end int) int {
	i := prevEnd
	for i < end && strings.IndexByte(" \t\r\n,:", raw[i]) >= 0 {
		i++
	}
	return i
}

// writePrefixed writes value to b, one line for each line of value, and puts
// prefix at the start of every line. A long line is wrapped (see writeWrapped).
func writePrefixed(b *strings.Builder, prefix, value string) {
	cont := strings.TrimSuffix(prefix, ": ") + contMarker
	for line := range strings.SplitSeq(value, "\n") {
		writeWrapped(b, prefix, cont, line)
	}
}

// writeWrapped writes text to b as one or more lines. The first line is lead,
// and the next lines are cont, each followed by at most maxLineRunes runes of
// text. It cuts only between runes, so a valid UTF-8 character never splits. An
// empty text gives one line with only lead. The work is linear in len(text).
//
// Every line keeps at most maxIndent bytes of lead, and cont keeps contMarker
// after the cut. cont must end with contMarker. A lead is a short prefix or
// spaces, so a cut inside it is safe.
func writeWrapped(b *strings.Builder, lead, cont, text string) {
	lead = lead[:min(len(lead), maxIndent)]
	if len(cont) > maxIndent+len(contMarker) {
		cont = cont[:maxIndent] + contMarker
	}
	b.WriteString(lead)
	runes := 0
	for i := 0; i < len(text); {
		if runes == maxLineRunes {
			b.WriteByte('\n')
			b.WriteString(cont)
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
		return fmt.Errorf("indent %s", strings.TrimSuffix(label, ":"))
	}
	b.WriteString(label)
	b.WriteByte('\n')
	// json.Indent does not indent the first line, so add the two spaces. Each
	// line is wrapped on its text, after its indentation.
	for line := range strings.SplitSeq("  "+buf.String(), "\n") {
		text := strings.TrimLeft(line, " ")
		indent := line[:len(line)-len(text)]
		writeWrapped(b, indent, indent+contMarker, text)
	}
	return nil
}
