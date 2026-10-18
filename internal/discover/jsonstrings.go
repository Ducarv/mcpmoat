package discover

import (
	"bytes"
	"encoding/json"
	"unicode/utf16"
	"unicode/utf8"
)

// This file holds the string checks of the JSON reader. encoding/json turns a
// string that has no valid UTF-8 form into U+FFFD, and so it can make two
// different names one name:
//
//   - A lone UTF-16 surrogate escape ("\ud800" with no low surrogate after
//     it) becomes one U+FFFD. JSON.parse in the clients keeps it as it is, so
//     "x\ud800" and "x\udc00" are two names for the client.
//   - An invalid UTF-8 byte becomes one U+FFFD for each bad byte. The clients
//     decode the file with a UTF-8 decoder that gives one U+FFFD for each
//     maximal bad sequence. So "x\xE2\x82" (one sequence) and "x\xC0\xC0"
//     (two sequences) are two names for the client, but both are "x" and two
//     U+FFFD for encoding/json.
//
// decodeJSONTop rejects such a file with reasonBadString. These functions
// find the position of the first bad string.

// findBadServerString returns the byte offset in data of the first bad string
// (see findBadString) in a part of the file that the reader uses, or -1 if
// there is none. For a bad string under "projects", it also returns the
// project key, decoded (a bad part of it is U+FFFD).
//
// The checked parts are:
//   - the value of every top-level "mcpServers" member: the server names and
//     all keys and values of the entries (command, args, env, url, headers);
//   - if readProjects is true, every key of the top-level "projects" object,
//     and the value of every "mcpServers" member of every project.
//
// A duplicate key is checked every time it occurs, although encoding/json
// keeps only the last one. The other parts of the file are not checked.
// ~/.claude.json holds chat history and other text that mcpmoat ignores, and
// JavaScript's JSON.stringify writes a lone surrogate when a string was cut
// inside a surrogate pair. A check of the whole file would then reject every
// server of the file for a reason that does not matter to mcpmoat.
//
// data must be a valid JSON object.
func findBadServerString(data []byte, readProjects bool) (int, string) {
	top, _ := objectMembers(data)
	for _, m := range top {
		switch {
		case m.key == keyMCPServers:
			if off := findBadString(data[m.valStart:m.valEnd]); off >= 0 {
				return m.valStart + off, ""
			}
		case m.key == keyProjects && readProjects:
			if off, project := findBadProjectString(data[m.valStart:m.valEnd]); off >= 0 {
				return m.valStart + off, project
			}
		}
	}
	return -1, ""
}

// findBadProjectString does the "projects" part of findBadServerString. data
// is the value of "projects", and the offset it returns is an offset in data.
// A value that is not an object has nothing to check; decodeProjects reports
// it. The same holds for a project that is not an object.
func findBadProjectString(data []byte) (int, string) {
	projects, _ := objectMembers(data)
	for _, p := range projects {
		// The key range holds only the key string, and maybe a comma and
		// whitespace before it, so this checks the project key only.
		if off := findBadString(data[p.keyStart:p.keyEnd]); off >= 0 {
			return p.keyStart + off, p.key
		}
		// Offsets of the project fields are relative to the project value.
		value := data[p.valStart:p.valEnd]
		fields, _ := objectMembers(value)
		for _, f := range fields {
			if f.key != keyMCPServers {
				continue
			}
			if off := findBadString(value[f.valStart:f.valEnd]); off >= 0 {
				return p.valStart + f.valStart + off, p.key
			}
		}
	}
	return -1, ""
}

// jsonMember is one member of a JSON object: its decoded key and two byte
// ranges in the data of the object. The key range starts where the previous
// member (or the "{") ends, so it can hold a comma and whitespace before the
// key string. It ends right after the closing quote of the key. The value
// range holds the value and nothing else.
type jsonMember struct {
	key              string
	keyStart, keyEnd int
	valStart, valEnd int
}

// objectMembers returns the members of the JSON object in data, in file
// order. A key that occurs twice gives two members. It returns false if data
// is not a valid JSON object.
//
// Unmarshal into a map cannot tell where a value is in the file, and a
// json.RawMessage is a copy, not a part of data. So objectMembers reads the
// object one token at a time with a json.Decoder, and takes the positions
// from Decoder.InputOffset.
func objectMembers(data []byte) ([]jsonMember, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var members []jsonMember
	for dec.More() {
		m := jsonMember{keyStart: int(dec.InputOffset())}
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok {
			return nil, false
		}
		m.key = key
		m.keyEnd = int(dec.InputOffset())
		// Decode reads the value. RawMessage keeps its bytes as written, so
		// its length is the length of the value in data.
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		// Between the key and the value there is only a colon and JSON
		// white space. len(data) minus the length of the rest gives the index.
		m.valStart = len(data) - len(bytes.TrimLeft(data[m.keyEnd:], jsonSpace+":"))
		m.valEnd = m.valStart + len(raw)
		members = append(members, m)
	}
	return members, true
}

// findBadString returns the byte offset of the first bad string part in data,
// or -1 if there is none. A bad part is a lone surrogate escape (see
// findLoneSurrogate) or an invalid UTF-8 byte (see findInvalidUTF8). When
// data has both, the offset of the first one is returned.
//
// data must be valid JSON, or a part of valid JSON that starts and ends
// outside a string (see findLoneSurrogate).
func findBadString(data []byte) int {
	s := findLoneSurrogate(data)
	u := findInvalidUTF8(data)
	switch {
	case s < 0:
		return u
	case u < 0:
		return s
	default:
		return min(s, u)
	}
}

// findInvalidUTF8 returns the byte offset of the first byte in data that is
// not part of a valid UTF-8 sequence, or -1 if data is valid UTF-8. The text
// U+FFFD itself (the bytes EF BF BD) is valid.
//
// In valid JSON every byte outside a string is ASCII, so a bad byte is always
// in a string.
func findInvalidUTF8(data []byte) int {
	if utf8.Valid(data) {
		return -1
	}
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		i += size
	}
	return -1
}

// findLoneSurrogate returns the byte offset of the first \u escape in data
// that is a lone UTF-16 surrogate, or -1 if there is none. A high surrogate
// (U+D800 to U+DBFF) is valid only if a \u escape of a low surrogate (U+DC00
// to U+DFFF) comes right after it. A low surrogate alone is never valid.
//
// data must be valid JSON, or a part of valid JSON that starts and ends
// outside a string. Then a backslash outside a string cannot occur, every
// string ends with a quote, and every \u has four hex digits after it. The
// scan follows the strings, so an escaped backslash ("\\ud800", the text
// \ud800) is not taken for an escape.
func findLoneSurrogate(data []byte) int {
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			inString = c == '"'
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			r, ok := unicodeEscape(data, i)
			if !ok {
				i++ // Skip the escaped byte, for example the second \ of \\.
				continue
			}
			if !utf16.IsSurrogate(r) {
				i += 5 // Skip uXXXX.
				continue
			}
			low, ok := unicodeEscape(data, i+6)
			if !ok || utf16.DecodeRune(r, low) == utf8.RuneError {
				return i
			}
			i += 11 // Skip uXXXX\uXXXX.
		}
	}
	return -1
}

// unicodeEscape returns the code unit of the \uXXXX escape that starts at
// data[i], or false if no such escape starts there.
func unicodeEscape(data []byte, i int) (rune, bool) {
	if i+6 > len(data) || data[i] != '\\' || data[i+1] != 'u' {
		return 0, false
	}
	var r rune
	for _, c := range data[i+2 : i+6] {
		var v byte
		switch {
		case '0' <= c && c <= '9':
			v = c - '0'
		case 'a' <= c && c <= 'f':
			v = c - 'a' + 10
		case 'A' <= c && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(v)
	}
	return r, true
}
