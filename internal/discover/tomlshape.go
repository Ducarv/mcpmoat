package discover

import "bytes"

// tomlLevel is one open [ or { in a value, as seen by tomlScanner.
type tomlLevel struct {
	// prefix is the number of key parts of the path to this bracket: the parts
	// of the table header, plus the parts of each key that opened an inline
	// table above it, plus the key that holds this value.
	prefix int
	// table is true for { and false for [.
	table bool
}

// checkTOMLShape reports whether data stays inside two limits that protect
// the TOML parser. Both limits make the parser use too much time or memory
// when they are ignored. It returns the reason for the first limit that data
// breaks, or "" if data stays inside both:
//
//   - reasonTooDeep: the nesting of [ ] and { } goes deeper than maxDepth.
//   - reasonKeyTooLong: a full key path has more than maxParts dot-separated
//     parts.
//
// It is a small scanner, not a parser. It skips the places where a bracket or
// a dot is plain text:
//
//   - a comment, from # to the end of the line
//   - a basic string "..." (a backslash escapes the next byte)
//   - a literal string '...' (no escapes)
//   - a multi-line string, in triple double quotes or triple single quotes
//
// So a quoted key part such as "a.b" counts as one part.
//
// The key path is the sum of three things:
//
//  1. the parts of the table header, for example 2 for [mcp_servers.docs]. The
//     header is the base for every key below it, until the next header.
//  2. the parts of each key that opened a still-open inline table. In
//     a.b = { c.d = { e = 1 } } the path of e has 2 + 2 + 1 = 5 parts. The
//     scanner keeps these counts in a stack (a slice): it pushes at { and pops
//     at }.
//  3. the parts of the current key.
//
// If each piece had its own limit, a short line could still build a long path
// by nesting many inline tables that each hold a long dotted key.
//
// An array [ in a value does not add key parts, but it counts as depth. The
// scanner counts dots only in keys and headers, never in values (a float such
// as 1.5 has a dot). A value that is not valid TOML may get a wrong answer
// here, but the parser rejects it later anyway.
func checkTOMLShape(data []byte, maxDepth, maxParts int) reason {
	s := tomlScanner{maxDepth: maxDepth, maxParts: maxParts}
	for i := 0; i < len(data); {
		switch c := data[i]; {
		case c == '#':
			// Comment: skip to the end of the line. i stops on the '\n', so the
			// next turn of the loop sees the end of the line.
			j := bytes.IndexByte(data[i:], '\n')
			if j < 0 {
				return ""
			}
			i += j
		case bytes.HasPrefix(data[i:], []byte(`"""`)):
			i = skipTOMLString(data, i+3, '"', true)
		case bytes.HasPrefix(data[i:], []byte("'''")):
			i = skipTOMLString(data, i+3, '\'', true)
		case c == '"' || c == '\'':
			i = skipTOMLString(data, i+1, c, false)
		default:
			// Every other byte is one token.
			i++
			if r := s.onByte(c); r != "" {
				return r
			}
		}
	}
	return ""
}

// tomlScanner holds the state of checkTOMLShape between two bytes. Its zero
// value, plus the two limits, is the state at the start of a file. The methods
// use a pointer receiver (*tomlScanner) because they change the state.
type tomlScanner struct {
	maxDepth int // the limit for the nesting of [ ] and { }
	maxParts int // the limit for the parts of a full key path

	stack          []tomlLevel // the open [ and { in values
	sectionParts   int         // parts of the last table header
	valueParts     int         // parts of the path to the value that is being read
	dots           int         // dots in the current key; parts = dots + 1
	headerBrackets int         // the [ that opened a table header; 0 if not in one
	inValue        bool        // true after '=', until the end of the value
}

// onByte handles one byte that is not in a comment or a string. It returns
// the reason if the byte breaks a limit, or "". Bytes that have no meaning
// for the shape (letters, digits, spaces) change nothing.
func (s *tomlScanner) onByte(c byte) reason {
	switch c {
	case '.':
		return s.onDot()
	case '=':
		return s.onEquals()
	case '[', '{':
		return s.onOpen(c)
	case ']', '}':
		s.onClose(c)
	case ',':
		s.afterSeparator()
	case '\n':
		s.headerBrackets = 0
		s.afterSeparator()
	}
	return ""
}

// base returns the number of key parts above the current key: the prefix of
// the innermost open bracket, or the parts of the table header.
func (s *tomlScanner) base() int {
	if len(s.stack) > 0 {
		return s.stack[len(s.stack)-1].prefix
	}
	return s.sectionParts
}

// afterSeparator resets the key state after a comma or a new line.
func (s *tomlScanner) afterSeparator() {
	s.dots = 0
	if len(s.stack) == 0 {
		s.inValue = false
		return
	}
	top := s.stack[len(s.stack)-1]
	s.inValue = !top.table // in an array the next item is a value
	s.valueParts = top.prefix
}

// onDot handles a '.'. In a key or a header it starts a new key part; in a
// value (for example the float 1.5) it means nothing. It returns
// reasonKeyTooLong if the key path gets too long.
func (s *tomlScanner) onDot() reason {
	if s.inValue {
		return ""
	}
	s.dots++
	total := s.dots + 1 // a table header has no base
	if s.headerBrackets == 0 {
		total += s.base()
	}
	if total > s.maxParts {
		return reasonKeyTooLong
	}
	return ""
}

// onEquals handles a '='. It ends a key, and the value starts. It returns
// reasonKeyTooLong if the key path is too long.
func (s *tomlScanner) onEquals() reason {
	if s.inValue || s.headerBrackets > 0 {
		return ""
	}
	// The key ends here. Its parts become the base of the value, which may be
	// an inline table. A key without a dot is checked here, because onDot does
	// not see it.
	s.valueParts = s.base() + s.dots + 1
	if s.valueParts > s.maxParts {
		return reasonKeyTooLong
	}
	s.dots = 0
	s.inValue = true
	return ""
}

// onOpen handles a '[' or a '{'. A '[' where a key can start opens a table
// header; any other bracket opens an array or an inline table in a value. It
// returns reasonTooDeep if the nesting gets too deep.
func (s *tomlScanner) onOpen(c byte) reason {
	switch {
	case c == '[' && s.headerBrackets > 0:
		// The second [ of [[array.of.tables]].
		s.headerBrackets++
		if s.headerBrackets > s.maxDepth {
			return reasonTooDeep
		}
		return ""
	case c == '[' && !s.inValue && len(s.stack) == 0:
		// A [ where a key can start, outside any value: a table header.
		s.headerBrackets = 1
		s.dots = 0
		return ""
	}
	prefix := s.base()
	if s.inValue {
		prefix = s.valueParts
	}
	s.stack = append(s.stack, tomlLevel{prefix: prefix, table: c == '{'})
	if len(s.stack) > s.maxDepth {
		return reasonTooDeep
	}
	s.dots = 0
	s.inValue = c == '['
	return ""
}

// onClose handles a ']' or a '}'. It ends a table header or closes the
// innermost open bracket of a value.
func (s *tomlScanner) onClose(c byte) {
	if c == ']' && s.headerBrackets > 0 {
		// The end of the header: its parts are the base for the keys below.
		s.sectionParts = s.dots + 1
		s.headerBrackets = 0
		s.dots = 0
		return
	}
	s.dots = 0
	if len(s.stack) > 0 {
		s.stack = s.stack[:len(s.stack)-1]
		s.inValue = true // a whole value is complete
	}
}

// skipTOMLString returns the index just after the string whose body starts at
// i (the opening quote is already behind i). quote is the quote byte, and multi
// is true for a multi-line string. In a basic string (double quotes) a
// backslash escapes the next byte; in a literal string (single quotes) it does
// not.
//
// A single-line string ends at its closing quote or at the end of the line (a
// string that is not closed is a syntax error that the parser reports). A
// multi-line string ends at a run of three or more quotes; in a longer run, the
// quotes before the last three belong to the string.
func skipTOMLString(data []byte, i int, quote byte, multi bool) int {
	escapes := quote == '"'
	for i < len(data) {
		c := data[i]
		switch {
		case escapes && c == '\\':
			i += 2 // skip the backslash and the byte it escapes
		case !multi && c == '\n':
			return i
		case c == quote && !multi:
			return i + 1
		case c == quote:
			run := 1
			for i+run < len(data) && data[i+run] == quote {
				run++
			}
			i += run
			if run >= 3 {
				return i
			}
		default:
			i++
		}
	}
	return len(data)
}
