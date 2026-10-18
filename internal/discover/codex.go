package discover

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// maxTOMLDepth is the deepest nesting of [ ] and { } that readCodex accepts.
// Real Codex configs nest 3 to 4 levels. The TOML parser has no limit of its
// own, and deep input can use gigabytes of memory or crash the whole process
// with a stack overflow that no recover can stop.
const maxTOMLDepth = 16

// maxTOMLKeyParts is the most dot-separated parts that one full key path may
// have. The path counts every part from the table header and from each open
// inline table, so it is the sum for the whole path. For example, in
//
//	[mcp_servers.docs]
//	env = { API_KEY = "x" }
//
// the path of API_KEY is mcp_servers.docs.env.API_KEY: 4 parts. Real Codex
// configs have paths of 2 to 4 parts. The parser cost grows faster than linear
// in the length of the path, and a long path can be built from many small
// pieces (one dotted key in each nested inline table), so the limit is for the
// total and not for each piece.
const maxTOMLKeyParts = 16

// maxTOMLSize is the largest Codex config file that readCodex reads: 256 KiB.
// Real Codex configs are a few KiB, and the TOML parser is slower than the
// JSON one, so this cap is lower than maxConfigSize.
const maxTOMLSize = 256 << 10

// codexServersKey is the top-level key that holds the servers.
const codexServersKey = "mcp_servers"

// codexKnownKeys lists the server keys that Codex knows. readCodex reads the
// first six and ignores the others (see ReadCodex). It uses the full list to
// find keys that differ from a known key only by letter case. It is an array,
// not a slice, so it is a value that no code can change.
var codexKnownKeys = [...]string{
	"command", "args", "env", "url", "http_headers", "cwd",
	"bearer_token_env_var", "env_http_headers", "env_vars",
	"enabled", "startup_timeout_sec", "tool_timeout_sec",
}

// codexEntry is the part of one [mcp_servers.<name>] table that readCodex
// uses. decodeCodexEntry fills it from the exact keys command, args, env, url,
// http_headers and cwd.
//
// Env and HTTPHeaders are SecretMap values, and URL is a URL. The TOML
// decoder calls their UnmarshalText methods, so the values are never held
// in a plain string map.
type codexEntry struct {
	Command     string
	Args        []string
	Env         SecretMap
	URL         URL
	HTTPHeaders SecretMap
	Cwd         string
}

// ReadCodex reads one Codex CLI config file (~/.codex/config.toml). The file
// may be at most 256 KiB; a bigger file gives a FileError.
//
// It returns the servers in the [mcp_servers.<name>] tables, sorted by name.
// Every server has ScopeGlobal, because Codex has one user-wide config. Other
// sections of the file (model, profiles, model_providers and so on) are
// ignored.
//
// A server with a command is a stdio server (command, args, env, and cwd as
// Server.Dir). A server without a command but with a url is an HTTP server
// (url, http_headers). Codex supports only streamable HTTP, so a remote server
// is never SSE. A server with neither gives a FileError, and so does an entry
// whose command, url or cwd is not a string, whose args is not an array of
// strings, or whose env or http_headers is not a table of strings.
//
// Keys are matched exactly, as Codex does: "Command" is not "command". A
// server key that differs from a known key only by letter case (for example
// Command or ENV) gives a FileError with the reason "ambiguous key" for that
// server, and the server is not returned. A top-level key that differs from
// mcp_servers only by case gives the same reason for the whole file, and no
// servers. A server with the empty name ([mcp_servers.""]) gives a FileError
// with the reason "empty server name".
//
// These keys are NOT mapped, on purpose: bearer_token_env_var,
// env_http_headers and env_vars hold the NAMES of environment variables, not
// values. mcpmoat does not read the environment of the user, so it cannot
// build the real header or env value from them. This is a known limit: a
// remote server that uses only bearer_token_env_var is scanned without its
// token. The keys enabled, startup_timeout_sec and tool_timeout_sec are
// ignored because the scanner does not need them.
//
// A missing file gives an empty Result. An empty file is valid TOML and gives
// no servers. A file that is not valid TOML gives one FileError with the line
// and column, and no servers. So does a file that nests deeper than 16 levels
// of [ ] and { }, has a key path with more than 16 dot-separated parts in all
// (the table header, the keys of the open inline tables and the key itself;
// both give the reason "nesting is too deep"), or holds more than 10,000
// servers. A bad server entry gives one FileError that names the server; the
// other servers are still returned. Errors for the whole file come first, then
// the errors for servers, sorted by server name. No error holds text from the
// file (see FileError).
func ReadCodex(ctx context.Context, path string) Result {
	servers, errs := readCodex(ctx, path)
	return Result{Servers: servers, Errors: errs}
}

// readCodex does the work of ReadCodex. See ReadCodex for the rules.
func readCodex(ctx context.Context, path string) ([]Server, []*FileError) {
	data, found, fe := readConfigFile(ctx, path, maxTOMLSize)
	if fe != nil {
		return nil, []*FileError{fe}
	}
	if !found {
		return nil, nil
	}
	// Check the shape before the parser sees the data (see maxTOMLDepth and
	// maxTOMLKeyParts).
	if !tomlShapeOK(data, maxTOMLDepth, maxTOMLKeyParts) {
		return nil, []*FileError{{Path: path, Reason: reasonTooDeep}}
	}

	// The file is decoded into maps and not into a struct. The TOML decoder
	// matches struct fields without regard to letter case: a struct field for
	// "command" also takes a key "Command". Codex reads keys exactly, so a
	// file with both keys would show mcpmoat one command and run another.
	//
	// toml.Primitive keeps the raw value of a key and delays its decoding.
	// Each server is decoded later, on its own, so one bad server does not
	// make the whole file fail and the other servers are still returned.
	var top map[string]toml.Primitive
	md, err := toml.Decode(string(data), &top)
	if err != nil {
		return nil, []*FileError{codexFileError(path, data, err)}
	}
	tables, fe := codexServerTables(&md, path, top)
	if fe != nil {
		return nil, []*FileError{fe}
	}

	var servers []Server
	var errs []*FileError
	// Sorted names make the output the same on every run (map order is random).
	for _, name := range slices.Sorted(maps.Keys(tables)) {
		if err := ctx.Err(); err != nil {
			errs = append(errs, canceledError(path, err))
			break
		}
		s, reason := readCodexServer(&md, path, name, tables[name])
		if reason != "" {
			errs = append(errs, &FileError{Path: path, Server: name, Reason: reason})
			continue
		}
		servers = append(servers, s)
	}
	// The same order as the JSON readers: errors for the whole file (for
	// example canceled) first, then by server name.
	sortErrors(errs)
	return servers, errs
}

// codexServerTables returns the raw [mcp_servers.<name>] tables of the file,
// by server name. It returns a FileError for the whole file if a top-level key
// differs from mcp_servers only by letter case, if mcp_servers is not a table,
// or if it holds more than maxServersPerFile servers. A file without
// mcp_servers gives no tables and no error.
func codexServerTables(md *toml.MetaData, path string, top map[string]toml.Primitive) (map[string]toml.Primitive, *FileError) {
	for key := range top {
		if codexCaseVariant(key, codexServersKey) {
			return nil, &FileError{Path: path, Reason: reasonAmbiguousKey}
		}
	}
	raw, ok := top[codexServersKey]
	if !ok {
		return nil, nil
	}
	// PrimitiveDecode does not catch a mcp_servers that is a number, a string
	// or an array: it leaves the map empty without an error, and the file
	// would be ignored without a word. So check the type first. The error
	// holds no value from the file.
	if !codexIsTable(md, codexServersKey) {
		return nil, &FileError{Path: path, Reason: reasonBadShape}
	}
	var tables map[string]toml.Primitive
	if err := md.PrimitiveDecode(raw, &tables); err != nil {
		return nil, &FileError{Path: path, Reason: reasonBadShape}
	}
	if len(tables) > maxServersPerFile {
		return nil, &FileError{Path: path, Reason: reasonTooManyServers}
	}
	return tables, nil
}

// readCodexServer builds the Server called name from its raw table. It
// returns a reason (and a zero Server) if the entry is not valid.
func readCodexServer(md *toml.MetaData, path, name string, raw toml.Primitive) (Server, string) {
	if name == "" {
		return Server{}, reasonEmptyName
	}
	e, reason := decodeCodexEntry(md, name, raw)
	if reason != "" {
		return Server{}, reason
	}
	return newCodexServer(path, name, e)
}

// decodeCodexEntry decodes the raw table of the server called name. It reads
// only the exact keys command, args, env, url, http_headers and cwd, and
// checks the TOML type of each one. It returns reasonAmbiguousKey for a key
// that differs from a known key only by letter case, and reasonBadEntry for
// a value of the wrong type.
func decodeCodexEntry(md *toml.MetaData, name string, raw toml.Primitive) (codexEntry, string) {
	// A server that is not a table (for example x = 5) decodes into an empty
	// map without an error, so check its type first.
	if !codexIsTable(md, codexServersKey, name) {
		return codexEntry{}, reasonBadEntry
	}
	var fields map[string]toml.Primitive
	if err := md.PrimitiveDecode(raw, &fields); err != nil {
		// Do not use err.Error(): the TOML library can quote the input.
		return codexEntry{}, reasonBadEntry
	}
	for key := range fields {
		if codexCaseVariant(key, codexKnownKeys[:]...) {
			return codexEntry{}, reasonAmbiguousKey
		}
	}

	var e codexEntry
	// Each key that readCodex reads, the TOML type it must have, and a
	// pointer to the field that takes its value. PrimitiveDecode writes
	// through the pointer.
	reads := []struct {
		key  string
		typ  string
		dest any
	}{
		{key: "command", typ: "String", dest: &e.Command},
		{key: "args", typ: "Array", dest: &e.Args},
		{key: "env", typ: "Hash", dest: &e.Env},
		{key: "url", typ: "String", dest: &e.URL},
		{key: "http_headers", typ: "Hash", dest: &e.HTTPHeaders},
		{key: "cwd", typ: "String", dest: &e.Cwd},
	}
	for _, r := range reads {
		value, ok := fields[r.key]
		if !ok {
			continue
		}
		if !codexHasType(md, r.typ, codexServersKey, name, r.key) || md.PrimitiveDecode(value, r.dest) != nil {
			return codexEntry{}, reasonBadEntry
		}
	}
	if !codexStringsOnly(md, name, e) {
		return codexEntry{}, reasonBadEntry
	}
	return e, ""
}

// newCodexServer builds a Server from a decoded entry. It returns a reason (and
// a zero Server) if the entry has neither a command nor a url. Fields that do
// not belong to the chosen transport are dropped.
func newCodexServer(path, name string, e codexEntry) (Server, string) {
	s := Server{
		Name:   name,
		Client: ClientCodex,
		Scope:  ScopeGlobal,
		Source: path,
	}
	switch {
	case e.Command != "":
		s.Transport = TransportStdio
		s.Command = e.Command
		s.Args = NewArgs(e.Args)
		s.Dir = e.Cwd
		s.Env = e.Env
	case e.URL.Reveal() != "":
		s.Transport = TransportHTTP
		s.URL = e.URL
		s.Headers = e.HTTPHeaders
	default:
		return Server{}, reasonNoCommandOrURL
	}
	return s, ""
}

// codexStringsOnly reports whether every env and http_headers value of the
// server called name is a TOML string.
//
// The TOML decoder calls UnmarshalText for Secret even when the TOML value is
// a number or a boolean (it passes the text "5"). The JSON readers reject such
// a value, so this check keeps the readers the same. md.Type gives the TOML
// type of a key, for example "String" or "Integer".
func codexStringsOnly(md *toml.MetaData, name string, e codexEntry) bool {
	tables := []struct {
		key    string
		values SecretMap
	}{
		{key: "env", values: e.Env},
		{key: "http_headers", values: e.HTTPHeaders},
	}
	for _, t := range tables {
		for k := range t.values {
			if md.Type(codexServersKey, name, t.key, k) != "String" {
				return false
			}
		}
	}
	return true
}

// codexHasType reports whether the key at the path has the TOML type want, as
// md.Type names it ("String", "Array", "Hash" and so on). For "Hash" it calls
// codexIsTable, because a table can also have the type "".
func codexHasType(md *toml.MetaData, want string, path ...string) bool {
	if want == "Hash" {
		return codexIsTable(md, path...)
	}
	return md.Type(path...) == want
}

// codexIsTable reports whether the key at the path, which must be in the file,
// is a TOML table. md.Type gives "Hash" for a table. It gives "" for a table
// that the file makes only through a header or a dotted key below it, such as
// mcp_servers in [mcp_servers.name]. Any other type is not a table: for
// example "Integer", "Array" or "ArrayHash" (an array of tables).
func codexIsTable(md *toml.MetaData, path ...string) bool {
	t := md.Type(path...)
	return t == "" || t == "Hash"
}

// codexCaseVariant reports whether key differs from one of names only by
// letter case, for example "Command" for "command". A key that is equal to a
// name is not a variant. strings.EqualFold compares two strings without
// regard to letter case (it also folds Unicode letters).
func codexCaseVariant(key string, names ...string) bool {
	for _, n := range names {
		if key != n && strings.EqualFold(key, n) {
			return true
		}
	}
	return false
}

// tomlLevel is one open [ or { in a value, as seen by tomlScanner.
type tomlLevel struct {
	// prefix is the number of key parts of the path to this bracket: the parts
	// of the table header, plus the parts of each key that opened an inline
	// table above it, plus the key that holds this value.
	prefix int
	// table is true for { and false for [.
	table bool
}

// tomlShapeOK reports whether data stays inside two limits that protect the
// TOML parser: the nesting of [ ] and { } never goes deeper than maxDepth, and
// no full key path has more than maxParts dot-separated parts. Both limits
// make the parser use too much time or memory when they are ignored.
// readCodex gives reasonTooDeep for both.
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
func tomlShapeOK(data []byte, maxDepth, maxParts int) bool {
	s := tomlScanner{maxDepth: maxDepth, maxParts: maxParts}
	for i := 0; i < len(data); {
		switch c := data[i]; {
		case c == '#':
			// Comment: skip to the end of the line. i stops on the '\n', so the
			// next turn of the loop sees the end of the line.
			j := bytes.IndexByte(data[i:], '\n')
			if j < 0 {
				return true
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
			if !s.onByte(c) {
				return false
			}
		}
	}
	return true
}

// tomlScanner holds the state of tomlShapeOK between two bytes. Its zero
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
// false if the byte breaks a limit. Bytes that have no meaning for the shape
// (letters, digits, spaces) change nothing.
func (s *tomlScanner) onByte(c byte) bool {
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
	return true
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
// value (for example the float 1.5) it means nothing.
func (s *tomlScanner) onDot() bool {
	if s.inValue {
		return true
	}
	s.dots++
	total := s.dots + 1 // a table header has no base
	if s.headerBrackets == 0 {
		total += s.base()
	}
	return total <= s.maxParts
}

// onEquals handles a '='. It ends a key, and the value starts.
func (s *tomlScanner) onEquals() bool {
	if s.inValue || s.headerBrackets > 0 {
		return true
	}
	// The key ends here. Its parts become the base of the value, which may be
	// an inline table. A key without a dot is checked here, because onDot does
	// not see it.
	s.valueParts = s.base() + s.dots + 1
	if s.valueParts > s.maxParts {
		return false
	}
	s.dots = 0
	s.inValue = true
	return true
}

// onOpen handles a '[' or a '{'. A '[' where a key can start opens a table
// header; any other bracket opens an array or an inline table in a value.
func (s *tomlScanner) onOpen(c byte) bool {
	switch {
	case c == '[' && s.headerBrackets > 0:
		// The second [ of [[array.of.tables]].
		s.headerBrackets++
		return s.headerBrackets <= s.maxDepth
	case c == '[' && !s.inValue && len(s.stack) == 0:
		// A [ where a key can start, outside any value: a table header.
		s.headerBrackets = 1
		s.dots = 0
		return true
	}
	prefix := s.base()
	if s.inValue {
		prefix = s.valueParts
	}
	s.stack = append(s.stack, tomlLevel{prefix: prefix, table: c == '{'})
	if len(s.stack) > s.maxDepth {
		return false
	}
	s.dots = 0
	s.inValue = c == '['
	return true
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

// codexFileError turns a toml.Decode error into a FileError.
//
// toml.ParseError.Error, Message, Usage and ErrorWithPosition can quote the
// bad input, and the input can hold a secret. So only the position is used
// and the reason is fixed text.
func codexFileError(path string, data []byte, err error) *FileError {
	// toml.ParseError is returned as a value (not a pointer), so errors.As
	// needs a variable of the value type.
	var pe toml.ParseError
	if !errors.As(err, &pe) {
		// The syntax is fine, but the decoder could not store a value. With a
		// map of toml.Primitive as the target this should not happen, so it
		// is reported as a bad shape.
		return &FileError{Path: path, Reason: reasonBadShape}
	}
	// Position.Start is a byte offset. lineCol turns it into a line and column.
	line, col := lineCol(data, int64(pe.Position.Start))
	return &FileError{Path: path, Line: line, Col: col, Reason: reasonInvalidTOML}
}
