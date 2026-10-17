package discover

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"

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

// codexEntry is the part of one [mcp_servers.<name>] table that readCodex
// uses. Keys that are not listed here are ignored by the TOML decoder.
//
// Env and HTTPHeaders are SecretMap values, and URL is a URL. The TOML
// decoder calls their UnmarshalText methods, so the values are never held
// in a plain string map.
type codexEntry struct {
	Command     string    `toml:"command"`
	Args        []string  `toml:"args"`
	Env         SecretMap `toml:"env"`
	URL         URL       `toml:"url"`
	HTTPHeaders SecretMap `toml:"http_headers"`
}

// ReadCodex reads one Codex CLI config file (~/.codex/config.toml). The file
// may be at most 256 KiB; a bigger file gives a FileError.
//
// It returns the servers in the [mcp_servers.<name>] tables, sorted by name.
// Every server has ScopeGlobal, because Codex has one user-wide config. Other
// sections of the file (model, profiles, model_providers and so on) are
// ignored.
//
// A server with a command is a stdio server (command, args, env). A server
// without a command but with a url is an HTTP server (url, http_headers).
// Codex supports only streamable HTTP, so a remote server is never SSE. A
// server with neither gives a FileError, and so does an entry whose env or
// http_headers is not a table of strings.
//
// These keys are NOT mapped, on purpose: bearer_token_env_var,
// env_http_headers and env_vars hold the NAMES of environment variables, not
// values. mcpmoat does not read the environment of the user, so it cannot
// build the real header or env value from them. This is a known limit: a
// remote server that uses only bearer_token_env_var is scanned without its
// token. The keys cwd, enabled, startup_timeout_sec and tool_timeout_sec are
// ignored because the scanner does not need them.
//
// A missing file gives an empty Result. An empty file is valid TOML and gives
// no servers. A file that is not valid TOML gives one FileError with the line
// and column, and no servers. So does a file that nests deeper than 16 levels
// of [ ] and { }, has a key path with more than 16 dot-separated parts in all
// (the table header, the keys of the open inline tables and the key itself;
// both give the reason "nesting is too deep"), or holds more than 10,000
// servers. A bad server entry gives one FileError that names the server; the
// other servers are still returned. No error holds text from the file (see FileError).
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

	// toml.Primitive keeps the raw value of a key and delays its decoding.
	// We decode each server later, on its own, so one bad server does not
	// make the whole file fail and the other servers are still returned.
	var top struct {
		MCPServers map[string]toml.Primitive `toml:"mcp_servers"`
	}
	md, err := toml.Decode(string(data), &top)
	if err != nil {
		return nil, []*FileError{codexFileError(path, data, err)}
	}
	// If mcp_servers is a number or a string, toml.Decode returns an error and
	// codexFileError maps it to reasonBadShape. An array or an array of tables
	// gets past Decode with no error and leaves the map empty, so the file would
	// be ignored without a word. md.Type gives "Hash" for a table. It gives ""
	// for a table that the file makes only with a header such as
	// [mcp_servers.name], and for a key that is not in the file, so "" is valid
	// too. Any other type is a bad shape. The error holds no value from the
	// file.
	if t := md.Type("mcp_servers"); t != "" && t != "Hash" {
		return nil, []*FileError{{Path: path, Reason: reasonBadShape}}
	}
	if len(top.MCPServers) > maxServersPerFile {
		return nil, []*FileError{{Path: path, Reason: reasonTooManyServers}}
	}

	var servers []Server
	var errs []*FileError
	// Sorted names make the output the same on every run (map order is random).
	for _, name := range slices.Sorted(maps.Keys(top.MCPServers)) {
		if err := ctx.Err(); err != nil {
			errs = append(errs, &FileError{Path: path, Reason: reasonCanceled, Err: err})
			break
		}

		var e codexEntry
		if err := md.PrimitiveDecode(top.MCPServers[name], &e); err != nil {
			// Do not use err.Error(): the TOML library can quote the input.
			errs = append(errs, &FileError{Path: path, Server: name, Reason: reasonBadEntry})
			continue
		}
		if !codexStringsOnly(md, name, e) {
			errs = append(errs, &FileError{Path: path, Server: name, Reason: reasonBadEntry})
			continue
		}

		s, reason := newCodexServer(path, name, e)
		if reason != "" {
			errs = append(errs, &FileError{Path: path, Server: name, Reason: reason})
			continue
		}
		servers = append(servers, s)
	}
	return servers, errs
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
		s.Args = e.Args
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

// codexStringsOnly reports whether the env and http_headers keys of the server
// called name are tables, and whether url and every env and http_headers value
// are TOML strings.
//
// The TOML decoder calls UnmarshalText for Secret and URL even when the TOML
// value is a number or a boolean (it passes the text "5"). The JSON readers
// reject such a value, so this check keeps the readers the same. The decoder
// also drops an env or http_headers key that is a number, a string or an array
// without an error, so the check looks at the type of the key itself.
// md.Type gives the TOML type of a key, for example "String" or "Integer".
func codexStringsOnly(md toml.MetaData, name string, e codexEntry) bool {
	if e.URL.Reveal() != "" && md.Type("mcp_servers", name, "url") != "String" {
		return false
	}
	for _, key := range []string{"env", "http_headers"} {
		// md.Type gives "" for a key that is not in the file, and "Hash" for a
		// table (inline or with a header). Anything else is not a table.
		if t := md.Type("mcp_servers", name, key); t != "" && t != "Hash" {
			return false
		}
	}
	for k := range e.Env {
		if md.Type("mcp_servers", name, "env", k) != "String" {
			return false
		}
	}
	for k := range e.HTTPHeaders {
		if md.Type("mcp_servers", name, "http_headers", k) != "String" {
			return false
		}
	}
	return true
}

// tomlLevel is one open [ or { in a value, as seen by tomlShapeOK.
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
	var stack []tomlLevel // the open [ and { in values
	sectionParts := 0     // parts of the last table header
	valueParts := 0       // parts of the path to the value that is being read
	dots := 0             // dots in the current key; parts = dots + 1
	headerBrackets := 0   // the [ that opened a table header; 0 if not in one
	inValue := false      // true after '=', until the end of the value

	// base is the number of key parts above the current key.
	base := func() int {
		if len(stack) > 0 {
			return stack[len(stack)-1].prefix
		}
		return sectionParts
	}
	// afterSeparator resets the key state after a comma or a new line.
	afterSeparator := func() {
		dots = 0
		if len(stack) == 0 {
			inValue = false
			return
		}
		top := stack[len(stack)-1]
		inValue = !top.table // in an array the next item is a value
		valueParts = top.prefix
	}

	for i := 0; i < len(data); {
		switch c := data[i]; {
		case c == '#':
			// Comment: skip to the end of the line.
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
		case c == '.':
			i++
			if inValue {
				continue
			}
			dots++
			total := dots + 1 // a table header has no base
			if headerBrackets == 0 {
				total += base()
			}
			if total > maxParts {
				return false
			}
		case c == '=':
			i++
			if inValue || headerBrackets > 0 {
				continue
			}
			// The key ends here. Its parts become the base of the value, which
			// may be an inline table. A key without a dot is checked here, because
			// the check at '.' does not see it.
			valueParts = base() + dots + 1
			if valueParts > maxParts {
				return false
			}
			dots = 0
			inValue = true
		case c == '[' && headerBrackets > 0:
			// The second [ of [[array.of.tables]].
			i++
			headerBrackets++
			if headerBrackets > maxDepth {
				return false
			}
		case c == '[' && !inValue && len(stack) == 0:
			// A [ where a key can start, outside any value: a table header.
			i++
			headerBrackets = 1
			dots = 0
		case c == '[' || c == '{':
			i++
			prefix := base()
			if inValue {
				prefix = valueParts
			}
			stack = append(stack, tomlLevel{prefix: prefix, table: c == '{'})
			if len(stack) > maxDepth {
				return false
			}
			dots = 0
			inValue = c == '['
		case c == ']' && headerBrackets > 0:
			// The end of the header: its parts are the base for the keys below.
			i++
			sectionParts = dots + 1
			headerBrackets = 0
			dots = 0
		case c == ']' || c == '}':
			i++
			dots = 0
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
				inValue = true // a whole value is complete
			}
		case c == ',':
			i++
			afterSeparator()
		case c == '\n':
			i++
			headerBrackets = 0
			afterSeparator()
		default:
			i++
		}
	}
	return true
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
		// For example mcp_servers is not a table. The shape is wrong, but the
		// syntax is fine.
		return &FileError{Path: path, Reason: reasonBadShape}
	}
	// Position.Start is a byte offset. lineCol turns it into a line and column.
	line, col := lineCol(data, int64(pe.Position.Start))
	return &FileError{Path: path, Line: line, Col: col, Reason: reasonInvalidTOML}
}
