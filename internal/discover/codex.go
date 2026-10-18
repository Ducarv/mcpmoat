package discover

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/BurntSushi/toml"
)

// maxTOMLDepth is the deepest nesting of [ ] and { } that parseCodex accepts.
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

// maxTOMLSize is the largest Codex config file that ReadCodex reads: 256 KiB.
// Real Codex configs are a few KiB, and the TOML parser is slower than the
// JSON one, so this cap is lower than maxConfigSize.
const maxTOMLSize = 256 << 10

// codexServersKey is the top-level key that holds the servers.
const codexServersKey = "mcp_servers"

// The server keys that Codex knows. parseCodex reads the first group (see
// codexReads) and ignores the second (see codexIgnoredKeys).
//
// These constants are kept apart from the JSON key constants on purpose,
// even where the text is the same: the two formats can change on their own.
const (
	codexKeyCommand     = "command"
	codexKeyArgs        = "args"
	codexKeyEnv         = "env"
	codexKeyURL         = "url"
	codexKeyHTTPHeaders = "http_headers"
	codexKeyCwd         = "cwd"

	// codexKeyAuthEnvVar is bearer_token_env_var. Its name has no "token":
	// gosec (G101) takes such a name with a string value for a hard-coded
	// credential, but the value is only a key name.
	codexKeyAuthEnvVar        = "bearer_token_env_var"
	codexKeyEnvHTTPHeaders    = "env_http_headers"
	codexKeyEnvVars           = "env_vars"
	codexKeyEnabled           = "enabled"
	codexKeyStartupTimeoutSec = "startup_timeout_sec"
	codexKeyToolTimeoutSec    = "tool_timeout_sec"
)

// codexIgnoredKeys lists the server keys that Codex knows and parseCodex
// does not map to a Server field. bearer_token_env_var, env_http_headers and
// env_vars hold the names of environment variables, and mcpmoat does not read
// the environment. The scanner does not need enabled, startup_timeout_sec and
// tool_timeout_sec. No code writes to it.
var codexIgnoredKeys = [...]string{
	codexKeyAuthEnvVar, codexKeyEnvHTTPHeaders, codexKeyEnvVars,
	codexKeyEnabled, codexKeyStartupTimeoutSec, codexKeyToolTimeoutSec,
}

// codexStdioKeys and codexRemoteKeys list the server keys that Codex allows
// only for one transport: stdio (an entry with command) or streamable HTTP
// (an entry with url). Codex refuses an entry that has keys from both lists
// (see codexMixesTransports). No code writes to them.
var (
	codexStdioKeys = [...]string{
		codexKeyCommand, codexKeyArgs, codexKeyEnv, codexKeyEnvVars, codexKeyCwd,
	}
	codexRemoteKeys = [...]string{
		codexKeyURL, codexKeyHTTPHeaders, codexKeyEnvHTTPHeaders, codexKeyAuthEnvVar,
	}
)

// codexKnownKeys lists every server key that Codex knows: the keys in
// codexReads and the keys in codexIgnoredKeys. parseCodex uses it to find keys
// that differ from a known key only by letter case. It is built once, when
// the package loads, so codexReads stays the one list of the keys that
// parseCodex reads. No code writes to it.
var codexKnownKeys = codexAllKeys()

// codexAllKeys returns the keys of codexReads, in order, then the keys in
// codexIgnoredKeys. It runs once, to build codexKnownKeys.
func codexAllKeys() []string {
	reads := codexReads(&codexEntry{})
	keys := make([]string, 0, len(reads)+len(codexIgnoredKeys))
	for _, r := range reads {
		keys = append(keys, r.key)
	}
	return append(keys, codexIgnoredKeys[:]...)
}

// The TOML type names that md.Type returns. A table made only through a
// header or a dotted key below it has the type "" (see codexIsTable), and
// "ArrayHash" is an array of tables ([[name]]).
const (
	tomlTypeString    = "String"
	tomlTypeArray     = "Array"
	tomlTypeHash      = "Hash"
	tomlTypeArrayHash = "ArrayHash"
)

// codexEntry is the part of one [mcp_servers.<name>] table that parseCodex
// uses. decodeCodexEntry fills it from the exact keys in codexReads.
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

// codexRead is one key that parseCodex reads: the TOML type that the value
// must have, and a pointer to the codexEntry field that takes the value.
// PrimitiveDecode writes through the pointer.
type codexRead struct {
	key  string
	typ  string
	dest any
}

// codexReads returns one codexRead for each server key that parseCodex reads,
// with pointers into e. It is the one list of these keys: codexKnownKeys is
// built from it.
func codexReads(e *codexEntry) []codexRead {
	return []codexRead{
		{key: codexKeyCommand, typ: tomlTypeString, dest: &e.Command},
		{key: codexKeyArgs, typ: tomlTypeArray, dest: &e.Args},
		{key: codexKeyEnv, typ: tomlTypeHash, dest: &e.Env},
		{key: codexKeyURL, typ: tomlTypeString, dest: &e.URL},
		{key: codexKeyHTTPHeaders, typ: tomlTypeHash, dest: &e.HTTPHeaders},
		{key: codexKeyCwd, typ: tomlTypeString, dest: &e.Cwd},
	}
}

// ReadCodex reads one Codex CLI config file (~/.codex/config.toml). It
// returns the servers in the [mcp_servers.<name>] tables, sorted by name, all
// with ScopeGlobal, because Codex has one user-wide config. Other sections of
// the file (model, profiles and so on) are ignored.
//
// A server with a command key is a stdio server, and its cwd is Server.Dir.
// A server with a url key and no command key is an HTTP server: Codex
// supports only streamable HTTP, so it is never SSE. As in Codex, an entry
// that mixes the keys of the two transports (for example command with
// http_headers, or url with env) gives a FileError with the reason "invalid
// server entry", even when a value is empty.
//
// A file that is not valid TOML gives one FileError with the line and column,
// which do not count a byte order mark at the start of the file.
//
// See the package doc, Reading configs.
func ReadCodex(ctx context.Context, path string) Result {
	// root "" reads the user's own file without confinement.
	data, found, fe := readConfigFile(ctx, path, maxTOMLSize, "")
	switch {
	case fe != nil:
		return Result{Errors: []*FileError{fe}}
	case !found:
		return Result{}
	}
	servers, errs, _ := parseCodex(ctx, path, data)
	return Result{Servers: servers, Errors: errs}
}

// parseCodex does the work of ReadCodex and readUntrustedCodex on data, the
// content of the Codex file at path. See ReadCodex for the rules.
//
// noServersKey is true only for valid TOML whose top level has no
// mcp_servers key, for example an empty file, a file with only comments or a
// pyproject.toml. Such a file gives no servers and no errors.
// readUntrustedCodex uses it to refuse a .toml file that is not a Codex
// config (see ReadConfig).
func parseCodex(ctx context.Context, path string, data []byte) (servers []Server, errs []*FileError, noServersKey bool) {
	// Check the shape before the parser sees the data (see maxTOMLDepth and
	// maxTOMLKeyParts).
	if r := checkTOMLShape(data, maxTOMLDepth, maxTOMLKeyParts); r != "" {
		return nil, []*FileError{newFileError(path, r)}, false
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
		return nil, []*FileError{codexFileError(path, data, err)}, false
	}
	tables, fe := codexServerTables(&md, path, top)
	if fe != nil {
		return nil, []*FileError{fe}, false
	}
	if _, ok := top[codexServersKey]; !ok {
		return nil, nil, true
	}

	// Sorted names make the output the same on every run (map order is random).
	for _, name := range slices.Sorted(maps.Keys(tables)) {
		if err := ctx.Err(); err != nil {
			errs = append(errs, canceledError(path, err))
			break
		}
		s, r := readCodexServer(&md, path, name, tables[name])
		if r != "" {
			errs = append(errs, newFileError(path, r).forServer(name))
			continue
		}
		servers = append(servers, s)
	}
	// The same order as the JSON readers: errors for the whole file (for
	// example canceled) first, then by server name.
	sortErrors(errs)
	return servers, errs, false
}

// codexServerTables returns the raw [mcp_servers.<name>] tables of the file,
// by server name. It returns a FileError for the whole file if a top-level key
// differs from mcp_servers only by letter case, if mcp_servers is not a table,
// or if it holds more than maxServersPerFile servers. A file without
// mcp_servers gives no tables and no error.
func codexServerTables(md *toml.MetaData, path string, top map[string]toml.Primitive) (map[string]toml.Primitive, *FileError) {
	if hasCaseVariant(top, codexServersKey) {
		return nil, newFileError(path, reasonAmbiguousKey)
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
		return nil, newFileError(path, reasonBadShape)
	}
	var tables map[string]toml.Primitive
	if err := md.PrimitiveDecode(raw, &tables); err != nil {
		return nil, newFileError(path, reasonBadShape)
	}
	if len(tables) > maxServersPerFile {
		return nil, newFileError(path, reasonTooManyServers)
	}
	return tables, nil
}

// readCodexServer builds the Server called name from its raw table. It
// returns a reason (and a zero Server) if the entry is not valid.
func readCodexServer(md *toml.MetaData, path, name string, raw toml.Primitive) (Server, reason) {
	if name == "" {
		return Server{}, reasonEmptyName
	}
	e, r := decodeCodexEntry(md, name, raw)
	if r != "" {
		return Server{}, r
	}
	return newCodexServer(path, name, e)
}

// decodeCodexEntry decodes the raw table of the server called name. It reads
// only the exact keys in codexReads, and checks the TOML type of each one.
// It returns reasonAmbiguousKey for a key that differs from a known key only
// by letter case, and reasonBadEntry for a value of the wrong type or for an
// entry that mixes the keys of the two transports (see codexMixesTransports).
func decodeCodexEntry(md *toml.MetaData, name string, raw toml.Primitive) (codexEntry, reason) {
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
	if hasCaseVariant(fields, codexKnownKeys...) {
		return codexEntry{}, reasonAmbiguousKey
	}
	if codexMixesTransports(fields) {
		return codexEntry{}, reasonBadEntry
	}

	var e codexEntry
	for _, r := range codexReads(&e) {
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

// codexMixesTransports reports whether the fields of one server mix the keys
// of the two transports. Codex refuses such an entry (codex-rs, TryFrom
// RawMcpServerConfig for McpServerConfig). An entry with command is a stdio
// entry and must have no key from codexRemoteKeys. An entry with url and no
// command is a remote entry and must have no key from codexStdioKeys. As in
// Codex, only the presence of a key counts, not its value: command = "" makes
// a stdio entry too.
func codexMixesTransports(fields map[string]toml.Primitive) bool {
	_, hasCommand := fields[codexKeyCommand]
	_, hasURL := fields[codexKeyURL]
	var other []string
	switch {
	case hasCommand:
		other = codexRemoteKeys[:]
	case hasURL:
		other = codexStdioKeys[:]
	default:
		// Neither key: newCodexServer gives reasonNoCommandOrURL.
		return false
	}
	for _, k := range other {
		if _, ok := fields[k]; ok {
			return true
		}
	}
	return false
}

// newCodexServer builds a Server from a decoded entry. It returns a reason (and
// a zero Server) if the entry has neither a command nor a url.
// decodeCodexEntry has already refused an entry that mixes the two
// transports, so each case keeps every field it reads.
func newCodexServer(path, name string, e codexEntry) (Server, reason) {
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
		{key: codexKeyEnv, values: e.Env},
		{key: codexKeyHTTPHeaders, values: e.HTTPHeaders},
	}
	for _, t := range tables {
		for k := range t.values {
			if md.Type(codexServersKey, name, t.key, k) != tomlTypeString {
				return false
			}
		}
	}
	return true
}

// codexHasType reports whether the key at the path has the TOML type want, as
// md.Type names it (tomlTypeString, tomlTypeArray and so on). For
// tomlTypeHash it calls codexIsTable, because a table can also have the type "".
func codexHasType(md *toml.MetaData, want string, path ...string) bool {
	if want == tomlTypeHash {
		return codexIsTable(md, path...)
	}
	return md.Type(path...) == want
}

// codexIsTable reports whether the key at the path, which must be in the file,
// is a TOML table. md.Type gives tomlTypeHash for a table. It gives "" for a
// table that the file makes only through a header or a dotted key below it,
// such as mcp_servers in [mcp_servers.name]. Any other type is not a table:
// for example "Integer", tomlTypeArray or tomlTypeArrayHash (an array of
// tables).
func codexIsTable(md *toml.MetaData, path ...string) bool {
	t := md.Type(path...)
	return t == "" || t == tomlTypeHash
}

// codexFileError turns a toml.Decode error into a FileError.
//
// toml.ParseError.Error, Message, Usage and ErrorWithPosition can quote the
// bad input, and the input can hold a secret. So only the position is used
// and the reason is fixed text.
func codexFileError(path string, data []byte, err error) *FileError {
	// toml.ParseError is returned as a value (not a pointer), so the type
	// argument is the value type.
	pe, ok := errors.AsType[toml.ParseError](err)
	if !ok {
		// The syntax is fine, but the decoder could not store a value. With a
		// map of toml.Primitive as the target this should not happen, so it
		// is reported as a bad shape.
		return newFileError(path, reasonBadShape)
	}
	// Position.Start is a byte offset in the data after the byte order mark,
	// because the parser removes the mark before it reads (see tomlBOMLen).
	// So count the line and column in the same data. Then a file with a mark
	// gives the same line and column as the same file without it, which is
	// also what an editor shows.
	body := data[tomlBOMLen(data):]
	return newFileError(path, reasonInvalidTOML).atOffset(body, pe.Position.Start)
}

// tomlBOMLen returns the length of the byte order mark at the start of data
// that the TOML parser removes before it reads: 3 for the UTF-8 mark, 2 for a
// UTF-16 mark (in either byte order), or 0 if data has no mark. The checks
// are the same as in the parser.
func tomlBOMLen(data []byte) int {
	switch {
	case bytes.HasPrefix(data, []byte("\xff\xfe")), bytes.HasPrefix(data, []byte("\xfe\xff")):
		return 2
	case bytes.HasPrefix(data, []byte("\xef\xbb\xbf")):
		return 3
	}
	return 0
}
