package discover

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Exact keys of the Claude Code and Cursor JSON configs. The clients read the
// files with JSON.parse, which matches keys exactly, so mcpmoat must do the
// same. encoding/json matches struct fields without regard to letter case, so
// the reader never decodes into a struct with json tags: it decodes each
// object into a map and reads these keys only.
const (
	keyMCPServers = "mcpServers"
	keyProjects   = "projects"
	keyType       = "type"
	keyCommand    = "command"
	keyArgs       = "args"
	keyEnv        = "env"
	keyURL        = "url"
	keyHeaders    = "headers"
)

// entryKeys lists the keys that a server entry can have. It is an array, so no
// code can change it.
var entryKeys = [...]string{keyType, keyCommand, keyArgs, keyEnv, keyURL, keyHeaders}

// jsonEntry is one server entry in a Claude Code or Cursor JSON config. Both
// clients use the same shape. Fields that a JSON entry does not have stay at
// their zero value. decodeEntry fills it; it has no json tags on purpose.
type jsonEntry struct {
	Type    string
	Command string
	Args    []string
	Env     SecretMap
	URL     URL
	Headers SecretMap
}

// origin tells where one "mcpServers" object is in the file.
type origin struct {
	// scope and projectPath go to every Server of the object.
	scope       Scope
	projectPath string
	// project is the projects.<path> key for an object under "projects", and
	// "" for the top-level object. It goes to FileError.ProjectPath.
	project string
}

// jsonParser holds the state of the parse of one file. Only decodeServers and
// decodeProjects change count and full. The other methods only read path and
// client.
type jsonParser struct {
	path   string
	client Client

	// count is the number of entries seen so far: every server entry and every
	// project of the file.
	count int
	// full is set when the file went over the cap. After that, decodeServers
	// and decodeProjects decode nothing more, and parseJSONServers returns no
	// servers.
	full bool
}

// parseJSONServers reads the Claude Code or Cursor JSON config at path.
//
// The top-level "mcpServers" servers get scope and projectPath as given. If
// withProjects is true, the servers under "projects.<dir>.mcpServers" are also
// read; they always get ScopeProject and ProjectPath <dir>. Cursor files pass
// withProjects=false.
//
// A missing file and an empty (or whitespace-only) file give no servers and no
// error. A problem in one server entry gives a *FileError for that entry; the
// other entries are still returned. An error for an entry or a project under
// "projects" has FileError.ProjectPath set to the project key.
//
// Keys are matched exactly, as the clients do. A known key in a different
// letter case ("Command", "MCPSERVERS") is an "ambiguous key" error: for an
// entry, the entry gives no server; for a project, the project gives no
// servers; for the top level, that section gives no servers.
//
// A lone UTF-16 surrogate escape (for example "\ud800" without a low
// surrogate after it) in a server entry or in a project key makes the whole
// file an "invalid string" error. encoding/json turns every lone surrogate
// into U+FFFD, so two names that differ for the client would become one name
// here. A lone surrogate in another part of the file, for example in the chat
// history of ~/.claude.json, is not an error. See findServerSurrogate.
//
// Order: servers are sorted by (ProjectPath, Name). Errors come file-level
// first (Server is empty), then by Server name. Errors of the same name keep
// the order in which they were found: top-level first, then projects sorted by
// path.
//
// Size limits: a file read with ScopeProject (<WorkDir>/.mcp.json and
// <WorkDir>/.cursor/mcp.json) can be at most maxProjectConfigSize, because it
// comes from a cloned repository and is untrusted. Any other file can be at
// most maxConfigSize.
//
// A file with more than maxServersPerFile entries (server entries and projects
// together) gives one "too many servers" error and no servers. The entries and
// the projects after the cap are not decoded.
//
// Error messages never contain library error text. encoding/json errors can
// quote bytes of the config, and the config can hold secrets. So the code uses
// only the fixed reason constants and, for a syntax error or a bad string, the
// position.
func parseJSONServers(
	ctx context.Context,
	path string,
	client Client,
	scope Scope,
	projectPath string,
	withProjects bool,
) ([]Server, []*FileError) {
	maxSize := int64(maxConfigSize)
	if scope == ScopeProject {
		maxSize = maxProjectConfigSize
	}
	data, found, fe := readConfigFile(ctx, path, maxSize)
	if fe != nil {
		return nil, []*FileError{fe}
	}
	if !found || len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}

	// RawMessage keeps the bytes of a value without decoding them. We use it
	// so that one bad value does not stop the decoding of the others.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, []*FileError{topLevelError(path, data, err)}
	}
	// The file is a valid JSON object now, which findServerSurrogate needs.
	if off, project := findServerSurrogate(data, withProjects); off >= 0 {
		line, col := lineCol(data, int64(off))
		return nil, []*FileError{{Path: path, ProjectPath: project, Line: line, Col: col, Reason: reasonBadString}}
	}

	p := &jsonParser{path: path, client: client}
	var servers []Server
	var errs []*FileError
	if hasCaseVariant(top, keyMCPServers) {
		errs = append(errs, &FileError{Path: path, Reason: reasonAmbiguousKey})
	} else {
		servers, errs = p.decodeServers(top[keyMCPServers], origin{scope: scope, projectPath: projectPath})
	}
	if withProjects {
		if hasCaseVariant(top, keyProjects) {
			errs = append(errs, &FileError{Path: path, Reason: reasonAmbiguousKey})
		} else {
			projServers, projErrs := p.decodeProjects(ctx, top[keyProjects])
			servers = append(servers, projServers...)
			errs = append(errs, projErrs...)
		}
	}

	// A file over the cap is refused as a whole, as the Codex reader does.
	if p.full {
		return nil, []*FileError{{Path: path, Reason: reasonTooManyServers}}
	}

	sortServers(servers)
	sortErrors(errs)
	return servers, errs
}

// topLevelError turns a decode error for the whole file into a FileError. We
// look at the error type only and never use its text.
func topLevelError(path string, data []byte, err error) *FileError {
	var se *json.SyntaxError
	if errors.As(err, &se) {
		// Offset is the number of bytes read when the error was found, so the
		// bad byte is at index Offset-1. lineCol clamps a negative value.
		line, col := lineCol(data, se.Offset-1)
		return &FileError{Path: path, Line: line, Col: col, Reason: reasonInvalidJSON}
	}
	// Valid JSON of the wrong shape, for example a top-level array.
	return &FileError{Path: path, Reason: reasonBadShape}
}

// decodeProjects reads the "projects" object of ~/.claude.json. Every server
// in it is a project server. Project keys are visited in sorted order, so the
// result does not depend on Go's random map order.
//
// Each project counts as one entry toward maxServersPerFile, so a file with
// many empty projects is refused too.
func (p *jsonParser) decodeProjects(ctx context.Context, raw json.RawMessage) ([]Server, []*FileError) {
	if p.full || isNull(raw) {
		return nil, nil
	}
	var projects map[string]json.RawMessage
	if err := json.Unmarshal(raw, &projects); err != nil {
		return nil, []*FileError{{Path: p.path, Reason: reasonBadShape}}
	}

	var servers []Server
	var errs []*FileError

	// slices.Sorted collects the keys of the map iterator and sorts them.
	for _, key := range slices.Sorted(maps.Keys(projects)) {
		if err := ctx.Err(); err != nil {
			errs = append(errs, canceledError(p.path, err))
			break
		}
		// Count the project before the decode, so the cap holds even for
		// projects that hold no servers. A file over the cap stops the loop:
		// the next projects would only add more work for a refused file.
		p.count++
		if p.count > maxServersPerFile {
			p.full = true
			break
		}
		// Decode each project on its own, so a bad project does not drop
		// the other projects. A project is an object; we read only its
		// "mcpServers" key.
		var project map[string]json.RawMessage
		if err := json.Unmarshal(projects[key], &project); err != nil {
			errs = append(errs, &FileError{Path: p.path, ProjectPath: key, Reason: reasonBadShape})
			continue
		}
		if hasCaseVariant(project, keyMCPServers) {
			errs = append(errs, &FileError{Path: p.path, ProjectPath: key, Reason: reasonAmbiguousKey})
			continue
		}
		s, e := p.decodeServers(project[keyMCPServers], origin{scope: ScopeProject, projectPath: key, project: key})
		servers = append(servers, s...)
		errs = append(errs, e...)
		if p.full {
			break
		}
	}
	return servers, errs
}

// decodeServers reads one "mcpServers" object. An absent or null value means
// no servers: Claude Code and Cursor write null or leave the key out when
// nothing is configured.
//
// If the object would take the entries of the file over maxServersPerFile, it
// sets p.full and decodes none of its entries.
func (p *jsonParser) decodeServers(raw json.RawMessage, o origin) ([]Server, []*FileError) {
	if p.full || isNull(raw) {
		return nil, nil
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, []*FileError{{Path: p.path, ProjectPath: o.project, Reason: reasonBadServers}}
	}
	if p.count+len(entries) > maxServersPerFile {
		p.full = true
		return nil, nil
	}
	p.count += len(entries)

	var servers []Server
	var errs []*FileError
	for name, entryRaw := range entries {
		// An empty name has no use and cannot be shown in an error message.
		if name == "" {
			errs = append(errs, &FileError{Path: p.path, ProjectPath: o.project, Reason: reasonEmptyName})
			continue
		}
		entry, reason := decodeEntry(entryRaw)
		if reason == "" {
			var srv Server
			srv, reason = p.newServer(name, entry, o)
			if reason == "" {
				servers = append(servers, srv)
				continue
			}
		}
		errs = append(errs, &FileError{Path: p.path, ProjectPath: o.project, Server: name, Reason: reason})
	}
	return servers, errs
}

// decodeEntry decodes one server entry. It reads only the exact keys in
// entryKeys and ignores other keys. It returns a fixed reason text if the
// entry is not an object, if a known key has a value of the wrong type, or if
// the entry has a known key in a different letter case.
func decodeEntry(raw json.RawMessage) (jsonEntry, string) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return jsonEntry{}, reasonBadEntry
	}
	if hasCaseVariant(fields, entryKeys[:]...) {
		return jsonEntry{}, reasonAmbiguousKey
	}
	var e jsonEntry
	err := errors.Join(
		decodeField(fields, keyType, &e.Type),
		decodeField(fields, keyCommand, &e.Command),
		decodeField(fields, keyArgs, &e.Args),
		decodeField(fields, keyEnv, &e.Env),
		decodeField(fields, keyURL, &e.URL),
		decodeField(fields, keyHeaders, &e.Headers),
	)
	if err != nil {
		return jsonEntry{}, reasonBadEntry
	}
	return e, ""
}

// decodeField decodes fields[key] into dst. An absent key leaves dst at its
// zero value, and so does a null value.
func decodeField(fields map[string]json.RawMessage, key string, dst any) error {
	raw, ok := fields[key]
	if !ok {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

// hasCaseVariant reports whether obj has a key that is not one of known but
// differs from one of them only by letter case. strings.EqualFold uses Unicode
// case folding, so "ARGſ" (with U+017F, a long s) matches "args" too.
func hasCaseVariant(obj map[string]json.RawMessage, known ...string) bool {
	for key := range obj {
		for _, k := range known {
			if key != k && strings.EqualFold(key, k) {
				return true
			}
		}
	}
	return false
}

// findServerSurrogate returns the byte offset in data of the first lone
// surrogate escape (see findLoneSurrogate) in a part of the file that the
// reader uses, or -1 if there is none. For a surrogate under "projects", it
// also returns the project key, decoded (a lone surrogate in it is U+FFFD).
//
// The checked parts are:
//   - the value of every top-level "mcpServers" member: the server names and
//     all keys and values of the entries (command, args, env, url, headers);
//   - if withProjects is true, every key of the top-level "projects" object,
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
func findServerSurrogate(data []byte, withProjects bool) (int, string) {
	top, _ := objectMembers(data)
	for _, m := range top {
		switch {
		case m.key == keyMCPServers:
			if off := findLoneSurrogate(data[m.valStart:m.valEnd]); off >= 0 {
				return m.valStart + off, ""
			}
		case m.key == keyProjects && withProjects:
			if off, project := findProjectSurrogate(data[m.valStart:m.valEnd]); off >= 0 {
				return m.valStart + off, project
			}
		}
	}
	return -1, ""
}

// findProjectSurrogate does the "projects" part of findServerSurrogate. data
// is the value of "projects", and the offset it returns is an offset in data.
// A value that is not an object has nothing to check; decodeProjects reports
// it. The same holds for a project that is not an object.
func findProjectSurrogate(data []byte) (int, string) {
	projects, _ := objectMembers(data)
	for _, p := range projects {
		// The key range holds only the key string, and maybe a comma and
		// whitespace before it, so this checks the project key only.
		if off := findLoneSurrogate(data[p.keyStart:p.keyEnd]); off >= 0 {
			return p.keyStart + off, p.key
		}
		// Offsets of the project fields are relative to the project value.
		value := data[p.valStart:p.valEnd]
		fields, _ := objectMembers(value)
		for _, f := range fields {
			if f.key != keyMCPServers {
				continue
			}
			if off := findLoneSurrogate(value[f.valStart:f.valEnd]); off >= 0 {
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
		// Between the key and the value there is only a colon and
		// whitespace. len(data) minus the length of the rest gives the index.
		m.valStart = len(data) - len(bytes.TrimLeft(data[m.keyEnd:], " \t\r\n:"))
		m.valEnd = m.valStart + len(raw)
		members = append(members, m)
	}
	return members, true
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

// newServer builds a Server from a decoded entry. If the entry is not valid it
// returns a fixed reason text and the Server is not usable.
//
// Fields that do not belong to the chosen transport are dropped: a stdio
// server keeps Command, Args and Env; a remote server keeps URL and Headers.
func (p *jsonParser) newServer(name string, e jsonEntry, o origin) (Server, string) {
	transport, reason := resolveTransport(e)
	if reason != "" {
		return Server{}, reason
	}
	srv := Server{
		Name:        name,
		Client:      p.client,
		Scope:       o.scope,
		ProjectPath: o.projectPath,
		Source:      p.path,
		Transport:   transport,
	}
	if transport.IsRemote() {
		srv.URL = e.URL
		srv.Headers = e.Headers
	} else {
		srv.Command = e.Command
		srv.Args = NewArgs(e.Args)
		srv.Env = e.Env
	}
	return srv, ""
}

// resolveTransport picks the transport of an entry from its "type" field. With
// no type it infers one: a command means stdio, else a url means http. It
// returns a fixed reason text if the entry is not valid. The unknown type
// value is never put in the reason.
func resolveTransport(e jsonEntry) (Transport, string) {
	hasURL := e.URL.Reveal() != ""
	switch e.Type {
	case "stdio":
		if e.Command == "" {
			return "", reasonStdioNoCommand
		}
		return TransportStdio, ""
	case "http", "streamable-http":
		return remoteTransport(TransportHTTP, hasURL)
	case "sse":
		return remoteTransport(TransportSSE, hasURL)
	case "":
		if e.Command != "" {
			return TransportStdio, ""
		}
		if hasURL {
			return TransportHTTP, ""
		}
		return "", reasonNoCommandOrURL
	default:
		return "", reasonUnknownTransport
	}
}

// remoteTransport returns t if the entry has a url, else the reason for a
// remote entry without a url.
func remoteTransport(t Transport, hasURL bool) (Transport, string) {
	if !hasURL {
		return "", reasonRemoteNoURL
	}
	return t, ""
}

// isNull reports whether raw is absent or the JSON value null.
func isNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

// sortServers sorts servers by (ProjectPath, Name). The sort is stable: servers
// with the same key keep their input order, so a top-level server comes before
// a project server of the same name and path.
func sortServers(servers []Server) {
	slices.SortStableFunc(servers, func(a, b Server) int {
		return cmp.Or(
			strings.Compare(a.ProjectPath, b.ProjectPath),
			strings.Compare(a.Name, b.Name),
		)
	})
}

// sortErrors puts file-level errors (empty Server) first, then sorts by Server
// name. Empty sorts before every other string, so comparing the names is
// enough. The sort is stable: errors with the same name keep their order.
func sortErrors(errs []*FileError) {
	slices.SortStableFunc(errs, func(a, b *FileError) int {
		return strings.Compare(a.Server, b.Server)
	})
}
