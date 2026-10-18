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
// A missing file and an empty file give no servers and no error. Empty means
// no bytes, or only the JSON whitespace bytes space, tab, CR and LF. Other
// space characters (for example U+00A0) are not JSON whitespace, so a file of
// them is invalid JSON. A file that holds only null is an "unexpected
// structure" error: the clients need an object. A problem in one server entry
// gives a *FileError for that entry; the other entries are still returned. An
// error for an entry or a project under "projects" has FileError.ProjectPath
// set to the project key.
//
// Project files: with scope ScopeProject the file is a project file from a
// cloned repository, so it is untrusted. Every Server and every FileError of
// the file then has Untrusted set, also a read error. With a non-empty
// projectPath, the file is opened below projectPath only (see
// readConfigFile): a symlink that leads out of projectPath gives a "file is
// outside the project" error. With an empty projectPath there is no such
// check. With ScopeGlobal, Untrusted is false everywhere, also for the
// servers under "projects".
//
// Keys are matched exactly, as the clients do. A known key in a different
// letter case ("Command", "MCPSERVERS") is an "ambiguous key" error: for an
// entry, the entry gives no server; for a project, the project gives no
// servers; for the top level, that section gives no servers.
//
// A lone UTF-16 surrogate escape (for example "\ud800" without a low
// surrogate after it) or an invalid UTF-8 byte in a server entry or in a
// project key makes the whole file an "invalid string" error, with the
// position of the first bad spot. encoding/json turns both into U+FFFD, so
// two names that differ for the client could become one name here. A bad
// string in another part of the file, for example in the chat history of
// ~/.claude.json, is not an error. See findBadServerString.
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
	servers, errs := parseJSONFile(ctx, path, client, scope, projectPath, withProjects)
	if scope == ScopeProject {
		markUntrusted(servers, errs)
	}
	return servers, errs
}

// markUntrusted sets Untrusted on every server and every error.
func markUntrusted(servers []Server, errs []*FileError) {
	for i := range servers {
		servers[i].Untrusted = true
	}
	for _, e := range errs {
		e.Untrusted = true
	}
}

// parseJSONFile does the work of parseJSONServers, except Untrusted.
func parseJSONFile(
	ctx context.Context,
	path string,
	client Client,
	scope Scope,
	projectPath string,
	withProjects bool,
) ([]Server, []*FileError) {
	maxSize := int64(maxConfigSize)
	root := ""
	if scope == ScopeProject {
		maxSize = maxProjectConfigSize
		root = projectPath
	}
	data, found, fe := readConfigFile(ctx, path, maxSize, root)
	if fe != nil {
		return nil, []*FileError{fe}
	}
	// Trim only the four JSON whitespace bytes. bytes.TrimSpace would also
	// trim Unicode spaces such as U+00A0, which JSON does not allow.
	if !found || len(bytes.Trim(data, " \t\r\n")) == 0 {
		return nil, nil
	}

	// RawMessage keeps the bytes of a value without decoding them. We use it
	// so that one bad value does not stop the decoding of the others.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, []*FileError{topLevelError(path, data, err)}
	}
	// Unmarshal of null into a map gives a nil map and no error.
	if top == nil {
		return nil, []*FileError{{Path: path, Reason: reasonBadShape}}
	}
	// The file is a valid JSON object now, which findBadServerString needs.
	if off, project := findBadServerString(data, withProjects); off >= 0 {
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
		entry, r := decodeEntry(entryRaw)
		if r == "" {
			var srv Server
			srv, r = p.newServer(name, entry, o)
			if r == "" {
				servers = append(servers, srv)
				continue
			}
		}
		errs = append(errs, &FileError{Path: p.path, ProjectPath: o.project, Server: name, Reason: string(r)})
	}
	return servers, errs
}

// decodeEntry decodes one server entry. It reads only the exact keys in
// entryKeys and ignores other keys. It returns a reason if the entry is not an
// object, if a known key has a value of the wrong type, or if the entry has a
// known key in a different letter case, and "" if the entry is valid.
func decodeEntry(raw json.RawMessage) (jsonEntry, reason) {
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

// newServer builds a Server from a decoded entry. If the entry is not valid it
// returns a reason and the Server is not usable; else the reason is "".
//
// Fields that do not belong to the chosen transport are dropped: a stdio
// server keeps Command, Args and Env; a remote server keeps URL and Headers.
func (p *jsonParser) newServer(name string, e jsonEntry, o origin) (Server, reason) {
	transport, r := resolveTransport(e)
	if r != "" {
		return Server{}, r
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
// returns a reason if the entry is not valid, and "" if it is. The unknown
// type value is never put in the reason.
func resolveTransport(e jsonEntry) (Transport, reason) {
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
func remoteTransport(t Transport, hasURL bool) (Transport, reason) {
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
