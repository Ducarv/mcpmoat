package discover

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"path/filepath"
	"slices"
)

// Exact keys of the Claude Code and Cursor JSON configs. The clients read the
// files with JSON.parse, which matches keys exactly, so mcpmoat must do the
// same. encoding/json matches struct fields without regard to letter case, so
// the reader never decodes into a struct with json tags: it decodes each
// object into a map and reads these keys only.
//
// The JSON and Codex key names (codexKeyCommand and the others) are kept
// apart on purpose, also where the text is the same: the two formats can
// change on their own.
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

// jsonEntry is one server entry in a Claude Code or Cursor JSON config. Both
// clients use the same shape. Fields that a JSON entry does not have stay at
// their zero value. decodeJSONEntry fills it from the exact keys in
// jsonReads; it has no json tags on purpose.
type jsonEntry struct {
	Type    string
	Command string
	Args    []string
	Env     SecretMap
	URL     URL
	Headers SecretMap
}

// jsonRead is one key of a server entry that decodeJSONEntry reads, and a
// pointer to the jsonEntry field that takes the value.
type jsonRead struct {
	key string
	dst any
}

// jsonReads returns one jsonRead for each key of a server entry, with
// pointers into e. It is the one list of these keys: jsonKnownKeys is built
// from it.
func jsonReads(e *jsonEntry) []jsonRead {
	return []jsonRead{
		{key: keyType, dst: &e.Type},
		{key: keyCommand, dst: &e.Command},
		{key: keyArgs, dst: &e.Args},
		{key: keyEnv, dst: &e.Env},
		{key: keyURL, dst: &e.URL},
		{key: keyHeaders, dst: &e.Headers},
	}
}

// jsonKnownKeys lists the keys of jsonReads, in order. decodeJSONEntry uses it
// to find keys that differ from a known key only by letter case. It is built
// once, when the package loads. No code writes to it.
var jsonKnownKeys = jsonAllKeys()

// jsonAllKeys returns the keys of jsonReads, in order. It runs once, to build
// jsonKnownKeys.
func jsonAllKeys() []string {
	reads := jsonReads(&jsonEntry{})
	keys := make([]string, 0, len(reads))
	for _, r := range reads {
		keys = append(keys, r.key)
	}
	return keys
}

// jsonFile is one Claude Code or Cursor JSON config to read. ReadClaudeCode
// and ReadCursor build it with named fields.
type jsonFile struct {
	path   string
	client Client
	// scope goes to the servers of the top-level "mcpServers" object. Only
	// ScopeGlobal is trusted: parseJSONServers reads any other value as
	// ScopeProject.
	scope Scope
	// projectPath goes to those servers with ScopeProject (see
	// topProjectPath). It is ignored with ScopeGlobal.
	projectPath string
	// withProjects reads the "projects" section too. Only ~/.claude.json has
	// one.
	withProjects bool
	// reportProjects adds one reasonProjectsNotRead error when the file has a
	// "projects" value that is not null and withProjects is false. Only
	// ReadConfig sets it, for an untrusted Claude Code file named with
	// --config. Discover does not set it for <WorkDir>/.mcp.json.
	reportProjects bool
	// data is the content of the file when the caller has read it already,
	// and hasData tells that it has. ReadConfig reads the file once to detect
	// the format, and the reader then parses those bytes: a second read could
	// find another file, or no file. Without hasData, read reads the file.
	data    []byte
	hasData bool
}

// read returns the content of the file: f.data when f.hasData is true, or
// else what readConfigFile reads within the limits of the file.
func (f jsonFile) read(ctx context.Context) (data []byte, found bool, fe *FileError) {
	if f.hasData {
		return f.data, true, nil
	}
	maxSize, root := f.limits()
	return readConfigFile(ctx, f.path, maxSize, root)
}

// limits returns the size limit of the file and the directory that the read
// must stay in ("" for no such directory).
//
// For a project file the directory is projectPath. If projectPath is "", it
// is the directory of the file, also for a Cursor file in a ".cursor"
// directory, where topProjectPath gives the parent directory. That root is
// the smaller one, so a symlink from .cursor/mcp.json to a file next to
// .cursor is refused. A symlink out of the directory and an absolute symlink
// are refused too.
func (f jsonFile) limits() (maxSize int64, root string) {
	if f.scope == ScopeGlobal {
		return maxConfigSize, ""
	}
	root = f.projectPath
	if root == "" {
		root = filepath.Dir(f.path)
	}
	return maxProjectConfigSize, root
}

// topProjectPath returns the ProjectPath of the servers of the top-level
// "mcpServers" object. A global file applies to all projects, so its servers
// get "". A project file gets projectPath, or, if projectPath is "", the
// project directory that projectDirOf derives from the path.
func (f jsonFile) topProjectPath() string {
	switch {
	case f.scope == ScopeGlobal:
		return ""
	case f.projectPath == "":
		return projectDirOf(f.path, f.client)
	}
	return f.projectPath
}

// projectDirOf returns the project directory of the project file at path:
// the directory of the file, or, for a Cursor file in a directory named
// ".cursor", the parent of that directory. Cursor keeps its project file in
// <project>/.cursor/mcp.json. The path is not made absolute: the package
// never reads the current directory by itself.
func projectDirOf(path string, client Client) string {
	dir := filepath.Dir(path)
	if client == ClientCursor && inCursorDir(path) {
		return filepath.Dir(dir)
	}
	return dir
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
	// and decodeProjects decode nothing more, and decodeJSONSections returns
	// no servers.
	full bool
}

// parseJSONServers reads the Claude Code or Cursor JSON config f.
//
// Only ScopeGlobal is trusted. Any other value of f.scope, also the zero
// Scope, is read as ScopeProject: the file is read within the project
// limits, and its servers get ScopeProject. So a caller error fails closed.
//
// The servers of the top-level "mcpServers" object get f.scope and the
// ProjectPath of topProjectPath. If f.withProjects is true, the servers under
// "projects.<dir>.mcpServers" are read too. They get ScopeProject and
// ProjectPath <dir>, and an error about one of them, or about the project
// itself, has FileError.ProjectPath <dir>. An empty <dir> is refused
// (reasonEmptyProject), and the other projects are still read.
//
// For a project file, markUntrusted marks every server and every error at
// the end.
//
// See the package doc, Reading configs.
func parseJSONServers(ctx context.Context, f jsonFile) ([]Server, []*FileError) {
	if f.scope != ScopeGlobal {
		f.scope = ScopeProject
	}

	var servers []Server
	var errs []*FileError
	top, fe := loadJSONFile(ctx, f)
	switch {
	case fe != nil:
		errs = []*FileError{fe}
	case top != nil:
		servers, errs = decodeJSONSections(ctx, f, top)
	}

	if f.scope != ScopeGlobal {
		markUntrusted(servers, errs)
	}
	return servers, errs
}

// markUntrusted sets Untrusted on every server and every error. For a JSON
// file it is the only code that sets Untrusted: the other functions return
// every error of the file, read errors from readConfigFile too, without the
// mark.
func markUntrusted(servers []Server, errs []*FileError) {
	for i := range servers {
		servers[i].Untrusted = true
	}
	for _, e := range errs {
		e.Untrusted = true
	}
}

// loadJSONFile reads f within its limits (or takes f.data, see jsonFile.read)
// and checks the file as a whole. It returns the top-level members of the
// file, or the one *FileError that refuses the file. A missing file and an
// empty file give neither.
func loadJSONFile(ctx context.Context, f jsonFile) (map[string]json.RawMessage, *FileError) {
	data, found, fe := f.read(ctx)
	if fe != nil {
		return nil, fe
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
		return nil, topLevelError(f.path, data, err)
	}
	// Unmarshal of null into a map gives a nil map and no error.
	if top == nil {
		return nil, newFileError(f.path, reasonBadShape)
	}
	// The file is a valid JSON object now, which findBadServerString needs.
	if off, project := findBadServerString(data, f.withProjects); off >= 0 {
		return nil, newFileError(f.path, reasonBadString).inProject(project).atOffset(data, off)
	}
	return top, nil
}

// decodeJSONSections decodes the "mcpServers" section of top and, if
// f.withProjects is true, the "projects" section. It refuses a file over
// maxServersPerFile as a whole, as the Codex reader does, and sorts the
// result.
func decodeJSONSections(ctx context.Context, f jsonFile, top map[string]json.RawMessage) ([]Server, []*FileError) {
	p := &jsonParser{path: f.path, client: f.client}
	var servers []Server
	var errs []*FileError
	if hasCaseVariant(top, keyMCPServers) {
		errs = append(errs, newFileError(f.path, reasonAmbiguousKey))
	} else {
		servers, errs = p.decodeServers(top[keyMCPServers], origin{scope: f.scope, projectPath: f.topProjectPath()})
	}
	if f.withProjects {
		if hasCaseVariant(top, keyProjects) {
			errs = append(errs, newFileError(f.path, reasonAmbiguousKey))
		} else {
			projServers, projErrs := p.decodeProjects(ctx, top[keyProjects])
			servers = append(servers, projServers...)
			errs = append(errs, projErrs...)
		}
	} else if f.reportProjects && !isNull(top[keyProjects]) {
		// Any value that is not null fails closed, also an empty object or a
		// value of the wrong type: the section is not read, so this reader
		// cannot tell that it holds no servers.
		errs = append(errs, newFileError(f.path, reasonProjectsNotRead))
	}

	if p.full {
		return nil, []*FileError{newFileError(f.path, reasonTooManyServers)}
	}

	sortServers(servers)
	sortErrors(errs)
	return servers, errs
}

// topLevelError turns a decode error for the whole file into a FileError. We
// look at the error type only and never use its text.
func topLevelError(path string, data []byte, err error) *FileError {
	if se, ok := errors.AsType[*json.SyntaxError](err); ok {
		// Offset is the number of bytes read when the error was found, so the
		// bad byte is at index Offset-1. lineCol clamps a negative value.
		return newFileError(path, reasonInvalidJSON).atOffset(data, int(se.Offset-1))
	}
	// Valid JSON of the wrong shape, for example a top-level array.
	return newFileError(path, reasonBadShape)
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
		return nil, []*FileError{newFileError(p.path, reasonBadShape)}
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
		// An empty key names no directory, and its servers would get the
		// ProjectPath "" of a global server.
		if key == "" {
			errs = append(errs, newFileError(p.path, reasonEmptyProject))
			continue
		}
		// Decode each project on its own, so a bad project does not drop
		// the other projects. A project is an object; we read only its
		// "mcpServers" key.
		var project map[string]json.RawMessage
		if err := json.Unmarshal(projects[key], &project); err != nil {
			errs = append(errs, newFileError(p.path, reasonBadShape).inProject(key))
			continue
		}
		if hasCaseVariant(project, keyMCPServers) {
			errs = append(errs, newFileError(p.path, reasonAmbiguousKey).inProject(key))
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
		return nil, []*FileError{newFileError(p.path, reasonBadServers).inProject(o.project)}
	}
	if p.count+len(entries) > maxServersPerFile {
		p.full = true
		return nil, nil
	}
	p.count += len(entries)

	var servers []Server
	var errs []*FileError
	for name, entryRaw := range entries {
		srv, r := p.readJSONServer(name, entryRaw, o)
		if r != "" {
			errs = append(errs, newFileError(p.path, r).inProject(o.project).forServer(name))
			continue
		}
		servers = append(servers, srv)
	}
	return servers, errs
}

// readJSONServer turns the server entry raw called name into a Server. It
// returns a reason if the entry is not valid, and "" if it is. It is the
// JSON form of readCodexServer; it is a method because newJSONServer needs
// the path and the client of the parser.
func (p *jsonParser) readJSONServer(name string, raw json.RawMessage, o origin) (Server, reason) {
	// An empty name has no use and cannot be shown in an error message.
	if name == "" {
		return Server{}, reasonEmptyName
	}
	e, r := decodeJSONEntry(raw)
	if r != "" {
		return Server{}, r
	}
	return p.newJSONServer(name, e, o)
}

// decodeJSONEntry decodes one server entry. It reads only the exact keys in
// jsonReads and ignores other keys. It returns reasonBadEntry if the entry is
// null or not an object, or if a known key has a value of the wrong type or a
// null (see decodeField), reasonAmbiguousKey if the entry has a known key in
// a different letter case, and "" if the entry is valid.
func decodeJSONEntry(raw json.RawMessage) (jsonEntry, reason) {
	// Unmarshal of null into a map gives a nil map and no error, which would
	// make the entry an empty object. The client gets the real null.
	if isNull(raw) {
		return jsonEntry{}, reasonBadEntry
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return jsonEntry{}, reasonBadEntry
	}
	if hasCaseVariant(fields, jsonKnownKeys...) {
		return jsonEntry{}, reasonAmbiguousKey
	}
	var e jsonEntry
	for _, r := range jsonReads(&e) {
		if err := decodeField(fields, r.key, r.dst); err != nil {
			return jsonEntry{}, reasonBadEntry
		}
	}
	return e, ""
}

// errNull is the error of decodeField for a null value. decodeJSONEntry turns
// it into reasonBadEntry, so its text is never shown.
var errNull = errors.New("null value")

// decodeField decodes fields[key] into dst. An absent key leaves dst at its
// zero value.
//
// A null is an error: a null value, a null item of an array ("args":
// ["x", null]) and a null value of an object ("env": {"K": null}).
// encoding/json would make each of them a zero value ("" or an empty
// Secret), or treat the key as absent. The client gets the real null: it
// refuses the entry, or Node turns the null into the text "null". inspect
// could then run another command line than the client (NFR-04).
func decodeField(fields map[string]json.RawMessage, key string, dst any) error {
	raw, ok := fields[key]
	if !ok {
		return nil
	}
	if isNull(raw) || hasNullItem(raw) {
		return errNull
	}
	return json.Unmarshal(raw, dst)
}

// hasNullItem reports whether raw is an array with a null item or an object
// with a null value. It checks one level only, and gives false for any other
// value and for invalid JSON: the decode into the field type finds those.
func hasNullItem(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	switch raw[0] {
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return false
		}
		return slices.ContainsFunc(items, isNull)
	case '{':
		var members map[string]json.RawMessage
		if err := json.Unmarshal(raw, &members); err != nil {
			return false
		}
		for _, v := range members {
			if isNull(v) {
				return true
			}
		}
	}
	return false
}

// newJSONServer builds a Server from a decoded entry. If the entry is not
// valid it returns a reason and the Server is not usable; else the reason is
// "".
//
// Fields that do not belong to the chosen transport are dropped: a stdio
// server keeps Command, Args and Env; a remote server keeps URL and Headers.
func (p *jsonParser) newJSONServer(name string, e jsonEntry, o origin) (Server, reason) {
	transport, r := resolveTransport(p.client, e)
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

// resolveTransport picks the transport of an entry of client from its "type"
// field. With no type, a command means stdio, and a url without a command
// means http for Cursor only. Claude Code reads an entry with no type as
// stdio and refuses it without a command, so for any other client such an
// entry gives reasonBadEntry. It returns a reason if the entry is not valid,
// and "" if it is. The unknown type value is never put in the reason.
func resolveTransport(client Client, e jsonEntry) (Transport, reason) {
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
		switch {
		case e.Command != "":
			return TransportStdio, ""
		case !hasURL:
			return "", reasonNoCommandOrURL
		case client != ClientCursor:
			return "", reasonBadEntry
		}
		return TransportHTTP, ""
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
//
// raw is not trimmed. Every raw value here comes from a decode into a
// map[string]json.RawMessage or a []json.RawMessage, and encoding/json keeps
// only the bytes of the value there, without the whitespace around it.
func isNull(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(raw, []byte("null"))
}
