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

// jsonSpace holds the four bytes that JSON allows as white space: space, tab,
// CR and LF. DetectClient, decodeJSONTop and objectMembers trim only these
// bytes. bytes.TrimSpace would also trim Unicode spaces such as U+00A0, which
// JSON does not allow.
const jsonSpace = " \t\r\n"

// jsonFile is one Claude Code or Cursor JSON config to read. ReadClaudeCode,
// readGlobalClaudeCodeState, ReadCursor and readUntrustedJSON build it with
// named fields.
type jsonFile struct {
	path   string
	client Client
	// scope goes to the servers of the top-level "mcpServers" object. Only
	// ScopeGlobal is trusted: readJSONServers reads any other value as
	// ScopeProject.
	scope Scope
	// projectPath goes to those servers with ScopeProject (see
	// topProjectPath). It is ignored with ScopeGlobal.
	projectPath string
	// projects tells what to do with the top-level "projects" section. The
	// zero value, projectsSkip, ignores it.
	projects projectsMode
	// states receives the enabled and approval state of each project that
	// decodeProjects reads. nil means "do not collect". Only
	// readGlobalClaudeCodeState sets it. decodeProjects reads and applies the
	// state of each project also when states is nil.
	states *claudeStates
}

// claudeStates holds the enabled and approval state of each project of a
// Claude Code ~/.claude.json, as decodeProjects read it.
type claudeStates struct {
	// byProject maps a projects.<path> key, exactly as the file has it, to
	// the state of that project. A project whose state has an error is not
	// in the map. decodeProjects makes the map when it first adds a project.
	byProject map[string]claudeProjectState
	// seen holds every projects.<path> key that decodeProjects visited, also
	// a key whose project or state has an error. So a key in seen and not in
	// byProject is a project whose state could not be read.
	seen nameSet
	// decoded is true when decodeProjects read the "projects" section to the
	// end: it visited every project, or the section is absent or null. It
	// stays false when the file is not decoded (missing, empty, or refused
	// as a whole), when the section is not an object or is ambiguous, and
	// when ctx ends during the loop. A file refused for too many entries
	// sets it back to false.
	decoded bool
}

// add stores st as the state of the project key.
func (c *claudeStates) add(key string, st claudeProjectState) {
	if c.byProject == nil {
		c.byProject = make(map[string]claudeProjectState)
	}
	c.byProject[key] = st
}

// see records that decodeProjects visited the project key.
func (c *claudeStates) see(key string) {
	if c.seen == nil {
		c.seen = make(nameSet)
	}
	c.seen[key] = struct{}{}
}

// reset forgets all projects, for a file that is refused as a whole.
func (c *claudeStates) reset() {
	c.byProject = nil
	c.seen = nil
	c.decoded = false
}

// projectsMode tells a JSON reader what to do with the top-level "projects"
// section of a Claude Code file.
type projectsMode int

const (
	// projectsSkip ignores the section. ReadCursor uses it, and
	// ReadClaudeCode for a project file, such as <WorkDir>/.mcp.json.
	projectsSkip projectsMode = iota
	// projectsRead reads the servers of the section. Only ~/.claude.json
	// has one, so only ReadClaudeCode with ScopeGlobal uses it.
	projectsRead
	// projectsReport does not read the section, but reports it (and a case
	// variant of its key) with an error. Only ReadConfig uses it, for every
	// untrusted JSON file. See ReadConfig.
	projectsReport
)

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
		return projectDirOf(f.path)
	}
	return f.projectPath
}

// projectDirOf returns the project directory of the project file at path:
// the directory of the file, or the parent of that directory when it is
// named cursorDir or codexDir. Cursor and Codex keep their project files in a
// directory of their own (<project>/.cursor/mcp.json and
// <project>/.codex/config.toml). The rule looks only at the path, not at the
// client, so a file in such a directory gets the parent for every client: a
// wrong guess of DetectClient cannot change the ProjectPath. The path is not
// made absolute: the package never reads the current directory by itself.
func projectDirOf(path string) string {
	dir := filepath.Dir(path)
	if inCursorDir(path) || inCodexDir(path) {
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
	// states is jsonFile.states. decodeProjects adds to it when it is not
	// nil.
	states *claudeStates

	// count is the number of entries seen so far: every server entry and every
	// project of the file.
	count int
	// full is set when the file went over the cap. After that, decodeServers
	// and decodeProjects decode nothing more, and decodeJSONSections returns
	// no servers.
	full bool
}

// readJSONServers reads the Claude Code or Cursor JSON config f within its
// limits (see jsonFile.limits) and parses the content with parseJSONBytes. A
// missing file gives no servers and no errors.
//
// Only ScopeGlobal is trusted. Any other value of f.scope, also the zero
// Scope, is read as ScopeProject: the file is read within the project
// limits, and its servers get ScopeProject. So a caller error fails closed.
// For a project file, a read error is marked Untrusted too.
func readJSONServers(ctx context.Context, f jsonFile) ([]Server, []*FileError) {
	maxSize, root := f.limits()
	data, found, fe := readConfigFile(ctx, f.path, maxSize, root)
	switch {
	case fe != nil:
		errs := []*FileError{fe}
		if f.scope != ScopeGlobal {
			markUntrusted(nil, errs)
		}
		return nil, errs
	case !found:
		return nil, nil
	}
	return parseJSONBytes(ctx, f, data)
}

// parseJSONBytes parses data, the content of the Claude Code or Cursor JSON
// config f. It does no I/O. ReadConfig calls it with the bytes of its one
// read, so a file that changes or goes away after that read cannot change the
// result. As in readJSONServers, any f.scope other than ScopeGlobal is read
// as ScopeProject.
//
// The servers of the top-level "mcpServers" object get f.scope and the
// ProjectPath of topProjectPath. With projectsRead, the servers under
// "projects.<dir>.mcpServers" are read too. They get ScopeProject and
// ProjectPath <dir>, and an error about one of them, or about the project
// itself, has FileError.ProjectPath <dir>. An empty <dir> is refused
// (reasonEmptyProject), and the other projects are still read. For Claude
// Code, decodeProjects also reads the state keys of each project; see there.
//
// For a project file, markUntrusted marks every server and every error at
// the end. A Claude Code project file (.mcp.json) also gives every server
// StateUnapproved: Claude Code runs such a server only after an approval,
// and parseJSONBytes reads no approval. Only [Discover] reads the settings
// that approve it (see setMcpjsonStates), so every other reader fails
// closed.
//
// See the package doc, Reading configs.
func parseJSONBytes(ctx context.Context, f jsonFile, data []byte) ([]Server, []*FileError) {
	if f.scope != ScopeGlobal {
		f.scope = ScopeProject
	}

	var servers []Server
	var errs []*FileError
	top, fe := decodeJSONTop(f, data)
	switch {
	case fe != nil:
		errs = []*FileError{fe}
	case top != nil:
		servers, errs = decodeJSONSections(ctx, f, top)
	}

	if f.scope != ScopeGlobal {
		markUntrusted(servers, errs)
		if f.client == ClientClaudeCode {
			for i := range servers {
				servers[i].State = StateUnapproved
			}
		}
	}
	return servers, errs
}

// markUntrusted sets Untrusted on every server and every error. For a JSON
// file it is the only code that sets Untrusted: readJSONServers and
// parseJSONBytes call it, and the other functions return every error of the
// file, read errors from readConfigFile too, without the mark.
func markUntrusted(servers []Server, errs []*FileError) {
	for i := range servers {
		servers[i].Untrusted = true
	}
	for _, e := range errs {
		e.Untrusted = true
	}
}

// decodeJSONTop checks data, the content of the file f, as a whole. It
// returns the top-level members of the file, or the one *FileError that
// refuses the file. A file that holds only JSON white space gives neither.
func decodeJSONTop(f jsonFile, data []byte) (map[string]json.RawMessage, *FileError) {
	if len(bytes.Trim(data, jsonSpace)) == 0 {
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
	if off, project := findBadServerString(data, f.projects == projectsRead); off >= 0 {
		return nil, newFileError(f.path, reasonBadString).inProject(project).atOffset(data, off)
	}
	return top, nil
}

// decodeJSONSections decodes the "mcpServers" section of top and handles the
// "projects" section as f.projects says. It refuses a file over
// maxServersPerFile as a whole, as the Codex reader does, and sorts the
// result.
func decodeJSONSections(ctx context.Context, f jsonFile, top map[string]json.RawMessage) ([]Server, []*FileError) {
	p := &jsonParser{path: f.path, client: f.client, states: f.states}
	var servers []Server
	var errs []*FileError
	if hasCaseVariant(top, keyMCPServers) {
		errs = append(errs, newFileError(f.path, reasonAmbiguousKey))
	} else {
		servers, errs = p.decodeServers(top[keyMCPServers], origin{scope: f.scope, projectPath: f.topProjectPath()})
	}
	// A case variant such as "Projects" is ambiguous: a reader that folds
	// case would read it as the section.
	projectsVariant := hasCaseVariant(top, keyProjects)
	switch f.projects {
	case projectsRead:
		if projectsVariant {
			errs = append(errs, newFileError(f.path, reasonAmbiguousKey))
			break
		}
		projServers, projErrs := p.decodeProjects(ctx, top[keyProjects])
		servers = append(servers, projServers...)
		errs = append(errs, projErrs...)
	case projectsReport:
		if projectsVariant {
			errs = append(errs, newFileError(f.path, reasonAmbiguousKey))
		}
		// Any value that is not null fails closed, also an empty object or a
		// value of the wrong type: the section is not read, so this reader
		// cannot tell that it holds no servers.
		if !isNull(top[keyProjects]) {
			errs = append(errs, newFileError(f.path, reasonProjectsNotRead))
		}
	case projectsSkip:
		// A project file must not choose ProjectPath values, so the section
		// and its case variants are ignored.
	}

	if p.full {
		// The file is refused as a whole, so the states of its projects do
		// not count either.
		if p.states != nil {
			p.states.reset()
		}
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
//
// For a Claude Code file it also reads the enabled and approval state of each
// project (see decodeClaudeState). A server of the project whose name is in
// its disabledMcpServers list gets StateDisabled. When p.states is not nil,
// the state goes there, under the project key, and p.states also records each
// key that it visits and whether it read the whole section (see
// claudeStates).
//
// A state key with the wrong type gives one FileError with the reason of
// decodeClaudeState and ProjectPath <path>, and the project's servers are
// dropped, as for a project that is not an object. This fails closed: a
// server that the unreadable list could turn off is never shown as
// StateEnabled, and the error makes the scan fail, so the dropped servers do
// not look clean. The other projects are still read.
func (p *jsonParser) decodeProjects(ctx context.Context, raw json.RawMessage) ([]Server, []*FileError) {
	if p.full {
		return nil, nil
	}
	if isNull(raw) {
		p.markDecoded()
		return nil, nil
	}
	var projects map[string]json.RawMessage
	if err := json.Unmarshal(raw, &projects); err != nil {
		return nil, []*FileError{newFileError(p.path, reasonBadShape)}
	}

	var servers []Server
	var errs []*FileError
	// canceled tells that ctx ended before the loop visited every project.
	var canceled bool

	// slices.Sorted collects the keys of the map iterator and sorts them.
	for _, key := range slices.Sorted(maps.Keys(projects)) {
		if err := ctx.Err(); err != nil {
			errs = append(errs, canceledError(p.path, err))
			canceled = true
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
		if p.states != nil {
			p.states.see(key)
		}
		// An empty key names no directory, and its servers would get the
		// ProjectPath "" of a global server.
		if key == "" {
			errs = append(errs, newFileError(p.path, reasonEmptyProject))
			continue
		}
		// Decode each project on its own, so a bad project does not drop
		// the other projects. A project is an object; we read only its
		// "mcpServers" key and, for Claude Code, its state keys.
		var project map[string]json.RawMessage
		if err := json.Unmarshal(projects[key], &project); err != nil {
			errs = append(errs, newFileError(p.path, reasonBadShape).inProject(key))
			continue
		}
		if hasCaseVariant(project, keyMCPServers) {
			errs = append(errs, newFileError(p.path, reasonAmbiguousKey).inProject(key))
			continue
		}
		var st claudeProjectState
		if p.client == ClientClaudeCode {
			var r reason
			if st, r = decodeClaudeState(project); r != "" {
				errs = append(errs, newFileError(p.path, r).inProject(key))
				continue
			}
		}
		s, e := p.decodeServers(project[keyMCPServers], origin{scope: ScopeProject, projectPath: key, project: key})
		applyDisabledServers(s, st)
		if p.states != nil {
			p.states.add(key, st)
		}
		servers = append(servers, s...)
		errs = append(errs, e...)
		if p.full {
			break
		}
	}
	// A break above leaves the section not read to the end: the file is
	// full (and refused as a whole), or ctx ended.
	if !p.full && !canceled {
		p.markDecoded()
	}
	return servers, errs
}

// markDecoded records that decodeProjects read the "projects" section to the
// end, when p.states is not nil.
func (p *jsonParser) markDecoded() {
	if p.states != nil {
		p.states.decoded = true
	}
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
