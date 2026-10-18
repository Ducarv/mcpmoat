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

// jsonEntry is one server entry in a Claude Code or Cursor JSON config. Both
// clients use the same shape. Fields that a JSON entry does not have stay at
// their zero value.
type jsonEntry struct {
	Type    string    `json:"type"`
	Command string    `json:"command"`
	Args    []string  `json:"args"`
	Env     SecretMap `json:"env"`
	URL     URL       `json:"url"`
	Headers SecretMap `json:"headers"`
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
	// full is set when the file went over the cap. A file gets at most one "too
	// many servers" error: after that, decodeServers and decodeProjects decode
	// nothing more.
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
// other entries are still returned.
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
// together) gives one "too many servers" error. The entries and the projects
// after the cap are not decoded.
//
// Error messages never contain library error text. encoding/json errors can
// quote bytes of the config, and the config can hold secrets. So the code uses
// only the fixed reason constants and, for a syntax error, the byte offset.
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

	p := &jsonParser{path: path, client: client}
	servers, errs := p.decodeServers(top["mcpServers"], scope, projectPath)
	if withProjects {
		projServers, projErrs := p.decodeProjects(ctx, top["projects"])
		servers = append(servers, projServers...)
		errs = append(errs, projErrs...)
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
		// A file over the cap stops the loop: the next projects would only add
		// more work for a file that is already refused.
		if p.full {
			break
		}
		if err := ctx.Err(); err != nil {
			errs = append(errs, &FileError{Path: p.path, Reason: reasonCanceled, Err: err})
			break
		}
		// Count the project before the decode, so the cap holds even for
		// projects that hold no servers.
		p.count++
		if p.count > maxServersPerFile {
			p.full = true
			errs = append(errs, &FileError{Path: p.path, Reason: reasonTooManyServers})
			break
		}
		// Decode each project on its own, so a bad project does not drop
		// the other projects.
		var project struct {
			MCPServers json.RawMessage `json:"mcpServers"`
		}
		if err := json.Unmarshal(projects[key], &project); err != nil {
			errs = append(errs, &FileError{Path: p.path, Reason: reasonBadShape})
			continue
		}
		s, e := p.decodeServers(project.MCPServers, ScopeProject, key)
		servers = append(servers, s...)
		errs = append(errs, e...)
	}
	return servers, errs
}

// decodeServers reads one "mcpServers" object. An absent or null value means
// no servers: Claude Code and Cursor write null or leave the key out when
// nothing is configured.
//
// If the object would take the entries of the file over maxServersPerFile, none
// of its entries are decoded and the result is one "too many servers" error.
func (p *jsonParser) decodeServers(raw json.RawMessage, scope Scope, projectPath string) ([]Server, []*FileError) {
	if p.full || isNull(raw) {
		return nil, nil
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, []*FileError{{Path: p.path, Reason: reasonBadServers}}
	}
	if p.count+len(entries) > maxServersPerFile {
		p.full = true
		return nil, []*FileError{{Path: p.path, Reason: reasonTooManyServers}}
	}
	p.count += len(entries)

	var servers []Server
	var errs []*FileError
	for name, entryRaw := range entries {
		var entry jsonEntry
		if err := json.Unmarshal(entryRaw, &entry); err != nil {
			errs = append(errs, &FileError{Path: p.path, Server: name, Reason: reasonBadEntry})
			continue
		}
		srv, reason := p.newServer(name, entry, scope, projectPath)
		if reason != "" {
			errs = append(errs, &FileError{Path: p.path, Server: name, Reason: reason})
			continue
		}
		servers = append(servers, srv)
	}
	return servers, errs
}

// newServer builds a Server from a decoded entry. If the entry is not valid it
// returns a fixed reason text and the Server is not usable.
//
// Fields that do not belong to the chosen transport are dropped: a stdio
// server keeps Command, Args and Env; a remote server keeps URL and Headers.
func (p *jsonParser) newServer(name string, e jsonEntry, scope Scope, projectPath string) (Server, string) {
	transport, reason := resolveTransport(e)
	if reason != "" {
		return Server{}, reason
	}
	srv := Server{
		Name:        name,
		Client:      p.client,
		Scope:       scope,
		ProjectPath: projectPath,
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
