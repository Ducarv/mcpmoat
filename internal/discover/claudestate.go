package discover

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
)

// This file reads the Claude Code settings that turn a server on or off, and
// the approval of the servers of a project .mcp.json. They come from two
// kinds of places:
//
//   - the settings files: Home/.claude/settings.json (trusted), and
//     WorkDir/.claude/settings.json and WorkDir/.claude/settings.local.json
//     (untrusted: a cloned repository can ship them);
//   - the projects.<path> object of ~/.claude.json (the legacy place).
//
// Each place can hold the same four keys (see the key constants below). The
// readers of the server files call these helpers and set Server.State.

// Exact keys of the Claude Code enabled and approval settings. Claude Code
// reads them exactly, so mcpmoat does too. A key in another letter case is
// ignored, as in Claude Code.
const (
	// keyEnabledMcpjsonServers lists the .mcp.json servers that the user
	// approved.
	keyEnabledMcpjsonServers = "enabledMcpjsonServers"
	// keyDisabledMcpjsonServers lists the .mcp.json servers that the user
	// rejected.
	keyDisabledMcpjsonServers = "disabledMcpjsonServers"
	// keyDisabledMcpServers lists the servers that the user turned off for
	// one project, with any scope.
	keyDisabledMcpServers = "disabledMcpServers"
	// keyEnableAllProjectMcpServers approves all .mcp.json servers when it is
	// true.
	keyEnableAllProjectMcpServers = "enableAllProjectMcpServers"
)

// The names of the Claude Code settings files and of their directory.
const (
	// claudeDir is the directory of the settings files, in the home
	// directory and in a project directory.
	claudeDir = ".claude"
	// claudeSettingsFile is the shared settings file in claudeDir.
	claudeSettingsFile = "settings.json"
	// claudeLocalSettingsFile is the personal settings file in claudeDir of
	// a project. It has precedence over claudeSettingsFile.
	claudeLocalSettingsFile = "settings.local.json"
)

// nameSet is a set of server names. A nil nameSet is empty.
type nameSet map[string]struct{}

// has reports whether name is in the set.
func (s nameSet) has(name string) bool {
	_, ok := s[name]
	return ok
}

// claudeProjectState holds the enabled and approval settings of one place: a
// settings file, or one projects.<path> object of ~/.claude.json. The zero
// value holds no setting.
type claudeProjectState struct {
	// enabledMcpjson are the names in enabledMcpjsonServers.
	enabledMcpjson nameSet
	// disabledMcpjson are the names in disabledMcpjsonServers.
	disabledMcpjson nameSet
	// disabledMcp are the names in disabledMcpServers.
	disabledMcp nameSet
	// enableAll is the value of enableAllProjectMcpServers, or nil when the
	// key is absent.
	enableAll *bool
}

// decodeClaudeState reads the enabled and approval keys of obj, a decoded
// JSON object: a settings file or one projects.<path> object. It reads the
// exact keys only and ignores all other keys. An absent key or a null value
// gives no setting.
//
// It returns reasonBadServerState and a zero state when a key has the wrong
// type: a list that is not an array of strings, or an
// enableAllProjectMcpServers that is not a boolean. It returns reasonBadString
// when a name in a list holds a lone UTF-16 surrogate escape or invalid UTF-8
// (see findBadString), because encoding/json would change such a name. The
// reason holds no value from the file. The caller builds the FileError.
func decodeClaudeState(obj map[string]json.RawMessage) (claudeProjectState, reason) {
	var st claudeProjectState
	lists := []struct {
		key string
		dst *nameSet
	}{
		{key: keyEnabledMcpjsonServers, dst: &st.enabledMcpjson},
		{key: keyDisabledMcpjsonServers, dst: &st.disabledMcpjson},
		{key: keyDisabledMcpServers, dst: &st.disabledMcp},
	}
	for _, l := range lists {
		set, r := decodeNameList(obj[l.key])
		if r != "" {
			return claudeProjectState{}, r
		}
		*l.dst = set
	}

	raw := obj[keyEnableAllProjectMcpServers]
	if isNull(raw) {
		return st, ""
	}
	var all bool
	if err := json.Unmarshal(raw, &all); err != nil {
		return claudeProjectState{}, reasonBadServerState
	}
	st.enableAll = &all
	return st, ""
}

// decodeNameList decodes raw, one list key of decodeClaudeState, into a set.
// An absent or null value gives a nil set. A value that is not an array, or
// an array with an item that is not a string (a null item too), gives
// reasonBadServerState. A name with a bad string part gives reasonBadString.
func decodeNameList(raw json.RawMessage) (nameSet, reason) {
	if isNull(raw) {
		return nil, ""
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, reasonBadServerState
	}
	set := make(nameSet, len(items))
	for _, item := range items {
		// Unmarshal of null into a string leaves it unchanged without an
		// error, so check for null first.
		var name string
		if isNull(item) || json.Unmarshal(item, &name) != nil {
			return nil, reasonBadServerState
		}
		if findBadString(item) >= 0 {
			return nil, reasonBadString
		}
		set[name] = struct{}{}
	}
	return set, ""
}

// readClaudeSettings reads the Claude Code settings file at path and returns
// its enabled and approval settings. A missing file gives a zero state and no
// error.
//
// root == "" is only for the user's own file, Home/.claude/settings.json: it
// is read without confinement, with the cap maxConfigSize. With a root (the
// project directory, WorkDir), the file is untrusted: it is read through
// os.Root within root, with the cap maxProjectConfigSize, and the FileError
// has Untrusted set.
//
// On any problem it returns a zero state and one FileError with a fixed
// reason: the read errors of readConfigFile, reasonInvalidJSON with the
// position, reasonBadShape for a file that is not a JSON object (null too),
// and the reasons of decodeClaudeState. An empty file, or one with only JSON
// white space, gives a zero state and no error.
func readClaudeSettings(ctx context.Context, path, root string) (claudeProjectState, *FileError) {
	st, fe := readClaudeSettingsFile(ctx, path, root)
	if fe != nil && root != "" {
		fe.Untrusted = true
	}
	return st, fe
}

// readClaudeSettingsFile does the work of readClaudeSettings without the
// Untrusted mark.
func readClaudeSettingsFile(ctx context.Context, path, root string) (claudeProjectState, *FileError) {
	var maxSize int64 = maxConfigSize
	if root != "" {
		maxSize = maxProjectConfigSize
	}
	data, found, fe := readConfigFile(ctx, path, maxSize, root)
	if fe != nil || !found {
		return claudeProjectState{}, fe
	}
	if len(bytes.Trim(data, jsonSpace)) == 0 {
		return claudeProjectState{}, nil
	}
	// Only the exact keys are read, from a map, as in decodeJSONTop. The
	// strings of the file are not checked as a whole: decodeClaudeState
	// checks the names that it reads.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return claudeProjectState{}, topLevelError(path, data, err)
	}
	// Unmarshal of null into a map gives a nil map and no error.
	if top == nil {
		return claudeProjectState{}, newFileError(path, reasonBadShape)
	}
	st, r := decodeClaudeState(top)
	if r != "" {
		return claudeProjectState{}, newFileError(path, r)
	}
	return st, nil
}

// readClaudeSettingsFiles reads the Claude Code settings files that can
// approve the servers of WorkDir/.mcp.json:
//
//  1. WorkDir/.claude/settings.local.json (untrusted, confined to WorkDir)
//  2. WorkDir/.claude/settings.json (untrusted, confined to WorkDir)
//  3. Home/.claude/settings.json (trusted)
//
// It returns the states in this order, which is the order of precedence for
// mcpjsonState (sourceLocal, sourceProject, sourceUser): append the
// projects.<WorkDir> state of ~/.claude.json last (sourceLegacy).
// A file that is missing or has an error gives a zero state, so states always
// has three items. An empty home or workDir skips its files (they give a zero
// state too).
//
// When home and workDir are the same directory, files 2 and 3 are the same
// file. It is read once, as the trusted user file, and the project slot gets
// a zero state. So a bad file gives one FileError, not a second one with
// Untrusted set. As in Discover, the check compares the cleaned paths as
// text. File 1 is still read from workDir.
//
// errs holds the FileErrors in the order home, project, local, the order of
// the paths. The project ones have Untrusted set. When ctx ends, it stops
// after the canceled error, and the next files give a zero state. A missing
// file gives no error, so each FileError is a source that failed: the caller
// must not trust the states for approval (see setMcpjsonStates).
func readClaudeSettingsFiles(ctx context.Context, home, workDir string) (states []claudeProjectState, errs []*FileError) {
	home, workDir = cleanDir(home), cleanDir(workDir)
	var local, project, user claudeProjectState
	reads := []struct {
		dir, file, root string
		dst             *claudeProjectState
	}{
		// root "" reads the user's own file without confinement.
		{dir: home, file: claudeSettingsFile, root: "", dst: &user},
		{dir: workDir, file: claudeSettingsFile, root: workDir, dst: &project},
		{dir: workDir, file: claudeLocalSettingsFile, root: workDir, dst: &local},
	}
	// userPath stays empty when home is empty, and a read path is never
	// empty, so an empty userPath matches no read.
	var userPath string
	if home != "" {
		userPath = filepath.Join(home, claudeDir, claudeSettingsFile)
	}
	for _, r := range reads {
		if r.dir == "" {
			continue
		}
		path := filepath.Join(r.dir, claudeDir, r.file)
		// The project file is the user file when workDir is home. The user
		// read already did it, so skip it.
		if r.root != "" && path == userPath {
			continue
		}
		st, fe := readClaudeSettings(ctx, path, r.root)
		*r.dst = st
		if fe != nil {
			errs = append(errs, fe)
			if fe.Reason == reasonCanceled {
				break
			}
		}
	}
	return []claudeProjectState{local, project, user}, errs
}

// setMcpjsonStates sets State on servers, the servers of WorkDir/.mcp.json.
// It reads the settings files with readClaudeSettingsFiles and applies them
// with legacy, the projects.<WorkDir> state of ~/.claude.json, through
// applyMcpjsonStates. It changes the servers in place and returns the
// FileErrors of the settings files.
//
// It fails closed. A source that failed to read or to decode gives a zero
// state, so its disabledMcpjsonServers and disabledMcpServers lists are lost,
// and another source could still approve a server that the lost list turns
// off. So when a settings file has a FileError, or when legacyFailed is true
// (the projects.<WorkDir> state of ~/.claude.json could not be read, see
// readGlobalClaudeCodeState), no server keeps an approval: a server that
// would be StateEnabled or StateProjectApproved gets StateUnapproved.
// StateDisabled stays. A missing file is normal and does not count. The
// FileError tells the user why, and makes the scan fail.
func setMcpjsonStates(ctx context.Context, servers []Server, home, workDir string, legacy claudeProjectState, legacyFailed bool) []*FileError {
	// states is a new slice of three, so this append does not change a
	// slice that another caller holds.
	states, errs := readClaudeSettingsFiles(ctx, home, workDir)
	applyMcpjsonStates(servers, append(states, legacy)...)
	if legacyFailed || len(errs) > 0 {
		revokeApprovals(servers)
	}
	return errs
}

// revokeApprovals sets StateUnapproved on every server with StateEnabled or
// StateProjectApproved. Other servers keep their State. It changes the
// servers in place. Use it only for .mcp.json servers, where these states
// come from an approval.
func revokeApprovals(servers []Server) {
	for i := range servers {
		if servers[i].State == StateEnabled || servers[i].State == StateProjectApproved {
			servers[i].State = StateUnapproved
		}
	}
}

// The positions of the sources of mcpjsonState, in order of precedence. The
// first two are files of the repository, which a cloned repository can ship,
// so they are untrusted. The last two belong to the user, so they are
// trusted.
const (
	// sourceLocal is WorkDir/.claude/settings.local.json (untrusted).
	sourceLocal = iota
	// sourceProject is WorkDir/.claude/settings.json (untrusted).
	sourceProject
	// sourceUser is Home/.claude/settings.json (trusted).
	sourceUser
	// sourceLegacy is the projects.<WorkDir> object of ~/.claude.json
	// (trusted).
	sourceLegacy
)

// trustedSource reports whether the source at position i of mcpjsonState
// belongs to the user. Only sourceUser and sourceLegacy do. Any other
// position, also one after sourceLegacy, is untrusted, so a caller error
// fails closed.
func trustedSource(i int) bool {
	return i == sourceUser || i == sourceLegacy
}

// mcpjsonState returns the State of the .mcp.json server called name. sources
// are the settings places in order of precedence, at the positions
// sourceLocal, sourceProject, sourceUser and sourceLegacy: the three states
// of readClaudeSettingsFiles, then the projects.<WorkDir> state of
// ~/.claude.json.
//
// The rule:
//
//  1. A name in any disabledMcpjsonServers gives StateDisabled.
//  2. Else the server is approved when its name is in any
//     enabledMcpjsonServers, or when enableAllProjectMcpServers is true: for
//     this key the first source that has it decides, and a later source
//     cannot change it. An approval from a trusted source (sourceUser or
//     sourceLegacy) gives StateEnabled. An approval only from untrusted
//     sources (sourceLocal or sourceProject) gives StateProjectApproved. So
//     a trusted enabled list wins over an untrusted enableAll, and the
//     other way round too.
//  3. Else the server is StateUnapproved.
//  4. Last, a name in any disabledMcpServers gives StateDisabled, also when
//     step 2 approved it.
//
// Step 4 wins over all other steps, so the code checks it first. With no
// sources, every server is StateUnapproved.
func mcpjsonState(name string, sources ...claudeProjectState) State {
	if disabledIn(name, sources...) {
		return StateDisabled
	}
	for _, st := range sources {
		if st.disabledMcpjson.has(name) {
			return StateDisabled
		}
	}

	// byUser and byRepo tell which kind of source approved the server.
	var byUser, byRepo bool
	approve := func(i int) {
		if trustedSource(i) {
			byUser = true
		} else {
			byRepo = true
		}
	}
	for i, st := range sources {
		if st.enabledMcpjson.has(name) {
			approve(i)
		}
	}
	if i, all := firstEnableAll(sources); all {
		approve(i)
	}

	switch {
	case byUser:
		return StateEnabled
	case byRepo:
		return StateProjectApproved
	default:
		return StateUnapproved
	}
}

// firstEnableAll returns the position in sources of the first source that has
// enableAllProjectMcpServers, and the value of that key. When no source has
// the key, it returns -1 and false.
func firstEnableAll(sources []claudeProjectState) (int, bool) {
	for i, st := range sources {
		if st.enableAll != nil {
			return i, *st.enableAll
		}
	}
	return -1, false
}

// disabledIn reports whether name is in the disabledMcpServers list of any of
// sources.
func disabledIn(name string, sources ...claudeProjectState) bool {
	for _, st := range sources {
		if st.disabledMcp.has(name) {
			return true
		}
	}
	return false
}

// applyMcpjsonStates sets State on every server of a project .mcp.json with
// mcpjsonState. sources are in the order that mcpjsonState needs. It changes
// the servers in place.
func applyMcpjsonStates(servers []Server, sources ...claudeProjectState) {
	for i := range servers {
		servers[i].State = mcpjsonState(servers[i].Name, sources...)
	}
}

// applyDisabledServers sets StateDisabled on every server whose name is in
// the disabledMcpServers list of st. Other servers keep their State. It
// changes the servers in place. Use it for the servers of one
// projects.<path> object, and for the top-level servers of ~/.claude.json
// with the projects.<WorkDir> state.
func applyDisabledServers(servers []Server, st claudeProjectState) {
	for i := range servers {
		if st.disabledMcp.has(servers[i].Name) {
			servers[i].State = StateDisabled
		}
	}
}
