package discover

import (
	"context"
	"path/filepath"
)

// ReadClaudeCode reads one Claude Code config file: ~/.claude.json with
// ScopeGlobal, or a project .mcp.json with ScopeProject. Any scope other than
// ScopeGlobal is read as ScopeProject.
//
// The servers of the top-level "mcpServers" object get scope. With
// ScopeProject they get ProjectPath projectPath. If projectPath is "", they
// get the directory of the file, or for a file in a directory named ".cursor"
// or ".codex" the parent of that directory. With ScopeGlobal projectPath is
// ignored and ProjectPath is "".
//
// An entry with no "type" is a stdio entry, as in Claude Code, so an entry
// with a "url" and no "command" is an error: a remote entry needs "type".
//
// Only a global file has its "projects.<path>.mcpServers" servers read. They
// get ScopeProject and ProjectPath <path>. A project .mcp.json comes from a
// cloned repository, so its "projects" key is ignored: it must not choose a
// ProjectPath.
//
// State: a server of "projects.<path>.mcpServers" whose name is in the
// "projects.<path>.disabledMcpServers" list gets StateDisabled. All other
// servers keep StateEnabled. ReadClaudeCode reads one file and knows no
// project directory, so it does not apply the approval of the servers of a
// project .mcp.json (they are not StateUnapproved here), and it does not
// apply the state of a project to the top-level servers. Only [Discover]
// reads the settings files and the projects.<WorkDir> state for that.
//
// See the package doc, Reading configs.
func ReadClaudeCode(ctx context.Context, path string, scope Scope, projectPath string) Result {
	projects := projectsSkip
	if scope == ScopeGlobal {
		projects = projectsRead
	}
	servers, errs := readJSONServers(ctx, jsonFile{
		path:        path,
		client:      ClientClaudeCode,
		scope:       scope,
		projectPath: projectPath,
		projects:    projects,
	})
	return Result{Servers: servers, Errors: errs}
}

// readGlobalClaudeCodeState reads ~/.claude.json at path as a trusted global
// file, as ReadClaudeCode with ScopeGlobal does, for the project directory
// workDir. Discover uses it for its first step.
//
// It also returns the state of the "projects.<workDir>" object, and applies
// the disabledMcpServers list of that object to the top-level servers: in
// Claude Code, that list turns off a server of any scope while the user works
// in the project. The servers of "projects.<path>.mcpServers" get the state
// of their own project (see decodeProjects), not the one of workDir.
//
// The project keys are compared as written with two forms of workDir, both
// cleaned (see cleanDir):
//
//   - the exact form: workDir as given;
//   - the resolved form: workDir after filepath.EvalSymlinks. os.Getwd can
//     give a path through a symlink, but Claude Code writes the key with the
//     real path. If EvalSymlinks fails, or gives the exact form, only the
//     exact form is used.
//
// When both keys are in the file, the state joins them (see
// projectStateFor). The disabledMcpServers and disabledMcpjsonServers lists
// are the union of the two keys: a name that one key turns off stays off.
// The enabledMcpjsonServers list and enableAllProjectMcpServers come from
// one key only, the exact key if it is in the file, else the resolved key.
// So a join never adds an approval.
//
// A key with any other form of the same directory does not match. This is a
// known limit: for example another letter case on a case-insensitive file
// system. Then no state applies: the top-level servers keep StateEnabled, and
// the .mcp.json servers get no approval from ~/.claude.json.
//
// failed is true when the state of projects.<workDir> could not be read, so
// a zero state can hide a disabled list. That is so in two cases:
//
//   - The file exists, but its "projects" section was not read to the end:
//     a read error, a file refused as a whole (also for a bad string in
//     another project, or for too many entries), a "projects" section that
//     is not an object or that has a case variant, or a canceled read.
//   - The key of the exact or of the resolved form is in the file, but its
//     object or its state has an error.
//
// When failed is true, it fails closed: every top-level server with
// StateEnabled gets StateUnapproved, because mcpmoat cannot confirm that
// projects.<workDir>.disabledMcpServers does not turn it off. The servers of
// "projects.<path>.mcpServers" keep their State. Result.Errors holds the
// error, so the scan fails and the result does not look clean.
//
// The state is zero when the "projects" section was not read to the end,
// when the file is missing or holds only white space, or when the file has
// no key for workDir. The last cases are not a failure: failed is false and
// the top-level servers keep their State. An empty workDir matches no
// project and gives a zero state and failed false.
func readGlobalClaudeCodeState(ctx context.Context, path, workDir string) (res Result, st claudeProjectState, failed bool) {
	states := &claudeStates{}
	servers, errs := readJSONServers(ctx, jsonFile{
		path:     path,
		client:   ClientClaudeCode,
		scope:    ScopeGlobal,
		projects: projectsRead,
		states:   states,
	})
	res = Result{Servers: servers, Errors: errs}

	keys := workDirKeys(workDir)
	if len(keys) == 0 {
		return res, claudeProjectState{}, false
	}
	st, bad := projectStateFor(states, keys)
	// A missing file, and a file with only white space, give no error and
	// leave decoded false. Any other file that is not read to the end gives
	// at least one error, so the check of errs tells the two apart.
	failed = (!states.decoded && len(errs) > 0) || bad
	for i := range res.Servers {
		// Only the top-level servers have ScopeGlobal. The project servers
		// already have the state of their own project.
		if res.Servers[i].Scope != ScopeGlobal {
			continue
		}
		applyDisabledServers(res.Servers[i:i+1], st)
		if failed && res.Servers[i].State == StateEnabled {
			res.Servers[i].State = StateUnapproved
		}
	}
	return res, st, failed
}

// workDirKeys returns the project keys to look up for workDir: the cleaned
// workDir, then its cleaned real path from filepath.EvalSymlinks when that
// is another path. An empty workDir gives no key. An error of EvalSymlinks
// (for example a directory that does not exist) only drops the second key.
func workDirKeys(workDir string) []string {
	exact := cleanDir(workDir)
	if exact == "" {
		return nil
	}
	keys := []string{exact}
	resolved, err := filepath.EvalSymlinks(exact)
	if err != nil {
		return keys
	}
	if resolved = cleanDir(resolved); resolved != "" && resolved != exact {
		keys = append(keys, resolved)
	}
	return keys
}

// projectStateFor joins the states of the projects.<key> objects of states
// for keys, in order of precedence (the exact key first, see workDirKeys).
//
//   - disabledMcp and disabledMcpjson are the union of the lists of every key
//     in the file. A union can only turn more servers off, so it fails
//     closed.
//   - enabledMcpjson and enableAll come from the first key in the file only.
//     They are never merged, so a second key cannot add an approval.
//
// bad is true when a key is in the file (in states.seen) but its state could
// not be read. A key that is not in the file gives nothing and is not bad.
// The result shares no set with states.
func projectStateFor(states *claudeStates, keys []string) (st claudeProjectState, bad bool) {
	var first bool
	for _, key := range keys {
		// A read from a nil map gives the zero value and false, so a file
		// with no projects gives a zero state.
		s, found := states.byProject[key]
		if !found {
			bad = bad || states.seen.has(key)
			continue
		}
		if !first {
			first = true
			st.enabledMcpjson = unionNames(nil, s.enabledMcpjson)
			st.enableAll = s.enableAll
		}
		st.disabledMcp = unionNames(st.disabledMcp, s.disabledMcp)
		st.disabledMcpjson = unionNames(st.disabledMcpjson, s.disabledMcpjson)
	}
	return st, bad
}

// unionNames returns a set with the names of dst and of src. It adds to dst
// when dst is not nil, else it makes a new set. It returns dst unchanged
// when src is empty, so two nil sets give nil.
func unionNames(dst, src nameSet) nameSet {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(nameSet, len(src))
	}
	for name := range src {
		dst[name] = struct{}{}
	}
	return dst
}
