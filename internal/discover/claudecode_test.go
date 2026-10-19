package discover

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

func TestReadClaudeCode(t *testing.T) {
	t.Parallel()

	files := jsonFixtureFiles{client: ClientClaudeCode, fixture: "claude-code", home: ".claude.json", work: ".mcp.json"}
	runJSONFixtureCases(t, files, ReadClaudeCode, []jsonFixtureCase{
		{
			name: "valid",
			// Order is (ProjectPath, Name): global servers first. The servers
			// with a ProjectPath come from projects.<path> of ~/.claude.json.
			home: []serverView{
				{Name: "filesystem", Transport: TransportStdio, Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"}},
				{Name: "remote-http", Transport: TransportHTTP, URL: "https://mcp.example.com/mcp"},
				{Name: "remote-sse", Transport: TransportSSE, URL: "https://sse.example.com/sse"},
				{Name: "alpha-tool", ProjectPath: "/work/alpha", Transport: TransportStdio, Command: "node", Args: []string{"alpha-server.js"}},
				// "type" is missing here: a command means stdio.
				{Name: "gamma-tool", ProjectPath: "/work/gamma", Transport: TransportStdio, Command: "python3", Args: []string{"-m", "gamma_server"}},
			},
			work: []serverView{
				{Name: "local-db", Transport: TransportStdio, Command: "uvx", Args: []string{"mcp-server-sqlite", "--db-path", "./data.db"}},
				{Name: "team-api", Transport: TransportHTTP, URL: "https://team.example.com/mcp"},
			},
		},
		{
			name:        "secrets",
			hideValues:  true,
			canaryFiles: []string{"home/.claude.json", "work/.mcp.json"},
			home: []serverView{
				{
					Name: "with-env", Transport: TransportStdio, Command: "npx",
					Args: []string{"-y", "example-server", "--token", discovertest.CanaryArgs},
					Env:  map[string]string{"API_KEY": discovertest.CanaryEnv},
				},
				{
					Name: "with-headers", Transport: TransportHTTP, URL: "https://mcp.example.com/mcp",
					Headers: map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader},
				},
				{
					Name: "with-url-secret", Transport: TransportHTTP,
					URL: "https://user:" + discovertest.CanaryURL + "@mcp.example.com/mcp?key=" + discovertest.CanaryURL,
				},
				{
					Name: "project-with-env", ProjectPath: "/work/secret-project",
					Transport: TransportStdio, Command: "node", Args: []string{"server.js"},
					Env: map[string]string{"API_KEY": discovertest.CanaryEnv},
				},
			},
			work: []serverView{
				{
					Name: "work-env", Transport: TransportStdio, Command: "node", Args: []string{"server.js"},
					Env: map[string]string{"API_KEY": discovertest.CanaryEnv},
				},
				{
					Name: "work-headers", Transport: TransportSSE, URL: "https://sse.example.com/sse",
					Headers: map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader},
				},
			},
		},
		// Home file is "{}", work file has 0 bytes.
		{name: "empty"},
		{
			// The canary comes right after the bad spot in both files.
			name:       "malformed",
			hideValues: true,
			homeErrs:   []errWant{{Reason: reasonInvalidJSON, Line: 3}},
			workErrs:   []errWant{{Reason: reasonInvalidJSON, Line: 3}},
		},
		{
			name: "invalid-entries",
			home: []serverView{
				{Name: "good", Transport: TransportStdio, Command: "npx", Args: []string{"-y", "example-server"}},
			},
			// Errors are sorted by server name.
			homeErrs: []errWant{
				{Server: "empty", Reason: reasonNoCommandOrURL},
				{Server: "http-no-url", Reason: reasonRemoteNoURL},
				{Server: "num-env", Reason: reasonBadEntry},
				{Server: "stdio-no-cmd", Reason: reasonStdioNoCommand},
				{Server: "unknown-type", Reason: reasonUnknownTransport},
			},
		},
		// The fixture has no files: both directories are empty.
		{name: "missing"},
	})
}

// TestReadClaudeCodeCanaryMasking checks that the canaries are really read
// (the values are in the servers) and that the display forms hide them.
func TestReadClaudeCodeCanaryMasking(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "secrets")
	res := ReadClaudeCode(t.Context(), filepath.Join(home, ".claude.json"), ScopeGlobal, "")
	if len(res.Errors) != 0 {
		t.Fatalf("errors = %v, want none", res.Errors)
	}

	var found bool
	for _, s := range res.Servers {
		if s.Name != "with-url-secret" {
			continue
		}
		found = true
		display := RedactURL(s.URL.Reveal())
		if !strings.Contains(display, Mask) {
			t.Errorf("RedactURL() = %q, want it to contain %q", display, Mask)
		}
		if !strings.Contains(display, "mcp.example.com") {
			t.Errorf("RedactURL() = %q, want the host to stay", display)
		}
		if display != s.URL.String() {
			t.Errorf("RedactURL() = %q differs from URL.String() = %q", display, s.URL.String())
		}
		if len(discovertest.Leaks(display)) > 0 {
			t.Errorf("RedactURL() output holds a canary")
		}
	}
	if !found {
		t.Fatalf("server with-url-secret not found; got %v", serverNames(res.Servers))
	}

	// The keys of env and headers are kept, the values stay masked.
	var envKeys, headerKeys int
	for _, s := range res.Servers {
		for _, key := range s.Env.Keys() {
			envKeys++
			if s.Env[key].String() == s.Env[key].Reveal() {
				t.Errorf("server %q env key %q: String() shows the value", s.Name, key)
			}
		}
		for _, key := range s.Headers.Keys() {
			headerKeys++
			if s.Headers[key].String() == s.Headers[key].Reveal() {
				t.Errorf("server %q header key %q: String() shows the value", s.Name, key)
			}
		}
	}
	// The fixture has env and headers values, so both loops must run.
	if envKeys == 0 || headerKeys == 0 {
		t.Errorf("checked %d env keys and %d header keys, want both above 0", envKeys, headerKeys)
	}
}

// TestReadClaudeCodeProjectPath checks that a global file ignores the
// projectPath of the call: its top-level servers have no ProjectPath, and
// servers under "projects" keep their own key.
func TestReadClaudeCodeProjectPath(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "valid")
	path := filepath.Join(home, ".claude.json")

	res := ReadClaudeCode(t.Context(), path, ScopeGlobal, "/custom/dir")
	if len(res.Errors) != 0 {
		t.Fatalf("errors = %v, want none", res.Errors)
	}
	want := []struct {
		name, project string
		scope         Scope
	}{
		// Sorted by (ProjectPath, Name): "" < "/work/alpha" < "/work/gamma".
		{"filesystem", "", ScopeGlobal},
		{"remote-http", "", ScopeGlobal},
		{"remote-sse", "", ScopeGlobal},
		{"alpha-tool", "/work/alpha", ScopeProject},
		{"gamma-tool", "/work/gamma", ScopeProject},
	}
	if len(res.Servers) != len(want) {
		t.Fatalf("got servers %v, want %d servers", serverNames(res.Servers), len(want))
	}
	for i, w := range want {
		s := res.Servers[i]
		if s.Name != w.name || s.ProjectPath != w.project || s.Scope != w.scope {
			t.Errorf("servers[%d] = {%q %q %q}, want {%q %q %q}",
				i, s.Name, s.ProjectPath, s.Scope, w.name, w.project, w.scope)
		}
	}
}

// TestReadClaudeCodeProjectsKeyByScope checks that "projects" is read only from
// a global file. A project .mcp.json is untrusted, so its "projects" key must
// not create servers with a ProjectPath that the file chose.
func TestReadClaudeCodeProjectsKeyByScope(t *testing.T) {
	t.Parallel()

	const content = `{
		"mcpServers": {"top": {"command": "t"}},
		"projects": {
			"/attacker/chosen": {"mcpServers": {"spoofed": {"command": "x"}}}
		}
	}`

	tests := []struct {
		name  string
		scope Scope
		want  []string
	}{
		{name: "project file ignores projects", scope: ScopeProject, want: []string{"top"}},
		// Sorted by (ProjectPath, Name): a global file ignores projectPath,
		// so "top" has ProjectPath "", and "" < "/attacker/chosen".
		{name: "global file reads projects", scope: ScopeGlobal, want: []string{"top", "spoofed"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// A project file must be below its projectPath.
			dir := t.TempDir()
			path := writeFile(t, dir, ".mcp.json", []byte(content))

			res := ReadClaudeCode(t.Context(), path, tt.scope, dir)
			if len(res.Errors) != 0 {
				t.Fatalf("errors = %v, want none", res.Errors)
			}
			if got := serverNames(res.Servers); !slices.Equal(got, tt.want) {
				t.Fatalf("servers = %v, want %v", got, tt.want)
			}
			for _, s := range res.Servers {
				if tt.scope == ScopeProject && s.ProjectPath != dir {
					t.Errorf("server %q ProjectPath = %q, want %q", s.Name, s.ProjectPath, dir)
				}
			}
		})
	}
}

// TestReadClaudeCodeErrorsAs checks that the Result errors work with errors.As
// and that the messages hold the path, the position and the server name.
func TestReadClaudeCodeErrorsAs(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "invalid-entries")
	path := filepath.Join(home, ".claude.json")
	res := ReadClaudeCode(t.Context(), path, ScopeGlobal, "")
	if len(res.Errors) == 0 {
		t.Fatal("errors = none, want entry errors")
	}

	var joined []error
	for _, e := range res.Errors {
		joined = append(joined, e)
	}
	err := errors.Join(joined...)
	var fe *FileError
	if !errors.As(err, &fe) {
		t.Fatalf("errors.As(%T, *FileError) = false, want true", err)
	}
	if fe.Server != "empty" {
		t.Errorf("first FileError.Server = %q, want %q", fe.Server, "empty")
	}

	for _, e := range res.Errors {
		msg := e.Error()
		// The exact compare also shows that the message does not echo a
		// config value, for example the unknown transport type.
		want := path + ": server " + e.Server + ": " + e.Reason
		if msg != want {
			t.Errorf("Error() = %q, want %q", msg, want)
		}
	}
}

// TestReadClaudeCodeMalformedMessage checks the text of a syntax error: it has
// the path and the position and no config text.
func TestReadClaudeCodeMalformedMessage(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "malformed")
	path := filepath.Join(home, ".claude.json")
	res := ReadClaudeCode(t.Context(), path, ScopeGlobal, "")
	if len(res.Errors) != 1 {
		t.Fatalf("got %d errors, want 1", len(res.Errors))
	}
	msg := res.Errors[0].Error()
	if !strings.HasPrefix(msg, path+":3:") {
		t.Errorf("Error() = %q, want prefix %q", msg, path+":3:")
	}
	if !strings.HasSuffix(msg, ": "+reasonInvalidJSON) {
		t.Errorf("Error() = %q, want suffix %q", msg, ": "+reasonInvalidJSON)
	}
	if len(discovertest.Leaks(msg)) > 0 {
		t.Errorf("Error() holds a canary")
	}
}

// TestReadClaudeCodeMissingPath checks that a path that does not exist
// gives an empty Result and not an error.
func TestReadClaudeCodeMissingPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	res := ReadClaudeCode(t.Context(), filepath.Join(dir, "no", "such", ".claude.json"), ScopeGlobal, "")
	if len(res.Servers) != 0 || len(res.Errors) != 0 {
		t.Errorf("Result = %d servers, %v errors; want empty", len(res.Servers), res.Errors)
	}
}

// TestReadClaudeCodeCanceled checks that a canceled context gives an error
// that wraps context.Canceled.
func TestReadClaudeCodeCanceled(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "valid")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	res := ReadClaudeCode(ctx, filepath.Join(home, ".claude.json"), ScopeGlobal, "")
	if len(res.Servers) != 0 {
		t.Errorf("servers = %v, want none", serverNames(res.Servers))
	}
	if len(res.Errors) != 1 {
		t.Fatalf("got %d errors, want 1", len(res.Errors))
	}
	if !errors.Is(res.Errors[0], context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false for %v", res.Errors[0])
	}
	var pe *fs.PathError
	if errors.As(res.Errors[0], &pe) {
		t.Errorf("canceled error wraps a PathError: %v", pe)
	}
}

// stateGlobalFile is a ~/.claude.json for the state tests. The top-level
// servers are top-a and top-b. The project /work/proj turns off top-a (a
// top-level server) and its own p-srv. The project /work/other turns off
// top-b, and has a server called top-a of its own that no list turns off.
const stateGlobalFile = `{
	"mcpServers": {"top-a": {"command": "a"}, "top-b": {"command": "b"}},
	"projects": {
		"/work/proj": {
			"mcpServers": {"p-srv": {"command": "p"}, "p-keep": {"command": "p"}},
			"disabledMcpServers": ["top-a", "p-srv"],
			"enabledMcpjsonServers": ["m-on"],
			"disabledMcpjsonServers": ["m-off"],
			"enableAllProjectMcpServers": false
		},
		"/work/other": {
			"mcpServers": {"top-a": {"command": "o"}},
			"disabledMcpServers": ["top-b"]
		}
	}
}`

// TestReadClaudeCodeState checks the State of the servers of a standalone
// ReadClaudeCode. In ~/.claude.json, each projects.<path> list turns off the
// servers of its own project only; the top-level servers stay enabled,
// because ReadClaudeCode knows no project directory. A project .mcp.json has
// no approval data, so its servers stay StateEnabled, also when settings files
// next to it reject them or do not approve them.
func TestReadClaudeCodeState(t *testing.T) {
	t.Parallel()

	t.Run("global file", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, t.TempDir(), ".claude.json", []byte(stateGlobalFile))

		// The projectPath argument of a global file is ignored, also when
		// it names a project with a list.
		for _, projectPath := range []string{"", "/work/proj", "/work/other"} {
			res := ReadClaudeCode(t.Context(), path, ScopeGlobal, projectPath)

			checkFileErrors(t, path, res.Errors, nil)
			checkProjectStates(t, res.Servers, map[projectServer]State{
				{"", "top-a"}:            StateEnabled,
				{"", "top-b"}:            StateEnabled,
				{"/work/proj", "p-srv"}:  StateDisabled,
				{"/work/proj", "p-keep"}: StateEnabled,
				{"/work/other", "top-a"}: StateEnabled,
			})
		}
	})

	t.Run("standalone .mcp.json", func(t *testing.T) {
		t.Parallel()
		// The fixture has settings files that approve approved-srv and
		// repo-srv and reject rejected-srv. ReadClaudeCode does not read
		// them, so every server fails closed to StateUnapproved.
		_, work := copyFixture(t, "claude-code", "state")
		path := filepath.Join(work, ".mcp.json")

		res := ReadClaudeCode(t.Context(), path, ScopeProject, work)

		checkFileErrors(t, path, res.Errors, nil)
		if got, want := serverNames(res.Servers), []string{"approved-srv", "pending-srv", "rejected-srv", "repo-srv"}; !slices.Equal(got, want) {
			t.Fatalf("servers = %v, want %v", got, want)
		}
		checkStates(t, res.Servers, map[string]State{
			"approved-srv": StateUnapproved,
			"pending-srv":  StateUnapproved,
			"rejected-srv": StateUnapproved,
			"repo-srv":     StateUnapproved,
		})
	})

	t.Run(".mcp.json state keys ignored", func(t *testing.T) {
		t.Parallel()
		// A project file is untrusted: its own state keys, at the top level
		// or under projects, must not change a State. With no approval
		// read, the server is StateUnapproved.
		work := t.TempDir()
		path := writeFile(t, work, ".mcp.json", []byte(`{
			"mcpServers": {"x": {"command": "x"}},
			"disabledMcpServers": ["x"],
			"disabledMcpjsonServers": ["x"],
			"projects": {"`+filepath.ToSlash(work)+`": {"disabledMcpServers": ["x"]}}
		}`))

		res := ReadClaudeCode(t.Context(), path, ScopeProject, work)

		checkFileErrors(t, path, res.Errors, nil)
		if got := serverNames(res.Servers); !slices.Equal(got, []string{"x"}) {
			t.Fatalf("servers = %v, want [x]", got)
		}
		checkStates(t, res.Servers, map[string]State{"x": StateUnapproved})
	})
}

// TestReadGlobalClaudeCodeState checks that readGlobalClaudeCodeState applies
// the disabledMcpServers list of projects.<workDir> to the top-level servers
// only, matches workDir after cleaning, and returns the state of that project.
func TestReadGlobalClaudeCodeState(t *testing.T) {
	t.Parallel()
	no := false
	projState := claudeProjectState{
		enabledMcpjson:  nameSet{"m-on": {}},
		disabledMcpjson: nameSet{"m-off": {}},
		disabledMcp:     nameSet{"top-a": {}, "p-srv": {}},
		enableAll:       &no,
	}
	otherState := claudeProjectState{disabledMcp: nameSet{"top-b": {}}}
	// The project servers always have the state of their own project, for
	// every workDir.
	projectServers := map[projectServer]State{
		{"/work/proj", "p-srv"}:  StateDisabled,
		{"/work/proj", "p-keep"}: StateEnabled,
		{"/work/other", "top-a"}: StateEnabled,
	}

	tests := []struct {
		name      string
		workDir   string
		wantTopA  State
		wantTopB  State
		wantState claudeProjectState
	}{
		{name: "exact", workDir: "/work/proj", wantTopA: StateDisabled, wantState: projState},
		{name: "trailing slash", workDir: "/work/proj/", wantTopA: StateDisabled, wantState: projState},
		{name: "dot parts", workDir: "/work/./proj/.", wantTopA: StateDisabled, wantState: projState},
		{name: "dot dot part", workDir: "/work/other/../proj", wantTopA: StateDisabled, wantState: projState},
		{name: "double slash", workDir: "/work//proj", wantTopA: StateDisabled, wantState: projState},
		{name: "other project", workDir: "/work/other", wantTopB: StateDisabled, wantState: otherState},
		{name: "empty workDir", workDir: ""},
		{name: "no such project", workDir: "/work/none"},
		{name: "parent of a project", workDir: "/work"},
		{name: "child of a project", workDir: "/work/proj/sub"},
		// The match is exact. Another letter case is another key (a known
		// limit on case-insensitive file systems).
		{name: "other letter case", workDir: "/work/Proj"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), ".claude.json", []byte(stateGlobalFile))

			res, st, failed := readGlobalClaudeCodeState(t.Context(), path, tt.workDir)

			checkFileErrors(t, path, res.Errors, nil)
			if failed {
				t.Error("failed = true, want false for a file with no error")
			}
			want := map[projectServer]State{
				{"", "top-a"}: tt.wantTopA,
				{"", "top-b"}: tt.wantTopB,
			}
			for k, v := range projectServers {
				want[k] = v
			}
			checkProjectStates(t, res.Servers, want)
			if !reflect.DeepEqual(st, tt.wantState) {
				t.Errorf("state =\n got  %+v\n want %+v", st, tt.wantState)
			}
		})
	}
}

// TestReadGlobalClaudeCodeStateSameAsReadClaudeCode checks that
// readGlobalClaudeCodeState gives the servers and errors of ReadClaudeCode
// with ScopeGlobal, except for the State of the top-level servers.
func TestReadGlobalClaudeCodeStateSameAsReadClaudeCode(t *testing.T) {
	t.Parallel()
	path := writeFile(t, t.TempDir(), ".claude.json", []byte(`{
		"mcpServers": {"top-a": {"command": "a"}, "bad": {"type": "nope"}},
		"projects": {"/work/proj": {"mcpServers": {"p": {"command": "p"}}, "disabledMcpServers": ["top-a", "p"]}}
	}`))

	// failed stays false: the error is in a server entry, not in the
	// projects section.
	got, _, failed := readGlobalClaudeCodeState(t.Context(), path, "/work/proj")
	if failed {
		t.Error("failed = true, want false for an error in a server entry")
	}
	want := ReadClaudeCode(t.Context(), path, ScopeGlobal, "")

	checkFileErrors(t, path, got.Errors, []errWant{{Server: "bad", Reason: reasonUnknownTransport}})
	if !reflect.DeepEqual(got.Errors, want.Errors) {
		t.Errorf("errors = %v, want %v", got.Errors, want.Errors)
	}
	if len(got.Servers) != len(want.Servers) {
		t.Fatalf("servers = %v, want %v", serverNames(got.Servers), serverNames(want.Servers))
	}
	for i := range want.Servers {
		g, w := got.Servers[i], want.Servers[i]
		if w.Scope == ScopeGlobal && w.Name == "top-a" {
			if w.State != StateEnabled || g.State != StateDisabled {
				t.Errorf("top-a State: ReadClaudeCode %v, readGlobalClaudeCodeState %v, want enabled and disabled", w.State, g.State)
			}
			g.State = w.State
		}
		if !reflect.DeepEqual(viewOf(g), viewOf(w)) || g.State != w.State {
			t.Errorf("servers[%d] = %+v (%v), want %+v (%v)", i, viewOf(g), g.State, viewOf(w), w.State)
		}
	}
}

// TestReadGlobalClaudeCodeStateSymlink checks a workDir given through a
// symlink. Claude Code writes the projects.<path> key with the real path, so
// readGlobalClaudeCodeState also looks up the key of the resolved workDir. The
// disabled lists of the two keys are joined. The approval (the enabled list
// and enableAllProjectMcpServers) comes from the exact key when it is in the
// file, else from the resolved key, and is never joined.
func TestReadGlobalClaudeCodeStateSymlink(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)
	yes, no := true, false

	tests := []struct {
		name string
		// linkKey and realKey are the projects objects under the symlink
		// path (the exact workDir) and under the real path. nil leaves the
		// key out of the file.
		linkKey, realKey any
		// gone adds a part that does not exist to workDir and to both keys,
		// so filepath.EvalSymlinks fails.
		gone bool
		// badReal tells that the real key has a bad state.
		badReal    bool
		wantTop    map[string]State
		wantState  claudeProjectState
		wantFailed bool
	}{
		{
			name: "real key only",
			realKey: map[string]any{
				keyDisabledMcpServers:         []string{"top-a"},
				keyEnabledMcpjsonServers:      []string{"m-on"},
				keyEnableAllProjectMcpServers: true,
			},
			wantTop: map[string]State{"top-a": StateDisabled},
			wantState: claudeProjectState{
				disabledMcp:    nameSet{"top-a": {}},
				enabledMcpjson: nameSet{"m-on": {}},
				enableAll:      &yes,
			},
		},
		{
			name:      "link key only",
			linkKey:   map[string]any{keyDisabledMcpServers: []string{"top-b"}},
			wantTop:   map[string]State{"top-b": StateDisabled},
			wantState: claudeProjectState{disabledMcp: nameSet{"top-b": {}}},
		},
		{
			name: "both keys join the disabled lists",
			linkKey: map[string]any{
				keyDisabledMcpServers:     []string{"top-a"},
				keyDisabledMcpjsonServers: []string{"m-a"},
			},
			realKey: map[string]any{
				keyDisabledMcpServers:     []string{"top-b"},
				keyDisabledMcpjsonServers: []string{"m-b"},
			},
			wantTop: map[string]State{"top-a": StateDisabled, "top-b": StateDisabled},
			wantState: claudeProjectState{
				disabledMcp:     nameSet{"top-a": {}, "top-b": {}},
				disabledMcpjson: nameSet{"m-a": {}, "m-b": {}},
			},
		},
		{
			name: "approval only from the exact key",
			linkKey: map[string]any{
				keyEnabledMcpjsonServers:      []string{"m-link"},
				keyEnableAllProjectMcpServers: false,
			},
			realKey: map[string]any{
				keyEnabledMcpjsonServers:      []string{"m-real"},
				keyEnableAllProjectMcpServers: true,
				keyDisabledMcpServers:         []string{"top-c"},
			},
			wantTop: map[string]State{"top-c": StateDisabled},
			wantState: claudeProjectState{
				enabledMcpjson: nameSet{"m-link": {}},
				enableAll:      &no,
				disabledMcp:    nameSet{"top-c": {}},
			},
		},
		{
			// The exact key has no enableAllProjectMcpServers. The true value
			// of the real key must not fill the gap: that would add an
			// approval.
			name:      "no enable all from the real key when the exact key is there",
			linkKey:   map[string]any{keyEnabledMcpjsonServers: []string{"m-link"}},
			realKey:   map[string]any{keyEnableAllProjectMcpServers: true},
			wantState: claudeProjectState{enabledMcpjson: nameSet{"m-link": {}}},
		},
		{
			// A bad real key fails closed, also when the exact key is good.
			name:       "bad real key",
			linkKey:    map[string]any{keyDisabledMcpServers: []string{"top-a"}},
			realKey:    map[string]any{keyDisabledMcpServers: "top-b"},
			badReal:    true,
			wantTop:    map[string]State{"top-a": StateDisabled, "top-b": StateUnapproved, "top-c": StateUnapproved},
			wantState:  claudeProjectState{disabledMcp: nameSet{"top-a": {}}},
			wantFailed: true,
		},
		{
			// workDir does not exist, so it cannot be resolved: only the
			// exact key counts, and the real key does not match.
			name:    "workDir that does not exist",
			realKey: map[string]any{keyDisabledMcpServers: []string{"top-a"}},
			gone:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			realDir := makeDir(t, base, "real")
			link := symlinkTo(t, realDir, base, "link")
			// The key that Claude Code writes is the real path. On macOS
			// t.TempDir itself is below a symlink (/var to /private/var), so
			// resolve the whole path.
			realPath, err := filepath.EvalSymlinks(realDir)
			if err != nil {
				t.Fatalf("resolve %s: %v", realDir, err)
			}
			workDir := link
			if tt.gone {
				workDir = filepath.Join(link, "gone")
				realPath = filepath.Join(realPath, "gone")
			}

			projects := map[string]any{}
			if tt.linkKey != nil {
				projects[workDir] = tt.linkKey
			}
			if tt.realKey != nil {
				projects[realPath] = tt.realKey
			}
			data, err := json.Marshal(map[string]any{
				"mcpServers": map[string]any{
					"top-a": map[string]any{"command": "a"},
					"top-b": map[string]any{"command": "b"},
					"top-c": map[string]any{"command": "c"},
				},
				"projects": projects,
			})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			path := writeFile(t, t.TempDir(), ".claude.json", data)

			res, st, failed := readGlobalClaudeCodeState(t.Context(), path, workDir)

			var wantErrs []errWant
			if tt.badReal {
				wantErrs = []errWant{{ProjectPath: realPath, Reason: reasonBadServerState}}
			}
			checkFileErrors(t, path, res.Errors, wantErrs)
			if failed != tt.wantFailed {
				t.Errorf("failed = %v, want %v", failed, tt.wantFailed)
			}
			checkStates(t, res.Servers, tt.wantTop)
			if !reflect.DeepEqual(st, tt.wantState) {
				t.Errorf("state =\n got  %+v\n want %+v", st, tt.wantState)
			}
		})
	}
}

// TestReadGlobalClaudeCodeStateNoState checks the cases that give a zero
// state: a missing file, a file that is refused as a whole, a projects
// section that is not an object, a bad state or shape of the
// projects.<workDir> object, and a canceled context. Only the missing file is
// not a failure. All other cases return failed true and fail closed: a
// top-level server that is still in the result gets StateUnapproved. None of
// them panics.
func TestReadGlobalClaudeCodeStateNoState(t *testing.T) {
	t.Parallel()
	const work = "/work/proj"

	tests := []struct {
		name string
		// content is the file; "" means that the file is missing.
		content  string
		canceled bool
		// wantServers are the top-level servers, all StateUnapproved when
		// wantFailed is true.
		wantServers []string
		wantErrs    []errWant
		wantFailed  bool
	}{
		{name: "missing file"},
		{
			name:       "invalid JSON",
			content:    `{"projects": {"/work/proj": {"disabledMcpServers": ["top"]`,
			wantErrs:   []errWant{{Reason: reasonInvalidJSON, Line: 1}},
			wantFailed: true,
		},
		{
			name:       "not an object",
			content:    `[]`,
			wantErrs:   []errWant{{Reason: reasonBadShape}},
			wantFailed: true,
		},
		{
			name:     "projects not an object",
			content:  `{"mcpServers": {"top": {"command": "t"}}, "projects": []}`,
			wantErrs: []errWant{{Reason: reasonBadShape}},
			// A top-level server with no readable state becomes
			// unapproved, and the error makes the scan fail.
			wantServers: []string{"top"},
			wantFailed:  true,
		},
		{
			name: "bad state in the workDir project",
			content: `{"mcpServers": {"top": {"command": "t"}}, "projects": {
				"/work/proj": {"disabledMcpServers": "top", "enableAllProjectMcpServers": true}}}`,
			wantErrs:    []errWant{{ProjectPath: work, Reason: reasonBadServerState}},
			wantServers: []string{"top"},
			wantFailed:  true,
		},
		{
			name: "project not an object",
			content: `{"mcpServers": {"top": {"command": "t"}}, "projects": {
				"/work/proj": ["top"]}}`,
			wantErrs:    []errWant{{ProjectPath: work, Reason: reasonBadShape}},
			wantServers: []string{"top"},
			wantFailed:  true,
		},
		{
			// The bad string is in another project, but the file is
			// refused as a whole, so the state of the work project is lost.
			name: "bad string in another project",
			content: `{"mcpServers": {"top": {"command": "t"}}, "projects": {
				"/work/proj": {"disabledMcpServers": ["top"]},
				"/work/zzz": {"mcpServers": {"x": {"command": "\ud800"}}}}}`,
			wantErrs:   []errWant{{ProjectPath: "/work/zzz", Reason: reasonBadString, Line: 3}},
			wantFailed: true,
		},
		{
			name: "too many servers",
			content: `{"projects": {"/work/proj": {"disabledMcpServers": ["top"], "enableAllProjectMcpServers": true}, ` +
				manyEntries(`"/z%d": {}`, maxServersPerFile) + `}}`,
			wantErrs:   []errWant{{Reason: reasonTooManyServers}},
			wantFailed: true,
		},
		{
			name:       "canceled",
			content:    `{"mcpServers": {"top": {"command": "t"}}, "projects": {"/work/proj": {"disabledMcpServers": ["top"]}}}`,
			canceled:   true,
			wantErrs:   []errWant{{Reason: reasonCanceled, HasErr: true}},
			wantFailed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), ".claude.json")
			if tt.content != "" {
				writeFile(t, filepath.Dir(path), ".claude.json", []byte(tt.content))
			}
			ctx := t.Context()
			if tt.canceled {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}

			res, st, failed := readGlobalClaudeCodeState(ctx, path, work)

			checkFileErrors(t, path, res.Errors, tt.wantErrs)
			if failed != tt.wantFailed {
				t.Errorf("failed = %v, want %v", failed, tt.wantFailed)
			}
			if got := serverNames(res.Servers); !slices.Equal(got, tt.wantServers) {
				t.Errorf("servers = %v, want %v", got, tt.wantServers)
			}
			var wantStates map[string]State
			if tt.wantFailed {
				wantStates = map[string]State{}
				for _, name := range tt.wantServers {
					wantStates[name] = StateUnapproved
				}
			}
			checkStates(t, res.Servers, wantStates)
			if !reflect.DeepEqual(st, claudeProjectState{}) {
				t.Errorf("state = %+v, want the zero state", st)
			}
		})
	}
}
