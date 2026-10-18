package discover

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// claudeCodeCase describes the expected result of reading one fixture. The want
// functions get the copied file paths, because Source and Path hold them.
type claudeCodeCase struct {
	name string
	// hideValues is set for fixtures that hold canaries. On a mismatch the test
	// then prints no server data, only a fixed message.
	hideValues bool
	// canaryFiles are the fixture files, relative to the fixture directory,
	// that must hold every canary. The leak checks only mean something if the
	// input holds the canaries.
	canaryFiles []string

	homeServers func(source string) []serverView
	workServers func(source, work string) []serverView
	homeErrs    []errWant
	workErrs    []errWant
}

// claudeStdioView builds the want value of a stdio server of Claude Code.
func claudeStdioView(name string, scope Scope, projectPath, source, command string, args []string) serverView {
	return serverView{
		Name:        name,
		Client:      ClientClaudeCode,
		Scope:       scope,
		ProjectPath: projectPath,
		Source:      source,
		Transport:   TransportStdio,
		Command:     command,
		Args:        args,
	}
}

// claudeRemoteView builds the want value of an http or sse server of Claude Code.
func claudeRemoteView(name string, scope Scope, projectPath, source string, transport Transport, url string) serverView {
	return serverView{
		Name:        name,
		Client:      ClientClaudeCode,
		Scope:       scope,
		ProjectPath: projectPath,
		Source:      source,
		Transport:   transport,
		URL:         url,
	}
}

// claudeCodeCases returns one case for each fixture directory under
// testdata/discover/claude-code. Each call returns a new slice.
func claudeCodeCases() []claudeCodeCase {
	return []claudeCodeCase{
		{
			name: "valid",
			homeServers: func(src string) []serverView {
				// Order is (ProjectPath, Name): global servers first.
				return []serverView{
					claudeStdioView("filesystem", ScopeGlobal, "", src, "npx",
						[]string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"}),
					claudeRemoteView("remote-http", ScopeGlobal, "", src, TransportHTTP, "https://mcp.example.com/mcp"),
					claudeRemoteView("remote-sse", ScopeGlobal, "", src, TransportSSE, "https://sse.example.com/sse"),
					claudeStdioView("alpha-tool", ScopeProject, "/work/alpha", src, "node", []string{"alpha-server.js"}),
					// "type" is missing here: a command means stdio.
					claudeStdioView("gamma-tool", ScopeProject, "/work/gamma", src, "python3", []string{"-m", "gamma_server"}),
				}
			},
			workServers: func(src, work string) []serverView {
				return []serverView{
					claudeStdioView("local-db", ScopeProject, work, src, "uvx",
						[]string{"mcp-server-sqlite", "--db-path", "./data.db"}),
					claudeRemoteView("team-api", ScopeProject, work, src, TransportHTTP, "https://team.example.com/mcp"),
				}
			},
		},
		{
			name:        "secrets",
			hideValues:  true,
			canaryFiles: []string{"home/.claude.json", "work/.mcp.json"},
			homeServers: func(src string) []serverView {
				return []serverView{
					{
						Name: "with-env", Client: ClientClaudeCode, Scope: ScopeGlobal, Source: src,
						Transport: TransportStdio, Command: "npx", Args: []string{"-y", "example-server", "--token", discovertest.CanaryArgs},
						Env: map[string]string{"API_KEY": discovertest.CanaryEnv},
					},
					{
						Name: "with-headers", Client: ClientClaudeCode, Scope: ScopeGlobal, Source: src,
						Transport: TransportHTTP, URL: "https://mcp.example.com/mcp",
						Headers: map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader},
					},
					{
						Name: "with-url-secret", Client: ClientClaudeCode, Scope: ScopeGlobal, Source: src,
						Transport: TransportHTTP,
						URL: "https://user:" + discovertest.CanaryURL + "@mcp.example.com/mcp?key=" +
							discovertest.CanaryURL,
					},
					{
						Name: "project-with-env", Client: ClientClaudeCode, Scope: ScopeProject,
						ProjectPath: "/work/secret-project", Source: src,
						Transport: TransportStdio, Command: "node", Args: []string{"server.js"},
						Env: map[string]string{"API_KEY": discovertest.CanaryEnv},
					},
				}
			},
			workServers: func(src, work string) []serverView {
				return []serverView{
					{
						Name: "work-env", Client: ClientClaudeCode, Scope: ScopeProject, ProjectPath: work, Source: src,
						Transport: TransportStdio, Command: "node", Args: []string{"server.js"},
						Env: map[string]string{"API_KEY": discovertest.CanaryEnv},
					},
					{
						Name: "work-headers", Client: ClientClaudeCode, Scope: ScopeProject, ProjectPath: work, Source: src,
						Transport: TransportSSE, URL: "https://sse.example.com/sse",
						Headers: map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader},
					},
				}
			},
		},
		{
			// Home file is "{}", work file has 0 bytes.
			name:        "empty",
			homeServers: func(string) []serverView { return nil },
			workServers: func(string, string) []serverView { return nil },
		},
		{
			// The canary comes right after the bad spot in both files.
			name:        "malformed",
			hideValues:  true,
			homeServers: func(string) []serverView { return nil },
			workServers: func(string, string) []serverView { return nil },
			homeErrs:    []errWant{{Reason: reasonInvalidJSON, Line: 3}},
			workErrs:    []errWant{{Reason: reasonInvalidJSON, Line: 3}},
		},
		{
			name: "invalid-entries",
			homeServers: func(src string) []serverView {
				return []serverView{
					claudeStdioView("good", ScopeGlobal, "", src, "npx", []string{"-y", "example-server"}),
				}
			},
			workServers: func(string, string) []serverView { return nil },
			// Errors are sorted by server name.
			homeErrs: []errWant{
				{Server: "empty", Reason: reasonNoCommandOrURL},
				{Server: "http-no-url", Reason: reasonRemoteNoURL},
				{Server: "num-env", Reason: reasonBadEntry},
				{Server: "stdio-no-cmd", Reason: reasonStdioNoCommand},
				{Server: "unknown-type", Reason: reasonUnknownTransport},
			},
		},
		{
			// The fixture has no files: both directories are empty.
			name:        "missing",
			homeServers: func(string) []serverView { return nil },
			workServers: func(string, string) []serverView { return nil },
		},
	}
}

func TestReadClaudeCode(t *testing.T) {
	t.Parallel()
	for _, tc := range claudeCodeCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			home, work := copyFixture(t, "claude-code", tc.name)
			homePath := filepath.Join(home, ".claude.json")
			workPath := filepath.Join(work, ".mcp.json")

			// A leak test only means something if the fixture holds the canaries.
			if len(tc.canaryFiles) > 0 {
				repo := fixtureDir(t, "claude-code", tc.name)
				var paths []string
				for _, f := range tc.canaryFiles {
					paths = append(paths, filepath.Join(repo, filepath.FromSlash(f)))
				}
				assertFixtureHasCanaries(t, paths...)
			}

			r1 := ReadClaudeCode(ctx, homePath, ScopeGlobal, "")
			r2 := ReadClaudeCode(ctx, workPath, ScopeProject, work)

			checkServers(t, "~/.claude.json", r1.Servers, tc.homeServers(homePath), tc.hideValues)
			checkServers(t, ".mcp.json", r2.Servers, tc.workServers(workPath, work), tc.hideValues)
			checkFileErrors(t, homePath, r1.Errors, tc.homeErrs)
			checkFileErrors(t, workPath, r2.Errors, tc.workErrs)

			// No result may hold a canary, in any form.
			for _, r := range []Result{r1, r2} {
				assertNoLeakServers(t, r.Servers)
				assertNoLeakErrors(t, r.Errors)
			}
		})
	}
}

// TestReadClaudeCodeCanaryMasking checks that the canaries are really read
// (the values are in the servers) and that the display forms hide them.
func TestReadClaudeCodeCanaryMasking(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "secrets")
	r := ReadClaudeCode(t.Context(), filepath.Join(home, ".claude.json"), ScopeGlobal, "")
	if len(r.Errors) != 0 {
		t.Fatalf("errors = %v, want none", r.Errors)
	}

	var found bool
	for _, s := range r.Servers {
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
		t.Fatalf("server with-url-secret not found; got %v", serverNames(r.Servers))
	}

	// The keys of env and headers are kept, the values stay masked.
	for _, s := range r.Servers {
		for _, key := range s.Env.Keys() {
			if s.Env[key].String() == s.Env[key].Reveal() {
				t.Errorf("server %q env key %q: String() shows the value", s.Name, key)
			}
		}
	}
}

// TestReadClaudeCodeProjectPath checks that a top-level server of a global
// file gets the projectPath of the call, while servers under "projects" keep
// their own key.
func TestReadClaudeCodeProjectPath(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "valid")
	path := filepath.Join(home, ".claude.json")

	r := ReadClaudeCode(t.Context(), path, ScopeGlobal, "/custom/dir")
	if len(r.Errors) != 0 {
		t.Fatalf("errors = %v, want none", r.Errors)
	}
	want := []struct {
		name, project string
		scope         Scope
	}{
		// Sorted by (ProjectPath, Name): "/custom/dir" < "/work/alpha" < "/work/gamma".
		{"filesystem", "/custom/dir", ScopeGlobal},
		{"remote-http", "/custom/dir", ScopeGlobal},
		{"remote-sse", "/custom/dir", ScopeGlobal},
		{"alpha-tool", "/work/alpha", ScopeProject},
		{"gamma-tool", "/work/gamma", ScopeProject},
	}
	if len(r.Servers) != len(want) {
		t.Fatalf("got servers %v, want %d servers", serverNames(r.Servers), len(want))
	}
	for i, w := range want {
		s := r.Servers[i]
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
		// Sorted by (ProjectPath, Name): "/attacker/chosen" < "/real/project".
		{name: "global file reads projects", scope: ScopeGlobal, want: []string{"spoofed", "top"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), "config.json", []byte(content))

			r := ReadClaudeCode(t.Context(), path, tt.scope, "/real/project")
			if len(r.Errors) != 0 {
				t.Fatalf("errors = %v, want none", r.Errors)
			}
			if got := serverNames(r.Servers); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("servers = %v, want %v", got, tt.want)
			}
			for _, s := range r.Servers {
				if tt.scope == ScopeProject && s.ProjectPath != "/real/project" {
					t.Errorf("server %q ProjectPath = %q, want %q", s.Name, s.ProjectPath, "/real/project")
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
	r := ReadClaudeCode(t.Context(), path, ScopeGlobal, "")
	if len(r.Errors) == 0 {
		t.Fatal("errors = none, want entry errors")
	}

	var joined []error
	for _, e := range r.Errors {
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

	for _, e := range r.Errors {
		msg := e.Error()
		wantPrefix := path + ": server " + e.Server + ": " + e.Reason
		if msg != wantPrefix {
			t.Errorf("Error() = %q, want %q", msg, wantPrefix)
		}
		if e.Server == "unknown-type" && strings.Contains(msg, "websocket") {
			t.Errorf("Error() = %q, must not echo the transport type", msg)
		}
	}
}

// TestReadClaudeCodeMalformedMessage checks the text of a syntax error: it has
// the path and the position and no config text.
func TestReadClaudeCodeMalformedMessage(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "malformed")
	path := filepath.Join(home, ".claude.json")
	r := ReadClaudeCode(t.Context(), path, ScopeGlobal, "")
	if len(r.Errors) != 1 {
		t.Fatalf("got %d errors, want 1", len(r.Errors))
	}
	msg := r.Errors[0].Error()
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
	r := ReadClaudeCode(t.Context(), filepath.Join(dir, "no", "such", ".claude.json"), ScopeGlobal, "")
	if len(r.Servers) != 0 || len(r.Errors) != 0 {
		t.Errorf("Result = %d servers, %v errors; want empty", len(r.Servers), r.Errors)
	}
}

// TestReadClaudeCodeCanceled checks that a canceled context gives an error
// that wraps context.Canceled.
func TestReadClaudeCodeCanceled(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "valid")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r := ReadClaudeCode(ctx, filepath.Join(home, ".claude.json"), ScopeGlobal, "")
	if len(r.Servers) != 0 {
		t.Errorf("servers = %v, want none", serverNames(r.Servers))
	}
	if len(r.Errors) != 1 {
		t.Fatalf("got %d errors, want 1", len(r.Errors))
	}
	if !errors.Is(r.Errors[0], context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false for %v", r.Errors[0])
	}
	var pe *fs.PathError
	if errors.As(r.Errors[0], &pe) {
		t.Errorf("canceled error wraps a PathError: %v", pe)
	}
}
