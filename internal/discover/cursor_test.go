package discover

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

func TestReadCursor(t *testing.T) {
	t.Parallel()

	const (
		envKey    = "API_KEY"
		authKey   = "Authorization"
		cursorURL = "https://user:" + discovertest.CanaryURL + "@cursor.example.com/mcp?key=" + discovertest.CanaryURL
	)

	files := jsonFixtureFiles{client: ClientCursor, fixture: "cursor", home: ".cursor/mcp.json", work: ".cursor/mcp.json"}
	runJSONFixtureCases(t, files, ReadCursor, []jsonFixtureCase{
		{
			name: "valid",
			home: []serverView{
				{Name: "events", Transport: TransportSSE, URL: "https://sse.example.com/sse"},
				{Name: "git", Transport: TransportStdio, Command: "uvx", Args: []string{"mcp-server-git"}},
				{Name: "remote", Transport: TransportHTTP, URL: "https://cursor.example.com/mcp"},
			},
			work: []serverView{
				{Name: "project-remote", Transport: TransportHTTP, URL: "https://project.example.com/mcp"},
				{Name: "project-tools", Transport: TransportStdio, Command: "npx", Args: []string{"-y", "example-mcp-server"}},
			},
		},
		{
			name:        "secrets",
			hideValues:  true,
			canaryFiles: []string{"home/.cursor/mcp.json", "work/.cursor/mcp.json"},
			home: []serverView{
				{
					Name: "local-api", Transport: TransportStdio, Command: "uvx", Args: []string{"mcp-server-api", "--token", discovertest.CanaryArgs},
					Env: map[string]string{envKey: discovertest.CanaryEnv},
				},
				{
					Name: "remote-api", Transport: TransportHTTP, URL: cursorURL,
					Headers: map[string]string{authKey: "Bearer " + discovertest.CanaryHeader},
				},
			},
			work: []serverView{
				{
					Name: "project-local", Transport: TransportStdio, Command: "npx", Args: []string{"-y", "example-mcp-server"},
					Env: map[string]string{envKey: discovertest.CanaryEnv},
				},
				{
					Name: "project-remote", Transport: TransportHTTP, URL: "https://project.example.com/mcp",
					Headers: map[string]string{authKey: "Bearer " + discovertest.CanaryHeader},
				},
			},
		},
		{name: "empty"},
		{
			// The syntax error is on the line of "broken" in the home file
			// (line 3) and on the env line in the work file (line 5).
			name:       "malformed",
			hideValues: true,
			homeErrs:   []errWant{{Line: 3, Reason: reasonInvalidJSON}},
			workErrs:   []errWant{{Line: 5, Reason: reasonInvalidJSON}},
		},
		{
			name: "invalid-entries",
			home: []serverView{
				{Name: "good", Transport: TransportStdio, Command: "uvx", Args: []string{"mcp-server-git"}},
			},
			// Errors come sorted by server name.
			homeErrs: []errWant{
				{Server: "empty", Reason: reasonNoCommandOrURL},
				{Server: "num-env", Reason: reasonBadEntry},
				{Server: "sse-no-url", Reason: reasonRemoteNoURL},
				{Server: "unknown-type", Reason: reasonUnknownTransport},
			},
		},
		{name: "missing"},
	})
}

// TestReadCursorMalformedPosition checks that a syntax error also has a column,
// and that the message holds the position and the reason but no config text.
func TestReadCursorMalformedPosition(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "cursor", "malformed")
	path := filepath.Join(home, ".cursor", "mcp.json")

	res := ReadCursor(t.Context(), path, ScopeGlobal, "")
	if len(res.Errors) != 1 {
		t.Fatalf("len(Errors) = %d, want 1", len(res.Errors))
	}
	e := res.Errors[0]
	if e.Col <= 0 {
		t.Errorf("Col = %d, want a positive column", e.Col)
	}
	if e.Server != "" {
		t.Errorf("Server = %q, want empty for a whole-file error", e.Server)
	}
	assertNoLeakErrors(t, res.Errors)
}

// TestReadCursorIgnoresProjects checks that a Cursor file reads only the
// top-level "mcpServers". Claude Code files have a "projects" key with servers
// per project; Cursor files do not, so the reader must not turn those into
// servers.
func TestReadCursorIgnoresProjects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name: "top-level servers and projects",
			content: `{
  "mcpServers": { "top": { "command": "uvx" } },
  "projects": {
    "/some/project": { "mcpServers": { "nested": { "command": "npx" } } }
  }
}`,
			want: []string{"top"},
		},
		{
			name: "only projects",
			content: `{
  "projects": {
    "/some/project": { "mcpServers": { "nested": { "command": "npx" } } }
  }
}`,
			want: nil,
		},
		{
			name:    "projects of the wrong shape are not read",
			content: `{ "mcpServers": { "top": { "command": "uvx" } }, "projects": 5 }`,
			want:    []string{"top"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := writeFile(t, dir, "mcp.json", []byte(tt.content))

			res := ReadCursor(t.Context(), path, ScopeProject, dir)
			if len(res.Errors) != 0 {
				t.Errorf("Errors = %v, want none", res.Errors)
			}
			// slices.Equal treats a nil and an empty slice as equal.
			if got := serverNames(res.Servers); !slices.Equal(got, tt.want) {
				t.Errorf("server names = %v, want %v", got, tt.want)
			}
			for _, s := range res.Servers {
				if s.Scope != ScopeProject || s.ProjectPath != dir {
					t.Errorf("server %q scope=%q projectPath=%q, want %q and %q",
						s.Name, s.Scope, s.ProjectPath, ScopeProject, dir)
				}
			}
		})
	}
}

// TestReadCursorGlobalIgnoresProjectPath checks that a global file ignores the
// projectPath of the call: its servers have no ProjectPath.
func TestReadCursorGlobalIgnoresProjectPath(t *testing.T) {
	t.Parallel()
	path := writeFile(t, t.TempDir(), "mcp.json", []byte(`{"mcpServers": {"s": {"command": "x"}}}`))

	res := ReadCursor(t.Context(), path, ScopeGlobal, "/custom/dir")
	if len(res.Errors) != 0 {
		t.Fatalf("Errors = %v, want none", res.Errors)
	}
	if len(res.Servers) != 1 {
		t.Fatalf("server names = %v, want [s]", serverNames(res.Servers))
	}
	if s := res.Servers[0]; s.Scope != ScopeGlobal || s.ProjectPath != "" || s.Untrusted {
		t.Errorf("server %q scope=%q projectPath=%q untrusted=%v, want %q, \"\" and false",
			s.Name, s.Scope, s.ProjectPath, s.Untrusted, ScopeGlobal)
	}
}
