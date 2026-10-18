package discover

import (
	"path/filepath"
	"reflect"
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

	// view builds the want value of one server. Source, scope and project path
	// depend on the copied directories, so each case receives them.
	type place struct {
		source      string
		scope       Scope
		projectPath string
	}
	view := func(p place, v serverView) serverView {
		v.Client = ClientCursor
		v.Scope = p.scope
		v.ProjectPath = p.projectPath
		v.Source = p.source
		return v
	}

	tests := []struct {
		name string
		// hideValues hides server views in failure messages (secrets and
		// malformed fixtures).
		hideValues bool
		// canaryFiles are the fixture files, relative to the fixture
		// directory, that must hold every canary.
		canaryFiles []string
		// want returns the wanted servers and errors for the global file
		// (home) and the project file (work).
		want func(home, work place) (hs []serverView, he []errWant, ws []serverView, we []errWant)
	}{
		{
			name: "valid",
			want: func(home, work place) ([]serverView, []errWant, []serverView, []errWant) {
				hs := []serverView{
					view(home, serverView{Name: "events", Transport: TransportSSE, URL: "https://sse.example.com/sse"}),
					view(home, serverView{Name: "git", Transport: TransportStdio, Command: "uvx", Args: []string{"mcp-server-git"}}),
					view(home, serverView{Name: "remote", Transport: TransportHTTP, URL: "https://cursor.example.com/mcp"}),
				}
				ws := []serverView{
					view(work, serverView{Name: "project-remote", Transport: TransportHTTP, URL: "https://project.example.com/mcp"}),
					view(work, serverView{Name: "project-tools", Transport: TransportStdio, Command: "npx", Args: []string{"-y", "example-mcp-server"}}),
				}
				return hs, nil, ws, nil
			},
		},
		{
			name:        "secrets",
			hideValues:  true,
			canaryFiles: []string{"home/.cursor/mcp.json", "work/.cursor/mcp.json"},
			want: func(home, work place) ([]serverView, []errWant, []serverView, []errWant) {
				hs := []serverView{
					view(home, serverView{
						Name: "local-api", Transport: TransportStdio, Command: "uvx", Args: []string{"mcp-server-api", "--token", discovertest.CanaryArgs},
						Env: map[string]string{envKey: discovertest.CanaryEnv},
					}),
					view(home, serverView{
						Name: "remote-api", Transport: TransportHTTP, URL: cursorURL,
						Headers: map[string]string{authKey: "Bearer " + discovertest.CanaryHeader},
					}),
				}
				ws := []serverView{
					view(work, serverView{
						Name: "project-local", Transport: TransportStdio, Command: "npx", Args: []string{"-y", "example-mcp-server"},
						Env: map[string]string{envKey: discovertest.CanaryEnv},
					}),
					view(work, serverView{
						Name: "project-remote", Transport: TransportHTTP, URL: "https://project.example.com/mcp",
						Headers: map[string]string{authKey: "Bearer " + discovertest.CanaryHeader},
					}),
				}
				return hs, nil, ws, nil
			},
		},
		{
			name: "empty",
			want: func(_, _ place) ([]serverView, []errWant, []serverView, []errWant) {
				return nil, nil, nil, nil
			},
		},
		{
			name:       "malformed",
			hideValues: true,
			want: func(_, _ place) ([]serverView, []errWant, []serverView, []errWant) {
				// The syntax error is on the line of "broken" in the home
				// file (line 3) and on the env line in the work file (line 5).
				return nil, []errWant{{Line: 3, Reason: reasonInvalidJSON}},
					nil, []errWant{{Line: 5, Reason: reasonInvalidJSON}}
			},
		},
		{
			name: "invalid-entries",
			want: func(home, _ place) ([]serverView, []errWant, []serverView, []errWant) {
				hs := []serverView{
					view(home, serverView{Name: "good", Transport: TransportStdio, Command: "uvx", Args: []string{"mcp-server-git"}}),
				}
				// Errors come sorted by server name.
				he := []errWant{
					{Server: "empty", Reason: reasonNoCommandOrURL},
					{Server: "num-env", Reason: reasonBadEntry},
					{Server: "sse-no-url", Reason: reasonRemoteNoURL},
					{Server: "unknown-type", Reason: reasonUnknownTransport},
				}
				return hs, he, nil, nil
			},
		},
		{
			name: "missing",
			want: func(_, _ place) ([]serverView, []errWant, []serverView, []errWant) {
				return nil, nil, nil, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			fixture := fixtureDir(t, "cursor", tt.name)
			if len(tt.canaryFiles) > 0 {
				// A leak test only means something if the fixture holds the
				// canaries, so check the repository files first.
				var paths []string
				for _, f := range tt.canaryFiles {
					paths = append(paths, filepath.Join(fixture, filepath.FromSlash(f)))
				}
				assertFixtureHasCanaries(t, paths...)
			}

			home, work := copyFixture(t, "cursor", tt.name)
			homeFile := filepath.Join(home, ".cursor", "mcp.json")
			workFile := filepath.Join(work, ".cursor", "mcp.json")

			global := ReadCursor(ctx, homeFile, ScopeGlobal, "")
			project := ReadCursor(ctx, workFile, ScopeProject, work)

			hs, he, ws, we := tt.want(
				place{source: homeFile, scope: ScopeGlobal},
				place{source: workFile, scope: ScopeProject, projectPath: work},
			)
			checkServers(t, "global", global.Servers, hs, tt.hideValues)
			checkFileErrors(t, homeFile, global.Errors, he)
			checkServers(t, "project", project.Servers, ws, tt.hideValues)
			checkFileErrors(t, workFile, project.Errors, we)

			if tt.hideValues {
				for _, r := range []Result{global, project} {
					assertNoLeakServers(t, r.Servers)
					assertNoLeakErrors(t, r.Errors)
				}
			}
		})
	}
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
			got := serverNames(res.Servers)
			if len(tt.want) == 0 {
				if len(got) != 0 {
					t.Errorf("server names = %v, want none", got)
				}
			} else if !reflect.DeepEqual(got, tt.want) {
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
