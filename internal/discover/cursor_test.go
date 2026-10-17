package discover

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// wantCursorErr is the part of a FileError that a cursor test checks. The path is not
// here: every error must name the file that the reader opened.
type wantCursorErr struct {
	Server string
	Line   int
	Reason string
}

// cursorErrsOf returns the wantCursorErr form of errs and checks that every error names
// path and holds no OS error. Parse problems must not carry an Err.
func cursorErrsOf(t *testing.T, errs []*FileError, path string) []wantCursorErr {
	t.Helper()
	if len(errs) == 0 {
		return nil
	}
	out := make([]wantCursorErr, 0, len(errs))
	for i, e := range errs {
		if e.Path != path {
			t.Errorf("errs[%d].Path = %q, want %q", i, e.Path, path)
		}
		if e.Err != nil {
			t.Errorf("errs[%d].Err = %v, want nil for a parse problem", i, e.Err)
		}
		out = append(out, wantCursorErr{Server: e.Server, Line: e.Line, Reason: e.Reason})
	}
	return out
}

// checkCursorResult compares one Result with the wanted servers and errors. If quiet
// is true the failure message holds names only, because the views hold secret
// values.
func checkCursorResult(t *testing.T, label, path string, got Result, want []serverView, wantErrs []wantCursorErr, quiet bool) {
	t.Helper()
	gotViews := viewsOf(got.Servers)
	if !reflect.DeepEqual(gotViews, want) {
		if quiet {
			t.Errorf("%s servers differ from the want list; got names %v", label, serverNames(got.Servers))
		} else {
			t.Errorf("%s servers =\n%+v\nwant\n%+v", label, gotViews, want)
		}
	}
	if gotErrs := cursorErrsOf(t, got.Errors, path); !reflect.DeepEqual(gotErrs, wantErrs) {
		t.Errorf("%s errors = %+v, want %+v", label, gotErrs, wantErrs)
	}
}

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
		// quiet hides server views in failure messages (secrets fixture).
		quiet bool
		// want returns the wanted servers and errors for the global file
		// (home) and the project file (work).
		want func(home, work place) (hs []serverView, he []wantCursorErr, ws []serverView, we []wantCursorErr)
	}{
		{
			name: "valid",
			want: func(home, work place) ([]serverView, []wantCursorErr, []serverView, []wantCursorErr) {
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
			name:  "secrets",
			quiet: true,
			want: func(home, work place) ([]serverView, []wantCursorErr, []serverView, []wantCursorErr) {
				hs := []serverView{
					view(home, serverView{
						Name: "local-api", Transport: TransportStdio, Command: "uvx", Args: []string{"mcp-server-api"},
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
			want: func(_, _ place) ([]serverView, []wantCursorErr, []serverView, []wantCursorErr) {
				return nil, nil, nil, nil
			},
		},
		{
			name:  "malformed",
			quiet: true,
			want: func(_, _ place) ([]serverView, []wantCursorErr, []serverView, []wantCursorErr) {
				// The syntax error is on the line of "broken" in the home
				// file (line 3) and on the env line in the work file (line 5).
				return nil, []wantCursorErr{{Line: 3, Reason: reasonInvalidJSON}},
					nil, []wantCursorErr{{Line: 5, Reason: reasonInvalidJSON}}
			},
		},
		{
			name: "invalid-entries",
			want: func(home, _ place) ([]serverView, []wantCursorErr, []serverView, []wantCursorErr) {
				hs := []serverView{
					view(home, serverView{Name: "good", Transport: TransportStdio, Command: "uvx", Args: []string{"mcp-server-git"}}),
				}
				// Errors come sorted by server name.
				he := []wantCursorErr{
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
			want: func(_, _ place) ([]serverView, []wantCursorErr, []serverView, []wantCursorErr) {
				return nil, nil, nil, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			fixture := fixtureDir(t, "cursor", tt.name)
			if tt.name == "secrets" {
				// A leak test only means something if the fixture holds the
				// canaries, so check the repository files first.
				assertFixtureHasCanaries(t,
					filepath.Join(fixture, "home", ".cursor", "mcp.json"),
					filepath.Join(fixture, "work", ".cursor", "mcp.json"),
				)
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
			checkCursorResult(t, "global", homeFile, global, hs, he, tt.quiet)
			checkCursorResult(t, "project", workFile, project, ws, we, tt.quiet)

			if tt.quiet {
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
			path := filepath.Join(dir, "mcp.json")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("write test file: %v", err)
			}

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
