package discover

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// TestParseJSONServersTransport checks how an entry becomes a transport, one
// server per input, and which fields are kept or dropped. Each case runs for
// Claude Code and Cursor.
func TestParseJSONServersTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		entry     string
		want      serverView // used when wantError is empty
		wantError string     // fixed reason; empty means the server is valid
		// claudeCodeError replaces wantError for Claude Code when it is not
		// empty. Claude Code reads an entry with no type as stdio, so it
		// refuses a url without a command.
		claudeCodeError string
	}{
		{
			name:  "no type with command is stdio",
			entry: `{"command": "npx", "args": ["-y", "pkg"], "env": {"K": "v"}}`,
			want: serverView{
				Transport: TransportStdio,
				Command:   "npx",
				Args:      []string{"-y", "pkg"},
				Env:       map[string]string{"K": "v"},
			},
		},
		{
			name:  "no type with url is http for Cursor only",
			entry: `{"url": "https://example.com/mcp", "headers": {"X-Key": "v"}}`,
			want: serverView{
				Transport: TransportHTTP,
				URL:       "https://example.com/mcp",
				Headers:   map[string]string{"X-Key": "v"},
			},
			claudeCodeError: reasonBadEntry,
		},
		{
			name:  "no type with url and empty command is http for Cursor only",
			entry: `{"command": "", "url": "https://example.com/mcp"}`,
			want: serverView{
				Transport: TransportHTTP,
				URL:       "https://example.com/mcp",
			},
			claudeCodeError: reasonBadEntry,
		},
		{
			name: "no type with command and url is stdio and drops url and headers",
			entry: `{"command": "run", "env": {"K": "v"},
				"url": "https://example.com/mcp", "headers": {"X-Key": "v"}}`,
			want: serverView{
				Transport: TransportStdio,
				Command:   "run",
				Env:       map[string]string{"K": "v"},
			},
		},
		{
			name:  "stdio with command",
			entry: `{"type": "stdio", "command": "run", "args": ["a"]}`,
			want: serverView{
				Transport: TransportStdio,
				Command:   "run",
				Args:      []string{"a"},
			},
		},
		{
			name:  "http with url",
			entry: `{"type": "http", "url": "https://example.com/mcp"}`,
			want: serverView{
				Transport: TransportHTTP,
				URL:       "https://example.com/mcp",
			},
		},
		{
			name:  "streamable-http is http",
			entry: `{"type": "streamable-http", "url": "https://example.com/mcp"}`,
			want: serverView{
				Transport: TransportHTTP,
				URL:       "https://example.com/mcp",
			},
		},
		{
			name:  "sse with url",
			entry: `{"type": "sse", "url": "https://example.com/sse"}`,
			want: serverView{
				Transport: TransportSSE,
				URL:       "https://example.com/sse",
			},
		},
		{
			name: "http with command drops command args and env",
			entry: `{"type": "http", "url": "https://example.com/mcp", "command": "run",
				"args": ["a"], "env": {"K": "v"}}`,
			want: serverView{
				Transport: TransportHTTP,
				URL:       "https://example.com/mcp",
			},
		},
		{
			name: "stdio with url drops url and headers",
			entry: `{"type": "stdio", "command": "run", "url": "https://example.com/mcp",
				"headers": {"X-Key": "v"}}`,
			want: serverView{
				Transport: TransportStdio,
				Command:   "run",
			},
		},
		{
			name:      "unknown type",
			entry:     `{"type": "websocket", "url": "wss://example.com"}`,
			wantError: reasonUnknownTransport,
		},
		{
			name:      "type is case sensitive",
			entry:     `{"type": "STDIO", "command": "run"}`,
			wantError: reasonUnknownTransport,
		},
		{
			name:      "stdio without command",
			entry:     `{"type": "stdio", "url": "https://example.com/mcp"}`,
			wantError: reasonStdioNoCommand,
		},
		{
			name:      "http without url",
			entry:     `{"type": "http", "command": "run"}`,
			wantError: reasonRemoteNoURL,
		},
		{
			name:      "streamable-http without url",
			entry:     `{"type": "streamable-http"}`,
			wantError: reasonRemoteNoURL,
		},
		{
			name:      "sse without url",
			entry:     `{"type": "sse"}`,
			wantError: reasonRemoteNoURL,
		},
		{
			name:      "empty entry",
			entry:     `{}`,
			wantError: reasonNoCommandOrURL,
		},
		{
			name:      "empty command and empty url",
			entry:     `{"command": "", "url": ""}`,
			wantError: reasonNoCommandOrURL,
		},
	}

	for _, tt := range tests {
		for _, client := range []Client{ClientClaudeCode, ClientCursor} {
			t.Run(tt.name+"/"+string(client), func(t *testing.T) {
				t.Parallel()
				path := writeFile(t, t.TempDir(), "config.json", []byte(`{"mcpServers": {"srv": `+tt.entry+`}}`))

				servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: client, scope: ScopeGlobal})

				wantError := tt.wantError
				if client == ClientClaudeCode && tt.claudeCodeError != "" {
					wantError = tt.claudeCodeError
				}
				if wantError != "" {
					if len(servers) != 0 {
						t.Errorf("servers = %v, want none", serverNames(servers))
					}
					checkFileErrors(t, path, errs, []errWant{{Server: "srv", Reason: wantError}})
					if strings.Contains(errs[0].Error(), "websocket") || strings.Contains(errs[0].Error(), "STDIO") {
						t.Errorf("error text %q echoes the transport type value", errs[0].Error())
					}
					return
				}

				if len(errs) != 0 {
					t.Fatalf("errors = %v, want none", errs)
				}
				want := tt.want
				want.Name = "srv"
				want.Client = client
				want.Scope = ScopeGlobal
				want.Source = path
				if got := viewsOf(servers); !reflect.DeepEqual(got, []serverView{want}) {
					t.Errorf("servers = %+v, want %+v", got, []serverView{want})
				}
			})
		}
	}
}

// TestParseJSONServersBadEntries checks that one bad entry gives one error and
// the good entries are still returned.
func TestParseJSONServersBadEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantServers []serverView
		wantErrors  []errWant
	}{
		{
			name: "number env value",
			input: `{"mcpServers": {
				"bad":  {"command": "x", "env": {"PORT": 8080}},
				"good": {"command": "y"}}}`,
			wantServers: []serverView{{Name: "good", Transport: TransportStdio, Command: "y"}},
			wantErrors:  []errWant{{Server: "bad", Reason: reasonBadEntry}},
		},
		{
			// The client gets the real null, not an empty env, so the entry
			// is refused (NFR-04).
			name: "null env",
			input: `{"mcpServers": {
				"bad":  {"command": "x", "env": null},
				"good": {"command": "y"}}}`,
			wantServers: []serverView{{Name: "good", Transport: TransportStdio, Command: "y"}},
			wantErrors:  []errWant{{Server: "bad", Reason: reasonBadEntry}},
		},
		{
			name: "string entry",
			input: `{"mcpServers": {
				"bad":  "x",
				"good": {"command": "y"}}}`,
			wantServers: []serverView{{Name: "good", Transport: TransportStdio, Command: "y"}},
			wantErrors:  []errWant{{Server: "bad", Reason: reasonBadEntry}},
		},
		{
			name: "array entry and number entry",
			input: `{"mcpServers": {
				"arr": [],
				"num": 5,
				"ok":  {"url": "https://example.com/mcp"}}}`,
			wantServers: []serverView{{Name: "ok", Transport: TransportHTTP, URL: "https://example.com/mcp"}},
			wantErrors: []errWant{
				{Server: "arr", Reason: reasonBadEntry},
				{Server: "num", Reason: reasonBadEntry},
			},
		},
		{
			name: "args is not a list of strings",
			input: `{"mcpServers": {
				"bad":  {"command": "x", "args": "one"},
				"good": {"command": "y"}}}`,
			wantServers: []serverView{{Name: "good", Transport: TransportStdio, Command: "y"}},
			wantErrors:  []errWant{{Server: "bad", Reason: reasonBadEntry}},
		},
		{
			// encoding/json would make a null entry an empty object, but the
			// client gets the real null. A null is refused as for a field.
			name: "null entry",
			input: `{"mcpServers": {
				"nothing": null,
				"good":    {"command": "y"}}}`,
			wantServers: []serverView{{Name: "good", Transport: TransportStdio, Command: "y"}},
			wantErrors:  []errWant{{Server: "nothing", Reason: reasonBadEntry}},
		},
		{
			name: "empty object entry is a server without command or url",
			input: `{"mcpServers": {
				"nothing": {}}}`,
			wantErrors: []errWant{{Server: "nothing", Reason: reasonNoCommandOrURL}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), "config.json", []byte(tt.input))

			servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientCursor, scope: ScopeGlobal})

			for i := range tt.wantServers {
				tt.wantServers[i].Client = ClientCursor
				tt.wantServers[i].Scope = ScopeGlobal
				tt.wantServers[i].Source = path
			}
			if got := viewsOf(servers); !reflect.DeepEqual(got, tt.wantServers) {
				t.Errorf("servers = %+v, want %+v", got, tt.wantServers)
			}
			checkFileErrors(t, path, errs, tt.wantErrors)
		})
	}
}

// TestParseJSONServersNullFields checks that an explicit null in a known field
// of an entry makes the entry invalid. encoding/json would turn the null into
// "" or an empty Secret, or treat the key as absent, but the client gets the
// real null: it refuses the entry, or Node turns the null into the text
// "null". A server built from the decoded value could then run another
// command line than the client (NFR-04).
func TestParseJSONServersNullFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry string
		// want is the server of a valid entry. It is nil when the entry
		// must give reasonBadEntry.
		want *serverView
	}{
		{name: "null type", entry: `{"type": null, "command": "x"}`},
		{name: "null command", entry: `{"command": null}`},
		{name: "null command with a url", entry: `{"command": null, "url": "https://example.com/mcp"}`},
		{name: "null url", entry: `{"url": null}`},
		{name: "null url with a command", entry: `{"command": "x", "url": null}`},
		{name: "null args", entry: `{"command": "x", "args": null}`},
		{name: "null args item", entry: `{"command": "x", "args": ["a", null]}`},
		{name: "null first args item", entry: `{"command": "x", "args": [null, "a"]}`},
		{name: "null args item with whitespace", entry: "{\"command\": \"x\", \"args\": [ \"a\" ,\n\tnull\r\n ]}"},
		{name: "null env", entry: `{"command": "x", "env": null}`},
		{name: "null env value", entry: `{"command": "x", "env": {"A": "1", "K": null}}`},
		{name: "null headers", entry: `{"url": "https://example.com/mcp", "headers": null}`},
		{name: "null headers value", entry: `{"url": "https://example.com/mcp", "headers": {"Authorization": null}}`},
		{
			name:  "text null is a value",
			entry: `{"command": "x", "args": ["null"], "env": {"K": "null"}}`,
			want: &serverView{
				Name: "s", Transport: TransportStdio, Command: "x",
				Args: []string{"null"}, Env: map[string]string{"K": "null"},
			},
		},
		{
			name:  "null in an unknown key is ignored",
			entry: `{"command": "x", "args": ["a"], "other": null, "list": [null], "map": {"k": null}}`,
			want:  &serverView{Name: "s", Transport: TransportStdio, Command: "x", Args: []string{"a"}},
		},
		{
			name:  "remote entry without nulls",
			entry: `{"type": "sse", "url": "https://example.com/sse", "headers": {"Authorization": "Bearer t"}}`,
			want: &serverView{
				Name: "s", Transport: TransportSSE, URL: "https://example.com/sse",
				Headers: map[string]string{"Authorization": "Bearer t"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := `{"mcpServers": {"s": ` + tt.entry + `}}`
			path := writeFile(t, t.TempDir(), "config.json", []byte(input))

			servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientCursor, scope: ScopeGlobal})

			if tt.want == nil {
				if len(servers) != 0 {
					t.Errorf("servers = %v, want none", serverNames(servers))
				}
				checkFileErrors(t, path, errs, []errWant{{Server: "s", Reason: reasonBadEntry}})
				return
			}
			checkFileErrors(t, path, errs, nil)
			want := *tt.want
			want.Client, want.Scope, want.Source = ClientCursor, ScopeGlobal, path
			if got := viewsOf(servers); !reflect.DeepEqual(got, []serverView{want}) {
				t.Errorf("servers = %+v, want %+v", got, []serverView{want})
			}
		})
	}
}

// TestParseJSONServersShapes checks empty files, wrong top-level shapes and
// the handling of "projects".
func TestParseJSONServersShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		withProjects bool
		wantServers  []string // names, in order
		wantErrors   []errWant
	}{
		{name: "empty file", input: ``},
		{name: "whitespace-only file", input: " \n\t\r\n "},
		{name: "empty object", input: `{}`},
		{name: "top-level array", input: `[]`, wantErrors: []errWant{{Reason: reasonBadShape}}},
		{name: "top-level number", input: `5`, wantErrors: []errWant{{Reason: reasonBadShape}}},
		{name: "top-level string", input: `"x"`, wantErrors: []errWant{{Reason: reasonBadShape}}},
		// The clients need an object, so a file of only null is an error.
		{name: "top-level null", input: `null`, wantErrors: []errWant{{Reason: reasonBadShape}}},
		{name: "top-level null with whitespace", input: " null\n", wantErrors: []errWant{{Reason: reasonBadShape}}},
		// U+00A0 is a space for bytes.TrimSpace, but not JSON whitespace.
		{name: "only no-break spaces", input: "\u00a0\u00a0", wantErrors: []errWant{{Reason: reasonInvalidJSON, Line: 1}}},
		{name: "no-break space after the object", input: "{}\u00a0", wantErrors: []errWant{{Reason: reasonInvalidJSON, Line: 1}}},
		{
			name:       "mcpServers array",
			input:      `{"mcpServers": []}`,
			wantErrors: []errWant{{Reason: reasonBadServers}},
		},
		{
			name:       "mcpServers string",
			input:      `{"mcpServers": "x"}`,
			wantErrors: []errWant{{Reason: reasonBadServers}},
		},
		{name: "mcpServers null", input: `{"mcpServers": null}`},
		{name: "mcpServers empty object", input: `{"mcpServers": {}}`},
		{
			name:         "projects array",
			input:        `{"projects": []}`,
			withProjects: true,
			wantErrors:   []errWant{{Reason: reasonBadShape}},
		},
		{name: "projects null", input: `{"projects": null}`, withProjects: true},
		{
			name:        "projects ignored when withProjects is false",
			input:       `{"projects": {"/p": {"mcpServers": {"s": {"command": "x"}}}}, "mcpServers": {"top": {"command": "x"}}}`,
			wantServers: []string{"top"},
		},
		{
			name:         "bad projects shape is ignored when withProjects is false",
			input:        `{"projects": []}`,
			withProjects: false,
		},
		{
			name: "bad project value keeps the other projects",
			input: `{"projects": {
				"/a": 5,
				"/b": {"mcpServers": {"s": {"command": "x"}}}}}`,
			withProjects: true,
			wantServers:  []string{"s"},
			wantErrors:   []errWant{{ProjectPath: "/a", Reason: reasonBadShape}},
		},
		{
			name: "project without mcpServers",
			input: `{"projects": {
				"/a": {"allowedTools": []},
				"/b": {"mcpServers": null}}}`,
			withProjects: true,
		},
		{
			name: "project mcpServers is not an object",
			input: `{"projects": {
				"/a": {"mcpServers": []},
				"/b": {"mcpServers": {"s": {"command": "x"}}}}}`,
			withProjects: true,
			wantServers:  []string{"s"},
			wantErrors:   []errWant{{ProjectPath: "/a", Reason: reasonBadServers}},
		},
		{
			name:         "bad top-level mcpServers keeps the project servers",
			input:        `{"mcpServers": 1, "projects": {"/b": {"mcpServers": {"s": {"command": "x"}}}}}`,
			withProjects: true,
			wantServers:  []string{"s"},
			wantErrors:   []errWant{{Reason: reasonBadServers}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), "config.json", []byte(tt.input))

			servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal, withProjects: tt.withProjects})

			var gotNames []string
			if len(servers) > 0 {
				gotNames = serverNames(servers)
			}
			if !slices.Equal(gotNames, tt.wantServers) {
				t.Errorf("servers = %v, want %v", gotNames, tt.wantServers)
			}
			checkFileErrors(t, path, errs, tt.wantErrors)
		})
	}
}

// TestParseJSONServersMissingFile checks that a missing file gives nothing.
func TestParseJSONServersMissingFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nope.json")

	servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientCursor, scope: ScopeGlobal})

	if len(servers) != 0 || len(errs) != 0 {
		t.Errorf("got %d servers and %d errors, want none", len(servers), len(errs))
	}
}

// TestParseJSONServersScopeAndProjectPath checks the Scope, ProjectPath,
// Source, Client and Untrusted of each server.
func TestParseJSONServersScopeAndProjectPath(t *testing.T) {
	t.Parallel()

	const input = `{
		"mcpServers": {"top": {"command": "t"}},
		"projects": {
			"/work/one": {"mcpServers": {"p1": {"command": "p1"}}},
			"/work/two": {"mcpServers": {"p2": {"type": "http", "url": "https://example.com/mcp"}}}
		}
	}`

	// workDirWant stands for the directory of the file in a want value. A
	// project file must be below its projectPath, so the test uses the
	// temporary directory as projectPath.
	const workDirWant = "<dir>"

	tests := []struct {
		name   string
		client Client
		scope  Scope
		want   []serverView
	}{
		{
			name:   "global",
			client: ClientClaudeCode,
			scope:  ScopeGlobal,
			want: []serverView{
				{Name: "top", Client: ClientClaudeCode, Scope: ScopeGlobal, Transport: TransportStdio, Command: "t"},
				{
					Name: "p1", Client: ClientClaudeCode, Scope: ScopeProject, ProjectPath: "/work/one",
					Transport: TransportStdio, Command: "p1",
				},
				{
					Name: "p2", Client: ClientClaudeCode, Scope: ScopeProject, ProjectPath: "/work/two",
					Transport: TransportHTTP, URL: "https://example.com/mcp",
				},
			},
		},
		{
			// withProjects is true here, so the projects of a project file
			// are read too. ReadClaudeCode never does that. Every server of
			// a project file is untrusted.
			name:   "project file",
			client: ClientClaudeCode,
			scope:  ScopeProject,
			want: []serverView{
				{
					Name: "top", Client: ClientClaudeCode, Scope: ScopeProject, ProjectPath: workDirWant,
					Untrusted: true, Transport: TransportStdio, Command: "t",
				},
				{
					Name: "p1", Client: ClientClaudeCode, Scope: ScopeProject, ProjectPath: "/work/one",
					Untrusted: true, Transport: TransportStdio, Command: "p1",
				},
				{
					Name: "p2", Client: ClientClaudeCode, Scope: ScopeProject, ProjectPath: "/work/two",
					Untrusted: true, Transport: TransportHTTP, URL: "https://example.com/mcp",
				},
			},
		},
		{
			name:   "client is passed through",
			client: ClientCursor,
			scope:  ScopeGlobal,
			want: []serverView{
				{Name: "top", Client: ClientCursor, Scope: ScopeGlobal, Transport: TransportStdio, Command: "t"},
				{
					Name: "p1", Client: ClientCursor, Scope: ScopeProject, ProjectPath: "/work/one",
					Transport: TransportStdio, Command: "p1",
				},
				{
					Name: "p2", Client: ClientCursor, Scope: ScopeProject, ProjectPath: "/work/two",
					Transport: TransportHTTP, URL: "https://example.com/mcp",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := writeFile(t, dir, "config.json", []byte(input))
			projectPath := ""
			if tt.scope == ScopeProject {
				projectPath = dir
			}

			servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: tt.client, scope: tt.scope, projectPath: projectPath, withProjects: true})

			if len(errs) != 0 {
				t.Fatalf("errors = %v, want none", errs)
			}
			for i := range tt.want {
				tt.want[i].Source = path
				if tt.want[i].ProjectPath == workDirWant {
					tt.want[i].ProjectPath = dir
				}
			}
			// The servers are sorted by (ProjectPath, Name), and dir can sort
			// anywhere, so sort the want list the same way.
			slices.SortStableFunc(tt.want, func(a, b serverView) int {
				return cmp.Or(strings.Compare(a.ProjectPath, b.ProjectPath), strings.Compare(a.Name, b.Name))
			})
			if got := viewsOf(servers); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("servers = %+v\nwant     %+v", got, tt.want)
			}
		})
	}
}

// TestParseJSONServersOrder checks that the result does not depend on the
// order of the keys in the file (Go map order is random, so we repeat).
func TestParseJSONServersOrder(t *testing.T) {
	t.Parallel()

	// Keys are in reverse sorted order on purpose.
	const input = `{
		"mcpServers": {
			"zeta":  {"command": "z"},
			"bad2":  5,
			"alpha": {"command": "a"},
			"bad1":  "x"
		},
		"projects": {
			"/z": {"mcpServers": {"b": {"command": "b"}, "a": {"command": "a"}, "badz": 1}},
			"/a": {"mcpServers": {"m": {"command": "m"}, "n": {"command": "n"}, "bada": 1}},
			"/m": 5
		}
	}`
	path := writeFile(t, t.TempDir(), "config.json", []byte(input))

	// Servers: sorted by (ProjectPath, Name). The empty ProjectPath is the
	// top level of a global file and sorts first.
	wantNames := []string{"alpha", "zeta", "m", "n", "a", "b"}
	wantPaths := []string{"", "", "/a", "/a", "/z", "/z"}
	// Errors: the error without a server (project "/m") first, then by name.
	wantErrors := []errWant{
		{ProjectPath: "/m", Reason: reasonBadShape},
		{Server: "bad1", Reason: reasonBadEntry},
		{Server: "bad2", Reason: reasonBadEntry},
		{ProjectPath: "/a", Server: "bada", Reason: reasonBadEntry},
		{ProjectPath: "/z", Server: "badz", Reason: reasonBadEntry},
	}

	for i := range 30 {
		servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal, withProjects: true})

		if got := serverNames(servers); !slices.Equal(got, wantNames) {
			t.Fatalf("run %d: server names = %v, want %v", i, got, wantNames)
		}
		var gotPaths []string
		for _, s := range servers {
			gotPaths = append(gotPaths, s.ProjectPath)
		}
		if !slices.Equal(gotPaths, wantPaths) {
			t.Fatalf("run %d: project paths = %v, want %v", i, gotPaths, wantPaths)
		}
		checkFileErrors(t, path, errs, wantErrors)
		if t.Failed() {
			t.Fatalf("run %d: errors differ from the want list", i)
		}
	}
}

// TestParseJSONServersSyntaxError checks that a JSON syntax error has a
// position and that the error text holds no part of the file. The exact
// positions are in TestParseJSONServersSyntaxErrorPosition.
func TestParseJSONServersSyntaxError(t *testing.T) {
	t.Parallel()

	t.Run("not JSON at all", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, t.TempDir(), "config.json", []byte("not json"))

		_, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal, withProjects: true})

		checkFileErrors(t, path, errs, []errWant{{Reason: reasonInvalidJSON, Line: 1}})
		if strings.Contains(errs[0].Error(), "not json") {
			t.Errorf("error text %q holds file content", errs[0].Error())
		}
	})

	t.Run("invalid escape in a string", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, t.TempDir(), "config.json", []byte(`{"mcpServers": {"x": {"command": "\u00zz"}}}`))

		servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal, withProjects: true})

		// The whole file is checked for syntax first, so a bad escape is a
		// syntax error of the file and no server is returned.
		if len(servers) != 0 {
			t.Errorf("servers = %v, want none", serverNames(servers))
		}
		// checkFileErrors also checks that Col is set.
		checkFileErrors(t, path, errs, []errWant{{Reason: reasonInvalidJSON, Line: 1}})
		// The position is inside the bad escape, not at the start of the file.
		if want := strings.Index(`{"mcpServers": {"x": {"command": "\u00zz"}}}`, `\u00zz`); errs[0].Col <= want {
			t.Errorf("Col = %d, want a column inside the escape (after byte %d)", errs[0].Col, want)
		}
		for _, e := range errs {
			if strings.Contains(e.Error(), "zz") {
				t.Errorf("error text %q holds file content", e.Error())
			}
		}
	})
}

// TestParseJSONServersNoLeak checks that no canary secret reaches an error or
// the formatted form of a server.
func TestParseJSONServersNoLeak(t *testing.T) {
	t.Parallel()

	envCanary := discovertest.CanaryEnv
	headerCanary := discovertest.CanaryHeader
	urlCanary := discovertest.CanaryURL

	tests := []struct {
		name  string
		input string
	}{
		{
			name: "valid file",
			input: `{"mcpServers": {
				"a": {"command": "x", "env": {"K": "` + envCanary + `"}},
				"b": {"type": "http", "url": "https://u:` + urlCanary + `@example.com/mcp?k=` + urlCanary + `",
				      "headers": {"Authorization": "` + headerCanary + `"}}}}`,
		},
		{
			name: "entries with bad shapes next to canaries",
			input: `{"mcpServers": {
				"num":  {"command": "x", "env": {"K": 1, "L": "` + envCanary + `"}},
				"type": {"type": "` + headerCanary + `", "url": "https://example.com/` + urlCanary + `"},
				"str":  "` + envCanary + `",
				"arr":  ["` + headerCanary + `"]}}`,
		},
		{
			name: "syntax error right before a canary",
			input: `{"mcpServers": {"a": {"command": "x", "env": {"K": ` + envCanary + `,
				"H": "` + headerCanary + `"}, "url": "https://example.com/` + urlCanary + `"}}}`,
		},
		{
			name: "missing comma before a canary",
			input: `{"mcpServers": {"a": {"headers": {"One": "1" "Two": "` + headerCanary + `"}},
				"b": {"env": {"K": "` + envCanary + `"}}}}`,
		},
		{
			// A project key is a directory name, like a server name, so the
			// error shows it. The value of a bad project must not show.
			name: "canary as value of a bad project",
			input: `{"mcpServers": {"a": {"command": "x"}},
				"projects": {"/p": "` + urlCanary + `", "/q": {"mcpServers": "` + envCanary + `"}}}`,
		},
		{
			name: "canary next to an ambiguous key",
			input: `{"mcpServers": {"a": {"command": "x", "Env": {"K": "` + envCanary + `"},
				"HEADERS": {"H": "` + headerCanary + `"}}}}`,
		},
		{
			name:  "canary next to a lone surrogate",
			input: `{"mcpServers": {"a\ud800": {"command": "x", "env": {"K": "` + envCanary + `"}}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), "config.json", []byte(tt.input))

			servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal, withProjects: true})

			assertNoLeakServers(t, servers)
			assertNoLeakErrors(t, errs)
		})
	}
}

// TestParseJSONServersCanceledContext checks that a canceled context gives
// one canceled error and no server.
func TestParseJSONServersCanceledContext(t *testing.T) {
	t.Parallel()
	path := writeFile(t, t.TempDir(), "config.json", []byte(`{"mcpServers": {"a": {"command": "x"}}}`))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	servers, errs := parseJSONServers(ctx, jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal, withProjects: true})

	if len(servers) != 0 {
		t.Errorf("servers = %v, want none", serverNames(servers))
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(errs), errs)
	}
	if errs[0].Reason != reasonCanceled {
		t.Errorf("Reason = %q, want %q", errs[0].Reason, reasonCanceled)
	}
	if !errors.Is(errs[0], context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false, want true")
	}
}

// TestParseJSONServersDuplicateKeys records what happens when a server name
// appears twice in "mcpServers". The assertions follow the observed behaviour.
func TestParseJSONServersDuplicateKeys(t *testing.T) {
	t.Parallel()

	envCanary := discovertest.CanaryEnv
	path := writeFile(t, t.TempDir(), "config.json", []byte(`{"mcpServers": {
		"a": {"command": "first", "env": {"K": "`+envCanary+`"}},
		"a": {"command": "second"}}}`))

	servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal})

	assertNoLeakServers(t, servers)
	assertNoLeakErrors(t, errs)
	// Observed: encoding/json keeps the last value for a repeated key and
	// reports no error, so the first entry is dropped without a message. This
	// test pins that behaviour; change it on purpose, not by accident.
	if len(errs) != 0 {
		t.Errorf("errors = %v, want none", errs)
	}
	if len(servers) != 1 || servers[0].Name != "a" || servers[0].Command != "second" {
		t.Errorf("servers = %+v, want one server %q with command %q", viewsOf(servers), "a", "second")
	}
}

// TestParseJSONServersSyntaxErrorPosition checks the exact line and column of
// a syntax error. The column counts bytes and points at the byte that the
// parser rejected.
func TestParseJSONServersSyntaxErrorPosition(t *testing.T) {
	t.Parallel()

	const truncated = `{"mcpServers": {"x": {"command": "a"`

	tests := []struct {
		name     string
		input    string
		wantLine int
		wantCol  int
	}{
		// The parser finds the error at the opening quote of "b".
		{name: "missing comma", input: "{\n  \"a\": 1\n  \"b\": 2\n}", wantLine: 3, wantCol: 3},
		// At an unexpected end of input the error points at the last byte.
		{name: "truncated file", input: truncated, wantLine: 1, wantCol: len(truncated)},
		{name: "bad value", input: `{"a": x}`, wantLine: 1, wantCol: 7},
		{name: "trailing comma", input: "{\n  \"a\": 1,\n}", wantLine: 3, wantCol: 1},
		{
			// The raw newline ends line 2, and it is the rejected byte: line 2
			// is `  "a": "x` (9 bytes), so the newline is column 10. The error
			// must not point at line 3.
			name:     "raw newline in a string",
			input:    "{\n  \"a\": \"x\ny\"\n}",
			wantLine: 2,
			wantCol:  10,
		},
		{name: "trailing garbage", input: `{"a": 1} x`, wantLine: 1, wantCol: 10},
		{name: "second closing brace", input: `{"a": 1}}`, wantLine: 1, wantCol: 9},
		{
			// At the end of the input, the error points at the last byte.
			name:     "unexpected end of input",
			input:    `{"a": 1`,
			wantLine: 1,
			wantCol:  7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), "config.json", []byte(tt.input))

			servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal, withProjects: true})

			if len(servers) != 0 {
				t.Errorf("servers = %v, want none", serverNames(servers))
			}
			checkFileErrors(t, path, errs, []errWant{{Reason: reasonInvalidJSON, Line: tt.wantLine}})
			if errs[0].Line != tt.wantLine || errs[0].Col != tt.wantCol {
				t.Errorf("position = %d:%d, want %d:%d", errs[0].Line, errs[0].Col, tt.wantLine, tt.wantCol)
			}
		})
	}
}

// manyEntries returns the body of a JSON object with n members, separated by
// commas. format makes member i; it gets i as its one argument (%d). For
// example `"s%d":{"command":"x"}` gives n valid servers and `"/p%d":{}` gives
// n empty projects.
func manyEntries(format string, n int) string {
	var b strings.Builder
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, format, i)
	}
	return b.String()
}

// TestParseJSONServersTooManyServers checks the cap on entries per file. A file
// over the cap gives one error and no servers, also none that were decoded
// before the cap.
func TestParseJSONServersTooManyServers(t *testing.T) {
	t.Parallel()

	half := maxServersPerFile/2 + 1
	tooMany := []errWant{{Reason: reasonTooManyServers}}

	tests := []struct {
		name        string
		input       string
		wantServers int
		wantErrors  []errWant
	}{
		{
			name:        "at the cap is accepted",
			input:       `{"mcpServers": {` + manyEntries(`"s%d":{"command":"x"}`, maxServersPerFile) + `}}`,
			wantServers: maxServersPerFile,
		},
		{
			name:       "over the cap in mcpServers",
			input:      `{"mcpServers": {` + manyEntries(`"s%d":{"command":"x"}`, maxServersPerFile+1) + `}}`,
			wantErrors: tooMany,
		},
		{
			// /a fits, /b goes over the cap. /a gives no servers either, and
			// /c is not decoded.
			name: "over the cap across projects",
			input: `{"projects": {
				"/a": {"mcpServers": {` + manyEntries(`"a%d":{"command":"x"}`, half) + `}},
				"/b": {"mcpServers": {` + manyEntries(`"b%d":{"command":"x"}`, half) + `}},
				"/c": {"mcpServers": {"c": {"command": "x"}}}}}`,
			wantErrors: tooMany,
		},
		{
			name:       "empty projects count toward the cap",
			input:      `{"projects": {` + manyEntries(`"/p%d":{}`, maxServersPerFile+1) + `}}`,
			wantErrors: tooMany,
		},
		{
			name:  "empty projects at the cap are accepted",
			input: `{"projects": {` + manyEntries(`"/p%d":{}`, maxServersPerFile) + `}}`,
		},
		{
			// The top level fits (half servers), the projects then go one
			// over the cap.
			name: "projects and servers together go over the cap",
			input: `{"mcpServers": {` + manyEntries(`"t%d":{"command":"x"}`, half) + `},
				"projects": {` + manyEntries(`"/p%d":{}`, maxServersPerFile/2) + `}}`,
			wantErrors: tooMany,
		},
		{
			name: "top level and projects share the cap",
			input: `{"mcpServers": {` + manyEntries(`"t%d":{"command":"x"}`, maxServersPerFile) + `},
				"projects": {"/p": {"mcpServers": {"extra": {"command": "x"}}}}}`,
			wantErrors: tooMany,
		},
		{
			// The entry error of /a is dropped too: the file has one error.
			name: "entry errors before the cap are dropped",
			input: `{"projects": {
				"/a": {"mcpServers": {"bad": 5, ` + manyEntries(`"a%d":{"command":"x"}`, half) + `}},
				"/b": {"mcpServers": {` + manyEntries(`"b%d":{"command":"x"}`, half) + `}}}}`,
			wantErrors: tooMany,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), "config.json", []byte(tt.input))

			servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal, withProjects: true})

			if len(servers) != tt.wantServers {
				t.Errorf("got %d servers, want %d", len(servers), tt.wantServers)
			}
			checkFileErrors(t, path, errs, tt.wantErrors)
		})
	}
}

// TestSortServersStable checks that sortServers sorts by (ProjectPath, Name)
// and keeps the input order of servers with the same key. parseJSONServers
// gives the top-level servers first, then the project servers, so a top-level
// server stays before a project server of the same name and path. In
// production that happens for a global file with a "projects" key "".
func TestSortServersStable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []Server
		want []string // Command of each server, in order
	}{
		{
			name: "top-level server first",
			in: []Server{
				{Name: "b", Command: "b"},
				{Name: "dup", Scope: ScopeGlobal, Command: "top"},
				{Name: "dup", Scope: ScopeProject, Command: "project"},
			},
			want: []string{"b", "top", "project"},
		},
		{
			// The sort keeps the input order; it does not look at Scope.
			name: "input order is kept",
			in: []Server{
				{Name: "dup", Scope: ScopeProject, Command: "project"},
				{Name: "dup", Scope: ScopeGlobal, Command: "top"},
				{Name: "a", Command: "a"},
			},
			want: []string{"a", "project", "top"},
		},
		{
			name: "ProjectPath before Name",
			in: []Server{
				{Name: "a", ProjectPath: "/z", Command: "a /z"},
				{Name: "z", ProjectPath: "/a", Command: "z /a"},
				{Name: "m", Command: "m"},
			},
			want: []string{"m", "z /a", "a /z"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			servers := slices.Clone(tt.in)

			sortServers(servers)

			var got []string
			for _, s := range servers {
				got = append(got, s.Command)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("commands = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseJSONServersSizeLimitByScope checks that a project file has the
// smaller size limit and a global file keeps the larger one.
func TestParseJSONServersSizeLimitByScope(t *testing.T) {
	t.Parallel()

	// Valid JSON with trailing spaces, one byte over the project limit.
	const body = `{"mcpServers": {"s": {"command": "x"}}}`
	overLimit := body + strings.Repeat(" ", maxProjectConfigSize+1-len(body))
	if len(overLimit) != maxProjectConfigSize+1 {
		t.Fatalf("test input has %d bytes, want %d", len(overLimit), maxProjectConfigSize+1)
	}

	tests := []struct {
		name        string
		content     string
		scope       Scope
		wantServers int
		wantErrors  []errWant
	}{
		{
			name:       "project scope over the limit is refused",
			content:    overLimit,
			scope:      ScopeProject,
			wantErrors: []errWant{{Reason: reasonTooLarge}},
		},
		{
			name:        "project scope at the limit is read",
			content:     overLimit[:maxProjectConfigSize],
			scope:       ScopeProject,
			wantServers: 1,
		},
		{
			name:        "global scope over the project limit is read",
			content:     overLimit,
			scope:       ScopeGlobal,
			wantServers: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := writeFile(t, dir, "config.json", []byte(tt.content))
			projectPath := ""
			if tt.scope == ScopeProject {
				projectPath = dir // a project file must be below its projectPath
			}

			servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: tt.scope, projectPath: projectPath})

			if len(servers) != tt.wantServers {
				t.Errorf("got %d servers, want %d", len(servers), tt.wantServers)
			}
			checkFileErrors(t, path, errs, tt.wantErrors)
		})
	}
}

// TestParseJSONServersCaseVariantKeys checks that the keys of a server entry
// are matched exactly, as JSON.parse in Claude Code and Cursor does. A known
// key in another letter case makes the entry an "ambiguous key" error, so
// mcpmoat never scans a server other than the one that the client starts.
func TestParseJSONServersCaseVariantKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		entry     string
		want      serverView // used when wantError is empty
		wantError string
	}{
		{
			// encoding/json with a struct would take "benign" and ["ok"];
			// the client runs "evil" with ["-c", "bad"].
			name:      "command and args",
			entry:     `{"command": "evil", "args": ["-c", "bad"], "Command": "benign", "ARGS": ["ok"]}`,
			wantError: reasonAmbiguousKey,
		},
		{
			name:      "args",
			entry:     `{"command": "x", "args": ["a"], "Args": ["b"]}`,
			wantError: reasonAmbiguousKey,
		},
		{
			name:      "type",
			entry:     `{"type": "stdio", "TYPE": "http", "command": "x", "url": "https://example.com/mcp"}`,
			wantError: reasonAmbiguousKey,
		},
		{
			name:      "url",
			entry:     `{"url": "https://a.example.com/mcp", "URL": "https://b.example.com/mcp"}`,
			wantError: reasonAmbiguousKey,
		},
		{
			name:      "headers",
			entry:     `{"url": "https://example.com/mcp", "headers": {"A": "1"}, "Headers": {"A": "2"}}`,
			wantError: reasonAmbiguousKey,
		},
		{
			name:      "env",
			entry:     `{"command": "x", "env": {"K": "1"}, "Env": {"K": "2"}}`,
			wantError: reasonAmbiguousKey,
		},
		{
			// The client sees an http server; a reader that ignores case
			// would see a stdio server.
			name:      "variant alone",
			entry:     `{"url": "https://example.com/mcp", "COMMAND": "local"}`,
			wantError: reasonAmbiguousKey,
		},
		{
			name:      "variant with a null value",
			entry:     `{"command": "x", "ENV": null}`,
			wantError: reasonAmbiguousKey,
		},
		{
			// U+017F (long s) folds to "s" in Unicode case folding, and
			// encoding/json folds it too.
			name:      "unicode folding",
			entry:     `{"command": "x", "argſ": ["a"]}`,
			wantError: reasonAmbiguousKey,
		},
		{
			name:  "exact keys",
			entry: `{"type": "stdio", "command": "x", "args": ["a"], "env": {"K": "v"}}`,
			want: serverView{
				Transport: TransportStdio, Command: "x", Args: []string{"a"},
				Env: map[string]string{"K": "v"},
			},
		},
		{
			name:  "unknown keys are ignored",
			entry: `{"command": "x", "Commands": "y", "argv": ["z"], "disabled": true}`,
			want:  serverView{Transport: TransportStdio, Command: "x"},
		},
		{
			// JSON.parse keeps the last value of a repeated key too.
			name:  "repeated exact key keeps the last value",
			entry: `{"command": "first", "command": "second"}`,
			want:  serverView{Transport: TransportStdio, Command: "second"},
		},
		{
			// Env names are case-sensitive on Unix, so both are kept.
			name:  "env names that differ by case",
			entry: `{"command": "x", "env": {"Path": "1", "PATH": "2"}}`,
			want: serverView{
				Transport: TransportStdio, Command: "x",
				Env: map[string]string{"Path": "1", "PATH": "2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), "config.json", []byte(`{"mcpServers": {"srv": `+tt.entry+`, "other": {"command": "ok"}}}`))

			servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientCursor, scope: ScopeGlobal})

			other := serverView{
				Name: "other", Client: ClientCursor, Scope: ScopeGlobal, Source: path,
				Transport: TransportStdio, Command: "ok",
			}
			if tt.wantError != "" {
				if got := viewsOf(servers); !reflect.DeepEqual(got, []serverView{other}) {
					t.Errorf("servers = %+v, want only %q", got, "other")
				}
				want := []errWant{{Server: "srv", Reason: tt.wantError}}
				checkFileErrors(t, path, errs, want)
				return
			}

			if len(errs) != 0 {
				t.Fatalf("errors = %v, want none", errs)
			}
			want := tt.want
			want.Name = "srv"
			want.Client = ClientCursor
			want.Scope = ScopeGlobal
			want.Source = path
			if got := viewsOf(servers); !reflect.DeepEqual(got, []serverView{other, want}) {
				t.Errorf("servers = %+v, want %+v", got, []serverView{other, want})
			}
		})
	}
}

// TestParseJSONServersCaseVariantSections checks the exact match of the
// "mcpServers" and "projects" keys, at the top level and in a project.
func TestParseJSONServersCaseVariantSections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		withProjects bool
		wantServers  []string // names, in order
		wantErrors   []errWant
	}{
		{
			// A reader that ignores case would take the second object.
			name: "project mcpServers",
			input: `{"projects": {
				"/a": {"mcpServers": {"x": {"command": "evil"}}, "MCPSERVERS": {"x": {"command": "benign"}}},
				"/b": {"mcpServers": {"y": {"command": "y"}}}}}`,
			withProjects: true,
			wantServers:  []string{"y"},
			wantErrors:   []errWant{{ProjectPath: "/a", Reason: reasonAmbiguousKey}},
		},
		{
			name:         "project variant alone",
			input:        `{"projects": {"/a": {"McpServers": {"x": {"command": "x"}}}}}`,
			withProjects: true,
			wantErrors:   []errWant{{ProjectPath: "/a", Reason: reasonAmbiguousKey}},
		},
		{
			name: "other project keys are not checked",
			input: `{"projects": {
				"/a": {"mcpServers": {"x": {"command": "x"}}, "allowedTools": [], "AllowedTools": []}}}`,
			withProjects: true,
			wantServers:  []string{"x"},
		},
		{
			name: "top-level mcpServers",
			input: `{"mcpServers": {"a": {"command": "a"}}, "MCPServers": {"b": {"command": "b"}},
				"projects": {"/p": {"mcpServers": {"c": {"command": "c"}}}}}`,
			withProjects: true,
			wantServers:  []string{"c"},
			wantErrors:   []errWant{{Reason: reasonAmbiguousKey}},
		},
		{
			name: "top-level projects",
			input: `{"mcpServers": {"a": {"command": "a"}},
				"projects": {"/p": {"mcpServers": {"c": {"command": "c"}}}},
				"Projects": {"/q": {"mcpServers": {"d": {"command": "d"}}}}}`,
			withProjects: true,
			wantServers:  []string{"a"},
			wantErrors:   []errWant{{Reason: reasonAmbiguousKey}},
		},
		{
			// Without withProjects the reader does not use "projects".
			name: "top-level projects variant without withProjects",
			input: `{"mcpServers": {"a": {"command": "a"}},
				"projects": {}, "Projects": {}}`,
			wantServers: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), "config.json", []byte(tt.input))

			servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal, withProjects: tt.withProjects})

			var gotNames []string
			if len(servers) > 0 {
				gotNames = serverNames(servers)
			}
			if !slices.Equal(gotNames, tt.wantServers) {
				t.Errorf("servers = %v, want %v", gotNames, tt.wantServers)
			}
			checkFileErrors(t, path, errs, tt.wantErrors)
		})
	}
}

// TestParseJSONServersLoneSurrogate checks that a lone UTF-16 surrogate
// escape in a server entry or a project key rejects the whole file.
// encoding/json turns "x\ud800" and "x\udc00" into the same "x�", but for
// JSON.parse they are two names. A lone surrogate in a part of the file that
// the reader ignores (for example the chat history of ~/.claude.json) is not
// an error.
func TestParseJSONServersLoneSurrogate(t *testing.T) {
	t.Parallel()

	runBadStringCases(t, []badStringCase{
		{
			name: "server names",
			input: `{"mcpServers": {
  "x\ud800": {"command": "a"},
  "x\udc00": {"command": "b"}}}`,
			wantLine: 2,
			wantCol:  5,
		},
		{
			name:     "low surrogate alone",
			input:    `{"mcpServers": {"x\udc00": {"command": "b"}}}`,
			wantLine: 1,
			wantCol:  19,
		},
		{
			name: "project keys",
			input: `{"projects": {
"/a\udbff": {"mcpServers": {"s": {"command": "a"}}},
"/a\udfff": {"mcpServers": {"s": {"command": "b"}}}}}`,
			wantLine:    2,
			wantCol:     4,
			wantProject: "/a\uFFFD",
		},
		{
			name:        "second project key",
			input:       `{"projects": {"/a": {}, "/b\udfff": {}}}`,
			wantLine:    1,
			wantCol:     28,
			wantProject: "/b\uFFFD",
		},
		{
			name:        "server name of a project",
			input:       `{"projects": {"/p": {"mcpServers": {"x\ud800": {"command": "a"}}}}}`,
			wantLine:    1,
			wantCol:     39,
			wantProject: "/p",
		},
		{
			// Whitespace around the colon must not move the position.
			name:     "whitespace around the colon",
			input:    "{\"n\": 1 ,\"mcpServers\"\t:\n {\"x\\ud800\": {}}}",
			wantLine: 2,
			wantCol:  5,
		},
		{
			// encoding/json keeps the last "mcpServers", but both are checked.
			name:     "first of two mcpServers keys",
			input:    `{"mcpServers": {"x\ud800": {}}, "mcpServers": {"x": {"command": "a"}}}`,
			wantLine: 1,
			wantCol:  19,
		},
		{
			name:     "env keys",
			input:    `{"mcpServers": {"s": {"command": "a", "env": {"K\ud800": "1", "K\udfff": "2"}}}}`,
			wantLine: 1,
			wantCol:  49,
		},
		{
			name:     "upper-case hex",
			input:    `{"mcpServers": {"x\uD800": {"command": "a"}}}`,
			wantLine: 1,
			wantCol:  19,
		},
		{
			name:     "two high surrogates",
			input:    `{"mcpServers": {"x\ud800\ud800": {"command": "a"}}}`,
			wantLine: 1,
			wantCol:  19,
		},
		{
			name:     "low before high",
			input:    `{"mcpServers": {"x\udc00\ud800": {"command": "a"}}}`,
			wantLine: 1,
			wantCol:  19,
		},
		{
			name:     "high before a plain character",
			input:    `{"mcpServers": {"x\ud800y": {"command": "a"}}}`,
			wantLine: 1,
			wantCol:  19,
		},
		{
			name:     "in a value",
			input:    `{"mcpServers": {"x": {"command": "\ud800"}}}`,
			wantLine: 1,
			wantCol:  35,
		},
		// Parts of the file that the reader ignores are not checked.
		{
			name:     "in an ignored top-level value",
			input:    `{"history": ["\ud800"], "mcpServers": {"x": {"command": "a"}}}`,
			wantName: "x",
		},
		{
			name:     "in the chat history",
			input:    `{"history": [{"display": "x\ud83d"}], "mcpServers": {"x": {"command": "a"}}}`,
			wantName: "x",
		},
		{
			name:     "in an ignored top-level key",
			input:    `{"a\ud800": 1, "mcpServers": {"x": {"command": "a"}}}`,
			wantName: "x",
		},
		{
			name:     "in an ignored project field",
			input:    `{"projects": {"/p": {"lastPrompt": "\ud83d", "mcpServers": {"x": {"command": "a"}}}}}`,
			wantName: "x",
		},
		{
			name:     "in an mcpServers below an ignored project field",
			input:    `{"projects": {"/p": {"other": {"mcpServers": {"y\ud800": 1}}, "mcpServers": {"x": {"command": "a"}}}}}`,
			wantName: "x",
		},
		{
			name:     "in a project key of a file read without projects",
			input:    `{"projects": {"/a\ud800": {}}, "mcpServers": {"x": {"command": "a"}}}`,
			cursor:   true,
			wantName: "x",
		},
		{
			name:     "valid pair",
			input:    `{"mcpServers": {"x\ud83d\ude00": {"command": "a"}}}`,
			wantName: "x\U0001F600",
		},
		{
			name:     "escaped backslash is not an escape",
			input:    `{"mcpServers": {"x\\ud800": {"command": "a"}}}`,
			wantName: `x\ud800`,
		},
		{
			name:     "escaped quote and backslash before the text",
			input:    `{"mcpServers": {"x\"\\ud800": {"command": "a"}}}`,
			wantName: `x"\ud800`,
		},
		{
			name:     "escaped backslash then a valid pair",
			input:    `{"mcpServers": {"x\\\ud83d\ude00": {"command": "a"}}}`,
			wantName: "x\\\U0001F600",
		},
		{
			name:     "escape that is not a surrogate",
			input:    `{"mcpServers": {"caf\u00e9": {"command": "a"}}}`,
			wantName: "café",
		},
	})
}

// badStringCase is one case of TestParseJSONServersLoneSurrogate and
// TestParseJSONServersInvalidUTF8.
type badStringCase struct {
	name        string
	input       string
	cursor      bool // read with withProjects=false, as for Cursor
	wantLine    int  // 0: the file is valid and gives wantName
	wantCol     int
	wantProject string
	wantName    string
}

// runBadStringCases reads the input of each case as a global file. A case
// with wantLine 0 must give the one server wantName and no error. Any other
// case must give no server and one "invalid string" error at the exact
// position.
func runBadStringCases(t *testing.T, tests []badStringCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), "config.json", []byte(tt.input))

			servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal, withProjects: !tt.cursor})

			if tt.wantLine == 0 {
				if len(errs) != 0 {
					t.Fatalf("errors = %v, want none", errs)
				}
				if got := serverNames(servers); !slices.Equal(got, []string{tt.wantName}) {
					t.Errorf("servers = %q, want [%q]", got, tt.wantName)
				}
				return
			}
			if len(servers) != 0 {
				t.Errorf("servers = %q, want none", serverNames(servers))
			}
			want := []errWant{{ProjectPath: tt.wantProject, Reason: reasonBadString, Line: tt.wantLine}}
			checkFileErrors(t, path, errs, want)
			e := errs[0]
			if e.Line != tt.wantLine || e.Col != tt.wantCol {
				t.Errorf("position = %d:%d, want %d:%d", e.Line, e.Col, tt.wantLine, tt.wantCol)
			}
		})
	}
}

// TestParseJSONServersEmptyName checks that a server with the name "" gives
// an error and no server. The other servers are still returned.
func TestParseJSONServersEmptyName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantServers []string
		wantErrors  []errWant
	}{
		{
			name:        "top level",
			input:       `{"mcpServers": {"": {"command": "x"}, "ok": {"command": "y"}}}`,
			wantServers: []string{"ok"},
			wantErrors:  []errWant{{Reason: reasonEmptyName}},
		},
		{
			name:       "bad entry with an empty name",
			input:      `{"mcpServers": {"": 5}}`,
			wantErrors: []errWant{{Reason: reasonEmptyName}},
		},
		{
			name:       "in a project",
			input:      `{"projects": {"/a": {"mcpServers": {"": {"command": "x"}}}}}`,
			wantErrors: []errWant{{ProjectPath: "/a", Reason: reasonEmptyName}},
		},
		{
			// An empty project key would give its servers the ProjectPath ""
			// of a global server. The other projects are still read.
			name: "empty project key",
			input: `{"projects": {
				"":   {"mcpServers": {"x": {"command": "x"}}},
				"/b": {"mcpServers": {"ok": {"command": "y"}}}}}`,
			wantServers: []string{"ok"},
			wantErrors:  []errWant{{Reason: reasonEmptyProject}},
		},
		{
			name:       "empty project key that is not an object",
			input:      `{"projects": {"": 5}}`,
			wantErrors: []errWant{{Reason: reasonEmptyProject}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), "config.json", []byte(tt.input))

			servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal, withProjects: true})

			var gotNames []string
			if len(servers) > 0 {
				gotNames = serverNames(servers)
			}
			if !slices.Equal(gotNames, tt.wantServers) {
				t.Errorf("servers = %q, want %q", gotNames, tt.wantServers)
			}
			checkFileErrors(t, path, errs, tt.wantErrors)
		})
	}
}

// TestParseJSONServersProjectPathInErrors checks that an error from
// projects.<path> names the project, and that an error from the top level
// does not, even in a project file.
func TestParseJSONServersProjectPathInErrors(t *testing.T) {
	t.Parallel()

	t.Run("global file", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, t.TempDir(), "config.json", []byte(`{
			"mcpServers": {"x": {"type": "bad"}},
			"projects": {
				"/a": {"mcpServers": {"x": {"type": "bad"}}},
				"/b": 5,
				"/c": {"mcpServers": {"y": {"command": "c", "Command": "d"}}},
				"/d": {"mcpServers": []}}}`))

		_, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal, withProjects: true})

		// Errors without a server come first, then by server name; the same
		// name keeps the top level first.
		want := []string{
			path + ": project /b: " + reasonBadShape,
			path + ": project /d: " + reasonBadServers,
			path + ": server x: " + reasonUnknownTransport,
			path + ": project /a: server x: " + reasonUnknownTransport,
			path + ": project /c: server y: " + reasonAmbiguousKey,
		}
		var got []string
		for _, e := range errs {
			got = append(got, e.Error())
		}
		if !slices.Equal(got, want) {
			t.Errorf("errors =\n%q\nwant\n%q", got, want)
		}
	})

	t.Run("project file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := writeFile(t, dir, "config.json", []byte(`{"mcpServers": {"x": {"type": "bad"}}}`))

		_, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeProject, projectPath: dir})

		want := []string{path + ": server x: " + reasonUnknownTransport}
		var got []string
		for _, e := range errs {
			got = append(got, e.Error())
		}
		if !slices.Equal(got, want) {
			t.Errorf("errors = %q, want %q", got, want)
		}
	})
}

// TestParseJSONServersInvalidUTF8 checks that an invalid UTF-8 byte in a
// server entry or a project key rejects the whole file. encoding/json gives
// one U+FFFD for each bad byte, but the clients give one U+FFFD for each
// maximal bad sequence. So "x\xE2\x82" (one sequence) and "x\xC0\xC0" (two)
// are two names for the client and one name for encoding/json. An invalid
// byte in a part of the file that the reader ignores is not an error.
func TestParseJSONServersInvalidUTF8(t *testing.T) {
	t.Parallel()

	runBadStringCases(t, []badStringCase{
		{
			name:     "server names that encoding/json merges",
			input:    "{\"mcpServers\": {\"x\xE2\x82\": {\"command\": \"a\"}, \"x\xC0\xC0\": {\"command\": \"b\"}}}",
			wantLine: 1,
			wantCol:  19,
		},
		{
			name:     "second server name",
			input:    "{\"mcpServers\": {\"a\": {\"command\": \"a\"},\n  \"b\xFF\": {\"command\": \"b\"}}}",
			wantLine: 2,
			wantCol:  5,
		},
		{
			name:        "project keys",
			input:       "{\"projects\": {\"/a\xFF\": {}, \"/a\xFE\": {}}}",
			wantLine:    1,
			wantCol:     18,
			wantProject: "/a\uFFFD",
		},
		{
			name:        "server name of a project",
			input:       "{\"projects\": {\"/p\": {\"mcpServers\": {\"x\xFF\": {\"command\": \"a\"}}}}}",
			wantLine:    1,
			wantCol:     39,
			wantProject: "/p",
		},
		{
			name:     "env keys",
			input:    "{\"mcpServers\": {\"s\": {\"command\": \"a\", \"env\": {\"K\xFF\": \"1\", \"K\xFE\": \"2\"}}}}",
			wantLine: 1,
			wantCol:  49,
		},
		{
			name:     "in a value",
			input:    "{\"mcpServers\": {\"x\": {\"command\": \"\xFF\"}}}",
			wantLine: 1,
			wantCol:  35,
		},
		{
			// UTF-8 has no encoded surrogates: ED A0 80 would be U+D800.
			name:     "encoded surrogate",
			input:    "{\"mcpServers\": {\"x\xED\xA0\x80\": {\"command\": \"a\"}}}",
			wantLine: 1,
			wantCol:  19,
		},
		{
			// C0 80 is an overlong form of U+0000.
			name:     "overlong encoding",
			input:    "{\"mcpServers\": {\"x\xC0\x80\": {\"command\": \"a\"}}}",
			wantLine: 1,
			wantCol:  19,
		},
		{
			// The lone surrogate comes first, so its position is reported.
			name:     "lone surrogate before a bad byte",
			input:    "{\"mcpServers\": {\"ab\\ud800\": {}, \"\xFF\": {}}}",
			wantLine: 1,
			wantCol:  20,
		},
		{
			name:     "bad byte before a lone surrogate",
			input:    "{\"mcpServers\": {\"ab\xFF\": {}, \"\\ud800\": {}}}",
			wantLine: 1,
			wantCol:  20,
		},
		// Parts of the file that the reader ignores are not checked.
		{
			name:     "in the chat history",
			input:    "{\"history\": [{\"display\": \"x\xE2\x82\"}], \"mcpServers\": {\"x\": {\"command\": \"a\"}}}",
			wantName: "x",
		},
		{
			name:     "in an ignored top-level key",
			input:    "{\"a\xFF\": 1, \"mcpServers\": {\"x\": {\"command\": \"a\"}}}",
			wantName: "x",
		},
		{
			name:     "in an ignored project field",
			input:    "{\"projects\": {\"/p\": {\"lastPrompt\": \"\xFF\", \"mcpServers\": {\"x\": {\"command\": \"a\"}}}}}",
			wantName: "x",
		},
		{
			name:     "in a project key of a file read without projects",
			input:    "{\"projects\": {\"/a\xFF\": {}}, \"mcpServers\": {\"x\": {\"command\": \"a\"}}}",
			cursor:   true,
			wantName: "x",
		},
		// Valid UTF-8 is not an error.
		{
			// The bytes EF BF BD are the valid encoding of U+FFFD.
			name:     "U+FFFD as written",
			input:    "{\"mcpServers\": {\"x\xEF\xBF\xBD\": {\"command\": \"a\"}}}",
			wantName: "x\uFFFD",
		},
		{
			name:     "multi-byte characters",
			input:    "{\"mcpServers\": {\"caf\xC3\xA9 \xF0\x9F\x98\x80\": {\"command\": \"a\"}}}",
			wantName: "café \U0001F600",
		},
	})
}

// TestParseJSONServersUntrusted checks that every server and every error of a
// project file is untrusted, and that nothing of a global file is, also not
// the servers under "projects". As in ReadClaudeCode, only the global file is
// read with withProjects.
func TestParseJSONServersUntrusted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		// wantServers and wantErrors are the numbers that both scopes give,
		// so the Untrusted checks are not empty by accident.
		wantServers int
		wantErrors  int
	}{
		{
			name: "servers and entry errors",
			input: `{"mcpServers": {
				"good": {"command": "x"},
				"remote": {"type": "http", "url": "https://example.com/mcp"},
				"bad": 5,
				"": {"command": "x"},
				"amb": {"command": "x", "Command": "y"},
				"unknown": {"type": "ws"}}}`,
			wantServers: 2,
			wantErrors:  4,
		},
		{name: "invalid JSON", input: `{"mcpServers": `, wantErrors: 1},
		{name: "null file", input: `null`, wantErrors: 1},
		{name: "top-level array", input: `[]`, wantErrors: 1},
		{name: "lone surrogate", input: `{"mcpServers": {"x\ud800": {}}}`, wantErrors: 1},
		{name: "invalid UTF-8", input: "{\"mcpServers\": {\"x\xFF\": {}}}", wantErrors: 1},
		{name: "ambiguous top-level key", input: `{"mcpServers": {}, "MCPServers": {}}`, wantErrors: 1},
		{name: "mcpServers is not an object", input: `{"mcpServers": 1}`, wantErrors: 1},
		{
			name:       "too many servers",
			input:      `{"mcpServers": {` + manyEntries(`"s%d":{"command":"x"}`, maxServersPerFile+1) + `}}`,
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		for _, scope := range []Scope{ScopeGlobal, ScopeProject} {
			t.Run(tt.name+"/"+string(scope), func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				path := writeFile(t, dir, "config.json", []byte(tt.input))
				projectPath := ""
				if scope == ScopeProject {
					projectPath = dir
				}

				servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: scope, projectPath: projectPath, withProjects: scope == ScopeGlobal})

				if len(servers) != tt.wantServers || len(errs) != tt.wantErrors {
					t.Fatalf("got %d servers and %d errors, want %d and %d: %v",
						len(servers), len(errs), tt.wantServers, tt.wantErrors, errs)
				}
				untrusted := scope == ScopeProject
				checkServersUntrusted(t, servers, untrusted)
				checkErrorsUntrusted(t, errs, untrusted)
			})
		}
	}

	t.Run("projects servers and errors of a global file", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, t.TempDir(), "config.json", []byte(`{"projects": {
			"/a": {"mcpServers": {"s": {"command": "x"}, "bad": 5}},
			"/b": 5,
			"/c": {"mcpServers": {"t": {"command": "x"}}, "MCPSERVERS": {}}}}`))

		servers, errs := parseJSONServers(t.Context(), jsonFile{path: path, client: ClientClaudeCode, scope: ScopeGlobal, withProjects: true})

		if len(servers) != 1 || len(errs) != 3 {
			t.Fatalf("got %d servers and %d errors, want 1 and 3: %v", len(servers), len(errs), errs)
		}
		checkServersUntrusted(t, servers, false)
		checkErrorsUntrusted(t, errs, false)
	})
}

// TestParseJSONServersUntrustedReadErrors checks that a read error of a
// project file is untrusted, with and without a projectPath, and that a read
// error of a global file is not.
func TestParseJSONServersUntrustedReadErrors(t *testing.T) {
	t.Parallel()

	// tooLarge is valid JSON one byte over the project limit.
	tooLarge := `{}` + strings.Repeat(" ", maxProjectConfigSize-1)

	tests := []struct {
		name string
		// setup makes the file in dir and returns its path.
		setup      func(t *testing.T, dir string) string
		scope      Scope
		withRoot   bool // pass dir as projectPath
		cancel     bool // cancel the context before the read
		wantReason string
		wantErr    bool // the error must wrap an OS or context error
	}{
		{
			name:       "directory in a project file",
			setup:      func(t *testing.T, dir string) string { return makeDir(t, dir, "config.json") },
			scope:      ScopeProject,
			withRoot:   true,
			wantReason: reasonNotRegular,
		},
		{
			name:       "directory in a project file without a projectPath",
			setup:      func(t *testing.T, dir string) string { return makeDir(t, dir, "config.json") },
			scope:      ScopeProject,
			wantReason: reasonNotRegular,
		},
		{
			name:       "project file too large without a projectPath",
			setup:      func(t *testing.T, dir string) string { return writeFile(t, dir, "config.json", []byte(tooLarge)) },
			scope:      ScopeProject,
			wantReason: reasonTooLarge,
		},
		{
			name:       "canceled read of a project file",
			setup:      func(t *testing.T, dir string) string { return writeFile(t, dir, "config.json", []byte(`{}`)) },
			scope:      ScopeProject,
			withRoot:   true,
			cancel:     true,
			wantReason: reasonCanceled,
			wantErr:    true,
		},
		{
			name:       "canceled read of a project file without a projectPath",
			setup:      func(t *testing.T, dir string) string { return writeFile(t, dir, "config.json", []byte(`{}`)) },
			scope:      ScopeProject,
			cancel:     true,
			wantReason: reasonCanceled,
			wantErr:    true,
		},
		{
			name:       "directory in a global file",
			setup:      func(t *testing.T, dir string) string { return makeDir(t, dir, "config.json") },
			scope:      ScopeGlobal,
			wantReason: reasonNotRegular,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := tt.setup(t, dir)
			projectPath := ""
			if tt.withRoot {
				projectPath = dir
			}
			ctx := t.Context()
			if tt.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			servers, errs := parseJSONServers(ctx, jsonFile{path: path, client: ClientCursor, scope: tt.scope, projectPath: projectPath})

			if len(servers) != 0 {
				t.Errorf("servers = %v, want none", serverNames(servers))
			}
			checkFileErrors(t, path, errs, []errWant{{Reason: tt.wantReason, HasErr: tt.wantErr}})
			checkErrorsUntrusted(t, errs, tt.scope == ScopeProject)
		})
	}
}

// TestReadJSONProjectRoot checks that a project file is read only from below
// its projectPath, or from below its own directory when projectPath is empty.
// A cloned repository could otherwise make mcpmoat read a file of the user,
// for example ~/.claude.json, as its own project file.
func TestReadJSONProjectRoot(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	const content = `{"mcpServers": {"s": {"command": "x"}}}`

	readers := []struct {
		name string
		read jsonReader
		rel  string // the project file below the work directory
	}{
		{name: "claude-code", read: ReadClaudeCode, rel: ".mcp.json"},
		{name: "cursor", read: ReadCursor, rel: ".cursor/mcp.json"},
	}

	tests := []struct {
		name string
		// setup makes the project file below work, maybe as a symlink to a
		// file in outside. It returns the path to read.
		setup func(t *testing.T, work, outside, rel string) string
		scope Scope
		// noRoot passes an empty projectPath. The root is then the
		// directory of the file.
		noRoot     bool
		wantReason string // "" means the file is read and gives server "s"
	}{
		{
			name: "symlink out of the work directory",
			setup: func(t *testing.T, work, outside, rel string) string {
				return symlinkTo(t, writeFile(t, outside, "config.json", []byte(content)), work, rel)
			},
			scope:      ScopeProject,
			wantReason: reasonOutsideProject,
		},
		{
			name: "relative symlink out of the work directory",
			setup: func(t *testing.T, work, outside, rel string) string {
				target := writeFile(t, outside, "config.json", []byte(content))
				link := filepath.Join(work, filepath.FromSlash(rel))
				relTarget, err := filepath.Rel(filepath.Dir(link), target)
				if err != nil {
					t.Fatalf("relative path: %v", err)
				}
				return symlinkTo(t, relTarget, work, rel)
			},
			scope:      ScopeProject,
			wantReason: reasonOutsideProject,
		},
		{
			name: "file not below projectPath",
			setup: func(t *testing.T, _, outside, _ string) string {
				return writeFile(t, outside, "config.json", []byte(content))
			},
			scope:      ScopeProject,
			wantReason: reasonOutsideProject,
		},
		{
			// os.Root follows a relative symlink that stays inside the
			// root. It refuses every absolute symlink.
			name: "relative symlink inside the work directory",
			setup: func(t *testing.T, work, _, rel string) string {
				target := writeFile(t, work, "real/config.json", []byte(content))
				link := filepath.Join(work, filepath.FromSlash(rel))
				relTarget, err := filepath.Rel(filepath.Dir(link), target)
				if err != nil {
					t.Fatalf("relative path: %v", err)
				}
				return symlinkTo(t, relTarget, work, rel)
			},
			scope: ScopeProject,
		},
		{
			name: "absolute symlink inside the work directory",
			setup: func(t *testing.T, work, _, rel string) string {
				target := writeFile(t, work, "real/config.json", []byte(content))
				return symlinkTo(t, target, work, rel)
			},
			scope:      ScopeProject,
			wantReason: reasonOutsideProject,
		},
		{
			name: "symlink out without a projectPath",
			setup: func(t *testing.T, work, outside, rel string) string {
				return symlinkTo(t, writeFile(t, outside, "config.json", []byte(content)), work, rel)
			},
			scope:      ScopeProject,
			noRoot:     true,
			wantReason: reasonOutsideProject,
		},
		{
			name: "relative symlink out without a projectPath",
			setup: func(t *testing.T, work, outside, rel string) string {
				target := writeFile(t, outside, "config.json", []byte(content))
				link := filepath.Join(work, filepath.FromSlash(rel))
				relTarget, err := filepath.Rel(filepath.Dir(link), target)
				if err != nil {
					t.Fatalf("relative path: %v", err)
				}
				return symlinkTo(t, relTarget, work, rel)
			},
			scope:      ScopeProject,
			noRoot:     true,
			wantReason: reasonOutsideProject,
		},
		{
			name: "absolute symlink in the file's directory without a projectPath",
			setup: func(t *testing.T, work, _, rel string) string {
				dir := filepath.Dir(filepath.Join(work, filepath.FromSlash(rel)))
				target := writeFile(t, dir, "real.json", []byte(content))
				return symlinkTo(t, target, work, rel)
			},
			scope:      ScopeProject,
			noRoot:     true,
			wantReason: reasonOutsideProject,
		},
		{
			name: "relative symlink in the file's directory without a projectPath",
			setup: func(t *testing.T, work, _, rel string) string {
				dir := filepath.Dir(filepath.Join(work, filepath.FromSlash(rel)))
				writeFile(t, dir, "real.json", []byte(content))
				return symlinkTo(t, "real.json", work, rel)
			},
			scope:  ScopeProject,
			noRoot: true,
		},
		{
			name: "global file follows a symlink anywhere",
			setup: func(t *testing.T, work, outside, rel string) string {
				return symlinkTo(t, writeFile(t, outside, "config.json", []byte(content)), work, rel)
			},
			scope:  ScopeGlobal,
			noRoot: true,
		},
	}

	for _, r := range readers {
		for _, tt := range tests {
			t.Run(r.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				work, outside := t.TempDir(), t.TempDir()
				path := tt.setup(t, work, outside, r.rel)
				projectPath := work
				if tt.noRoot {
					projectPath = ""
				}

				res := r.read(t.Context(), path, tt.scope, projectPath)

				untrusted := tt.scope == ScopeProject
				checkErrorsUntrusted(t, res.Errors, untrusted)
				checkServersUntrusted(t, res.Servers, untrusted)
				if tt.wantReason != "" {
					if len(res.Servers) != 0 {
						t.Errorf("servers = %v, want none", serverNames(res.Servers))
					}
					checkFileErrors(t, path, res.Errors, []errWant{{Reason: tt.wantReason}})
					return
				}
				checkFileErrors(t, path, res.Errors, nil)
				if got := serverNames(res.Servers); !slices.Equal(got, []string{"s"}) {
					t.Errorf("servers = %v, want [s]", got)
				}
			})
		}
	}
}

// TestReadJSONProjectPathFromFile checks the ProjectPath of a project file
// read without a projectPath. It is the directory of the file. Only the
// Cursor reader skips a ".cursor" directory: the servers of
// <project>/.cursor/mcp.json get <project>, as Discover gives it. A Claude
// Code .mcp.json is at the top of its project.
func TestReadJSONProjectPathFromFile(t *testing.T) {
	t.Parallel()

	const content = `{"mcpServers": {"s": {"command": "x"}}}`

	tests := []struct {
		name string
		read jsonReader
		rel  string // the file below the temporary directory
		// wantRel is the wanted ProjectPath below the temporary directory.
		wantRel string
	}{
		{name: "claude-code/project file", read: ReadClaudeCode, rel: "proj/.mcp.json", wantRel: "proj"},
		{name: "claude-code/in a .cursor directory", read: ReadClaudeCode, rel: "proj/.cursor/.mcp.json", wantRel: "proj/.cursor"},
		{name: "cursor/in .cursor", read: ReadCursor, rel: "proj/.cursor/mcp.json", wantRel: "proj"},
		{name: "cursor/in another directory", read: ReadCursor, rel: "proj/conf/mcp.json", wantRel: "proj/conf"},
		{name: "cursor/name ends with .cursor", read: ReadCursor, rel: "proj/my.cursor/mcp.json", wantRel: "proj/my.cursor"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := writeFile(t, dir, tt.rel, []byte(content))

			res := tt.read(t.Context(), path, ScopeProject, "")

			if len(res.Errors) != 0 {
				t.Fatalf("errors = %v, want none", res.Errors)
			}
			if len(res.Servers) != 1 {
				t.Fatalf("server names = %v, want [s]", serverNames(res.Servers))
			}
			want := filepath.Join(dir, filepath.FromSlash(tt.wantRel))
			if s := res.Servers[0]; s.Scope != ScopeProject || s.ProjectPath != want || !s.Untrusted {
				t.Errorf("server %q scope=%q projectPath=%q untrusted=%v, want %q, %q and true",
					s.Name, s.Scope, s.ProjectPath, s.Untrusted, ScopeProject, want)
			}
		})
	}
}

// TestReadJSONUnknownScope checks that a scope other than ScopeGlobal fails
// closed: the readers read the file as a project file. The read stays below
// the project directory, the smaller size limit holds, every server and
// error is Untrusted, and the servers get ScopeProject. Claude Code does not
// read the "projects" key of such a file.
func TestReadJSONUnknownScope(t *testing.T) {
	t.Parallel()

	const content = `{"mcpServers": {"s": {"command": "x"}},
		"projects": {"/attacker/chosen": {"mcpServers": {"spoofed": {"command": "y"}}}}}`

	readers := []struct {
		name string
		read jsonReader
		rel  string // the project file below the work directory
	}{
		{name: "claude-code", read: ReadClaudeCode, rel: ".mcp.json"},
		{name: "cursor", read: ReadCursor, rel: ".cursor/mcp.json"},
	}

	tests := []struct {
		name string
		// setup makes the file below work, maybe as a symlink to a file in
		// outside. It returns the path to read.
		setup      func(t *testing.T, work, outside, rel string) string
		wantReason string // "" means the file is read and gives server "s"
	}{
		{
			name: "servers are untrusted project servers",
			setup: func(t *testing.T, work, _, rel string) string {
				return writeFile(t, work, rel, []byte(content))
			},
		},
		{
			name: "symlink out of the project is refused",
			setup: func(t *testing.T, work, outside, rel string) string {
				skipOnWindows(t)
				return symlinkTo(t, writeFile(t, outside, "config.json", []byte(content)), work, rel)
			},
			wantReason: reasonOutsideProject,
		},
		{
			name: "file over the project size limit is refused",
			setup: func(t *testing.T, work, _, rel string) string {
				data := content + strings.Repeat(" ", maxProjectConfigSize+1-len(content))
				return writeFile(t, work, rel, []byte(data))
			},
			wantReason: reasonTooLarge,
		},
	}

	for _, r := range readers {
		for _, scope := range []Scope{"", "Project"} {
			for _, tt := range tests {
				t.Run(fmt.Sprintf("%s/scope %q/%s", r.name, scope, tt.name), func(t *testing.T) {
					t.Parallel()
					work, outside := t.TempDir(), t.TempDir()
					path := tt.setup(t, work, outside, r.rel)

					res := r.read(t.Context(), path, scope, work)

					checkErrorsUntrusted(t, res.Errors, true)
					checkServersUntrusted(t, res.Servers, true)
					if tt.wantReason != "" {
						if len(res.Servers) != 0 {
							t.Errorf("servers = %v, want none", serverNames(res.Servers))
						}
						checkFileErrors(t, path, res.Errors, []errWant{{Reason: tt.wantReason}})
						return
					}
					checkFileErrors(t, path, res.Errors, nil)
					if got := serverNames(res.Servers); !slices.Equal(got, []string{"s"}) {
						t.Fatalf("servers = %v, want [s]", got)
					}
					if s := res.Servers[0]; s.Scope != ScopeProject || s.ProjectPath != work {
						t.Errorf("server %q scope=%q projectPath=%q, want %q and %q",
							s.Name, s.Scope, s.ProjectPath, ScopeProject, work)
					}
				})
			}
		}
	}
}

// TestJSONKeys checks the key list of a server entry: every entry in jsonReads
// has a destination, no key is listed twice, and jsonKnownKeys holds the keys
// of jsonReads in order.
func TestJSONKeys(t *testing.T) {
	t.Parallel()

	var e jsonEntry
	reads := jsonReads(&e)
	keys := make([]string, 0, len(reads))
	for _, r := range reads {
		if r.dst == nil {
			t.Errorf("jsonReads: key %q has no destination", r.key)
		}
		if slices.Contains(keys, r.key) {
			t.Errorf("jsonReads: key %q is listed twice", r.key)
		}
		keys = append(keys, r.key)
	}
	if !slices.Equal(jsonKnownKeys, keys) {
		t.Errorf("jsonKnownKeys = %q, want %q", jsonKnownKeys, keys)
	}
}
