package discover

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// writeJSONConfig writes content to a new file in a temporary directory and
// returns the file path. The tests build their own small inputs here; the
// reader tests use the fixtures in testdata/discover.
func writeJSONConfig(t testing.TB, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// errorView is a comparable summary of a FileError: the server name and the
// fixed reason.
type errorView struct {
	Server string
	Reason string
}

// errorViews returns the (Server, Reason) pair of each error, in order.
func errorViews(errs []*FileError) []errorView {
	if len(errs) == 0 {
		return nil
	}
	out := make([]errorView, 0, len(errs))
	for _, e := range errs {
		out = append(out, errorView{Server: e.Server, Reason: e.Reason})
	}
	return out
}

// TestParseJSONServersTransport checks how an entry becomes a transport, one
// server per input, and which fields are kept or dropped.
func TestParseJSONServersTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		entry     string
		want      serverView // used when wantReason is empty
		wantError string     // fixed reason; empty means the server is valid
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
			name:  "no type with url is http",
			entry: `{"url": "https://example.com/mcp", "headers": {"X-Key": "v"}}`,
			want: serverView{
				Transport: TransportHTTP,
				URL:       "https://example.com/mcp",
				Headers:   map[string]string{"X-Key": "v"},
			},
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeJSONConfig(t, `{"mcpServers": {"srv": `+tt.entry+`}}`)

			servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", false)

			if tt.wantError != "" {
				if len(servers) != 0 {
					t.Errorf("servers = %v, want none", serverNames(servers))
				}
				want := []errorView{{Server: "srv", Reason: tt.wantError}}
				if got := errorViews(errs); !reflect.DeepEqual(got, want) {
					t.Fatalf("errors = %v, want %v", got, want)
				}
				if errs[0].Path != path {
					t.Errorf("error Path = %q, want %q", errs[0].Path, path)
				}
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
			want.Client = ClientClaudeCode
			want.Scope = ScopeGlobal
			want.Source = path
			if got := viewsOf(servers); !reflect.DeepEqual(got, []serverView{want}) {
				t.Errorf("servers = %+v, want %+v", got, []serverView{want})
			}
		})
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
		wantErrors  []errorView
	}{
		{
			name: "number env value",
			input: `{"mcpServers": {
				"bad":  {"command": "x", "env": {"PORT": 8080}},
				"good": {"command": "y"}}}`,
			wantServers: []serverView{{Name: "good", Transport: TransportStdio, Command: "y"}},
			wantErrors:  []errorView{{Server: "bad", Reason: reasonBadEntry}},
		},
		{
			name: "null env is an empty env",
			input: `{"mcpServers": {
				"nullenv": {"command": "x", "env": null}}}`,
			wantServers: []serverView{{Name: "nullenv", Transport: TransportStdio, Command: "x"}},
		},
		{
			name: "string entry",
			input: `{"mcpServers": {
				"bad":  "x",
				"good": {"command": "y"}}}`,
			wantServers: []serverView{{Name: "good", Transport: TransportStdio, Command: "y"}},
			wantErrors:  []errorView{{Server: "bad", Reason: reasonBadEntry}},
		},
		{
			name: "array entry and number entry",
			input: `{"mcpServers": {
				"arr": [],
				"num": 5,
				"ok":  {"url": "https://example.com/mcp"}}}`,
			wantServers: []serverView{{Name: "ok", Transport: TransportHTTP, URL: "https://example.com/mcp"}},
			wantErrors: []errorView{
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
			wantErrors:  []errorView{{Server: "bad", Reason: reasonBadEntry}},
		},
		{
			name: "null entry is a server without command or url",
			input: `{"mcpServers": {
				"nothing": null}}`,
			wantErrors: []errorView{{Server: "nothing", Reason: reasonNoCommandOrURL}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeJSONConfig(t, tt.input)

			servers, errs := parseJSONServers(t.Context(), path, ClientCursor, ScopeGlobal, "", false)

			for i := range tt.wantServers {
				tt.wantServers[i].Client = ClientCursor
				tt.wantServers[i].Scope = ScopeGlobal
				tt.wantServers[i].Source = path
			}
			if got := viewsOf(servers); !reflect.DeepEqual(got, tt.wantServers) {
				t.Errorf("servers = %+v, want %+v", got, tt.wantServers)
			}
			if got := errorViews(errs); !reflect.DeepEqual(got, tt.wantErrors) {
				t.Errorf("errors = %v, want %v", got, tt.wantErrors)
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
		wantErrors   []errorView
	}{
		{name: "empty file", input: ``},
		{name: "whitespace-only file", input: " \n\t\r\n "},
		{name: "empty object", input: `{}`},
		{name: "top-level array", input: `[]`, wantErrors: []errorView{{Reason: reasonBadShape}}},
		{name: "top-level number", input: `5`, wantErrors: []errorView{{Reason: reasonBadShape}}},
		{name: "top-level string", input: `"x"`, wantErrors: []errorView{{Reason: reasonBadShape}}},
		{name: "top-level null", input: `null`},
		{
			name:       "mcpServers array",
			input:      `{"mcpServers": []}`,
			wantErrors: []errorView{{Reason: reasonBadServers}},
		},
		{
			name:       "mcpServers string",
			input:      `{"mcpServers": "x"}`,
			wantErrors: []errorView{{Reason: reasonBadServers}},
		},
		{name: "mcpServers null", input: `{"mcpServers": null}`},
		{name: "mcpServers empty object", input: `{"mcpServers": {}}`},
		{
			name:         "projects array",
			input:        `{"projects": []}`,
			withProjects: true,
			wantErrors:   []errorView{{Reason: reasonBadShape}},
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
			wantErrors:   []errorView{{Reason: reasonBadShape}},
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
			wantErrors:   []errorView{{Reason: reasonBadServers}},
		},
		{
			name:         "bad top-level mcpServers keeps the project servers",
			input:        `{"mcpServers": 1, "projects": {"/b": {"mcpServers": {"s": {"command": "x"}}}}}`,
			withProjects: true,
			wantServers:  []string{"s"},
			wantErrors:   []errorView{{Reason: reasonBadServers}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeJSONConfig(t, tt.input)

			servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", tt.withProjects)

			var gotNames []string
			if len(servers) > 0 {
				gotNames = serverNames(servers)
			}
			if !reflect.DeepEqual(gotNames, tt.wantServers) {
				t.Errorf("servers = %v, want %v", gotNames, tt.wantServers)
			}
			if got := errorViews(errs); !reflect.DeepEqual(got, tt.wantErrors) {
				t.Errorf("errors = %v, want %v", got, tt.wantErrors)
			}
			for _, e := range errs {
				if e.Path != path {
					t.Errorf("error Path = %q, want %q", e.Path, path)
				}
			}
		})
	}
}

// TestParseJSONServersMissingFile checks that a missing file gives nothing.
func TestParseJSONServersMissingFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nope.json")

	servers, errs := parseJSONServers(t.Context(), path, ClientCursor, ScopeGlobal, "", false)

	if len(servers) != 0 || len(errs) != 0 {
		t.Errorf("got %d servers and %d errors, want none", len(servers), len(errs))
	}
}

// TestParseJSONServersScopeAndProjectPath checks the Scope, ProjectPath,
// Source and Client of each server.
func TestParseJSONServersScopeAndProjectPath(t *testing.T) {
	t.Parallel()

	const input = `{
		"mcpServers": {"top": {"command": "t"}},
		"projects": {
			"/work/one": {"mcpServers": {"p1": {"command": "p1"}}},
			"/work/two": {"mcpServers": {"p2": {"url": "https://example.com/mcp"}}}
		}
	}`

	tests := []struct {
		name        string
		client      Client
		scope       Scope
		projectPath string
		want        []serverView
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
			name:        "project file",
			client:      ClientClaudeCode,
			scope:       ScopeProject,
			projectPath: "/work/root",
			want: []serverView{
				{
					Name: "p1", Client: ClientClaudeCode, Scope: ScopeProject, ProjectPath: "/work/one",
					Transport: TransportStdio, Command: "p1",
				},
				{
					Name: "top", Client: ClientClaudeCode, Scope: ScopeProject, ProjectPath: "/work/root",
					Transport: TransportStdio, Command: "t",
				},
				{
					Name: "p2", Client: ClientClaudeCode, Scope: ScopeProject, ProjectPath: "/work/two",
					Transport: TransportHTTP, URL: "https://example.com/mcp",
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
			path := writeJSONConfig(t, input)

			servers, errs := parseJSONServers(t.Context(), path, tt.client, tt.scope, tt.projectPath, true)

			if len(errs) != 0 {
				t.Fatalf("errors = %v, want none", errs)
			}
			for i := range tt.want {
				tt.want[i].Source = path
			}
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
	path := writeJSONConfig(t, input)

	// Servers: sorted by (ProjectPath, Name). The empty ProjectPath is the
	// top level of a global file and sorts first.
	wantNames := []string{"alpha", "zeta", "m", "n", "a", "b"}
	wantPaths := []string{"", "", "/a", "/a", "/z", "/z"}
	// Errors: the file-level error (project "/m") first, then by name.
	wantErrors := []errorView{
		{Reason: reasonBadShape},
		{Server: "bad1", Reason: reasonBadEntry},
		{Server: "bad2", Reason: reasonBadEntry},
		{Server: "bada", Reason: reasonBadEntry},
		{Server: "badz", Reason: reasonBadEntry},
	}

	for i := range 30 {
		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

		if got := serverNames(servers); !reflect.DeepEqual(got, wantNames) {
			t.Fatalf("run %d: server names = %v, want %v", i, got, wantNames)
		}
		var gotPaths []string
		for _, s := range servers {
			gotPaths = append(gotPaths, s.ProjectPath)
		}
		if !reflect.DeepEqual(gotPaths, wantPaths) {
			t.Fatalf("run %d: project paths = %v, want %v", i, gotPaths, wantPaths)
		}
		if got := errorViews(errs); !reflect.DeepEqual(got, wantErrors) {
			t.Fatalf("run %d: errors = %v, want %v", i, got, wantErrors)
		}
	}
}

// TestParseJSONServersSyntaxError checks the position of a JSON syntax error
// and that the error text holds no part of the file.
func TestParseJSONServersSyntaxError(t *testing.T) {
	t.Parallel()

	t.Run("missing comma gives line 3", func(t *testing.T) {
		t.Parallel()
		path := writeJSONConfig(t, "{\n  \"a\": 1\n  \"b\": 2\n}")

		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

		if len(servers) != 0 {
			t.Errorf("servers = %v, want none", serverNames(servers))
		}
		if len(errs) != 1 {
			t.Fatalf("got %d errors, want 1: %v", len(errs), errs)
		}
		e := errs[0]
		if e.Reason != reasonInvalidJSON || e.Server != "" || e.Err != nil {
			t.Errorf("error = %+v, want reason %q, no server, no Err", e, reasonInvalidJSON)
		}
		// The parser finds the error at the opening quote of "b": line 3, col 3.
		if e.Line != 3 || e.Col != 3 {
			t.Errorf("position = %d:%d, want 3:3", e.Line, e.Col)
		}
	})

	t.Run("truncated file", func(t *testing.T) {
		t.Parallel()
		const input = `{"mcpServers": {"x": {"command": "a"`
		path := writeJSONConfig(t, input)

		_, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

		if got := errorViews(errs); !reflect.DeepEqual(got, []errorView{{Reason: reasonInvalidJSON}}) {
			t.Fatalf("errors = %v, want one %q", got, reasonInvalidJSON)
		}
		// At an unexpected end of input the error points at the last byte.
		if errs[0].Line != 1 || errs[0].Col != len(input) {
			t.Errorf("position = %d:%d, want 1:%d", errs[0].Line, errs[0].Col, len(input))
		}
	})

	t.Run("not JSON at all", func(t *testing.T) {
		t.Parallel()
		path := writeJSONConfig(t, "not json")

		_, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

		if got := errorViews(errs); !reflect.DeepEqual(got, []errorView{{Reason: reasonInvalidJSON}}) {
			t.Fatalf("errors = %v, want one %q", got, reasonInvalidJSON)
		}
		if strings.Contains(errs[0].Error(), "not json") {
			t.Errorf("error text %q holds file content", errs[0].Error())
		}
	})

	t.Run("invalid escape in a string", func(t *testing.T) {
		t.Parallel()
		path := writeJSONConfig(t, `{"mcpServers": {"x": {"command": "\u00zz"}}}`)

		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

		// The whole file is checked for syntax first, so a bad escape is a
		// syntax error of the file and no server is returned.
		if len(servers) != 0 {
			t.Errorf("servers = %v, want none", serverNames(servers))
		}
		if got := errorViews(errs); !reflect.DeepEqual(got, []errorView{{Reason: reasonInvalidJSON}}) {
			t.Fatalf("errors = %v, want one %q", got, reasonInvalidJSON)
		}
		if errs[0].Line != 1 || errs[0].Col <= 0 {
			t.Errorf("position = %d:%d, want line 1 and col > 0", errs[0].Line, errs[0].Col)
		}
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
				"b": {"url": "https://u:` + urlCanary + `@example.com/mcp?k=` + urlCanary + `",
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
			name: "canary as project key of a bad project",
			input: `{"mcpServers": {"a": {"command": "x"}},
				"projects": {"/` + urlCanary + `": 5}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeJSONConfig(t, tt.input)

			servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

			assertNoLeakServers(t, servers)
			assertNoLeakErrors(t, errs)
		})
	}
}

// TestParseJSONServersCanceledContext checks that a canceled context gives
// one canceled error and no server.
func TestParseJSONServersCanceledContext(t *testing.T) {
	t.Parallel()
	path := writeJSONConfig(t, `{"mcpServers": {"a": {"command": "x"}}}`)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	servers, errs := parseJSONServers(ctx, path, ClientClaudeCode, ScopeGlobal, "", true)

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
	path := writeJSONConfig(t, `{"mcpServers": {
		"a": {"command": "first", "env": {"K": "`+envCanary+`"}},
		"a": {"command": "second"}}}`)

	servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", false)

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

	tests := []struct {
		name     string
		input    string
		wantLine int
		wantCol  int
	}{
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
			path := writeJSONConfig(t, tt.input)

			servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

			if len(servers) != 0 {
				t.Errorf("servers = %v, want none", serverNames(servers))
			}
			if got := errorViews(errs); !reflect.DeepEqual(got, []errorView{{Reason: reasonInvalidJSON}}) {
				t.Fatalf("errors = %v, want one %q", got, reasonInvalidJSON)
			}
			if errs[0].Line != tt.wantLine || errs[0].Col != tt.wantCol {
				t.Errorf("position = %d:%d, want %d:%d", errs[0].Line, errs[0].Col, tt.wantLine, tt.wantCol)
			}
		})
	}
}

// manyEntries returns the body of an "mcpServers" object with n valid entries.
func manyEntries(prefix string, n int) string {
	var b strings.Builder
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"%s%d":{"command":"x"}`, prefix, i)
	}
	return b.String()
}

// emptyProjects returns the body of a "projects" object with n empty projects.
func emptyProjects(n int) string {
	var b strings.Builder
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"/p%d":{}`, i)
	}
	return b.String()
}

// TestParseJSONServersTooManyServers checks the cap on entries per file.
func TestParseJSONServersTooManyServers(t *testing.T) {
	t.Parallel()

	wantOne := []errorView{{Reason: reasonTooManyServers}}

	t.Run("at the cap is accepted", func(t *testing.T) {
		t.Parallel()
		path := writeJSONConfig(t, `{"mcpServers": {`+manyEntries("s", maxServersPerFile)+`}}`)

		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

		if len(servers) != maxServersPerFile || len(errs) != 0 {
			t.Errorf("got %d servers and %d errors, want %d and 0", len(servers), len(errs), maxServersPerFile)
		}
	})

	t.Run("over the cap in mcpServers", func(t *testing.T) {
		t.Parallel()
		path := writeJSONConfig(t, `{"mcpServers": {`+manyEntries("s", maxServersPerFile+1)+`}}`)

		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

		if len(servers) != 0 {
			t.Errorf("got %d servers, want none", len(servers))
		}
		if got := errorViews(errs); !reflect.DeepEqual(got, wantOne) {
			t.Fatalf("errors = %v, want %v", got, wantOne)
		}
		if errs[0].Path != path {
			t.Errorf("error Path = %q, want %q", errs[0].Path, path)
		}
	})

	t.Run("over the cap across projects", func(t *testing.T) {
		t.Parallel()
		// /a fits. /b would go over the cap, so it gives the error and the
		// loop stops: /c is not decoded.
		half := maxServersPerFile/2 + 1
		path := writeJSONConfig(t, `{"projects": {
			"/a": {"mcpServers": {`+manyEntries("a", half)+`}},
			"/b": {"mcpServers": {`+manyEntries("b", half)+`}},
			"/c": {"mcpServers": {"c": {"command": "x"}}}}}`)

		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

		if len(servers) != half {
			t.Errorf("got %d servers, want %d (only /a)", len(servers), half)
		}
		for _, s := range servers {
			if s.ProjectPath != "/a" {
				t.Fatalf("server %q has ProjectPath %q, want /a", s.Name, s.ProjectPath)
			}
		}
		if got := errorViews(errs); !reflect.DeepEqual(got, wantOne) {
			t.Fatalf("errors = %v, want %v", got, wantOne)
		}
	})

	t.Run("empty projects count toward the cap", func(t *testing.T) {
		t.Parallel()
		path := writeJSONConfig(t, `{"projects": {`+emptyProjects(maxServersPerFile+1)+`}}`)

		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

		if len(servers) != 0 {
			t.Errorf("got %d servers, want none", len(servers))
		}
		if got := errorViews(errs); !reflect.DeepEqual(got, wantOne) {
			t.Fatalf("errors = %v, want %v", got, wantOne)
		}
	})

	t.Run("empty projects at the cap are accepted", func(t *testing.T) {
		t.Parallel()
		path := writeJSONConfig(t, `{"projects": {`+emptyProjects(maxServersPerFile)+`}}`)

		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

		if len(servers) != 0 || len(errs) != 0 {
			t.Errorf("got %d servers and %d errors, want none", len(servers), len(errs))
		}
	})

	t.Run("projects and servers together go over the cap", func(t *testing.T) {
		t.Parallel()
		// 5000 projects plus 5001 top-level servers is one over the cap. The
		// top level is decoded first and fits (5001), so the projects give
		// the one error when the count reaches the cap.
		path := writeJSONConfig(t, `{"mcpServers": {`+manyEntries("t", maxServersPerFile/2+1)+`},
			"projects": {`+emptyProjects(maxServersPerFile/2)+`}}`)

		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

		if len(servers) != maxServersPerFile/2+1 {
			t.Errorf("got %d servers, want %d (top level only)", len(servers), maxServersPerFile/2+1)
		}
		if got := errorViews(errs); !reflect.DeepEqual(got, wantOne) {
			t.Fatalf("errors = %v, want %v", got, wantOne)
		}
	})

	t.Run("top level and projects share the cap", func(t *testing.T) {
		t.Parallel()
		path := writeJSONConfig(t, `{"mcpServers": {`+manyEntries("t", maxServersPerFile)+`},
			"projects": {"/p": {"mcpServers": {"extra": {"command": "x"}}}}}`)

		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", true)

		if len(servers) != maxServersPerFile {
			t.Errorf("got %d servers, want %d (top level only)", len(servers), maxServersPerFile)
		}
		if got := errorViews(errs); !reflect.DeepEqual(got, wantOne) {
			t.Fatalf("errors = %v, want %v", got, wantOne)
		}
	})
}

// TestParseJSONServersStableOrder checks that servers with the same
// (ProjectPath, Name) keep their input order: the top-level server first, then
// the project server.
func TestParseJSONServersStableOrder(t *testing.T) {
	t.Parallel()

	// The file is read as a project file for "/p", and it also has a project
	// "/p" with a server of the same name.
	path := writeJSONConfig(t, `{
		"mcpServers": {"dup": {"command": "top"}},
		"projects": {"/p": {"mcpServers": {"dup": {"command": "project"}}}}}`)

	for i := range 20 {
		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeProject, "/p", true)

		if len(errs) != 0 {
			t.Fatalf("run %d: errors = %v, want none", i, errs)
		}
		var commands []string
		for _, s := range servers {
			commands = append(commands, s.Command)
		}
		if want := []string{"top", "project"}; !reflect.DeepEqual(commands, want) {
			t.Fatalf("run %d: commands = %v, want %v", i, commands, want)
		}
	}
}

// TestParseJSONServersSizeLimitByScope checks that a project file has the
// smaller size limit and a global file keeps the larger one.
func TestParseJSONServersSizeLimitByScope(t *testing.T) {
	t.Parallel()

	// Valid JSON with trailing spaces, one byte over the project limit.
	const body = `{"mcpServers": {"s": {"command": "x"}}}`
	content := body + strings.Repeat(" ", maxProjectConfigSize+1-len(body))
	if len(content) != maxProjectConfigSize+1 {
		t.Fatalf("test input has %d bytes, want %d", len(content), maxProjectConfigSize+1)
	}

	t.Run("project scope is refused", func(t *testing.T) {
		t.Parallel()
		path := writeJSONConfig(t, content)

		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeProject, "/work", false)

		if len(servers) != 0 {
			t.Errorf("got %d servers, want none", len(servers))
		}
		if got := errorViews(errs); !reflect.DeepEqual(got, []errorView{{Reason: reasonTooLarge}}) {
			t.Fatalf("errors = %v, want one %q", got, reasonTooLarge)
		}
	})

	t.Run("project scope at the limit is read", func(t *testing.T) {
		t.Parallel()
		path := writeJSONConfig(t, content[:maxProjectConfigSize])

		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeProject, "/work", false)

		if len(errs) != 0 || len(servers) != 1 {
			t.Errorf("got %d servers and errors %v, want 1 server and none", len(servers), errs)
		}
	})

	t.Run("global scope is read", func(t *testing.T) {
		t.Parallel()
		path := writeJSONConfig(t, content)

		servers, errs := parseJSONServers(t.Context(), path, ClientClaudeCode, ScopeGlobal, "", false)

		if len(errs) != 0 || len(servers) != 1 {
			t.Errorf("got %d servers and errors %v, want 1 server and none", len(servers), errs)
		}
	})
}
