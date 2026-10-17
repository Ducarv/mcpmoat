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
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// codexConfigPath returns the path of the Codex config file inside home.
func codexConfigPath(home string) string {
	return filepath.Join(home, ".codex", "config.toml")
}

// writeCodexConfig writes content as a Codex config file in a new temporary
// home directory and returns the path of the file.
func writeCodexConfig(t testing.TB, content string) string {
	t.Helper()
	path := codexConfigPath(t.TempDir())
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	return path
}

// keyParts returns a key with n parts separated by dots, for example "a.a.a"
// for n = 3.
func keyParts(n int) string {
	return strings.TrimSuffix(strings.Repeat("a.", n), ".")
}

// codexWantError is the part of a FileError that a test checks.
type codexWantError struct {
	server string
	reason string
	line   int // 0 means the reader must not report a line
	colSet bool
}

// checkCodexErrors compares errs with want, in order. It checks that every
// error names path, has no OS error and has the wanted server, reason and
// position.
func checkCodexErrors(t *testing.T, path string, errs []*FileError, want []codexWantError) {
	t.Helper()
	if len(errs) != len(want) {
		t.Fatalf("got %d errors, want %d: %v", len(errs), len(want), errs)
	}
	for i, w := range want {
		e := errs[i]
		if e.Path != path {
			t.Errorf("errs[%d].Path = %q, want %q", i, e.Path, path)
		}
		if e.Server != w.server {
			t.Errorf("errs[%d].Server = %q, want %q", i, e.Server, w.server)
		}
		if e.Reason != w.reason {
			t.Errorf("errs[%d].Reason = %q, want %q", i, e.Reason, w.reason)
		}
		if e.Line != w.line {
			t.Errorf("errs[%d].Line = %d, want %d", i, e.Line, w.line)
		}
		if w.colSet != (e.Col > 0) {
			t.Errorf("errs[%d].Col = %d, want a positive column: %v", i, e.Col, w.colSet)
		}
		if e.Err != nil {
			t.Errorf("errs[%d].Err = %v, want nil for a parse problem", i, e.Err)
		}
	}
}

func TestReadCodexFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		fixture    string
		wantServer []serverView // Source is filled in with the copied path
		wantErrs   []codexWantError
	}{
		{
			name:    "valid",
			fixture: "valid",
			wantServer: []serverView{
				{
					Name:      "docs",
					Transport: TransportStdio,
					Command:   "npx",
					Args:      []string{"-y", "mcp-docs"},
					Env:       map[string]string{"LOG_LEVEL": "info"},
				},
				{
					// cwd, enabled and startup_timeout_sec are ignored.
					Name:      "git",
					Transport: TransportStdio,
					Command:   "uvx",
					Args:      []string{"mcp-server-git", "--repository", "."},
				},
				{
					// bearer_token_env_var and env_http_headers are not mapped.
					Name:      "remote",
					Transport: TransportHTTP,
					URL:       "https://codex.example.com/mcp",
				},
			},
		},
		{
			name:    "empty",
			fixture: "empty",
		},
		{
			name:    "missing",
			fixture: "missing",
		},
		{
			name:    "malformed",
			fixture: "malformed",
			wantErrs: []codexWantError{
				{reason: reasonInvalidTOML, line: 3, colSet: true},
			},
		},
		{
			name:    "invalid-entries",
			fixture: "invalid-entries",
			wantServer: []serverView{
				{
					Name:      "good",
					Transport: TransportStdio,
					Command:   "npx",
					Args:      []string{"-y", "mcp-docs"},
				},
			},
			// Errors are sorted by server name.
			wantErrs: []codexWantError{
				{server: "args-str", reason: reasonBadEntry},
				{server: "nothing", reason: reasonNoCommandOrURL},
				{server: "num-env", reason: reasonBadEntry},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, _ := copyFixture(t, "codex", tt.fixture)
			path := codexConfigPath(home)

			r := ReadCodex(t.Context(), path)

			want := make([]serverView, 0, len(tt.wantServer))
			for _, w := range tt.wantServer {
				w.Client = ClientCodex
				w.Scope = ScopeGlobal
				w.ProjectPath = ""
				w.Source = path
				want = append(want, w)
			}
			if len(want) == 0 {
				want = nil
			}
			if got := viewsOf(r.Servers); !reflect.DeepEqual(got, want) {
				t.Errorf("servers =\n%+v\nwant\n%+v", got, want)
			}
			checkCodexErrors(t, path, r.Errors, tt.wantErrs)

			assertNoLeakErrors(t, r.Errors)
			assertNoLeakServers(t, r.Servers)
		})
	}
}

func TestReadCodexSecrets(t *testing.T) {
	t.Parallel()

	dir := fixtureDir(t, "codex", "secrets")
	assertFixtureHasCanaries(t, codexConfigPath(filepath.Join(dir, "home")))

	home, _ := copyFixture(t, "codex", "secrets")
	path := codexConfigPath(home)
	r := ReadCodex(t.Context(), path)

	checkCodexErrors(t, path, r.Errors, nil)
	if got := serverNames(r.Servers); !reflect.DeepEqual(got, []string{"s1", "s2"}) {
		t.Fatalf("server names = %v, want [s1 s2]", got)
	}

	// The failure messages below name the field only, never the value.
	s1 := r.Servers[0]
	if s1.Transport != TransportStdio || s1.Command != "x" {
		t.Errorf("s1 transport = %q, command = %q, want stdio and x", s1.Transport, s1.Command)
	}
	if keys := s1.Env.Keys(); !reflect.DeepEqual(keys, []string{"API_KEY"}) {
		t.Errorf("s1 env keys = %v, want [API_KEY]", keys)
	}
	if s1.Env["API_KEY"].Reveal() != discovertest.CanaryEnv {
		t.Error("s1 env API_KEY does not reveal the env canary")
	}

	s2 := r.Servers[1]
	if s2.Transport != TransportHTTP {
		t.Errorf("s2 transport = %q, want http", s2.Transport)
	}
	wantURL := "https://user:" + discovertest.CanaryURL + "@codex.example.com/mcp?key=" + discovertest.CanaryURL
	if s2.URL.Reveal() != wantURL {
		t.Error("s2 URL does not reveal the URL canary")
	}
	if keys := s2.Headers.Keys(); !reflect.DeepEqual(keys, []string{"Authorization"}) {
		t.Errorf("s2 header keys = %v, want [Authorization]", keys)
	}
	if s2.Headers["Authorization"].Reveal() != "Bearer "+discovertest.CanaryHeader {
		t.Error("s2 header Authorization does not reveal the header canary")
	}
	for _, s := range r.Servers {
		if s.Client != ClientCodex || s.Scope != ScopeGlobal || s.ProjectPath != "" || s.Source != path {
			t.Errorf("server %q has wrong client, scope, project path or source", s.Name)
		}
	}

	assertNoLeakServers(t, r.Servers)
	assertNoLeakErrors(t, r.Errors)
}

// TestReadCodexInline covers files that are too small for a fixture. Each
// config is written to a temporary home directory.
func TestReadCodexInline(t *testing.T) {
	t.Parallel()

	// bad is a distinctive value. No error text may hold it.
	const bad = "7391025"

	tests := []struct {
		name       string
		config     string
		wantNames  []string
		wantErrs   []codexWantError
		wantLeaked []string // extra strings that no error text may hold
	}{
		{
			name:       "url is a number",
			config:     "[mcp_servers.x]\nurl = " + bad + "\n",
			wantErrs:   []codexWantError{{server: "x", reason: reasonBadEntry}},
			wantLeaked: []string{bad},
		},
		{
			name:       "url is a boolean",
			config:     "[mcp_servers.x]\nurl = true\n",
			wantErrs:   []codexWantError{{server: "x", reason: reasonBadEntry}},
			wantLeaked: []string{"true"},
		},
		{
			name: "http_headers value is a number",
			config: "[mcp_servers.x]\nurl = \"https://example.com/mcp\"\n\n" +
				"[mcp_servers.x.http_headers]\nAuthorization = " + bad + "\n",
			wantErrs:   []codexWantError{{server: "x", reason: reasonBadEntry}},
			wantLeaked: []string{bad},
		},
		{
			name:       "env value is a boolean",
			config:     "[mcp_servers.x]\ncommand = \"c\"\nenv = { K = true }\n",
			wantErrs:   []codexWantError{{server: "x", reason: reasonBadEntry}},
			wantLeaked: []string{"true"},
		},
		{
			name:       "command is a number",
			config:     "[mcp_servers.x]\ncommand = " + bad + "\n",
			wantErrs:   []codexWantError{{server: "x", reason: reasonBadEntry}},
			wantLeaked: []string{bad},
		},
		{
			name:       "args is a string with a canary",
			config:     "[mcp_servers.x]\ncommand = \"c\"\nargs = \"" + discovertest.CanaryEnv + "\"\n",
			wantErrs:   []codexWantError{{server: "x", reason: reasonBadEntry}},
			wantLeaked: []string{discovertest.CanaryEnv},
		},
		{
			name:       "args holds a number",
			config:     "[mcp_servers.x]\ncommand = \"c\"\nargs = [\"a\", " + bad + "]\n",
			wantErrs:   []codexWantError{{server: "x", reason: reasonBadEntry}},
			wantLeaked: []string{bad},
		},
		{
			name:       "server is not a table",
			config:     "[mcp_servers]\nx = " + bad + "\n",
			wantErrs:   []codexWantError{{server: "x", reason: reasonBadEntry}},
			wantLeaked: []string{bad},
		},
		{
			name:      "server name with a dot",
			config:    "[mcp_servers.\"a.b\"]\ncommand = \"c\"\nargs = [\"x\"]\n",
			wantNames: []string{"a.b"},
		},
		{
			name:      "server name with a space and unicode",
			config:    "[mcp_servers.\"my server é\"]\ncommand = \"c\"\n",
			wantNames: []string{"my server é"},
		},
		{
			name:      "mixed-type array in another section is ignored",
			config:    "[model_providers]\nx = [1, \"a\"]\n\n[mcp_servers.ok]\ncommand = \"c\"\n",
			wantNames: []string{"ok"},
		},
		{
			name:      "other sections with unrelated shapes are ignored",
			config:    "model = 5\nprofiles = \"s\"\n\n[mcp_servers.ok]\nurl = \"https://example.com/mcp\"\n",
			wantNames: []string{"ok"},
		},
		{
			name:      "command wins over url",
			config:    "[mcp_servers.both]\ncommand = \"c\"\nurl = \"https://example.com/mcp\"\n",
			wantNames: []string{"both"},
		},
		{
			name:     "empty command and no url",
			config:   "[mcp_servers.x]\ncommand = \"\"\n",
			wantErrs: []codexWantError{{server: "x", reason: reasonNoCommandOrURL}},
		},
		{
			name:       "syntax error reports its line and keeps the value out",
			config:     "a = 1\nb = 2\nc = \"" + discovertest.CanaryEnv + "\" " + discovertest.CanaryEnv + "\n",
			wantErrs:   []codexWantError{{reason: reasonInvalidTOML, line: 3, colSet: true}},
			wantLeaked: []string{discovertest.CanaryEnv},
		},
		{
			name:       "duplicate key is a TOML error",
			config:     "a = 1\na = " + bad + "\n",
			wantErrs:   []codexWantError{{reason: reasonInvalidTOML, line: 2, colSet: true}},
			wantLeaked: []string{bad},
		},
		{
			name:   "whitespace and comments only",
			config: "\n  \n# only a comment\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeCodexConfig(t, tt.config)

			r := ReadCodex(t.Context(), path)

			if tt.wantNames == nil && len(r.Servers) != 0 {
				t.Errorf("server names = %v, want none", serverNames(r.Servers))
			}
			if tt.wantNames != nil && !reflect.DeepEqual(serverNames(r.Servers), tt.wantNames) {
				t.Errorf("server names = %v, want %v", serverNames(r.Servers), tt.wantNames)
			}
			checkCodexErrors(t, path, r.Errors, tt.wantErrs)

			for i, e := range r.Errors {
				for _, leaked := range tt.wantLeaked {
					if strings.Contains(e.Error(), leaked) {
						t.Errorf("errs[%d].Error() = %q holds the bad value %q", i, e.Error(), leaked)
					}
				}
			}
			assertNoLeakErrors(t, r.Errors)
			assertNoLeakServers(t, r.Servers)
		})
	}
}

// TestReadCodexTransport checks the transport and the dropped fields of a
// server that has both a command and a url, and of the stdio and http paths.
func TestReadCodexTransport(t *testing.T) {
	t.Parallel()

	config := `
[mcp_servers.both]
command = "c"
args = ["a"]
env = { K = "v1" }
url = "https://example.com/mcp"
http_headers = { H = "v2" }

[mcp_servers.web]
url = "https://example.com/web"
http_headers = { H = "v3" }
command = ""
args = ["dropped"]
env = { E = "dropped" }
`
	path := writeCodexConfig(t, config)
	r := ReadCodex(t.Context(), path)
	checkCodexErrors(t, path, r.Errors, nil)

	want := []serverView{
		{
			// A command makes the server stdio. The url and headers are dropped.
			Name: "both", Client: ClientCodex, Scope: ScopeGlobal, Source: path,
			Transport: TransportStdio, Command: "c", Args: []string{"a"},
			Env: map[string]string{"K": "v1"},
		},
		{
			// An HTTP server never carries command, args or env.
			Name: "web", Client: ClientCodex, Scope: ScopeGlobal, Source: path,
			Transport: TransportHTTP, URL: "https://example.com/web",
			Headers: map[string]string{"H": "v3"},
		},
	}
	if got := viewsOf(r.Servers); !reflect.DeepEqual(got, want) {
		t.Errorf("servers =\n%+v\nwant\n%+v", got, want)
	}
}

func TestReadCodexFileProblems(t *testing.T) {
	t.Parallel()

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		r := ReadCodex(t.Context(), codexConfigPath(t.TempDir()))
		if len(r.Servers) != 0 || len(r.Errors) != 0 {
			t.Errorf("got %d servers and %d errors, want an empty Result", len(r.Servers), len(r.Errors))
		}
	})

	t.Run("path is a directory", func(t *testing.T) {
		t.Parallel()
		path := codexConfigPath(t.TempDir())
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		r := ReadCodex(t.Context(), path)
		if len(r.Servers) != 0 {
			t.Errorf("got %d servers, want none", len(r.Servers))
		}
		checkCodexErrors(t, path, r.Errors, []codexWantError{{reason: reasonNotRegular}})
	})

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		path := writeCodexConfig(t, "[mcp_servers.a]\ncommand = \"c\"\n")
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		r := ReadCodex(ctx, path)
		if len(r.Servers) != 0 {
			t.Errorf("got %d servers, want none", len(r.Servers))
		}
		if len(r.Errors) != 1 || !errors.Is(r.Errors[0], context.Canceled) {
			t.Errorf("errors = %v, want one error that wraps context.Canceled", r.Errors)
		}
	})
}

// TestReadCodexBadShape checks a mcp_servers key that is not a table.
//
// The TOML library does not report an error for these values, so readCodex
// checks the type of the key itself. Each case must give one reasonBadShape
// error and no servers.
func TestReadCodexBadShape(t *testing.T) {
	t.Parallel()

	const bad = "7391025"
	tests := []struct {
		name   string
		config string
		leaked string
	}{
		{name: "number", config: "mcp_servers = " + bad + "\n", leaked: bad},
		{name: "string", config: "mcp_servers = \"" + discovertest.CanaryHeader + "\"\n", leaked: discovertest.CanaryHeader},
		{name: "array", config: "mcp_servers = [" + bad + "]\n", leaked: bad},
		{name: "array of tables", config: "[[mcp_servers]]\ncommand = \"" + bad + "\"\n", leaked: bad},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeCodexConfig(t, tt.config)
			r := ReadCodex(t.Context(), path)
			if len(r.Servers) != 0 {
				t.Errorf("got %d servers, want none", len(r.Servers))
			}
			checkCodexErrors(t, path, r.Errors, []codexWantError{{reason: reasonBadShape}})
			for _, e := range r.Errors {
				if strings.Contains(e.Error(), tt.leaked) {
					t.Errorf("Error() = %q holds the bad value", e.Error())
				}
			}
			assertNoLeakErrors(t, r.Errors)
		})
	}
}

// TestTOMLShapeOK checks the bracket and key scanner on its own.
func TestTOMLShapeOK(t *testing.T) {
	t.Parallel()

	nested := func(open, closing string, n int) string {
		return "a = " + strings.Repeat(open, n) + strings.Repeat(closing, n) + "\n"
	}
	tests := []struct {
		name  string
		input string
		limit int
		want  bool
	}{
		{name: "empty", input: "", limit: 2, want: true},
		{name: "inline tables at the limit", input: "a = " + strings.Repeat("{a=", 15) + "1" + strings.Repeat("}", 15) + "\n", limit: 16, want: true},
		{name: "arrays at the limit", input: nested("[", "]", 16), limit: 16, want: true},
		{name: "arrays over the limit", input: nested("[", "]", 17), limit: 16, want: false},
		{name: "inline tables over the limit", input: "a = " + strings.Repeat("{a=", 17) + "1" + strings.Repeat("}", 17) + "\n", limit: 16, want: false},
		{name: "unclosed brackets count", input: strings.Repeat("[", 17), limit: 16, want: false},
		{name: "closing brackets alone stay at zero", input: strings.Repeat("]", 100) + "a = [[1]]\n", limit: 2, want: true},
		{name: "table headers", input: "[a.b]\nx = 1\n[[c]]\ny = [1]\n", limit: 3, want: true},
		{name: "comment", input: "# [[[[[[[[\na = 1\n", limit: 2, want: true},
		{name: "comment at the end without newline", input: "a = 1 # [[[[[[[[", limit: 2, want: true},
		{name: "brackets after a comment count", input: "# x\na = [[[1]]]\n", limit: 2, want: false},
		{name: "basic string", input: `a = "[[[[[[[["` + "\n", limit: 2, want: true},
		{name: "basic string with an escaped quote", input: `a = "\"[[[[[[[["` + "\n", limit: 2, want: true},
		{name: "literal string", input: "a = '[[[[[[[['\n", limit: 2, want: true},
		{name: "literal string keeps a backslash", input: `a = '\'` + "\nb = [[[1]]]\n", limit: 2, want: false},
		{name: "multi-line basic string", input: "a = \"\"\"\n[[[[[[[[\n\"\"\"\n", limit: 2, want: true},
		{name: "multi-line literal string", input: "a = '''\n{{{{{{{{\n'''\n", limit: 2, want: true},
		{name: "multi-line string with quotes before the end", input: "a = \"\"\"x\"\"\"\"\nb = [[[1]]]\n", limit: 2, want: false},
		{name: "brackets after a multi-line string count", input: "a = '''x'''\nb = [[[1]]]\n", limit: 2, want: false},
		{name: "quoted key in a header", input: "[\"a[[[[[b\"]\nx = 1\n", limit: 2, want: true},
		{name: "string that is not closed ends at the line", input: "a = \"[[[\nb = [[[1]]]\n", limit: 2, want: false},
		{name: "header with 16 parts", input: "[" + keyParts(16) + "]\n", limit: 64, want: true},
		{name: "header with 17 parts", input: "[" + keyParts(17) + "]\n", limit: 64, want: false},
		{name: "array header with 17 parts", input: "[[" + keyParts(17) + "]]\n", limit: 64, want: false},
		{name: "dotted key with 16 parts", input: keyParts(16) + " = 1\n", limit: 64, want: true},
		{name: "dotted key with 17 parts", input: keyParts(17) + " = 1\n", limit: 64, want: false},
		{name: "dotted key in an inline table with 17 parts", input: "t = { " + keyParts(17) + " = 1 }\n", limit: 64, want: false},
		{name: "the counter restarts on each line", input: strings.Repeat(keyParts(10)+" = 1\n", 5), limit: 64, want: true},
		{name: "the header is the base of the keys below it", input: "[" + keyParts(8) + "]\n" + keyParts(8) + " = 1\n", limit: 64, want: true},
		{name: "header and key over the limit", input: "[" + keyParts(8) + "]\n" + keyParts(9) + " = 1\n", limit: 64, want: false},
		{name: "the next header drops the base", input: "[" + keyParts(15) + "]\nb = 1\n[a]\n" + keyParts(15) + " = 1\n", limit: 64, want: true},
		{name: "header, key and inline table at 16 parts", input: "[a.b]\nc.d = { e.f = { g.h = { i.j.k.l.m.n.o.p = 1 } } }\n", limit: 64, want: true},
		{name: "header, key and inline table at 17 parts", input: "[a.b]\nc.d = { e.f = { g.h = { i.j.k.l.m.n.o.p.q = 1 } } }\n", limit: 64, want: false},
		{name: "sibling inline tables do not add up", input: "t = { " + keyParts(8) + " = 1, " + keyParts(8) + " = 2 }\n", limit: 64, want: true},
		{name: "inline tables in an array do not add up", input: "t = [" + strings.Repeat("{ "+keyParts(8)+" = 1 }, ", 20) + "]\n", limit: 64, want: true},
		{name: "the base returns after an inline table closes", input: "t = { " + keyParts(8) + " = {} }\n" + keyParts(16) + " = 1\n", limit: 64, want: true},
		{name: "nested inline table bypass", input: "x0 = " + strings.Repeat("{"+keyParts(63)+"=", 63) + "1" + strings.Repeat("}", 63) + "\n", limit: 64, want: false},
		{name: "arrays add depth but no parts", input: "t = [[[" + keyParts(1) + "]]]\n[a]\n" + keyParts(15) + " = [[1.5]]\n", limit: 64, want: true},
		{name: "real shape: sub-table", input: "[mcp_servers.x]\ncommand = \"c\"\n[mcp_servers.x.env]\nAPI_KEY = \"v\"\n", limit: 16, want: true},
		{name: "real shape: inline headers", input: "[mcp_servers.x]\nurl = \"http://h\"\nhttp_headers = { Authorization = \"v\" }\n", limit: 16, want: true},
		{name: "real shape: dotted keys at the root", input: "mcp_servers.x.env.API_KEY = \"v\"\nmcp_servers.x.command = \"c\"\n", limit: 16, want: true},
		{name: "dots in a quoted key do not count", input: "[\"" + strings.Repeat("a.", 200) + "\"]\nx = 1\n", limit: 64, want: true},
		{name: "dots in a literal quoted key do not count", input: "'" + strings.Repeat("a.", 200) + "' = 1\n", limit: 64, want: true},
		{name: "dots in a string value do not count", input: "a = \"" + strings.Repeat("a.", 200) + "\"\n", limit: 64, want: true},
		{name: "dots in a multi-line string do not count", input: "a = \"\"\"" + strings.Repeat("a.", 200) + "\"\"\"\n", limit: 64, want: true},
		{name: "dots in a comment do not count", input: "# " + strings.Repeat("a.", 200) + "\nx = 1\n", limit: 64, want: true},
		{name: "dots in a comment at the end do not count", input: "x = 1 # " + strings.Repeat("a.", 200), limit: 64, want: true},
		{name: "floats and dates", input: "f = 1.5\nd = 1979-05-27T07:32:00.999\nt = 07:32:00.999\n", limit: 64, want: true},
		{name: "many floats in an array", input: "a = [" + strings.Repeat("1.5, ", 200) + "]\n", limit: 64, want: true},
		{name: "many floats in an inline table", input: "t = { " + strings.Repeat("a = 1.5, ", 200) + "z = 1 }\n", limit: 64, want: true},
		{name: "quoted part and plain parts", input: "[a.\"b.c\"." + keyParts(14) + "]\n", limit: 64, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tomlShapeOK([]byte(tt.input), tt.limit, maxTOMLKeyParts); got != tt.want {
				t.Errorf("tomlShapeOK(%q, %d, %d) = %v, want %v", tt.input, tt.limit, maxTOMLKeyParts, got, tt.want)
			}
		})
	}
}

// TestReadCodexTooDeep checks that deep nesting gives one reasonTooDeep error
// and does not reach the TOML parser. Without the check, the parser can use
// gigabytes of memory or crash the process.
func TestReadCodexTooDeep(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config string
	}{
		{name: "inline tables", config: "a = " + strings.Repeat("{a=", maxTOMLDepth+1) + "1" + strings.Repeat("}", maxTOMLDepth+1) + "\n"},
		{name: "arrays", config: "a = " + strings.Repeat("[", maxTOMLDepth+1) + strings.Repeat("]", maxTOMLDepth+1) + "\n"},
		{name: "256 KiB of nested arrays", config: strings.Repeat("[", maxTOMLSize)},
		{name: "inline tables, 63 levels with 63 dots in each key", config: "x0 = " + strings.Repeat("{"+keyParts(63)+"=", 63) + "1" + strings.Repeat("}", 63) + "\n"},
		{name: "deep input after a valid server", config: "[mcp_servers.ok]\ncommand = \"c\"\n\n[x]\na = " + strings.Repeat("{a=", 5000) + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeCodexConfig(t, tt.config)
			r := ReadCodex(t.Context(), path)
			if len(r.Servers) != 0 {
				t.Errorf("got %d servers, want none", len(r.Servers))
			}
			checkCodexErrors(t, path, r.Errors, []codexWantError{{reason: reasonTooDeep}})
		})
	}

	t.Run("depth at the limit is accepted", func(t *testing.T) {
		t.Parallel()
		config := "[mcp_servers.ok]\ncommand = \"c\"\n\n[x]\na = " +
			strings.Repeat("[", maxTOMLDepth) + strings.Repeat("]", maxTOMLDepth) + "\n"
		path := writeCodexConfig(t, config)
		r := ReadCodex(t.Context(), path)
		checkCodexErrors(t, path, r.Errors, nil)
		if got := serverNames(r.Servers); !reflect.DeepEqual(got, []string{"ok"}) {
			t.Errorf("server names = %v, want [ok]", got)
		}
	})

	t.Run("brackets in a comment and in a string do not count", func(t *testing.T) {
		t.Parallel()
		config := "# " + strings.Repeat("[", 200) + "\n" +
			"[mcp_servers.ok]\ncommand = \"c\"\nargs = [\"" + strings.Repeat("[", 200) + "\"]\n"
		path := writeCodexConfig(t, config)
		r := ReadCodex(t.Context(), path)
		checkCodexErrors(t, path, r.Errors, nil)
		if got := serverNames(r.Servers); !reflect.DeepEqual(got, []string{"ok"}) {
			t.Errorf("server names = %v, want [ok]", got)
		}
	})
}

// TestReadCodexKeyParts checks the cap on the parts of a full key path (table
// header, open inline tables and the key itself). A header with 20,000 parts
// takes seconds and gigabytes in the TOML parser, so readCodex must reject it
// before the parser sees it.
func TestReadCodexKeyParts(t *testing.T) {
	t.Parallel()

	// valid is a server that must survive in the "accepted" cases.
	const valid = "[mcp_servers.ok]\ncommand = \"c\"\n\n"

	rejected := []struct {
		name   string
		config string
	}{
		{name: "header with 17 parts", config: valid + "[" + keyParts(17) + "]\n"},
		{name: "array-of-tables header with 17 parts", config: valid + "[[" + keyParts(17) + "]]\n"},
		{name: "dotted key with 17 parts", config: valid + keyParts(17) + " = 1\n"},
		{name: "dotted key in an inline table", config: valid + "t = { " + keyParts(17) + " = 1 }\n"},
		{name: "header with 200 parts", config: valid + "[" + keyParts(200) + "]\n"},
		{name: "17 parts split over header, dotted key and inline table", config: valid + "[a.b.c.d.e]\nf.g.h.i = { j.k.l.m.n.o.p.q = 1 }\n"},
		{name: "16 parts in the header and one more in the key", config: valid + "[" + keyParts(16) + "]\nk = 1\n"},
	}
	for _, tt := range rejected {
		t.Run("rejected: "+tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeCodexConfig(t, tt.config)
			r := ReadCodex(t.Context(), path)
			if len(r.Servers) != 0 {
				t.Errorf("got %d servers, want none", len(r.Servers))
			}
			checkCodexErrors(t, path, r.Errors, []codexWantError{{reason: reasonTooDeep}})
		})
	}

	accepted := []struct {
		name   string
		config string
	}{
		{name: "header with 16 parts", config: valid + "[" + keyParts(16) + "]\n"},
		{name: "dotted key with 16 parts", config: keyParts(16) + " = 1\n" + valid},
		{name: "16 parts split over header, dotted key and inline table", config: valid + "[a.b.c.d.e]\nf.g.h.i = { j.k.l.m.n.o.p = 1 }\n"},
		{name: "real shape: sub-table", config: valid + "[mcp_servers.ok.env]\nAPI_KEY = \"v\"\n"},
		{name: "real shape: inline http_headers", config: "[mcp_servers.ok]\nurl = \"http://h\"\nhttp_headers = { Authorization = \"v\" }\n"},
		{name: "dots in a quoted key", config: valid + "[\"" + strings.Repeat("a.", 200) + "\"]\nx = 1\n"},
		{name: "dots in a string value", config: valid + "[x]\ns = \"" + strings.Repeat("a.", 200) + "\"\n"},
		{name: "dots in a comment", config: valid + "# " + strings.Repeat("a.", 200) + "\n"},
		{name: "floats and dates", config: valid + "[x]\nf = 1.5\nd = 1979-05-27T07:32:00.999\nl = [1.5, 2.5, 3.5]\nt = { a = 1.5, b = 2.5 }\n"},
	}
	for _, tt := range accepted {
		t.Run("accepted: "+tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeCodexConfig(t, tt.config)
			r := ReadCodex(t.Context(), path)
			checkCodexErrors(t, path, r.Errors, nil)
			if got := serverNames(r.Servers); !reflect.DeepEqual(got, []string{"ok"}) {
				t.Errorf("server names = %v, want [ok]", got)
			}
		})
	}

	// Without the check, this header takes about 1.4 s and 4.8 GiB, and a dotted
	// key with the same number of parts takes about 23 s.
	for _, tt := range []struct{ name, config string }{
		{name: "header with 20000 parts", config: "[mcp_servers." + keyParts(20000) + "]\n"},
		{name: "dotted key with 20000 parts", config: "mcp_servers." + keyParts(20000) + " = 1\n"},
	} {
		t.Run("fast: "+tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeCodexConfig(t, tt.config)
			start := time.Now()
			r := ReadCodex(t.Context(), path)
			if d := time.Since(start); d > time.Second {
				t.Errorf("ReadCodex took %v, want less than 1s", d)
			}
			checkCodexErrors(t, path, r.Errors, []codexWantError{{reason: reasonTooDeep}})
		})
	}
}

// TestReadCodexSizeCap checks the 256 KiB cap on a Codex config file.
func TestReadCodexSizeCap(t *testing.T) {
	t.Parallel()

	// pad returns a TOML comment line block of exactly n bytes after prefix.
	pad := func(prefix string, n int) string {
		return prefix + strings.Repeat("#", n-len(prefix)-1) + "\n"
	}
	const server = "[mcp_servers.ok]\ncommand = \"c\"\n"

	t.Run("just over the cap", func(t *testing.T) {
		t.Parallel()
		path := writeCodexConfig(t, pad(server, maxTOMLSize+1))
		r := ReadCodex(t.Context(), path)
		if len(r.Servers) != 0 {
			t.Errorf("got %d servers, want none", len(r.Servers))
		}
		checkCodexErrors(t, path, r.Errors, []codexWantError{{reason: reasonTooLarge}})
	})

	t.Run("exactly at the cap", func(t *testing.T) {
		t.Parallel()
		path := writeCodexConfig(t, pad(server, maxTOMLSize))
		r := ReadCodex(t.Context(), path)
		checkCodexErrors(t, path, r.Errors, nil)
		if got := serverNames(r.Servers); !reflect.DeepEqual(got, []string{"ok"}) {
			t.Errorf("server names = %v, want [ok]", got)
		}
	})
}

// TestReadCodexEnvNotATable checks an env or http_headers key that is not a
// table. The TOML decoder drops such a key without an error, so readCodex
// checks its type. The other servers must still be returned.
func TestReadCodexEnvNotATable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config string
	}{
		{name: "env is a number", config: "[mcp_servers.bad]\ncommand = \"c\"\nenv = 5\n"},
		{name: "env is a string", config: "[mcp_servers.bad]\ncommand = \"c\"\nenv = \"s\"\n"},
		{name: "env is an array", config: "[mcp_servers.bad]\ncommand = \"c\"\nenv = [\"A\"]\n"},
		{name: "env is an array of tables", config: "[[mcp_servers.bad.env]]\nA = \"1\"\n[mcp_servers.bad]\ncommand = \"c\"\n"},
		{name: "http_headers is a number", config: "[mcp_servers.bad]\nurl = \"https://example.com/mcp\"\nhttp_headers = 5\n"},
		{name: "http_headers is an array", config: "[mcp_servers.bad]\nurl = \"https://example.com/mcp\"\nhttp_headers = [\"A\"]\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeCodexConfig(t, tt.config+"\n[mcp_servers.good]\ncommand = \"c\"\n")
			r := ReadCodex(t.Context(), path)
			checkCodexErrors(t, path, r.Errors, []codexWantError{{server: "bad", reason: reasonBadEntry}})
			if got := serverNames(r.Servers); !reflect.DeepEqual(got, []string{"good"}) {
				t.Errorf("server names = %v, want [good]", got)
			}
		})
	}

	t.Run("sub-table forms still work", func(t *testing.T) {
		t.Parallel()
		config := "[mcp_servers.a]\ncommand = \"c\"\n\n[mcp_servers.a.env]\nK = \"v1\"\n\n" +
			"[mcp_servers.b]\nurl = \"https://example.com/mcp\"\n\n[mcp_servers.b.http_headers]\nH = \"v2\"\n"
		path := writeCodexConfig(t, config)
		r := ReadCodex(t.Context(), path)
		checkCodexErrors(t, path, r.Errors, nil)
		want := []serverView{
			{
				Name: "a", Client: ClientCodex, Scope: ScopeGlobal, Source: path,
				Transport: TransportStdio, Command: "c", Env: map[string]string{"K": "v1"},
			},
			{
				Name: "b", Client: ClientCodex, Scope: ScopeGlobal, Source: path,
				Transport: TransportHTTP, URL: "https://example.com/mcp", Headers: map[string]string{"H": "v2"},
			},
		}
		if got := viewsOf(r.Servers); !reflect.DeepEqual(got, want) {
			t.Errorf("servers =\n%+v\nwant\n%+v", got, want)
		}
	})
}

// TestReadCodexTooManyServers checks the cap on servers in one file.
func TestReadCodexTooManyServers(t *testing.T) {
	t.Parallel()

	// generate uses one inline table, the shortest form, so that 10,000 servers
	// fit in maxTOMLSize.
	generate := func(n int) string {
		var b strings.Builder
		b.WriteString("mcp_servers={")
		for i := range n {
			fmt.Fprintf(&b, "s%d={command=\"c\"},", i)
		}
		b.WriteString("}\n")
		return b.String()
	}

	t.Run("over the cap", func(t *testing.T) {
		t.Parallel()
		path := writeCodexConfig(t, generate(maxServersPerFile+1))
		r := ReadCodex(t.Context(), path)
		if len(r.Servers) != 0 {
			t.Errorf("got %d servers, want none", len(r.Servers))
		}
		checkCodexErrors(t, path, r.Errors, []codexWantError{{reason: reasonTooManyServers}})
	})

	t.Run("at the cap", func(t *testing.T) {
		t.Parallel()
		path := writeCodexConfig(t, generate(maxServersPerFile))
		r := ReadCodex(t.Context(), path)
		checkCodexErrors(t, path, r.Errors, nil)
		if len(r.Servers) != maxServersPerFile {
			t.Errorf("got %d servers, want %d", len(r.Servers), maxServersPerFile)
		}
	})
}
