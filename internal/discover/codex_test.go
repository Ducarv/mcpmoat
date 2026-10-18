package discover

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// codexConfigPath returns the path of the Codex config file inside home.
func codexConfigPath(home string) string {
	return filepath.Join(home, filepath.FromSlash(codexConfigRel))
}

// TestReadCodexFixtures runs ReadCodex on a copy of each fixture in
// testdata/discover/codex/<name>. It checks the servers and the errors, and
// that no server and no error holds a canary in fmt output, in Error or in
// JSON. The want values hold the canaries, so viewOf (which calls Reveal) is
// the only way that a test can see them.
func TestReadCodexFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string // the fixture directory under testdata/discover/codex
		// hideValues is set for fixtures that hold canaries. On a mismatch
		// the test then prints only the server names, never the values.
		hideValues bool
		// canaries is set when the config file of the fixture must hold
		// every canary. The leak checks only mean something if the input
		// holds the canaries.
		canaries   bool
		wantServer []serverView // Client, Scope and Source are filled in
		wantErrs   []errWant
	}{
		{
			name: "valid",
			wantServer: []serverView{
				{
					Name:      "docs",
					Transport: TransportStdio,
					Command:   "npx",
					Args:      []string{"-y", "mcp-docs"},
					Env:       map[string]string{"LOG_LEVEL": "info"},
				},
				{
					// cwd maps to Dir (see also TestReadCodexCwd).
					// enabled and startup_timeout_sec are ignored.
					Name:      "git",
					Transport: TransportStdio,
					Command:   "uvx",
					Args:      []string{"mcp-server-git", "--repository", "."},
					Dir:       "/tmp",
				},
				{
					// bearer_token_env_var and env_http_headers are not mapped.
					Name:      "remote",
					Transport: TransportHTTP,
					URL:       "https://codex.example.com/mcp",
				},
			},
		},
		{name: "empty"},
		{name: "missing"},
		{
			name:       "malformed",
			hideValues: true,
			wantErrs: []errWant{
				{Reason: reasonInvalidTOML, Line: 3},
			},
		},
		{
			name: "invalid-entries",
			wantServer: []serverView{
				{
					Name:      "good",
					Transport: TransportStdio,
					Command:   "npx",
					Args:      []string{"-y", "mcp-docs"},
				},
			},
			// Errors are sorted by server name.
			wantErrs: []errWant{
				{Server: "args-str", Reason: reasonBadEntry},
				{Server: "nothing", Reason: reasonNoCommandOrURL},
				{Server: "num-env", Reason: reasonBadEntry},
			},
		},
		{
			// Every secret value is read in full and is visible only
			// through Reveal (see viewOf).
			name:       "secrets",
			hideValues: true,
			canaries:   true,
			wantServer: []serverView{
				{
					Name:      "s1",
					Transport: TransportStdio,
					Command:   "x",
					Args:      []string{"--token", discovertest.CanaryArgs},
					Env:       map[string]string{"API_KEY": discovertest.CanaryEnv},
				},
				{
					Name:      "s2",
					Transport: TransportHTTP,
					URL:       "https://user:" + discovertest.CanaryURL + "@codex.example.com/mcp?key=" + discovertest.CanaryURL,
					Headers:   map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.canaries {
				assertFixtureFilesHaveCanaries(t, fixtureDir(t, "codex", tt.name), "home/"+codexConfigRel)
			}
			home, _ := copyFixture(t, "codex", tt.name)
			path := codexConfigPath(home)

			r := ReadCodex(t.Context(), path)

			want := make([]serverView, 0, len(tt.wantServer))
			for _, w := range tt.wantServer {
				w.Client = ClientCodex
				w.Scope = ScopeGlobal
				w.Source = path
				want = append(want, w)
			}
			checkServers(t, "servers", r.Servers, want, tt.hideValues)
			checkFileErrors(t, path, r.Errors, tt.wantErrs)

			assertNoLeakErrors(t, r.Errors)
			assertNoLeakServers(t, r.Servers)
		})
	}
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
		wantErrs   []errWant
		wantLeaked []string // extra strings that no error text may hold
	}{
		{
			name:       "url is a number",
			config:     "[mcp_servers.x]\nurl = " + bad + "\n",
			wantErrs:   []errWant{{Server: "x", Reason: reasonBadEntry}},
			wantLeaked: []string{bad},
		},
		{
			name:       "url is a boolean",
			config:     "[mcp_servers.x]\nurl = true\n",
			wantErrs:   []errWant{{Server: "x", Reason: reasonBadEntry}},
			wantLeaked: []string{"true"},
		},
		{
			name: "http_headers value is a number",
			config: "[mcp_servers.x]\nurl = \"https://example.com/mcp\"\n\n" +
				"[mcp_servers.x.http_headers]\nAuthorization = " + bad + "\n",
			wantErrs:   []errWant{{Server: "x", Reason: reasonBadEntry}},
			wantLeaked: []string{bad},
		},
		{
			name:       "env value is a boolean",
			config:     "[mcp_servers.x]\ncommand = \"c\"\nenv = { K = true }\n",
			wantErrs:   []errWant{{Server: "x", Reason: reasonBadEntry}},
			wantLeaked: []string{"true"},
		},
		{
			name:       "command is a number",
			config:     "[mcp_servers.x]\ncommand = " + bad + "\n",
			wantErrs:   []errWant{{Server: "x", Reason: reasonBadEntry}},
			wantLeaked: []string{bad},
		},
		{
			name:       "args is a string with a canary",
			config:     "[mcp_servers.x]\ncommand = \"c\"\nargs = \"" + discovertest.CanaryEnv + "\"\n",
			wantErrs:   []errWant{{Server: "x", Reason: reasonBadEntry}},
			wantLeaked: []string{discovertest.CanaryEnv},
		},
		{
			name:       "args holds a number",
			config:     "[mcp_servers.x]\ncommand = \"c\"\nargs = [\"a\", " + bad + "]\n",
			wantErrs:   []errWant{{Server: "x", Reason: reasonBadEntry}},
			wantLeaked: []string{bad},
		},
		{
			name:       "server is not a table",
			config:     "[mcp_servers]\nx = " + bad + "\n",
			wantErrs:   []errWant{{Server: "x", Reason: reasonBadEntry}},
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
			// Codex rejects an entry with both keys, so mcpmoat must not
			// guess which transport the user meant.
			name:      "command and url",
			config:    "[mcp_servers.both]\ncommand = \"c\"\nurl = \"https://example.com/mcp\"\n\n[mcp_servers.ok]\ncommand = \"c\"\n",
			wantNames: []string{"ok"},
			wantErrs:  []errWant{{Server: "both", Reason: reasonBadEntry}},
		},
		{
			name:     "empty command and url",
			config:   "[mcp_servers.both]\ncommand = \"\"\nurl = \"https://example.com/mcp\"\n",
			wantErrs: []errWant{{Server: "both", Reason: reasonBadEntry}},
		},
		{
			name:     "command and empty url",
			config:   "[mcp_servers.both]\ncommand = \"c\"\nurl = \"\"\n",
			wantErrs: []errWant{{Server: "both", Reason: reasonBadEntry}},
		},
		{
			name:     "command and url in an inline table",
			config:   "mcp_servers = { both = { command = \"c\", url = \"https://example.com/mcp\" } }\n",
			wantErrs: []errWant{{Server: "both", Reason: reasonBadEntry}},
		},
		{
			name:     "empty command and no url",
			config:   "[mcp_servers.x]\ncommand = \"\"\n",
			wantErrs: []errWant{{Server: "x", Reason: reasonNoCommandOrURL}},
		},
		{
			name:       "syntax error reports its line and keeps the value out",
			config:     "a = 1\nb = 2\nc = \"" + discovertest.CanaryEnv + "\" " + discovertest.CanaryEnv + "\n",
			wantErrs:   []errWant{{Reason: reasonInvalidTOML, Line: 3}},
			wantLeaked: []string{discovertest.CanaryEnv},
		},
		{
			name:       "duplicate key is a TOML error",
			config:     "a = 1\na = " + bad + "\n",
			wantErrs:   []errWant{{Reason: reasonInvalidTOML, Line: 2}},
			wantLeaked: []string{bad},
		},
		{
			name:   "whitespace and comments only",
			config: "\n  \n# only a comment\n",
		},
		{
			name:      "empty server name in a header",
			config:    "[mcp_servers.\"\"]\ncommand = \"c\"\n\n[mcp_servers.ok]\ncommand = \"c\"\n",
			wantNames: []string{"ok"},
			wantErrs:  []errWant{{Server: "", Reason: reasonEmptyName}},
		},
		{
			name:     "empty server name in an inline table",
			config:   "mcp_servers = { \"\" = { command = \"c\" } }\n",
			wantErrs: []errWant{{Server: "", Reason: reasonEmptyName}},
		},
		{
			name:     "server is an array of tables",
			config:   "[[mcp_servers.x]]\ncommand = \"c\"\n",
			wantErrs: []errWant{{Server: "x", Reason: reasonBadEntry}},
		},
		{
			name:     "command is a table",
			config:   "[mcp_servers.x.command]\na = \"c\"\n",
			wantErrs: []errWant{{Server: "x", Reason: reasonBadEntry}},
		},
		{
			name:     "url is a table",
			config:   "[mcp_servers.x]\nurl = { a = \"https://example.com/mcp\" }\n",
			wantErrs: []errWant{{Server: "x", Reason: reasonBadEntry}},
		},
		{
			name:     "args is an array of arrays",
			config:   "[mcp_servers.x]\ncommand = \"c\"\nargs = [[\"a\"]]\n",
			wantErrs: []errWant{{Server: "x", Reason: reasonBadEntry}},
		},
		{
			name:     "args is an array of tables",
			config:   "[mcp_servers.x]\ncommand = \"c\"\n[[mcp_servers.x.args]]\na = \"b\"\n",
			wantErrs: []errWant{{Server: "x", Reason: reasonBadEntry}},
		},
		{
			name:      "dotted keys at the root",
			config:    "mcp_servers.x.command = \"c\"\nmcp_servers.x.env.K = \"v\"\n",
			wantNames: []string{"x"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), codexConfigRel, []byte(tt.config))

			r := ReadCodex(t.Context(), path)

			if tt.wantNames == nil && len(r.Servers) != 0 {
				t.Errorf("server names = %v, want none", serverNames(r.Servers))
			}
			if tt.wantNames != nil && !reflect.DeepEqual(serverNames(r.Servers), tt.wantNames) {
				t.Errorf("server names = %v, want %v", serverNames(r.Servers), tt.wantNames)
			}
			checkFileErrors(t, path, r.Errors, tt.wantErrs)

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

// TestReadCodexTransport checks the transport and the dropped fields of the
// stdio and http paths.
func TestReadCodexTransport(t *testing.T) {
	t.Parallel()

	config := `
[mcp_servers.local]
command = "c"
args = ["a"]
env = { K = "v1" }
http_headers = { H = "v2" }

[mcp_servers.web]
url = "https://example.com/web"
http_headers = { H = "v3" }
args = ["dropped"]
env = { E = "dropped" }
`
	path := writeFile(t, t.TempDir(), codexConfigRel, []byte(config))
	r := ReadCodex(t.Context(), path)
	checkFileErrors(t, path, r.Errors, nil)

	want := []serverView{
		{
			// A stdio server never carries headers.
			Name: "local", Client: ClientCodex, Scope: ScopeGlobal, Source: path,
			Transport: TransportStdio, Command: "c", Args: []string{"a"},
			Env: map[string]string{"K": "v1"},
		},
		{
			// An HTTP server never carries args or env.
			Name: "web", Client: ClientCodex, Scope: ScopeGlobal, Source: path,
			Transport: TransportHTTP, URL: "https://example.com/web",
			Headers: map[string]string{"H": "v3"},
		},
	}
	checkServers(t, "servers", r.Servers, want, false)
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
		checkFileErrors(t, path, r.Errors, []errWant{{Reason: reasonNotRegular}})
	})

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, t.TempDir(), codexConfigRel, []byte("[mcp_servers.a]\ncommand = \"c\"\n"))
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
			path := writeFile(t, t.TempDir(), codexConfigRel, []byte(tt.config))
			r := ReadCodex(t.Context(), path)
			if len(r.Servers) != 0 {
				t.Errorf("got %d servers, want none", len(r.Servers))
			}
			checkFileErrors(t, path, r.Errors, []errWant{{Reason: reasonBadShape}})
			for _, e := range r.Errors {
				if strings.Contains(e.Error(), tt.leaked) {
					t.Errorf("Error() = %q holds the bad value", e.Error())
				}
			}
			assertNoLeakErrors(t, r.Errors)
		})
	}
}

// TestCheckTOMLShape checks the bracket and key scanner on its own, and that
// it names the limit that the input breaks.
func TestCheckTOMLShape(t *testing.T) {
	t.Parallel()

	nested := func(open, closing string, n int) string {
		return "a = " + strings.Repeat(open, n) + strings.Repeat(closing, n) + "\n"
	}
	tests := []struct {
		name  string
		input string
		limit int // maxDepth
		parts int // maxParts; 0 means maxTOMLKeyParts
		want  reason
	}{
		{name: "empty", input: "", limit: 2, want: ""},
		{name: "inline tables at the limit", input: "a = " + strings.Repeat("{a=", 15) + "1" + strings.Repeat("}", 15) + "\n", limit: 16, want: ""},
		{name: "arrays at the limit", input: nested("[", "]", 16), limit: 16, want: ""},
		{name: "arrays over the limit", input: nested("[", "]", 17), limit: 16, want: reasonTooDeep},
		// Each nested inline table adds a key part, so the depth limit only
		// shows when the parts limit is higher.
		{name: "inline tables over the limit", input: "a = " + strings.Repeat("{a=", 17) + "1" + strings.Repeat("}", 17) + "\n", limit: 16, parts: 64, want: reasonTooDeep},
		{name: "inline tables over the limit break the parts limit first", input: "a = " + strings.Repeat("{a=", 17) + "1" + strings.Repeat("}", 17) + "\n", limit: 16, want: reasonKeyTooLong},
		{name: "inline tables in arrays over the limit", input: "a = " + strings.Repeat("[{b=", 9) + "1" + strings.Repeat("}]", 9) + "\n", limit: 16, want: reasonTooDeep},
		{name: "array header deeper than the limit", input: "[[[a]]]\n", limit: 2, want: reasonTooDeep},
		{name: "unclosed brackets count", input: strings.Repeat("[", 17), limit: 16, want: reasonTooDeep},
		{name: "closing brackets alone stay at zero", input: strings.Repeat("]", 100) + "a = [[1]]\n", limit: 2, want: ""},
		{name: "table headers", input: "[a.b]\nx = 1\n[[c]]\ny = [1]\n", limit: 3, want: ""},
		{name: "comment", input: "# [[[[[[[[\na = 1\n", limit: 2, want: ""},
		{name: "comment at the end without newline", input: "a = 1 # [[[[[[[[", limit: 2, want: ""},
		{name: "brackets after a comment count", input: "# x\na = [[[1]]]\n", limit: 2, want: reasonTooDeep},
		{name: "basic string", input: `a = "[[[[[[[["` + "\n", limit: 2, want: ""},
		{name: "basic string with an escaped quote", input: `a = "\"[[[[[[[["` + "\n", limit: 2, want: ""},
		{name: "literal string", input: "a = '[[[[[[[['\n", limit: 2, want: ""},
		{name: "literal string keeps a backslash", input: `a = '\'` + "\nb = [[[1]]]\n", limit: 2, want: reasonTooDeep},
		{name: "multi-line basic string", input: "a = \"\"\"\n[[[[[[[[\n\"\"\"\n", limit: 2, want: ""},
		{name: "multi-line literal string", input: "a = '''\n{{{{{{{{\n'''\n", limit: 2, want: ""},
		{name: "multi-line string with quotes before the end", input: "a = \"\"\"x\"\"\"\"\nb = [[[1]]]\n", limit: 2, want: reasonTooDeep},
		{name: "brackets after a multi-line string count", input: "a = '''x'''\nb = [[[1]]]\n", limit: 2, want: reasonTooDeep},
		{name: "quoted key in a header", input: "[\"a[[[[[b\"]\nx = 1\n", limit: 2, want: ""},
		{name: "string that is not closed ends at the line", input: "a = \"[[[\nb = [[[1]]]\n", limit: 2, want: reasonTooDeep},
		{name: "header with 16 parts", input: "[" + keyParts(16) + "]\n", limit: 64, want: ""},
		{name: "header with 17 parts", input: "[" + keyParts(17) + "]\n", limit: 64, want: reasonKeyTooLong},
		{name: "array header with 17 parts", input: "[[" + keyParts(17) + "]]\n", limit: 64, want: reasonKeyTooLong},
		{name: "dotted key with 16 parts", input: keyParts(16) + " = 1\n", limit: 64, want: ""},
		{name: "dotted key with 17 parts", input: keyParts(17) + " = 1\n", limit: 64, want: reasonKeyTooLong},
		{name: "dotted key in an inline table with 17 parts", input: "t = { " + keyParts(17) + " = 1 }\n", limit: 64, want: reasonKeyTooLong},
		{name: "the counter restarts on each line", input: strings.Repeat(keyParts(10)+" = 1\n", 5), limit: 64, want: ""},
		{name: "the header is the base of the keys below it", input: "[" + keyParts(8) + "]\n" + keyParts(8) + " = 1\n", limit: 64, want: ""},
		{name: "header and key over the limit", input: "[" + keyParts(8) + "]\n" + keyParts(9) + " = 1\n", limit: 64, want: reasonKeyTooLong},
		{name: "the next header drops the base", input: "[" + keyParts(15) + "]\nb = 1\n[a]\n" + keyParts(15) + " = 1\n", limit: 64, want: ""},
		{name: "header, key and inline table at 16 parts", input: "[a.b]\nc.d = { e.f = { g.h = { i.j.k.l.m.n.o.p = 1 } } }\n", limit: 64, want: ""},
		{name: "header, key and inline table at 17 parts", input: "[a.b]\nc.d = { e.f = { g.h = { i.j.k.l.m.n.o.p.q = 1 } } }\n", limit: 64, want: reasonKeyTooLong},
		{name: "sibling inline tables do not add up", input: "t = { " + keyParts(8) + " = 1, " + keyParts(8) + " = 2 }\n", limit: 64, want: ""},
		{name: "inline tables in an array do not add up", input: "t = [" + strings.Repeat("{ "+keyParts(8)+" = 1 }, ", 20) + "]\n", limit: 64, want: ""},
		{name: "the base returns after an inline table closes", input: "t = { " + keyParts(8) + " = {} }\n" + keyParts(16) + " = 1\n", limit: 64, want: ""},
		{name: "nested inline table bypass", input: "x0 = " + strings.Repeat("{"+keyParts(63)+"=", 63) + "1" + strings.Repeat("}", 63) + "\n", limit: 64, want: reasonKeyTooLong},
		{name: "arrays add depth but no parts", input: "t = [[[" + keyParts(1) + "]]]\n[a]\n" + keyParts(15) + " = [[1.5]]\n", limit: 64, want: ""},
		{name: "real shape: sub-table", input: "[mcp_servers.x]\ncommand = \"c\"\n[mcp_servers.x.env]\nAPI_KEY = \"v\"\n", limit: 16, want: ""},
		{name: "real shape: inline headers", input: "[mcp_servers.x]\nurl = \"http://h\"\nhttp_headers = { Authorization = \"v\" }\n", limit: 16, want: ""},
		{name: "real shape: dotted keys at the root", input: "mcp_servers.x.env.API_KEY = \"v\"\nmcp_servers.x.command = \"c\"\n", limit: 16, want: ""},
		{name: "dots in a quoted key do not count", input: "[\"" + strings.Repeat("a.", 200) + "\"]\nx = 1\n", limit: 64, want: ""},
		{name: "dots in a literal quoted key do not count", input: "'" + strings.Repeat("a.", 200) + "' = 1\n", limit: 64, want: ""},
		{name: "dots in a string value do not count", input: "a = \"" + strings.Repeat("a.", 200) + "\"\n", limit: 64, want: ""},
		{name: "dots in a multi-line string do not count", input: "a = \"\"\"" + strings.Repeat("a.", 200) + "\"\"\"\n", limit: 64, want: ""},
		{name: "dots in a comment do not count", input: "# " + strings.Repeat("a.", 200) + "\nx = 1\n", limit: 64, want: ""},
		{name: "dots in a comment at the end do not count", input: "x = 1 # " + strings.Repeat("a.", 200), limit: 64, want: ""},
		{name: "floats and dates", input: "f = 1.5\nd = 1979-05-27T07:32:00.999\nt = 07:32:00.999\n", limit: 64, want: ""},
		{name: "many floats in an array", input: "a = [" + strings.Repeat("1.5, ", 200) + "]\n", limit: 64, want: ""},
		{name: "many floats in an inline table", input: "t = { " + strings.Repeat("a = 1.5, ", 200) + "z = 1 }\n", limit: 64, want: ""},
		{name: "quoted part and plain parts", input: "[a.\"b.c\"." + keyParts(14) + "]\n", limit: 64, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parts := tt.parts
			if parts == 0 {
				parts = maxTOMLKeyParts
			}
			if got := checkTOMLShape([]byte(tt.input), tt.limit, parts); got != tt.want {
				t.Errorf("checkTOMLShape(%q, %d, %d) = %q, want %q", tt.input, tt.limit, parts, got, tt.want)
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
		// An inline table in an inline table needs a key, which adds a key
		// part. Arrays of inline tables add depth faster than parts.
		{name: "inline tables in arrays", config: "a = " + strings.Repeat("[{b=", maxTOMLDepth/2+1) + "1" + strings.Repeat("}]", maxTOMLDepth/2+1) + "\n"},
		{name: "arrays", config: "a = " + strings.Repeat("[", maxTOMLDepth+1) + strings.Repeat("]", maxTOMLDepth+1) + "\n"},
		{name: "256 KiB of nested arrays", config: strings.Repeat("[", maxTOMLSize)},
		{name: "deep input after a valid server", config: "[mcp_servers.ok]\ncommand = \"c\"\n\n[x]\na = " + strings.Repeat("[", 5000) + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), codexConfigRel, []byte(tt.config))
			r := ReadCodex(t.Context(), path)
			if len(r.Servers) != 0 {
				t.Errorf("got %d servers, want none", len(r.Servers))
			}
			checkFileErrors(t, path, r.Errors, []errWant{{Reason: reasonTooDeep}})
		})
	}

	t.Run("depth at the limit is accepted", func(t *testing.T) {
		t.Parallel()
		config := "[mcp_servers.ok]\ncommand = \"c\"\n\n[x]\na = " +
			strings.Repeat("[", maxTOMLDepth) + strings.Repeat("]", maxTOMLDepth) + "\n"
		path := writeFile(t, t.TempDir(), codexConfigRel, []byte(config))
		r := ReadCodex(t.Context(), path)
		checkFileErrors(t, path, r.Errors, nil)
		if got := serverNames(r.Servers); !reflect.DeepEqual(got, []string{"ok"}) {
			t.Errorf("server names = %v, want [ok]", got)
		}
	})

	t.Run("brackets in a comment and in a string do not count", func(t *testing.T) {
		t.Parallel()
		config := "# " + strings.Repeat("[", 200) + "\n" +
			"[mcp_servers.ok]\ncommand = \"c\"\nargs = [\"" + strings.Repeat("[", 200) + "\"]\n"
		path := writeFile(t, t.TempDir(), codexConfigRel, []byte(config))
		r := ReadCodex(t.Context(), path)
		checkFileErrors(t, path, r.Errors, nil)
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
		// Each nested inline table adds the key that opens it.
		{name: "inline tables, 17 levels", config: valid + "a = " + strings.Repeat("{a=", maxTOMLDepth+1) + "1" + strings.Repeat("}", maxTOMLDepth+1) + "\n"},
		{name: "inline tables, 63 levels with 63 dots in each key", config: valid + "x0 = " + strings.Repeat("{"+keyParts(63)+"=", 63) + "1" + strings.Repeat("}", 63) + "\n"},
	}
	for _, tt := range rejected {
		t.Run("rejected: "+tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), codexConfigRel, []byte(tt.config))
			r := ReadCodex(t.Context(), path)
			if len(r.Servers) != 0 {
				t.Errorf("got %d servers, want none", len(r.Servers))
			}
			checkFileErrors(t, path, r.Errors, []errWant{{Reason: reasonKeyTooLong}})
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
			path := writeFile(t, t.TempDir(), codexConfigRel, []byte(tt.config))
			r := ReadCodex(t.Context(), path)
			checkFileErrors(t, path, r.Errors, nil)
			if got := serverNames(r.Servers); !reflect.DeepEqual(got, []string{"ok"}) {
				t.Errorf("server names = %v, want [ok]", got)
			}
		})
	}

	// Without the check, this header takes about 1.4 s and 4.8 GiB, and a dotted
	// key with the same number of parts takes about 23 s. The time limit below
	// is loose on purpose, so a slow or busy CI machine does not fail the test.
	// The reasonKeyTooLong error already proves that the parser never ran.
	for _, tt := range []struct{ name, config string }{
		{name: "header with 20000 parts", config: "[mcp_servers." + keyParts(20000) + "]\n"},
		{name: "dotted key with 20000 parts", config: "mcp_servers." + keyParts(20000) + " = 1\n"},
	} {
		t.Run("fast: "+tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), codexConfigRel, []byte(tt.config))
			start := time.Now()
			r := ReadCodex(t.Context(), path)
			if d := time.Since(start); d > 10*time.Second {
				t.Errorf("ReadCodex took %v, want less than 10s", d)
			}
			checkFileErrors(t, path, r.Errors, []errWant{{Reason: reasonKeyTooLong}})
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
		path := writeFile(t, t.TempDir(), codexConfigRel, []byte(pad(server, maxTOMLSize+1)))
		r := ReadCodex(t.Context(), path)
		if len(r.Servers) != 0 {
			t.Errorf("got %d servers, want none", len(r.Servers))
		}
		checkFileErrors(t, path, r.Errors, []errWant{{Reason: reasonTooLarge}})
	})

	t.Run("exactly at the cap", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, t.TempDir(), codexConfigRel, []byte(pad(server, maxTOMLSize)))
		r := ReadCodex(t.Context(), path)
		checkFileErrors(t, path, r.Errors, nil)
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
			path := writeFile(t, t.TempDir(), codexConfigRel, []byte(tt.config+"\n[mcp_servers.good]\ncommand = \"c\"\n"))
			r := ReadCodex(t.Context(), path)
			checkFileErrors(t, path, r.Errors, []errWant{{Server: "bad", Reason: reasonBadEntry}})
			if got := serverNames(r.Servers); !reflect.DeepEqual(got, []string{"good"}) {
				t.Errorf("server names = %v, want [good]", got)
			}
		})
	}

	t.Run("sub-table forms still work", func(t *testing.T) {
		t.Parallel()
		config := "[mcp_servers.a]\ncommand = \"c\"\n\n[mcp_servers.a.env]\nK = \"v1\"\n\n" +
			"[mcp_servers.b]\nurl = \"https://example.com/mcp\"\n\n[mcp_servers.b.http_headers]\nH = \"v2\"\n"
		path := writeFile(t, t.TempDir(), codexConfigRel, []byte(config))
		r := ReadCodex(t.Context(), path)
		checkFileErrors(t, path, r.Errors, nil)
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
		checkServers(t, "servers", r.Servers, want, false)
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
		path := writeFile(t, t.TempDir(), codexConfigRel, []byte(generate(maxServersPerFile+1)))
		r := ReadCodex(t.Context(), path)
		if len(r.Servers) != 0 {
			t.Errorf("got %d servers, want none", len(r.Servers))
		}
		checkFileErrors(t, path, r.Errors, []errWant{{Reason: reasonTooManyServers}})
	})

	t.Run("at the cap", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, t.TempDir(), codexConfigRel, []byte(generate(maxServersPerFile)))
		r := ReadCodex(t.Context(), path)
		checkFileErrors(t, path, r.Errors, nil)
		if len(r.Servers) != maxServersPerFile {
			t.Errorf("got %d servers, want %d", len(r.Servers), maxServersPerFile)
		}
	})
}

// TestReadCodexExactKeys checks that readCodex reads keys exactly, as Codex
// does. The TOML library matches struct fields without regard to letter case,
// so a reader built on a struct would take "Command" for "command" and could
// show a different command than the one Codex runs. A key that differs from a
// known key only by case must give reasonAmbiguousKey and no server.
func TestReadCodexExactKeys(t *testing.T) {
	t.Parallel()

	// good is a valid server that must survive next to a bad one.
	const good = "\n[mcp_servers.good]\ncommand = \"c\"\n"
	ambiguous := []errWant{{Server: "x", Reason: reasonAmbiguousKey}}

	tests := []struct {
		name      string
		config    string
		wantNames []string
		wantErrs  []errWant
	}{
		{
			name:      "command and Command",
			config:    "[mcp_servers.x]\ncommand = \"evil\"\nCommand = \"benign\"\n" + good,
			wantNames: []string{"good"},
			wantErrs:  ambiguous,
		},
		{
			name:      "Command alone",
			config:    "[mcp_servers.x]\nCommand = \"c\"\n" + good,
			wantNames: []string{"good"},
			wantErrs:  ambiguous,
		},
		{
			name:      "args and ARGS",
			config:    "[mcp_servers.x]\ncommand = \"c\"\nargs = [\"a\"]\nARGS = [\"b\"]\n" + good,
			wantNames: []string{"good"},
			wantErrs:  ambiguous,
		},
		{
			name:      "url and URL",
			config:    "[mcp_servers.x]\nurl = \"https://a.example.com/mcp\"\nURL = \"https://b.example.com/mcp\"\n" + good,
			wantNames: []string{"good"},
			wantErrs:  ambiguous,
		},
		{
			name:      "env and Env as a sub-table",
			config:    "[mcp_servers.x]\ncommand = \"c\"\nenv = { K = \"a\" }\n[mcp_servers.x.Env]\nK = \"b\"\n" + good,
			wantNames: []string{"good"},
			wantErrs:  ambiguous,
		},
		{
			name:      "http_headers and HTTP_HEADERS",
			config:    "[mcp_servers.x]\nurl = \"https://example.com/mcp\"\nHTTP_HEADERS = { H = \"v\" }\n" + good,
			wantNames: []string{"good"},
			wantErrs:  ambiguous,
		},
		{
			name:      "cwd and CWD",
			config:    "[mcp_servers.x]\ncommand = \"c\"\ncwd = \"/a\"\nCWD = \"/b\"\n" + good,
			wantNames: []string{"good"},
			wantErrs:  ambiguous,
		},
		{
			name:      "an ignored key in another case",
			config:    "[mcp_servers.x]\ncommand = \"c\"\nEnabled = false\n" + good,
			wantNames: []string{"good"},
			wantErrs:  ambiguous,
		},
		{
			// U+017F (long s) folds to s, so "argſ" differs from "args" only by case.
			name:      "a Unicode case variant",
			config:    "[mcp_servers.x]\ncommand = \"c\"\n\"argſ\" = [\"a\"]\n" + good,
			wantNames: []string{"good"},
			wantErrs:  ambiguous,
		},
		{
			name:     "MCP_SERVERS header",
			config:   "[MCP_SERVERS.y]\ncommand = \"c\"\n" + good,
			wantErrs: []errWant{{Reason: reasonAmbiguousKey}},
		},
		{
			name:     "Mcp_Servers dotted key",
			config:   "Mcp_Servers.y.command = \"c\"\n" + good,
			wantErrs: []errWant{{Reason: reasonAmbiguousKey}},
		},
		{
			name:     "MCP_SERVERS alone",
			config:   "[MCP_SERVERS.y]\ncommand = \"c\"\n",
			wantErrs: []errWant{{Reason: reasonAmbiguousKey}},
		},
		{
			name: "exact keys still work",
			config: "model = \"o3\"\nModel = \"x\"\n\n[mcp_servers.x]\ncommand = \"c\"\nargs = [\"a\"]\n" +
				"env = { K = \"v\" }\ncwd = \"/w\"\nenabled = true\nstartup_timeout_sec = 5\ntool_timeout_sec = 5\n" +
				"bearer_token_env_var = \"T\"\nenv_vars = [\"A\"]\ncommands = \"not a known key\"\n" + good,
			wantNames: []string{"good", "x"},
		},
		{
			// Env names are case-sensitive on Unix, so K and k are two variables.
			name:      "env keys that differ by case are two variables",
			config:    "[mcp_servers.x]\ncommand = \"c\"\nenv = { K = \"a\", k = \"b\" }\n",
			wantNames: []string{"x"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), codexConfigRel, []byte(tt.config))
			r := ReadCodex(t.Context(), path)
			got := serverNames(r.Servers)
			if len(got) != len(tt.wantNames) || (len(got) > 0 && !reflect.DeepEqual(got, tt.wantNames)) {
				t.Errorf("server names = %v, want %v", got, tt.wantNames)
			}
			checkFileErrors(t, path, r.Errors, tt.wantErrs)
			assertNoLeakErrors(t, r.Errors)
			assertNoLeakServers(t, r.Servers)
		})
	}

	t.Run("the exact key gives the value", func(t *testing.T) {
		t.Parallel()
		config := "[mcp_servers.x]\ncommand = \"c\"\nargs = [\"a\"]\nenv = { K = \"v\" }\n"
		path := writeFile(t, t.TempDir(), codexConfigRel, []byte(config))
		r := ReadCodex(t.Context(), path)
		checkFileErrors(t, path, r.Errors, nil)
		want := []serverView{{
			Name: "x", Client: ClientCodex, Scope: ScopeGlobal, Source: path,
			Transport: TransportStdio, Command: "c", Args: []string{"a"},
			Env: map[string]string{"K": "v"},
		}}
		checkServers(t, "servers", r.Servers, want, false)
	})
}

// TestReadCodexCwd checks that cwd maps to Server.Dir for a stdio server.
func TestReadCodexCwd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   string
		wantDir  string
		wantErrs []errWant
	}{
		{name: "stdio with cwd", config: "[mcp_servers.x]\ncommand = \"c\"\ncwd = \"/work/dir\"\n", wantDir: "/work/dir"},
		{name: "relative cwd is kept as written", config: "[mcp_servers.x]\ncommand = \"c\"\ncwd = \"../w\"\n", wantDir: "../w"},
		{name: "stdio without cwd", config: "[mcp_servers.x]\ncommand = \"c\"\n"},
		{name: "http drops cwd", config: "[mcp_servers.x]\nurl = \"https://example.com/mcp\"\ncwd = \"/work/dir\"\n"},
		{name: "cwd is a number", config: "[mcp_servers.x]\ncommand = \"c\"\ncwd = 5\n", wantErrs: []errWant{{Server: "x", Reason: reasonBadEntry}}},
		{name: "cwd is an array", config: "[mcp_servers.x]\ncommand = \"c\"\ncwd = [\"/a\"]\n", wantErrs: []errWant{{Server: "x", Reason: reasonBadEntry}}},
		{name: "cwd is a table", config: "[mcp_servers.x]\ncommand = \"c\"\ncwd = { a = \"/a\" }\n", wantErrs: []errWant{{Server: "x", Reason: reasonBadEntry}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), codexConfigRel, []byte(tt.config))
			r := ReadCodex(t.Context(), path)
			checkFileErrors(t, path, r.Errors, tt.wantErrs)
			if tt.wantErrs != nil {
				if len(r.Servers) != 0 {
					t.Errorf("got %d servers, want none", len(r.Servers))
				}
				return
			}
			if len(r.Servers) != 1 {
				t.Fatalf("got %d servers, want 1", len(r.Servers))
			}
			if got := r.Servers[0].Dir; got != tt.wantDir {
				t.Errorf("Dir = %q, want %q", got, tt.wantDir)
			}
		})
	}

	t.Run("valid fixture", func(t *testing.T) {
		t.Parallel()
		home, _ := copyFixture(t, "codex", "valid")
		r := ReadCodex(t.Context(), codexConfigPath(home))
		dirs := make(map[string]string, len(r.Servers))
		for _, s := range r.Servers {
			dirs[s.Name] = s.Dir
		}
		want := map[string]string{"docs": "", "git": "/tmp", "remote": ""}
		if !reflect.DeepEqual(dirs, want) {
			t.Errorf("Dir by server = %v, want %v", dirs, want)
		}
	})
}

// errAfterCtx is a context whose Err method returns nil for the first calls
// and context.Canceled after that. It lets a test stop readCodex in the middle
// of its loop over the servers. Done comes from the embedded context and never
// closes; readCodex only calls Err.
type errAfterCtx struct {
	context.Context
	left atomic.Int64 // calls of Err that still return nil
}

// Err returns nil while calls are left, then context.Canceled.
func (c *errAfterCtx) Err() error {
	if c.left.Add(-1) >= 0 {
		return nil
	}
	return context.Canceled
}

// TestReadCodexErrorOrder checks that errors for the whole file come first,
// then the errors for servers, sorted by name. A cancel in the middle of the
// loop adds a file-level error after a server error, so readCodex must sort.
func TestReadCodexErrorOrder(t *testing.T) {
	t.Parallel()

	// a and c are bad, b is good. readCodex visits them in this order.
	config := "[mcp_servers.a]\ncwd = \"/a\"\n\n[mcp_servers.b]\ncommand = \"c\"\n\n[mcp_servers.c]\ncommand = 5\n"
	path := writeFile(t, t.TempDir(), codexConfigRel, []byte(config))

	sawCancelAfterServer := false
	// n is how many calls of Err return nil. The exact count that readCodex
	// needs before the loop is not part of the test, so try several.
	for n := range 8 {
		ctx := &errAfterCtx{Context: t.Context()}
		ctx.left.Store(int64(n))
		r := ReadCodex(ctx, path)

		for i, e := range r.Errors {
			if i > 0 && r.Errors[i-1].Server > e.Server {
				t.Errorf("n=%d: errors are not sorted by server: %v", n, r.Errors)
			}
			if e.Reason == reasonCanceled {
				if i != 0 || e.Server != "" || !errors.Is(e, context.Canceled) {
					t.Errorf("n=%d: errs[%d] = %v, want the canceled error first, for the whole file", n, i, e)
				}
				if len(r.Errors) > 1 {
					sawCancelAfterServer = true
				}
			}
		}
	}
	if !sawCancelAfterServer {
		t.Error("no run stopped after a server error; the test does not cover the sort")
	}

	t.Run("without a cancel", func(t *testing.T) {
		t.Parallel()
		r := ReadCodex(t.Context(), path)
		checkFileErrors(t, path, r.Errors, []errWant{
			{Server: "a", Reason: reasonNoCommandOrURL},
			{Server: "c", Reason: reasonBadEntry},
		})
		if got := serverNames(r.Servers); !reflect.DeepEqual(got, []string{"b"}) {
			t.Errorf("server names = %v, want [b]", got)
		}
	})
}

// TestReadCodexBOM checks that a byte order mark at the start of the file
// does not move the position of a syntax error. The TOML parser removes the
// mark before it reads, so its offsets do not count the mark.
func TestReadCodexBOM(t *testing.T) {
	t.Parallel()

	boms := []struct{ name, mark string }{
		{name: "UTF-8", mark: "\xef\xbb\xbf"},
		{name: "UTF-16 LE", mark: "\xff\xfe"},
		{name: "UTF-16 BE", mark: "\xfe\xff"},
	}
	configs := []struct{ name, config string }{
		{name: "error on line 1", config: "c = \"x\" y\n"},
		{name: "error on line 3", config: "a = 1\nb = 2\n  c = \"x\" y\n"},
	}
	for _, c := range configs {
		for _, b := range boms {
			t.Run(c.name+", "+b.name, func(t *testing.T) {
				t.Parallel()
				plain := ReadCodex(t.Context(), writeFile(t, t.TempDir(), codexConfigRel, []byte(c.config)))
				marked := ReadCodex(t.Context(), writeFile(t, t.TempDir(), codexConfigRel, []byte(b.mark+c.config)))
				if len(plain.Errors) != 1 || len(marked.Errors) != 1 {
					t.Fatalf("got %d and %d errors, want 1 each", len(plain.Errors), len(marked.Errors))
				}
				p, m := plain.Errors[0], marked.Errors[0]
				if p.Reason != reasonInvalidTOML || m.Reason != reasonInvalidTOML {
					t.Fatalf("reasons = %q and %q, want %q", p.Reason, m.Reason, reasonInvalidTOML)
				}
				if p.Line == 0 || p.Col == 0 {
					t.Fatalf("without a mark: line %d, col %d, want both set", p.Line, p.Col)
				}
				if m.Line != p.Line || m.Col != p.Col {
					t.Errorf("with a mark: %d:%d, want %d:%d as without it", m.Line, m.Col, p.Line, p.Col)
				}
			})
		}
	}

	t.Run("valid file with a UTF-8 mark", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, t.TempDir(), codexConfigRel, []byte("\xef\xbb\xbf[mcp_servers.ok]\ncommand = \"c\"\n"))
		r := ReadCodex(t.Context(), path)
		checkFileErrors(t, path, r.Errors, nil)
		if got := serverNames(r.Servers); !reflect.DeepEqual(got, []string{"ok"}) {
			t.Errorf("server names = %v, want [ok]", got)
		}
	})
}

// TestTOMLBOMLen checks the byte order marks that the TOML parser removes.
func TestTOMLBOMLen(t *testing.T) {
	t.Parallel()

	tests := []struct {
		data string
		want int
	}{
		{data: "", want: 0},
		{data: "a = 1", want: 0},
		{data: "\xef\xbb\xbfa = 1", want: 3},
		{data: "\xef\xbb", want: 0},
		{data: "\xff\xfea", want: 2},
		{data: "\xfe\xffa", want: 2},
		{data: "\xff", want: 0},
	}
	for _, tt := range tests {
		if got := tomlBOMLen([]byte(tt.data)); got != tt.want {
			t.Errorf("tomlBOMLen(%q) = %d, want %d", tt.data, got, tt.want)
		}
	}
}

// TestCodexKeys checks the key lists: every entry in codexReads has a
// destination, codexKnownKeys holds each known key once (so no key is both
// read and ignored), and it holds every read key and every ignored key.
func TestCodexKeys(t *testing.T) {
	t.Parallel()

	seen := make(map[string]int, len(codexKnownKeys))
	for _, k := range codexKnownKeys {
		seen[k]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("key %q is in codexKnownKeys %d times", k, n)
		}
	}

	var e codexEntry
	reads := codexReads(&e)
	for _, r := range reads {
		if r.dest == nil {
			t.Errorf("codexReads: key %q has no destination", r.key)
		}
		if seen[r.key] == 0 {
			t.Errorf("read key %q is not in codexKnownKeys", r.key)
		}
	}
	for _, k := range codexIgnoredKeys {
		if seen[k] == 0 {
			t.Errorf("ignored key %q is not in codexKnownKeys", k)
		}
	}
	if want := len(reads) + len(codexIgnoredKeys); len(codexKnownKeys) != want {
		t.Errorf("len(codexKnownKeys) = %d, want %d", len(codexKnownKeys), want)
	}
}

// TestCodexIsTable checks the md.Type names that codexIsTable and
// codexHasType depend on. A change in the TOML library would show here first.
func TestCodexIsTable(t *testing.T) {
	t.Parallel()

	const config = "n = 1\ns = \"x\"\nl = [1]\ninl = { z = 1 }\n[t]\nx = 1\n[p.q]\ny = 1\n[[arr]]\nw = 1\n"
	var top map[string]toml.Primitive
	md, err := toml.Decode(config, &top)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		key      string
		wantType string
		table    bool
	}{
		{key: "n", wantType: "Integer"},
		{key: "s", wantType: tomlTypeString},
		{key: "l", wantType: tomlTypeArray},
		{key: "inl", wantType: tomlTypeHash, table: true},
		{key: "t", wantType: tomlTypeHash, table: true},
		{key: "p", wantType: "", table: true}, // made only through the header [p.q]
		{key: "arr", wantType: tomlTypeArrayHash},
	}
	for _, tt := range tests {
		if got := md.Type(tt.key); got != tt.wantType {
			t.Errorf("md.Type(%q) = %q, want %q", tt.key, got, tt.wantType)
		}
		if got := codexIsTable(&md, tt.key); got != tt.table {
			t.Errorf("codexIsTable(%q) = %v, want %v", tt.key, got, tt.table)
		}
		if got := codexHasType(&md, tomlTypeHash, tt.key); got != tt.table {
			t.Errorf("codexHasType(Hash, %q) = %v, want %v", tt.key, got, tt.table)
		}
	}
}
