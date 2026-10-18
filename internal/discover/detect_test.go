package discover

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// detectCase is one input for DetectClient: a path, the file content and the
// expected answer.
type detectCase struct {
	name   string
	path   string
	data   string
	want   Client
	wantOK bool
}

// inlineDetectCases returns the DetectClient cases that need no fixture file.
// TestDetectClient runs them and FuzzDetectClient uses them as seeds.
//
// The paths are made up. DetectClient does no I/O, so they do not need to
// exist. Control characters are written as Go escapes.
func inlineDetectCases() []detectCase {
	return []detectCase{
		// Claude Code: a "projects" key wins over the path.
		{"projects in a .cursor dir", "/x/.cursor/mcp.json", `{"projects":{}}`, ClientClaudeCode, true},
		{"projects and mcpServers in a .cursor dir", "/x/.cursor/mcp.json", `{"mcpServers":{},"projects":{}}`, ClientClaudeCode, true},
		{"projects as an array", "/x/mcp.json", `{"projects":[]}`, ClientClaudeCode, true},
		{"projects with null mcpServers", "/x/mcp.json", `{"projects":{},"mcpServers":null}`, ClientClaudeCode, true},

		// mcpServers is chosen by the parent directory.
		{"mcpServers outside .cursor", "/x/mcp.json", `{"mcpServers":{}}`, ClientClaudeCode, true},
		{"mcpServers inside .cursor", "/x/.cursor/mcp.json", `{"mcpServers":{}}`, ClientCursor, true},
		{"mcpServers in a nested dir below .cursor", "/x/.cursor/sub/mcp.json", `{"mcpServers":{}}`, ClientClaudeCode, true},
		{"mcpServers in a dir that only starts with .cursor", "/x/.cursorx/mcp.json", `{"mcpServers":{}}`, ClientClaudeCode, true},
		{"mcpServers in a dir named .Cursor", "/x/.Cursor/mcp.json", `{"mcpServers":{}}`, ClientClaudeCode, true},
		{"mcpServers in a relative path", "mcp.json", `{"mcpServers":{}}`, ClientClaudeCode, true},
		{"mcpServers with null projects", "/x/.cursor/mcp.json", `{"projects":null,"mcpServers":{}}`, ClientCursor, true},
		{"mcpServers with other name", "/x/.cursor/other.json", `{"mcpServers":{}}`, ClientCursor, true},
		{"mcpServers after leading white space", "/x/.cursor/mcp.json", " \n\t{\"mcpServers\":{}}", ClientCursor, true},

		// A JSON object does not need the .json extension.
		{"JSON object in a .txt file", "/x/config.txt", `{"mcpServers":{}}`, ClientClaudeCode, true},
		{"JSON object in a file without extension", "/x/config", `{"mcpServers":{}}`, ClientClaudeCode, true},
		{"JSON object in a .txt file in .cursor", "/x/.cursor/config.txt", `{"mcpServers":{}}`, ClientCursor, true},
		{"JSON object after white space in a .txt file", "/x/config.txt", "\n  {\"projects\":{}}", ClientClaudeCode, true},

		// Codex: the extension decides, whatever the content.
		{"toml", "/x/config.toml", "model = \"o3\"\n", ClientCodex, true},
		{"TOML upper case", "/x/config.TOML", "model = \"o3\"\n", ClientCodex, true},
		{"Toml mixed case", "/x/config.Toml", "", ClientCodex, true},
		{"toml with JSON content", "/x/config.toml", `{"mcpServers":{}}`, ClientCodex, true},
		{"toml with garbage", "/x/.cursor/config.toml", "{bad", ClientCodex, true},
		{"toml with binary-like content", "/x/config.toml", "\x00\x01\xff", ClientCodex, true},

		// Unknown formats.
		{"empty object", "/x/mcp.json", `{}`, "", false},
		{"empty object without extension", "/x/config", `{}`, "", false},
		{"array", "/x/mcp.json", `[1]`, "", false},
		{"string", "/x/mcp.json", `"s"`, "", false},
		{"number", "/x/mcp.json", `42`, "", false},
		{"null", "/x/mcp.json", `null`, "", false},
		{"upper case .JSON with an array", "/x/mcp.JSON", `[]`, "", false},
		{"null projects", "/x/mcp.json", `{"projects":null}`, "", false},
		{"null mcpServers", "/x/mcp.json", `{"mcpServers":null}`, "", false},
		{"other keys only", "/x/mcp.json", `{"theme":"dark","numStartups":3}`, "", false},
		{"empty object as package.json", "/x/package.json", `{}`, "", false},
		{"empty object as settings.json", "/x/settings.json", `{}`, "", false},
		{"empty object as other.json in .cursor", "/x/.cursor/other.json", `{}`, "", false},
		{"empty object as mcp.json in a nested dir below .cursor", "/x/.cursor/sub/mcp.json", `{}`, "", false},
		{"empty object as .Claude.json", "/x/.Claude.json", `{}`, "", false},
		{"other keys as package.json", "/x/package.json", `{"name":"x"}`, "", false},
		{"array as .claude.json", "/x/.claude.json", `[]`, "", false},
		// Keys are case-sensitive, like the readers.
		{"MCPServers with wrong case", "/x/mcp.json", `{"MCPServers":{}}`, "", false},
		{"Projects with wrong case", "/x/mcp.json", `{"Projects":{}}`, "", false},
		{"mcpservers in lower case", "/x/mcp.json", `{"mcpservers":{}}`, "", false},
		{"plain text in a .txt file", "/x/notes.txt", "hello world\n", "", false},
		{"empty .txt file", "/x/notes.txt", "", "", false},
		{"white space .txt file", "/x/notes.txt", " \n\t", "", false},
		{"file without extension", "/x/config", "hello", "", false},
		{"empty file without extension", "/x/config", "", "", false},
		{"array in a .txt file", "/x/notes.txt", `[1]`, "", false},
		{"yaml file", "/x/config.yaml", "mcpServers: {}\n", "", false},
		{"JSON key in text", "/x/notes.txt", `"mcpServers"`, "", false},
		{"empty path and content", "", "", "", false},

		// An object with neither key: the known client file names decide.
		{"empty object as .claude.json", "/x/.claude.json", `{}`, ClientClaudeCode, true},
		{"unrelated keys as .claude.json", "/x/.claude.json", `{"numStartups":1}`, ClientClaudeCode, true},
		{"null projects as .claude.json", "/x/.claude.json", `{"projects":null}`, ClientClaudeCode, true},
		{"null mcpServers as .claude.json", "/x/.claude.json", `{"mcpServers":null}`, ClientClaudeCode, true},
		{"empty object as .mcp.json", "/x/.mcp.json", `{}`, ClientClaudeCode, true},
		{"empty object as .claude.json in .cursor", "/x/.cursor/.claude.json", `{}`, ClientClaudeCode, true},
		{"empty object as mcp.json in .cursor", "/x/.cursor/mcp.json", `{}`, ClientCursor, true},
		{"both keys null as mcp.json in .cursor", "/x/.cursor/mcp.json", `{"projects":null,"mcpServers":null}`, ClientCursor, true},
		{"empty object with white space around it as .claude.json", "/x/.claude.json", " \n{}\n", ClientClaudeCode, true},

		// Empty and white space .json files: chosen by the path, no servers.
		{"empty .json", "/x/mcp.json", "", ClientClaudeCode, true},
		{"white space .json", "/x/mcp.json", " \n\t\r\n", ClientClaudeCode, true},
		{"empty .json in .cursor", "/x/.cursor/mcp.json", "", ClientCursor, true},
		{"white space .json in .cursor", "/x/.cursor/mcp.json", "\n\n", ClientCursor, true},
		{"empty upper case .JSON", "/x/mcp.JSON", "", ClientClaudeCode, true},

		// Invalid JSON: chosen by the path, so the reader can report the position.
		{"bad JSON in .json", "/x/mcp.json", `{bad`, ClientClaudeCode, true},
		{"bad JSON in .cursor", "/x/.cursor/mcp.json", `{bad`, ClientCursor, true},
		{"bad JSON in .txt", "/x/notes.txt", `{bad`, ClientClaudeCode, true},
		{"bad JSON in .txt in .cursor", "/x/.cursor/notes.txt", `{bad`, ClientCursor, true},
		{"bad JSON, text in .json", "/x/mcp.json", `hello`, ClientClaudeCode, true},
		{"bad JSON, text in .json in .cursor", "/x/.cursor/mcp.json", `hello`, ClientCursor, true},
		{"truncated object", "/x/mcp.json", `{"mcpServers":{"a":`, ClientClaudeCode, true},
		{"trailing garbage", "/x/mcp.json", `{"projects":{}} x`, ClientClaudeCode, true},
		{"trailing garbage in .cursor", "/x/.cursor/mcp.json", `{"projects":{}} x`, ClientCursor, true},
		{"byte order mark in .json", "/x/.cursor/mcp.json", "\ufeff{\"projects\":{}}", ClientCursor, true},
		{"byte order mark in .txt", "/x/notes.txt", "\ufeff{\"projects\":{}}", "", false},
		{"invalid UTF-8 in .json", "/x/mcp.json", "{\"a\":\"\xff\"", ClientClaudeCode, true},
	}
}

// readFixtureFile returns the content of a fixture file. The files are
// repository testdata, not user config.
func readFixtureFile(t testing.TB, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: test reads a fixture path chosen by the test
	if err != nil {
		t.Fatalf("read fixture file: %v", err)
	}
	return string(data)
}

func TestDetectClient(t *testing.T) {
	t.Parallel()

	// The fixture files are the real shapes of the three clients. They must
	// give the same answer as the readers expect.
	fixtures := []struct {
		name  string
		parts []string
		want  Client
	}{
		{"claude-code ~/.claude.json", []string{"claude-code", "valid", "home", ".claude.json"}, ClientClaudeCode},
		{"claude-code .mcp.json", []string{"claude-code", "valid", "work", ".mcp.json"}, ClientClaudeCode},
		{"claude-code secrets ~/.claude.json", []string{"claude-code", "secrets", "home", ".claude.json"}, ClientClaudeCode},
		{"claude-code secrets .mcp.json", []string{"claude-code", "secrets", "work", ".mcp.json"}, ClientClaudeCode},
		{"cursor home mcp.json", []string{"cursor", "valid", "home", ".cursor", "mcp.json"}, ClientCursor},
		{"cursor work mcp.json", []string{"cursor", "valid", "work", ".cursor", "mcp.json"}, ClientCursor},
		{"cursor secrets mcp.json", []string{"cursor", "secrets", "home", ".cursor", "mcp.json"}, ClientCursor},
		{"codex config.toml", []string{"codex", "valid", "home", ".codex", "config.toml"}, ClientCodex},
		{"codex secrets config.toml", []string{"codex", "secrets", "home", ".codex", "config.toml"}, ClientCodex},
	}
	for _, tt := range fixtures {
		t.Run("fixture "+tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(fixtureDir(t, tt.parts[0], tt.parts[1]), filepath.Join(tt.parts[2:]...))
			data := readFixtureFile(t, path)
			got, ok := DetectClient(path, []byte(data))
			if !ok || got != tt.want {
				t.Errorf("DetectClient(%s) = %q, %v, want %q, true", path, got, ok, tt.want)
			}
		})
	}

	for _, tt := range inlineDetectCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := DetectClient(tt.path, []byte(tt.data))
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("DetectClient(%q, %q) = %q, %v, want %q, %v",
					tt.path, tt.data, got, ok, tt.want, tt.wantOK)
			}
		})
	}

	t.Run("nil data", func(t *testing.T) {
		t.Parallel()
		if got, ok := DetectClient("/x/notes.txt", nil); ok || got != "" {
			t.Errorf("DetectClient(.txt, nil) = %q, %v, want \"\", false", got, ok)
		}
		if got, ok := DetectClient("/x/mcp.json", nil); !ok || got != ClientClaudeCode {
			t.Errorf("DetectClient(.json, nil) = %q, %v, want claude-code, true", got, ok)
		}
	})

	t.Run("does not change data", func(t *testing.T) {
		t.Parallel()
		data := []byte(`{"projects":{}}`)
		before := slices.Clone(data)
		DetectClient("/x/mcp.json", data)
		if !slices.Equal(data, before) {
			t.Errorf("DetectClient changed its data argument: %q, want %q", data, before)
		}
	})
}

// wantServer is the part of a Server that the ReadConfig tests compare.
type wantServer struct {
	Name        string
	Scope       Scope
	ProjectPath string
}

// sortedWant returns the name, scope and project path of each server, sorted,
// so a test does not depend on the order of the reader.
func sortedWant(ss []Server) []wantServer {
	out := make([]wantServer, 0, len(ss))
	for _, s := range ss {
		out = append(out, wantServer{s.Name, s.Scope, s.ProjectPath})
	}
	slices.SortFunc(out, func(a, b wantServer) int {
		return strings.Compare(
			a.Name+"|"+string(a.Scope)+"|"+a.ProjectPath,
			b.Name+"|"+string(b.Scope)+"|"+b.ProjectPath,
		)
	})
	return out
}

func TestReadConfig(t *testing.T) {
	t.Parallel()

	global := func(names ...string) []wantServer {
		var out []wantServer
		for _, n := range names {
			out = append(out, wantServer{Name: n, Scope: ScopeGlobal})
		}
		return out
	}

	valid := []struct {
		name        string
		fixture     string
		side        string // "home" or "work"
		rel         []string
		wantClient  Client
		wantServers []wantServer
	}{
		{
			name:       "claude-code ~/.claude.json with projects",
			fixture:    "claude-code",
			side:       "home",
			rel:        []string{".claude.json"},
			wantClient: ClientClaudeCode,
			wantServers: append(global("filesystem", "remote-http", "remote-sse"),
				wantServer{"alpha-tool", ScopeProject, "/work/alpha"},
				wantServer{"gamma-tool", ScopeProject, "/work/gamma"},
			),
		},
		{
			name:        "claude-code .mcp.json",
			fixture:     "claude-code",
			side:        "work",
			rel:         []string{".mcp.json"},
			wantClient:  ClientClaudeCode,
			wantServers: global("local-db", "team-api"),
		},
		{
			name:        "cursor home",
			fixture:     "cursor",
			side:        "home",
			rel:         []string{".cursor", "mcp.json"},
			wantClient:  ClientCursor,
			wantServers: global("events", "git", "remote"),
		},
		{
			name:        "cursor work",
			fixture:     "cursor",
			side:        "work",
			rel:         []string{".cursor", "mcp.json"},
			wantClient:  ClientCursor,
			wantServers: global("project-remote", "project-tools"),
		},
		{
			name:        "codex",
			fixture:     "codex",
			side:        "home",
			rel:         []string{".codex", "config.toml"},
			wantClient:  ClientCodex,
			wantServers: global("docs", "git", "remote"),
		},
	}
	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := copyFixture(t, tt.fixture, "valid")
			dir := home
			if tt.side == "work" {
				dir = work
			}
			path := filepath.Join(append([]string{dir}, tt.rel...)...)

			res := ReadConfig(t.Context(), path)

			if len(res.Errors) != 0 {
				t.Fatalf("ReadConfig() errors = %v, want none", res.Errors)
			}
			if got := sortedWant(res.Servers); !reflect.DeepEqual(got, sortedWant(toServers(tt.wantServers))) {
				t.Errorf("ReadConfig() servers = %v, want %v", got, sortedWant(toServers(tt.wantServers)))
			}
			for _, s := range res.Servers {
				if s.Client != tt.wantClient {
					t.Errorf("server %q client = %q, want %q", s.Name, s.Client, tt.wantClient)
				}
				if s.Source != path {
					t.Errorf("server %q source = %q, want %q", s.Name, s.Source, path)
				}
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "nope.json")
		res := ReadConfig(t.Context(), path)
		if len(res.Servers) != 0 {
			t.Errorf("ReadConfig() servers = %v, want none", serverNames(res.Servers))
		}
		if len(res.Errors) != 1 {
			t.Fatalf("ReadConfig() errors = %v, want exactly one", res.Errors)
		}
		fe := res.Errors[0]
		if fe.Reason != reasonNotFound || fe.Path != path || fe.Server != "" {
			t.Errorf("error = %+v, want path %q and reason %q", fe, path, reasonNotFound)
		}
		if !strings.Contains(fe.Error(), path) {
			t.Errorf("Error() = %q, want it to name the path %q", fe.Error(), path)
		}
	})

	t.Run("missing file with a toml name", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "config.toml")
		res := ReadConfig(t.Context(), path)
		if len(res.Errors) != 1 || res.Errors[0].Reason != reasonNotFound {
			t.Errorf("ReadConfig() errors = %v, want one %q", res.Errors, reasonNotFound)
		}
	})

	t.Run("directory", func(t *testing.T) {
		t.Parallel()
		path := t.TempDir()
		res := ReadConfig(t.Context(), path)
		if len(res.Servers) != 0 {
			t.Errorf("ReadConfig() servers = %v, want none", serverNames(res.Servers))
		}
		if len(res.Errors) != 1 || res.Errors[0].Reason != reasonNotRegular || res.Errors[0].Path != path {
			t.Errorf("ReadConfig() errors = %v, want one %q for %q", res.Errors, reasonNotRegular, path)
		}
	})

	t.Run("a file used as a directory is a read error", func(t *testing.T) {
		t.Parallel()
		// A file used as a directory: the OS error is ENOTDIR, not ENOENT.
		file := filepath.Join(t.TempDir(), "file.json")
		if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		res := ReadConfig(t.Context(), filepath.Join(file, "mcp.json"))
		if len(res.Errors) != 1 {
			t.Fatalf("ReadConfig() errors = %v, want exactly one", res.Errors)
		}
		if res.Errors[0].Reason != reasonCannotRead {
			t.Errorf("reason = %q, want %q", res.Errors[0].Reason, reasonCannotRead)
		}
	})

	unknown := []struct {
		name string
		file string
		data string
	}{
		{"text file", "notes.txt", "hello world\n"},
		{"empty text file", "notes.txt", ""},
		{"no extension", "config", "hello"},
		{"yaml", "config.yaml", "mcpServers: {}\n"},
		{"empty object", "mcp.json", `{}`},
		{"empty object as package.json", "package.json", `{}`},
		{"empty object as settings.json", "settings.json", `{}`},
		{"array", "mcp.json", `[1]`},
		{"null projects", "mcp.json", `{"projects":null}`},
		{"other keys", "mcp.json", `{"theme":"dark"}`},
		{"mcpServers with wrong case", "mcp.json", `{"MCPServers":{"a":{"command":"x"}}}`},
	}
	for _, tt := range unknown {
		t.Run("unknown format "+tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), tt.file)
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatal(err)
			}
			res := ReadConfig(t.Context(), path)
			if len(res.Servers) != 0 {
				t.Errorf("ReadConfig() servers = %v, want none", serverNames(res.Servers))
			}
			if len(res.Errors) != 1 || res.Errors[0].Reason != reasonUnknownFormat || res.Errors[0].Path != path {
				t.Fatalf("ReadConfig() errors = %v, want one %q for %q", res.Errors, reasonUnknownFormat, path)
			}
			if tt.data != "" && strings.Contains(res.Errors[0].Error(), strings.TrimSpace(tt.data)) {
				t.Errorf("Error() = %q holds config text", res.Errors[0].Error())
			}
		})
	}

	t.Run("empty object in known client files has no servers and no error", func(t *testing.T) {
		t.Parallel()
		files := []struct {
			rel  []string
			data string
		}{
			{[]string{".claude.json"}, `{}`},
			{[]string{".claude.json"}, `{"numStartups":1}`},
			{[]string{".claude.json"}, `{"projects":null}`},
			{[]string{".mcp.json"}, `{}`},
			{[]string{".cursor", "mcp.json"}, `{}`},
		}
		for _, f := range files {
			dir := t.TempDir()
			path := filepath.Join(append([]string{dir}, f.rel...)...)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(f.data), 0o600); err != nil {
				t.Fatal(err)
			}
			res := ReadConfig(t.Context(), path)
			if len(res.Servers) != 0 || len(res.Errors) != 0 {
				t.Errorf("ReadConfig(%s with %s) = %+v, want an empty result", filepath.Join(f.rel...), f.data, res)
			}
		}
	})

	t.Run("empty json file has no servers and no error", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "mcp.json")
		if err := os.WriteFile(path, []byte(" \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		res := ReadConfig(t.Context(), path)
		if len(res.Servers) != 0 || len(res.Errors) != 0 {
			t.Errorf("ReadConfig() = %+v, want an empty result", res)
		}
	})

	malformed := []struct {
		name    string
		fixture string
		rel     []string
	}{
		{"claude-code", "claude-code", []string{".claude.json"}},
		{"cursor", "cursor", []string{".cursor", "mcp.json"}},
	}
	for _, tt := range malformed {
		t.Run("malformed JSON "+tt.name, func(t *testing.T) {
			t.Parallel()
			home, _ := copyFixture(t, tt.fixture, "malformed")
			path := filepath.Join(append([]string{home}, tt.rel...)...)
			res := ReadConfig(t.Context(), path)
			if len(res.Servers) != 0 {
				t.Errorf("ReadConfig() servers = %v, want none", serverNames(res.Servers))
			}
			if len(res.Errors) != 1 {
				t.Fatalf("ReadConfig() errors = %v, want exactly one", res.Errors)
			}
			fe := res.Errors[0]
			if fe.Reason != reasonInvalidJSON || fe.Path != path || fe.Line <= 0 {
				t.Errorf("error = %+v, want reason %q, path %q and Line > 0", fe, reasonInvalidJSON, path)
			}
			assertNoLeakErrors(t, res.Errors)
		})
	}

	t.Run("malformed JSON in a .cursor dir is read as cursor", func(t *testing.T) {
		t.Parallel()
		// Both readers report the same error, so compare through a file that is
		// valid for the cursor reader only: it has no "projects" key, and a
		// .mcp.json style file would give the same servers. The check here is
		// that detection by path does not give "unknown format".
		path := filepath.Join(t.TempDir(), ".cursor", "mcp.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{\n  \"mcpServers\": {\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		res := ReadConfig(t.Context(), path)
		if len(res.Errors) != 1 || res.Errors[0].Reason != reasonInvalidJSON {
			t.Fatalf("ReadConfig() errors = %v, want one %q", res.Errors, reasonInvalidJSON)
		}
		if res.Errors[0].Line < 2 {
			t.Errorf("Line = %d, want 2 or more", res.Errors[0].Line)
		}
	})

	t.Run("malformed TOML", func(t *testing.T) {
		t.Parallel()
		home, _ := copyFixture(t, "codex", "malformed")
		path := filepath.Join(home, ".codex", "config.toml")
		res := ReadConfig(t.Context(), path)
		if len(res.Errors) != 1 || res.Errors[0].Reason != reasonInvalidTOML {
			t.Fatalf("ReadConfig() errors = %v, want one %q", res.Errors, reasonInvalidTOML)
		}
		assertNoLeakErrors(t, res.Errors)
	})

	t.Run("upper case .TOML extension is read as codex", func(t *testing.T) {
		t.Parallel()
		home, _ := copyFixture(t, "codex", "valid")
		src := filepath.Join(home, ".codex", "config.toml")
		dst := filepath.Join(home, ".codex", "CONFIG.TOML")
		if err := os.Rename(src, dst); err != nil {
			t.Fatal(err)
		}
		res := ReadConfig(t.Context(), dst)
		if len(res.Errors) != 0 || len(res.Servers) == 0 {
			t.Fatalf("ReadConfig() = %+v, want codex servers", res)
		}
		for _, s := range res.Servers {
			if s.Client != ClientCodex {
				t.Errorf("server %q client = %q, want codex", s.Name, s.Client)
			}
		}
	})

	secrets := []struct {
		name    string
		fixture string
		rel     [][]string // home and work files; work may be nil
		client  Client
	}{
		{"claude-code", "claude-code", [][]string{{"home", ".claude.json"}, {"work", ".mcp.json"}}, ClientClaudeCode},
		{"cursor", "cursor", [][]string{{"home", ".cursor", "mcp.json"}, {"work", ".cursor", "mcp.json"}}, ClientCursor},
		{"codex", "codex", [][]string{{"home", ".codex", "config.toml"}}, ClientCodex},
	}
	for _, tt := range secrets {
		t.Run("secrets "+tt.name, func(t *testing.T) {
			t.Parallel()
			src := fixtureDir(t, tt.fixture, "secrets")
			var srcFiles []string
			for _, r := range tt.rel {
				srcFiles = append(srcFiles, filepath.Join(src, filepath.Join(r...)))
			}
			// The leak check only means something if the fixture holds the canaries.
			assertFixtureHasCanaries(t, srcFiles...)

			home, work := copyFixture(t, tt.fixture, "secrets")
			var servers []Server
			var errs []*FileError
			for _, r := range tt.rel {
				dir := home
				if r[0] == "work" {
					dir = work
				}
				res := ReadConfig(t.Context(), filepath.Join(append([]string{dir}, r[1:]...)...))
				servers = append(servers, res.Servers...)
				errs = append(errs, res.Errors...)
			}
			if len(servers) == 0 {
				t.Fatal("ReadConfig() found no servers in the secrets fixture")
			}
			for _, s := range servers {
				if s.Client != tt.client {
					t.Errorf("server %q client = %q, want %q", s.Name, s.Client, tt.client)
				}
			}
			assertNoLeakServers(t, servers)
			assertNoLeakErrors(t, errs)
		})
	}

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		home, _ := copyFixture(t, "claude-code", "valid")
		path := filepath.Join(home, ".claude.json")
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		res := ReadConfig(ctx, path)
		if len(res.Servers) != 0 {
			t.Errorf("ReadConfig() servers = %v, want none", serverNames(res.Servers))
		}
		if len(res.Errors) != 1 || res.Errors[0].Reason != reasonCanceled {
			t.Fatalf("ReadConfig() errors = %v, want one %q", res.Errors, reasonCanceled)
		}
		if !errors.Is(res.Errors[0], context.Canceled) {
			t.Errorf("error does not wrap context.Canceled: %v", res.Errors[0])
		}
	})

	t.Run("canceled context on a missing file", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		res := ReadConfig(ctx, filepath.Join(t.TempDir(), "nope.json"))
		if len(res.Errors) != 1 {
			t.Fatalf("ReadConfig() errors = %v, want exactly one", res.Errors)
		}
		if res.Errors[0].Reason != reasonCanceled {
			t.Errorf("reason = %q, want %q", res.Errors[0].Reason, reasonCanceled)
		}
	})
}

// toServers turns a want list into servers, so sortedWant can sort both sides
// in the same way.
func toServers(ws []wantServer) []Server {
	out := make([]Server, 0, len(ws))
	for _, w := range ws {
		out = append(out, Server{Name: w.Name, Scope: w.Scope, ProjectPath: w.ProjectPath})
	}
	return out
}

// FuzzDetectClient checks DetectClient on any path and content. Run it for
// real with:
//
//	go test -run '^$' -fuzz=FuzzDetectClient -fuzztime=30s ./internal/discover/
//
// Properties: no panic; when ok, the client is one of the three constants;
// when not ok, the client is empty; the answer is the same on a second call;
// a .toml name is always Codex; Cursor needs a parent directory named .cursor.
func FuzzDetectClient(f *testing.F) {
	root := fixtureDir(f)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() == ".gitkeep" {
			return nil
		}
		f.Add(path, []byte(readFixtureFile(f, path)))
		return nil
	})
	if err != nil {
		f.Fatalf("walk fixtures: %v", err)
	}
	for _, c := range inlineDetectCases() {
		f.Add(c.path, []byte(c.data))
	}

	f.Fuzz(func(t *testing.T, path string, data []byte) {
		if len(data) > maxFuzzInput {
			t.Skip("input too large")
		}
		client, ok := DetectClient(path, data)
		again, okAgain := DetectClient(path, data)
		if client != again || ok != okAgain {
			t.Fatalf("DetectClient(%q, %q) is not deterministic: %q,%v then %q,%v",
				path, data, client, ok, again, okAgain)
		}
		if !ok {
			if client != "" {
				t.Fatalf("DetectClient(%q, %q) = %q with ok=false, want empty client", path, data, client)
			}
			if strings.EqualFold(filepath.Ext(path), ".toml") {
				t.Fatalf("DetectClient(%q, %q): a .toml name must be known", path, data)
			}
			return
		}
		switch client {
		case ClientClaudeCode, ClientCodex:
		case ClientCursor:
			if filepath.Base(filepath.Dir(path)) != ".cursor" {
				t.Fatalf("DetectClient(%q, %q) = cursor outside a .cursor dir", path, data)
			}
		default:
			t.Fatalf("DetectClient(%q, %q) = unknown client %q with ok=true", path, data, client)
		}
		if strings.EqualFold(filepath.Ext(path), ".toml") && client != ClientCodex {
			t.Fatalf("DetectClient(%q, %q) = %q, want codex for a .toml name", path, data, client)
		}
	})
}
