package discover

import (
	"io/fs"
	"os"
	"path/filepath"
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

		// Empty and white space .json files have no servers, as "{}". So they
		// follow the same rule: only the known client file names decide.
		{"empty .claude.json", "/x/.claude.json", "", ClientClaudeCode, true},
		{"white space .claude.json", "/x/.claude.json", " \n\t\r\n", ClientClaudeCode, true},
		{"empty .mcp.json", "/x/.mcp.json", "", ClientClaudeCode, true},
		{"white space .mcp.json", "/x/.mcp.json", "\n", ClientClaudeCode, true},
		{"empty .json in .cursor", "/x/.cursor/mcp.json", "", ClientCursor, true},
		{"white space .json in .cursor", "/x/.cursor/mcp.json", "\n\n", ClientCursor, true},
		{"empty mcp.json", "/x/mcp.json", "", "", false},
		{"white space mcp.json", "/x/mcp.json", " \n\t\r\n", "", false},
		{"empty package.json", "/x/package.json", "", "", false},
		{"white space package.json", "/x/package.json", " \n", "", false},
		{"empty other.json in .cursor", "/x/.cursor/other.json", "", "", false},
		{"empty upper case .JSON", "/x/mcp.JSON", "", "", false},
		{"empty upper case .MCP.JSON", "/x/.MCP.JSON", "", "", false},
		// U+00A0 is not JSON white space, so the file is invalid JSON.
		{"no-break space in package.json", "/x/package.json", "\u00a0", ClientClaudeCode, true},

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
		if got, ok := DetectClient("/x/.mcp.json", nil); !ok || got != ClientClaudeCode {
			t.Errorf("DetectClient(.mcp.json, nil) = %q, %v, want claude-code, true", got, ok)
		}
		if got, ok := DetectClient("/x/package.json", nil); ok || got != "" {
			t.Errorf("DetectClient(package.json, nil) = %q, %v, want \"\", false", got, ok)
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
