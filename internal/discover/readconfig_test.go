package discover

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

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

// wantGlobal gives the want list of servers from one of the user's own global
// files: ScopeGlobal and no project directory.
func wantGlobal(names ...string) []wantServer {
	var out []wantServer
	for _, n := range names {
		out = append(out, wantServer{Name: n, Scope: ScopeGlobal})
	}
	return out
}

// wantProject gives the want list of servers that ReadConfig reads as
// untrusted: ScopeProject and the project directory dir.
func wantProject(dir string, names ...string) []wantServer {
	var out []wantServer
	for _, n := range names {
		out = append(out, wantServer{Name: n, Scope: ScopeProject, ProjectPath: dir})
	}
	return out
}

// TestReadConfigValid reads the valid fixture of each client, as a global
// file and as an untrusted file, and checks the servers and their fields.
func TestReadConfigValid(t *testing.T) {
	t.Parallel()

	valid := []struct {
		name    string
		fixture string
		side    string // "home" or "work"
		rel     []string
		// withHome passes the fixture's home directory to ReadConfig. Without
		// it, ReadConfig gets no home, so no file is a global file.
		withHome   bool
		wantClient Client
		// wantServers returns the want list. home and work are the fixture copy.
		wantServers func(home, work string) []wantServer
		// wantReasons are the reasons of the errors, in order. Each error must
		// name the file and be Untrusted.
		wantReasons []string
	}{
		{
			name:       "claude-code ~/.claude.json with projects",
			fixture:    "claude-code",
			side:       "home",
			rel:        []string{".claude.json"},
			withHome:   true,
			wantClient: ClientClaudeCode,
			wantServers: func(_, _ string) []wantServer {
				return append(wantGlobal("filesystem", "remote-http", "remote-sse"),
					wantServer{"alpha-tool", ScopeProject, "/work/alpha"},
					wantServer{"gamma-tool", ScopeProject, "/work/gamma"},
				)
			},
		},
		{
			// The same file outside the home directory is untrusted: its
			// "projects" section is not read, and an error says so.
			name:       "claude-code .claude.json that is not the home file",
			fixture:    "claude-code",
			side:       "home",
			rel:        []string{".claude.json"},
			wantClient: ClientClaudeCode,
			wantServers: func(home, _ string) []wantServer {
				return wantProject(home, "filesystem", "remote-http", "remote-sse")
			},
			wantReasons: []string{reasonProjectsNotRead},
		},
		{
			name:       "claude-code .mcp.json",
			fixture:    "claude-code",
			side:       "work",
			rel:        []string{".mcp.json"},
			withHome:   true,
			wantClient: ClientClaudeCode,
			wantServers: func(_, work string) []wantServer {
				return wantProject(work, "local-db", "team-api")
			},
		},
		{
			name:        "cursor home",
			fixture:     "cursor",
			side:        "home",
			rel:         []string{".cursor", "mcp.json"},
			withHome:    true,
			wantClient:  ClientCursor,
			wantServers: func(_, _ string) []wantServer { return wantGlobal("events", "git", "remote") },
		},
		{
			name:       "cursor work",
			fixture:    "cursor",
			side:       "work",
			rel:        []string{".cursor", "mcp.json"},
			withHome:   true,
			wantClient: ClientCursor,
			wantServers: func(_, work string) []wantServer {
				return wantProject(work, "project-remote", "project-tools")
			},
		},
		{
			name:        "codex home",
			fixture:     "codex",
			side:        "home",
			rel:         []string{".codex", "config.toml"},
			withHome:    true,
			wantClient:  ClientCodex,
			wantServers: func(_, _ string) []wantServer { return wantGlobal("docs", "git", "remote") },
		},
		{
			// A Codex file that is not the home file gets the parent of its
			// .codex directory as the project directory.
			name:       "codex that is not the home file",
			fixture:    "codex",
			side:       "home",
			rel:        []string{".codex", "config.toml"},
			wantClient: ClientCodex,
			wantServers: func(home, _ string) []wantServer {
				return wantProject(home, "docs", "git", "remote")
			},
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
			var homeArg string
			if tt.withHome {
				homeArg = home
			}

			res := ReadConfig(t.Context(), path, homeArg)

			if len(res.Errors) != len(tt.wantReasons) {
				t.Fatalf("ReadConfig() errors = %v, want reasons %q", res.Errors, tt.wantReasons)
			}
			for i, fe := range res.Errors {
				if fe.Reason != tt.wantReasons[i] || fe.Path != path || fe.Server != "" || !fe.Untrusted {
					t.Errorf("error %d = %+v, want reason %q, path %q, no server and Untrusted", i, fe, tt.wantReasons[i], path)
				}
			}
			want := sortedWant(toServers(tt.wantServers(home, work)))
			if got := sortedWant(res.Servers); !reflect.DeepEqual(got, want) {
				t.Errorf("ReadConfig() servers = %v, want %v", got, want)
			}
			for _, s := range res.Servers {
				if s.Client != tt.wantClient {
					t.Errorf("server %q client = %q, want %q", s.Name, s.Client, tt.wantClient)
				}
				if s.Source != path {
					t.Errorf("server %q source = %q, want %q", s.Name, s.Source, path)
				}
				// A server from the global file, also one of its projects,
				// is trusted. Every other server is untrusted.
				if wantUntrusted := !tt.withHome || tt.side == "work"; s.Untrusted != wantUntrusted {
					t.Errorf("server %q Untrusted = %v, want %v", s.Name, s.Untrusted, wantUntrusted)
				}
			}
		})
	}

	t.Run("upper case .TOML extension is read as codex", func(t *testing.T) {
		t.Parallel()
		home, _ := copyFixture(t, "codex", "valid")
		src := filepath.Join(home, ".codex", "config.toml")
		dst := filepath.Join(home, ".codex", "CONFIG.TOML")
		if err := os.Rename(src, dst); err != nil {
			t.Fatal(err)
		}
		res := ReadConfig(t.Context(), dst, "")
		if len(res.Errors) != 0 || len(res.Servers) == 0 {
			t.Fatalf("ReadConfig() = %+v, want codex servers", res)
		}
		for _, s := range res.Servers {
			if s.Client != ClientCodex {
				t.Errorf("server %q client = %q, want codex", s.Name, s.Client)
			}
		}
	})
}

// TestReadConfigGlobalFile checks which path names one of the user's own
// global files. Only such a path is read as a trusted, global file.
func TestReadConfigGlobalFile(t *testing.T) {
	t.Parallel()

	// A second name of ~/.claude.json is the global file: os.SameFile
	// compares the files, not the paths. ReadConfig then reads the global
	// path, so every server names it, not the second name.
	secondNames := []struct {
		name string
		// link makes a second name of the file global and returns it.
		link func(t *testing.T, global string) string
	}{
		{"a symlink", func(t *testing.T, global string) string {
			return symlinkTo(t, global, t.TempDir(), "my.json")
		}},
		{"a hard link", func(t *testing.T, global string) string {
			link := filepath.Join(t.TempDir(), "my.json")
			if err := os.Link(global, link); err != nil {
				t.Fatalf("hard link %s: %v", link, err)
			}
			return link
		}},
		{"another letter case", func(t *testing.T, global string) string {
			if !caseInsensitiveFS(t, filepath.Dir(global)) {
				t.Skip("the temporary file system is case-sensitive")
			}
			return filepath.Join(filepath.Dir(global), ".CLAUDE.JSON")
		}},
	}
	for _, tt := range secondNames {
		t.Run(tt.name+" of the home file is the global file", func(t *testing.T) {
			t.Parallel()
			home, _ := copyFixture(t, "claude-code", "valid")
			global := filepath.Join(home, ".claude.json")
			link := tt.link(t, global)
			res := ReadConfig(t.Context(), link, home)
			if len(res.Errors) != 0 {
				t.Fatalf("ReadConfig() errors = %v, want none", res.Errors)
			}
			// The projects section is read, so the file was read as global.
			names := serverNames(res.Servers)
			if !slices.Contains(names, "alpha-tool") || !slices.Contains(names, "filesystem") {
				t.Errorf("ReadConfig() servers = %v, want the top-level and the project servers", names)
			}
			for _, s := range res.Servers {
				if s.Untrusted || s.Source != global {
					t.Errorf("server %q: Untrusted = %v, Source = %q; want false and %q", s.Name, s.Untrusted, s.Source, global)
				}
			}
		})
	}

	t.Run("a copy of the home file is untrusted", func(t *testing.T) {
		t.Parallel()
		// The same content in another file is not the global file.
		home := t.TempDir()
		data := []byte(`{"mcpServers":{"h":{"command":"x"}}}`)
		writeFile(t, home, ".claude.json", data)
		path := writeFile(t, t.TempDir(), "copy.json", data)
		res := ReadConfig(t.Context(), path, home)
		if len(res.Errors) != 0 || len(res.Servers) != 1 {
			t.Fatalf("ReadConfig() = %+v, want one server and no errors", res)
		}
		if s := res.Servers[0]; !s.Untrusted || s.Scope != ScopeProject || s.Source != path {
			t.Errorf("server = %+v, want Untrusted, ScopeProject and Source %q", s, path)
		}
	})

	t.Run("a symlinked home matches its home files", func(t *testing.T) {
		t.Parallel()
		// os.SameFile compares the files, so a home path that is itself a
		// symlink (for example /var and /private/var on macOS) still matches.
		home, _ := copyFixture(t, "cursor", "valid")
		homeLink := symlinkTo(t, home, t.TempDir(), "home")
		res := ReadConfig(t.Context(), filepath.Join(home, ".cursor", "mcp.json"), homeLink)
		if len(res.Errors) != 0 || len(res.Servers) == 0 {
			t.Fatalf("ReadConfig() = %+v, want servers and no errors", res)
		}
		for _, s := range res.Servers {
			if s.Untrusted || s.Scope != ScopeGlobal {
				t.Errorf("server %q: Untrusted = %v, Scope = %q; want false and %q", s.Name, s.Untrusted, s.Scope, ScopeGlobal)
			}
		}
	})

	t.Run("a file with a global name in another directory is untrusted", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		writeFile(t, home, ".claude.json", []byte(`{"mcpServers":{"h":{"command":"x"}}}`))
		other := t.TempDir()
		path := writeFile(t, other, ".claude.json", []byte(`{"projects":{"/p":{"mcpServers":{"p":{"command":"x"}}}},"mcpServers":{"o":{"command":"x"}}}`))
		res := ReadConfig(t.Context(), path, home)
		if len(res.Errors) != 1 || res.Errors[0].Reason != reasonProjectsNotRead || !res.Errors[0].Untrusted {
			t.Fatalf("ReadConfig() errors = %v, want one untrusted %q", res.Errors, reasonProjectsNotRead)
		}
		if got := serverNames(res.Servers); !slices.Equal(got, []string{"o"}) {
			t.Fatalf("ReadConfig() servers = %v, want [o] (the projects section is not read)", got)
		}
		if s := res.Servers[0]; !s.Untrusted || s.Scope != ScopeProject || s.ProjectPath != other {
			t.Errorf("server = %+v, want Untrusted, ScopeProject and ProjectPath %q", s, other)
		}
	})
}

// TestReadConfigUntrusted checks the confinement of an untrusted file and the
// Untrusted mark on its servers and errors.
func TestReadConfigUntrusted(t *testing.T) {
	t.Parallel()

	t.Run("a named file is confined and untrusted", func(t *testing.T) {
		t.Parallel()
		// The file can come from a cloned repository, so ReadConfig refuses a
		// symlink out of its directory, as Discover does for
		// <WorkDir>/.mcp.json. The canary in the target must never show.
		outside := t.TempDir()
		files := []struct {
			name   string
			target string
			link   string // with forward slashes
			data   string
		}{
			{"claude-code", "real.json", ".mcp.json", `{"mcpServers":{"a":{"command":"x","args":["` + discovertest.CanaryArgs + `"]}}}`},
			{"cursor", "real-cursor.json", ".cursor/mcp.json", `{"mcpServers":{"a":{"command":"x"}}}`},
			{"codex", "real.toml", ".codex/config.toml", "[mcp_servers.a]\ncommand = \"x\"\nargs = [\"" + discovertest.CanaryArgs + "\"]\n"},
		}
		for _, f := range files {
			target := writeFile(t, outside, f.target, []byte(f.data))
			link := symlinkTo(t, target, t.TempDir(), f.link)
			// The target is not a home file either: home is outside.
			res := ReadConfig(t.Context(), link, outside)
			if len(res.Servers) != 0 {
				t.Errorf("%s: ReadConfig() servers = %v, want none", f.name, serverNames(res.Servers))
			}
			if len(res.Errors) != 1 {
				t.Fatalf("%s: ReadConfig() errors = %v, want exactly one", f.name, res.Errors)
			}
			fe := res.Errors[0]
			if fe.Reason != reasonOutsideProject || fe.Path != link || !fe.Untrusted {
				t.Errorf("%s: error = %+v, want reason %q, path %q and Untrusted", f.name, fe, reasonOutsideProject, link)
			}
			assertNoLeakErrors(t, res.Errors)
		}
	})

	t.Run("a symlink that stays in the directory is followed", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, dir, "conf/codex.toml", []byte("[mcp_servers.a]\ncommand = \"x\"\n"))
		link := symlinkTo(t, filepath.Join("conf", "codex.toml"), dir, "config.toml")
		res := ReadConfig(t.Context(), link, "")
		if len(res.Errors) != 0 || len(res.Servers) != 1 {
			t.Fatalf("ReadConfig() = %+v, want one server and no errors", res)
		}
		if s := res.Servers[0]; !s.Untrusted || s.Scope != ScopeProject || s.ProjectPath != dir {
			t.Errorf("server = %+v, want Untrusted, ScopeProject and ProjectPath %q", s, dir)
		}
	})

	t.Run("untrusted codex errors are marked", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, t.TempDir(), "my.toml", []byte("[mcp_servers.a]\nurl = 5\n[mcp_servers.b]\ncommand = \"x\"\n"))
		res := ReadConfig(t.Context(), path, "")
		if len(res.Servers) != 1 || !res.Servers[0].Untrusted {
			t.Fatalf("ReadConfig() servers = %+v, want one untrusted server", res.Servers)
		}
		if len(res.Errors) != 1 || !res.Errors[0].Untrusted {
			t.Fatalf("ReadConfig() errors = %+v, want one untrusted error", res.Errors)
		}
	})
}

// TestReadConfigSizeLimits checks the size limit of an untrusted file:
// maxProjectConfigSize for JSON, and the smaller maxTOMLSize for Codex.
func TestReadConfigSizeLimits(t *testing.T) {
	t.Parallel()

	// The Codex check comes after the read, so the read limit must be the
	// larger one.
	if maxTOMLSize > maxProjectConfigSize {
		t.Fatalf("maxTOMLSize = %d is larger than maxProjectConfigSize = %d", maxTOMLSize, maxProjectConfigSize)
	}

	// codexServer is a Codex file with one server, padded with a comment to
	// size bytes.
	codexServer := func(size int) []byte {
		head := "[mcp_servers.a]\ncommand = \"x\"\n# "
		return []byte(head + strings.Repeat("x", size-len(head)-1) + "\n")
	}

	tests := []struct {
		name string
		file string
		data []byte
		// wantTooLarge expects one untrusted "file too large" error and no
		// servers. Else the test expects one server and no errors.
		wantTooLarge bool
	}{
		{"an untrusted codex file has the smaller size limit", "my.toml", []byte("# " + strings.Repeat("x", maxTOMLSize) + "\n"), true},
		{"an untrusted codex file one byte over the limit", "my.toml", codexServer(maxTOMLSize + 1), true},
		{"an untrusted codex file at the limit is read", "my.toml", codexServer(maxTOMLSize), false},
		{"an untrusted JSON file has the project size limit", ".mcp.json", []byte(`{"pad":"` + strings.Repeat("x", maxProjectConfigSize) + `"}`), true},
		{"an untrusted JSON file over the codex limit is read", ".mcp.json", []byte(`{"mcpServers":{"a":{"command":"x"}},"pad":"` + strings.Repeat("x", maxTOMLSize) + `"}`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), tt.file, tt.data)
			res := ReadConfig(t.Context(), path, "")
			if !tt.wantTooLarge {
				if len(res.Errors) != 0 || len(res.Servers) != 1 || !res.Servers[0].Untrusted {
					t.Fatalf("ReadConfig() = %+v, want one untrusted server and no errors", res)
				}
				return
			}
			if len(res.Servers) != 0 {
				t.Errorf("ReadConfig() servers = %v, want none", serverNames(res.Servers))
			}
			if len(res.Errors) != 1 || res.Errors[0].Reason != reasonTooLarge || res.Errors[0].Path != path || !res.Errors[0].Untrusted {
				t.Fatalf("ReadConfig() errors = %v, want one untrusted %q for %q", res.Errors, reasonTooLarge, path)
			}
		})
	}
}

// TestReadConfigReadErrors checks a path that cannot be read as a file.
// ReadConfig reports each one, also a missing file.
func TestReadConfigReadErrors(t *testing.T) {
	t.Parallel()

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "nope.json")
		res := ReadConfig(t.Context(), path, "")
		if len(res.Servers) != 0 {
			t.Errorf("ReadConfig() servers = %v, want none", serverNames(res.Servers))
		}
		if len(res.Errors) != 1 {
			t.Fatalf("ReadConfig() errors = %v, want exactly one", res.Errors)
		}
		fe := res.Errors[0]
		if fe.Reason != reasonNotFound || fe.Path != path || fe.Server != "" || !fe.Untrusted {
			t.Errorf("error = %+v, want path %q, reason %q and Untrusted", fe, path, reasonNotFound)
		}
		if !strings.Contains(fe.Error(), path) {
			t.Errorf("Error() = %q, want it to name the path %q", fe.Error(), path)
		}
	})

	t.Run("missing file with a toml name", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "config.toml")
		res := ReadConfig(t.Context(), path, "")
		if len(res.Errors) != 1 || res.Errors[0].Reason != reasonNotFound {
			t.Errorf("ReadConfig() errors = %v, want one %q", res.Errors, reasonNotFound)
		}
	})

	t.Run("directory", func(t *testing.T) {
		t.Parallel()
		path := t.TempDir()
		res := ReadConfig(t.Context(), path, "")
		if len(res.Servers) != 0 {
			t.Errorf("ReadConfig() servers = %v, want none", serverNames(res.Servers))
		}
		if len(res.Errors) != 1 || res.Errors[0].Reason != reasonNotRegular || res.Errors[0].Path != path {
			t.Errorf("ReadConfig() errors = %v, want one %q for %q", res.Errors, reasonNotRegular, path)
		}
	})

	t.Run("a file used as a directory is an error", func(t *testing.T) {
		t.Parallel()
		// A file used as a directory. ReadConfig confines the read to the
		// directory of the path, here a regular file. os.OpenRoot refuses it
		// with a "not a directory" error that has no OS error number on Unix,
		// so the reason is "cannot read file". Another OS can report the path
		// as missing ("file not found"). Both are one untrusted error.
		file := filepath.Join(t.TempDir(), "file.json")
		if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(file, "mcp.json")
		res := ReadConfig(t.Context(), path, "")
		if len(res.Servers) != 0 || len(res.Errors) != 1 {
			t.Fatalf("ReadConfig() = %+v, want exactly one error", res)
		}
		fe := res.Errors[0]
		if fe.Reason != reasonNotFound && fe.Reason != reasonCannotRead {
			t.Errorf("reason = %q, want %q or %q", fe.Reason, reasonNotFound, reasonCannotRead)
		}
		if fe.Path != path || !fe.Untrusted {
			t.Errorf("error = %+v, want path %q and Untrusted", fe, path)
		}
	})
}

// TestReadConfigUnknownFormat checks files that DetectClient does not know.
// Each gives one untrusted "unknown config format" error without config text.
func TestReadConfigUnknownFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
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
		// An empty or white space .json file has no servers, as "{}", so
		// only a known client file name is accepted.
		{"empty mcp.json", "mcp.json", ""},
		{"white space mcp.json", "mcp.json", " \n"},
		{"white space as package.json", "package.json", " \n\t"},
		{"array", "mcp.json", `[1]`},
		{"null projects", "mcp.json", `{"projects":null}`},
		{"other keys", "mcp.json", `{"theme":"dark"}`},
		{"mcpServers with wrong case", "mcp.json", `{"MCPServers":{"a":{"command":"x"}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), tt.file)
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatal(err)
			}
			res := ReadConfig(t.Context(), path, "")
			if len(res.Servers) != 0 {
				t.Errorf("ReadConfig() servers = %v, want none", serverNames(res.Servers))
			}
			if len(res.Errors) != 1 || res.Errors[0].Reason != reasonUnknownFormat || res.Errors[0].Path != path {
				t.Fatalf("ReadConfig() errors = %v, want one %q for %q", res.Errors, reasonUnknownFormat, path)
			}
			if !res.Errors[0].Untrusted {
				t.Error("FileError Untrusted = false, want true")
			}
			if text := strings.TrimSpace(tt.data); text != "" && strings.Contains(res.Errors[0].Error(), text) {
				t.Errorf("Error() = %q holds config text", res.Errors[0].Error())
			}
		})
	}
}

// TestReadConfigEmpty checks the known client files with no servers: an
// object with neither key, or only JSON white space. Each gives an empty
// result, as Discover does for the same file.
func TestReadConfigEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rel  []string
		data string
	}{
		{"empty object as .claude.json", []string{".claude.json"}, `{}`},
		{"other keys as .claude.json", []string{".claude.json"}, `{"numStartups":1}`},
		{"null projects as .claude.json", []string{".claude.json"}, `{"projects":null}`},
		{"empty object as .mcp.json", []string{".mcp.json"}, `{}`},
		{"empty object as .cursor/mcp.json", []string{".cursor", "mcp.json"}, `{}`},
		{"empty .claude.json", []string{".claude.json"}, ""},
		{"white space .mcp.json", []string{".mcp.json"}, " \n"},
		{"white space .cursor/mcp.json", []string{".cursor", "mcp.json"}, "\r\n\t"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(append([]string{t.TempDir()}, tt.rel...)...)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatal(err)
			}
			res := ReadConfig(t.Context(), path, "")
			if len(res.Servers) != 0 || len(res.Errors) != 0 {
				t.Errorf("ReadConfig() = %+v, want an empty result", res)
			}
		})
	}
}

// TestReadConfigMalformed checks that a file with a parse error gives one
// error with the reason and the position, and no config text.
func TestReadConfigMalformed(t *testing.T) {
	t.Parallel()

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
			res := ReadConfig(t.Context(), path, "")
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
		res := ReadConfig(t.Context(), path, "")
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
		res := ReadConfig(t.Context(), path, "")
		if len(res.Errors) != 1 || res.Errors[0].Reason != reasonInvalidTOML {
			t.Fatalf("ReadConfig() errors = %v, want one %q", res.Errors, reasonInvalidTOML)
		}
		assertNoLeakErrors(t, res.Errors)
	})
}

// TestReadConfigSecrets reads the secrets fixture of each client, the home
// files as global files and the work files as untrusted files, and checks
// that no secret value shows in a server or an error.
func TestReadConfigSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fixture string
		rel     [][]string // home and work files; work may be nil
		client  Client
	}{
		{"claude-code", "claude-code", [][]string{{"home", ".claude.json"}, {"work", ".mcp.json"}}, ClientClaudeCode},
		{"cursor", "cursor", [][]string{{"home", ".cursor", "mcp.json"}, {"work", ".cursor", "mcp.json"}}, ClientCursor},
		{"codex", "codex", [][]string{{"home", ".codex", "config.toml"}}, ClientCodex},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
				// With the home directory, the home files are read as global
				// files and the work files as untrusted files.
				res := ReadConfig(t.Context(), filepath.Join(append([]string{dir}, r[1:]...)...), home)
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
}

// TestReadConfigCanceled checks that a canceled context gives one "canceled"
// error and no servers, also for a missing file.
func TestReadConfigCanceled(t *testing.T) {
	t.Parallel()

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		home, _ := copyFixture(t, "claude-code", "valid")
		path := filepath.Join(home, ".claude.json")
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		res := ReadConfig(ctx, path, "")
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
		res := ReadConfig(ctx, filepath.Join(t.TempDir(), "nope.json"), "")
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

// caseInsensitiveFS reports whether the file system of dir finds a file by a
// name in another letter case. It writes a probe file in dir.
func caseInsensitiveFS(t testing.TB, dir string) bool {
	t.Helper()
	probe := writeFile(t, dir, "case-probe", nil)
	want, err := os.Stat(probe)
	if err != nil {
		t.Fatalf("stat %s: %v", probe, err)
	}
	got, err := os.Stat(filepath.Join(dir, "CASE-PROBE"))
	return err == nil && os.SameFile(want, got)
}

// TestReadConfigProjects checks the "projects" section of an untrusted Claude
// Code file. The section is not read. Any value that is not null, also an
// empty object, gives one untrusted "projects section not read" error, so
// the scan fails. The top-level servers are still returned.
func TestReadConfigProjects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		file      string
		data      string
		wantError bool
	}{
		{"projects with servers", ".claude.json", `{"projects":{"/p":{"mcpServers":{"p":{"command":"x"}}}},"mcpServers":{"o":{"command":"x"}}}`, true},
		{"empty projects object", ".claude.json", `{"projects":{},"mcpServers":{"o":{"command":"x"}}}`, true},
		{"projects of the wrong type", "backup.json", `{"projects":[1],"mcpServers":{"o":{"command":"x"}}}`, true},
		{"projects in a file with another name", "backup.json", `{"projects":{"/p":{"mcpServers":{"p":{"command":"x"}}}},"mcpServers":{"o":{"command":"x"}}}`, true},
		{"null projects", ".claude.json", `{"projects":null,"mcpServers":{"o":{"command":"x"}}}`, false},
		{"no projects key", ".claude.json", `{"mcpServers":{"o":{"command":"x"}}}`, false},
		{"projects key in another letter case", ".claude.json", `{"Projects":{"/p":{}},"mcpServers":{"o":{"command":"x"}}}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), tt.file, []byte(tt.data))

			res := ReadConfig(t.Context(), path, "")

			if got := serverNames(res.Servers); !slices.Equal(got, []string{"o"}) {
				t.Errorf("ReadConfig() servers = %v, want [o]", got)
			}
			if !tt.wantError {
				if len(res.Errors) != 0 {
					t.Errorf("ReadConfig() errors = %v, want none", res.Errors)
				}
				return
			}
			if len(res.Errors) != 1 {
				t.Fatalf("ReadConfig() errors = %v, want exactly one", res.Errors)
			}
			fe := res.Errors[0]
			if fe.Reason != reasonProjectsNotRead || fe.Path != path || fe.Server != "" || fe.ProjectPath != "" || !fe.Untrusted {
				t.Errorf("error = %+v, want reason %q, path %q, no server or project and Untrusted", fe, reasonProjectsNotRead, path)
			}
			if want := path + ": " + reasonProjectsNotRead; fe.Error() != want {
				t.Errorf("Error() = %q, want %q", fe.Error(), want)
			}
		})
	}

	t.Run("the error comes before the server errors", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, t.TempDir(), ".claude.json", []byte(`{"projects":{},"mcpServers":{"a":{"type":"bad"}}}`))
		res := ReadConfig(t.Context(), path, "")
		if len(res.Errors) != 2 || res.Errors[0].Reason != reasonProjectsNotRead || res.Errors[1].Server != "a" {
			t.Errorf("ReadConfig() errors = %v, want %q first, then the error of server a", res.Errors, reasonProjectsNotRead)
		}
	})

	t.Run("Discover does not report the projects of a project file", func(t *testing.T) {
		t.Parallel()
		// Only ReadConfig adds the error. Discover reads <WorkDir>/.mcp.json
		// with ReadClaudeCode and ScopeProject, which skips the section.
		work := t.TempDir()
		writeFile(t, work, ".mcp.json", []byte(`{"projects":{"/p":{}},"mcpServers":{"o":{"command":"x"}}}`))
		res := Discover(t.Context(), Options{WorkDir: work})
		if len(res.Errors) != 0 || len(res.Servers) != 1 {
			t.Errorf("Discover() = %+v, want one server and no errors", res)
		}
	})
}

// TestReadConfigReadsOnce checks that an untrusted file is parsed from the
// bytes of the detection read. The parse entries get a path that does not
// exist: they must still give the servers of the bytes, so they cannot read
// the file a second time. A file that goes away after the detection read
// therefore cannot turn into an empty, clean result.
func TestReadConfigReadsOnce(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "gone")

	t.Run("json", func(t *testing.T) {
		t.Parallel()
		for _, client := range []Client{ClientClaudeCode, ClientCursor} {
			servers, errs := parseJSONServers(t.Context(), jsonFile{
				path:    filepath.Join(missing, "mcp.json"),
				client:  client,
				scope:   ScopeProject,
				data:    []byte(`{"mcpServers":{"a":{"command":"x"}}}`),
				hasData: true,
			})
			if len(errs) != 0 || len(servers) != 1 || !servers[0].Untrusted {
				t.Errorf("%s: parseJSONServers() = %v, %v, want one untrusted server and no errors", client, servers, errs)
			}
		}
	})

	t.Run("codex", func(t *testing.T) {
		t.Parallel()
		res := readUntrustedCodex(t.Context(), filepath.Join(missing, "config.toml"), []byte("[mcp_servers.a]\ncommand = \"x\"\n"))
		if len(res.Errors) != 0 || len(res.Servers) != 1 || !res.Servers[0].Untrusted {
			t.Errorf("readUntrustedCodex() = %+v, want one untrusted server and no errors", res)
		}
	})
}

// TestReadConfigGlobalGone checks that a global file that goes away after the
// check in globalFor is "file not found", not an empty result. The test calls
// readGlobal on a home without the file, the state after such a race.
func TestReadConfigGlobalGone(t *testing.T) {
	t.Parallel()
	for _, g := range globalFiles {
		t.Run(g.rel, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			res := readGlobal(t.Context(), g, home)
			if len(res.Servers) != 0 || len(res.Errors) != 1 {
				t.Fatalf("readGlobal() = %+v, want exactly one error", res)
			}
			fe := res.Errors[0]
			if want := g.path(home); fe.Reason != reasonNotFound || fe.Path != want || fe.Untrusted {
				t.Errorf("error = %+v, want reason %q, path %q and not Untrusted", fe, reasonNotFound, want)
			}
		})
	}
}

// TestReadConfigCleansPath checks that ReadConfig cleans the path before it
// takes its directory, so a path that names a directory through ".." gives
// "not a regular file" and not "file is outside the project".
func TestReadConfigCleansPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	makeDir(t, dir, "sub")
	sep := string(filepath.Separator)

	tests := []struct {
		name     string
		path     string
		wantPath string
	}{
		// The test runs in the package directory, so ".." and "../.." are
		// directories of the repository.
		{"parent", "..", ".."},
		{"parent of parent", ".." + sep + "..", filepath.Join("..", "..")},
		{"dir/..", dir + sep + "sub" + sep + "..", dir},
		{"dir/.", dir + sep + "sub" + sep + ".", filepath.Join(dir, "sub")},
		{"current", ".", "."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := ReadConfig(t.Context(), tt.path, "")
			if len(res.Servers) != 0 || len(res.Errors) != 1 {
				t.Fatalf("ReadConfig(%q) = %+v, want exactly one error", tt.path, res)
			}
			fe := res.Errors[0]
			if fe.Reason != reasonNotRegular || fe.Path != tt.wantPath || !fe.Untrusted {
				t.Errorf("ReadConfig(%q) error = %+v, want reason %q, path %q and Untrusted", tt.path, fe, reasonNotRegular, tt.wantPath)
			}
		})
	}

	t.Run("a cleaned file path names the file", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, dir, "conf.json", []byte(`{"mcpServers":{"a":{"command":"x"}}}`))
		res := ReadConfig(t.Context(), dir+sep+"sub"+sep+".."+sep+"conf.json", "")
		if len(res.Errors) != 0 || len(res.Servers) != 1 {
			t.Fatalf("ReadConfig() = %+v, want one server and no errors", res)
		}
		if s := res.Servers[0]; s.Source != path || s.ProjectPath != dir {
			t.Errorf("server = %+v, want Source %q and ProjectPath %q", s, path, dir)
		}
	})
}
