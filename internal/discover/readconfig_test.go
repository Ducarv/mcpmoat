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
		// wantReasons are the reasons of the errors for the whole file, in
		// order. Each error must name the file and be Untrusted.
		wantReasons []string
		// wantServerErrs are the errors for one server, in order, after the
		// errors of wantReasons. Each error must name the file and be
		// Untrusted.
		wantServerErrs []errWant
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
			// .codex directory as the project directory. The git server has
			// cwd "/tmp", which is outside that project, so it is dropped.
			name:       "codex that is not the home file",
			fixture:    "codex",
			side:       "home",
			rel:        []string{".codex", "config.toml"},
			wantClient: ClientCodex,
			wantServers: func(home, _ string) []wantServer {
				return wantProject(home, "docs", "remote")
			},
			wantServerErrs: []errWant{{Server: "git", Reason: reasonCwdOutsideProject}},
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

			if len(res.Errors) != len(tt.wantReasons)+len(tt.wantServerErrs) {
				t.Fatalf("ReadConfig() errors = %v, want reasons %q and server errors %+v", res.Errors, tt.wantReasons, tt.wantServerErrs)
			}
			for i, fe := range res.Errors[:len(tt.wantReasons)] {
				if fe.Reason != tt.wantReasons[i] || fe.Path != path || fe.Server != "" || !fe.Untrusted {
					t.Errorf("error %d = %+v, want reason %q, path %q, no server and Untrusted", i, fe, tt.wantReasons[i], path)
				}
			}
			for i, fe := range res.Errors[len(tt.wantReasons):] {
				w := tt.wantServerErrs[i]
				if fe.Reason != w.Reason || fe.Path != path || fe.Server != w.Server || !fe.Untrusted {
					t.Errorf("server error %d = %+v, want reason %q, path %q, server %q and Untrusted", i, fe, w.Reason, path, w.Server)
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
		// The git server of the fixture has cwd "/tmp", outside the project.
		if len(res.Errors) != 1 || res.Errors[0].Reason != reasonCwdOutsideProject || len(res.Servers) == 0 {
			t.Fatalf("ReadConfig() = %+v, want codex servers and one %q error", res, reasonCwdOutsideProject)
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

	t.Run("a symlinked directory in the path is followed", func(t *testing.T) {
		t.Parallel()
		// Only the file is confined to its directory. The directories in the
		// path are the user's choice, so ReadConfig follows proj/.cursor to
		// outside. The file is still untrusted, and the ProjectPath comes from
		// the path as written.
		outside := t.TempDir()
		writeFile(t, outside, "mcp.json", []byte(`{"mcpServers":{"a":{"command":"x"}}}`))
		proj := t.TempDir()
		symlinkTo(t, outside, proj, ".cursor")
		path := filepath.Join(proj, ".cursor", "mcp.json")

		res := ReadConfig(t.Context(), path, "")

		if len(res.Errors) != 0 || len(res.Servers) != 1 {
			t.Fatalf("ReadConfig() = %+v, want one server and no errors", res)
		}
		s := res.Servers[0]
		if !s.Untrusted || s.Scope != ScopeProject || s.ProjectPath != proj || s.Source != path || s.Client != ClientCursor {
			t.Errorf("server = %+v, want Untrusted, ScopeProject, ProjectPath %q, Source %q and client cursor", s, proj, path)
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
		// A .toml file with no mcp_servers key has no servers, so only the
		// known name .codex/config.toml is accepted, as for JSON.
		{"pyproject.toml", "pyproject.toml", "[project]\nname = \"x\"\n"},
		{"Cargo.toml", "Cargo.toml", "[package]\nname = \"x\"\n"},
		{"empty foo.toml", "foo.toml", ""},
		{"white space foo.toml", "foo.toml", " \n\t\r\n"},
		{"comments only foo.toml", "foo.toml", "# a comment\n\n# another one\n"},
		{"config.toml outside .codex", "config.toml", "model = \"o3\"\n"},
		{"other name in .codex", ".codex/other.toml", ""},
		{"config.toml in a dir named .Codex", ".Codex/config.toml", ""},
		{"upper case CONFIG.TOML in .codex", ".codex/CONFIG.TOML", ""},
		{"config.toml in a nested dir below .codex", ".codex/sub/config.toml", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), tt.file, []byte(tt.data))
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
		{"empty .codex/config.toml", []string{".codex", "config.toml"}, ""},
		{"comments only .codex/config.toml", []string{".codex", "config.toml"}, "# a comment\n"},
		{"other keys as .codex/config.toml", []string{".codex", "config.toml"}, "model = \"o3\"\n"},
		// The file has the mcp_servers key, so any name is read as Codex.
		{"empty mcp_servers table in foo.toml", []string{"foo.toml"}, "[mcp_servers]\n"},
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

// TestReadConfigProjects checks the "projects" section of an untrusted JSON
// file, Claude Code or Cursor. The section is not read. Any value that is not null, also an
// empty object, gives one untrusted "projects section not read" error, so
// the scan fails. A key in another letter case, such as "Projects", gives
// one untrusted "ambiguous key" error, as in a global file. The top-level
// servers are still returned.
func TestReadConfigProjects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		file        string
		data        string
		wantReasons []string
	}{
		{"projects with servers", ".claude.json", `{"projects":{"/p":{"mcpServers":{"p":{"command":"x"}}}},"mcpServers":{"o":{"command":"x"}}}`, []string{reasonProjectsNotRead}},
		{"empty projects object", ".claude.json", `{"projects":{},"mcpServers":{"o":{"command":"x"}}}`, []string{reasonProjectsNotRead}},
		{"projects of the wrong type", "backup.json", `{"projects":[1],"mcpServers":{"o":{"command":"x"}}}`, []string{reasonProjectsNotRead}},
		{"projects in a file with another name", "backup.json", `{"projects":{"/p":{"mcpServers":{"p":{"command":"x"}}}},"mcpServers":{"o":{"command":"x"}}}`, []string{reasonProjectsNotRead}},
		{"null projects", ".claude.json", `{"projects":null,"mcpServers":{"o":{"command":"x"}}}`, nil},
		{"no projects key", ".claude.json", `{"mcpServers":{"o":{"command":"x"}}}`, nil},
		{"projects key in another letter case", ".claude.json", `{"Projects":{"/p":{}},"mcpServers":{"o":{"command":"x"}}}`, []string{reasonAmbiguousKey}},
		{"null projects key in another letter case", "backup.json", `{"PROJECTS":null,"mcpServers":{"o":{"command":"x"}}}`, []string{reasonAmbiguousKey}},
		{"projects and a case variant", ".claude.json", `{"projects":{},"Projects":{},"mcpServers":{"o":{"command":"x"}}}`, []string{reasonAmbiguousKey, reasonProjectsNotRead}},
		{"null projects and a case variant", ".claude.json", `{"projects":null,"Projects":{},"mcpServers":{"o":{"command":"x"}}}`, []string{reasonAmbiguousKey}},
		// DetectClient picks Cursor for these files (no "projects" key), and
		// the rule is the same.
		{"case variant in a cursor file", ".cursor/mcp.json", `{"Projects":{"/p":{}},"mcpServers":{"o":{"command":"x"}}}`, []string{reasonAmbiguousKey}},
		{"null projects and a case variant in a cursor file", ".cursor/mcp.json", `{"projects":null,"PROJECTS":null,"mcpServers":{"o":{"command":"x"}}}`, []string{reasonAmbiguousKey}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), tt.file, []byte(tt.data))

			res := ReadConfig(t.Context(), path, "")

			if got := serverNames(res.Servers); !slices.Equal(got, []string{"o"}) {
				t.Errorf("ReadConfig() servers = %v, want [o]", got)
			}
			if len(res.Errors) != len(tt.wantReasons) {
				t.Fatalf("ReadConfig() errors = %v, want reasons %q", res.Errors, tt.wantReasons)
			}
			for i, fe := range res.Errors {
				want := tt.wantReasons[i]
				if fe.Reason != want || fe.Path != path || fe.Server != "" || fe.ProjectPath != "" || !fe.Untrusted {
					t.Errorf("error %d = %+v, want reason %q, path %q, no server or project and Untrusted", i, fe, want, path)
				}
				if want := path + ": " + want; fe.Error() != want {
					t.Errorf("Error() = %q, want %q", fe.Error(), want)
				}
			}
		})
	}

	t.Run("a cursor file is read as cursor", func(t *testing.T) {
		t.Parallel()
		// The cases above with .cursor/mcp.json test the Cursor client only
		// if DetectClient picks it for them.
		path := writeFile(t, t.TempDir(), ".cursor/mcp.json", []byte(`{"Projects":{},"mcpServers":{"o":{"command":"x"}}}`))
		res := ReadConfig(t.Context(), path, "")
		if len(res.Servers) != 1 || res.Servers[0].Client != ClientCursor {
			t.Errorf("ReadConfig() servers = %+v, want one cursor server", res.Servers)
		}
	})

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
			res := readUntrustedJSON(t.Context(), filepath.Join(missing, "mcp.json"), client, []byte(`{"mcpServers":{"a":{"command":"x"}}}`))
			if len(res.Errors) != 0 || len(res.Servers) != 1 || !res.Servers[0].Untrusted {
				t.Errorf("%s: readUntrustedJSON() = %+v, want one untrusted server and no errors", client, res)
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

// TestReadConfigCodexCwd checks the lexical step of the cwd check of an
// untrusted Codex file through ReadConfig. A server whose cwd fails is
// dropped and gives an untrusted reasonCwdOutsideProject error. A cwd with a
// ".." element always fails. An empty cwd, a local relative cwd (also with a
// "." element) and an absolute cwd in the project are kept as written.
func TestReadConfigCodexCwd(t *testing.T) {
	t.Parallel()
	sep := string(filepath.Separator)

	tests := []struct {
		name string
		// rel is the path of the config file below the temporary directory.
		// Its project is that directory, also for .codex/config.toml.
		rel []string
		// cwd returns the cwd value for the project directory proj, or ok
		// false for an entry with no cwd key.
		cwd     func(proj string) (cwd string, ok bool)
		wantDir func(proj string) string // nil: the server is dropped
	}{
		{name: "root", rel: []string{"conf.toml"}, cwd: fixedCwd("/")},
		{name: "etc", rel: []string{"conf.toml"}, cwd: fixedCwd("/etc")},
		{name: "parent", rel: []string{"conf.toml"}, cwd: fixedCwd("../x")},
		{name: "parent through a subdirectory", rel: []string{"conf.toml"}, cwd: fixedCwd("a/../../x")},
		{name: "parent of a .codex project", rel: []string{".codex", "config.toml"}, cwd: fixedCwd("..")},
		{
			name: "absolute next to the project",
			rel:  []string{"conf.toml"},
			cwd:  func(proj string) (string, bool) { return proj + "-other", true },
		},
		{
			name: "absolute that leaves the project through ..",
			rel:  []string{"conf.toml"},
			cwd:  func(proj string) (string, bool) { return proj + sep + "sub" + sep + ".." + sep + "..", true },
		},
		{
			// A ".." element is refused also when the text stays in the
			// project: the kernel resolves ".." after a symlink.
			name: "absolute with .. that stays in the project",
			rel:  []string{"conf.toml"},
			cwd:  func(proj string) (string, bool) { return proj + sep + "sub" + sep + "..", true },
		},
		{name: "relative with .. that stays local", rel: []string{"conf.toml"}, cwd: fixedCwd("a/../b")},
		{name: "relative with .. back to the same directory", rel: []string{"conf.toml"}, cwd: fixedCwd("sub/../sub")},
		{
			name:    "absolute in the project",
			rel:     []string{"conf.toml"},
			cwd:     func(proj string) (string, bool) { return filepath.Join(proj, "sub"), true },
			wantDir: func(proj string) string { return filepath.Join(proj, "sub") },
		},
		{
			name:    "absolute project directory",
			rel:     []string{".codex", "config.toml"},
			cwd:     func(proj string) (string, bool) { return proj, true },
			wantDir: func(proj string) string { return proj },
		},
		{name: "relative subdirectory", rel: []string{"conf.toml"}, cwd: fixedCwd("sub"), wantDir: fixedDir("sub")},
		{name: "relative with a . element", rel: []string{"conf.toml"}, cwd: fixedCwd("./sub"), wantDir: fixedDir("./sub")},
		{name: "relative current directory", rel: []string{"conf.toml"}, cwd: fixedCwd("."), wantDir: fixedDir(".")},
		{name: "empty", rel: []string{"conf.toml"}, cwd: fixedCwd(""), wantDir: fixedDir("")},
		{
			name:    "no cwd",
			rel:     []string{"conf.toml"},
			cwd:     func(string) (string, bool) { return "", false },
			wantDir: fixedDir(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			proj := t.TempDir()
			// sub exists, so a kept cwd below it also passes the symlink step
			// on a real directory.
			makeDir(t, proj, "sub")
			cwd, hasCwd := tt.cwd(proj)
			// "ok" has no cwd, so the result also shows that one dropped
			// server does not drop the others.
			config := "[mcp_servers.ok]\ncommand = \"x\"\n\n[mcp_servers.x]\ncommand = \"x\"\n"
			if hasCwd {
				// A TOML literal string ('...') has no escapes, so a Windows
				// path needs no change.
				config += "cwd = '" + cwd + "'\n"
			}
			path := writeFile(t, proj, filepath.Join(tt.rel...), []byte(config))

			res := ReadConfig(t.Context(), path, "")

			if tt.wantDir == nil {
				if got := serverNames(res.Servers); !slices.Equal(got, []string{"ok"}) {
					t.Errorf("ReadConfig() servers = %v, want [ok]", got)
				}
				if len(res.Errors) != 1 {
					t.Fatalf("ReadConfig() errors = %v, want exactly one", res.Errors)
				}
				fe := res.Errors[0]
				if fe.Reason != reasonCwdOutsideProject || fe.Path != path || fe.Server != "x" || !fe.Untrusted {
					t.Errorf("error = %+v, want reason %q, path %q, server x and Untrusted", fe, reasonCwdOutsideProject, path)
				}
				return
			}
			if len(res.Errors) != 0 || len(res.Servers) != 2 {
				t.Fatalf("ReadConfig() = %+v, want servers ok and x and no errors", res)
			}
			s := res.Servers[1]
			if want := tt.wantDir(proj); s.Name != "x" || s.Dir != want || s.ProjectPath != proj || !s.Untrusted {
				t.Errorf("server = %+v, want x with Dir %q, ProjectPath %q and Untrusted", s, want, proj)
			}
		})
	}

	t.Run("the error keeps the order by server name", func(t *testing.T) {
		t.Parallel()
		config := "[mcp_servers.a]\ncommand = \"x\"\ncwd = '/'\n\n[mcp_servers.b]\ncommand = 5\n\n[mcp_servers.c]\ncommand = \"x\"\ncwd = '../c'\n"
		path := writeFile(t, t.TempDir(), "conf.toml", []byte(config))
		res := ReadConfig(t.Context(), path, "")
		got := make([]string, 0, len(res.Errors))
		for _, fe := range res.Errors {
			got = append(got, fe.Server+": "+fe.Reason)
		}
		want := []string{"a: " + reasonCwdOutsideProject, "b: " + reasonBadEntry, "c: " + reasonCwdOutsideProject}
		if len(res.Servers) != 0 || !slices.Equal(got, want) {
			t.Errorf("ReadConfig() = servers %v, errors %q, want no servers and errors %q", res.Servers, got, want)
		}
	})

	t.Run("the user's own Codex file keeps any cwd", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		path := writeFile(t, home, filepath.Join(".codex", "config.toml"), []byte("[mcp_servers.x]\ncommand = \"x\"\ncwd = '/'\n"))
		res := ReadConfig(t.Context(), path, home)
		if len(res.Errors) != 0 || len(res.Servers) != 1 || res.Servers[0].Dir != "/" || res.Servers[0].Untrusted {
			t.Errorf("ReadConfig() = %+v, want one trusted server with Dir \"/\"", res)
		}
	})
}

// fixedCwd returns a cwd function of TestReadConfigCodexCwd that gives cwd for
// every project directory.
func fixedCwd(cwd string) func(string) (string, bool) {
	return func(string) (string, bool) { return cwd, true }
}

// fixedDir returns a wantDir function of TestReadConfigCodexCwd that gives
// dir for every project directory.
func fixedDir(dir string) func(string) string {
	return func(string) string { return dir }
}

// TestProjectDirHoldsDir checks the lexical step of the cwd rule of an untrusted
// Codex file, also with a relative ProjectPath, which ReadConfig gives for a
// relative path. No dir of the cases exists, so the symlink step keeps every
// dir that the lexical step keeps. TestReadConfigCodexCwdSymlink checks the
// symlink step.
func TestProjectDirHoldsDir(t *testing.T) {
	t.Parallel()
	abs := t.TempDir()
	tests := []struct {
		name        string
		dir         string
		projectPath string
		want        bool
	}{
		{"empty dir", "", "proj", true},
		{"local dir", "sub", "proj", true},
		{"current dir", ".", "proj", true},
		{"parent dir", "..", "proj", false},
		{"dir that leaves through a subdirectory", "a/../../x", abs, false},
		{"local dir with a .. element", "a/../b", "proj", false},
		{"local dir with a . element", "./sub", "proj", true},
		{"absolute dir with a .. element in the project", abs + string(filepath.Separator) + "a" + string(filepath.Separator) + "..", abs, false},
		{"absolute dir with a . element", abs + string(filepath.Separator) + "." + string(filepath.Separator) + "a", abs, true},
		{"absolute root", "/", abs, false},
		{"absolute project itself", abs, abs, true},
		{"absolute below the project", filepath.Join(abs, "a", "b"), abs, true},
		{"absolute with a name that starts like the project", abs + "x", abs, false},
		{"absolute dir with a relative project", abs, "proj", false},
		{"absolute dir with the project .", abs, ".", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := openProjectDir(tt.projectPath)
			defer p.close()
			if got := p.holdsDir(tt.dir); got != tt.want {
				t.Errorf("holdsDir(%q) with project %q = %v, want %v", tt.dir, tt.projectPath, got, tt.want)
			}
		})
	}
}

// TestReadConfigTOMLName checks the other .toml files: a file with an
// mcp_servers key is read as Codex under any name, and a file that is not
// valid TOML is reported, not called an unknown format.
func TestReadConfigTOMLName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		file        string
		data        string
		wantServers []string
		wantReason  string // "" for no error
	}{
		{"servers in foo.toml", "foo.toml", "[mcp_servers.a]\ncommand = \"x\"\n", []string{"a"}, ""},
		{"servers in pyproject.toml", "pyproject.toml", "[project]\nname = \"x\"\n\n[mcp_servers.a]\ncommand = \"x\"\n", []string{"a"}, ""},
		{"mcp_servers of the wrong type in foo.toml", "foo.toml", "mcp_servers = 5\n", nil, reasonBadShape},
		{"mcp_servers in another letter case in foo.toml", "foo.toml", "[MCP_Servers.a]\ncommand = \"x\"\n", nil, reasonAmbiguousKey},
		{"invalid TOML in foo.toml", "foo.toml", "[mcp_servers\n", nil, reasonInvalidTOML},
		{"invalid TOML in Cargo.toml", "Cargo.toml", "name = \n", nil, reasonInvalidTOML},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, t.TempDir(), tt.file, []byte(tt.data))

			res := ReadConfig(t.Context(), path, "")

			if got := serverNames(res.Servers); !slices.Equal(got, tt.wantServers) {
				t.Errorf("ReadConfig() servers = %v, want %v", got, tt.wantServers)
			}
			for _, s := range res.Servers {
				if s.Client != ClientCodex || !s.Untrusted {
					t.Errorf("server %q = %+v, want client codex and Untrusted", s.Name, s)
				}
			}
			if tt.wantReason == "" {
				if len(res.Errors) != 0 {
					t.Errorf("ReadConfig() errors = %v, want none", res.Errors)
				}
				return
			}
			if len(res.Errors) != 1 || res.Errors[0].Reason != tt.wantReason || !res.Errors[0].Untrusted {
				t.Errorf("ReadConfig() errors = %v, want one untrusted %q", res.Errors, tt.wantReason)
			}
		})
	}
}

// TestReadConfigProjectPath checks that the path, not the detected client,
// decides the ProjectPath: a file directly in a ".cursor" or ".codex"
// directory gets the parent of that directory for every client.
func TestReadConfigProjectPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		rel         string // with forward slashes, below the project
		data        string
		wantClient  Client
		wantReasons []string
		// wantInDir is true when the ProjectPath is the directory of the
		// file, and false when it is the project, the parent of that
		// directory.
		wantInDir bool
	}{
		{
			// A "projects" key makes the file Claude Code, also in .cursor.
			name:        "claude-code file with projects in .cursor",
			rel:         ".cursor/mcp.json",
			data:        `{"projects":{},"mcpServers":{"a":{"command":"x"}}}`,
			wantClient:  ClientClaudeCode,
			wantReasons: []string{reasonProjectsNotRead},
		},
		{"cursor file in .cursor", ".cursor/mcp.json", `{"mcpServers":{"a":{"command":"x"}}}`, ClientCursor, nil, false},
		{"claude-code file in .codex", ".codex/mcp.json", `{"mcpServers":{"a":{"command":"x"}}}`, ClientClaudeCode, nil, false},
		{"codex file in .cursor", ".cursor/config.toml", "[mcp_servers.a]\ncommand = \"x\"\n", ClientCodex, nil, false},
		{"codex file in .codex", ".codex/config.toml", "[mcp_servers.a]\ncommand = \"x\"\n", ClientCodex, nil, false},
		{"claude-code file in another dir", "conf/mcp.json", `{"mcpServers":{"a":{"command":"x"}}}`, ClientClaudeCode, nil, true},
		{"codex file in another dir", "conf/x.toml", "[mcp_servers.a]\ncommand = \"x\"\n", ClientCodex, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			proj := t.TempDir()
			path := writeFile(t, proj, tt.rel, []byte(tt.data))
			want := proj
			if tt.wantInDir {
				want = filepath.Dir(path)
			}

			res := ReadConfig(t.Context(), path, "")

			var got []string
			for _, fe := range res.Errors {
				got = append(got, fe.Reason)
			}
			if !slices.Equal(got, tt.wantReasons) {
				t.Errorf("ReadConfig() errors = %v, want reasons %q", res.Errors, tt.wantReasons)
			}
			if len(res.Servers) != 1 {
				t.Fatalf("ReadConfig() servers = %v, want one", serverNames(res.Servers))
			}
			if s := res.Servers[0]; s.Client != tt.wantClient || s.ProjectPath != want {
				t.Errorf("server = %+v, want client %q and ProjectPath %q", s, tt.wantClient, want)
			}
		})
	}
}

// TestReadConfigCodexCwdSymlink checks the symlink step of the cwd rule of an
// untrusted Codex file. A cwd that leads out of the project through a
// symlink, passes an absolute symlink or is not a directory is dropped. A
// symlink that stays in the project is followed, and a cwd that does not
// exist is kept.
func TestReadConfigCodexCwdSymlink(t *testing.T) {
	t.Parallel()

	outside := t.TempDir()
	tests := []struct {
		name string
		// setup makes the files of the case below the project proj.
		setup func(t *testing.T, proj string)
		// cwd returns the cwd value for proj.
		cwd  func(proj string) string
		keep bool
	}{
		{"relative symlink out of the project", func(t *testing.T, proj string) {
			symlinkTo(t, "..", proj, "link")
		}, relCwd("link"), false},
		{"absolute symlink to the file system root", func(t *testing.T, proj string) {
			symlinkTo(t, string(filepath.Separator), proj, "link")
		}, relCwd("link"), false},
		{"absolute symlink to another directory", func(t *testing.T, proj string) {
			symlinkTo(t, outside, proj, "link")
		}, relCwd("link"), false},
		{"path below a symlink out of the project", func(t *testing.T, proj string) {
			symlinkTo(t, outside, proj, "link")
		}, relCwd("link/sub"), false},
		{"absolute cwd through a symlink out of the project", func(t *testing.T, proj string) {
			symlinkTo(t, outside, proj, "link")
		}, func(proj string) string { return filepath.Join(proj, "link") }, false},
		{"symlink below a subdirectory out of the project", func(t *testing.T, proj string) {
			makeDir(t, proj, "a")
			symlinkTo(t, "../..", proj, "a/link")
		}, relCwd("a/link"), false},
		{"lexically local path through a symlink", func(t *testing.T, proj string) {
			symlinkTo(t, outside, proj, "link")
		}, relCwd("link/../x"), false},
		{"absolute cwd with .. after a symlink out of the project", func(t *testing.T, proj string) {
			// filepath.Rel cleans "<proj>/link/.." to "." as text, but the
			// kernel goes up from outside, the target of link.
			symlinkTo(t, outside, proj, "link")
		}, func(proj string) string { return filepath.Join(proj, "link") + string(filepath.Separator) + ".." }, false},
		{"relative cwd with .. after a symlink out of the project", func(t *testing.T, proj string) {
			symlinkTo(t, outside, proj, "link")
		}, relCwd("link/.."), false},
		{"dangling symlink out of the project", func(t *testing.T, proj string) {
			symlinkTo(t, "../does-not-exist", proj, "link")
		}, relCwd("link"), false},
		{"absolute symlink into the project", func(t *testing.T, proj string) {
			sub := makeDir(t, proj, "sub")
			symlinkTo(t, sub, proj, "link")
		}, relCwd("link"), false},
		{"regular file", func(t *testing.T, proj string) {
			writeFile(t, proj, "file", nil)
		}, relCwd("file"), false},
		{"symlink to a regular file", func(t *testing.T, proj string) {
			writeFile(t, proj, "file", nil)
			symlinkTo(t, "file", proj, "link")
		}, relCwd("link"), false},
		{"symlink loop", func(t *testing.T, proj string) {
			symlinkTo(t, "loop", proj, "loop")
		}, relCwd("loop"), false},
		{"relative symlink inside the project", func(t *testing.T, proj string) {
			makeDir(t, proj, "sub")
			symlinkTo(t, "sub", proj, "link")
		}, relCwd("link"), true},
		{"symlink up to the project itself", func(t *testing.T, proj string) {
			makeDir(t, proj, "a")
			symlinkTo(t, "..", proj, "a/link")
		}, relCwd("a/link"), true},
		{"absolute cwd through a symlink inside the project", func(t *testing.T, proj string) {
			makeDir(t, proj, "sub")
			symlinkTo(t, "sub", proj, "link")
		}, func(proj string) string { return filepath.Join(proj, "link") }, true},
		{"dangling symlink inside the project", func(t *testing.T, proj string) {
			symlinkTo(t, "does-not-exist", proj, "link")
		}, relCwd("link"), true},
		{"directory that does not exist", func(*testing.T, string) {}, relCwd("missing/sub"), true},
		{"existing directory", func(t *testing.T, proj string) {
			makeDir(t, proj, "sub")
		}, relCwd("sub"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			proj := t.TempDir()
			tt.setup(t, proj)
			cwd := tt.cwd(proj)
			// A TOML literal string ('...') has no escapes, so a Windows path
			// needs no change. The config is in .codex, so its project is
			// proj, and the read of the file stays in .codex.
			config := "[mcp_servers.x]\ncommand = \"x\"\ncwd = '" + cwd + "'\n"
			path := writeFile(t, proj, ".codex/config.toml", []byte(config))

			res := ReadConfig(t.Context(), path, "")

			if tt.keep {
				if len(res.Errors) != 0 || len(res.Servers) != 1 {
					t.Fatalf("ReadConfig() = %+v, want server x and no errors", res)
				}
				if s := res.Servers[0]; s.Dir != cwd || s.ProjectPath != proj {
					t.Errorf("server = %+v, want Dir %q and ProjectPath %q", s, cwd, proj)
				}
				return
			}
			if len(res.Servers) != 0 {
				t.Errorf("ReadConfig() servers = %v, want none", serverNames(res.Servers))
			}
			if len(res.Errors) != 1 {
				t.Fatalf("ReadConfig() errors = %v, want exactly one", res.Errors)
			}
			if fe := res.Errors[0]; fe.Reason != reasonCwdOutsideProject || fe.Server != "x" || !fe.Untrusted {
				t.Errorf("error = %+v, want reason %q, server x and Untrusted", fe, reasonCwdOutsideProject)
			}
		})
	}
}

// relCwd returns a cwd function of TestReadConfigCodexCwdSymlink that gives
// the relative path p, written with forward slashes, for every project.
func relCwd(p string) func(string) string {
	return func(string) string { return filepath.FromSlash(p) }
}
