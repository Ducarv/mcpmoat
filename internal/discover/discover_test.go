package discover

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// writeDiscoverFile writes content to dir/rel and creates the parent directories.
func writeDiscoverFile(t testing.TB, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("create directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// assertDiscoverNoErrors fails the test if r has any error.
func assertDiscoverNoErrors(t testing.TB, r Result) {
	t.Helper()
	for _, e := range r.Errors {
		t.Errorf("unexpected error: %v", e)
	}
}

// assertDiscoverNames fails the test if the server names in r are not exactly want.
func assertDiscoverNames(t testing.TB, r Result, want []string) {
	t.Helper()
	got := serverNames(r.Servers)
	if len(want) == 0 && len(got) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("server names = %v, want %v", got, want)
	}
}

// TestDiscoverFull is the FR-01 acceptance case: all three clients, home and
// project files, found in one call and in the fixed file order.
func TestDiscoverFull(t *testing.T) {
	t.Parallel()
	home, work := copyFixture(t, "all", "full")

	r := Discover(t.Context(), Options{Home: home, WorkDir: work})

	assertDiscoverNoErrors(t, r)
	wantNames := []string{"cc-global", "cc-alpha", "cc-project", "cursor-global", "cursor-project", "codex-global"}
	assertDiscoverNames(t, r, wantNames)
	if len(r.Servers) != len(wantNames) {
		t.Fatalf("got %d servers, want %d", len(r.Servers), len(wantNames))
	}

	want := map[string]serverView{
		"cc-global": {
			Name: "cc-global", Client: ClientClaudeCode, Scope: ScopeGlobal,
			Source:    filepath.Join(home, ".claude.json"),
			Transport: TransportStdio, Command: "npx", Args: []string{"-y", "cc-global"},
		},
		"cc-alpha": {
			Name: "cc-alpha", Client: ClientClaudeCode, Scope: ScopeProject,
			ProjectPath: "/work/alpha",
			Source:      filepath.Join(home, ".claude.json"),
			Transport:   TransportStdio, Command: "node", Args: []string{"alpha.js"},
		},
		"cc-project": {
			Name: "cc-project", Client: ClientClaudeCode, Scope: ScopeProject,
			ProjectPath: work,
			Source:      filepath.Join(work, ".mcp.json"),
			Transport:   TransportHTTP, URL: "https://cc-project.example.com/mcp",
		},
		"cursor-global": {
			Name: "cursor-global", Client: ClientCursor, Scope: ScopeGlobal,
			Source:    filepath.Join(home, ".cursor", "mcp.json"),
			Transport: TransportStdio, Command: "uvx", Args: []string{"cursor-global"},
		},
		"cursor-project": {
			Name: "cursor-project", Client: ClientCursor, Scope: ScopeProject,
			ProjectPath: work,
			Source:      filepath.Join(work, ".cursor", "mcp.json"),
			Transport:   TransportHTTP, URL: "https://cursor-project.example.com/mcp",
		},
		"codex-global": {
			Name: "codex-global", Client: ClientCodex, Scope: ScopeGlobal,
			Source:    filepath.Join(home, ".codex", "config.toml"),
			Transport: TransportStdio, Command: "npx", Args: []string{"-y", "codex-global"},
		},
	}
	for _, s := range r.Servers {
		w, ok := want[s.Name]
		if !ok {
			t.Errorf("unexpected server %q", s.Name)
			continue
		}
		if got := viewOf(s); !reflect.DeepEqual(got, w) {
			t.Errorf("server %s:\n got  %+v\n want %+v", s.Name, got, w)
		}
	}
}

// TestDiscoverPartialFailure checks that one broken file does not hide the
// servers of the other files.
func TestDiscoverPartialFailure(t *testing.T) {
	t.Parallel()
	home, work := copyFixture(t, "all", "partial-failure")

	r := Discover(t.Context(), Options{Home: home, WorkDir: work})

	assertDiscoverNames(t, r, []string{"cc-project", "cursor-global", "cursor-project", "codex-global"})
	if len(r.Errors) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(r.Errors), r.Errors)
	}
	e := r.Errors[0]
	if want := filepath.Join(home, ".claude.json"); e.Path != want {
		t.Errorf("error Path = %q, want %q", e.Path, want)
	}
	if e.Reason != reasonInvalidJSON {
		t.Errorf("error Reason = %q, want %q", e.Reason, reasonInvalidJSON)
	}
	if e.Line <= 0 {
		t.Errorf("error Line = %d, want > 0", e.Line)
	}
	if e.Server != "" {
		t.Errorf("error Server = %q, want empty for a whole-file problem", e.Server)
	}
}

// TestDiscoverSameHomeAndWork checks that a file is read once when WorkDir is
// the home directory, however the directory is spelled.
func TestDiscoverSameHomeAndWork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		workDir func(home string) string
	}{
		{name: "same string", workDir: func(home string) string { return home }},
		{name: "trailing dot", workDir: func(home string) string { return home + "/." }},
		{name: "trailing separator", workDir: func(home string) string { return home + string(filepath.Separator) }},
		{name: "double separator", workDir: func(home string) string { return home + "//" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, _ := copyFixture(t, "all", "same-home-and-work")
			workDir := tt.workDir(home)

			r := Discover(t.Context(), Options{Home: home, WorkDir: workDir})

			assertDiscoverNoErrors(t, r)
			// only-once is in ~/.cursor/mcp.json. Without the dedupe it would
			// appear twice, the second time as a project server.
			assertDiscoverNames(t, r, []string{"cc-once", "mcp-json", "only-once"})
			for _, s := range r.Servers {
				switch s.Name {
				case "mcp-json":
					if s.Scope != ScopeProject {
						t.Errorf("mcp-json Scope = %q, want %q", s.Scope, ScopeProject)
					}
					if filepath.Clean(s.ProjectPath) != home {
						t.Errorf("mcp-json ProjectPath = %q, want %q", s.ProjectPath, home)
					}
				case "only-once":
					if s.Scope != ScopeGlobal || s.ProjectPath != "" {
						t.Errorf("only-once Scope = %q, ProjectPath = %q, want global and empty", s.Scope, s.ProjectPath)
					}
				}
			}
		})
	}
}

// TestDiscoverEmptyOptions checks that empty Options read nothing.
func TestDiscoverEmptyOptions(t *testing.T) {
	t.Parallel()

	r := Discover(t.Context(), Options{})

	if len(r.Servers) != 0 || len(r.Errors) != 0 {
		t.Errorf("Discover(Options{}) = %d servers, %d errors, want an empty Result", len(r.Servers), len(r.Errors))
	}
}

// TestDiscoverIgnoresRealHome proves that Discover never reads $HOME or the
// current directory by itself. It is not parallel: t.Setenv and t.Chdir panic
// in a parallel test.
func TestDiscoverIgnoresRealHome(t *testing.T) {
	dir := t.TempDir()
	const jsonConfig = `{"mcpServers": {"trap": {"command": "x"}}}`
	writeDiscoverFile(t, dir, ".claude.json", jsonConfig)
	writeDiscoverFile(t, dir, ".mcp.json", jsonConfig)
	writeDiscoverFile(t, dir, filepath.Join(".cursor", "mcp.json"), jsonConfig)
	writeDiscoverFile(t, dir, filepath.Join(".codex", "config.toml"), "[mcp_servers.trap]\ncommand = \"x\"\n")
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Chdir(dir)

	r := Discover(t.Context(), Options{})

	if len(r.Servers) != 0 || len(r.Errors) != 0 {
		t.Errorf("Discover(Options{}) = servers %v, errors %v, want an empty Result", serverNames(r.Servers), r.Errors)
	}

	// Sanity check: the trap works. An explicit Home finds the servers.
	r = Discover(t.Context(), Options{Home: dir})
	if len(r.Servers) == 0 {
		t.Error("Discover(Options{Home: dir}) found nothing, so the trap files are not valid")
	}
}

// TestDiscoverCleansWorkDir checks that ProjectPath is the clean path, however
// the caller spells WorkDir.
func TestDiscoverCleansWorkDir(t *testing.T) {
	t.Parallel()
	_, work := copyFixture(t, "all", "full")

	r := Discover(t.Context(), Options{WorkDir: work + "/./"})

	assertDiscoverNoErrors(t, r)
	found := false
	for _, s := range r.Servers {
		if s.Name != "cc-project" {
			continue
		}
		found = true
		if s.ProjectPath != work {
			t.Errorf("cc-project ProjectPath = %q, want %q", s.ProjectPath, work)
		}
	}
	if !found {
		t.Errorf("cc-project not found in %v", serverNames(r.Servers))
	}
}

// TestDiscoverEmptyStaysEmpty checks that an empty Home or WorkDir does not
// become "." (the current directory) and so reads no files.
func TestDiscoverEmptyStaysEmpty(t *testing.T) {
	// Not parallel: t.Chdir panics in a parallel test.
	dir := t.TempDir()
	const jsonConfig = `{"mcpServers": {"trap": {"command": "x"}}}`
	writeDiscoverFile(t, dir, ".claude.json", jsonConfig)
	writeDiscoverFile(t, dir, ".mcp.json", jsonConfig)
	writeDiscoverFile(t, dir, filepath.Join(".cursor", "mcp.json"), jsonConfig)
	writeDiscoverFile(t, dir, filepath.Join(".codex", "config.toml"), "[mcp_servers.trap]\ncommand = \"x\"\n")
	t.Chdir(dir)

	r := Discover(t.Context(), Options{Home: "", WorkDir: ""})

	if len(r.Servers) != 0 || len(r.Errors) != 0 {
		t.Errorf("Discover() = servers %v, errors %v, want an empty Result", serverNames(r.Servers), r.Errors)
	}
}

// TestDiscoverOnlyHomeOrWorkDir checks that each option selects its own files.
func TestDiscoverOnlyHomeOrWorkDir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts func(home, work string) Options
		want []string
	}{
		{
			name: "only home",
			opts: func(home, _ string) Options { return Options{Home: home} },
			want: []string{"cc-global", "cc-alpha", "cursor-global", "codex-global"},
		},
		{
			name: "only work dir",
			opts: func(_, work string) Options { return Options{WorkDir: work} },
			want: []string{"cc-project", "cursor-project"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := copyFixture(t, "all", "full")

			r := Discover(t.Context(), tt.opts(home, work))

			assertDiscoverNoErrors(t, r)
			assertDiscoverNames(t, r, tt.want)
		})
	}
}

// TestDiscoverMissingEverything checks that missing files are not an error
// (FR-01).
func TestDiscoverMissingEverything(t *testing.T) {
	t.Parallel()

	r := Discover(t.Context(), Options{Home: t.TempDir(), WorkDir: t.TempDir()})

	if len(r.Servers) != 0 || len(r.Errors) != 0 {
		t.Errorf("Discover() = servers %v, errors %v, want an empty Result", serverNames(r.Servers), r.Errors)
	}
}

// TestDiscoverCanceled checks that a context that is already canceled gives
// one error that names the first file. The cancel during a read is tested in
// TestRunStepsCanceledDuringRead.
func TestDiscoverCanceled(t *testing.T) {
	t.Parallel()
	home, work := copyFixture(t, "all", "full")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	r := Discover(ctx, Options{Home: home, WorkDir: work})

	if len(r.Servers) != 0 {
		t.Errorf("got servers %v, want none", serverNames(r.Servers))
	}
	if len(r.Errors) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(r.Errors), r.Errors)
	}
	e := r.Errors[0]
	if e.Reason != reasonCanceled {
		t.Errorf("Reason = %q, want %q", e.Reason, reasonCanceled)
	}
	if !errors.Is(e, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false, err = %v", e)
	}
	if want := filepath.Join(home, ".claude.json"); e.Path != want {
		t.Errorf("Path = %q, want %q", e.Path, want)
	}
}

// TestRunStepsCanceledDuringRead checks that a cancel during a read gives one
// canceled error and stops the later steps. A real reader is hard to cancel at
// the right time, so the steps here are fakes.
func TestRunStepsCanceledDuringRead(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	secondRan := false
	steps := []step{
		{path: "first", read: func() Result {
			cancel()
			return Result{
				Servers: []Server{{Name: "partial"}},
				Errors:  []*FileError{{Path: "first", Reason: reasonCanceled, Err: ctx.Err()}},
			}
		}},
		{path: "second", read: func() Result {
			secondRan = true
			return Result{}
		}},
	}

	r := runSteps(ctx, steps)

	if secondRan {
		t.Error("the second step ran after the cancel")
	}
	if len(r.Errors) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(r.Errors), r.Errors)
	}
	if r.Errors[0].Path != "first" || r.Errors[0].Reason != reasonCanceled {
		t.Errorf("error = %v, want the canceled error of the first step", r.Errors[0])
	}
	assertDiscoverNames(t, r, []string{"partial"})
}

// TestDiscoverNoLeak checks that no secret value from the config files reaches
// a server, an error, or their text and JSON forms.
func TestDiscoverNoLeak(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	work := t.TempDir()

	entry := func(name string) string {
		return fmt.Sprintf(`{"mcpServers": {%q: {
  "type": "http",
  "url": "https://user:%s@example.com/mcp?k=%s",
  "headers": {"X-Key": %q}
}}}`, name, discovertest.CanaryURL, discovertest.CanaryURL, discovertest.CanaryHeader)
	}
	stdioEntry := fmt.Sprintf(`{"mcpServers": {"stdio-one": {
  "command": "x",
  "env": {"API_KEY": %q}
}}}`, discovertest.CanaryEnv)

	writeDiscoverFile(t, home, ".claude.json", stdioEntry)
	writeDiscoverFile(t, home, filepath.Join(".cursor", "mcp.json"), entry("cursor-http"))
	writeDiscoverFile(t, work, filepath.Join(".cursor", "mcp.json"), entry("cursor-project-http"))
	writeDiscoverFile(t, home, filepath.Join(".codex", "config.toml"), fmt.Sprintf(`[mcp_servers.codex-http]
url = "https://user:%s@example.com/mcp"

[mcp_servers.codex-http.http_headers]
X-Key = %q

[mcp_servers.codex-stdio]
command = "x"

[mcp_servers.codex-stdio.env]
API_KEY = %q
`, discovertest.CanaryURL, discovertest.CanaryHeader, discovertest.CanaryEnv))
	// The malformed file has the bad spot (a missing colon) before the canaries.
	writeDiscoverFile(t, work, ".mcp.json", fmt.Sprintf(`{"mcpServers": {"bad" {
  "command": "x",
  "env": {"API_KEY": %q},
  "headers": {"X-Key": %q},
  "url": "https://user:%s@example.com/mcp"
}}}`, discovertest.CanaryEnv, discovertest.CanaryHeader, discovertest.CanaryURL))

	r := Discover(t.Context(), Options{Home: home, WorkDir: work})

	// The test is only useful if the valid files were read and the bad file failed.
	assertDiscoverNames(t, r, []string{"stdio-one", "cursor-http", "cursor-project-http", "codex-http", "codex-stdio"})
	if len(r.Errors) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(r.Errors), r.Errors)
	}
	if r.Errors[0].Path != filepath.Join(work, ".mcp.json") {
		t.Errorf("error Path = %q, want the malformed file", r.Errors[0].Path)
	}
	// A server holds the real secret values, so check one is really there.
	if got := r.Servers[0].Env["API_KEY"].Reveal(); got != discovertest.CanaryEnv {
		t.Fatalf("env value was not read, got %q", got)
	}

	assertNoLeakServers(t, r.Servers)
	assertNoLeakErrors(t, r.Errors)
	discovertest.AssertNoLeak(t, "Result %+v", fmt.Sprintf("%+v", r))
	discovertest.AssertNoLeak(t, "Result %v", fmt.Sprintf("%v", r))
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal(Result): %v", err)
	}
	discovertest.AssertNoLeak(t, "Result JSON", string(data))
}
