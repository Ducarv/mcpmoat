package discover

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// assertDiscoverNoErrors fails the test if r has any error.
func assertDiscoverNoErrors(t testing.TB, res Result) {
	t.Helper()
	for _, e := range res.Errors {
		t.Errorf("unexpected error: %v", e)
	}
}

// assertDiscoverNames fails the test if the server names in r are not exactly want.
func assertDiscoverNames(t testing.TB, res Result, want []string) {
	t.Helper()
	// slices.Equal treats a nil slice and an empty slice as equal.
	if got := serverNames(res.Servers); !slices.Equal(got, want) {
		t.Errorf("server names = %v, want %v", got, want)
	}
}

// TestDiscoverFull is the FR-01 acceptance case: all three clients, home and
// project files, found in one call and in the fixed file order.
func TestDiscoverFull(t *testing.T) {
	t.Parallel()
	home, work := copyFixture(t, "all", "full")

	res := Discover(t.Context(), Options{Home: home, WorkDir: work})

	assertDiscoverNoErrors(t, res)
	wantNames := []string{"cc-global", "cc-alpha", "cc-project", "cursor-global", "cursor-project", "codex-global"}
	assertDiscoverNames(t, res, wantNames)
	if len(res.Servers) != len(wantNames) {
		t.Fatalf("got %d servers, want %d", len(res.Servers), len(wantNames))
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
			Untrusted:   true,
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
			Untrusted:   true,
			Transport:   TransportHTTP, URL: "https://cursor-project.example.com/mcp",
		},
		"codex-global": {
			Name: "codex-global", Client: ClientCodex, Scope: ScopeGlobal,
			Source:    filepath.Join(home, ".codex", "config.toml"),
			Transport: TransportStdio, Command: "npx", Args: []string{"-y", "codex-global"},
		},
	}
	for _, s := range res.Servers {
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

	res := Discover(t.Context(), Options{Home: home, WorkDir: work})

	assertDiscoverNames(t, res, []string{"cc-project", "cursor-global", "cursor-project", "codex-global"})
	if len(res.Errors) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(res.Errors), res.Errors)
	}
	e := res.Errors[0]
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

			res := Discover(t.Context(), Options{Home: home, WorkDir: workDir})

			assertDiscoverNoErrors(t, res)
			// only-once is in ~/.cursor/mcp.json. Without the dedupe it would
			// appear twice, the second time as a project server.
			assertDiscoverNames(t, res, []string{"cc-once", "mcp-json", "only-once"})
			for _, s := range res.Servers {
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

	res := Discover(t.Context(), Options{})

	if len(res.Servers) != 0 || len(res.Errors) != 0 {
		t.Errorf("Discover(Options{}) = %d servers, %d errors, want an empty Result", len(res.Servers), len(res.Errors))
	}
}

// TestDiscoverIgnoresRealHome proves that Discover never reads $HOME or the
// current directory by itself: an empty Home or WorkDir does not become "."
// (the current directory). It is not parallel: t.Setenv and t.Chdir panic in
// a parallel test.
func TestDiscoverIgnoresRealHome(t *testing.T) {
	dir := t.TempDir()
	const jsonConfig = `{"mcpServers": {"trap": {"command": "x"}}}`
	writeFile(t, dir, ".claude.json", []byte(jsonConfig))
	writeFile(t, dir, ".mcp.json", []byte(jsonConfig))
	writeFile(t, dir, ".cursor/mcp.json", []byte(jsonConfig))
	writeFile(t, dir, codexConfigRel, []byte("[mcp_servers.trap]\ncommand = \"x\"\n"))
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Chdir(dir)

	res := Discover(t.Context(), Options{})

	if len(res.Servers) != 0 || len(res.Errors) != 0 {
		t.Errorf("Discover(Options{}) = servers %v, errors %v, want an empty Result", serverNames(res.Servers), res.Errors)
	}

	// Sanity check: the trap works. An explicit Home finds the servers.
	res = Discover(t.Context(), Options{Home: dir})
	if len(res.Servers) == 0 {
		t.Error("Discover(Options{Home: dir}) found nothing, so the trap files are not valid")
	}
}

// TestDiscoverUntrusted checks that the servers from the WorkDir project
// files are Untrusted, and the servers from the user's own files are not.
// cc-alpha comes from a projects.<path> entry of ~/.claude.json: it is a
// project server, but the user's own file holds it.
func TestDiscoverUntrusted(t *testing.T) {
	t.Parallel()
	home, work := copyFixture(t, "all", "full")

	res := Discover(t.Context(), Options{Home: home, WorkDir: work})

	assertDiscoverNoErrors(t, res)
	want := map[string]bool{
		"cc-global":      false,
		"cc-alpha":       false,
		"cc-project":     true,
		"cursor-global":  false,
		"cursor-project": true,
		"codex-global":   false,
	}
	for _, s := range res.Servers {
		w, ok := want[s.Name]
		if !ok {
			t.Errorf("unexpected server %q", s.Name)
			continue
		}
		delete(want, s.Name)
		if s.Untrusted != w {
			t.Errorf("server %s (%s): Untrusted = %v, want %v", s.Name, s.Source, s.Untrusted, w)
		}
	}
	for name := range want {
		t.Errorf("server %s not found", name)
	}
}

// TestDiscoverUntrustedErrors checks that an error about a WorkDir project
// file is Untrusted and an error about a global file is not. It also checks
// that a project file that is a symlink to a file of the user is refused.
func TestDiscoverUntrustedErrors(t *testing.T) {
	t.Parallel()
	const broken = `{"mcpServers": `

	tests := []struct {
		name string
		// setup writes the files and returns the path of the file in error.
		setup         func(t *testing.T, home, work string) string
		wantReason    string
		wantUntrusted bool
	}{
		{
			name: "broken global file",
			setup: func(t *testing.T, home, _ string) string {
				return writeFile(t, home, ".claude.json", []byte(broken))
			},
			wantReason: reasonInvalidJSON,
		},
		{
			name: "broken .mcp.json",
			setup: func(t *testing.T, _, work string) string {
				return writeFile(t, work, ".mcp.json", []byte(broken))
			},
			wantReason:    reasonInvalidJSON,
			wantUntrusted: true,
		},
		{
			name: "broken .cursor/mcp.json",
			setup: func(t *testing.T, _, work string) string {
				return writeFile(t, work, ".cursor/mcp.json", []byte(broken))
			},
			wantReason:    reasonInvalidJSON,
			wantUntrusted: true,
		},
		{
			name: ".mcp.json is a symlink to ~/.claude.json",
			setup: func(t *testing.T, home, work string) string {
				skipOnWindows(t)
				target := writeFile(t, home, ".claude.json", []byte(`{}`))
				return symlinkTo(t, target, work, ".mcp.json")
			},
			wantReason:    reasonOutsideProject,
			wantUntrusted: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := t.TempDir(), t.TempDir()
			path := tt.setup(t, home, work)

			res := Discover(t.Context(), Options{Home: home, WorkDir: work})

			if len(res.Errors) != 1 {
				t.Fatalf("got %d errors, want 1: %v", len(res.Errors), res.Errors)
			}
			e := res.Errors[0]
			if e.Path != path || e.Reason != tt.wantReason {
				t.Errorf("error = {Path: %q, Reason: %q}, want {Path: %q, Reason: %q}", e.Path, e.Reason, path, tt.wantReason)
			}
			if e.Untrusted != tt.wantUntrusted {
				t.Errorf("error Untrusted = %v, want %v", e.Untrusted, tt.wantUntrusted)
			}
		})
	}
}

// TestDiscoverCleansWorkDir checks that ProjectPath is the clean path, however
// the caller spells WorkDir.
func TestDiscoverCleansWorkDir(t *testing.T) {
	t.Parallel()
	_, work := copyFixture(t, "all", "full")

	res := Discover(t.Context(), Options{WorkDir: work + "/./"})

	assertDiscoverNoErrors(t, res)
	found := false
	for _, s := range res.Servers {
		if s.Name != "cc-project" {
			continue
		}
		found = true
		if s.ProjectPath != work {
			t.Errorf("cc-project ProjectPath = %q, want %q", s.ProjectPath, work)
		}
	}
	if !found {
		t.Errorf("cc-project not found in %v", serverNames(res.Servers))
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

			res := Discover(t.Context(), tt.opts(home, work))

			assertDiscoverNoErrors(t, res)
			assertDiscoverNames(t, res, tt.want)
		})
	}
}

// TestDiscoverMissingEverything checks that missing files are not an error
// (FR-01).
func TestDiscoverMissingEverything(t *testing.T) {
	t.Parallel()

	res := Discover(t.Context(), Options{Home: t.TempDir(), WorkDir: t.TempDir()})

	if len(res.Servers) != 0 || len(res.Errors) != 0 {
		t.Errorf("Discover() = servers %v, errors %v, want an empty Result", serverNames(res.Servers), res.Errors)
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

	res := Discover(ctx, Options{Home: home, WorkDir: work})

	if len(res.Servers) != 0 {
		t.Errorf("got servers %v, want none", serverNames(res.Servers))
	}
	if len(res.Errors) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(res.Errors), res.Errors)
	}
	e := res.Errors[0]
	if e.Reason != reasonCanceled {
		t.Errorf("Reason = %q, want %q", e.Reason, reasonCanceled)
	}
	if !errors.Is(e, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false, err = %v", e)
	}
	if want := filepath.Join(home, ".claude.json"); e.Path != want {
		t.Errorf("Path = %q, want %q", e.Path, want)
	}
	if e.Untrusted {
		t.Error("Untrusted = true, want false for ~/.claude.json")
	}
}

// TestDiscoverCanceledProjectStep checks that the canceled error that
// Discover adds before a WorkDir project file is read has Untrusted set.
func TestDiscoverCanceledProjectStep(t *testing.T) {
	t.Parallel()
	_, work := copyFixture(t, "all", "full")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Without Home, the first step is <WorkDir>/.mcp.json.
	res := Discover(ctx, Options{WorkDir: work})

	if len(res.Servers) != 0 {
		t.Errorf("got servers %v, want none", serverNames(res.Servers))
	}
	if len(res.Errors) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(res.Errors), res.Errors)
	}
	e := res.Errors[0]
	if want := filepath.Join(work, ".mcp.json"); e.Path != want || e.Reason != reasonCanceled {
		t.Errorf("error = {Path: %q, Reason: %q}, want {Path: %q, Reason: %q}", e.Path, e.Reason, want, reasonCanceled)
	}
	if !e.Untrusted {
		t.Error("Untrusted = false, want true for a WorkDir project file")
	}
	if !errors.Is(e, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false, err = %v", e)
	}
}

// TestRunStepsCanceledBeforeStep checks the canceled error that runSteps adds
// when ctx ends between two steps: it names the next step and takes its
// untrusted mark. The first step cancels ctx but reports no error itself.
func TestRunStepsCanceledBeforeStep(t *testing.T) {
	t.Parallel()

	for _, untrusted := range []bool{false, true} {
		t.Run(fmt.Sprintf("untrusted=%v", untrusted), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			secondRan := false
			steps := []step{
				{path: "first", read: func(context.Context) Result {
					cancel()
					return Result{Servers: []Server{{Name: "done"}}}
				}},
				{path: "second", untrusted: untrusted, read: func(context.Context) Result {
					secondRan = true
					return Result{}
				}},
			}

			res := runSteps(ctx, steps)

			if secondRan {
				t.Error("the second step ran after the cancel")
			}
			assertDiscoverNames(t, res, []string{"done"})
			if len(res.Errors) != 1 {
				t.Fatalf("got %d errors, want 1: %v", len(res.Errors), res.Errors)
			}
			e := res.Errors[0]
			if e.Path != "second" || e.Reason != reasonCanceled {
				t.Errorf("error = %v, want the canceled error of the second step", e)
			}
			if e.Untrusted != untrusted {
				t.Errorf("Untrusted = %v, want %v", e.Untrusted, untrusted)
			}
		})
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
		{path: "first", read: func(ctx context.Context) Result {
			cancel()
			return Result{
				Servers: []Server{{Name: "partial"}},
				Errors:  []*FileError{canceledError("first", ctx.Err())},
			}
		}},
		{path: "second", read: func(context.Context) Result {
			secondRan = true
			return Result{}
		}},
	}

	res := runSteps(ctx, steps)

	if secondRan {
		t.Error("the second step ran after the cancel")
	}
	if len(res.Errors) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(res.Errors), res.Errors)
	}
	if res.Errors[0].Path != "first" || res.Errors[0].Reason != reasonCanceled {
		t.Errorf("error = %v, want the canceled error of the first step", res.Errors[0])
	}
	assertDiscoverNames(t, res, []string{"partial"})
}

// TestBuildStepsGlobalFiles checks that the global steps of buildSteps (the
// trusted ones) are the files of globalFiles, in the same order, and that
// each step reads its file with the reader of its globalFile. globalFor and
// readGlobal use globalFiles, so ReadConfig reads a global file as Discover
// does.
func TestBuildStepsGlobalFiles(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	writeFile(t, home, ".claude.json", []byte(`{"mcpServers":{"a":{"command":"x"}}}`))
	writeFile(t, home, ".cursor/mcp.json", []byte(`{"mcpServers":{"a":{"command":"x"}}}`))
	writeFile(t, home, ".codex/config.toml", []byte("[mcp_servers.a]\ncommand = \"x\"\n"))

	// WorkDir is set, so the project steps sit between the global steps.
	var global []step
	for _, s := range buildSteps(Options{Home: home, WorkDir: t.TempDir()}) {
		if !s.untrusted {
			global = append(global, s)
		}
	}

	if len(global) != len(globalFiles) {
		t.Fatalf("buildSteps() has %d global steps, want %d", len(global), len(globalFiles))
	}
	for i, g := range globalFiles {
		s := global[i]
		if want := g.path(home); s.path != want {
			t.Errorf("global step %d path = %q, want %q", i, s.path, want)
			continue
		}
		got, want := s.read(t.Context()), g.read(t.Context(), s.path)
		if len(got.Servers) != 1 || !reflect.DeepEqual(got, want) {
			t.Errorf("global step %d (%s) read = %+v, want %+v", i, g.rel, got, want)
		}
	}
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

	writeFile(t, home, ".claude.json", []byte(stdioEntry))
	writeFile(t, home, ".cursor/mcp.json", []byte(entry("cursor-http")))
	writeFile(t, work, ".cursor/mcp.json", []byte(entry("cursor-project-http")))
	writeFile(t, home, codexConfigRel, []byte(fmt.Sprintf(`[mcp_servers.codex-http]
url = "https://user:%s@example.com/mcp"

[mcp_servers.codex-http.http_headers]
X-Key = %q

[mcp_servers.codex-stdio]
command = "x"

[mcp_servers.codex-stdio.env]
API_KEY = %q
`, discovertest.CanaryURL, discovertest.CanaryHeader, discovertest.CanaryEnv)))

	// The malformed file has the bad spot (a missing colon) before the canaries.
	writeFile(t, work, ".mcp.json", []byte(fmt.Sprintf(`{"mcpServers": {"bad" {
  "command": "x",
  "env": {"API_KEY": %q},
  "headers": {"X-Key": %q},
  "url": "https://user:%s@example.com/mcp"
}}}`, discovertest.CanaryEnv, discovertest.CanaryHeader, discovertest.CanaryURL)))

	res := Discover(t.Context(), Options{Home: home, WorkDir: work})

	// The test is only useful if the valid files were read and the bad file failed.
	assertDiscoverNames(t, res, []string{"stdio-one", "cursor-http", "cursor-project-http", "codex-http", "codex-stdio"})
	if len(res.Errors) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(res.Errors), res.Errors)
	}
	if res.Errors[0].Path != filepath.Join(work, ".mcp.json") {
		t.Errorf("error Path = %q, want the malformed file", res.Errors[0].Path)
	}
	// A server holds the real secret values, so check one is really there.
	if got := res.Servers[0].Env["API_KEY"].Reveal(); got != discovertest.CanaryEnv {
		t.Fatalf("env value was not read, got %q", got)
	}

	assertNoLeakServers(t, res.Servers)
	assertNoLeakErrors(t, res.Errors)
	discovertest.AssertNoLeak(t, "Result %+v", fmt.Sprintf("%+v", res))
	discovertest.AssertNoLeak(t, "Result %v", fmt.Sprintf("%v", res))
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("json.Marshal(Result): %v", err)
	}
	discovertest.AssertNoLeak(t, "Result JSON", string(data))
}

// stateMcpJSON is a WorkDir/.mcp.json with four servers for the state tests.
const stateMcpJSON = `{"mcpServers": {
	"a": {"command": "a"}, "b": {"command": "b"},
	"c": {"command": "c"}, "d": {"command": "d"}}}`

// writeStateClaudeJSON writes Home/.claude.json with the top-level server
// global-srv and, when project is not nil, the object project under
// projects.<key>. It encodes the file with encoding/json, so any key is
// quoted correctly.
func writeStateClaudeJSON(t testing.TB, home, key string, project map[string]any) {
	t.Helper()
	file := map[string]any{
		"mcpServers": map[string]any{"global-srv": map[string]any{"command": "g"}},
	}
	if project != nil {
		file["projects"] = map[string]any{key: project}
	}
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("json.Marshal(.claude.json): %v", err)
	}
	writeFile(t, home, ".claude.json", data)
}

// checkDiscoverStates fails the test unless res has exactly the servers of
// want (by name), each with its State in want. Every server of WorkDir/.mcp.json
// must stay Untrusted, whatever its State: an approval only changes the State.
func checkDiscoverStates(t testing.TB, res Result, want map[string]State) {
	t.Helper()
	got := make(map[string]State, len(res.Servers))
	for _, s := range res.Servers {
		got[s.Name] = s.State
		if s.Name != "global-srv" && !s.Untrusted {
			t.Errorf("server %q: Untrusted = false, want true for a .mcp.json server", s.Name)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("server states =\n got  %v\n want %v", got, want)
	}
}

// TestDiscoverStateFixture checks the claude-code/state fixture: the user's
// own settings.json approves approved-srv, the settings.local.json of the
// project approves repo-srv and rejects rejected-srv, so pending-srv waits for
// approval. The approval of repo-srv comes only from a file of the
// repository, so it gives StateProjectApproved. The global server has no list
// that turns it off.
func TestDiscoverStateFixture(t *testing.T) {
	t.Parallel()
	home, work := copyFixture(t, "claude-code", "state")

	res := Discover(t.Context(), Options{Home: home, WorkDir: work})

	assertDiscoverNoErrors(t, res)
	assertDiscoverNames(t, res, []string{"global-srv", "approved-srv", "pending-srv", "rejected-srv", "repo-srv"})
	checkDiscoverStates(t, res, map[string]State{
		"global-srv":   StateEnabled,
		"approved-srv": StateEnabled,
		"repo-srv":     StateProjectApproved,
		"rejected-srv": StateDisabled,
		"pending-srv":  StateUnapproved,
	})
}

// TestDiscoverStateLegacy checks the state that the projects.<WorkDir> object
// of ~/.claude.json gives: the approval of the .mcp.json servers, and the
// disabledMcpServers list for the global servers too.
//
// The project key is the WorkDir string of the test, as given. On macOS
// t.TempDir is below /var, a symlink to /private/var, so the real path has
// another form. The test uses the same string on both sides. The lookup of
// the resolved form is tested in TestReadGlobalClaudeCodeStateSymlink.
func TestDiscoverStateLegacy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		project map[string]any
		// otherKey writes the project under another directory, not WorkDir.
		otherKey bool
		// workSuffix is added to WorkDir in Options. Discover cleans it.
		workSuffix string
		want       map[string]State
	}{
		{
			name: "approval lists",
			project: map[string]any{
				keyEnabledMcpjsonServers:  []string{"a"},
				keyDisabledMcpjsonServers: []string{"b"},
			},
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateEnabled, "b": StateDisabled,
				"c": StateUnapproved, "d": StateUnapproved,
			},
		},
		{
			name: "enable all true",
			project: map[string]any{
				keyEnableAllProjectMcpServers: true,
				keyDisabledMcpjsonServers:     []string{"b"},
			},
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateEnabled, "b": StateDisabled,
				"c": StateEnabled, "d": StateEnabled,
			},
		},
		{
			name: "enable all false",
			project: map[string]any{
				keyEnableAllProjectMcpServers: false,
				keyEnabledMcpjsonServers:      []string{"a"},
			},
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateEnabled, "b": StateUnapproved,
				"c": StateUnapproved, "d": StateUnapproved,
			},
		},
		{
			// disabledMcpServers turns off a server of any scope, also an
			// approved .mcp.json server.
			name: "disabledMcpServers for a global and a .mcp.json server",
			project: map[string]any{
				keyDisabledMcpServers:         []string{"global-srv", "a"},
				keyEnabledMcpjsonServers:      []string{"a"},
				keyEnableAllProjectMcpServers: true,
			},
			want: map[string]State{
				"global-srv": StateDisabled,
				"a":          StateDisabled, "b": StateEnabled,
				"c": StateEnabled, "d": StateEnabled,
			},
		},
		{
			name:       "WorkDir with a trailing separator",
			project:    map[string]any{keyDisabledMcpServers: []string{"global-srv"}, keyEnabledMcpjsonServers: []string{"a"}},
			workSuffix: "/./",
			want: map[string]State{
				"global-srv": StateDisabled,
				"a":          StateEnabled, "b": StateUnapproved,
				"c": StateUnapproved, "d": StateUnapproved,
			},
		},
		{
			// The lists of another project change nothing for WorkDir.
			name: "another project",
			project: map[string]any{
				keyDisabledMcpServers:         []string{"global-srv"},
				keyEnableAllProjectMcpServers: true,
			},
			otherKey: true,
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateUnapproved, "b": StateUnapproved,
				"c": StateUnapproved, "d": StateUnapproved,
			},
		},
		{
			name: "no projects",
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateUnapproved, "b": StateUnapproved,
				"c": StateUnapproved, "d": StateUnapproved,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := t.TempDir(), t.TempDir()
			key := work
			if tt.otherKey {
				key = t.TempDir()
			}
			writeStateClaudeJSON(t, home, key, tt.project)
			writeFile(t, work, ".mcp.json", []byte(stateMcpJSON))

			res := Discover(t.Context(), Options{Home: home, WorkDir: work + tt.workSuffix})

			assertDiscoverNoErrors(t, res)
			checkDiscoverStates(t, res, tt.want)
		})
	}
}

// TestDiscoverStatePrecedence checks some cases of the order of the
// settings places: settings.local.json, then the project settings.json, then
// the user settings.json, then projects.<WorkDir> of ~/.claude.json. The full
// rule is tested in TestMcpjsonState; this test proves that Discover reads
// each file and passes the states in that order.
func TestDiscoverStatePrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		user, project, local string // settings files; "" means missing
		legacy               map[string]any
		want                 map[string]State
	}{
		{
			name:  "local enable all false wins over user true",
			user:  `{"enableAllProjectMcpServers": true}`,
			local: `{"enableAllProjectMcpServers": false, "enabledMcpjsonServers": ["a"]}`,
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateProjectApproved, "b": StateUnapproved,
				"c": StateUnapproved, "d": StateUnapproved,
			},
		},
		{
			name:    "project enable all true wins over legacy false",
			project: `{"enableAllProjectMcpServers": true}`,
			legacy:  map[string]any{keyEnableAllProjectMcpServers: false},
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateProjectApproved, "b": StateProjectApproved,
				"c": StateProjectApproved, "d": StateProjectApproved,
			},
		},
		{
			name:   "user enable all false wins over legacy true",
			user:   `{"enableAllProjectMcpServers": false}`,
			legacy: map[string]any{keyEnableAllProjectMcpServers: true},
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateUnapproved, "b": StateUnapproved,
				"c": StateUnapproved, "d": StateUnapproved,
			},
		},
		{
			// A rejection in any place wins over an approval in any place.
			name:    "a rejection wins over an approval",
			user:    `{"enabledMcpjsonServers": ["a", "b"]}`,
			project: `{"disabledMcpjsonServers": ["a"]}`,
			local:   `{"enableAllProjectMcpServers": true}`,
			legacy:  map[string]any{keyDisabledMcpjsonServers: []string{"c"}},
			// b is approved by the user file, d only by the local file.
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateDisabled, "b": StateEnabled,
				"c": StateDisabled, "d": StateProjectApproved,
			},
		},
		{
			// disabledMcpServers of a settings file turns off a .mcp.json
			// server, also an approved one.
			name:  "settings disabledMcpServers",
			local: `{"enabledMcpjsonServers": ["a", "b"], "disabledMcpServers": ["a"]}`,
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateDisabled, "b": StateProjectApproved,
				"c": StateUnapproved, "d": StateUnapproved,
			},
		},
		{
			// A cloned repository ships WorkDir/.claude/settings.json that
			// approves all its servers. That gives only project-approved,
			// never enabled, and it overrides no trusted setting: the
			// user's approval and rejection, and the legacy lists, keep
			// their effect.
			name:    "repository settings approve all",
			user:    `{"disabledMcpjsonServers": ["b"]}`,
			project: `{"enableAllProjectMcpServers": true}`,
			legacy: map[string]any{
				keyEnabledMcpjsonServers: []string{"a"},
				keyDisabledMcpServers:    []string{"d", "global-srv"},
			},
			want: map[string]State{
				"global-srv": StateDisabled,
				"a":          StateEnabled, "b": StateDisabled,
				"c": StateProjectApproved, "d": StateDisabled,
			},
		},
		{
			// The same file alone: every server is only project-approved.
			name:    "repository settings approve all, nothing else",
			project: `{"enableAllProjectMcpServers": true, "enabledMcpjsonServers": ["a"]}`,
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateProjectApproved, "b": StateProjectApproved,
				"c": StateProjectApproved, "d": StateProjectApproved,
			},
		},
		{
			// An untrusted enable all false hides a trusted true, as in
			// Claude Code. That can only turn off servers.
			name:    "repository enable all false hides user true",
			user:    `{"enableAllProjectMcpServers": true, "enabledMcpjsonServers": ["a"]}`,
			project: `{"enableAllProjectMcpServers": false}`,
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateEnabled, "b": StateUnapproved,
				"c": StateUnapproved, "d": StateUnapproved,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := t.TempDir(), t.TempDir()
			writeStateClaudeJSON(t, home, work, tt.legacy)
			writeFile(t, work, ".mcp.json", []byte(stateMcpJSON))
			for _, f := range []struct{ dir, rel, content string }{
				{home, ".claude/settings.json", tt.user},
				{work, ".claude/settings.json", tt.project},
				{work, ".claude/settings.local.json", tt.local},
			} {
				if f.content != "" {
					writeFile(t, f.dir, f.rel, []byte(f.content))
				}
			}

			res := Discover(t.Context(), Options{Home: home, WorkDir: work})

			assertDiscoverNoErrors(t, res)
			checkDiscoverStates(t, res, tt.want)
		})
	}
}

// writeBrokenSettings writes a malformed settings file in each of the three
// settings places and returns their paths.
func writeBrokenSettings(t testing.TB, home, work string) []string {
	t.Helper()
	const broken = `{"enabledMcpjsonServers": [`
	return []string{
		writeFile(t, home, ".claude/settings.json", []byte(broken)),
		writeFile(t, work, ".claude/settings.json", []byte(broken)),
		writeFile(t, work, ".claude/settings.local.json", []byte(broken)),
	}
}

// TestDiscoverStateSettingsNotRead checks that Discover reads the settings
// files only when WorkDir/.mcp.json has servers: they only matter for those
// servers. All three settings files are malformed here, so a read would give
// an error.
func TestDiscoverStateSettingsNotRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// mcpJSON is WorkDir/.mcp.json; "" means that the file is missing.
		mcpJSON string
		// wantMcpErr is the reason of the one .mcp.json error, if any.
		wantMcpErr string
	}{
		{name: "missing .mcp.json"},
		{name: "empty .mcp.json", mcpJSON: " "},
		{name: "no servers", mcpJSON: `{"mcpServers": {}}`},
		{name: "null servers", mcpJSON: `{"mcpServers": null}`},
		{name: "only a bad entry", mcpJSON: `{"mcpServers": {"x": {"type": "nope"}}}`, wantMcpErr: reasonUnknownTransport},
		{name: "malformed .mcp.json", mcpJSON: `{"mcpServers": `, wantMcpErr: reasonInvalidJSON},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := t.TempDir(), t.TempDir()
			writeStateClaudeJSON(t, home, work, map[string]any{keyEnableAllProjectMcpServers: true})
			writeBrokenSettings(t, home, work)
			if tt.mcpJSON != "" {
				writeFile(t, work, ".mcp.json", []byte(tt.mcpJSON))
			}

			res := Discover(t.Context(), Options{Home: home, WorkDir: work})

			checkDiscoverStates(t, res, map[string]State{"global-srv": StateEnabled})
			var wantErrs []string
			if tt.wantMcpErr != "" {
				wantErrs = []string{filepath.Join(work, ".mcp.json")}
			}
			var gotErrs []string
			for _, e := range res.Errors {
				gotErrs = append(gotErrs, e.Path)
				if e.Reason != tt.wantMcpErr {
					t.Errorf("error %v: Reason = %q, want %q", e, e.Reason, tt.wantMcpErr)
				}
			}
			if !slices.Equal(gotErrs, wantErrs) {
				t.Errorf("error paths = %q, want %q", gotErrs, wantErrs)
			}
		})
	}
}

// stateErrWant is one FileError that a Discover state test expects.
type stateErrWant struct {
	rel       string // the path below home or work, with forward slashes
	inHome    bool
	reason    string
	untrusted bool
}

// checkDiscoverErrors compares the Path, Reason and Untrusted of the errors
// of res with want, in order.
func checkDiscoverErrors(t testing.TB, res Result, home, work string, want []stateErrWant) {
	t.Helper()
	if len(res.Errors) != len(want) {
		t.Fatalf("got %d errors, want %d: %v", len(res.Errors), len(want), res.Errors)
	}
	for i, w := range want {
		dir := work
		if w.inHome {
			dir = home
		}
		e := res.Errors[i]
		wantPath := filepath.Join(dir, filepath.FromSlash(w.rel))
		if e.Path != wantPath || e.Reason != w.reason || e.Untrusted != w.untrusted {
			t.Errorf("errors[%d] = {Path: %q, Reason: %q, Untrusted: %v}, want {%q, %q, %v}",
				i, e.Path, e.Reason, e.Untrusted, wantPath, w.reason, w.untrusted)
		}
	}
}

// TestDiscoverStateSettingsErrors checks a settings file with an error: it
// gives one FileError after the errors of .mcp.json, with Untrusted set for
// the project files only. It fails closed (see setMcpjsonStates): a source
// that cannot be read could hold a rejection, so no .mcp.json server gets
// StateEnabled from an approval in any other source; such a server falls back
// to StateUnapproved. A rejection from a source that was read still gives
// StateDisabled.
func TestDiscoverStateSettingsErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup writes the settings files.
		setup    func(t *testing.T, home, work string)
		mcpJSON  string
		want     map[string]State
		wantErrs []stateErrWant
	}{
		{
			name: "malformed local settings",
			setup: func(t *testing.T, home, work string) {
				writeFile(t, work, ".claude/settings.local.json", []byte(`{"enabledMcpjsonServers": ["a"],`))
				writeFile(t, home, ".claude/settings.json", []byte(`{"enabledMcpjsonServers": ["b"]}`))
			},
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateUnapproved, "b": StateUnapproved,
				"c": StateUnapproved, "d": StateUnapproved,
			},
			wantErrs: []stateErrWant{{rel: ".claude/settings.local.json", reason: reasonInvalidJSON, untrusted: true}},
		},
		{
			// The bad type drops the whole file. The user file still
			// counts for its rejection, but not for its approvals.
			name: "bad type in project settings",
			setup: func(t *testing.T, home, work string) {
				writeFile(t, work, ".claude/settings.json", []byte(`{"enabledMcpjsonServers": ["a"], "disabledMcpjsonServers": "b"}`))
				writeFile(t, home, ".claude/settings.json", []byte(`{"enableAllProjectMcpServers": true, "disabledMcpjsonServers": ["d"]}`))
			},
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateUnapproved, "b": StateUnapproved,
				"c": StateUnapproved, "d": StateDisabled,
			},
			wantErrs: []stateErrWant{{rel: ".claude/settings.json", reason: reasonBadServerState, untrusted: true}},
		},
		{
			// The user's own file is trusted, so its error is not
			// Untrusted, although the .mcp.json step reads it.
			name: "malformed user settings",
			setup: func(t *testing.T, home, work string) {
				writeFile(t, home, ".claude/settings.json", []byte(`[`))
				writeFile(t, work, ".claude/settings.local.json", []byte(`{"enabledMcpjsonServers": ["a"], "disabledMcpServers": ["b"]}`))
			},
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateUnapproved, "b": StateDisabled,
				"c": StateUnapproved, "d": StateUnapproved,
			},
			wantErrs: []stateErrWant{{rel: ".claude/settings.json", inHome: true, reason: reasonInvalidJSON}},
		},
		{
			// A symlink out of WorkDir is refused: a repository must not
			// make mcpmoat read the user's approvals from another path.
			name: "local settings symlink out of WorkDir",
			setup: func(t *testing.T, home, work string) {
				skipOnWindows(t)
				target := writeFile(t, home, "elsewhere.json", []byte(`{"enableAllProjectMcpServers": true}`))
				symlinkTo(t, target, work, ".claude/settings.local.json")
			},
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateUnapproved, "b": StateUnapproved,
				"c": StateUnapproved, "d": StateUnapproved,
			},
			wantErrs: []stateErrWant{{rel: ".claude/settings.local.json", reason: reasonOutsideProject, untrusted: true}},
		},
		{
			// The settings errors come after the .mcp.json errors, in the
			// order home, project, local.
			name:    "all broken and a bad .mcp.json entry",
			setup:   func(t *testing.T, home, work string) { writeBrokenSettings(t, home, work) },
			mcpJSON: `{"mcpServers": {"a": {"command": "a"}, "x": {"type": "nope"}}}`,
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateUnapproved,
			},
			wantErrs: []stateErrWant{
				{rel: ".mcp.json", reason: reasonUnknownTransport, untrusted: true},
				{rel: ".claude/settings.json", inHome: true, reason: reasonInvalidJSON},
				{rel: ".claude/settings.json", reason: reasonInvalidJSON, untrusted: true},
				{rel: ".claude/settings.local.json", reason: reasonInvalidJSON, untrusted: true},
			},
		},
		{
			// An error for one .mcp.json server is not a settings error, so
			// the approvals of the other servers stay. The approval comes
			// from the local file only, so it is project-approved.
			name: "bad .mcp.json entry only",
			setup: func(t *testing.T, _, work string) {
				writeFile(t, work, ".claude/settings.local.json", []byte(`{"enabledMcpjsonServers": ["a"]}`))
			},
			mcpJSON: `{"mcpServers": {"a": {"command": "a"}, "x": {"type": "nope"}}}`,
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateProjectApproved,
			},
			wantErrs: []stateErrWant{{rel: ".mcp.json", reason: reasonUnknownTransport, untrusted: true}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := t.TempDir(), t.TempDir()
			writeStateClaudeJSON(t, home, work, nil)
			mcpJSON := tt.mcpJSON
			if mcpJSON == "" {
				mcpJSON = stateMcpJSON
			}
			writeFile(t, work, ".mcp.json", []byte(mcpJSON))
			tt.setup(t, home, work)

			res := Discover(t.Context(), Options{Home: home, WorkDir: work})

			checkDiscoverStates(t, res, tt.want)
			checkDiscoverErrors(t, res, home, work, tt.wantErrs)
		})
	}
}

// TestDiscoverStateLegacyErrors checks the errors of ~/.claude.json that can
// hide the projects.<WorkDir> state. Such an error fails closed as a settings
// error does: no .mcp.json server keeps an approval from the settings files.
// An error for another project, or for one server, does not touch the state
// of WorkDir.
func TestDiscoverStateLegacyErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// claudeJSON makes ~/.claude.json for the project key work.
		claudeJSON func(work string) string
		want       map[string]State
		wantErrs   []stateErrWant
	}{
		{
			name: "bad state in the WorkDir project",
			claudeJSON: func(work string) string {
				return fmt.Sprintf(`{"mcpServers": {"global-srv": {"command": "g"}},
					"projects": {%q: {"disabledMcpServers": "global-srv"}}}`, work)
			},
			// The bad list could turn off global-srv, but it cannot be
			// read, so global-srv fails closed to StateUnapproved; the
			// error makes the scan fail.
			want: map[string]State{
				"global-srv": StateUnapproved,
				"a":          StateUnapproved, "b": StateUnapproved,
				"c": StateUnapproved, "d": StateUnapproved,
			},
			wantErrs: []stateErrWant{{rel: ".claude.json", inHome: true, reason: reasonBadServerState}},
		},
		{
			name: "malformed file",
			claudeJSON: func(string) string {
				return `{"mcpServers": `
			},
			want: map[string]State{
				"a": StateUnapproved, "b": StateUnapproved,
				"c": StateUnapproved, "d": StateUnapproved,
			},
			wantErrs: []stateErrWant{{rel: ".claude.json", inHome: true, reason: reasonInvalidJSON}},
		},
		{
			// A lone surrogate in the servers of another project refuses
			// the whole file, so the WorkDir state is lost too, and the
			// approval of the user settings file must not hold.
			name: "bad string in another project",
			claudeJSON: func(work string) string {
				return fmt.Sprintf(`{"mcpServers": {"global-srv": {"command": "g"}},
					"projects": {%q: {"enabledMcpjsonServers": ["a"]}, %q: {"mcpServers": {"x": {"command": "\ud800"}}}}}`,
					work, work+"-other")
			},
			want: map[string]State{
				"a": StateUnapproved, "b": StateUnapproved,
				"c": StateUnapproved, "d": StateUnapproved,
			},
			wantErrs: []stateErrWant{{rel: ".claude.json", inHome: true, reason: reasonBadString}},
		},
		{
			name: "bad state in another project",
			claudeJSON: func(work string) string {
				return fmt.Sprintf(`{"mcpServers": {"global-srv": {"command": "g"}},
					"projects": {%q: {"disabledMcpServers": 1}, %q: {"disabledMcpjsonServers": ["b"]}}}`, work+"-other", work)
			},
			want: map[string]State{
				"global-srv": StateEnabled,
				"a":          StateEnabled, "b": StateDisabled,
				"c": StateEnabled, "d": StateEnabled,
			},
			wantErrs: []stateErrWant{{rel: ".claude.json", inHome: true, reason: reasonBadServerState}},
		},
		{
			name: "bad global server entry",
			claudeJSON: func(work string) string {
				return fmt.Sprintf(`{"mcpServers": {"global-srv": {"command": "g"}, "x": {"type": "nope"}},
					"projects": {%q: {"disabledMcpServers": ["global-srv"]}}}`, work)
			},
			want: map[string]State{
				"global-srv": StateDisabled,
				"a":          StateEnabled, "b": StateEnabled,
				"c": StateEnabled, "d": StateEnabled,
			},
			wantErrs: []stateErrWant{{rel: ".claude.json", inHome: true, reason: reasonUnknownTransport}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := t.TempDir(), t.TempDir()
			writeFile(t, home, ".claude.json", []byte(tt.claudeJSON(work)))
			writeFile(t, work, ".mcp.json", []byte(stateMcpJSON))
			writeFile(t, home, ".claude/settings.json", []byte(`{"enableAllProjectMcpServers": true}`))

			res := Discover(t.Context(), Options{Home: home, WorkDir: work})

			checkDiscoverStates(t, res, tt.want)
			checkDiscoverErrors(t, res, home, work, tt.wantErrs)
		})
	}
}

// TestDiscoverStateSameHomeAndWork checks that the settings file is read once
// when WorkDir is the home directory: Home/.claude/settings.json is then also
// WorkDir/.claude/settings.json. A bad file gives one trusted FileError, not a
// second one with Untrusted set.
func TestDiscoverStateSameHomeAndWork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		settings string
		want     State
		wantErrs []stateErrWant
	}{
		{name: "approval", settings: `{"enabledMcpjsonServers": ["a"]}`, want: StateEnabled},
		{
			name:     "malformed",
			settings: `{`,
			want:     StateUnapproved,
			wantErrs: []stateErrWant{{rel: ".claude/settings.json", inHome: true, reason: reasonInvalidJSON}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			writeFile(t, home, ".mcp.json", []byte(`{"mcpServers": {"a": {"command": "a"}}}`))
			writeFile(t, home, ".claude/settings.json", []byte(tt.settings))

			res := Discover(t.Context(), Options{Home: home, WorkDir: home + "/"})

			checkDiscoverStates(t, res, map[string]State{"a": tt.want})
			checkDiscoverErrors(t, res, home, home, tt.wantErrs)
		})
	}
}
