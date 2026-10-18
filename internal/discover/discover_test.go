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
