package discover

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

func TestReadClaudeCode(t *testing.T) {
	t.Parallel()

	files := jsonFixtureFiles{client: ClientClaudeCode, fixture: "claude-code", home: ".claude.json", work: ".mcp.json"}
	runJSONFixtureCases(t, files, ReadClaudeCode, []jsonFixtureCase{
		{
			name: "valid",
			// Order is (ProjectPath, Name): global servers first. The servers
			// with a ProjectPath come from projects.<path> of ~/.claude.json.
			home: []serverView{
				{Name: "filesystem", Transport: TransportStdio, Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"}},
				{Name: "remote-http", Transport: TransportHTTP, URL: "https://mcp.example.com/mcp"},
				{Name: "remote-sse", Transport: TransportSSE, URL: "https://sse.example.com/sse"},
				{Name: "alpha-tool", ProjectPath: "/work/alpha", Transport: TransportStdio, Command: "node", Args: []string{"alpha-server.js"}},
				// "type" is missing here: a command means stdio.
				{Name: "gamma-tool", ProjectPath: "/work/gamma", Transport: TransportStdio, Command: "python3", Args: []string{"-m", "gamma_server"}},
			},
			work: []serverView{
				{Name: "local-db", Transport: TransportStdio, Command: "uvx", Args: []string{"mcp-server-sqlite", "--db-path", "./data.db"}},
				{Name: "team-api", Transport: TransportHTTP, URL: "https://team.example.com/mcp"},
			},
		},
		{
			name:        "secrets",
			hideValues:  true,
			canaryFiles: []string{"home/.claude.json", "work/.mcp.json"},
			home: []serverView{
				{
					Name: "with-env", Transport: TransportStdio, Command: "npx",
					Args: []string{"-y", "example-server", "--token", discovertest.CanaryArgs},
					Env:  map[string]string{"API_KEY": discovertest.CanaryEnv},
				},
				{
					Name: "with-headers", Transport: TransportHTTP, URL: "https://mcp.example.com/mcp",
					Headers: map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader},
				},
				{
					Name: "with-url-secret", Transport: TransportHTTP,
					URL: "https://user:" + discovertest.CanaryURL + "@mcp.example.com/mcp?key=" + discovertest.CanaryURL,
				},
				{
					Name: "project-with-env", ProjectPath: "/work/secret-project",
					Transport: TransportStdio, Command: "node", Args: []string{"server.js"},
					Env: map[string]string{"API_KEY": discovertest.CanaryEnv},
				},
			},
			work: []serverView{
				{
					Name: "work-env", Transport: TransportStdio, Command: "node", Args: []string{"server.js"},
					Env: map[string]string{"API_KEY": discovertest.CanaryEnv},
				},
				{
					Name: "work-headers", Transport: TransportSSE, URL: "https://sse.example.com/sse",
					Headers: map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader},
				},
			},
		},
		// Home file is "{}", work file has 0 bytes.
		{name: "empty"},
		{
			// The canary comes right after the bad spot in both files.
			name:       "malformed",
			hideValues: true,
			homeErrs:   []errWant{{Reason: reasonInvalidJSON, Line: 3}},
			workErrs:   []errWant{{Reason: reasonInvalidJSON, Line: 3}},
		},
		{
			name: "invalid-entries",
			home: []serverView{
				{Name: "good", Transport: TransportStdio, Command: "npx", Args: []string{"-y", "example-server"}},
			},
			// Errors are sorted by server name.
			homeErrs: []errWant{
				{Server: "empty", Reason: reasonNoCommandOrURL},
				{Server: "http-no-url", Reason: reasonRemoteNoURL},
				{Server: "num-env", Reason: reasonBadEntry},
				{Server: "stdio-no-cmd", Reason: reasonStdioNoCommand},
				{Server: "unknown-type", Reason: reasonUnknownTransport},
			},
		},
		// The fixture has no files: both directories are empty.
		{name: "missing"},
	})
}

// TestReadClaudeCodeCanaryMasking checks that the canaries are really read
// (the values are in the servers) and that the display forms hide them.
func TestReadClaudeCodeCanaryMasking(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "secrets")
	res := ReadClaudeCode(t.Context(), filepath.Join(home, ".claude.json"), ScopeGlobal, "")
	if len(res.Errors) != 0 {
		t.Fatalf("errors = %v, want none", res.Errors)
	}

	var found bool
	for _, s := range res.Servers {
		if s.Name != "with-url-secret" {
			continue
		}
		found = true
		display := RedactURL(s.URL.Reveal())
		if !strings.Contains(display, Mask) {
			t.Errorf("RedactURL() = %q, want it to contain %q", display, Mask)
		}
		if !strings.Contains(display, "mcp.example.com") {
			t.Errorf("RedactURL() = %q, want the host to stay", display)
		}
		if display != s.URL.String() {
			t.Errorf("RedactURL() = %q differs from URL.String() = %q", display, s.URL.String())
		}
		if len(discovertest.Leaks(display)) > 0 {
			t.Errorf("RedactURL() output holds a canary")
		}
	}
	if !found {
		t.Fatalf("server with-url-secret not found; got %v", serverNames(res.Servers))
	}

	// The keys of env and headers are kept, the values stay masked.
	var envKeys, headerKeys int
	for _, s := range res.Servers {
		for _, key := range s.Env.Keys() {
			envKeys++
			if s.Env[key].String() == s.Env[key].Reveal() {
				t.Errorf("server %q env key %q: String() shows the value", s.Name, key)
			}
		}
		for _, key := range s.Headers.Keys() {
			headerKeys++
			if s.Headers[key].String() == s.Headers[key].Reveal() {
				t.Errorf("server %q header key %q: String() shows the value", s.Name, key)
			}
		}
	}
	// The fixture has env and headers values, so both loops must run.
	if envKeys == 0 || headerKeys == 0 {
		t.Errorf("checked %d env keys and %d header keys, want both above 0", envKeys, headerKeys)
	}
}

// TestReadClaudeCodeProjectPath checks that a global file ignores the
// projectPath of the call: its top-level servers have no ProjectPath, and
// servers under "projects" keep their own key.
func TestReadClaudeCodeProjectPath(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "valid")
	path := filepath.Join(home, ".claude.json")

	res := ReadClaudeCode(t.Context(), path, ScopeGlobal, "/custom/dir")
	if len(res.Errors) != 0 {
		t.Fatalf("errors = %v, want none", res.Errors)
	}
	want := []struct {
		name, project string
		scope         Scope
	}{
		// Sorted by (ProjectPath, Name): "" < "/work/alpha" < "/work/gamma".
		{"filesystem", "", ScopeGlobal},
		{"remote-http", "", ScopeGlobal},
		{"remote-sse", "", ScopeGlobal},
		{"alpha-tool", "/work/alpha", ScopeProject},
		{"gamma-tool", "/work/gamma", ScopeProject},
	}
	if len(res.Servers) != len(want) {
		t.Fatalf("got servers %v, want %d servers", serverNames(res.Servers), len(want))
	}
	for i, w := range want {
		s := res.Servers[i]
		if s.Name != w.name || s.ProjectPath != w.project || s.Scope != w.scope {
			t.Errorf("servers[%d] = {%q %q %q}, want {%q %q %q}",
				i, s.Name, s.ProjectPath, s.Scope, w.name, w.project, w.scope)
		}
	}
}

// TestReadClaudeCodeProjectsKeyByScope checks that "projects" is read only from
// a global file. A project .mcp.json is untrusted, so its "projects" key must
// not create servers with a ProjectPath that the file chose.
func TestReadClaudeCodeProjectsKeyByScope(t *testing.T) {
	t.Parallel()

	const content = `{
		"mcpServers": {"top": {"command": "t"}},
		"projects": {
			"/attacker/chosen": {"mcpServers": {"spoofed": {"command": "x"}}}
		}
	}`

	tests := []struct {
		name  string
		scope Scope
		want  []string
	}{
		{name: "project file ignores projects", scope: ScopeProject, want: []string{"top"}},
		// Sorted by (ProjectPath, Name): a global file ignores projectPath,
		// so "top" has ProjectPath "", and "" < "/attacker/chosen".
		{name: "global file reads projects", scope: ScopeGlobal, want: []string{"top", "spoofed"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// A project file must be below its projectPath.
			dir := t.TempDir()
			path := writeFile(t, dir, ".mcp.json", []byte(content))

			res := ReadClaudeCode(t.Context(), path, tt.scope, dir)
			if len(res.Errors) != 0 {
				t.Fatalf("errors = %v, want none", res.Errors)
			}
			if got := serverNames(res.Servers); !slices.Equal(got, tt.want) {
				t.Fatalf("servers = %v, want %v", got, tt.want)
			}
			for _, s := range res.Servers {
				if tt.scope == ScopeProject && s.ProjectPath != dir {
					t.Errorf("server %q ProjectPath = %q, want %q", s.Name, s.ProjectPath, dir)
				}
			}
		})
	}
}

// TestReadClaudeCodeErrorsAs checks that the Result errors work with errors.As
// and that the messages hold the path, the position and the server name.
func TestReadClaudeCodeErrorsAs(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "invalid-entries")
	path := filepath.Join(home, ".claude.json")
	res := ReadClaudeCode(t.Context(), path, ScopeGlobal, "")
	if len(res.Errors) == 0 {
		t.Fatal("errors = none, want entry errors")
	}

	var joined []error
	for _, e := range res.Errors {
		joined = append(joined, e)
	}
	err := errors.Join(joined...)
	var fe *FileError
	if !errors.As(err, &fe) {
		t.Fatalf("errors.As(%T, *FileError) = false, want true", err)
	}
	if fe.Server != "empty" {
		t.Errorf("first FileError.Server = %q, want %q", fe.Server, "empty")
	}

	for _, e := range res.Errors {
		msg := e.Error()
		// The exact compare also shows that the message does not echo a
		// config value, for example the unknown transport type.
		want := path + ": server " + e.Server + ": " + e.Reason
		if msg != want {
			t.Errorf("Error() = %q, want %q", msg, want)
		}
	}
}

// TestReadClaudeCodeMalformedMessage checks the text of a syntax error: it has
// the path and the position and no config text.
func TestReadClaudeCodeMalformedMessage(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "malformed")
	path := filepath.Join(home, ".claude.json")
	res := ReadClaudeCode(t.Context(), path, ScopeGlobal, "")
	if len(res.Errors) != 1 {
		t.Fatalf("got %d errors, want 1", len(res.Errors))
	}
	msg := res.Errors[0].Error()
	if !strings.HasPrefix(msg, path+":3:") {
		t.Errorf("Error() = %q, want prefix %q", msg, path+":3:")
	}
	if !strings.HasSuffix(msg, ": "+reasonInvalidJSON) {
		t.Errorf("Error() = %q, want suffix %q", msg, ": "+reasonInvalidJSON)
	}
	if len(discovertest.Leaks(msg)) > 0 {
		t.Errorf("Error() holds a canary")
	}
}

// TestReadClaudeCodeMissingPath checks that a path that does not exist
// gives an empty Result and not an error.
func TestReadClaudeCodeMissingPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	res := ReadClaudeCode(t.Context(), filepath.Join(dir, "no", "such", ".claude.json"), ScopeGlobal, "")
	if len(res.Servers) != 0 || len(res.Errors) != 0 {
		t.Errorf("Result = %d servers, %v errors; want empty", len(res.Servers), res.Errors)
	}
}

// TestReadClaudeCodeCanceled checks that a canceled context gives an error
// that wraps context.Canceled.
func TestReadClaudeCodeCanceled(t *testing.T) {
	t.Parallel()
	home, _ := copyFixture(t, "claude-code", "valid")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	res := ReadClaudeCode(ctx, filepath.Join(home, ".claude.json"), ScopeGlobal, "")
	if len(res.Servers) != 0 {
		t.Errorf("servers = %v, want none", serverNames(res.Servers))
	}
	if len(res.Errors) != 1 {
		t.Fatalf("got %d errors, want 1", len(res.Errors))
	}
	if !errors.Is(res.Errors[0], context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false for %v", res.Errors[0])
	}
	var pe *fs.PathError
	if errors.As(res.Errors[0], &pe) {
		t.Errorf("canceled error wraps a PathError: %v", pe)
	}
}
