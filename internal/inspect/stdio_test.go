package inspect

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// The helpers that only this file uses have the prefix "sc" (stdioCommand).
// helpers_test.go holds the helpers that several test files share.

// scNoInstall is the entry that stdioCommand adds to the child environment
// unless the config declares npm_config_yes (issue #104). It is written out
// here, not built from npmYesName, so a change of the name fails the tests.
const scNoInstall = "npm_config_yes=false"

// scProjectServer returns a trusted Claude Code project server with the
// given command, whose ProjectPath is project.
func scProjectServer(command, project string) discover.Server {
	s := stdioServer(command)
	s.Client = discover.ClientClaudeCode
	s.Scope = discover.ScopeProject
	s.Source = project + "/.mcp.json"
	s.ProjectPath = project
	return s
}

// scConfigInputs returns the values from the config of s and the
// FallbackDir of opts. No error from stdioCommand may hold one of them.
func scConfigInputs(s discover.Server, opts stdioOptions) []string {
	in := []string{s.Command, s.Dir, opts.FallbackDir}
	in = append(in, s.Args.Values()...)
	for _, k := range s.Env.Keys() {
		in = append(in, k, s.Env[k].Reveal())
	}
	return in
}

// scCheckCmd checks every field of cmd that stdioCommand sets, and the
// fields that it must leave alone.
func scCheckCmd(t *testing.T, cmd *exec.Cmd, s discover.Server, wantPath, wantDir string, wantEnv []string) {
	t.Helper()
	if cmd == nil {
		t.Fatal("stdioCommand() cmd = nil, want a command")
	}
	if cmd.Err != nil {
		t.Errorf("cmd.Err = %v, want nil", cmd.Err)
	}
	if cmd.Path != wantPath {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, wantPath)
	}
	if len(cmd.Args) == 0 {
		t.Fatal("cmd.Args is empty, want Args[0] = the command")
	}
	if cmd.Args[0] != s.Command {
		t.Errorf("cmd.Args[0] = %q, want the command as written %q", cmd.Args[0], s.Command)
	}
	if want := s.Args.Values(); !slices.Equal(cmd.Args[1:], want) {
		t.Errorf("cmd.Args[1:] = %q, want %q", cmd.Args[1:], want)
	}
	if cmd.Dir != wantDir {
		t.Errorf("cmd.Dir = %q, want %q", cmd.Dir, wantDir)
	}
	if cmd.Env == nil {
		t.Error("cmd.Env = nil, want a non-nil slice (nil inherits the whole parent environment)")
	}
	if !slices.Equal(cmd.Env, wantEnv) {
		t.Errorf("cmd.Env = %q, want %q", cmd.Env, wantEnv)
	}
	if cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Error("cmd.Stdin, cmd.Stdout or cmd.Stderr is set, want all nil (the SDK transport makes the pipes)")
	}
	if cmd.Process != nil {
		t.Error("cmd.Process is set, want nil (stdioCommand must not start the process)")
	}
}

// TestStdioCommand checks the command that stdioCommand builds for a valid
// server: the path to run, the argv, the work directory and the scrubbed
// environment (NFR-04). No case starts a process.
//
// Each case builds its own directories in setup, so the cases can run in
// parallel.
func TestStdioCommand(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	type stdioCase struct {
		server   discover.Server
		opts     stdioOptions
		wantPath string
		wantDir  string
		wantEnv  []string
	}

	tests := []struct {
		name  string
		setup func(t *testing.T) stdioCase
	}{
		{
			name: "absolute command",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				return stdioCase{
					server:   stdioServer("/opt/mcp/server", "--stdio"),
					opts:     stdioOptions{Environ: []string{"PATH=/usr/bin", "HOME=/home/user"}, FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{"HOME=/home/user", "PATH=/usr/bin", scNoInstall},
				}
			},
		},
		{
			name: "absolute command with no args and an empty non-nil parent",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				return stdioCase{
					server:   stdioServer("/opt/mcp/server"),
					opts:     stdioOptions{Environ: []string{}, FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "bare name found in config PATH",
			setup: func(t *testing.T) stdioCase {
				bin := t.TempDir() + "/bin"
				tool := mustExecutable(t, bin, "tool")
				s := stdioServer("tool", "serve")
				s.Env = secrets(map[string]string{"PATH": bin})
				fallback := t.TempDir()
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback},
					wantPath: tool,
					wantDir:  fallback,
					wantEnv:  []string{"PATH=" + bin, scNoInstall},
				}
			},
		},
		{
			name: "bare name found in parent PATH when config sets no PATH",
			setup: func(t *testing.T) stdioCase {
				bin := t.TempDir() + "/bin"
				tool := mustExecutable(t, bin, "tool")
				fallback := t.TempDir()
				return stdioCase{
					server:   stdioServer("tool"),
					opts:     stdioOptions{Environ: []string{"PATH=" + bin}, FallbackDir: fallback},
					wantPath: tool,
					wantDir:  fallback,
					wantEnv:  []string{"PATH=" + bin, scNoInstall},
				}
			},
		},
		{
			name: "config PATH wins over parent PATH",
			setup: func(t *testing.T) stdioCase {
				root := t.TempDir()
				parentBin := root + "/parent-bin"
				configBin := root + "/config-bin"
				mustExecutable(t, parentBin, "tool")
				configTool := mustExecutable(t, configBin, "tool")
				s := stdioServer("tool")
				s.Env = secrets(map[string]string{"PATH": configBin})
				fallback := t.TempDir()
				return stdioCase{
					server:   s,
					opts:     stdioOptions{Environ: []string{"PATH=" + parentBin}, FallbackDir: fallback},
					wantPath: configTool,
					wantDir:  fallback,
					wantEnv:  []string{"PATH=" + configBin, scNoInstall},
				}
			},
		},
		{
			name: "relative command with absolute config Dir stays relative",
			setup: func(t *testing.T) stdioCase {
				dir := t.TempDir()
				s := stdioServer("./tool", "--port", "0")
				s.Dir = dir
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: t.TempDir()},
					wantPath: "./tool",
					wantDir:  dir,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "relative command with a subdirectory and absolute config Dir",
			setup: func(t *testing.T) stdioCase {
				dir := t.TempDir()
				s := stdioServer("bin/tool")
				s.Dir = dir
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: t.TempDir()},
					wantPath: "bin/tool",
					wantDir:  dir,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "absolute config Dir is kept as written",
			setup: func(t *testing.T) stdioCase {
				s := stdioServer("/opt/mcp/server")
				s.Dir = "/srv/mcp/../app/"
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: t.TempDir()},
					wantPath: "/opt/mcp/server",
					wantDir:  "/srv/mcp/../app/",
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "relative Dir uses FallbackDir",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := stdioServer("/opt/mcp/server")
				s.Dir = "sub"
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			// A relative Dir is not used, so a NUL byte in it does not
			// matter (see errInvalidArg).
			name: "relative Dir with NUL uses FallbackDir",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := stdioServer("/opt/mcp/server")
				s.Dir = "sub\x00dir"
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "untrusted server with opt-in",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := stdioServer("/opt/mcp/server")
				s.Scope = discover.ScopeProject
				s.ProjectPath = "/home/user/project"
				s.Untrusted = true
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback, AllowUntrusted: true},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "args with shell syntax and non-ASCII are kept exactly",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := stdioServer("/opt/mcp/server",
					"two words", "$HOME", "${HOME}", "$(touch x)", "`id`", ";", "a;b", "|", "&&",
					"*", "?.go", "~", `"double"`, "'single'", `back\slash`, "", " ", "--x=",
					"héllo", "日本語", "\t\n", discovertest.CanaryArgs,
				)
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "parent secrets are not passed",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				return stdioCase{
					server: stdioServer("/opt/mcp/server"),
					opts: stdioOptions{
						Environ: []string{
							"AWS_SECRET_ACCESS_KEY=" + discovertest.CanaryEnv,
							"GITHUB_TOKEN=" + discovertest.CanaryEnv,
							"SSH_AUTH_SOCK=/tmp/agent.sock",
							"NODE_OPTIONS=--require /tmp/evil.js",
							"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
							"PATH=/usr/bin",
						},
						FallbackDir: fallback,
					},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{"PATH=/usr/bin", scNoInstall},
				}
			},
		},
		{
			name: "declared env is passed as written and overrides the parent",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := stdioServer("/opt/mcp/server")
				s.Env = secrets(map[string]string{
					"API_KEY": discovertest.CanaryEnv,
					"HOME":    "/override",
					"REF":     "${HOME}/x",
				})
				return stdioCase{
					server:   s,
					opts:     stdioOptions{Environ: []string{"HOME=/home/user", "USER=user"}, FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv: []string{
						"API_KEY=" + discovertest.CanaryEnv,
						"HOME=/override",
						"REF=${HOME}/x",
						"USER=user",
						scNoInstall,
					},
				}
			},
		},
		{
			// npm_config_yes is not on the allowlist of the parent
			// environment, so a parent "true" never reaches the child, and
			// the forced "false" is added (issue #104).
			name: "parent npm_config_yes is dropped and the forced entry is added",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				return stdioCase{
					server: stdioServer("/opt/mcp/server"),
					opts: stdioOptions{
						Environ:     []string{"npm_config_yes=true", "NPM_CONFIG_YES=true", "PATH=/usr/bin"},
						FallbackDir: fallback,
					},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{"PATH=/usr/bin", scNoInstall},
				}
			},
		},
		{
			name: "declared npm_config_yes wins over the forced entry",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := stdioServer("/opt/mcp/server")
				s.Env = secrets(map[string]string{"npm_config_yes": "true"})
				return stdioCase{
					server:   s,
					opts:     stdioOptions{Environ: []string{"PATH=/usr/bin"}, FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{"PATH=/usr/bin", "npm_config_yes=true"},
				}
			},
		},
		{
			// npm reads its config variables in any letter case, so a
			// declared name in another case also counts as set.
			name: "declared NPM_CONFIG_YES in another case wins over the forced entry",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := stdioServer("/opt/mcp/server")
				s.Env = secrets(map[string]string{"NPM_CONFIG_YES": "true"})
				return stdioCase{
					server:   s,
					opts:     stdioOptions{Environ: []string{"PATH=/usr/bin"}, FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{"NPM_CONFIG_YES=true", "PATH=/usr/bin"},
				}
			},
		},
		{
			name: "disabled server with AllowDisabled",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := stdioServer("/opt/mcp/server")
				s.State = discover.StateDisabled
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback, AllowDisabled: true},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "unapproved server with AllowDisabled",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := stdioServer("/opt/mcp/server")
				s.State = discover.StateUnapproved
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback, AllowDisabled: true},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			// A .mcp.json server that only the repository approves is also
			// untrusted, so it needs both opt-ins.
			name: "untrusted project-approved server with both opt-ins",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := stdioServer("/opt/mcp/server")
				s.Untrusted = true
				s.State = discover.StateProjectApproved
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback, AllowUntrusted: true, AllowDisabled: true},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "untrusted and unapproved server with both opt-ins",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := stdioServer("/opt/mcp/server")
				s.Untrusted = true
				s.State = discover.StateUnapproved
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback, AllowUntrusted: true, AllowDisabled: true},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "trusted project server runs in ProjectPath",
			setup: func(t *testing.T) stdioCase {
				project := t.TempDir()
				s := scProjectServer("/opt/mcp/server", project)
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: t.TempDir()},
					wantPath: "/opt/mcp/server",
					wantDir:  project,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			// A project directory counts as a configured directory, so a
			// relative command stays relative and the kernel resolves it in
			// the project, as in the client.
			name: "trusted project server with a relative command resolves in ProjectPath",
			setup: func(t *testing.T) stdioCase {
				project := t.TempDir()
				mustExecutable(t, project, "server")
				s := scProjectServer("./server", project)
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: t.TempDir()},
					wantPath: "./server",
					wantDir:  project,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "trusted project server without FallbackDir needs none",
			setup: func(t *testing.T) stdioCase {
				project := t.TempDir()
				s := scProjectServer("/opt/mcp/server", project)
				return stdioCase{
					server:   s,
					opts:     stdioOptions{},
					wantPath: "/opt/mcp/server",
					wantDir:  project,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "absolute Dir wins over ProjectPath",
			setup: func(t *testing.T) stdioCase {
				dir := t.TempDir()
				s := scProjectServer("/opt/mcp/server", t.TempDir())
				s.Dir = dir
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: t.TempDir()},
					wantPath: "/opt/mcp/server",
					wantDir:  dir,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			// An untrusted project file can name any directory, so the
			// project directory is not used without the trust.
			name: "untrusted project server with opt-in uses FallbackDir, not ProjectPath",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := scProjectServer("/opt/mcp/server", t.TempDir())
				s.Untrusted = true
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback, AllowUntrusted: true},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "trusted project server whose ProjectPath does not exist uses FallbackDir",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := scProjectServer("/opt/mcp/server", t.TempDir()+"/missing")
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "global server with a ProjectPath uses FallbackDir",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := scProjectServer("/opt/mcp/server", t.TempDir())
				s.Scope = discover.ScopeGlobal
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
		{
			name: "empty Dir uses FallbackDir, and a nil parent with no declared env gives an empty non-nil env",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				return stdioCase{
					server:   stdioServer("/opt/mcp/server"),
					opts:     stdioOptions{Environ: nil, FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{scNoInstall},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := tt.setup(t)
			cmd, err := stdioCommand(c.server, c.opts)
			if err != nil {
				t.Fatalf("stdioCommand() error = %v, want nil", err)
			}
			scCheckCmd(t, cmd, c.server, c.wantPath, c.wantDir, c.wantEnv)
		})
	}
}

// TestStdioCommandParentSecretNotInEnv checks with the leak helper that a
// secret value from the parent environment reaches no part of the command:
// not the env, the argv, the path or the work directory.
func TestStdioCommandParentSecretNotInEnv(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	opts := stdioOptions{
		Environ:     []string{"AWS_SECRET_ACCESS_KEY=" + discovertest.CanaryEnv, "HOME=/home/user"},
		FallbackDir: t.TempDir(),
	}
	cmd, err := stdioCommand(stdioServer("/opt/mcp/server", "--stdio"), opts)
	if err != nil {
		t.Fatalf("stdioCommand() error = %v, want nil", err)
	}
	all := strings.Join(slices.Concat(cmd.Env, cmd.Args, []string{cmd.Path, cmd.Dir}), "\n")
	discovertest.AssertNoLeak(t, "command fields", all, discovertest.CanaryEnv)
	if slices.ContainsFunc(cmd.Env, func(e string) bool { return envKey(e) == "AWS_SECRET_ACCESS_KEY" }) {
		t.Error("cmd.Env has AWS_SECRET_ACCESS_KEY, want it scrubbed")
	}
}

// TestStdioCommandErrors checks that each invalid input gives the expected
// fixed error, no command and an error text with none of the inputs.
func TestStdioCommandErrors(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	const (
		canaryCmd  = "mcpmoat-canary-cmd-3Pq8Lz"
		canaryDir  = "/mcpmoat-canary-dir-6Wr2Nd"
		canaryName = "MCPMOAT_CANARY_NAME_8Ty4Gs"
	)

	tests := []struct {
		name    string
		setup   func(t *testing.T) (discover.Server, stdioOptions)
		wantErr error
	}{
		{
			name: "http transport",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/" + canaryCmd)
				s.Transport = discover.TransportHTTP
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errNotStdio,
		},
		{
			name: "sse transport",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/" + canaryCmd)
				s.Transport = discover.TransportSSE
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errNotStdio,
		},
		{
			name: "empty transport",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/" + canaryCmd)
				s.Transport = ""
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errNotStdio,
		},
		{
			name: "untrusted server without opt-in",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/"+canaryCmd, discovertest.CanaryArgs)
				s.Untrusted = true
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errUntrusted,
		},
		{
			name: "disabled server without opt-in",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/"+canaryCmd, discovertest.CanaryArgs)
				s.State = discover.StateDisabled
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errDisabled,
		},
		{
			name: "unapproved server without opt-in",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/"+canaryCmd, discovertest.CanaryArgs)
				s.State = discover.StateUnapproved
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errUnapproved,
		},
		{
			name: "project-approved server without opt-in",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/"+canaryCmd, discovertest.CanaryArgs)
				s.State = discover.StateProjectApproved
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errProjectApproved,
		},
		{
			// A State value that inspect does not know fails closed.
			name: "unknown state without opt-in",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/"+canaryCmd, discovertest.CanaryArgs)
				s.State = discover.State(200)
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errDisabled,
		},
		{
			// AllowUntrusted does not open the state gate.
			name: "untrusted disabled server with only AllowUntrusted",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/"+canaryCmd, discovertest.CanaryArgs)
				s.Untrusted = true
				s.State = discover.StateDisabled
				return s, stdioOptions{FallbackDir: t.TempDir(), AllowUntrusted: true}
			},
			wantErr: errDisabled,
		},
		{
			// The project directory of an untrusted server is not a
			// configured directory, so a relative command is refused.
			name: "relative command of an untrusted project server",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				project := t.TempDir()
				mustExecutable(t, project, canaryCmd)
				s := scProjectServer("./"+canaryCmd, project)
				s.Untrusted = true
				return s, stdioOptions{FallbackDir: t.TempDir(), AllowUntrusted: true}
			},
			wantErr: errRelativeCommand,
		},
		{
			name: "empty command",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("", discovertest.CanaryArgs)
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errEmptyCommand,
		},
		{
			name: "NUL in command",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				return stdioServer("/opt/" + canaryCmd + "\x00x"), stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errInvalidArg,
		},
		{
			name: "NUL in an arg",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/"+canaryCmd, "ok", discovertest.CanaryArgs+"\x00tail")
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errInvalidArg,
		},
		{
			name: "NUL in absolute Dir",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/" + canaryCmd)
				s.Dir = canaryDir + "\x00x"
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errInvalidArg,
		},
		{
			name: "empty FallbackDir when needed",
			setup: func(_ *testing.T) (discover.Server, stdioOptions) {
				return stdioServer("/opt/"+canaryCmd, discovertest.CanaryArgs), stdioOptions{}
			},
			wantErr: errNoWorkDir,
		},
		{
			name: "relative FallbackDir",
			setup: func(_ *testing.T) (discover.Server, stdioOptions) {
				return stdioServer("/opt/" + canaryCmd), stdioOptions{FallbackDir: "mcpmoat-canary-fallback"}
			},
			wantErr: errNoWorkDir,
		},
		{
			name: "FallbackDir with NUL",
			setup: func(_ *testing.T) (discover.Server, stdioOptions) {
				return stdioServer("/opt/" + canaryCmd), stdioOptions{FallbackDir: canaryDir + "\x00x"}
			},
			wantErr: errNoWorkDir,
		},
		{
			name: "relative command with no config Dir",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				return stdioServer("./" + canaryCmd), stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errRelativeCommand,
		},
		{
			name: "relative command with relative config Dir",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("bin/" + canaryCmd)
				s.Dir = "mcpmoat-canary-reldir"
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errRelativeCommand,
		},
		{
			name: "bare name not found in PATH",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				empty := t.TempDir()
				s := stdioServer(canaryCmd, discovertest.CanaryArgs)
				s.Env = secrets(map[string]string{canaryName: discovertest.CanaryEnv})
				return s, stdioOptions{Environ: []string{"PATH=" + empty}, FallbackDir: t.TempDir()}
			},
			wantErr: errCommandNotFound,
		},
		{
			// The file exists in the config Dir, but a bare name is looked
			// up only in PATH, never in Dir.
			name: "bare name in config Dir but not in PATH",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				dir := t.TempDir()
				mustExecutable(t, dir, canaryCmd)
				s := stdioServer(canaryCmd)
				s.Dir = dir
				return s, stdioOptions{Environ: []string{"PATH=" + t.TempDir()}, FallbackDir: t.TempDir()}
			},
			wantErr: errCommandNotFound,
		},
		{
			name: "bare name when PATH is absent everywhere",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				return stdioServer(canaryCmd), stdioOptions{Environ: []string{"HOME=/home/user"}, FallbackDir: t.TempDir()}
			},
			wantErr: errCommandNotFound,
		},
		{
			// "/" is absolute, so commandPath keeps it. exec.Command then
			// looks it up (filepath.Base("/") is "/"), the lookup fails and
			// sets cmd.Err.
			name: "command is the root directory",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				return stdioServer("/", discovertest.CanaryArgs), stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errCommandNotRunnable,
		},
		{
			name: "declared env name with =",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/" + canaryCmd)
				s.Env = secrets(map[string]string{"TOKEN=" + discovertest.CanaryEnv: discovertest.CanaryEnv})
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errInvalidEnvName,
		},
		{
			name: "empty declared env name",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/" + canaryCmd)
				s.Env = secrets(map[string]string{"": discovertest.CanaryEnv})
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errInvalidEnvName,
		},
		{
			name: "NUL in declared env value",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/" + canaryCmd)
				s.Env = secrets(map[string]string{canaryName: discovertest.CanaryEnv + "\x00tail"})
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errInvalidEnvValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, opts := tt.setup(t)
			cmd, err := stdioCommand(s, opts)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("stdioCommand() error = %v, want %v", err, tt.wantErr)
			}
			if cmd != nil {
				t.Error("stdioCommand() cmd is not nil, want nil on error")
			}
			discovertest.AssertNoLeak(t, "error", err.Error(), scConfigInputs(s, opts)...)
		})
	}
}

// TestStdioCommandCheckOrder checks the documented order of the checks:
// when two checks fail, the first one gives the error.
func TestStdioCommandCheckOrder(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	badName := func(t *testing.T) discover.SecretMap {
		t.Helper()
		return secrets(map[string]string{"TOKEN=" + discovertest.CanaryEnv: "x"})
	}

	tests := []struct {
		name    string
		setup   func(t *testing.T) (discover.Server, stdioOptions)
		wantErr error
	}{
		{
			name: "transport before untrusted gate",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/mcp/server")
				s.Transport = discover.TransportHTTP
				s.Untrusted = true
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errNotStdio,
		},
		{
			name: "untrusted gate before empty command",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("")
				s.Untrusted = true
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errUntrusted,
		},
		{
			name: "transport before state gate",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/mcp/server")
				s.Transport = discover.TransportHTTP
				s.State = discover.StateDisabled
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errNotStdio,
		},
		{
			// Both gates refuse the server. The state gate comes first, so
			// its error wins.
			name: "state gate before untrusted gate",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/mcp/server")
				s.Untrusted = true
				s.State = discover.StateUnapproved
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errUnapproved,
		},
		{
			// A .mcp.json server is untrusted, and only the repository
			// approves it: the state gate still wins.
			name: "project-approved state gate before untrusted gate",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/mcp/server")
				s.Untrusted = true
				s.State = discover.StateProjectApproved
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errProjectApproved,
		},
		{
			// AllowDisabled opens the state gate only. The untrusted gate
			// still refuses the server.
			name: "AllowDisabled does not open the untrusted gate",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/mcp/server")
				s.Untrusted = true
				s.State = discover.StateDisabled
				return s, stdioOptions{FallbackDir: t.TempDir(), AllowDisabled: true}
			},
			wantErr: errUntrusted,
		},
		{
			// AllowUntrusted opens the untrusted gate only. The state gate
			// still refuses the server.
			name: "AllowUntrusted does not open the state gate",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/mcp/server")
				s.Untrusted = true
				s.State = discover.StateProjectApproved
				return s, stdioOptions{FallbackDir: t.TempDir(), AllowUntrusted: true}
			},
			wantErr: errProjectApproved,
		},
		{
			name: "state gate before empty command",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("")
				s.State = discover.StateDisabled
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errDisabled,
		},
		{
			name: "state gate before env",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/mcp/server")
				s.State = discover.StateUnapproved
				s.Env = badName(t)
				return s, stdioOptions{}
			},
			wantErr: errUnapproved,
		},
		{
			name: "empty command before env",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("")
				s.Env = badName(t)
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errEmptyCommand,
		},
		{
			name: "NUL in arg before env",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/mcp/server", "a\x00b")
				s.Env = badName(t)
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errInvalidArg,
		},
		{
			name: "env before work directory",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("/opt/mcp/server")
				s.Env = badName(t)
				return s, stdioOptions{}
			},
			wantErr: errInvalidEnvName,
		},
		{
			name: "work directory before relative command",
			setup: func(_ *testing.T) (discover.Server, stdioOptions) {
				return stdioServer("./tool"), stdioOptions{}
			},
			wantErr: errNoWorkDir,
		},
		{
			name: "work directory before command lookup",
			setup: func(_ *testing.T) (discover.Server, stdioOptions) {
				return stdioServer("mcpmoat-no-such-tool"), stdioOptions{}
			},
			wantErr: errNoWorkDir,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, opts := tt.setup(t)
			cmd, err := stdioCommand(s, opts)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("stdioCommand() error = %v, want %v", err, tt.wantErr)
			}
			if cmd != nil {
				t.Error("stdioCommand() cmd is not nil, want nil on error")
			}
		})
	}
}

// TestStdioCommandFallbackOnlyWhenNeeded checks that a bad FallbackDir does
// not matter when the config sets an absolute Dir: stdioCommand checks the
// fallback only when it uses it.
func TestStdioCommandFallbackOnlyWhenNeeded(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	tests := []struct {
		name     string
		fallback string
	}{
		{name: "empty FallbackDir", fallback: ""},
		{name: "relative FallbackDir", fallback: "rel"},
		{name: "FallbackDir with NUL", fallback: "/tmp/a\x00b"},
		{name: "FallbackDir that does not exist", fallback: "/mcpmoat-no-such-dir"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			s := stdioServer("./tool", "--stdio")
			s.Dir = dir
			cmd, err := stdioCommand(s, stdioOptions{FallbackDir: tt.fallback})
			if err != nil {
				t.Fatalf("stdioCommand() error = %v, want nil", err)
			}
			scCheckCmd(t, cmd, s, "./tool", dir, []string{scNoInstall})
		})
	}
}

// TestStateGate checks every state with and without the opt-in. Only
// StateEnabled passes without the opt-in. StateProjectApproved is refused
// as StateUnapproved is, with its own error. A state that inspect does not
// know (State(4) and up) fails closed with errDisabled.
func TestStateGate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state discover.State
		allow bool
		want  error
	}{
		{name: "enabled", state: discover.StateEnabled, want: nil},
		{name: "enabled with opt-in", state: discover.StateEnabled, allow: true, want: nil},
		{name: "disabled", state: discover.StateDisabled, want: errDisabled},
		{name: "disabled with opt-in", state: discover.StateDisabled, allow: true, want: nil},
		{name: "unapproved", state: discover.StateUnapproved, want: errUnapproved},
		{name: "unapproved with opt-in", state: discover.StateUnapproved, allow: true, want: nil},
		{name: "project-approved", state: discover.StateProjectApproved, want: errProjectApproved},
		{name: "project-approved with opt-in", state: discover.StateProjectApproved, allow: true, want: nil},
		// State(4) is the first value after StateProjectApproved.
		{name: "first unknown state", state: discover.State(4), want: errDisabled},
		{name: "unknown state 200", state: discover.State(200), want: errDisabled},
		{name: "largest unknown state", state: discover.State(255), want: errDisabled},
		{name: "unknown state with opt-in", state: discover.State(255), allow: true, want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := stateGate(tt.state, tt.allow); !errors.Is(got, tt.want) {
				t.Errorf("stateGate(%v, %v) = %v, want %v", tt.state, tt.allow, got, tt.want)
			}
		})
	}
}

// TestStdioCommandNpxProjectServer is the acceptance test of issue #104. A
// trusted project server runs "npx local-only-tool". The child must start in
// the project directory, where npx finds the locally installed tool, and get
// npm_config_yes=false, so that npx never installs a package with that name
// from the registry. A declared npm_config_yes wins.
//
// The npx here is a fake shell script in a temporary PATH: no real npm runs
// and nothing goes to the network. The script writes its work directory, its
// npm_config_yes value and its first argument to a file in its work
// directory, so the test sees what the child really got.
func TestStdioCommandNpxProjectServer(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	const script = "#!/bin/sh\n" +
		"printf '%s\\n' \"$(pwd -P)\" \"${npm_config_yes-unset}\" \"$1\" > ./npx-ran\n"

	tests := []struct {
		name     string
		declared map[string]string
		wantYes  string
		wantEnv  func(bin string) []string
	}{
		{
			name:    "no declared npm_config_yes",
			wantYes: "false",
			wantEnv: func(bin string) []string { return []string{"PATH=" + bin, scNoInstall} },
		},
		{
			name:     "declared npm_config_yes wins",
			declared: map[string]string{"npm_config_yes": "true"},
			wantYes:  "true",
			wantEnv:  func(bin string) []string { return []string{"PATH=" + bin, "npm_config_yes=true"} },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bin := t.TempDir()
			npx := bin + "/npx"
			if err := os.WriteFile(npx, []byte(script), 0o600); err != nil {
				t.Fatalf("write fake npx: %v", err)
			}
			if err := os.Chmod(npx, 0o700); err != nil { //nolint:gosec // G302: the fake npx must be executable
				t.Fatalf("chmod fake npx: %v", err)
			}
			project := t.TempDir()

			s := scProjectServer("npx", project)
			s.Args = discover.NewArgs([]string{"local-only-tool"})
			s.Env = secrets(tt.declared)
			cmd, err := stdioCommand(s, stdioOptions{
				Environ:     []string{"PATH=" + bin, "npm_config_yes=true"},
				FallbackDir: t.TempDir(),
			})
			if err != nil {
				t.Fatalf("stdioCommand() error = %v, want nil", err)
			}
			scCheckCmd(t, cmd, s, npx, project, tt.wantEnv(bin))

			if err := cmd.Run(); err != nil {
				t.Fatalf("run fake npx: %v", err)
			}
			b, err := os.ReadFile(filepath.Join(project, "npx-ran")) //nolint:gosec // G304: test reads a file under t.TempDir()
			if err != nil {
				t.Fatalf("read the output of fake npx: %v (it did not run in the project directory?)", err)
			}
			wantDir, err := filepath.EvalSymlinks(project)
			if err != nil {
				t.Fatalf("EvalSymlinks(%q) error = %v", project, err)
			}
			want := wantDir + "\n" + tt.wantYes + "\nlocal-only-tool\n"
			if got := string(b); got != want {
				t.Errorf("fake npx saw %q, want %q", got, want)
			}
		})
	}
}

// TestPathFromEnv checks that pathFromEnv returns the PATH value exactly,
// and "" when env has no PATH entry.
func TestPathFromEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  []string
		want string
	}{
		{name: "nil env", env: nil, want: ""},
		{name: "empty env", env: []string{}, want: ""},
		{name: "no PATH", env: []string{"HOME=/home/user", "USER=user"}, want: ""},
		{name: "empty PATH", env: []string{"PATH="}, want: ""},
		{name: "PATH value returned exactly", env: []string{"HOME=/h", "PATH=/a/bin:/b/../c/:", "USER=u"}, want: "/a/bin:/b/../c/:"},
		{name: "spaces and = kept", env: []string{"PATH= /a b=c "}, want: " /a b=c "},
		{name: "PATH with no = is not a PATH entry", env: []string{"PATH"}, want: ""},
		{name: "lowercase path is not PATH", env: []string{"path=/x"}, want: ""},
		{name: "longer name is not PATH", env: []string{"PATHX=/x", "MYPATH=/y"}, want: ""},
		{name: "first PATH entry wins", env: []string{"PATH=/first", "PATH=/last"}, want: "/first"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pathFromEnv(tt.env); got != tt.want {
				t.Errorf("pathFromEnv(%q) = %q, want %q", tt.env, got, tt.want)
			}
		})
	}
}
