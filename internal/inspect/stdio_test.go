package inspect

import (
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// The helpers in this file have the prefix "sc" (stdioCommand), so they do
// not clash with helpers in other test files of the package.

// scServer returns a trusted global stdio server with the given command and
// args. Tests change the other fields when they need to.
func scServer(command string, args ...string) discover.Server {
	return discover.Server{
		Name:      "test-server",
		Client:    discover.ClientCodex,
		Scope:     discover.ScopeGlobal,
		Source:    "/home/user/.codex/config.toml",
		Transport: discover.TransportStdio,
		Command:   command,
		Args:      discover.NewArgs(args),
	}
}

// scBin creates the directory dir and an executable file name in it. It
// returns the path of the file, built with string concatenation like
// lookPath does.
func scBin(t *testing.T, dir, name string) string {
	t.Helper()
	lpMkdir(t, dir)
	path := dir + "/" + name
	lpWriteFile(t, path, 0o755)
	return path
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
					server:   scServer("/opt/mcp/server", "--stdio"),
					opts:     stdioOptions{Environ: []string{"PATH=/usr/bin", "HOME=/home/user"}, FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{"HOME=/home/user", "PATH=/usr/bin"},
				}
			},
		},
		{
			name: "absolute command with no args",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				return stdioCase{
					server:   scServer("/opt/mcp/server"),
					opts:     stdioOptions{FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{},
				}
			},
		},
		{
			name: "bare name found in config PATH",
			setup: func(t *testing.T) stdioCase {
				bin := t.TempDir() + "/bin"
				tool := scBin(t, bin, "tool")
				s := scServer("tool", "serve")
				s.Env = secrets(t, map[string]string{"PATH": bin})
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: t.TempDir()},
					wantPath: tool,
					wantEnv:  []string{"PATH=" + bin},
				}
			},
		},
		{
			name: "bare name found in parent PATH when config sets no PATH",
			setup: func(t *testing.T) stdioCase {
				bin := t.TempDir() + "/bin"
				tool := scBin(t, bin, "tool")
				return stdioCase{
					server:   scServer("tool"),
					opts:     stdioOptions{Environ: []string{"PATH=" + bin}, FallbackDir: t.TempDir()},
					wantPath: tool,
					wantEnv:  []string{"PATH=" + bin},
				}
			},
		},
		{
			name: "config PATH wins over parent PATH",
			setup: func(t *testing.T) stdioCase {
				root := t.TempDir()
				parentBin := root + "/parent-bin"
				configBin := root + "/config-bin"
				scBin(t, parentBin, "tool")
				configTool := scBin(t, configBin, "tool")
				s := scServer("tool")
				s.Env = secrets(t, map[string]string{"PATH": configBin})
				return stdioCase{
					server:   s,
					opts:     stdioOptions{Environ: []string{"PATH=" + parentBin}, FallbackDir: t.TempDir()},
					wantPath: configTool,
					wantEnv:  []string{"PATH=" + configBin},
				}
			},
		},
		{
			name: "relative command with absolute config Dir stays relative",
			setup: func(t *testing.T) stdioCase {
				dir := t.TempDir()
				s := scServer("./tool", "--port", "0")
				s.Dir = dir
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: t.TempDir()},
					wantPath: "./tool",
					wantDir:  dir,
					wantEnv:  []string{},
				}
			},
		},
		{
			name: "relative command with a subdirectory and absolute config Dir",
			setup: func(t *testing.T) stdioCase {
				dir := t.TempDir()
				s := scServer("bin/tool")
				s.Dir = dir
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: t.TempDir()},
					wantPath: "bin/tool",
					wantDir:  dir,
					wantEnv:  []string{},
				}
			},
		},
		{
			name: "absolute config Dir is kept as written",
			setup: func(t *testing.T) stdioCase {
				s := scServer("/opt/mcp/server")
				s.Dir = "/srv/mcp/../app/"
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: t.TempDir()},
					wantPath: "/opt/mcp/server",
					wantDir:  "/srv/mcp/../app/",
					wantEnv:  []string{},
				}
			},
		},
		{
			name: "empty Dir uses FallbackDir",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				return stdioCase{
					server:   scServer("/opt/mcp/server"),
					opts:     stdioOptions{FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{},
				}
			},
		},
		{
			name: "relative Dir uses FallbackDir",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := scServer("/opt/mcp/server")
				s.Dir = "sub"
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{},
				}
			},
		},
		{
			// A relative Dir is not used, so a NUL byte in it does not
			// matter (see errInvalidArg).
			name: "relative Dir with NUL uses FallbackDir",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := scServer("/opt/mcp/server")
				s.Dir = "sub\x00dir"
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{},
				}
			},
		},
		{
			name: "untrusted server with opt-in",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := scServer("/opt/mcp/server")
				s.Scope = discover.ScopeProject
				s.ProjectPath = "/home/user/project"
				s.Untrusted = true
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback, AllowUntrusted: true},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{},
				}
			},
		},
		{
			name: "args with shell syntax and non-ASCII are kept exactly",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := scServer("/opt/mcp/server",
					"two words", "$HOME", "${HOME}", "$(touch x)", "`id`", ";", "a;b", "|", "&&",
					"*", "?.go", "~", `"double"`, "'single'", `back\slash`, "", " ", "--x=",
					"héllo", "日本語", "\t\n", discovertest.CanaryArgs,
				)
				return stdioCase{
					server:   s,
					opts:     stdioOptions{FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{},
				}
			},
		},
		{
			name: "parent secrets are not passed",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				return stdioCase{
					server: scServer("/opt/mcp/server"),
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
					wantEnv:  []string{"PATH=/usr/bin"},
				}
			},
		},
		{
			name: "declared env is passed as written and overrides the parent",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				s := scServer("/opt/mcp/server")
				s.Env = secrets(t, map[string]string{
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
					},
				}
			},
		},
		{
			name: "nil parent and no declared env give an empty non-nil env",
			setup: func(t *testing.T) stdioCase {
				fallback := t.TempDir()
				return stdioCase{
					server:   scServer("/opt/mcp/server"),
					opts:     stdioOptions{Environ: nil, FallbackDir: fallback},
					wantPath: "/opt/mcp/server",
					wantDir:  fallback,
					wantEnv:  []string{},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := tt.setup(t)
			if c.wantDir == "" {
				c.wantDir = c.opts.FallbackDir
			}
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
	cmd, err := stdioCommand(scServer("/opt/mcp/server", "--stdio"), opts)
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
				s := scServer("/opt/" + canaryCmd)
				s.Transport = discover.TransportHTTP
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errNotStdio,
		},
		{
			name: "sse transport",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("/opt/" + canaryCmd)
				s.Transport = discover.TransportSSE
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errNotStdio,
		},
		{
			name: "empty transport",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("/opt/" + canaryCmd)
				s.Transport = ""
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errNotStdio,
		},
		{
			name: "untrusted server without opt-in",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("/opt/"+canaryCmd, discovertest.CanaryArgs)
				s.Untrusted = true
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errUntrusted,
		},
		{
			name: "empty command",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("", discovertest.CanaryArgs)
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errEmptyCommand,
		},
		{
			name: "NUL in command",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				return scServer("/opt/" + canaryCmd + "\x00x"), stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errInvalidArg,
		},
		{
			name: "NUL in an arg",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("/opt/"+canaryCmd, "ok", discovertest.CanaryArgs+"\x00tail")
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errInvalidArg,
		},
		{
			name: "NUL in absolute Dir",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("/opt/" + canaryCmd)
				s.Dir = canaryDir + "\x00x"
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errInvalidArg,
		},
		{
			name: "empty FallbackDir when needed",
			setup: func(_ *testing.T) (discover.Server, stdioOptions) {
				return scServer("/opt/"+canaryCmd, discovertest.CanaryArgs), stdioOptions{}
			},
			wantErr: errNoWorkDir,
		},
		{
			name: "relative FallbackDir",
			setup: func(_ *testing.T) (discover.Server, stdioOptions) {
				return scServer("/opt/" + canaryCmd), stdioOptions{FallbackDir: "mcpmoat-canary-fallback"}
			},
			wantErr: errNoWorkDir,
		},
		{
			name: "FallbackDir with NUL",
			setup: func(_ *testing.T) (discover.Server, stdioOptions) {
				return scServer("/opt/" + canaryCmd), stdioOptions{FallbackDir: canaryDir + "\x00x"}
			},
			wantErr: errNoWorkDir,
		},
		{
			name: "relative command with no config Dir",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				return scServer("./" + canaryCmd), stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errRelativeCommand,
		},
		{
			name: "relative command with relative config Dir",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("bin/" + canaryCmd)
				s.Dir = "mcpmoat-canary-reldir"
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errRelativeCommand,
		},
		{
			name: "bare name not found in PATH",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				empty := t.TempDir()
				s := scServer(canaryCmd, discovertest.CanaryArgs)
				s.Env = secrets(t, map[string]string{canaryName: discovertest.CanaryEnv})
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
				scBin(t, dir, canaryCmd)
				s := scServer(canaryCmd)
				s.Dir = dir
				return s, stdioOptions{Environ: []string{"PATH=" + t.TempDir()}, FallbackDir: t.TempDir()}
			},
			wantErr: errCommandNotFound,
		},
		{
			name: "bare name when PATH is absent everywhere",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				return scServer(canaryCmd), stdioOptions{Environ: []string{"HOME=/home/user"}, FallbackDir: t.TempDir()}
			},
			wantErr: errCommandNotFound,
		},
		{
			// "/" is absolute, so commandPath keeps it. exec.Command then
			// looks it up (filepath.Base("/") is "/"), the lookup fails and
			// sets cmd.Err.
			name: "command is the root directory",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				return scServer("/", discovertest.CanaryArgs), stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errCommandNotRunnable,
		},
		{
			name: "declared env name with =",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("/opt/" + canaryCmd)
				s.Env = secrets(t, map[string]string{"TOKEN=" + discovertest.CanaryEnv: discovertest.CanaryEnv})
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errInvalidEnvName,
		},
		{
			name: "empty declared env name",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("/opt/" + canaryCmd)
				s.Env = secrets(t, map[string]string{"": discovertest.CanaryEnv})
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errInvalidEnvName,
		},
		{
			name: "NUL in declared env value",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("/opt/" + canaryCmd)
				s.Env = secrets(t, map[string]string{canaryName: discovertest.CanaryEnv + "\x00tail"})
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
		return secrets(t, map[string]string{"TOKEN=" + discovertest.CanaryEnv: "x"})
	}

	tests := []struct {
		name    string
		setup   func(t *testing.T) (discover.Server, stdioOptions)
		wantErr error
	}{
		{
			name: "transport before untrusted gate",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("/opt/mcp/server")
				s.Transport = discover.TransportHTTP
				s.Untrusted = true
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errNotStdio,
		},
		{
			name: "untrusted gate before empty command",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("")
				s.Untrusted = true
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errUntrusted,
		},
		{
			name: "empty command before env",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("")
				s.Env = badName(t)
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errEmptyCommand,
		},
		{
			name: "NUL in arg before env",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("/opt/mcp/server", "a\x00b")
				s.Env = badName(t)
				return s, stdioOptions{FallbackDir: t.TempDir()}
			},
			wantErr: errInvalidArg,
		},
		{
			name: "env before work directory",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := scServer("/opt/mcp/server")
				s.Env = badName(t)
				return s, stdioOptions{}
			},
			wantErr: errInvalidEnvName,
		},
		{
			name: "work directory before relative command",
			setup: func(_ *testing.T) (discover.Server, stdioOptions) {
				return scServer("./tool"), stdioOptions{}
			},
			wantErr: errNoWorkDir,
		},
		{
			name: "work directory before command lookup",
			setup: func(_ *testing.T) (discover.Server, stdioOptions) {
				return scServer("mcpmoat-no-such-tool"), stdioOptions{}
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
			s := scServer("./tool", "--stdio")
			s.Dir = dir
			cmd, err := stdioCommand(s, stdioOptions{FallbackDir: tt.fallback})
			if err != nil {
				t.Fatalf("stdioCommand() error = %v, want nil", err)
			}
			scCheckCmd(t, cmd, s, "./tool", dir, []string{})
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
		{name: "last PATH entry wins", env: []string{"PATH=/first", "PATH=/last"}, want: "/last"},
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
