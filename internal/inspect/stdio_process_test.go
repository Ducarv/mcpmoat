package inspect

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// The tests in this file start a real child process: the test binary itself,
// in its env dump mode (see envDumpArg and TestMain in main_test.go). They are
// the acceptance tests of issue #27 (NFR-04). The child reports the argv, the
// environment and the work directory that it really got from the operating
// system, so the tests prove what reaches the server, not only what
// stdioCommand puts into the *exec.Cmd.

// Canary values for the parent environment in TestStdioChildEnvIsScrubbed.
// They are fake secrets in the style of the discovertest canaries, so
// discovertest.Leaks can find them in any form.
const (
	procCanaryAWS    = "mcpmoat-canary-aws-3Kp7Zs"
	procCanaryGitHub = "mcpmoat-canary-github-8Wm2Qd"
)

// procServer returns a stdio server config that runs command with envDumpArg
// as the first argument, then args, and the declared env.
func procServer(command string, args []string, env discover.SecretMap) discover.Server {
	argv := make([]string, 0, len(args)+1)
	argv = append(argv, envDumpArg)
	argv = append(argv, args...)
	return discover.Server{
		Name:      "envdump",
		Transport: discover.TransportStdio,
		Command:   command,
		Args:      discover.NewArgs(argv),
		Env:       env,
	}
}

// procRun builds the command for s with stdioCommand, runs it and decodes
// the env dump from its stdout. It reads stdout only, because the race
// detector runtime can write to stderr.
//
// showStderr adds the stderr of a failed child to the failure message. Set
// it only when opts.Environ is synthetic. With the real parent environment,
// the stderr could hold real values, so procRun then reports only the error.
// The fixture child writes only a short error text to stderr, never its
// environment, so the stderr is safe to show in the other tests.
func procRun(t *testing.T, s discover.Server, opts stdioOptions, showStderr bool) ([]byte, envDump) {
	t.Helper()
	cmd, err := stdioCommand(s, opts)
	if err != nil {
		t.Fatalf("stdioCommand() error = %v", err)
	}
	out, err := cmd.Output()
	if err != nil {
		exitErr, ok := errors.AsType[*exec.ExitError](err)
		if ok && showStderr {
			t.Fatalf("child process error = %v; stderr:\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("child process error = %v", err)
	}
	return out, decodeEnvDump(t, out)
}

// procSameDir fails the test when got and want do not name the same
// directory. It resolves symlinks on both sides first: on macOS,
// t.TempDir() is under /var, which is a symlink to /private/var, and the
// child reports the resolved path.
func procSameDir(t *testing.T, got, want string) {
	t.Helper()
	gotReal, err := filepath.EvalSymlinks(got)
	if err != nil {
		t.Fatalf("filepath.EvalSymlinks(child cwd %q) error = %v", got, err)
	}
	wantReal, err := filepath.EvalSymlinks(want)
	if err != nil {
		t.Fatalf("filepath.EvalSymlinks(%q) error = %v", want, err)
	}
	if gotReal != wantReal {
		t.Errorf("child cwd = %q (%q), want %q (%q)", got, gotReal, want, wantReal)
	}
}

// procEnvMap splits "name=value" entries into a map. It fails the test when
// a name occurs twice or an entry has no "=", and it reports only the name.
func procEnvMap(t *testing.T, env []string) map[string]string {
	t.Helper()
	m := make(map[string]string, len(env))
	for _, entry := range env {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatalf("child env has an entry with no \"=\" (name part %q)", name)
		}
		if _, dup := m[name]; dup {
			t.Fatalf("child env has the name %q more than once", name)
		}
		m[name] = value
	}
	return m
}

// procMaskEnv returns env for a failure message. An entry that is in known
// shows in full. Any other entry shows as its name and "=<hidden>". If the
// scrub is broken, the child has the real environment of the test process,
// so a message must not show values that the test did not set itself.
func procMaskEnv(env, known []string) []string {
	masked := make([]string, 0, len(env))
	for _, entry := range env {
		if slices.Contains(known, entry) {
			masked = append(masked, entry)
			continue
		}
		masked = append(masked, envKey(entry)+"=<hidden>")
	}
	return masked
}

// procAssertNoCanary fails the test for each canary value that
// discovertest.Leaks finds in out. canaries maps a variable name to its
// canary value. The message names the variable only. It does not use
// discovertest.AssertNoLeak, because that prints the whole output, and the
// output can hold the real environment of the test process.
func procAssertNoCanary(t *testing.T, out []byte, canaries map[string]string) {
	t.Helper()
	for _, name := range procSortedKeys(canaries) {
		if len(discovertest.Leaks(string(out), canaries[name])) > 0 {
			t.Errorf("child env dump contains the canary value of %s", name)
		}
	}
}

// procSortedKeys returns the keys of m in sorted order.
func procSortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// TestStdioChildEnvIsScrubbed proves two acceptance criteria of issue #27
// with the real parent environment: the child gets only the allowlisted
// parent variables and the declared variables, and a secret such as
// AWS_SECRET_ACCESS_KEY in the parent is absent in the child.
//
// The test uses t.Setenv, so it cannot run in parallel. The parent
// environment is real, so failure messages show variable names only, never
// values.
func TestStdioChildEnvIsScrubbed(t *testing.T) {
	skipOnWindows(t)
	t.Setenv("AWS_SECRET_ACCESS_KEY", procCanaryAWS)
	t.Setenv("GITHUB_TOKEN", procCanaryGitHub)

	declared := map[string]string{
		"API_KEY": "declared-value",
		// PATH is on the allowlist. The declared value must override the
		// parent value. The command is absolute, so PATH is not used to
		// find it.
		"PATH": "/usr/bin:/bin",
	}
	parent := os.Environ()

	// want is the parent entries whose names are on the allowlist (the
	// first entry wins), then the declared entries.
	want := make(map[string]string)
	for _, entry := range parent {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || !isBaseEnv(name) {
			continue
		}
		if _, seen := want[name]; !seen {
			want[name] = value
		}
	}
	for name, value := range declared {
		want[name] = value
	}

	s := procServer(envDumpExe(t), nil, secrets(t, declared))
	opts := stdioOptions{Environ: parent, FallbackDir: t.TempDir()}
	out, dump := procRun(t, s, opts, false)

	got := procEnvMap(t, dump.Env)
	gotKeys, wantKeys := procSortedKeys(got), procSortedKeys(want)
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Errorf("child env names = %q, want %q", gotKeys, wantKeys)
	}
	for _, name := range wantKeys {
		value, ok := got[name]
		if ok && value != want[name] {
			t.Errorf("child env %s has another value than expected (value not shown)", name)
		}
	}
	for _, name := range []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"} {
		if _, ok := got[name]; ok {
			t.Errorf("child env has %s, want it absent", name)
		}
	}
	procAssertNoCanary(t, out, map[string]string{
		"AWS_SECRET_ACCESS_KEY": procCanaryAWS,
		"GITHUB_TOKEN":          procCanaryGitHub,
	})
}

// TestStdioChildEnvExact proves with a synthetic parent environment that the
// child environment is exactly the allowlisted parent entries plus the
// declared entries, and that a declared entry overrides a parent entry.
// SSH_AUTH_SOCK, LD_PRELOAD and AWS_SECRET_ACCESS_KEY are not on the
// allowlist, so they must not reach the child.
func TestStdioChildEnvExact(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	parent := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/x",
		"AWS_SECRET_ACCESS_KEY=" + discovertest.CanaryEnv,
		"SSH_AUTH_SOCK=/tmp/s",
		"LANG=C.UTF-8",
		"LD_PRELOAD=/evil.so",
	}
	declared := secrets(t, map[string]string{"TOKEN": "t", "HOME": "/override"})

	s := procServer(envDumpExe(t), nil, declared)
	opts := stdioOptions{Environ: parent, FallbackDir: t.TempDir()}
	out, dump := procRun(t, s, opts, true)

	want := []string{"HOME=/override", "LANG=C.UTF-8", "PATH=/usr/bin:/bin", "TOKEN=t"}
	got := slices.Sorted(slices.Values(dump.Env))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("child env = %q, want %q", procMaskEnv(got, want), want)
	}
	procAssertNoCanary(t, out, map[string]string{"AWS_SECRET_ACCESS_KEY": discovertest.CanaryEnv})
}

// TestStdioChildEnvEmpty proves that an empty parent environment and no
// declared env give the child an empty environment. A nil cmd.Env would give
// the child the whole environment of the test process instead.
func TestStdioChildEnvEmpty(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	s := procServer(envDumpExe(t), nil, nil)
	opts := stdioOptions{Environ: nil, FallbackDir: t.TempDir()}
	_, dump := procRun(t, s, opts, true)

	if dump.Env == nil || len(dump.Env) != 0 {
		// Only the names: with a nil cmd.Env, the child has the real
		// environment of the test process.
		names := make([]string, 0, len(dump.Env))
		for _, entry := range dump.Env {
			names = append(names, envKey(entry))
		}
		t.Errorf("child env names = %q, want an empty environment", names)
	}
}

// TestStdioChildArgsExact proves the acceptance criterion that the command
// and args reach the child byte-for-byte as configured. No shell runs, so
// quotes, variables, globs, command substitution and separators stay plain
// text, and "$(touch pwned)" creates no file.
func TestStdioChildArgsExact(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	args := []string{
		"",
		" a b ",
		"$HOME",
		"$(touch pwned)",
		"`id`",
		";",
		"&&",
		"|",
		"*",
		"'single'",
		"\"double\"",
		"back\\slash",
		"new\nline",
		"naïve-ü-日本",
		"--flag=value",
	}
	workDir := t.TempDir()
	s := procServer(envDumpExe(t), args, nil)
	opts := stdioOptions{Environ: []string{"HOME=/home/x"}, FallbackDir: workDir}
	_, dump := procRun(t, s, opts, true)

	if len(dump.Args) < 2 {
		t.Fatalf("child argv = %q, want at least 2 entries", dump.Args)
	}
	if dump.Args[0] != s.Command {
		t.Errorf("child argv[0] = %q, want %q", dump.Args[0], s.Command)
	}
	if dump.Args[1] != envDumpArg {
		t.Errorf("child argv[1] = %q, want %q", dump.Args[1], envDumpArg)
	}
	if got := dump.Args[2:]; !reflect.DeepEqual(got, args) {
		t.Errorf("child argv[2:] = %q, want %q", got, args)
	}

	entries, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatalf("os.ReadDir(work dir) error = %v", err)
	}
	for _, e := range entries {
		t.Errorf("work dir has %q, want it empty (no shell may run the args)", e.Name())
	}
	procSameDir(t, dump.Cwd, workDir)
}

// TestStdioChildBareNameLookup proves that a bare command name is found in
// the PATH of the child environment (here the declared PATH), not in the
// parent PATH, and that the child gets the name as written as argv[0].
func TestStdioChildBareNameLookup(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	bin := t.TempDir() + "/bin"
	lpMkdir(t, bin)
	lpSymlink(t, envDumpExe(t), bin+"/mcpmoat-envdump")

	s := procServer("mcpmoat-envdump", nil, secrets(t, map[string]string{"PATH": bin}))
	opts := stdioOptions{Environ: []string{"PATH=/nonexistent"}, FallbackDir: t.TempDir()}

	cmd, err := stdioCommand(s, opts)
	if err != nil {
		t.Fatalf("stdioCommand() error = %v", err)
	}
	if want := bin + "/mcpmoat-envdump"; cmd.Path != want {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, want)
	}

	_, dump := procRun(t, s, opts, true)
	if len(dump.Args) == 0 || dump.Args[0] != "mcpmoat-envdump" {
		t.Errorf("child argv = %q, want argv[0] %q", dump.Args, "mcpmoat-envdump")
	}
	if got, ok := procEnvMap(t, dump.Env)["PATH"]; !ok || got != bin {
		// The value is not shown: with a broken scrub it is the real PATH.
		t.Errorf("child PATH is not the declared PATH %q (value not shown, present = %v)", bin, ok)
	}
}

// TestStdioChildRelativeCommand proves that a relative command such as
// "./envdump" runs relative to the absolute Dir of the config, and that the
// child gets the command as written as argv[0] and Dir as its work
// directory.
func TestStdioChildRelativeCommand(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	dir := t.TempDir()
	lpSymlink(t, envDumpExe(t), dir+"/envdump")

	s := procServer("./envdump", nil, nil)
	s.Dir = dir
	opts := stdioOptions{FallbackDir: t.TempDir()}
	_, dump := procRun(t, s, opts, true)

	if len(dump.Args) == 0 || dump.Args[0] != "./envdump" {
		t.Errorf("child argv = %q, want argv[0] %q", dump.Args, "./envdump")
	}
	procSameDir(t, dump.Cwd, dir)
}

// TestStdioChildRelativeDirUsesFallback proves that a relative Dir counts as
// no Dir: the child runs in opts.FallbackDir, not in a directory relative to
// the work directory of mcpmoat.
func TestStdioChildRelativeDirUsesFallback(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	fallback := t.TempDir()
	s := procServer(envDumpExe(t), nil, nil)
	s.Dir = "relative/sub"
	opts := stdioOptions{FallbackDir: fallback}
	_, dump := procRun(t, s, opts, true)

	procSameDir(t, dump.Cwd, fallback)
}
