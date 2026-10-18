package inspect_test

// These tests run the real SDKInspector against the benign fixture server in
// testdata/servers/benign. They are black-box tests: they use only the
// exported API of package inspect.
//
// The identifiers in this file start with "sdk", so they do not collide with
// the other files of package inspect_test (for example stop_unix_test.go).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

const (
	// sdkTimeout bounds every call to Inspect, so a bug never hangs CI.
	sdkTimeout = 10 * time.Second

	// sdkParentCanary is a fake secret in the environment of the test
	// process. It must never reach the child (NFR-04) or an error.
	sdkParentCanary = "mcpmoat-parent-canary-sdk-6Rw4Np"

	// sdkCommandMarker is a unique text in commands that inspect refuses.
	// The error of a refused command must not contain the command.
	sdkCommandMarker = "mcpmoat-cmd-marker-sdk-2Lp7Vy"
)

// sdkCtx returns a context that ends after timeout or when the test ends.
func sdkCtx(t *testing.T, timeout time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)
	return ctx
}

// sdkSecretEnv returns a SecretMap with one entry for each key and value.
func sdkSecretEnv(kv map[string]string) discover.SecretMap {
	m := make(discover.SecretMap, len(kv))
	for k, v := range kv {
		m[k] = discover.NewSecret(v)
	}
	return m
}

// sdkJSON returns v as indented JSON, for readable failure messages.
func sdkJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%#v (json error: %v)", v, err)
	}
	return string(b)
}

// sdkAssertResult fails the test when got is not deeply equal to want. It
// prints both values as JSON. JSON does not show the difference between a
// nil and an empty slice, so if the JSON is equal it prints the Go values
// too.
func sdkAssertResult(t *testing.T, got, want inspect.Result) {
	t.Helper()
	if reflect.DeepEqual(got, want) {
		return
	}
	gotJSON, wantJSON := sdkJSON(got), sdkJSON(want)
	if gotJSON == wantJSON {
		t.Errorf("Result differs only in nil versus empty values:\ngot:  %#v\nwant: %#v", got, want)
		return
	}
	t.Errorf("Result mismatch:\n--- got\n%s\n--- want\n%s", gotJSON, wantJSON)
}

// sdkAssertFailed checks the error contract of Inspect for a failed call:
// a non-nil error, a zero Result, and an error that wraps at least one of
// targets.
func sdkAssertFailed(t *testing.T, res inspect.Result, err error, targets ...error) {
	t.Helper()
	if err == nil {
		t.Fatalf("Inspect() error = nil, want an error that wraps one of %v", targets)
	}
	if !reflect.DeepEqual(res, inspect.Result{}) {
		t.Errorf("Inspect() Result = %s, want the zero Result with an error", sdkJSON(res))
	}
	if sdkWrapped(err, targets...) == nil {
		t.Errorf("Inspect() error = %q, want an error that wraps one of %v", err, targets)
	}
}

// sdkWrapped returns the first of targets that err wraps, or nil.
func sdkWrapped(err error, targets ...error) error {
	for _, target := range targets {
		if errors.Is(err, target) {
			return target
		}
	}
	return nil
}

// sdkAssertNoLeak fails the test when the error text holds any canary of
// package discovertest, the parent canary or one of extra.
func sdkAssertNoLeak(t *testing.T, err error, extra ...string) {
	t.Helper()
	if err == nil {
		return
	}
	secrets := append(discovertest.Canaries(), sdkParentCanary)
	secrets = append(secrets, extra...)
	discovertest.AssertNoLeak(t, "error", err.Error(), secrets...)
}

// sdkAssertNotExist fails the test when path exists.
func sdkAssertNotExist(t *testing.T, path, why string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("os.Stat(%q) error = %v, want fs.ErrNotExist: %s", path, err, why)
	}
}

// TestSDKInspectBenign checks the full Result of the benign server: the
// handshake fields, both tools (the fixture has page size 1, so this needs
// pagination), the prompt, the resource and the schema mapping.
func TestSDKInspectBenign(t *testing.T) {
	t.Parallel()

	got, err := sdkNew(t, inspect.Options{}).Inspect(sdkCtx(t, sdkTimeout), sdkBenign(t))
	if err != nil {
		t.Fatalf("Inspect() error = %v, want nil", err)
	}
	sdkAssertResult(t, got, inspecttest.BenignResult())
}

// TestSDKInspectClientVersion checks that a custom ClientVersion does not
// change what the server reports.
func TestSDKInspectClientVersion(t *testing.T) {
	t.Parallel()

	got, err := sdkNew(t, inspect.Options{ClientVersion: "1.2.3"}).Inspect(sdkCtx(t, sdkTimeout), sdkBenign(t))
	if err != nil {
		t.Fatalf("Inspect() error = %v, want nil", err)
	}
	sdkAssertResult(t, got, inspecttest.BenignResult())
}

// TestSDKInspectUntrusted checks that an untrusted server never starts
// without the opt-in, and that it works with the opt-in.
func TestSDKInspectUntrusted(t *testing.T) {
	t.Parallel()

	t.Run("refused without opt-in", func(t *testing.T) {
		t.Parallel()
		pidfile := filepath.Join(t.TempDir(), "pid")
		s := sdkBenign(t, "-pidfile", pidfile)
		s.Untrusted = true
		s.Env = sdkSecretEnv(map[string]string{"MCPMOAT_TEST_TOKEN": discovertest.CanaryEnv})

		res, err := sdkNew(t, inspect.Options{}).Inspect(sdkCtx(t, sdkTimeout), s)

		sdkAssertFailed(t, res, err, inspect.ErrUntrusted)
		sdkAssertNotExist(t, pidfile, "the untrusted server must not start")
		sdkAssertNoLeak(t, err, pidfile)
	})

	t.Run("allowed with opt-in", func(t *testing.T) {
		t.Parallel()
		pidfile := filepath.Join(t.TempDir(), "pid")
		s := sdkBenign(t, "-pidfile", pidfile)
		s.Untrusted = true

		got, err := sdkNew(t, inspect.Options{AllowUntrusted: true}).Inspect(sdkCtx(t, sdkTimeout), s)
		if err != nil {
			t.Fatalf("Inspect() error = %v, want nil with AllowUntrusted", err)
		}
		sdkAssertResult(t, got, inspecttest.BenignResult())
		sdkReadPID(t, pidfile)
	})
}

// TestSDKInspectRemote checks that a remote server returns
// ErrUnsupportedTransport and that the error does not hold the URL or the
// header values.
func TestSDKInspectRemote(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport discover.Transport
	}{
		{name: "http", transport: discover.TransportHTTP},
		{name: "sse", transport: discover.TransportSSE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := discover.Server{
				Name:      "remote",
				Transport: tt.transport,
				URL:       discover.NewURL("https://user:" + discovertest.CanaryURL + "@example.invalid/mcp?key=" + discovertest.CanaryURL),
				Headers:   sdkSecretEnv(map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader}),
			}

			res, err := sdkNew(t, inspect.Options{AllowUntrusted: true}).Inspect(sdkCtx(t, sdkTimeout), s)

			sdkAssertFailed(t, res, err, inspect.ErrUnsupportedTransport)
			sdkAssertNoLeak(t, err, "example.invalid")
		})
	}
}

// TestSDKInspectCrash checks a server that exits before the handshake.
func TestSDKInspectCrash(t *testing.T) {
	t.Parallel()

	// The fixture exits with code 2 on an unknown flag, so the canary goes
	// in Env, which the fixture ignores, and not in Args.
	s := sdkBenign(t, "-mode", "crash")
	s.Env = sdkSecretEnv(map[string]string{"MCPMOAT_TEST_TOKEN": discovertest.CanaryEnv})

	res, err := sdkNew(t, inspect.Options{}).Inspect(sdkCtx(t, sdkTimeout), s)

	sdkAssertFailed(t, res, err, inspect.ErrProtocol, inspect.ErrStart)
	t.Logf("crash mode: error wraps %q; error: %v", sdkWrapped(err, inspect.ErrProtocol, inspect.ErrStart), err)
	sdkAssertNoLeak(t, err)
}

// TestSDKInspectStartError checks commands that cannot start. The error
// must wrap ErrStart and must not hold the args or the env values.
func TestSDKInspectStartError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
	}{
		{name: "absolute path that does not exist", command: "/nonexistent/mcpmoat-test"},
		{name: "bare name not in PATH", command: "mcpmoat-no-such-command-sdk-9Xc"},
		{name: "directory, not a program", command: os.TempDir()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := discover.Server{
				Name:      "missing",
				Transport: discover.TransportStdio,
				Command:   tt.command,
				Args:      discover.NewArgs([]string{"--token=" + discovertest.CanaryArgs, discovertest.CanaryArgs}),
				Env:       sdkSecretEnv(map[string]string{"MCPMOAT_TEST_TOKEN": discovertest.CanaryEnv}),
			}

			res, err := sdkNew(t, inspect.Options{}).Inspect(sdkCtx(t, sdkTimeout), s)

			sdkAssertFailed(t, res, err, inspect.ErrStart)
			sdkAssertNoLeak(t, err)
		})
	}
}

// TestSDKInspectInvalidServer checks configs that inspect refuses before it
// starts anything. The error must wrap ErrInvalidServer and must not hold the
// command, the args, the env keys or the env values.
func TestSDKInspectInvalidServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		dir     string
		env     map[string]string
	}{
		{name: "empty command", command: ""},
		{name: "relative command without dir", command: "./" + sdkCommandMarker},
		{name: "relative command in subdir without dir", command: "bin/" + sdkCommandMarker},
		{name: "relative command with relative dir", command: "./" + sdkCommandMarker, dir: "rel"},
		{name: "NUL byte in command", command: "/bin/" + sdkCommandMarker + "\x00x"},
		{name: "env key with equals sign", command: "/bin/true", env: map[string]string{sdkCommandMarker + "=X": discovertest.CanaryEnv}},
		{name: "empty env key", command: "/bin/true", env: map[string]string{"": discovertest.CanaryEnv}},
		{name: "NUL byte in env key", command: "/bin/true", env: map[string]string{sdkCommandMarker + "\x00": discovertest.CanaryEnv}},
		{name: "NUL byte in env value", command: "/bin/true", env: map[string]string{"MCPMOAT_TEST_TOKEN": discovertest.CanaryEnv + "\x00"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pidfile := filepath.Join(t.TempDir(), "pid")
			s := discover.Server{
				Name:      "invalid",
				Transport: discover.TransportStdio,
				Command:   tt.command,
				Dir:       tt.dir,
				Args:      discover.NewArgs([]string{"-pidfile", pidfile, "--token=" + discovertest.CanaryArgs}),
				Env:       sdkSecretEnv(tt.env),
			}

			res, err := sdkNew(t, inspect.Options{}).Inspect(sdkCtx(t, sdkTimeout), s)

			sdkAssertFailed(t, res, err, inspect.ErrInvalidServer)
			sdkAssertNoLeak(t, err, sdkCommandMarker, pidfile)
		})
	}
}

// TestSDKInspectZeroValue checks that a zero SDKInspector, not made with New,
// works and does not panic: it reads the parent environment with os.Environ.
// The env key is invalid, so Inspect returns before it starts anything. The
// server has an absolute Dir, so Inspect needs no run root and never writes
// to the cache directory of the user.
func TestSDKInspectZeroValue(t *testing.T) {
	t.Parallel()

	s := discover.Server{
		Name:      "zero",
		Transport: discover.TransportStdio,
		Command:   "/bin/true",
		Dir:       t.TempDir(),
		Env:       sdkSecretEnv(map[string]string{"A=B": discovertest.CanaryEnv}),
	}

	var zero inspect.SDKInspector
	res, err := zero.Inspect(sdkCtx(t, sdkTimeout), s)

	sdkAssertFailed(t, res, err, inspect.ErrInvalidServer)
}

// TestSDKInspectCanceledContext checks that Inspect starts nothing when ctx
// has already ended.
func TestSDKInspectCanceledContext(t *testing.T) {
	t.Parallel()

	pidfile := filepath.Join(t.TempDir(), "pid")
	s := sdkBenign(t, "-pidfile", pidfile)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	res, err := sdkNew(t, inspect.Options{}).Inspect(ctx, s)

	sdkAssertFailed(t, res, err, context.Canceled)
	sdkAssertNotExist(t, pidfile, "a canceled ctx must not start the server")
}

// TestSDKInspectDeadline checks that Inspect honours the deadline of ctx in
// the handshake and in a list request, and that it returns soon after the
// deadline.
func TestSDKInspectDeadline(t *testing.T) {
	t.Parallel()

	const deadline = time.Second
	// The process gets SIGKILL when ctx ends, so a stop is fast. The
	// worst case of a stop is 3*inspect.StopGrace; one more second is slack
	// for a loaded CI machine.
	const bound = deadline + 3*inspect.StopGrace + time.Second

	tests := []struct {
		name string
		mode string
	}{
		{name: "server never answers the handshake", mode: "hang-init"},
		{name: "server blocks tools/list", mode: "hang-list"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := sdkBenign(t, "-mode", tt.mode)
			s.Env = sdkSecretEnv(map[string]string{"MCPMOAT_TEST_TOKEN": discovertest.CanaryEnv})
			inspector := sdkNew(t, inspect.Options{})
			ctx := sdkCtx(t, deadline)

			start := time.Now()
			res, err := inspector.Inspect(ctx, s)
			elapsed := time.Since(start)

			t.Logf("mode %s: Inspect returned after %v", tt.mode, elapsed)
			sdkAssertFailed(t, res, err, context.DeadlineExceeded)
			if elapsed > bound {
				t.Errorf("Inspect() returned after %v, want at most %v", elapsed, bound)
			}
			sdkAssertNoLeak(t, err)
		})
	}
}

// TestSDKInspectArgsReachChild checks that each arg reaches the child as one
// exact argument, with no shell. The pidfile and envfile paths hold spaces
// and shell syntax: a shell would split them or run "$(x)" and "`id`".
func TestSDKInspectArgsReachChild(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	weird := filepath.Join(root, "with space", "$(x);`id`|&*")
	if err := os.MkdirAll(weird, 0o700); err != nil {
		t.Fatal(err)
	}
	pidfile := filepath.Join(weird, "pid file $HOME")
	envfile := filepath.Join(weird, "env 'file'")
	s := sdkBenign(t, "-pidfile", pidfile, "-envfile", envfile)

	got, err := sdkNew(t, inspect.Options{}).Inspect(sdkCtx(t, sdkTimeout), s)
	if err != nil {
		t.Fatalf("Inspect() error = %v, want nil", err)
	}
	sdkAssertResult(t, got, inspecttest.BenignResult())
	sdkReadPID(t, pidfile)
	if _, err := os.Stat(envfile); err != nil {
		t.Errorf("envfile at the exact path: %v", err)
	}

	// Nothing else must appear: no file from a split path and no output of
	// a command substitution.
	entries, err := os.ReadDir(weird)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	if want := []string{"env 'file'", "pid file $HOME"}; !slices.Equal(names, want) {
		t.Errorf("files in the arg directory = %q, want %q", names, want)
	}
	rootEntries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rootEntries) != 1 || rootEntries[0].Name() != "with space" {
		t.Errorf("entries in the test directory = %v, want only %q", rootEntries, "with space")
	}
}

// sdkReadEnvFile reads the envfile of the fixture and returns its entries
// as a map from key to value.
func sdkReadEnvFile(t *testing.T, path string) (vars map[string]string, raw string) {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: test reads the envfile path that it chose under t.TempDir()
	if err != nil {
		t.Fatalf("read envfile: %v", err)
	}
	vars = map[string]string{}
	for line := range strings.SplitSeq(string(b), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("envfile line %q has no '='", line)
		}
		vars[key] = value
	}
	return vars, string(b)
}

// TestSDKInspectScrubbedEnv checks that Inspect gives the child only the
// allowlisted parent variables and the configured env (NFR-04), and never
// other variables of the parent. The parent environment is injected, so the
// result is exact and the test can run in parallel.
func TestSDKInspectScrubbedEnv(t *testing.T) {
	t.Parallel()

	parent := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/mcpmoat-test",
		"AWS_SECRET_ACCESS_KEY=" + sdkParentCanary,
		"MCPMOAT_PARENT_ONLY=" + sdkParentCanary,
	}

	tests := []struct {
		name string
		env  map[string]string
		want map[string]string
	}{
		{
			name: "configured key is added",
			env:  map[string]string{"MCPMOAT_TEST_TOKEN": discovertest.CanaryEnv},
			want: map[string]string{"HOME": "/home/mcpmoat-test", "PATH": "/usr/bin:/bin", "MCPMOAT_TEST_TOKEN": discovertest.CanaryEnv},
		},
		{
			name: "configured PATH replaces the parent PATH",
			env:  map[string]string{"PATH": "/mcpmoat/config/bin"},
			want: map[string]string{"HOME": "/home/mcpmoat-test", "PATH": "/mcpmoat/config/bin"},
		},
		{
			name: "configured key with a parent name gets the configured value",
			env:  map[string]string{"AWS_SECRET_ACCESS_KEY": discovertest.CanaryEnv},
			want: map[string]string{"HOME": "/home/mcpmoat-test", "PATH": "/usr/bin:/bin", "AWS_SECRET_ACCESS_KEY": discovertest.CanaryEnv},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			envfile := filepath.Join(t.TempDir(), "env")
			s := sdkBenign(t, "-envfile", envfile)
			s.Env = sdkSecretEnv(tt.env)

			inspector := inspect.NewForTest(inspect.Options{}, filepath.Join(t.TempDir(), "run"), parent)
			got, err := inspector.Inspect(sdkCtx(t, sdkTimeout), s)
			if err != nil {
				t.Fatalf("Inspect() error = %v, want nil", err)
			}
			sdkAssertResult(t, got, inspecttest.BenignResult())

			vars, raw := sdkReadEnvFile(t, envfile)
			if !reflect.DeepEqual(vars, tt.want) {
				// Print keys only: the values hold canaries.
				t.Errorf("child env keys = %q, want %q", slices.Sorted(maps.Keys(vars)), slices.Sorted(maps.Keys(tt.want)))
				for k, v := range tt.want {
					if vars[k] != v {
						t.Errorf("child env %s has the wrong value", k)
					}
				}
			}
			if strings.Contains(raw, sdkParentCanary) {
				t.Errorf("child env holds a parent-only value")
			}
		})
	}
}

// sdkServerDirs returns the paths of the "mcpmoat-server-*" directories
// in dir.
func sdkServerDirs(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "mcpmoat-server-*"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

// TestSDKInspectRemovesWorkDir checks that Inspect removes the temporary
// working directory of the server, on success and on each error path.
//
// The test gives Inspect its own run root, so it sees only the directories
// that Inspect makes in this test.
func TestSDKInspectRemovesWorkDir(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "run")
	inspector := inspect.NewForTest(inspect.Options{}, root, nil)
	stdio := func(args ...string) discover.Server { return sdkBenign(t, args...) }

	tests := []struct {
		name    string
		server  discover.Server
		timeout time.Duration
		wantErr bool
	}{
		{name: "success", server: stdio(), timeout: sdkTimeout},
		// A relative pidfile lands in the working directory, so the
		// directory is not empty when Inspect removes it.
		{name: "success with a file in the working directory", server: stdio("-pidfile", "pid"), timeout: sdkTimeout},
		{name: "crash", server: stdio("-mode", "crash"), timeout: sdkTimeout, wantErr: true},
		{name: "handshake deadline", server: stdio("-mode", "hang-init"), timeout: time.Second, wantErr: true},
		{name: "list deadline", server: stdio("-mode", "hang-list"), timeout: time.Second, wantErr: true},
		{
			name: "start error",
			server: discover.Server{
				Name:      "missing",
				Transport: discover.TransportStdio,
				Command:   "/nonexistent/mcpmoat-test",
			},
			timeout: sdkTimeout,
			wantErr: true,
		},
	}
	// The cases share root, so they run one after the other.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if before := sdkServerDirs(t, root); len(before) != 0 {
				t.Fatalf("server dirs before Inspect = %q, want none", before)
			}

			_, err := inspector.Inspect(sdkCtx(t, tt.timeout), tt.server)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Inspect() error = %v, want error: %v", err, tt.wantErr)
			}

			if after := sdkServerDirs(t, root); len(after) != 0 {
				t.Errorf("server dirs after Inspect = %q, want none", after)
			}
		})
	}

	// Proof that the test above is not empty: when the run root cannot be
	// made, Inspect cannot make the working directory, and the server does
	// not start. So the directories above were really made in root.
	t.Run("run root is used", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		pidfile := filepath.Join(t.TempDir(), "pid")
		s := stdio("-pidfile", pidfile)

		res, err := inspect.NewForTest(inspect.Options{}, filepath.Join(file, "run"), nil).Inspect(sdkCtx(t, sdkTimeout), s)
		sdkAssertFailed(t, res, err, inspect.ErrStart)
		sdkAssertNotExist(t, pidfile, "the server must not start without a working directory")
		sdkAssertNoLeak(t, err, pidfile)
	})
}

// TestSDKInspectConcurrent checks that one SDKInspector serves several
// goroutines at once. Run it with -race.
func TestSDKInspectConcurrent(t *testing.T) {
	t.Parallel()

	const workers = 4
	s := sdkBenign(t)
	inspector := sdkNew(t, inspect.Options{})
	ctx := sdkCtx(t, sdkTimeout)

	var (
		wg      sync.WaitGroup
		results [workers]inspect.Result
		errs    [workers]error
	)
	for i := range workers {
		wg.Go(func() {
			results[i], errs[i] = inspector.Inspect(ctx, s)
		})
	}
	wg.Wait()

	want := inspecttest.BenignResult()
	for i := range workers {
		if errs[i] != nil {
			t.Errorf("worker %d: Inspect() error = %v, want nil", i, errs[i])
			continue
		}
		sdkAssertResult(t, results[i], want)
	}
}
