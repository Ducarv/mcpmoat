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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
// a non-nil *inspect.ConnectError, a zero Result, and a Kind that is one of
// kinds. It returns the kind and the reason of the error.
func sdkAssertFailed(t *testing.T, res inspect.Result, err error, kinds ...inspect.ConnectKind) (inspect.ConnectKind, string) {
	t.Helper()
	if err == nil {
		t.Fatalf("Inspect() error = nil, want a ConnectError of kind %v", kinds)
	}
	if !reflect.DeepEqual(res, inspect.Result{}) {
		t.Errorf("Inspect() Result = %s, want the zero Result with an error", sdkJSON(res))
	}
	var ce *inspect.ConnectError
	if !errors.As(err, &ce) {
		t.Fatalf("Inspect() error = %v (%T), want a *inspect.ConnectError", err, err)
	}
	if !slices.Contains(kinds, ce.Kind) {
		t.Errorf("Inspect() error kind = %q (%v), want one of %v", ce.Kind, err, kinds)
	}
	return ce.Kind, ce.Reason
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

	got, err := sdkNew(t, inspect.SDKOptions{}).Inspect(sdkCtx(t, sdkTimeout), sdkBenign(t))
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

		res, err := sdkNew(t, inspect.SDKOptions{}).Inspect(sdkCtx(t, sdkTimeout), s)

		sdkAssertFailed(t, res, err, inspect.KindConfig)
		sdkAssertNotExist(t, pidfile, "the untrusted server must not start")
		sdkAssertNoLeak(t, err, pidfile)
	})

	t.Run("allowed with opt-in", func(t *testing.T) {
		t.Parallel()
		pidfile := filepath.Join(t.TempDir(), "pid")
		s := sdkBenign(t, "-pidfile", pidfile)
		s.Untrusted = true

		got, err := sdkNew(t, inspect.SDKOptions{AllowUntrusted: true}).Inspect(sdkCtx(t, sdkTimeout), s)
		if err != nil {
			t.Fatalf("Inspect() error = %v, want nil with AllowUntrusted", err)
		}
		sdkAssertResult(t, got, inspecttest.BenignResult())
		sdkReadPID(t, pidfile)
	})
}

// TestSDKInspectRemote checks that a remote server goes to Remote. The URL
// has an ftp scheme, which Remote refuses before any network access, so the
// test makes no network call. The error must not hold the URL secrets or the
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
				URL:       discover.NewURL("ftp://user:" + discovertest.CanaryURL + "@example.invalid/mcp?key=" + discovertest.CanaryURL),
				Headers:   sdkSecretEnv(map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader}),
			}

			res, err := sdkNew(t, inspect.SDKOptions{AllowUntrusted: true}).Inspect(sdkCtx(t, sdkTimeout), s)

			_, reason := sdkAssertFailed(t, res, err, inspect.KindConfig)
			if !strings.Contains(reason, "unsupported URL scheme") {
				t.Errorf("Inspect() reason = %q, want the URL scheme error of Remote", reason)
			}
			sdkAssertNoLeak(t, err)
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

	res, err := sdkNew(t, inspect.SDKOptions{}).Inspect(sdkCtx(t, sdkTimeout), s)

	kind, _ := sdkAssertFailed(t, res, err, inspect.KindProtocol, inspect.KindStart)
	t.Logf("crash mode: kind %q; error: %v", kind, err)
	sdkAssertNoLeak(t, err)
}

// TestSDKInspectStartError checks commands that cannot start. The error
// must be of KindStart and must not hold the args or the env values.
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

			res, err := sdkNew(t, inspect.SDKOptions{}).Inspect(sdkCtx(t, sdkTimeout), s)

			sdkAssertFailed(t, res, err, inspect.KindStart)
			sdkAssertNoLeak(t, err)
		})
	}
}

// TestSDKInspectInvalidServer checks configs that inspect refuses before it
// starts anything. The error must be of KindConfig and must not hold the
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

			res, err := sdkNew(t, inspect.SDKOptions{}).Inspect(sdkCtx(t, sdkTimeout), s)

			sdkAssertFailed(t, res, err, inspect.KindConfig)
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

	sdkAssertFailed(t, res, err, inspect.KindConfig)
}

// TestSDKInspectCanceledContext checks that Inspect starts nothing when ctx
// has already ended.
func TestSDKInspectCanceledContext(t *testing.T) {
	t.Parallel()

	pidfile := filepath.Join(t.TempDir(), "pid")
	s := sdkBenign(t, "-pidfile", pidfile)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	res, err := sdkNew(t, inspect.SDKOptions{}).Inspect(ctx, s)

	sdkAssertFailed(t, res, err, inspect.KindTimeout)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Inspect() error = %v, want errors.Is context.Canceled", err)
	}
	sdkAssertNotExist(t, pidfile, "a canceled ctx must not start the server")
}

// TestSDKInspectDeadline checks that Inspect honours the deadline of ctx in
// the handshake and in a list request, and that it returns soon after the
// deadline.
func TestSDKInspectDeadline(t *testing.T) {
	t.Parallel()

	const deadline = time.Second
	// The process group gets SIGKILL when ctx ends, so a stop is fast. A
	// normal stop takes at most one inspect.StopGrace; the bound allows
	// three, plus one second of slack for a loaded CI machine.
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
			inspector := sdkNew(t, inspect.SDKOptions{})
			ctx := sdkCtx(t, deadline)

			start := time.Now()
			res, err := inspector.Inspect(ctx, s)
			elapsed := time.Since(start)

			t.Logf("mode %s: Inspect returned after %v", tt.mode, elapsed)
			sdkAssertFailed(t, res, err, inspect.KindTimeout)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("Inspect() error = %v, want errors.Is context.DeadlineExceeded", err)
			}
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

	got, err := sdkNew(t, inspect.SDKOptions{}).Inspect(sdkCtx(t, sdkTimeout), s)
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
// allowlisted parent variables, the configured env and npm_config_yes=false
// (NFR-04, issue #104), and never other variables of the parent. A parent
// npm_config_yes does not reach the child, and a configured one wins over
// the forced entry. The parent environment is injected, so the result is
// exact and the test can run in parallel.
func TestSDKInspectScrubbedEnv(t *testing.T) {
	t.Parallel()

	parent := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/mcpmoat-test",
		"AWS_SECRET_ACCESS_KEY=" + sdkParentCanary,
		"MCPMOAT_PARENT_ONLY=" + sdkParentCanary,
		"npm_config_yes=true",
	}

	tests := []struct {
		name string
		env  map[string]string
		want map[string]string
	}{
		{
			name: "configured key is added",
			env:  map[string]string{"MCPMOAT_TEST_TOKEN": discovertest.CanaryEnv},
			want: map[string]string{"HOME": "/home/mcpmoat-test", "PATH": "/usr/bin:/bin", "MCPMOAT_TEST_TOKEN": discovertest.CanaryEnv, "npm_config_yes": "false"},
		},
		{
			name: "configured PATH replaces the parent PATH",
			env:  map[string]string{"PATH": "/mcpmoat/config/bin"},
			want: map[string]string{"HOME": "/home/mcpmoat-test", "PATH": "/mcpmoat/config/bin", "npm_config_yes": "false"},
		},
		{
			name: "configured key with a parent name gets the configured value",
			env:  map[string]string{"AWS_SECRET_ACCESS_KEY": discovertest.CanaryEnv},
			want: map[string]string{"HOME": "/home/mcpmoat-test", "PATH": "/usr/bin:/bin", "AWS_SECRET_ACCESS_KEY": discovertest.CanaryEnv, "npm_config_yes": "false"},
		},
		{
			name: "configured npm_config_yes wins over the forced entry",
			env:  map[string]string{"npm_config_yes": "true"},
			want: map[string]string{"HOME": "/home/mcpmoat-test", "PATH": "/usr/bin:/bin", "npm_config_yes": "true"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			envfile := filepath.Join(t.TempDir(), "env")
			s := sdkBenign(t, "-envfile", envfile)
			s.Env = sdkSecretEnv(tt.env)

			inspector := inspect.NewForTest(inspect.SDKOptions{}, filepath.Join(t.TempDir(), "run"), parent, 0)
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
	inspector := inspect.NewForTest(inspect.SDKOptions{}, root, nil, 0)
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
		s := sdkBenign(t, "-pidfile", pidfile)

		res, err := inspect.NewForTest(inspect.SDKOptions{}, filepath.Join(file, "run"), nil, 0).Inspect(sdkCtx(t, sdkTimeout), s)
		sdkAssertFailed(t, res, err, inspect.KindStart)
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
	inspector := sdkNew(t, inspect.SDKOptions{})
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

// sdkCountingServer starts an HTTP server that counts the requests it gets
// and answers each one with 404. It returns the server URL and the counter.
// A test that expects no request checks that the counter stays at zero.
func sdkCountingServer(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		http.NotFound(w, nil)
	}))
	t.Cleanup(ts.Close)
	return ts.URL + "/mcp", &n
}

// The fixed parts of the reasons of the state and untrusted gates. The tests
// check them to see which gate refused the server.
const (
	sdkReasonDisabled        = "turned off in the client config"
	sdkReasonUnapproved      = "not approved in the client config"
	sdkReasonProjectApproved = "approved only by files from the repository"
	sdkReasonUntrusted       = "untrusted project server"
)

// TestSDKInspectStateGate checks that Inspect never starts a stdio server
// whose State is not discover.StateEnabled without AllowDisabled (issue
// #87), and that the state gate comes before the untrusted gate. A refused
// server gets KindConfig with a fixed reason, and the marker file that the
// server would write at start does not exist.
//
// StateProjectApproved is a server of a .mcp.json file that only files from
// the repository approve. Such a server is also untrusted in practice, so it
// starts only with both opt-ins.
func TestSDKInspectStateGate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		state      discover.State
		untrusted  bool
		opts       inspect.SDKOptions
		wantReason string // "" means that the server starts
	}{
		{name: "disabled is refused", state: discover.StateDisabled, wantReason: sdkReasonDisabled},
		{name: "unapproved is refused", state: discover.StateUnapproved, wantReason: sdkReasonUnapproved},
		{name: "project-approved is refused", state: discover.StateProjectApproved, wantReason: sdkReasonProjectApproved},
		{
			name:       "untrusted project-approved is refused by the state gate",
			state:      discover.StateProjectApproved,
			untrusted:  true,
			wantReason: sdkReasonProjectApproved,
		},
		{
			name:       "untrusted project-approved with only AllowUntrusted is refused",
			state:      discover.StateProjectApproved,
			untrusted:  true,
			opts:       inspect.SDKOptions{AllowUntrusted: true},
			wantReason: sdkReasonProjectApproved,
		},
		{
			name:       "untrusted project-approved with only AllowDisabled is refused",
			state:      discover.StateProjectApproved,
			untrusted:  true,
			opts:       inspect.SDKOptions{AllowDisabled: true},
			wantReason: sdkReasonUntrusted,
		},
		{name: "unknown state is refused", state: discover.State(9), wantReason: sdkReasonDisabled},
		{
			name:       "disabled with only AllowUntrusted is refused",
			state:      discover.StateDisabled,
			opts:       inspect.SDKOptions{AllowUntrusted: true},
			wantReason: sdkReasonDisabled,
		},
		{
			name:       "state gate comes before the untrusted gate",
			state:      discover.StateUnapproved,
			untrusted:  true,
			wantReason: sdkReasonUnapproved,
		},
		{
			name:       "untrusted disabled with only AllowDisabled is refused by the untrusted gate",
			state:      discover.StateDisabled,
			untrusted:  true,
			opts:       inspect.SDKOptions{AllowDisabled: true},
			wantReason: sdkReasonUntrusted,
		},
		{name: "enabled starts", state: discover.StateEnabled},
		{name: "disabled starts with AllowDisabled", state: discover.StateDisabled, opts: inspect.SDKOptions{AllowDisabled: true}},
		{name: "unapproved starts with AllowDisabled", state: discover.StateUnapproved, opts: inspect.SDKOptions{AllowDisabled: true}},
		{name: "project-approved starts with AllowDisabled", state: discover.StateProjectApproved, opts: inspect.SDKOptions{AllowDisabled: true}},
		{
			name:      "untrusted project-approved starts with both opt-ins",
			state:     discover.StateProjectApproved,
			untrusted: true,
			opts:      inspect.SDKOptions{AllowDisabled: true, AllowUntrusted: true},
		},
		{
			name:      "untrusted unapproved starts with both opt-ins",
			state:     discover.StateUnapproved,
			untrusted: true,
			opts:      inspect.SDKOptions{AllowDisabled: true, AllowUntrusted: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pidfile := filepath.Join(t.TempDir(), "pid")
			s := sdkBenign(t, "-pidfile", pidfile)
			s.State = tt.state
			s.Untrusted = tt.untrusted
			s.Env = sdkSecretEnv(map[string]string{"MCPMOAT_TEST_TOKEN": discovertest.CanaryEnv})

			res, err := sdkNew(t, tt.opts).Inspect(sdkCtx(t, sdkTimeout), s)

			if tt.wantReason == "" {
				if err != nil {
					t.Fatalf("Inspect() error = %v, want nil", err)
				}
				sdkAssertResult(t, res, inspecttest.BenignResult())
				sdkReadPID(t, pidfile)
				return
			}
			_, reason := sdkAssertFailed(t, res, err, inspect.KindConfig)
			if !strings.Contains(reason, tt.wantReason) {
				t.Errorf("Inspect() reason = %q, want it to contain %q", reason, tt.wantReason)
			}
			sdkAssertNotExist(t, pidfile, "a refused server must not start")
			sdkAssertNoLeak(t, err, pidfile)
		})
	}
}

// TestSDKInspectStateGateRemote checks that Inspect sends no request to a
// remote server whose State is not discover.StateEnabled without
// AllowDisabled (issue #87). The case with the opt-in proves that the
// counter sees the requests.
func TestSDKInspectStateGateRemote(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		state     discover.State
		untrusted bool
		allow     bool
		trust     bool // AllowUntrusted
		transport discover.Transport
		wantSent  bool
	}{
		{name: "disabled http", state: discover.StateDisabled, transport: discover.TransportHTTP},
		{name: "unapproved http", state: discover.StateUnapproved, transport: discover.TransportHTTP},
		{name: "disabled sse", state: discover.StateDisabled, transport: discover.TransportSSE},
		{name: "unapproved sse", state: discover.StateUnapproved, transport: discover.TransportSSE},
		{name: "project-approved http", state: discover.StateProjectApproved, transport: discover.TransportHTTP},
		{name: "project-approved sse", state: discover.StateProjectApproved, transport: discover.TransportSSE},
		{name: "untrusted project-approved http", state: discover.StateProjectApproved, untrusted: true, transport: discover.TransportHTTP},
		{name: "untrusted project-approved http with AllowUntrusted only", state: discover.StateProjectApproved, untrusted: true, trust: true, transport: discover.TransportHTTP},
		{name: "untrusted project-approved http with AllowDisabled only", state: discover.StateProjectApproved, untrusted: true, allow: true, transport: discover.TransportHTTP},
		{name: "disabled http with AllowDisabled", state: discover.StateDisabled, allow: true, transport: discover.TransportHTTP, wantSent: true},
		{name: "project-approved http with AllowDisabled", state: discover.StateProjectApproved, allow: true, transport: discover.TransportHTTP, wantSent: true},
		{
			name: "untrusted project-approved sse with both opt-ins", state: discover.StateProjectApproved,
			untrusted: true, allow: true, trust: true, transport: discover.TransportSSE, wantSent: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			endpoint, count := sdkCountingServer(t)
			s := discover.Server{
				Name:      "remote",
				Client:    discover.ClientClaudeCode,
				Transport: tt.transport,
				URL:       discover.NewURL(endpoint),
				Headers:   sdkSecretEnv(map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader}),
				State:     tt.state,
				Untrusted: tt.untrusted,
			}

			opts := inspect.SDKOptions{AllowDisabled: tt.allow, AllowUntrusted: tt.trust}
			res, err := sdkNew(t, opts).Inspect(sdkCtx(t, sdkTimeout), s)

			if tt.wantSent {
				// The server answers 404, so the inspection fails, but
				// only after requests went out.
				sdkAssertFailed(t, res, err, inspect.KindHTTP, inspect.KindProtocol)
				if count.Load() == 0 {
					t.Error("the server got no request, want requests with AllowDisabled")
				}
				return
			}
			sdkAssertFailed(t, res, err, inspect.KindConfig)
			if n := count.Load(); n != 0 {
				t.Errorf("the server got %d requests, want none for a refused server", n)
			}
			sdkAssertNoLeak(t, err)
		})
	}
}

// sdkExpandSecret is the value of a variable that a config placeholder
// names. It stands for a secret in the user's environment.
const sdkExpandSecret = "mcpmoat-expand-canary-4Hd8Qz" //nolint:gosec // G101: fake test credential

// sdkExpandParent returns the injected parent environment of the expansion
// tests. MCPMOAT_TEST_DIR names dir.
func sdkExpandParent(t *testing.T, dir string) []string {
	t.Helper()
	return []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/mcpmoat-test",
		"MCPMOAT_TEST_DIR=" + dir,
		"MCPMOAT_TEST_VALUE=" + sdkExpandSecret,
		"MCPMOAT_TEST_FIXTURE=" + inspecttest.Fixture(t, "benign"),
	}
}

// TestSDKInspectExpand checks that Inspect expands the ${VAR} placeholders
// with the syntax of the client that declared the server, with the
// variables of the injected parent environment (issue #88), and that the
// expanded values reach the child: in the command, in the args (the envfile
// path) and in the env values. The parent variables that a placeholder
// names do not reach the child by themselves: only the expanded values do.
func TestSDKInspectExpand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		client  discover.Client
		project bool // a trusted project server whose ProjectPath is the test dir
		// state is the State of the server. A state other than
		// StateEnabled runs with AllowDisabled.
		state   discover.State
		command string
		envfile string // the envfile arg; ${MCPMOAT_TEST_DIR} etc. are placeholders
		env     map[string]string
		want    func(dir string) map[string]string
	}{
		{
			name:    "claude code",
			client:  discover.ClientClaudeCode,
			command: "${MCPMOAT_TEST_FIXTURE}",
			envfile: "${MCPMOAT_TEST_DIR}/env",
			env: map[string]string{
				"MCPMOAT_TEST_EXPANDED": "${MCPMOAT_TEST_VALUE}",
				"MCPMOAT_TEST_DEFAULT":  "${MCPMOAT_TEST_UNSET:-fallback-value}",
				"MCPMOAT_TEST_MIXED":    "a-${MCPMOAT_TEST_VALUE}-b",
			},
			want: func(string) map[string]string {
				return map[string]string{
					"HOME":                  "/home/mcpmoat-test",
					"PATH":                  "/usr/bin:/bin",
					"MCPMOAT_TEST_EXPANDED": sdkExpandSecret,
					"MCPMOAT_TEST_DEFAULT":  "fallback-value",
					"MCPMOAT_TEST_MIXED":    "a-" + sdkExpandSecret + "-b",
					"npm_config_yes":        "false",
				}
			},
		},
		{
			name:    "cursor global",
			client:  discover.ClientCursor,
			command: "${env:MCPMOAT_TEST_FIXTURE}",
			envfile: "${env:MCPMOAT_TEST_DIR}${/}env",
			env: map[string]string{
				"MCPMOAT_TEST_EXPANDED": "${env:MCPMOAT_TEST_VALUE}",
				"MCPMOAT_TEST_HOME":     "${userHome}",
			},
			want: func(string) map[string]string {
				return map[string]string{
					"HOME":                  "/home/mcpmoat-test",
					"PATH":                  "/usr/bin:/bin",
					"MCPMOAT_TEST_EXPANDED": sdkExpandSecret,
					"MCPMOAT_TEST_HOME":     "/home/mcpmoat-test",
					"npm_config_yes":        "false",
				}
			},
		},
		{
			name:    "cursor project",
			client:  discover.ClientCursor,
			project: true,
			command: "${env:MCPMOAT_TEST_FIXTURE}",
			envfile: "${workspaceFolder}/env",
			env:     map[string]string{"MCPMOAT_TEST_BASE": "${workspaceFolderBasename}"},
			want: func(dir string) map[string]string {
				return map[string]string{
					"HOME":              "/home/mcpmoat-test",
					"PATH":              "/usr/bin:/bin",
					"MCPMOAT_TEST_BASE": filepath.Base(dir),
					"npm_config_yes":    "false",
				}
			},
		},
		{
			// A server that is not enabled reads only the base variables:
			// HOME is found, MCPMOAT_TEST_VALUE is not, so its default
			// applies.
			name:    "claude code not enabled reads only base variables",
			client:  discover.ClientClaudeCode,
			state:   discover.StateUnapproved,
			command: "", // the fixture path, set below
			envfile: "", // dir/env, set below
			env: map[string]string{
				"MCPMOAT_TEST_DEFAULT": "${MCPMOAT_TEST_VALUE:-fallback-value}",
				"MCPMOAT_TEST_HOME":    "${HOME}",
			},
			want: func(string) map[string]string {
				return map[string]string{
					"HOME":                 "/home/mcpmoat-test",
					"PATH":                 "/usr/bin:/bin",
					"MCPMOAT_TEST_DEFAULT": "fallback-value",
					"MCPMOAT_TEST_HOME":    "/home/mcpmoat-test",
					"npm_config_yes":       "false",
				}
			},
		},
		{
			// Codex does not expand, so the placeholder reaches the child
			// as written.
			name:    "codex is not expanded",
			client:  discover.ClientCodex,
			command: "", // the fixture path, set below
			envfile: "", // dir/env, set below
			env:     map[string]string{"MCPMOAT_TEST_EXPANDED": "${MCPMOAT_TEST_VALUE}"},
			want: func(string) map[string]string {
				return map[string]string{
					"HOME":                  "/home/mcpmoat-test",
					"PATH":                  "/usr/bin:/bin",
					"MCPMOAT_TEST_EXPANDED": "${MCPMOAT_TEST_VALUE}",
					"npm_config_yes":        "false",
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			command, envfile := tt.command, tt.envfile
			if command == "" {
				command = inspecttest.Fixture(t, "benign")
			}
			if envfile == "" {
				envfile = filepath.Join(dir, "env")
			}
			s := discover.Server{
				Name:      "expand",
				Client:    tt.client,
				Scope:     discover.ScopeGlobal,
				Transport: discover.TransportStdio,
				Command:   command,
				Args:      discover.NewArgs([]string{"-envfile", envfile}),
				Env:       sdkSecretEnv(tt.env),
			}
			if tt.project {
				s.Scope = discover.ScopeProject
				s.ProjectPath = dir
			}
			s.State = tt.state

			opts := inspect.SDKOptions{AllowDisabled: tt.state != discover.StateEnabled}
			inspector := inspect.NewForTest(opts, filepath.Join(t.TempDir(), "run"), sdkExpandParent(t, dir), 0)
			got, err := inspector.Inspect(sdkCtx(t, sdkTimeout), s)
			if err != nil {
				t.Fatalf("Inspect() error = %v, want nil", err)
			}
			sdkAssertResult(t, got, inspecttest.BenignResult())

			vars, _ := sdkReadEnvFile(t, filepath.Join(dir, "env"))
			want := tt.want(dir)
			if !reflect.DeepEqual(vars, want) {
				// Print keys only: the values hold the canary.
				t.Errorf("child env keys = %q, want %q", slices.Sorted(maps.Keys(vars)), slices.Sorted(maps.Keys(want)))
				for k, v := range want {
					if vars[k] != v {
						t.Errorf("child env %s has the wrong value", k)
					}
				}
			}
		})
	}
}

// TestSDKInspectExpandErrors checks the placeholders that Inspect cannot
// expand: a variable that is not set, and a Cursor workspace placeholder on
// a global server, a name that is not a plain variable name, and an
// expanded text over the size limit. Inspect fails with KindConfig, the
// error wraps the sentinel of package discover, the server does not start or
// gets no request, and the error text holds no variable value, also not the
// value of a placeholder that Expand already expanded in an earlier field.
func TestSDKInspectExpandErrors(t *testing.T) {
	t.Parallel()

	// tooLong is one arg whose expansion is over the 64 KiB limit of
	// discover.Expand for one text: 3000 times the 29-byte value is about
	// 85 KiB. The text itself is about 62 KiB.
	tooLong := strings.Repeat("${MCPMOAT_TEST_VALUE}", 3000)

	tests := []struct {
		name   string
		client discover.Client
		args   []string // "PIDFILE" is replaced by the pidfile path
		env    map[string]string
		url    string // a remote server when set; "URL" is replaced by the counting server
		// headers are the headers of a remote server. nil means one
		// X-Api-Key header with ${MCPMOAT_TEST_VALUE}.
		headers map[string]string
		// state is the State of the server. A state other than
		// StateEnabled runs with AllowDisabled.
		state    discover.State
		wantErr  error
		wantName string
		// wantSuffix, when set, is the end of the reason.
		wantSuffix string
		// wantReason, when set, is the exact reason. It is for the errors
		// that show no variable name.
		wantReason string
		// noLeak are more texts that the error must not hold.
		noLeak []string
	}{
		{
			name:     "claude code variable not set",
			client:   discover.ClientClaudeCode,
			args:     []string{"-pidfile", "PIDFILE", "--x=${MCPMOAT_TEST_VALUE}"},
			env:      map[string]string{"MCPMOAT_TEST_EXPANDED": "${MCPMOAT_TEST_MISSING}"},
			wantErr:  discover.ErrMissingVariable,
			wantName: "MCPMOAT_TEST_MISSING",
		},
		{
			name:     "cursor variable not set",
			client:   discover.ClientCursor,
			args:     []string{"-pidfile", "PIDFILE", "--x=${env:MCPMOAT_TEST_VALUE}"},
			env:      map[string]string{"MCPMOAT_TEST_EXPANDED": "${env:MCPMOAT_TEST_MISSING}"},
			wantErr:  discover.ErrMissingVariable,
			wantName: "MCPMOAT_TEST_MISSING",
		},
		{
			name:     "cursor workspaceFolder on a global server",
			client:   discover.ClientCursor,
			args:     []string{"-pidfile", "PIDFILE", "-envfile", "${workspaceFolder}/env"},
			env:      map[string]string{"MCPMOAT_TEST_EXPANDED": "${env:MCPMOAT_TEST_VALUE}"},
			wantErr:  discover.ErrNoWorkspaceFolder,
			wantName: "workspaceFolder",
		},
		{
			name:     "claude code remote URL variable not set",
			client:   discover.ClientClaudeCode,
			url:      "URL?k=${MCPMOAT_TEST_MISSING}",
			wantErr:  discover.ErrMissingVariable,
			wantName: "MCPMOAT_TEST_MISSING",
		},
		{
			// A secret that holds "${" by chance. The text inside ${...}
			// is not a plain variable name, so the error does not show it.
			name:       "secret env value with a placeholder form",
			client:     discover.ClientClaudeCode,
			args:       []string{"-pidfile", "PIDFILE"},
			env:        map[string]string{"MCPMOAT_TEST_TOKEN": "p4ss${w0rd-9f8e7d}"}, //nolint:gosec // G101: fake test credential
			wantErr:    discover.ErrMissingVariable,
			wantReason: "cannot expand env: variable with an invalid name: variable is not set",
			noLeak:     []string{"p4ss", "w0rd-9f8e7d", "9f8e7d"},
		},
		{
			name:   "secret remote header value with a placeholder form",
			client: discover.ClientClaudeCode,
			url:    "URL",
			headers: map[string]string{
				"Authorization": "Bearer p4ss${w0rd-9f8e7d}",
				"X-Api-Key":     "${MCPMOAT_TEST_VALUE}",
			},
			wantErr:    discover.ErrMissingVariable,
			wantReason: "cannot expand headers: variable with an invalid name: variable is not set",
			noLeak:     []string{"p4ss", "w0rd-9f8e7d", "9f8e7d"},
		},
		{
			name:       "claude code expanded arg too long",
			client:     discover.ClientClaudeCode,
			args:       []string{"-pidfile", "PIDFILE", tooLong},
			wantErr:    discover.ErrExpandedTooLong,
			wantReason: "cannot expand args: expanded text is too long",
		},
		{
			name:       "cursor expanded env value too long",
			client:     discover.ClientCursor,
			args:       []string{"-pidfile", "PIDFILE"},
			env:        map[string]string{"MCPMOAT_TEST_LONG": strings.ReplaceAll(tooLong, "${", "${env:")},
			wantErr:    discover.ErrExpandedTooLong,
			wantReason: "cannot expand env: expanded text is too long",
		},
		{
			// A server that is not enabled reads only the base variables
			// (issue #88 hardening): a variable that is set in the
			// environment of the user is not found, and the reason says
			// why.
			name:       "not enabled stdio reads only base variables",
			client:     discover.ClientClaudeCode,
			state:      discover.StateUnapproved,
			args:       []string{"-pidfile", "PIDFILE"},
			env:        map[string]string{"MCPMOAT_TEST_EXPANDED": "${MCPMOAT_TEST_VALUE}"},
			wantErr:    discover.ErrMissingVariable,
			wantName:   "MCPMOAT_TEST_VALUE",
			wantSuffix: "; a server that is not enabled reads only the base environment variables",
		},
		{
			name:       "project-approved cursor stdio reads only base variables",
			client:     discover.ClientCursor,
			state:      discover.StateProjectApproved,
			args:       []string{"-pidfile", "PIDFILE", "--x=${env:MCPMOAT_TEST_VALUE}"},
			wantErr:    discover.ErrMissingVariable,
			wantName:   "MCPMOAT_TEST_VALUE",
			wantSuffix: "; a server that is not enabled reads only the base environment variables",
		},
		{
			// A cloned repository cannot send a secret to its own URL.
			name:       "disabled remote URL reads only base variables",
			client:     discover.ClientClaudeCode,
			state:      discover.StateDisabled,
			url:        "URL?k=${MCPMOAT_TEST_VALUE}",
			headers:    map[string]string{"X-Api-Key": "${HOME}"},
			wantErr:    discover.ErrMissingVariable,
			wantName:   "MCPMOAT_TEST_VALUE",
			wantSuffix: "; a server that is not enabled reads only the base environment variables",
		},
		{
			name:       "claude code remote URL too long",
			client:     discover.ClientClaudeCode,
			url:        "URL?k=" + tooLong,
			wantErr:    discover.ErrExpandedTooLong,
			wantReason: "cannot expand url: expanded text is too long",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			pidfile := filepath.Join(dir, "pid")
			args := slices.Clone(tt.args)
			for i, a := range args {
				if a == "PIDFILE" {
					args[i] = pidfile
				}
			}
			s := discover.Server{
				Name:      "expand",
				Client:    tt.client,
				Scope:     discover.ScopeGlobal,
				Transport: discover.TransportStdio,
				Command:   inspecttest.Fixture(t, "benign"),
				Args:      discover.NewArgs(args),
				Env:       sdkSecretEnv(tt.env),
			}
			var count *atomic.Int32
			if tt.url != "" {
				var endpoint string
				endpoint, count = sdkCountingServer(t)
				s.Transport = discover.TransportHTTP
				s.Command = ""
				s.Args = discover.Args{}
				s.URL = discover.NewURL(strings.Replace(tt.url, "URL", endpoint, 1))
				headers := tt.headers
				if headers == nil {
					headers = map[string]string{"X-Api-Key": "${MCPMOAT_TEST_VALUE}"}
				}
				s.Headers = sdkSecretEnv(headers)
			}
			s.State = tt.state

			opts := inspect.SDKOptions{AllowDisabled: tt.state != discover.StateEnabled}
			inspector := inspect.NewForTest(opts, filepath.Join(t.TempDir(), "run"), sdkExpandParent(t, dir), 0)
			res, err := inspector.Inspect(sdkCtx(t, sdkTimeout), s)

			_, reason := sdkAssertFailed(t, res, err, inspect.KindConfig)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Inspect() error = %v, want errors.Is %v", err, tt.wantErr)
			}
			var ee *discover.ExpandError
			if !errors.As(err, &ee) {
				t.Errorf("Inspect() error = %v, want a *discover.ExpandError in the chain", err)
			}
			if tt.wantReason != "" {
				if reason != tt.wantReason {
					t.Errorf("Inspect() reason = %q, want %q", reason, tt.wantReason)
				}
				if ee != nil && ee.Name != "" {
					t.Errorf("ExpandError.Name = %q, want \"\"", ee.Name)
				}
			} else if !strings.Contains(reason, tt.wantName) {
				t.Errorf("Inspect() reason = %q, want it to name the variable %q", reason, tt.wantName)
			}
			if !strings.HasSuffix(reason, tt.wantSuffix) {
				t.Errorf("Inspect() reason = %q, want the suffix %q", reason, tt.wantSuffix)
			}
			if tt.wantSuffix == "" && strings.Contains(reason, "base environment") {
				t.Errorf("Inspect() reason = %q, want no base environment note for an enabled server", reason)
			}
			sdkAssertNotExist(t, pidfile, "a server whose config cannot be expanded must not start")
			if count != nil {
				if n := count.Load(); n != 0 {
					t.Errorf("the server got %d requests, want none", n)
				}
			}
			sdkAssertNoLeak(t, err, append([]string{sdkExpandSecret, dir}, tt.noLeak...)...)
		})
	}
}

// TestSDKInspectStdioClientIdentity checks that Inspect sends a stdio server
// the identity of the client that declared it (issue #97), and never a name
// with mcpmoat. The "server" is /bin/sh: it copies the first message of the
// client to a file and exits, so Inspect fails, but the file shows the
// client info that a real server would see first.
func TestSDKInspectStdioClientIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		client   discover.Client
		wantName string
	}{
		{client: discover.ClientClaudeCode, wantName: "claude-code"},
		{client: discover.ClientCursor, wantName: "cursor-vscode"},
		{client: discover.ClientCodex, wantName: "codex-mcp-client"},
		{client: discover.Client("other-client"), wantName: "mcp-client"},
	}
	for _, tt := range tests {
		t.Run(string(tt.client), func(t *testing.T) {
			t.Parallel()
			out := filepath.Join(t.TempDir(), "first-message")
			s := discover.Server{
				Name:      "identity",
				Client:    tt.client,
				Transport: discover.TransportStdio,
				Command:   "/bin/sh",
				Args:      discover.NewArgs([]string{"-c", `head -n 1 > "$0"`, out}),
			}

			res, err := sdkNew(t, inspect.SDKOptions{}).Inspect(sdkCtx(t, sdkTimeout), s)
			sdkAssertFailed(t, res, err, inspect.KindProtocol, inspect.KindStart, inspect.KindTimeout)

			line, rerr := os.ReadFile(out) //nolint:gosec // G304: test reads a file under t.TempDir()
			if rerr != nil {
				t.Fatalf("read the first message: %v (error of Inspect: %v)", rerr, err)
			}
			if strings.Contains(strings.ToLower(string(line)), "mcpmoat") {
				t.Errorf("first message names mcpmoat: %s", line)
			}
			var msg struct {
				Method string `json:"method"`
				Params struct {
					ClientInfo *struct {
						Name string `json:"name"`
					} `json:"clientInfo"`
					Meta map[string]json.RawMessage `json:"_meta"`
				} `json:"params"`
			}
			if err := json.Unmarshal(line, &msg); err != nil {
				t.Fatalf("decode the first message %s: %v", line, err)
			}
			name := ""
			if msg.Params.ClientInfo != nil {
				name = msg.Params.ClientInfo.Name
			} else if raw, ok := msg.Params.Meta["io.modelcontextprotocol/clientInfo"]; ok {
				var info struct {
					Name string `json:"name"`
				}
				if err := json.Unmarshal(raw, &info); err != nil {
					t.Fatalf("decode the client info %s: %v", raw, err)
				}
				name = info.Name
			}
			if name != tt.wantName {
				t.Errorf("%s: client name = %q, want %q (message: %s)", msg.Method, name, tt.wantName, line)
			}
		})
	}
}

// sdkEchoScript is a /bin/sh "server" that answers every request with a
// JSON-RPC error whose message echoes its first argument, as a hostile
// server can echo what it got. It holds no "${", so the Claude Code
// expansion leaves it as written.
const sdkEchoScript = `while read -r line; do
  id=$(printf '%s\n' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  if [ -n "$id" ]; then
    printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"unknown tenant %s"}}\n' "$id" "$1"
  fi
done`

// TestSDKInspectStdioExpandedSecretEcho proves that Inspect removes the
// value of an expanded variable from error text when a stdio server echoes
// it (issue #88). The value stands in an arg, where no other scrub list has
// it: only the values that Inspect looked up for the expansion cover it.
func TestSDKInspectStdioExpandedSecretEcho(t *testing.T) {
	t.Parallel()

	const tenant = "acme-team-workspace"
	s := discover.Server{
		Name:      "echo",
		Client:    discover.ClientClaudeCode,
		Transport: discover.TransportStdio,
		Command:   "/bin/sh",
		Args:      discover.NewArgs([]string{"-c", sdkEchoScript, "sh", "${MCPMOAT_TEST_TENANT}"}),
	}
	parent := []string{"PATH=/usr/bin:/bin", "MCPMOAT_TEST_TENANT=" + tenant}

	inspector := inspect.NewForTest(inspect.SDKOptions{}, filepath.Join(t.TempDir(), "run"), parent, 0)
	res, err := inspector.Inspect(sdkCtx(t, sdkTimeout), s)

	_, reason := sdkAssertFailed(t, res, err, inspect.KindProtocol)
	sdkAssertNoLeak(t, err, tenant)
	// The echo must reach the reason or the cause, masked; else the test
	// would pass on an error that dropped the server text.
	text := reason
	if cause := errors.Unwrap(err); cause != nil {
		text += " | " + cause.Error()
	}
	if want := "unknown tenant " + discover.Mask; !strings.Contains(text, want) {
		t.Errorf("reason and cause = %q, want them to contain %q", text, want)
	}
}
