package inspecttest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// validName is the only form of fixture name that Fixture accepts. The name
// becomes part of a go build argument and of a file path, so it must not
// hold "/", "." or other path characters.
var validName = regexp.MustCompile(`^[a-z0-9-]+$`)

// build is the result of one fixture build. once makes sure that the build
// runs only one time, also when parallel tests ask for the same fixture.
type build struct {
	once sync.Once
	path string
	err  error
}

// The state below is shared by all tests of one test binary. That is the
// purpose of this file: Fixture builds the fixture MCP servers under
// testdata/servers/ into one shared temp directory, once per test binary on
// the first call for each name, not once per test. TestMain calls
// RemoveBuilds to remove the directory when all tests are done. mu protects
// dir and entries.
var (
	mu      sync.Mutex
	dir     string                // shared build directory; "" until the first build
	entries = map[string]*build{} // fixture name -> build

	// builds counts the go build runs, so a test in this package can check
	// that each fixture was built only once.
	builds atomic.Int32

	toolOnce   sync.Once
	goTool     string // absolute path of the go tool
	moduleRoot string // directory that holds go.mod
	toolErr    error
)

// Fixture returns the absolute path of the binary of the fixture MCP server
// in testdata/servers/<name>/ below the module root. It builds the binary on
// the first call for name and reuses it for all later calls in the same test
// binary.
//
// name must match [a-z0-9-]+. Fixture calls t.Fatalf for any other name, and
// when the build fails. It skips the test in short mode, because a build
// takes a few seconds, and on Windows.
func Fixture(t testing.TB, name string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping the fixture server build in short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the fixture servers need a Unix system")
	}
	// Never pass an unchecked name to go build.
	if !validName.MatchString(name) {
		t.Fatalf("fixture name %q is not valid: use only a-z, 0-9 and -", name)
	}

	b, buildDir, err := entry(name)
	if err != nil {
		t.Fatalf("build fixture %s: %v", name, err)
	}
	// The result is shared by all tests, so the build does not use the
	// context of the one test that runs it. With t.Context(), a first call
	// from a t.Cleanup function would get a canceled context, and the failed
	// build would then fail every later test too.
	b.once.Do(func() { b.path, b.err = runBuild(context.Background(), buildDir, name) })
	if b.err != nil {
		t.Fatalf("build fixture %s: %v", name, b.err)
	}
	return b.path
}

// RemoveBuilds removes the shared build directory and forgets all builds.
// Call it from TestMain after m.Run:
//
//	code := m.Run()
//	inspecttest.RemoveBuilds()
//	os.Exit(code)
//
// It is safe to call when no fixture was built.
func RemoveBuilds() {
	mu.Lock()
	defer mu.Unlock()
	if dir != "" {
		// The directory is in the system temp directory, so a failure
		// here only leaves files behind. There is no test to report it to.
		_ = os.RemoveAll(dir)
	}
	dir = ""
	entries = map[string]*build{}
}

// entry returns the build entry for name and the shared build directory. It
// creates the directory on the first call. The lock is held only for this
// short step, so builds of different fixtures can run at the same time.
func entry(name string) (*build, string, error) {
	mu.Lock()
	defer mu.Unlock()
	if dir == "" {
		d, err := os.MkdirTemp("", "mcpmoat-fixtures-*")
		if err != nil {
			return nil, "", fmt.Errorf("create build directory: %w", err)
		}
		// os.MkdirTemp returns a relative path if TMPDIR is relative.
		abs, err := filepath.Abs(d)
		if err != nil {
			_ = os.RemoveAll(d)
			return nil, "", fmt.Errorf("absolute path of %s: %w", d, err)
		}
		dir = abs
	}
	b, ok := entries[name]
	if !ok {
		b = &build{}
		entries[name] = b
	}
	return b, dir, nil
}

// runBuild runs "go build" for the fixture name in the module root and
// returns the path of the binary in buildDir.
func runBuild(ctx context.Context, buildDir, name string) (string, error) {
	builds.Add(1)
	tool, root, err := toolchain(ctx)
	if err != nil {
		return "", err
	}
	bin := filepath.Join(buildDir, name)
	// The "./" prefix makes go build read the argument as a directory below
	// the module root, and validName keeps it there.
	cmd := exec.CommandContext(ctx, tool, "build", "-o", bin, "./testdata/servers/"+name) //nolint:gosec // G204: the go tool comes from the test's own toolchain, and name matches validName
	cmd.Dir = root
	// cmd.Env stays nil, so go build gets the full environment of the test.
	// The go tool needs GOPATH, GOCACHE, HOME and similar variables. This is
	// the trusted toolchain, not an MCP server, so the NFR-04 rule to scrub
	// the environment does not apply here.
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go build failed: %w\n%s", err, out)
	}
	return bin, nil
}

// toolchain returns the path of the go tool and the module root. It finds
// them on the first call and returns the same result on all later calls.
func toolchain(ctx context.Context) (tool, root string, err error) {
	toolOnce.Do(func() {
		// "go test" puts the bin directory of its own toolchain first in
		// PATH, so LookPath finds the go tool that runs this test.
		// (runtime.GOROOT is deprecated.)
		goTool, toolErr = exec.LookPath("go")
		if toolErr != nil {
			return
		}
		moduleRoot, toolErr = findModuleRoot(ctx, goTool)
	})
	return goTool, moduleRoot, toolErr
}

// findModuleRoot asks the go tool for the go.mod file of the current
// directory and returns its directory.
func findModuleRoot(ctx context.Context, tool string) (string, error) {
	out, err := exec.CommandContext(ctx, tool, "env", "GOMOD").Output()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w", err)
	}
	gomod := strings.TrimSpace(string(out))
	// go env GOMOD prints "" outside a module and os.DevNull when
	// GO111MODULE=off.
	if gomod == "" || gomod == os.DevNull {
		return "", errors.New("go env GOMOD: the tests do not run in module mode")
	}
	return filepath.Dir(gomod), nil
}
