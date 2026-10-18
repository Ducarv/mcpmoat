package inspecttest

// This file is in package inspecttest, not inspecttest_test, so that the
// tests can read the unexported build counter and the build entries.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestMain removes the fixture builds after all tests of the package.
func TestMain(m *testing.M) {
	code := m.Run()
	RemoveBuilds()
	os.Exit(code)
}

// TestFixtureBuildsOnce checks that two calls for the same name return the
// same binary and that the second call does not build again.
//
// This test is not parallel on purpose. Go runs all non-parallel top-level
// tests before it resumes the parallel ones, so no other test in this
// package can start a build between the two counter reads.
func TestFixtureBuildsOnce(t *testing.T) {
	first := Fixture(t, "benign")
	// An earlier test (the order is shuffled) can have built the fixture
	// already, so only the change between the two calls is exact.
	afterFirst := builds.Load()
	second := Fixture(t, "benign")
	afterSecond := builds.Load()

	if afterFirst < 1 {
		t.Errorf("build count after the first call = %d, want at least 1", afterFirst)
	}
	if afterSecond != afterFirst {
		t.Errorf("build count changed from %d to %d on the second call, want no new build", afterFirst, afterSecond)
	}
	if first != second {
		t.Errorf("Fixture() paths differ: first %q, second %q", first, second)
	}
	if !filepath.IsAbs(first) {
		t.Errorf("Fixture() = %q, want an absolute path", first)
	}
	if got := filepath.Base(first); got != "benign" {
		t.Errorf("binary name = %q, want %q", got, "benign")
	}

	info, err := os.Stat(first)
	if err != nil {
		t.Fatalf("stat fixture binary: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("fixture binary mode = %v, want a regular file", info.Mode())
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("fixture binary mode = %v, want an executable file", info.Mode())
	}
}

// TestFixtureBinaryRuns runs the built benign server in crash mode with a
// minimal environment. It checks the exit code and the pidfile.
func TestFixtureBinaryRuns(t *testing.T) {
	t.Parallel()
	bin := Fixture(t, "benign")
	pidPath := filepath.Join(t.TempDir(), "pid")

	cmd := exec.CommandContext(t.Context(), bin, "-mode", "crash", "-pidfile", pidPath) //nolint:gosec // G204: bin is the fixture that this test package built
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run fixture: err = %v, want an *exec.ExitError; output:\n%s", err, out)
	}
	if got := exitErr.ExitCode(); got != 3 {
		t.Errorf("exit code = %d, want 3 (crash mode); output:\n%s", got, out)
	}

	data, err := os.ReadFile(pidPath) //nolint:gosec // G304: pidPath is in t.TempDir()
	if err != nil {
		t.Fatalf("read pidfile: %v", err)
	}
	text := string(data)
	if !strings.HasSuffix(text, "\n") {
		t.Errorf("pidfile = %q, want a trailing newline", text)
	}
	pid, err := strconv.Atoi(strings.TrimSuffix(text, "\n"))
	if err != nil {
		t.Fatalf("pidfile = %q, want a decimal process ID: %v", text, err)
	}
	if want := exitErr.Pid(); pid != want {
		t.Errorf("pidfile pid = %d, want %d (the pid of the child process)", pid, want)
	}
}

// TestValidName checks the name pattern that Fixture accepts.
func TestValidName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "fixture name", input: "benign", want: true},
		{name: "hyphen", input: "tool-poison", want: true},
		{name: "digits", input: "t1", want: true},
		{name: "empty", input: "", want: false},
		{name: "parent directory", input: "../x", want: false},
		{name: "dot", input: ".", want: false},
		{name: "dot in name", input: "a.b", want: false},
		{name: "slash", input: "a/b", want: false},
		{name: "absolute path", input: "/tmp/x", want: false},
		{name: "backslash", input: `a\b`, want: false},
		{name: "upper case", input: "Benign", want: false},
		{name: "space", input: "a b", want: false},
		{name: "trailing newline", input: "benign\n", want: false},
		{name: "leading flag", input: "-o", want: true}, // safe: "./testdata/servers/" is always in front
		{name: "underscore", input: "a_b", want: false},
		{name: "non-ASCII", input: "bénign", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := validName.MatchString(tt.input); got != tt.want {
				t.Errorf("validName.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// fatalSentinel is the panic value of fakeTB.Fatalf. The test recovers it.
type fatalSentinel struct{}

// fakeTB records calls to Fatalf. Fatalf on a real *testing.T stops the test
// goroutine, so the test cannot see it. fakeTB panics with fatalSentinel
// instead, and callFixture recovers that panic. All other methods go to the
// real test.
type fakeTB struct {
	testing.TB
	fatals []string
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Fatalf(format string, args ...any) {
	f.fatals = append(f.fatals, fmt.Sprintf(format, args...))
	panic(fatalSentinel{})
}

// callFixture calls Fixture with tb and reports whether it called Fatalf.
func callFixture(tb *fakeTB, name string) (path string, fatal bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(fatalSentinel); !ok {
				panic(r)
			}
			fatal = true
		}
	}()
	return Fixture(tb, name), false
}

// hasEntry reports whether Fixture created a build entry for name.
func hasEntry(name string) bool {
	mu.Lock()
	defer mu.Unlock()
	_, ok := entries[name]
	return ok
}

// TestFixtureRejectsBadName checks that Fixture calls Fatalf for a name that
// does not match validName, before it creates a build entry.
func TestFixtureRejectsBadName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"../x", "Benign", "a/b", ""} {
		t.Run(strconv.Quote(name), func(t *testing.T) {
			t.Parallel()
			tb := &fakeTB{TB: t}
			path, fatal := callFixture(tb, name)
			if !fatal {
				t.Fatalf("Fixture(%q) = %q, want a call to Fatalf", name, path)
			}
			if len(tb.fatals) != 1 || !strings.Contains(tb.fatals[0], "is not valid") {
				t.Errorf("Fatalf messages = %q, want one message that says the name is not valid", tb.fatals)
			}
			if hasEntry(name) {
				t.Errorf("Fixture(%q) created a build entry, want the name check first", name)
			}
		})
	}
}

// TestFixtureBuildError checks that Fixture calls Fatalf when go build fails,
// here for a valid name with no directory under testdata/servers/.
func TestFixtureBuildError(t *testing.T) {
	t.Parallel()
	const name = "no-such-fixture"
	tb := &fakeTB{TB: t}
	path, fatal := callFixture(tb, name)
	if !fatal {
		t.Fatalf("Fixture(%q) = %q, want a call to Fatalf", name, path)
	}
	if len(tb.fatals) != 1 || !strings.Contains(tb.fatals[0], "build fixture "+name) {
		t.Errorf("Fatalf messages = %q, want one build error for %s", tb.fatals, name)
	}
}
