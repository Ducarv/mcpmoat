package inspect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// envDumpArg is the first argument that turns the test binary into a
// fixture "server". The child does not run any tests. It writes its argv,
// environment and working directory to stdout as JSON and exits.
//
// A later test configures a server like this:
//
//	Command: envDumpExe(t)              (or a symlink to it)
//	Args:    []string{envDumpArg, "a", "b c"}
//
// In the child, os.Args[1] is envDumpArg (the trigger) and os.Args[2:] are
// the arguments under test.
//
// Why an argument and not an environment variable? The usual Go pattern sets
// GO_WANT_HELPER_PROCESS=1 in the child environment. The code under test
// scrubs the child environment (NFR-04), so that variable never arrives.
// An argument survives the scrub, because the command and its arguments are
// passed through exactly as configured.
const envDumpArg = "-mcpmoat-test-envdump"

// TestMain of the test binary of package inspect is in sdk_test.go (package
// inspect_test). Go allows one TestMain for the internal and the external
// tests together, and only the external package can import inspecttest. It
// implements the "re-exec the test binary" pattern with envDumpArg and
// writeEnvDump (exported to it in export_test.go).

// envDump is what the fixture child reports about itself.
type envDump struct {
	// Args is os.Args exactly as the child sees it, including os.Args[0].
	Args []string `json:"args"`
	// Env is os.Environ() in the child. It is never nil, so an empty
	// environment encodes as [] and not as null.
	Env []string `json:"env"`
	// Cwd is the working directory of the child.
	Cwd string `json:"cwd"`
}

// writeEnvDump writes the argv, environment and working directory of the
// current process to w as JSON.
func writeEnvDump(w io.Writer) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}
	env := os.Environ()
	if env == nil {
		// Normalise so that JSON gives [] and tests can compare against
		// an empty slice without a special case for nil.
		env = []string{}
	}
	d := envDump{Args: os.Args, Env: env, Cwd: cwd}
	if err := json.NewEncoder(w).Encode(d); err != nil {
		return fmt.Errorf("encode env dump: %w", err)
	}
	return nil
}

// envDumpExe returns the absolute path of the running test binary. Use it
// as the command of a fixture server, with envDumpArg as the first argument.
func envDumpExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}
	if !filepath.IsAbs(exe) {
		t.Fatalf("os.Executable() = %q, want an absolute path", exe)
	}
	return exe
}

// decodeEnvDump parses the stdout of a fixture child. On error it reports
// only the error and the output length, never the raw output, because the
// output can contain environment values.
func decodeEnvDump(t *testing.T, out []byte) envDump {
	t.Helper()
	var d envDump
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("decode env dump (%d bytes): %v", len(out), err)
	}
	return d
}

// TestWriteEnvDump checks that the dump of the current process round-trips
// through decodeEnvDump with the expected values.
func TestWriteEnvDump(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := writeEnvDump(&buf); err != nil {
		t.Fatalf("writeEnvDump() error = %v", err)
	}
	got := decodeEnvDump(t, buf.Bytes())

	wantCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error = %v", err)
	}
	if !reflect.DeepEqual(got.Args, os.Args) {
		t.Errorf("Args = %q, want %q", got.Args, os.Args)
	}
	if got.Cwd == "" || got.Cwd != wantCwd {
		t.Errorf("Cwd = %q, want %q", got.Cwd, wantCwd)
	}
	if got.Env == nil {
		t.Error("Env = nil, want a non-nil slice")
	}
}

// TestEnvDumpExe checks that the fixture command is an existing absolute path.
func TestEnvDumpExe(t *testing.T) {
	t.Parallel()

	exe := envDumpExe(t)
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatalf("os.Stat(%q) error = %v", exe, err)
	}
	if info.IsDir() {
		t.Errorf("envDumpExe() = %q is a directory, want a file", exe)
	}
}
