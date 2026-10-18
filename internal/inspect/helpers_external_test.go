package inspect_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// This file holds the test helpers that several external test files
// (package inspect_test) use. A helper that only one file uses stays in that
// file.

// sdkNew returns an SDKInspector with opts that makes the working
// directories of servers in a new directory of the test, never in the cache
// directory of the user.
func sdkNew(t *testing.T, opts inspect.Options) *inspect.SDKInspector {
	t.Helper()
	return inspect.NewForTest(opts, filepath.Join(t.TempDir(), "run"), nil)
}

// sdkReadPID reads the pidfile that the fixture writes and checks that it
// holds a positive process ID. The fixture writes it in every mode before
// the handshake, so a missing file means that the process never started.
func sdkReadPID(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: test reads the pidfile path that it chose under t.TempDir()
	if err != nil {
		t.Fatalf("read pidfile: %v (the server did not start?)", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		t.Fatalf("pidfile holds %q, want a positive process ID", b)
	}
	return pid
}
