package inspect_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

// This file holds the test helpers that several external test files
// (package inspect_test) use. A helper that only one file uses stays in that
// file.

// init makes TestMain (main_test.go) remove the fixture builds of
// inspecttest after all tests. TestMain is in package inspect, which cannot
// import inspecttest, because inspecttest imports inspect.
func init() {
	inspect.SetAfterTests(inspecttest.RemoveBuilds)
}

// sdkNew returns an SDKInspector with opts that makes the working
// directories of servers in a new directory of the test, never in the cache
// directory of the user.
func sdkNew(t *testing.T, opts inspect.SDKOptions) *inspect.SDKInspector {
	t.Helper()
	return inspect.NewForTest(opts, filepath.Join(t.TempDir(), "run"), nil, 0)
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

// sdkBenign returns a stdio server that runs the benign fixture with args.
func sdkBenign(t *testing.T, args ...string) discover.Server {
	t.Helper()
	return discover.Server{
		Name:      "benign",
		Transport: discover.TransportStdio,
		Command:   inspecttest.Fixture(t, "benign"),
		Args:      discover.NewArgs(args),
	}
}
