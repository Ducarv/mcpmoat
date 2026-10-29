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

// sdkPathSecrets returns the segments of paths that discover.RedactArgs
// masks. A stdio Result.Secrets holds the argv secrets (see
// discover.ArgSecrets), so it also holds such segments of the fixture path
// and of the t.TempDir paths in the args: the random names of the temp
// directories, and on macOS a segment of $TMPDIR. They depend on the machine,
// so a test cannot write them by hand. This helper reads the masks from the
// RedactArgs output, segment by segment, and does not call ArgSecrets, so a
// bug in what ArgSecrets collects cannot hide in the want. inspect.WantSecrets
// drops the short ones.
func sdkPathSecrets(t *testing.T, paths ...string) []string {
	t.Helper()
	var segments []string
	for _, p := range paths {
		in := strings.Split(p, "/")
		out := strings.Split(discover.RedactArgs([]string{p})[0], "/")
		if len(in) != len(out) {
			t.Fatalf("RedactArgs masks the test path %q as %q, want only whole segments masked", p, out)
		}
		for i, seg := range in {
			if out[i] == discover.Mask && seg != discover.Mask {
				segments = append(segments, seg)
			}
		}
	}
	return segments
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
