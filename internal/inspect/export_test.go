package inspect

import "io"

// StopGrace exports stopGrace to the tests in package inspect_test, so that
// their time bounds follow the production value.
const StopGrace = stopGrace

// EnvDumpArg and WriteEnvDump export the env-dump fixture of main_test.go to
// TestMain in package inspect_test.
const EnvDumpArg = envDumpArg

// WriteEnvDump writes the argv, environment and working directory of the
// current process to w as JSON; see writeEnvDump.
func WriteEnvDump(w io.Writer) error { return writeEnvDump(w) }

// NewForTest is [New] for the tests in package inspect_test.
//
// The work directories of servers go below root. root gets the checks of
// privateDir, but not the parent chain check: a test directory is below /tmp
// on Linux, which that check refuses on purpose. environ is the parent
// environment of the child; nil means os.Environ.
func NewForTest(opts Options, root string, environ []string) *SDKInspector {
	i := New(opts)
	i.runRoot = func() (string, error) { return privateDir(root) }
	if environ != nil {
		i.environ = func() []string { return environ }
	}
	return i
}
