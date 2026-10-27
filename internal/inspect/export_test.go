package inspect

// This file is compiled only with the tests. It gives the external test
// package inspect_test access to unexported names, so the tests use the real
// values and do not copy them by hand.

// ConfigureProcessGroup is configureProcessGroup, for the tests.
var ConfigureProcessGroup = configureProcessGroup

// KillProcessGroup is killProcessGroup, for the tests.
var KillProcessGroup = killProcessGroup

// KillWaitDelay is killWaitDelay, for the tests. It sizes upper time bounds.
const KillWaitDelay = killWaitDelay

// HelperModeArg is helperModeArg, for the tests. A command with it as the
// first argument runs the test binary as a helper-mode fixture server.
const HelperModeArg = helperModeArg

// StopGrace is stopGrace, for the tests. It sizes upper time bounds.
const StopGrace = stopGrace

// SetAfterTests sets the func that TestMain runs after all tests (see
// afterTests in main_test.go).
func SetAfterTests(f func()) { afterTests = f }

// NewForTest is [New] for the tests in package inspect_test.
//
// The work directories of servers go below root. root gets the checks of
// privateDir, but not the parent chain check: a test directory is below /tmp
// on Linux, which that check refuses on purpose. environ is the parent
// environment of the child; nil means os.Environ. rawLimit is the raw size
// limit; 0 means maxRawBytes.
func NewForTest(opts SDKOptions, root string, environ []string, rawLimit int64) *SDKInspector {
	i := New(opts)
	i.runRoot = func() (string, error) { return privateDir(root) }
	if environ != nil {
		i.environ = func() []string { return environ }
	}
	i.rawLimit = rawLimit
	return i
}

// ErrJSONTooComplex is errJSONTooComplex, for the tests.
var ErrJSONTooComplex = errJSONTooComplex

// JSONTooComplexReason is the fixed reason of a JSON shape violation, for the
// tests (see jsonTooComplexReason in errors_test.go).
const JSONTooComplexReason = jsonTooComplexReason

// CheckSecrets is checkSecrets, for the tests.
var CheckSecrets = checkSecrets

// WantSecrets is wantSecrets, for the tests.
var WantSecrets = wantSecrets

// AssertResultMasked is assertResultMasked, for the tests.
var AssertResultMasked = assertResultMasked
