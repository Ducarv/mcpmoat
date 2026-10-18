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
