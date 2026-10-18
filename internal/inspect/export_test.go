package inspect

// StopGrace exports stopGrace to the tests in package inspect_test, so that
// their time bounds follow the production value.
const StopGrace = stopGrace

// NewWithRunRoot is [New] with the working directories of servers below
// root, so that the tests in package inspect_test never write to the cache
// directory of the user. root gets the same checks as the default run root.
func NewWithRunRoot(opts Options, root string) *SDKInspector {
	i := New(opts)
	i.runRoot = func() (string, error) { return privateDir(root) }
	return i
}
