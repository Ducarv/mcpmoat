//go:build !unix

package inspect

// runHelperMode has no helper modes on this platform: the process tests are
// for Unix only. It always returns 0 and false.
func runHelperMode([]string) (int, bool) {
	return 0, false
}
