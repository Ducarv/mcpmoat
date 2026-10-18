//go:build !unix

package inspect

// checkPrivateChain does nothing on systems that are not Unix. Windows is a
// non-goal (PRD section 2.2); see the Unix version for the rule.
func checkPrivateChain(string) error {
	return nil
}
