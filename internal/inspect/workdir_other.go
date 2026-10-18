//go:build !unix

package inspect

import "io/fs"

// checkPrivateMode does nothing on systems that are not Unix: Windows
// reports no Unix permission bits for a directory. See the Unix version.
func checkPrivateMode(string, fs.FileInfo) error {
	return nil
}

// checkPrivateChain does nothing on systems that are not Unix. Windows is a
// non-goal (PRD section 2.2); see the Unix version for the rule.
func checkPrivateChain(string) error {
	return nil
}
