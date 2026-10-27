//go:build !unix

package pins

import "io/fs"

// checkOwnerAndMode does nothing on systems that are not Unix. Windows reports
// no Unix owner or permission bits, and it uses ACLs, which mcpmoat does not
// check. Windows is a non-goal (PRD section 2.2). See the Unix version for the
// rule.
func checkOwnerAndMode(string, string, fs.FileInfo, int) error {
	return nil
}
