//go:build !unix

package pins

import "io/fs"

// parentChecks is false on systems that are not Unix, so checkParents does not
// walk the path. The owner and symlink checks below do nothing here, so the
// walk would add no protection, but it could still fail or follow a wrong path
// (see checkParents). perm_unix.go sets it to true.
const parentChecks = false

// checkOwnerAndMode does nothing on systems that are not Unix. Windows reports
// no Unix owner or permission bits, and it uses ACLs, which mcpmoat does not
// check. Windows is a non-goal (PRD section 2.2). See the Unix version for the
// rule.
func checkOwnerAndMode(string, string, fs.FileInfo, int) error {
	return nil
}

// checkParentOwnerAndMode does nothing on systems that are not Unix. Windows
// reports no Unix owner or permission bits for the parent directories of the
// pins directory, and it uses ACLs, which mcpmoat does not check. Windows is a
// non-goal (PRD section 2.2). See the Unix version for the rule.
func checkParentOwnerAndMode(string, fs.FileInfo, int) error {
	return nil
}

// checkSymlinkOwner does nothing on systems that are not Unix. Windows reports
// no Unix owner for a symlink. Windows is a non-goal (PRD section 2.2). See
// the Unix version for the rule.
func checkSymlinkOwner(string, string, fs.FileInfo, int) error {
	return nil
}

// checkLockFile does nothing on systems that are not Unix. Windows reports no
// Unix owner or permission bits for the pins lock file, and mcpmoat takes no
// lock there (see lock_other.go). Windows is a non-goal (PRD section 2.2). See
// the Unix version for the rule.
func checkLockFile(string, fs.FileInfo, int) error {
	return nil
}
