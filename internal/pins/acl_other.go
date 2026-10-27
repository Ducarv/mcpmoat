//go:build !darwin

package pins

import "os"

// checkACL does nothing on systems that are not macOS. Only macOS has
// extended ACLs that the mode bits hide: chmod +a can give another user write
// access, and the mode bits do not change. On Linux, a POSIX ACL entry for a
// named user or group shows in the group bits of the mode through the ACL
// mask, so checkOwnerAndMode already refuses it. Other systems, such as
// Windows and the BSDs, are out of scope. See the darwin version for the rule.
func checkACL(string, string, *os.File) error {
	return nil
}
