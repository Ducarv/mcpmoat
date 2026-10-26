//go:build unix

package pins

import (
	"fmt"
	"io/fs"
	"strings"
	"syscall"
)

// checkOwnerAndMode returns an error that wraps ErrInsecurePermissions when
// info says that another user than uid owns the path, or that its group or
// others can write it (mode bits 0o022). Modes such as 0o755 and 0o644 pass.
// info is the os.Stat result of path, or the Stat result of its open file. info
// must not be nil.
//
// uid is a parameter, so a test can fake a foreign owner without root.
//
// The check reads the owner and the mode bits only. It does not read ACLs.
func checkOwnerAndMode(path, kind string, info fs.FileInfo, uid int) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Fail closed: without the owner we cannot tell that the path is safe.
		return fmt.Errorf("pins %s %s is not safe: its owner is unknown: %w", kind, path, ErrInsecurePermissions)
	}

	// Compare as int: converting uid to uint32 can overflow (gosec G115).
	foreignOwner := int(st.Uid) != uid
	perm := info.Mode().Perm()
	groupOrOtherWrite := perm&0o022 != 0

	var problems, fixes []string
	q := shellQuote(path)
	if foreignOwner {
		problems = append(problems, "owned by another user")
		fixes = append(fixes, fmt.Sprintf(`you must own the path: chown -- "$(id -un)" %s, or remove the path`, q))
	}
	if groupOrOtherWrite {
		problems = append(problems, "writable by group or others")
		// Put the chmod hint first when both problems exist.
		fixes = append([]string{"chmod go-w -- " + q}, fixes...)
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("pins %s %s is not safe: mode %04o, %s (fix: %s): %w",
		kind, path, perm, strings.Join(problems, ", "), strings.Join(fixes, "; "), ErrInsecurePermissions)
}
