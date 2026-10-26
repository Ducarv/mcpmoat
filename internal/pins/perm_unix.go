//go:build unix

package pins

import (
	"fmt"
	"io/fs"
	"strings"
	"syscall"
)

// groupOrOtherWrite is the mode bits that let the group or others write.
const groupOrOtherWrite fs.FileMode = 0o022

// checkOwnerAndMode returns an error that wraps ErrInsecurePermissions when
// info says that another user than uid owns the path, or that its group or
// others can write it (mode bits groupOrOtherWrite). Modes such as 0o755 and
// 0o644 pass. info is the os.Stat result of path, or the Stat result of its
// open file. info must not be nil.
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
	writable := perm&groupOrOtherWrite != 0

	// Only the owner or root can chown or chmod a path. So when the owner is
	// another user, the hint does not start with a command that fails for us.
	var problem, fix string
	switch {
	case foreignOwner && writable:
		problem = "owned by another user, writable by group or others"
		fix = "ask the owner or root to run chown, then chmod go-w -- " + shellQuote(path) + ", or to remove the path"
	case foreignOwner:
		problem = "owned by another user"
		fix = "ask the owner or root to run chown, or to remove the path"
	case writable:
		problem = "writable by group or others"
		fix = "chmod go-w -- " + shellQuote(path)
	default:
		return nil
	}
	return fmt.Errorf("pins %s %s is not safe: mode %04o, %s (fix: %s): %w",
		kind, path, perm, problem, fix, ErrInsecurePermissions)
}

// shellQuote returns s as one word for a POSIX shell: it wraps s in single
// quotes, and it replaces each single quote inside s with the four characters
// quote, backslash, quote, quote (close, escape, open). A user can paste the
// result into a shell command, also when the path holds spaces or shell
// metacharacters.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
