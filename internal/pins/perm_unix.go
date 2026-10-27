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

// privateConfigHint is the other fix for an unsafe parent directory: a config
// directory that only the current user can change.
const privateConfigHint = "or use a private XDG_CONFIG_HOME"

// checkParentOwnerAndMode returns an error that wraps ErrInsecurePermissions
// when info says that a parent directory of the pins directory lets another
// user swap, rename or remove the pins directory. Then the next run would see
// a first run and pin the current tools without an alert (T2).
//
// The rule:
//   - The owner must be uid or root (uid 0). Any other owner is refused.
//   - The group or others must not write the directory (mode bits
//     groupOrOtherWrite), unless the sticky bit is set, as on /tmp (mode
//     1777). With the sticky bit, only the owner of an entry (or the owner of
//     the directory, or root) can rename or remove the entry. The sticky bit
//     does not fix a foreign owner.
//   - Read and execute bits are fine, so ~/.config with mode 0o755 passes.
//
// info is the os.Stat result of path and must not be nil. uid is a parameter,
// so a test can fake a foreign owner without root.
//
// The check reads the owner and the mode bits only. It does not read ACLs.
func checkParentOwnerAndMode(path string, info fs.FileInfo, uid int) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Fail closed: without the owner we cannot tell that the path is safe.
		return fmt.Errorf("pins parent directory %s is not safe: its owner is unknown: %w", path, ErrInsecurePermissions)
	}

	// Compare as int: converting uid to uint32 can overflow (gosec G115).
	owner := int(st.Uid)
	rootOwner := owner == 0 && uid != 0
	foreignOwner := owner != uid && owner != 0
	mode := info.Mode()
	sticky := mode&fs.ModeSticky != 0
	writable := mode.Perm()&groupOrOtherWrite != 0 && !sticky

	// Show the mode as chmod writes it, with the sticky bit as 01000.
	shown := uint32(mode.Perm())
	if sticky {
		shown |= 0o1000
	}

	// Only the owner or root can chown or chmod a path. So the hint asks them
	// when the current user is not the owner.
	chmod := "chmod go-w -- " + shellQuote(path)
	var problem, fix string
	switch {
	case foreignOwner && writable:
		problem = "owned by another user, writable by group or others"
		fix = "ask the owner or root to run chown, then " + chmod + ", " + privateConfigHint
	case foreignOwner:
		problem = "owned by another user"
		fix = "ask the owner or root to run chown, " + privateConfigHint
	case writable && rootOwner:
		problem = "writable by group or others"
		fix = "ask root to run " + chmod + ", " + privateConfigHint
	case writable:
		problem = "writable by group or others"
		fix = chmod + ", " + privateConfigHint
	default:
		return nil
	}
	return fmt.Errorf("pins parent directory %s is not safe: mode %04o, %s (fix: %s): %w",
		path, shown, problem, fix, ErrInsecurePermissions)
}

// shellQuote returns s as one word for a POSIX shell: it wraps s in single
// quotes, and it replaces each single quote inside s with the four characters
// quote, backslash, quote, quote (close, escape, open). A user can paste the
// result into a shell command, also when the path holds spaces or shell
// metacharacters.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
