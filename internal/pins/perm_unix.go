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

// The problem texts of a permission error. checkOwnerAndMode and
// checkParentOwnerAndMode share them, so the same problem has the same words
// for the pins directory, pins.json and a parent directory. Each function adds
// its own fix hint.
const (
	problemForeignOwner         = "owned by another user"
	problemWritable             = "writable by group or others"
	problemForeignOwnerWritable = problemForeignOwner + ", " + problemWritable
)

// ownerUID returns the uid of the owner of the path that info describes. ok
// is false when info has no Unix owner (info.Sys is not a *syscall.Stat_t,
// for example a fake FileInfo). Each caller then fails closed: without the
// owner it cannot tell that the path is safe.
//
// The uid is an int, so the callers compare it with the uid of the user, also
// an int. Converting that uid to uint32 instead could overflow (gosec G115).
func ownerUID(info fs.FileInfo) (uid int, ok bool) {
	// A type assertion with two results: ok is false, and there is no panic,
	// when Sys returns another type.
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

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
	owner, ok := ownerUID(info)
	if !ok {
		return fmt.Errorf("pins %s %s is not safe: its owner is unknown: %w", kind, path, ErrInsecurePermissions)
	}

	foreignOwner := owner != uid
	perm := info.Mode().Perm()
	writable := perm&groupOrOtherWrite != 0

	// Only the owner or root can chown or chmod a path. So when the owner is
	// another user, the hint does not start with a command that fails for us.
	var problem, fix string
	switch {
	case foreignOwner && writable:
		problem = problemForeignOwnerWritable
		fix = "ask the owner or root to run chown, then chmod go-w -- " + shellQuote(path) + ", or to remove the path"
	case foreignOwner:
		problem = problemForeignOwner
		fix = "ask the owner or root to run chown, or to remove the path"
	case writable:
		problem = problemWritable
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
// info is the os.Lstat or os.Stat result of the directory path (the two are
// the same for a directory that is not a symlink) and must not be nil. uid is
// a parameter, so a test can fake a foreign owner without root.
//
// The check reads the owner and the mode bits only. It does not read ACLs.
func checkParentOwnerAndMode(path string, info fs.FileInfo, uid int) error {
	owner, ok := ownerUID(info)
	if !ok {
		return fmt.Errorf("pins parent directory %s is not safe: its owner is unknown: %w", path, ErrInsecurePermissions)
	}

	ownedByRootNotUs := owner == 0 && uid != 0
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
		problem = problemForeignOwnerWritable
		fix = "ask the owner or root to run chown, then " + chmod + ", " + privateConfigHint
	case foreignOwner:
		problem = problemForeignOwner
		fix = "ask the owner or root to run chown, " + privateConfigHint
	case writable && ownedByRootNotUs:
		problem = problemWritable
		fix = "ask root to run " + chmod + ", " + privateConfigHint
	case writable:
		problem = problemWritable
		fix = chmod + ", " + privateConfigHint
	default:
		return nil
	}
	return fmt.Errorf("pins parent directory %s is not safe: mode %04o, %s (fix: %s): %w",
		path, shown, problem, fix, ErrInsecurePermissions)
}

// problemForeignSymlink is the problem text of a symlink on the path to the
// pins directory that another user owns (checkSymlinkOwner).
const problemForeignSymlink = "a symlink " + problemForeignOwner

// checkSymlinkOwner returns an error that wraps ErrInsecurePermissions when
// info says that the symlink at path belongs to another user than uid or root.
// info is the os.Lstat result of path: Lstat describes the symlink itself, not
// its target. label is the start of the error text, "pins directory" or "pins
// parent directory". info must not be nil, and the caller has checked that it
// is a symlink.
//
// Why the owner of the symlink matters: in a directory with the sticky bit,
// such as /tmp, every user can create an entry, and the mode rule of
// checkParentOwnerAndMode passes. The sticky bit says only who can rename or
// remove an entry: its owner, the owner of the directory, or root. So another
// user can create /tmp/cfg as a symlink to an empty directory that we own, and
// later point it to another directory. Then the next run looks like a first
// run and pins the current tools without an alert (T2). A symlink that we or
// root own passes: only we, root or the owner of the directory (checked to be
// us or root) can replace it, and we can change the path anyway.
//
// uid is a parameter, so a test can fake a foreign owner without root. The
// check reads the owner only: the mode of a symlink is not used on Linux and
// macOS.
func checkSymlinkOwner(path, label string, info fs.FileInfo, uid int) error {
	owner, ok := ownerUID(info)
	if !ok {
		return fmt.Errorf("%s %s is not safe: the owner of the symlink is unknown: %w", label, path, ErrInsecurePermissions)
	}
	if owner == uid || owner == 0 {
		return nil
	}
	return fmt.Errorf("%s %s is not safe: %s (fix: ask the owner or root to remove or replace the symlink, %s): %w",
		label, path, problemForeignSymlink, privateConfigHint, ErrInsecurePermissions)
}

// shellQuote returns s as one word for a POSIX shell: it wraps s in single
// quotes, and it replaces each single quote inside s with the four characters
// quote, backslash, quote, quote (close, escape, open). A user can paste the
// result into a shell command, also when the path holds spaces or shell
// metacharacters.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
