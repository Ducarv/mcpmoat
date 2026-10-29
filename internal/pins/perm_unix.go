//go:build unix

package pins

import (
	"fmt"
	"io/fs"
	"strings"
	"syscall"
)

// parentChecks tells checkParents to walk the path to the pins directory. On
// Unix the walk checks the owner of each symlink and the owner and the mode of
// each parent directory. perm_other.go sets it to false.
const parentChecks = true

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
		return fmt.Errorf("%s %s is not safe: its owner is unknown: %w", labelParent, path, ErrInsecurePermissions)
	}

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
	// when the current user is not the owner (askOwnerPrefix).
	ask := askOwnerPrefix(info, uid)
	chmod := "chmod go-w -- " + shellQuote(path)
	var problem, fix string
	switch {
	case foreignOwner && writable:
		problem = problemForeignOwnerWritable
		fix = ask + "chown, then " + chmod + ", " + privateConfigHint
	case foreignOwner:
		problem = problemForeignOwner
		fix = ask + "chown, " + privateConfigHint
	case writable:
		problem = problemWritable
		fix = ask + chmod + ", " + privateConfigHint
	default:
		return nil
	}
	return fmt.Errorf("%s %s is not safe: mode %04o, %s (fix: %s): %w",
		labelParent, path, shown, problem, fix, ErrInsecurePermissions)
}

// askOwnerPrefix returns the start of a fix hint for a command that only the
// owner of a parent directory or root can run, for the current user uid. info
// is the Lstat or Stat result of the directory. The result is:
//   - "" when uid owns the directory: the user runs the command.
//   - "ask root to run " when root owns it.
//   - "ask the owner or root to run " for any other owner, and also when the
//     owner is not known (a nil info, or no Unix owner, see ownerUID). That
//     fails closed: the hint never tells the user to run a command that only
//     another user can run.
//
// checkParentOwnerAndMode and checkParentACL (macOS only) share it, so their
// hints use the same words.
func askOwnerPrefix(info fs.FileInfo, uid int) string {
	if info == nil {
		return "ask the owner or root to run "
	}
	owner, ok := ownerUID(info)
	switch {
	case ok && owner == uid:
		return ""
	case ok && owner == 0:
		return "ask root to run "
	default:
		return "ask the owner or root to run "
	}
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

// groupOrOtherAny is the mode bits that give the group or others any access:
// read, write or execute.
const groupOrOtherAny fs.FileMode = 0o077

// The problem texts of a refused pins lock file (checkLockFile).
const (
	problemLockNotRegular       = "not a regular file"
	problemLockOpen             = "accessible by group or others"
	problemLockForeignOwnerOpen = problemForeignOwner + ", " + problemLockOpen
)

// checkLockFile returns an error that wraps ErrInsecurePermissions when the
// pins lock file at path is not safe to lock. info is the Stat result of the
// open lock file and must not be nil. uid is a parameter, so a test can fake
// a foreign owner without root.
//
// The rule:
//   - It must be a regular file. A symlink, a named pipe (FIFO), a device or
//     a directory is refused.
//   - uid must own it.
//   - The group and others must have no access at all (no bit of
//     groupOrOtherAny), so mode 0600 passes and 0640 or 0604 is refused.
//
// Why read access is enough to refuse: flock(2) needs only a read-only
// descriptor. Any user who can open the file for reading can hold the lock
// for as long as they want and block every scan and pin --accept.
//
// The fix hint is to remove the file, never to chmod it (see lockFileFix).
func checkLockFile(path string, info fs.FileInfo, uid int) error {
	fix := lockFileFix(path, info)

	mode := info.Mode()
	if !mode.IsRegular() {
		return fmt.Errorf("%s %s is not safe: %s (fix: %s): %w",
			labelLock, path, problemLockNotRegular, fix, ErrInsecurePermissions)
	}

	owner, ok := ownerUID(info)
	if !ok {
		return fmt.Errorf("%s %s is not safe: its owner is unknown: %w", labelLock, path, ErrInsecurePermissions)
	}

	foreignOwner := owner != uid
	perm := mode.Perm()
	open := perm&groupOrOtherAny != 0

	var problem string
	switch {
	case foreignOwner && open:
		problem = problemLockForeignOwnerOpen
	case foreignOwner:
		problem = problemForeignOwner
	case open:
		problem = problemLockOpen
	default:
		return nil
	}
	return fmt.Errorf("%s %s is not safe: mode %04o, %s (fix: %s): %w",
		labelLock, path, perm, problem, fix, ErrInsecurePermissions)
}

// lockFileFix returns the fix hint of a refused pins lock file at path, with
// no "fix: " prefix: remove the entry, and the next run makes a new lock file.
// For example:
//
//	rm -- '/home/u/.config/mcpmoat/pins.json.lock', then mcpmoat makes a new one with mode 0600
//
// info is the Lstat or Stat result of the entry, or nil when it is not known.
// When info is a directory, the hint says rmdir instead of rm: rm without -r
// refuses a directory. The hint never says rm -r, which would also remove
// what the directory holds; rmdir fails on a directory that is not empty, and
// the user then looks at it first.
//
// The hint is to remove the file, never to chmod it. A descriptor that another
// user opened while the mode was open stays valid after a chmod, so that user
// could still hold the lock. After the remove, mcpmoat makes a new file with
// mode 0600. The pins directory is checked to belong to the user, so the user
// can remove the entry even when another user owns it.
func lockFileFix(path string, info fs.FileInfo) string {
	rm := "rm"
	if info != nil && info.IsDir() {
		rm = "rmdir"
	}
	return rm + " -- " + shellQuote(path) + ", then mcpmoat makes a new one with mode 0600"
}

// shellQuote returns s as one word for a POSIX shell: it wraps s in single
// quotes, and it replaces each single quote inside s with the four characters
// quote, backslash, quote, quote (close, escape, open). A user can paste the
// result into a shell command, also when the path holds spaces or shell
// metacharacters.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
