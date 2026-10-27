package pins

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/safefile"
)

// ErrInsecurePermissions means that the pins directory or pins.json belongs to
// another user, that its group or other users can write it, or that its ACL
// lets a user or group write it (macOS only, see checkACL). It also means that
// a parent directory of the pins directory lets another user swap, rename or
// remove the pins directory, by its owner, its mode bits or (macOS only) its
// ACL, or that a symlink on the path to the pins directory belongs to another
// user (see checkParents). And it means that the pins lock file is not a
// regular file, belongs to another user, lets its group or others open it,
// or (macOS only) has an ACL that lets a user or group open it (see
// checkLockFile and checkLockFileACL). An unsafe pins path could let another
// user change the pins and hide a rug-pull (T2), so Load and Save refuse it.
// An unsafe lock file could let another user hold the lock and block every
// save, so the code that takes the lock refuses it. mcpmoat never changes the
// mode of an existing path: the user must fix it. Use errors.Is to test for
// it.
//
// The text of such an error names the unsafe path and starts with "pins
// directory", "pins file", "pins parent directory", "pins lock file" or
// "cannot read the ACL". The last one is the fail-closed error of an ACL that
// cannot be read: "cannot read the ACL of the pins directory", "... of the pins
// file", "... of the pins parent directory" or "... of the pins lock file".
// Load, LoadLocked and Save return it as it is, with no "read <path>" or "save
// <path>" prefix. Their other errors from the same checks, for example a
// failed Lstat or Readlink in checkParents, do not wrap ErrInsecurePermissions
// and get the prefix (see Load).
var ErrInsecurePermissions = errors.New("insecure permissions")

// The kind of path in a permission error: the text says "pins directory",
// "pins file", "pins parent directory" or "pins lock file".
const (
	kindDir    = "directory"
	kindFile   = "file"
	kindParent = "parent directory"
	kindLock   = "lock file"
)

// checkDirPermByPath is for a pins directory that Load, LoadLocked or Save
// could not open because the current user may not open it (dirOpenError). It
// returns an error that wraps ErrInsecurePermissions when another user (not
// uid) owns the directory at path, or when its group or others can write it.
// Then the user gets the fix hint and not only "permission denied". It returns
// nil when it cannot tell: a Stat error, or a path that is not a directory.
// The caller then reports the open error. It does not read the ACL, because
// it has no open handle. checkFilePermByPath does the same for pins.json.
//
// It follows symlinks (os.Stat), as the open of the directory does, so it
// checks the target. The checks that decide whether the directory is safe run
// on the open handle (checkDirHandle); this function only gives a better text
// when there is no handle.
func checkDirPermByPath(path string, uid int) error {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return nil
	}
	return checkOwnerAndMode(path, kindDir, info, uid)
}

// checkDirHandle checks the open pins directory d, for example the handle
// that root.Open(".") gives for the os.Root of the pins directory. path is the
// path of the directory, for the error text only. It returns an error that
// wraps ErrInsecurePermissions when another user owns the directory, when its
// group or others can write it, or when its ACL lets a user or group write it
// (checkACL, macOS only).
//
// It reads the owner and the mode from d (d.Stat), not from path. So the
// checked directory is the directory that Load reads from, and a swap of the
// path after the open has no effect. A Stat error is an error, and so is a
// handle that is not a directory.
func checkDirHandle(path string, d *os.File) error {
	info, err := d.Stat()
	if err != nil {
		return fmt.Errorf("check the permissions of the pins directory %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("check the permissions of the pins directory %s: not a directory", path)
	}
	if err := checkOwnerAndMode(path, kindDir, info, os.Geteuid()); err != nil {
		return err
	}
	return checkACL(path, kindDir, d)
}

// checkFileHandle is the full check of the open pins.json f: the owner and
// the mode (checkOwnerAndMode, with the same rule as for the pins directory),
// then the ACL (checkACL, macOS only). info is the result of f.Stat, which the
// caller also uses for the size check, so both checks see the same file, and
// the owner and the mode belong to the bytes that Load parses. info must not
// be nil. path is for the error text only. The error wraps
// ErrInsecurePermissions.
//
// Load calls it after f.Stat and before it reads the data, so it never reads
// the bytes of an unsafe file.
func checkFileHandle(path string, f *os.File, info fs.FileInfo) error {
	if err := checkOwnerAndMode(path, kindFile, info, os.Geteuid()); err != nil {
		return err
	}
	return checkACL(path, kindFile, f)
}

// checkFilePermByPath is for a pins.json that Load could not open because the
// current user may not read it. It returns an error that wraps
// ErrInsecurePermissions when another user (not uid) owns the file, or when
// its group or others can write it. Then the user gets the fix hint and not
// only "permission denied". It returns nil when it cannot tell: a Stat error,
// or a path that is not a regular file. The caller then reports the read error.
// It does not read the ACL, because it has no open file.
//
// It stats the file through an os.Root of the pins directory, as Load opens it.
// So a symlink that leaves the directory is not followed, and the hint never
// names a file outside the pins directory.
func checkFilePermByPath(path string, uid int) error {
	root, err := safefile.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	info, err := root.Stat(filepath.Base(path))
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	return checkOwnerAndMode(path, kindFile, info, uid)
}

// checkParents returns an error that wraps ErrInsecurePermissions when a
// parent directory of the pins directory dir lets another user swap, rename or
// remove the pins directory, or when another user owns a symlink on the path
// to dir, dir included (checkSymlinkOwner, Unix only). Then the next run would
// see a first run and pin the current tools without an alert (T2). It checks
// for the current user (os.Geteuid). See checkParentsAs.
//
// For each parent it checks the owner and the mode bits
// (checkParentOwnerAndMode, Unix only) and, on macOS, the ACL
// (checkParentACL): an allow entry with a write-class right refuses the
// parent, and a deny entry such as the "everyone deny delete" entry of a home
// directory passes.
//
// On a system that is not Unix, it returns nil and does not walk the path
// (parentChecks is false, see perm_other.go). There the owner and symlink
// checks do nothing, so the walk adds no protection. But it could still fail,
// for example on a Readlink error, and it could follow a wrong path: on
// Windows, filepath.IsAbs is false for a rooted target such as \foo.
func checkParents(dir string) error {
	if !parentChecks {
		return nil
	}
	return checkParentsAs(dir, os.Geteuid())
}

// maxSymlinks is the largest number of symlinks that checkParentsAs follows
// on one path. Linux follows at most 40 (MAXSYMLINKS) and macOS 32, so a
// longer chain cannot open anyway. On macOS a chain of 33 to 40 symlinks
// passes this walk, but the open then fails with ELOOP, so the run fails
// closed. The limit also ends a loop such as a -> b -> a.
const maxSymlinks = 40

// Labels of a path in the permission errors: "pins directory", "pins parent
// directory" and "pins lock file".
const (
	labelDir    = "pins " + kindDir
	labelParent = "pins " + kindParent
	labelLock   = "pins " + kindLock
)

// checkParentsAs is checkParents for the user uid. uid is a parameter, so a
// test can fake a foreign owner without root.
//
// It resolves dir one path component at a time, as the kernel does when it
// opens the path, and as realpath(3) and the safe_path check of OpenSSH do.
// It does not use filepath.EvalSymlinks: that gives only the end result, and
// a symlink that is reached only through the target of another symlink is on
// neither the given path nor the resolved one. The walk instead checks each
// entry that it crosses:
//   - A symlink: another user than uid or root must not own it
//     (checkSymlinkOwner). This holds for every symlink on the way, also for
//     a symlink in the target of another symlink. The sticky bit of a parent
//     such as /tmp does not protect a symlink that another user created
//     there: that user can point it to another directory later. Then the walk
//     reads the target (os.Readlink) and goes on with the components of the
//     target, from the root for an absolute target, or from the directory
//     that holds the symlink for a relative one.
//   - A directory that is a parent of the pins directory: its owner and mode
//     (checkParentOwnerAndMode), then on macOS its ACL (checkParentACL). An
//     allow entry with a write-class right, for any principal, refuses it; a
//     deny entry, such as the "everyone deny delete" entry of a home
//     directory, passes. This covers the root directory (also the root of an
//     absolute symlink target), the directory that holds each symlink, and
//     each directory in the target of a symlink. Each directory is checked
//     once, by its real path with no symlink in it.
//   - The pins directory itself, after all symlinks: nothing.
//     checkDirHandle checks its owner, its mode and its ACL on the open
//     handle.
//
// The label of a symlink in the error is "pins directory" when it is the last
// component of the path that is left, so the pins directory itself is the
// symlink, and "pins parent directory" otherwise.
//
// A ".." component in a symlink target goes to the parent of the directory
// that the walk has reached, which is what the kernel does. A lexical clean
// of the path (filepath.Clean) would be wrong after a symlink: for a target
// "link2/../cfg", the kernel goes to the parent of the target of link2, not
// to the directory that holds link2. dir itself is made absolute and clean
// first (filepath.Abs), as filepath.Join and filepath.Dir already do with the
// paths of the callers.
//
// A directory that the walk enters is checked, also when a later ".." leaves
// it again: when the walk enters it, the check cannot know yet whether a
// symlink below it will be followed. So a writable directory that a symlink
// target enters and leaves with ".." is refused. That is a false refusal in
// rare layouts, and it fails closed; the fix is the usual hint.
//
// The walk stops without an error when the next component is missing (see
// safefile.IsMissing): that is a first run, and the directories above it,
// where Save creates the pins directory, are already checked. It also stops
// at a component that is not a directory or a symlink: then the pins
// directory cannot exist, and checkFirstRun reports the problem (in Load,
// and in ensurePinsDir for LoadLocked and Save). On macOS /var and /tmp are
// symlinks that root owns, with targets in /private, so they pass.
//
// The error names the path where the entry really is, after the symlinks
// before it are resolved: for example /private/var/... and not /var/... on
// macOS. When more than one entry is unsafe, the error names the last one
// that the walk found, which is the nearest to the pins directory. When the
// walk stops on another error (an Lstat or Readlink error other than
// "missing", or more than maxSymlinks symlinks), it returns that error, which
// names the path, unless an unsafe entry came before: then the unsafe entry
// wins, because it may have led the walk there.
//
// The check is by path, by design. When no other user (only root) can write
// any directory on the way or owns a symlink on it, no other user can change
// the path between this check and the open, so the path race does not help
// an attacker. On macOS an ACL can let another user write a directory whose
// mode bits are safe, so the walk reads the ACL of each parent too.
func checkParentsAs(dir string, uid int) error {
	abs, err := filepath.Abs(dir) // Abs also cleans the path.
	if err != nil {
		return fmt.Errorf("check the parent directories of the pins directory %s: %w", dir, err)
	}

	w := &parentWalk{dir: dir, uid: uid, checked: make(map[string]struct{})}
	w.resolved, w.rest = splitRoot(abs)
	if len(w.rest) > 0 {
		// The root directory is a parent of the pins directory too.
		if err := w.checkRoot(w.resolved); err != nil {
			return w.fail(err)
		}
	}
	for len(w.rest) > 0 {
		c := w.rest[0]
		w.rest = w.rest[1:]
		if c == ".." {
			// filepath.Dir of the root directory is the root directory, as in
			// the kernel.
			w.resolved = filepath.Dir(w.resolved)
			continue
		}
		next := filepath.Join(w.resolved, c)
		label := labelParent
		if len(w.rest) == 0 {
			label = labelDir
		}

		// Lstat does not follow a symlink at the end of next, so it describes
		// the entry itself. resolved holds no symlink, so this is the entry
		// that the kernel finds.
		info, err := os.Lstat(next)
		if safefile.IsMissing(err) {
			break
		}
		if err != nil {
			return w.fail(fmt.Errorf("check the %s %s: %w", label, next, err))
		}

		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			if err := w.followSymlink(next, label, info); err != nil {
				return w.fail(err)
			}
		case info.IsDir():
			w.enterDir(next, info)
		default:
			// Not a directory: the pins directory cannot exist below it.
			return w.refusal
		}
	}
	return w.refusal
}

// parentWalk is the state of one checkParentsAs walk.
type parentWalk struct {
	dir string // the pins directory as the caller gave it, for the error text
	uid int    // the user that every entry must be safe for

	// resolved is the directory that the walk has reached, with no symlink
	// in it. rest holds the components that are still to walk.
	resolved string
	rest     []string

	hops int // the number of symlinks followed so far

	// checked is a set of the directories that checkDir has checked: a map
	// whose values are not used. struct{} has size zero.
	checked map[string]struct{}

	refusal error // the last unsafe entry found so far
}

// fail returns err, unless the walk found an unsafe entry before: then it
// returns that entry, because it may have led the walk to err (see
// checkParentsAs).
func (w *parentWalk) fail(err error) error {
	if w.refusal != nil {
		return w.refusal
	}
	return err
}

// checkDir checks the parent directory p, once for each p: first its owner
// and its mode (checkParentOwnerAndMode), then, when they are safe, its ACL
// (checkParentACL, macOS only). An unsafe directory becomes the refusal of the
// walk, and the walk goes on. info is the Lstat result of p.
//
// p is always a real directory, never a symlink: the walk calls checkDir only
// for the root directory and for a directory that it enters, and resolved
// holds no symlink. This matters for the ACL, because checkParentACL reads it
// with FSOPT_NOFOLLOW: on a symlink it would read the ACL of the symlink and
// not of the directory. The ACL check runs only when the owner and the mode
// pass, so one directory gives one error, and the owner and mode error, which
// has its own fix hint, comes first.
func (w *parentWalk) checkDir(p string, info fs.FileInfo) {
	if _, done := w.checked[p]; done {
		return
	}
	w.checked[p] = struct{}{}
	if err := checkParentOwnerAndMode(p, info, w.uid); err != nil {
		w.refusal = err
		return
	}
	if err := checkParentACL(p, info, w.uid); err != nil {
		w.refusal = err
	}
}

// enterDir moves the walk into the directory next, whose Lstat result is
// info. When components are left after next, next is a parent of the pins
// directory, so it checks next with checkDir. Lstat and Stat give the same
// owner and mode for a directory that is not a symlink, and next is the real
// path of the directory (resolved holds no symlink). The pins directory
// itself is not checked here (see checkParentsAs).
func (w *parentWalk) enterDir(next string, info fs.FileInfo) {
	w.resolved = next
	if len(w.rest) > 0 {
		w.checkDir(next, info)
	}
}

// checkRoot checks the root directory root (for example "/") with checkDir:
// its owner, its mode and its ACL. A missing root is not an error, as for any
// other component. It returns only an Lstat error, without the fail rule: the
// caller applies it.
func (w *parentWalk) checkRoot(root string) error {
	info, err := os.Lstat(root)
	if safefile.IsMissing(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check the %s %s: %w", labelParent, root, err)
	}
	if info.IsDir() {
		w.checkDir(root, info)
	}
	return nil
}

// followSymlink handles the symlink next, whose Lstat result is info. It
// counts the hop, checks the owner of the symlink (checkSymlinkOwner), reads
// the target and puts the components of the target in front of rest. An
// unsafe owner becomes the refusal of the walk. It returns an error when the
// walk must stop, without the fail rule: the caller applies it.
func (w *parentWalk) followSymlink(next, label string, info fs.FileInfo) error {
	w.hops++
	if w.hops > maxSymlinks {
		return fmt.Errorf("check the parent directories of the pins directory %s: too many symlinks (more than %d) at %s",
			w.dir, maxSymlinks, next)
	}
	if err := checkSymlinkOwner(next, label, info, w.uid); err != nil {
		w.refusal = err
	}
	target, err := os.Readlink(next)
	if err != nil {
		return fmt.Errorf("check the %s %s: %w", label, next, err)
	}
	var targetRest []string
	if filepath.IsAbs(target) {
		// An absolute target starts again at the root.
		w.resolved, targetRest = splitRoot(target)
		if err := w.checkRoot(w.resolved); err != nil {
			return err
		}
	} else {
		// A relative target starts in the directory that holds the symlink,
		// which is resolved.
		targetRest = splitPath(target)
	}
	// Walk the target first, then the components after the symlink.
	// slices.Concat makes a new slice, so rest and targetRest do not share
	// memory.
	w.rest = slices.Concat(targetRest, w.rest)
	return nil
}

// splitRoot splits the absolute path p into its root directory (the volume
// name, which is empty on Unix, and one separator) and its other components
// (see splitPath).
func splitRoot(p string) (root string, rest []string) {
	vol := filepath.VolumeName(p)
	return vol + string(filepath.Separator), splitPath(p[len(vol):])
}

// splitPath splits the path p into its components. It drops empty components
// (from a leading, trailing or double separator) and "." components, which
// name the same directory. It keeps "..": its meaning depends on the
// symlinks before it, so checkParentsAs handles it on the resolved path.
// filepath.FromSlash makes "/" a separator on Windows too; on Unix it does
// nothing.
func splitPath(p string) []string {
	var parts []string
	for c := range strings.SplitSeq(filepath.FromSlash(p), string(filepath.Separator)) {
		if c != "" && c != "." {
			parts = append(parts, c)
		}
	}
	return parts
}
