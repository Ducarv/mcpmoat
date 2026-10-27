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
// remove the pins directory, or that a symlink on the path to the pins
// directory belongs to another user (see checkParents). Such a path could let
// another user change the pins and hide a rug-pull (T2), so Load and Save
// refuse it. They never change the mode of an existing path: the user must fix
// it. Use errors.Is to test for it.
//
// The text of such an error names the unsafe path and starts with "pins
// directory", "pins file", "pins parent directory" or "cannot read the ACL".
// Load, LoadLocked and Save return it as it is, with no "read <path>" or "save
// <path>" prefix. Their other errors from the same checks, for example a
// failed Lstat or Readlink in checkParents, do not wrap ErrInsecurePermissions
// and get the prefix (see Load).
var ErrInsecurePermissions = errors.New("insecure permissions")

// The kind of path in a permission error: the text says "pins directory" or
// "pins file".
const (
	kindDir  = "directory"
	kindFile = "file"
)

// checkDirPerm returns an error that wraps ErrInsecurePermissions when the
// pins directory at path is owned by another user or is writable by its group
// or by others. Save calls it (in atomicWriter.writeFile) after it created a
// missing directory. Load checks the directory on its open handle instead
// (checkDirHandle), and it checks pins.json on the open file (checkFileHandle,
// and checkFilePermByPath when it cannot open the file). dirOpenError also
// calls it, by path, when Load or LoadLocked cannot open the directory, only
// to give a better error text than "permission denied".
//
// It follows symlinks (os.Stat), so it checks the target. A missing path is
// not an error: it is the first run, and Save creates the directory with mode
// 0o700. A path below a regular file (ENOTDIR) counts as missing too. A path
// that is not a directory also passes: the later read reports "not a
// directory" with its own text, and the mode of a regular file is not the mode
// of a directory. Any other Stat error is an error. The error text never holds
// file content.
//
// It does not read the ACL, because it has no open handle. The path can
// change between this check and the later read or write. Only a process that
// can write the directory or one of its parents can do that, and it could
// change pins.json directly, so the race is accepted.
func checkDirPerm(path string) error {
	info, err := os.Stat(path)
	if safefile.IsMissing(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check the permissions of the pins directory %s: %w", path, err)
	}
	if !info.IsDir() {
		return nil
	}
	return checkOwnerAndMode(path, kindDir, info, os.Geteuid())
}

// checkDirHandle is checkDirPerm for the open pins directory d, for example
// the handle that root.Open(".") gives for the os.Root of the pins directory.
// path is the path of the directory, for the error text only. It returns an
// error that wraps ErrInsecurePermissions when another user owns the directory,
// when its group or others can write it, or when its ACL lets a user or group
// write it (checkACL, macOS only).
//
// It reads the owner and the mode from d (d.Stat), not from path. So the
// checked directory is the directory that Load reads from, and a swap of the
// path after the open has no effect. A Stat error is an error, with the same
// text as in checkDirPerm. A handle that is not a directory is an error too:
// unlike checkDirPerm, there is no later read that reports it.
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
// remove the pins directory (checkParentOwnerAndMode, Unix only), or when
// another user owns a symlink on the path to dir, dir included
// (checkSymlinkOwner, Unix only). Then the next run would see a first run and
// pin the current tools without an alert (T2). It checks for the current user
// (os.Geteuid). See checkParentsAs.
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

// Labels of a path in the errors of checkParentsAs.
const (
	labelDir    = "pins directory"
	labelParent = "pins parent directory"
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
//     (checkParentOwnerAndMode). This covers the root directory, the
//     directory that holds each symlink, and each directory in the target of
//     a symlink. Each directory is checked once.
//   - The pins directory itself, after all symlinks: nothing.
//     checkDirHandle and checkDirPerm check its owner and mode.
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
// directory cannot exist, and checkFirstRun (Load) or MkdirAll (Save) reports
// the problem. On macOS /var and /tmp are symlinks that root owns, with
// targets in /private, so they pass.
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
// an attacker. This argument is for the mode bits, and it has one exception:
// on macOS an ACL can let another user write a directory whose mode bits are
// safe, and the walk does not read the ACLs of the parent directories (see
// docs/limits.md, issue #217).
func checkParentsAs(dir string, uid int) error {
	abs, err := filepath.Abs(dir) // Abs also cleans the path.
	if err != nil {
		return fmt.Errorf("check the parent directories of the pins directory %s: %w", dir, err)
	}

	// refusal is the last unsafe entry found so far.
	var refusal error
	// fail returns err, unless an unsafe entry was found before (see the doc).
	fail := func(err error) error {
		if refusal != nil {
			return refusal
		}
		return err
	}

	// checked is a set of the directories whose owner and mode are checked: a
	// map whose values are not used. struct{} has size zero.
	checked := make(map[string]struct{})
	checkParentDir := func(p string, info fs.FileInfo) {
		if _, done := checked[p]; done {
			return
		}
		checked[p] = struct{}{}
		if err := checkParentOwnerAndMode(p, info, uid); err != nil {
			refusal = err
		}
	}

	// resolved is the directory that the walk has reached, with no symlink in
	// it. rest holds the components that are still to walk.
	resolved, rest := splitRoot(abs)
	if len(rest) > 0 {
		// The root directory is a parent of the pins directory too.
		if err := checkRootDir(resolved, checkParentDir); err != nil {
			return fail(err)
		}
	}
	hops := 0
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		if c == ".." {
			// filepath.Dir of the root directory is the root directory, as in
			// the kernel.
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, c)
		label := labelParent
		if len(rest) == 0 {
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
			return fail(fmt.Errorf("check the %s %s: %w", label, next, err))
		}

		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			hops++
			if hops > maxSymlinks {
				return fail(fmt.Errorf("check the parent directories of the pins directory %s: too many symlinks (more than %d) at %s",
					dir, maxSymlinks, next))
			}
			if err := checkSymlinkOwner(next, label, info, uid); err != nil {
				refusal = err
			}
			target, err := os.Readlink(next)
			if err != nil {
				return fail(fmt.Errorf("check the %s %s: %w", label, next, err))
			}
			var targetRest []string
			if filepath.IsAbs(target) {
				// An absolute target starts again at the root.
				resolved, targetRest = splitRoot(target)
				if err := checkRootDir(resolved, checkParentDir); err != nil {
					return fail(err)
				}
			} else {
				// A relative target starts in the directory that holds the
				// symlink, which is resolved.
				targetRest = splitPath(target)
			}
			// Walk the target first, then the components after the symlink.
			// slices.Concat makes a new slice, so rest and targetRest do not
			// share memory.
			rest = slices.Concat(targetRest, rest)
		case info.IsDir():
			resolved = next
			if len(rest) > 0 {
				// A parent of the pins directory. Lstat and Stat give the same
				// owner and mode for a directory that is not a symlink.
				checkParentDir(next, info)
			}
		default:
			// Not a directory: the pins directory cannot exist below it.
			return refusal
		}
	}
	return refusal
}

// checkRootDir checks the root directory root (for example "/") with check,
// the parent check of checkParentsAs. A missing root is not an error, as for
// any other component.
func checkRootDir(root string, check func(string, fs.FileInfo)) error {
	info, err := os.Lstat(root)
	if safefile.IsMissing(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check the %s %s: %w", labelParent, root, err)
	}
	if info.IsDir() {
		check(root, info)
	}
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
