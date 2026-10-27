package pins

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Ducarv/mcpmoat/internal/safefile"
)

// ErrInsecurePermissions means that the pins directory or pins.json belongs to
// another user, that its group or other users can write it, or that its ACL
// lets a user or group write it (macOS only, see checkACL). It also means that
// a parent directory of the pins directory lets another user swap, rename or
// remove the pins directory (see checkParents). Such a path could let another
// user change the pins and hide a rug-pull (T2), so Load and Save refuse it.
// They never change the mode of an existing path: the user must fix it. Use
// errors.Is to test for it.
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
// and checkFilePermByPath when it cannot open the file).
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

// checkFilePerm is checkDirPerm for pins.json. info is the Stat result of the
// open file, so the owner and the mode belong to the bytes that Load parses.
// It does not read the ACL: checkFileHandle adds that check.
func checkFilePerm(path string, info fs.FileInfo) error {
	return checkOwnerAndMode(path, kindFile, info, os.Geteuid())
}

// checkFileHandle is the full check of the open pins.json f: the owner and
// the mode (checkFilePerm), then the ACL (checkACL, macOS only). info is the
// result of f.Stat, which the caller also uses for the size check, so both
// checks see the same file. info must not be nil. path is for the error text
// only. The error wraps ErrInsecurePermissions.
//
// Load calls it after f.Stat and before it reads the data, so it never reads
// the bytes of an unsafe file.
func checkFileHandle(path string, f *os.File, info fs.FileInfo) error {
	if err := checkFilePerm(path, info); err != nil {
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
// remove the pins directory (checkParentOwnerAndMode, Unix only). Then the
// next run would see a first run and pin the current tools without an alert
// (T2). It checks for the current user (os.Geteuid). See checkParentsAs.
func checkParents(dir string) error {
	return checkParentsAs(dir, os.Geteuid())
}

// checkParentsAs is checkParents for the user uid. uid is a parameter, so a
// test can fake a foreign owner without root.
//
// It checks the ancestors of dir, from filepath.Dir(dir) up to the root
// directory (on Windows, the volume root). It does not check dir itself:
// checkDirHandle and checkDirPerm do that. A relative dir is made absolute
// first. dir can be missing (a first run): an ancestor that does not exist is
// skipped, so the nearest existing ancestor, in which Save creates the pins
// directory, and all directories above it are still checked. An ancestor that
// is not a directory is skipped too: then the pins directory cannot exist, and
// checkFirstRun (Load) or MkdirAll (Save) reports the problem.
//
// It walks two paths and checks each directory once:
//   - the lexical path, for example ~/.config/mcpmoat. Each ancestor is read
//     with os.Stat, which follows symlinks. On macOS /var and /tmp are
//     symlinks with mode 0777; their targets are checked, so they pass. The
//     lexical walk also covers the directory that holds a symlink, so nobody
//     else can replace the symlink.
//   - the path after filepath.EvalSymlinks, for example /data/cfg/mcpmoat when
//     ~/.config is a symlink to /data/cfg. Then /data is checked too. When dir
//     does not exist, the nearest existing ancestor is resolved and the
//     missing part is added again.
//
// The first unsafe ancestor gives the error. A Stat or EvalSymlinks error
// other than "missing" (see safefile.IsMissing) is an error that names the
// path.
//
// The check is by path, by design. When no other user (only root) can write
// any parent, no other user can swap a component of the path between this
// check and the open, so the path race does not help an attacker.
func checkParentsAs(dir string, uid int) error {
	abs, err := filepath.Abs(dir) // Abs also cleans the path.
	if err != nil {
		return fmt.Errorf("check the parent directories of the pins directory %s: %w", dir, err)
	}
	resolved, err := resolveExisting(abs)
	if err != nil {
		return fmt.Errorf("check the parent directories of the pins directory %s: %w", dir, err)
	}

	// A map used as a set: the value is not used, only the key. struct{} has
	// size zero.
	checked := make(map[string]struct{})
	for _, target := range []string{abs, resolved} {
		if target == "" {
			continue
		}
		if err := checkAncestors(target, uid, checked); err != nil {
			return err
		}
	}
	return nil
}

// checkAncestors checks each ancestor of the absolute, clean path target with
// os.Stat and checkParentOwnerAndMode, from filepath.Dir(target) up to the
// root directory. It skips a path that is already in checked, and adds each
// path that it checked. It skips an ancestor that is missing or that is not a
// directory (see checkParentsAs).
func checkAncestors(target string, uid int, checked map[string]struct{}) error {
	p := target
	for {
		parent := filepath.Dir(p)
		if parent == p {
			// filepath.Dir of the root directory is the root directory.
			return nil
		}
		p = parent
		if _, done := checked[p]; done {
			continue
		}
		checked[p] = struct{}{}

		info, err := os.Stat(p)
		if safefile.IsMissing(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("check the parent directory %s of the pins directory: %w", p, err)
		}
		if !info.IsDir() {
			continue
		}
		if err := checkParentOwnerAndMode(p, info, uid); err != nil {
			return err
		}
	}
}

// resolveExisting returns the absolute, clean path abs with all symlinks
// resolved (filepath.EvalSymlinks). When abs does not exist, it resolves the
// nearest existing ancestor and adds the missing part of the path again. It
// returns "" and no error when no part of the path resolves. An EvalSymlinks
// error other than "missing" (see safefile.IsMissing) is an error.
func resolveExisting(abs string) (string, error) {
	p := abs
	for {
		target, err := filepath.EvalSymlinks(p)
		if err == nil {
			// p is a prefix of abs, so rest is the missing part of abs, or "."
			// when p is abs.
			rest, err := filepath.Rel(p, abs)
			if err != nil {
				return "", err
			}
			return filepath.Join(target, rest), nil
		}
		if !safefile.IsMissing(err) {
			return "", err
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", nil
		}
		p = parent
	}
}
