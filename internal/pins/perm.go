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
// another user, or that its group or other users can write it. Such a path
// could let another user change the pins and hide a rug-pull (T2), so Load and
// Save refuse it. They never change the mode of an existing path: the user
// must fix it. Use errors.Is to test for it.
var ErrInsecurePermissions = errors.New("insecure permissions")

// The kind of path in a permission error: the text says "pins directory" or
// "pins file".
const (
	kindDir  = "directory"
	kindFile = "file"
)

// checkDirPerm returns an error that wraps ErrInsecurePermissions when the
// pins directory at path is owned by another user or is writable by its group
// or by others. Load and writeFile call it for the pins directory. Load checks
// pins.json on the open file instead (checkFilePerm, and checkFilePermByPath
// when it cannot open the file).
//
// It follows symlinks (os.Stat), so it checks the target. A missing path is
// not an error: it is the first run, and Save creates the directory with mode
// 0o700. A path below a regular file (ENOTDIR) counts as missing too. A path
// that is not a directory also passes: the later read reports "not a
// directory" with its own text, and the mode of a regular file is not the mode
// of a directory. Any other Stat error is an error. The error text never holds
// file content.
//
// The path can change between this check and the later read or write. Only a
// process that can write the directory or one of its parents can do that, and
// it could change pins.json directly, so the race is accepted.
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

// checkFilePerm is checkDirPerm for pins.json. info is the Stat result of the
// open file that Load read, so the owner and the mode belong to the bytes that
// Load parses.
func checkFilePerm(path string, info fs.FileInfo) error {
	return checkOwnerAndMode(path, kindFile, info, os.Geteuid())
}

// checkFilePermByPath is for a pins.json that Load could not open because the
// current user may not read it. It returns an error that wraps
// ErrInsecurePermissions when another user (not uid) owns the file, or when
// its group or others can write it. Then the user gets the fix hint and not
// only "permission denied". It returns nil when it cannot tell: a Stat error,
// or a path that is not a regular file. The caller then reports the read error.
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
