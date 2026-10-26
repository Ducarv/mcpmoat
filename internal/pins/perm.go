package pins

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"
)

// ErrInsecurePermissions means that the pins directory or pins.json belongs to
// another user, or that its group or other users can write it. Such a path
// could let another user change the pins and hide a rug-pull (T2), so Load and
// Save refuse it. They never change the mode of an existing path: the user
// must fix it. Use errors.Is to test for it.
var ErrInsecurePermissions = errors.New("insecure permissions")

// checkStorePerm returns an error that wraps ErrInsecurePermissions when the
// path is owned by another user or is writable by its group or by others. kind
// is "directory" or "file" and only names the path in the error text. Load and
// Save call it for the pins directory. Load checks pins.json on the open file
// instead (checkOwnerAndMode).
//
// It follows symlinks (os.Stat), so it checks the target. A missing path is
// not an error: it is the first run, and Save creates the directory with mode
// 0o700. A path below a regular file (ENOTDIR) counts as missing too, so the
// caller reports it with its own text, as it did before this check existed.
// Any other Stat error is an error. The error text never holds file content.
//
// The path can change between this check and the later read or write. Only a
// process that can already write the directory can do that, and it could
// change pins.json directly, so the race is accepted.
func checkStorePerm(path, kind string) error {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check the permissions of the pins %s %s: %w", kind, path, err)
	}
	return checkOwnerAndMode(path, kind, info, os.Geteuid())
}

// shellQuote returns s as one word for a POSIX shell: it wraps s in single
// quotes, and it replaces each single quote inside s with the four characters
// quote, backslash, quote, quote (close, escape, open). A user can paste the
// result into a shell command, also when the path holds spaces or shell
// metacharacters.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
