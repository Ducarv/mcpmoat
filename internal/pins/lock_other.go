//go:build !unix

package pins

import (
	"fmt"
	"os"
)

// lockOpenFlags are the flags of the open of the pins lock file
// (openLockFile) on systems that are not Unix. There is no named pipe (FIFO)
// in the file system there, so the open needs no O_NONBLOCK. See the Unix
// version for the reasons.
const lockOpenFlags = os.O_RDWR

// lockSwappedError is the error of openLockFile when the open lock file at
// lockPath is not the directory entry itself: a symlink, or a file that was
// swapped after the open. It wraps ErrInsecurePermissions. It quotes the path
// with %q, because shellQuote (a POSIX shell quote) exists only on Unix.
func lockSwappedError(lockPath string) error {
	return fmt.Errorf("pins lock file %s is not safe: it is a symlink or was swapped while it was opened (fix: remove %q, then mcpmoat makes a new one): %w",
		lockPath, lockPath, ErrInsecurePermissions)
}

// tryLock never takes a lock on systems that are not Unix. It always returns
// errLockUnsupported (declared in lock.go), so the caller warns and goes on
// without the lock. LoadLocked still opens and checks the lock file there, so
// the code path is the same on every system.
// Windows is a non-goal (PRD section 2.2). See the Unix version for the
// results that a real lock gives.
func tryLock(*os.File) (bool, error) {
	return false, errLockUnsupported
}

// unlock does nothing on systems that are not Unix, because tryLock never
// takes a lock there.
func unlock(*os.File) error {
	return nil
}
