//go:build !unix

package pins

import (
	"fmt"
	"io/fs"
	"os"
)

// lockOpenFlags are the flags of the open of the pins lock file
// (openLockFile) on systems that are not Unix. There is no named pipe (FIFO)
// in the file system there, so the open needs no O_NONBLOCK. See the Unix
// version for the reasons.
const lockOpenFlags = os.O_RDWR

// lockRemoveFix is the fix hint for a pins lock file at lockPath that mcpmoat
// refuses or cannot open: remove the entry, and the next run makes a new lock
// file. It quotes the path with %q, because shellQuote (a POSIX shell quote)
// and lockFileFix exist only on Unix, so it does not use the entry (see the
// Unix version).
func lockRemoveFix(lockPath string, _ fs.FileInfo) string {
	return fmt.Sprintf("remove %q, then mcpmoat makes a new one", lockPath)
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
