//go:build !unix

package pins

import (
	"errors"
	"os"
)

// errLockUnsupported means that the operating system or the file system
// cannot lock the pins directory. The caller decides what to do (for example,
// go on without the lock and warn). The Unix version declares the same name.
var errLockUnsupported = errors.New("file locking is not supported here")

// tryLock never takes a lock on systems that are not Unix. It always returns
// errLockUnsupported, so the caller warns and goes on without the lock.
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
