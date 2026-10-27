//go:build !unix

package pins

import "os"

// tryLock never takes a lock on systems that are not Unix. It always returns
// errLockUnsupported (declared in lock.go), so the caller warns and goes on
// without the lock.
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
