//go:build unix

package pins

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// errLockUnsupported means that the operating system or the file system
// cannot lock the pins directory. The caller decides what to do (for example,
// go on without the lock and warn). The version for systems that are not Unix
// declares the same name.
var errLockUnsupported = errors.New("file locking is not supported here")

// tryLock tries to take an exclusive advisory lock on the open file f
// (normally the handle of the pins directory). It does not wait.
//
// The results are:
//   - (true, nil): this handle now holds the lock.
//   - (false, nil): another holder has the lock (busy). Try again later.
//   - (false, err) where errors.Is(err, errLockUnsupported): the system or
//     the file system cannot lock this file.
//   - (false, err) for any other failure.
//
// The lock is flock(2). It belongs to the open file description, not to the
// process. So two different os.Open calls on the same directory get two
// locks that exclude each other, also in one process: a second tryLock on a
// second handle returns busy. The unit tests rely on this. A second tryLock
// on the same handle succeeds again (flock converts an existing lock).
//
// The lock is advisory: it only stops other callers of tryLock. It does not
// stop a process that reads or writes the files without the lock.
//
// Closing f releases the lock. unlock releases it explicitly.
func tryLock(f *os.File) (acquired bool, err error) {
	errno, err := flock(f, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return false, err
	}
	switch {
	case errno == 0:
		return true, nil
	case errors.Is(errno, syscall.EWOULDBLOCK), errors.Is(errno, syscall.EAGAIN):
		return false, nil
	case errors.Is(errno, syscall.ENOTSUP), errors.Is(errno, syscall.EOPNOTSUPP),
		errors.Is(errno, syscall.ENOLCK), errors.Is(errno, syscall.ENOSYS):
		return false, fmt.Errorf("lock %s: %w: %w", f.Name(), errLockUnsupported, errno)
	default:
		return false, fmt.Errorf("lock %s: %w", f.Name(), errno)
	}
}

// unlock releases the lock that tryLock took on f. It is safe to call when f
// holds no lock: flock then does nothing and returns no error.
func unlock(f *os.File) error {
	errno, err := flock(f, syscall.LOCK_UN)
	if err != nil {
		return err
	}
	if errno != 0 {
		return fmt.Errorf("unlock %s: %w", f.Name(), errno)
	}
	return nil
}

// flock calls flock(2) with how on the descriptor of f. It returns the errno
// of the call (0 on success) and, separately, an error when the descriptor is
// not usable (for example, f is closed).
//
// It uses SyscallConn and Control instead of f.Fd: Fd puts the descriptor in
// blocking mode, and the descriptor is only valid while Control runs, so a
// parallel Close cannot reuse it under us. The call repeats on EINTR, which a
// signal can cause.
func flock(f *os.File, how int) (syscall.Errno, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("flock %s: %w", f.Name(), err)
	}
	var errno syscall.Errno
	ctrlErr := rc.Control(func(fd uintptr) {
		for {
			// The descriptor fits in an int: the kernel returned it as an int.
			callErr := syscall.Flock(int(fd), how)
			if callErr == nil {
				errno = 0
				return
			}
			var e syscall.Errno
			if !errors.As(callErr, &e) {
				// syscall.Flock only returns Errno values. Treat anything
				// else as a generic I/O error.
				errno = syscall.EIO
				return
			}
			if e == syscall.EINTR {
				continue
			}
			errno = e
			return
		}
	})
	if ctrlErr != nil {
		return 0, fmt.Errorf("flock %s: %w", f.Name(), ctrlErr)
	}
	return errno, nil
}
