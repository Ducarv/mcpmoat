//go:build unix

package pins

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

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
	return lockErrno(errno)
}

// lockErrno turns errno, the result of a non-blocking flock(2), into the
// results of tryLock. It is a separate pure function, so a test can check each
// errno without a file system that returns it. The errors do not name the
// file: the caller adds the path.
//
// The errors.Is calls compare errno with each constant. A switch on the value
// would not compile on Linux: there EWOULDBLOCK is EAGAIN and ENOTSUP is
// EOPNOTSUPP, and a switch cannot list the same constant twice.
func lockErrno(errno syscall.Errno) (acquired bool, err error) {
	switch {
	case errno == 0:
		return true, nil
	case errors.Is(errno, syscall.EWOULDBLOCK), errors.Is(errno, syscall.EAGAIN):
		return false, nil
	// EBADF and EINVAL: on Linux, flock on NFS is emulated with byte-range
	// locks, which need a descriptor open for writing, so our read-only
	// directory handle gets EBADF. Some FUSE and network file systems answer
	// EINVAL. flock runs while the descriptor is valid (see flock), so here
	// these errnos can only mean that the file system cannot lock.
	case errors.Is(errno, syscall.ENOTSUP), errors.Is(errno, syscall.EOPNOTSUPP),
		errors.Is(errno, syscall.ENOLCK), errors.Is(errno, syscall.ENOSYS),
		errors.Is(errno, syscall.EBADF), errors.Is(errno, syscall.EINVAL):
		// Two %w verbs: errors.Is finds both errLockUnsupported and errno.
		return false, fmt.Errorf("%w: %w", errLockUnsupported, errno)
	default:
		return false, errno
	}
}

// unlock releases the lock that tryLock took on f. It is safe to call when f
// holds no lock: flock then does nothing and returns no error. Like the errors
// of tryLock, the error does not name the file.
func unlock(f *os.File) error {
	errno, err := flock(f, syscall.LOCK_UN)
	if err != nil {
		return err
	}
	if errno != 0 {
		return fmt.Errorf("unlock: %w", errno)
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
		return 0, fmt.Errorf("flock: %w", err)
	}
	var errno syscall.Errno
	ctrlErr := rc.Control(func(fd uintptr) {
		for {
			// The descriptor fits in an int: the kernel returned it as an int.
			callErr := syscall.Flock(int(fd), how)
			if callErr == nil {
				// errno keeps its zero value: success.
				return
			}
			// errors.AsType returns the first error in the chain that has the
			// type syscall.Errno, and false when there is none.
			e, ok := errors.AsType[syscall.Errno](callErr)
			if !ok {
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
		return 0, fmt.Errorf("flock: %w", ctrlErr)
	}
	return errno, nil
}
