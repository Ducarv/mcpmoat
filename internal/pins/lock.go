package pins

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrLocked means that another process held the lock on the pins lock file
// (see lockSuffix) for the whole wait time. Normally that is another mcpmoat
// run. The lock is an advisory flock(2), and flock works on any open
// descriptor, so any process that can open the lock file can hold it. That is
// why LoadLocked refuses a lock file that another user can open
// (checkLockFile and checkLockFileACL): then only the current user and root
// can hold the lock. The caller can try again later. Test for it with
// errors.Is.
//
// ErrLocked means only "another holder has the lock". An error that stops
// LoadLocked from opening or creating the lock file, for example in a
// read-only pins directory, does not wrap it.
var ErrLocked = errors.New("the pins file is locked by another process")

// errLockUnsupported means that the operating system or the file system
// cannot lock the pins lock file. tryLock returns it (lock_unix.go and
// lock_other.go), and lock then goes on without the lock, so the caller can
// warn once.
var errLockUnsupported = errors.New("file locking is not supported here")

// lockSuffix is the end of the name of the pins lock file. The lock file is
// the pins file name plus lockSuffix, in the pins directory: pins.json.lock
// for pins.json.
//
// Why a separate lock file and not the pins directory itself: flock(2) needs
// only a read-only descriptor, and the pins directory may have mode 0755. So
// any local user could open the directory and hold its lock for as long as
// they want, and every scan with a new server and every pin --accept would
// fail. The lock file has mode 0600 and checkLockFile refuses any group or
// other access, so another user cannot open it.
//
// The lock file is empty and stays in the directory after the run. Its
// content has no meaning: only the lock on it counts.
const lockSuffix = ".lock"

// openLockFile opens the pins lock file of the pins file path (path plus
// lockSuffix) through root, the open os.Root of the pins directory, and
// checks it. It creates a missing lock file with mode 0o600. The caller owns
// the file, locks it (locker.lock) and closes it.
//
// The open goes through root, so a symlink cannot make it leave the pins
// directory, and it uses lockOpenFlags (lock_unix.go): O_NONBLOCK makes the
// open of a named pipe (FIFO) return at once, and the check below then
// refuses it. The file is open for reading and writing: on Linux, flock on
// NFS is emulated with a byte-range lock, which needs a descriptor that can
// write.
//
// The checks run on the open file, in this order:
//   - The open file must be the directory entry itself (os.SameFile of
//     f.Stat and root.Lstat). A symlink, also one to another file in the pins
//     directory, or an entry that was swapped after the open is refused.
//   - checkLockFile: a regular file that the current user owns, with no
//     group or other access (mode 0600 passes, 0644 is refused).
//   - checkLockFileACL (macOS only): no ACL entry that lets a user or group
//     open the file.
//
// A refusal wraps ErrInsecurePermissions and names the lock file. openLockFile
// never changes the mode of an existing lock file: an unsafe one is refused,
// and the fix hint is to remove it. It sets mode 0o600 only on a file that it
// has just created, so the umask cannot leave a file that the next run cannot
// open for writing.
//
// Any other error names the lock file and the reason, for example "create the
// pins lock file <path>: permission denied" in a read-only pins directory
// (mode 0500) that has no lock file yet. Such an error does not wrap
// ErrLocked: no other process holds the lock. A read-only pins directory with
// an existing lock file needs no create, so the lock works there. When the
// user owns the lock file with no group or other access but may not open it
// (mode 0400 or 0000), the error also gives the fix hint: remove the file.
// The errors have no "read <path>" prefix: the caller adds it
// (prefixUnlessRefusal).
func openLockFile(root *os.Root, path string) (*os.File, error) {
	lockPath := path + lockSuffix
	name := filepath.Base(lockPath)

	// root.OpenFile is a method value: a function that calls OpenFile on this
	// root.
	f, created, err := openOrCreate(root.OpenFile, lockPath, name)
	if err != nil {
		// A lock file that the user may not open, for example one that another
		// user owns, gives only "permission denied". Check the entry itself
		// (Lstat does not follow a symlink), so the user gets the refusal and
		// its fix hint instead. A symlink is refused here too.
		if info, lerr := root.Lstat(name); lerr == nil {
			if checkErr := checkLockFile(lockPath, info, os.Geteuid()); checkErr != nil {
				return nil, checkErr
			}
			// The entry passed the check: the user owns a regular file with
			// no group or other access, and still cannot open it, for
			// example mode 0400 or 0000 after a run was killed between the
			// create and the chmod. That does not clear by itself, and
			// removing the file is the only fix.
			if errors.Is(err, fs.ErrPermission) && info.Mode().IsRegular() {
				return nil, fmt.Errorf("%w (fix: %s)", err, lockRemoveFix(lockPath, info))
			}
		}
		return nil, err
	}

	if err := checkOpenLockFile(root, lockPath, name, f, created); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// openFileFunc opens the file name with flag and perm, as os.Root.OpenFile
// does. openOrCreate takes one, so a test can run code between its steps.
type openFileFunc func(name string, flag int, perm fs.FileMode) (*os.File, error)

// maxLockCreates is the largest number of times that openOrCreate tries to
// create the lock file.
const maxLockCreates = 3

// openOrCreate opens the lock file name with open (root.OpenFile of the pins
// directory), and creates it when it is missing. lockPath is the path of the
// lock file, for the error texts. created is true when this call created the
// file; it is false when it opened a file that already existed, and on an
// error.
//
// It opens an existing file first, with no O_CREATE. So a read-only pins
// directory with an existing lock file works, and the common case is one
// open. Only when the file is missing does it create it, with O_EXCL, so the
// create never follows a symlink and created is true only for a file that
// this call made. When another run creates the file between the open and the
// create, the create fails with "file exists", and openOrCreate opens that
// file. When the file is gone again before that open (another run removed
// it), openOrCreate creates it again, at most maxLockCreates times in all.
//
// On an error, f is nil, and the error names lockPath and the step that
// failed: "create the pins lock file <lockPath>: <cause>" when the create
// failed (for example EACCES or EROFS in a read-only pins directory), and
// "open the pins lock file <lockPath>: <cause>" otherwise. The cause has no
// *fs.PathError around it (see pathErrCause).
func openOrCreate(open openFileFunc, lockPath, name string) (f *os.File, created bool, err error) {
	f, err = open(name, lockOpenFlags, 0)
	switch {
	case err == nil:
		return f, false, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, false, lockOpenError("open", lockPath, err)
	}
	for try := 1; ; try++ {
		f, err = open(name, lockOpenFlags|os.O_CREATE|os.O_EXCL, fileMode)
		switch {
		case err == nil:
			return f, true, nil
		case !errors.Is(err, fs.ErrExist):
			return nil, false, lockOpenError("create", lockPath, err)
		}
		// The name exists now: another run created the file, or the name is a
		// symlink with a missing target (O_EXCL does not follow it). Open it
		// again; the caller refuses a symlink.
		//
		// This open can fail with "permission denied" for a moment: another
		// run created the file with a very narrow umask (for example 0o777
		// gives mode 0000) and has not set mode 0o600 yet. Then this run
		// fails with exit code 2, and a second run works. When that other
		// run dies before the chmod, the mode stays, and openLockFile adds
		// the fix hint to the error. That is rare, so there is no wait and
		// no retry for it.
		f, err = open(name, lockOpenFlags, 0)
		switch {
		case err == nil:
			return f, false, nil
		case !errors.Is(err, fs.ErrNotExist) || try == maxLockCreates:
			// A symlink with a missing target gets "not exist" on each try
			// and ends here at the last try; the caller then refuses it.
			return nil, false, lockOpenError("open", lockPath, err)
		}
		// The file was removed between the create and this open: create it
		// again.
	}
}

// lockOpenError is an error of openOrCreate: err, the error of the step
// ("open" or "create"), for the lock file lockPath.
func lockOpenError(step, lockPath string, err error) error {
	return fmt.Errorf("%s the pins lock file %s: %w", step, lockPath, pathErrCause(err))
}

// lockSwappedError is the error of openLockFile when the open lock file at
// lockPath is not the directory entry itself: a symlink, or a file that was
// swapped after the open. It wraps ErrInsecurePermissions. entry is the Lstat
// result of the directory entry, or nil when the entry is gone. The fix hint
// is the one of checkLockFile (lockRemoveFix): remove the entry, and the next
// run makes a new lock file.
func lockSwappedError(lockPath string, entry fs.FileInfo) error {
	return fmt.Errorf("%s %s is not safe: it is a symlink or was swapped while it was opened (fix: %s): %w",
		labelLock, lockPath, lockRemoveFix(lockPath, entry), ErrInsecurePermissions)
}

// checkOpenLockFile checks f, the open lock file name in root (see
// openLockFile). lockPath is the path of the lock file, for the error texts.
// When created is true, it first sets mode 0o600 on f: OpenFile used that
// mode, but the umask can remove bits from it. The chmod works on the open
// descriptor, so a swapped name cannot redirect it.
func checkOpenLockFile(root *os.Root, lockPath, name string, f *os.File, created bool) error {
	if created {
		if err := f.Chmod(fileMode); err != nil {
			return fmt.Errorf("set the mode of the pins lock file %s: %w", lockPath, pathErrCause(err))
		}
	}

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("check the pins lock file %s: %w", lockPath, pathErrCause(err))
	}
	// os.Root follows a symlink that stays in the directory, so f can be the
	// target of a symlink. This is the same check as for pins.json
	// (readChecked): a symlink, an entry that another file replaced after the
	// open, and an entry that is gone are all refused (see sameEntry).
	entry, same, err := sameEntry(root.Lstat, name, info)
	if err != nil {
		return fmt.Errorf("check the pins lock file %s: %w", lockPath, pathErrCause(err))
	}
	if !same {
		return lockSwappedError(lockPath, entry)
	}

	if err := checkLockFile(lockPath, info, os.Geteuid()); err != nil {
		return err
	}
	return checkLockFileACL(lockPath, f)
}

// pathErrCause returns the cause of err when err is a *fs.PathError, and err
// itself otherwise. The errors of os.Root name only the base name, for
// example "openat pins.json.lock: permission denied". The callers name the
// full path themselves, so the cause alone ("permission denied") is enough.
// errors.Is still works on the result, for example with fs.ErrPermission.
func pathErrCause(err error) error {
	if pe, ok := errors.AsType[*fs.PathError](err); ok {
		return pe.Err
	}
	return err
}

// defaultLockPoll is the time between two lock attempts when locker.poll is
// zero.
const defaultLockPoll = 50 * time.Millisecond

// locker takes the advisory lock on the pins lock file (see lockSuffix), so
// two parallel runs cannot lose each other's pins.
//
// The zero value tries once, does not wait and uses the real lock function.
// The function fields exist so that a test can inject a busy or an
// unsupported result, or run code at a fixed step of LoadLocked. We pass
// them in a struct instead of package-level variables, so there is no global
// mutable state and the tests can run in parallel (the same pattern as
// atomicWriter).
type locker struct {
	// wait is how long lock keeps trying while another run holds the lock.
	// Zero (or a negative value) means: try once.
	wait time.Duration
	// poll is the time between two attempts. Zero means defaultLockPoll.
	poll time.Duration
	// onBusy, when not nil, runs each time an attempt finds the lock busy.
	// A test can use it to synchronise with a channel instead of time.Sleep.
	onBusy func()
	// tryLock, when not nil, replaces the package function tryLock.
	tryLock func(*os.File) (bool, error)
	// afterEnsureDir, when not nil, runs in LoadLocked after ensurePinsDir
	// and before the second check of the parent directories. A test uses it
	// to change a parent between the two checks, as another user could.
	afterEnsureDir func()
}

// lock takes an exclusive advisory lock on f, the open pins lock file (see
// openLockFile). The caller owns f and must keep it open while it holds the
// lock.
//
// The results are:
//   - (release, true, nil): this run holds the lock. Call release when done.
//   - (release, false, nil): the system or the file system cannot lock f
//     (errLockUnsupported). The caller warns once and goes on without the
//     lock.
//   - (release, false, err) where errors.Is(err, ErrLocked): another run held
//     the lock for the whole wait time. lock uses its own deadline, not a
//     context timeout, so this case never wraps a context error.
//   - (release, false, err) where errors.Is(err, context.Canceled) or
//     errors.Is(err, context.DeadlineExceeded): the caller's ctx ended first.
//     These errors always come from ctx, never from wait.
//   - (release, false, err) for any other failure.
//
// The errors do not name the lock file: the caller (loadLocked) adds the path
// of the pins file, so the path shows once.
//
// release is never nil, so the caller can defer it on every path. It is safe
// to call more than once. It releases the lock but does not close f.
//
// Why lock polls and does not use a blocking flock: a blocking flock cannot
// be stopped by ctx or by Ctrl-C. Go installs its signal handlers with
// SA_RESTART, so the kernel restarts the call after a signal and the run
// would hang until the other run ends.
func (l locker) lock(ctx context.Context, f *os.File) (release func(), locked bool, err error) {
	try := l.tryLock
	if try == nil {
		try = tryLock
	}
	poll := l.poll
	if poll <= 0 {
		poll = defaultLockPoll
	}
	// Compute the deadline once, so the total wait does not grow with the
	// time that each attempt takes.
	deadline := time.Now().Add(l.wait)

	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return noop, false, fmt.Errorf("lock the pins lock file: %w", ctxErr)
		}

		acquired, tryErr := try(f)
		switch {
		case errors.Is(tryErr, errLockUnsupported):
			return noop, false, nil
		case tryErr != nil:
			return noop, false, fmt.Errorf("lock the pins lock file: %w", tryErr)
		case acquired:
			return releaser(f), true, nil
		}

		// The lock is busy.
		if l.onBusy != nil {
			l.onBusy()
		}
		left := time.Until(deadline)
		if l.wait <= 0 || left <= 0 {
			return noop, false, fmt.Errorf("lock the pins lock file: %w", ErrLocked)
		}

		// Do not sleep past the deadline: the last attempt then happens at
		// the deadline, not up to one poll interval after it.
		timer := time.NewTimer(min(poll, left))
		select {
		case <-ctx.Done():
			timer.Stop()
			return noop, false, fmt.Errorf("lock the pins lock file: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

// releaser returns the release function for a lock that locker.lock took on
// f. The function unlocks f once; later calls do nothing. It does not close
// f, because the caller owns the handle.
func releaser(f *os.File) func() {
	// sync.OnceFunc returns a function that runs its argument on the first
	// call only.
	return sync.OnceFunc(func() {
		// Ignore the error: the caller closes f later, and closing the handle
		// releases the lock anyway.
		_ = unlock(f)
	})
}
