package pins

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// ErrLocked means that another process held the lock on the pins directory
// for the whole wait time. Normally that is another mcpmoat run, but the lock
// is an advisory flock(2) on the directory, so any local process that can open
// the directory can hold it. The caller can try again later. Test for it with
// errors.Is.
var ErrLocked = errors.New("the pins file is locked by another process")

// errLockUnsupported means that the operating system or the file system
// cannot lock the pins directory. tryLock returns it (lock_unix.go and
// lock_other.go), and lock then goes on without the lock, so the caller can
// warn once.
var errLockUnsupported = errors.New("file locking is not supported here")

// defaultLockPoll is the time between two lock attempts when locker.poll is
// zero.
const defaultLockPoll = 50 * time.Millisecond

// locker takes the advisory lock on the pins directory, so two parallel runs
// cannot lose each other's pins.
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

// lock takes an exclusive advisory lock on d, the open handle of the pins
// directory. The caller owns d and must keep it open while it holds the lock.
//
// The results are:
//   - (release, true, nil): this run holds the lock. Call release when done.
//   - (release, false, nil): the system or the file system cannot lock d
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
// release is never nil, so the caller can defer it on every path. It is safe
// to call more than once. It releases the lock but does not close d.
//
// Why lock polls and does not use a blocking flock: a blocking flock cannot
// be stopped by ctx or by Ctrl-C. Go installs its signal handlers with
// SA_RESTART, so the kernel restarts the call after a signal and the run
// would hang until the other run ends.
func (l locker) lock(ctx context.Context, d *os.File) (release func(), locked bool, err error) {
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
	noop := func() {}

	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return noop, false, fmt.Errorf("lock pins directory %s: %w", d.Name(), ctxErr)
		}

		acquired, tryErr := try(d)
		switch {
		case errors.Is(tryErr, errLockUnsupported):
			return noop, false, nil
		case tryErr != nil:
			return noop, false, fmt.Errorf("lock pins directory %s: %w", d.Name(), tryErr)
		case acquired:
			return releaser(d), true, nil
		}

		// The lock is busy.
		if l.onBusy != nil {
			l.onBusy()
		}
		left := time.Until(deadline)
		if l.wait <= 0 || left <= 0 {
			return noop, false, fmt.Errorf("lock pins directory %s: %w", d.Name(), ErrLocked)
		}

		// Do not sleep past the deadline: the last attempt then happens at
		// the deadline, not up to one poll interval after it.
		timer := time.NewTimer(min(poll, left))
		select {
		case <-ctx.Done():
			timer.Stop()
			return noop, false, fmt.Errorf("lock pins directory %s: %w", d.Name(), ctx.Err())
		case <-timer.C:
		}
	}
}

// releaser returns the release function for a lock that locker.lock took on
// d. The function unlocks d once; later calls do nothing. It does not close
// d, because the caller owns the handle.
func releaser(d *os.File) func() {
	// sync.OnceFunc returns a function that runs its argument on the first
	// call only.
	return sync.OnceFunc(func() {
		// Ignore the error: the caller closes d later, and closing the handle
		// releases the lock anyway.
		_ = unlock(d)
	})
}
