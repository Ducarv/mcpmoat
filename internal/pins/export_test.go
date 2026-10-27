package pins

import (
	"context"
	"os"
	"time"
)

// Exports of package pins for the external test package pins_test.
const (
	MaxFileSize   = maxFileSize
	MaxServerSize = maxServerSize
)

// Test helpers from atomic_test.go, shared with the external test package.
var (
	WantPerm = wantPerm
	ReadFile = readFile
	DirNames = dirNames
)

// CheckFirstRunWith exports checkFirstRunWith, so a test can fake lstat and
// stat.
var CheckFirstRunWith = checkFirstRunWith

// ErrLockUnsupported exports errLockUnsupported, so a test can inject a file
// system that cannot lock.
var ErrLockUnsupported = errLockUnsupported

// LockHooks holds the fields of a locker that a test sets. A nil function
// uses the real one (or does nothing, for a hook); a zero Poll uses
// defaultLockPoll.
type LockHooks struct {
	Wait           time.Duration
	Poll           time.Duration
	OnBusy         func()
	TryLock        func(*os.File) (bool, error)
	AfterEnsureDir func()
}

// LoadLockedWith is LoadLocked with a locker built from h.
func LoadLockedWith(ctx context.Context, path string, h LockHooks) (*Store, func(), error) {
	return loadLocked(ctx, path, locker{
		wait:           h.Wait,
		poll:           h.Poll,
		onBusy:         h.OnBusy,
		tryLock:        h.TryLock,
		afterEnsureDir: h.AfterEnsureDir,
	})
}

// TrackedFileSize returns the size of the file that Save would write, as the
// Store tracks it (fileSize of the tracked entries).
func (s *Store) TrackedFileSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fileSize(len(s.servers), s.entryBytes)
}
