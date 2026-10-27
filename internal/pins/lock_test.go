//go:build unix

package pins_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/pins"
)

// lockTestMustLoad runs LoadLocked with no wait and fails the test on an
// error. The release function also runs at cleanup; a second call is safe.
func lockTestMustLoad(t *testing.T, path string) (*pins.Store, func()) {
	t.Helper()
	s, release, err := pins.LoadLocked(t.Context(), path, 0)
	if err != nil {
		t.Fatalf("LoadLocked(%q) error = %v, want nil", path, err)
	}
	t.Cleanup(release)
	return s, release
}

// lockTestOpenFDs returns the number of open file descriptors of the process,
// or -1 when /dev/fd cannot tell.
func lockTestOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil || len(entries) < 3 {
		return -1
	}
	return len(entries)
}

// TestLoadLockedSerialisesRuns runs two read-change-save cycles on one path.
// The second waits for the lock of the first, so it loads the pins that the
// first saved, and no update is lost.
func TestLoadLockedSerialisesRuns(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	first, releaseFirst := lockTestMustLoad(t, path)

	busy := make(chan struct{})
	var busyOnce sync.Once
	done := make(chan error, 1)
	go func() {
		second, release, err := pins.LoadLockedWith(t.Context(), path, pins.LockHooks{
			Wait:   time.Minute,
			Poll:   time.Millisecond,
			OnBusy: func() { busyOnce.Do(func() { close(busy) }) },
		})
		defer release()
		if err != nil {
			done <- err
			return
		}
		if err := second.Set(idB, storeTestPins("b", "h2")); err != nil {
			done <- err
			return
		}
		done <- second.Save()
	}()

	// The first run changes and saves only after the second saw the lock busy.
	select {
	case <-busy:
	case err := <-done:
		t.Fatalf("the second LoadLocked did not wait for the lock (error = %v)", err)
	}
	storeTestMustSet(t, first, idA, storeTestPins("a", "h1"))
	storeTestMustSave(t, first)
	releaseFirst()

	if err := <-done; err != nil {
		t.Fatalf("second run error = %v, want nil", err)
	}
	got := storeTestMustLoad(t, path)
	storeTestWantPins(t, got, idA, storeTestPins("a", "h1"))
	storeTestWantPins(t, got, idB, storeTestPins("b", "h2"))
}

func TestLoadLockedBusy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		wait time.Duration
	}{
		{"wait zero tries once", 0},
		{"short wait runs out", 20 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := storeTestPath(t)
			_, releaseFirst := lockTestMustLoad(t, path)

			var busyCalls int
			s, release, err := pins.LoadLockedWith(t.Context(), path, pins.LockHooks{
				Wait:   tt.wait,
				Poll:   time.Millisecond,
				OnBusy: func() { busyCalls++ },
			})
			if !errors.Is(err, pins.ErrLocked) {
				t.Errorf("LoadLocked() error = %v, want errors.Is ErrLocked", err)
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("LoadLocked() error = %v, must not wrap a context error", err)
			}
			if s != nil {
				t.Errorf("LoadLocked() store = %v, want nil", s)
			}
			if release == nil {
				t.Fatal("LoadLocked() release = nil, want a function")
			}
			release()
			release()
			if tt.wait == 0 && busyCalls != 1 {
				t.Errorf("OnBusy ran %d times with wait 0, want 1", busyCalls)
			}
			if busyCalls < 1 {
				t.Errorf("OnBusy ran %d times, want at least 1", busyCalls)
			}

			// The failed call did not take the lock of the holder away, and
			// after the holder releases, the next run gets it.
			if _, _, err := pins.LoadLocked(t.Context(), path, 0); !errors.Is(err, pins.ErrLocked) {
				t.Errorf("LoadLocked() while still held error = %v, want ErrLocked", err)
			}
			releaseFirst()
			lockTestMustLoad(t, path)
		})
	}
}

func TestLoadLockedContextEnds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// cancelInHook cancels ctx in OnBusy, while another run holds the
		// lock. Otherwise ctx is cancelled before the call and the lock is
		// free: the ended ctx still wins.
		cancelInHook bool
	}{
		{"cancelled while busy", true},
		{"cancelled before the call, lock free", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := storeTestPath(t)
			if tt.cancelInHook {
				lockTestMustLoad(t, path)
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			hooks := pins.LockHooks{Wait: time.Hour}
			if tt.cancelInHook {
				hooks.OnBusy = cancel
			} else {
				cancel()
			}
			s, release, err := pins.LoadLockedWith(ctx, path, hooks)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("LoadLocked() error = %v, want errors.Is context.Canceled", err)
			}
			if errors.Is(err, pins.ErrLocked) {
				t.Errorf("LoadLocked() error = %v, must not wrap ErrLocked", err)
			}
			if s != nil {
				t.Errorf("LoadLocked() store = %v, want nil", s)
			}
			if release == nil {
				t.Fatal("LoadLocked() release = nil, want a function")
			}
			release()
		})
	}
}

// TestLoadLockedReadOnlyDir checks that the lock works on a pins directory
// with mode 0500: the lock is on the directory handle, not on a lock file.
func TestLoadLockedReadOnlyDir(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root can write a read-only directory")
	}
	path := storeTestPath(t)
	dir := filepath.Dir(path)
	storeTestMustSave(t, storeTestMustLoad(t, path))
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // G302: the test makes the directory read-only on purpose; a directory needs the execute bit
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: the cleanup restores the private mode so t.TempDir can delete the directory

	s, release := lockTestMustLoad(t, path)
	if s.Unlocked() {
		t.Error("Unlocked() = true, want false: a read-only handle can be locked")
	}
	if !s.Existed() {
		t.Error("Existed() = false, want true")
	}
	storeTestMustSet(t, s, idA, storeTestPins("t", "h"))
	if err := s.Save(); err == nil || errors.Is(err, pins.ErrLocked) {
		t.Errorf("Save() in a read-only directory error = %v, want a write error that is not ErrLocked", err)
	}
	release()
}

// TestLoadLockedReleaseNoLeak locks and releases one directory many times.
// Each LoadLocked with no wait must get the lock, so release really frees it,
// and the open file descriptors must not grow.
func TestLoadLockedReleaseNoLeak(t *testing.T) {
	// Not parallel: it counts the open file descriptors of the whole process.
	path := storeTestPath(t)
	storeTestMustSave(t, storeTestMustLoad(t, path))

	before := lockTestOpenFDs(t)
	for i := range 200 {
		_, release, err := pins.LoadLocked(t.Context(), path, 0)
		if err != nil {
			t.Fatalf("iteration %d: LoadLocked() error = %v, want nil", i, err)
		}
		release()
		release() // A second call is safe.
	}
	after := lockTestOpenFDs(t)
	if before < 0 || after < 0 {
		t.Log("cannot count the open file descriptors here; the leak check is skipped")
		return
	}
	// A small margin for descriptors that the runtime opens; a leak of one
	// handle per iteration adds 200 or more.
	if after > before+10 {
		t.Errorf("open file descriptors grew from %d to %d over 200 lock cycles", before, after)
	}
}

func TestLoadLockedFirstRunCreatesDir(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "new", "mcpmoat", "pins.json")
	s, _ := lockTestMustLoad(t, path)
	if s.Existed() {
		t.Error("Existed() = true on a first run, want false")
	}
	if s.Unlocked() {
		t.Error("Unlocked() = true, want false")
	}
	for _, dir := range []string{filepath.Dir(path), filepath.Dir(filepath.Dir(path))} {
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("LoadLocked did not create %s: %v", dir, err)
		}
		// The umask can only clear bits of 0o700, so check that the group and
		// others have none.
		if !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s mode = %v, want a directory with no group or other bits", dir, fi.Mode())
		}
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("LoadLocked created pins.json (Lstat error = %v)", err)
	}
}

// TestLoadLockedTryLockResult injects the result of one lock attempt.
func TestLoadLockedTryLockResult(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		tryErr       error
		wantErr      error // nil means success
		wantUnlocked bool
	}{
		{"unsupported", pins.ErrLockUnsupported, nil, true},
		{"unsupported, wrapped", errors.Join(errors.New("flock"), pins.ErrLockUnsupported), nil, true},
		{"other error", syscall.EIO, syscall.EIO, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := storeTestPath(t)
			storeTestMustSave(t, storeTestMustLoad(t, path))
			s, release, err := pins.LoadLockedWith(t.Context(), path, pins.LockHooks{
				TryLock: func(*os.File) (bool, error) { return false, tt.tryErr },
			})
			if release == nil {
				t.Fatal("LoadLocked() release = nil, want a function")
			}
			defer release()
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) || errors.Is(err, pins.ErrLocked) {
					t.Errorf("LoadLocked() error = %v, want errors.Is %v and not ErrLocked", err, tt.wantErr)
				}
				if s != nil {
					t.Errorf("LoadLocked() store = %v, want nil", s)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadLocked() error = %v, want nil", err)
			}
			if s.Unlocked() != tt.wantUnlocked {
				t.Errorf("Unlocked() = %v, want %v", s.Unlocked(), tt.wantUnlocked)
			}
			if !s.Existed() {
				t.Error("Existed() = false, want true")
			}
			// No lock was taken, so a real run gets the lock at once.
			lockTestMustLoad(t, path)
		})
	}
}
