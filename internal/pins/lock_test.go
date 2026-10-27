//go:build unix

package pins_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// lockTestReadOnlyDir makes the directory of path read-only (mode 0500) and
// restores mode 0700 at cleanup, so t.TempDir can delete it.
func lockTestReadOnlyDir(t *testing.T, path string) {
	t.Helper()
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // G302: the test makes the directory read-only on purpose; a directory needs the execute bit
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: the cleanup restores the private mode so t.TempDir can delete the directory
}

// TestLoadLockedReadOnlyDir covers a pins directory with mode 0500. The lock
// is on the lock file pins.json.lock, so it works only when that file already
// exists: LoadLocked cannot create it in a read-only directory.
func TestLoadLockedReadOnlyDir(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root can write a read-only directory")
	}

	t.Run("existing lock file", func(t *testing.T) {
		t.Parallel()
		path := storeTestPath(t)
		storeTestMustSave(t, storeTestMustLoad(t, path))
		// A first LoadLocked creates the lock file with mode 0600.
		_, release := lockTestMustLoad(t, path)
		release()
		lockTestReadOnlyDir(t, path)

		s, release := lockTestMustLoad(t, path)
		if s.RanWithoutLock() {
			t.Error("RanWithoutLock() = true, want false: the existing lock file can be locked")
		}
		if !s.Existed() {
			t.Error("Existed() = false, want true")
		}
		// The lock is really held on the lock file.
		lockTestWantFlock(t, path+".lock", false)
		storeTestMustSet(t, s, idA, storeTestPins("t", "h"))
		if err := s.Save(); err == nil || errors.Is(err, pins.ErrLocked) {
			t.Errorf("Save() in a read-only directory error = %v, want a write error that is not ErrLocked", err)
		}
		release()
	})

	t.Run("no lock file", func(t *testing.T) {
		t.Parallel()
		path := storeTestPath(t)
		storeTestMustSave(t, storeTestMustLoad(t, path))
		lockPath := path + ".lock"
		if _, err := os.Lstat(lockPath); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Lstat(%q) error = %v, want not exist: Load and Save must not make the lock file", lockPath, err)
		}
		lockTestReadOnlyDir(t, path)

		s, release, err := pins.LoadLocked(t.Context(), path, 0)
		if release == nil {
			t.Fatal("LoadLocked() release = nil, want a function")
		}
		release()
		if s != nil {
			t.Errorf("LoadLocked() store = %v, want nil", s)
		}
		if err == nil {
			t.Fatal("LoadLocked() error = nil, want an error: the lock file cannot be created")
		}
		if want := "create the pins lock file " + lockPath + ": "; !strings.Contains(err.Error(), want) {
			t.Errorf("LoadLocked() error = %q, want it to contain %q", err, want)
		}
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("LoadLocked() error = %v, want errors.Is fs.ErrPermission", err)
		}
		if errors.Is(err, pins.ErrLocked) || errors.Is(err, pins.ErrInsecurePermissions) {
			t.Errorf("LoadLocked() error = %v, must not wrap ErrLocked or ErrInsecurePermissions", err)
		}
		if _, err := os.Lstat(lockPath); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Lstat(%q) error = %v, want not exist", lockPath, err)
		}
	})
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
	if s.RanWithoutLock() {
		t.Error("RanWithoutLock() = true, want false")
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

// TestLoadLockedParentsCheckedAfterCreate covers the race between the first
// parents check and MkdirAll. The first check skips a missing ancestor. If
// another user creates that ancestor, with an unsafe mode, before MkdirAll
// runs, MkdirAll uses it. The AfterEnsureDir hook makes the same state: it
// changes the mode of a parent that ensurePinsDir has just created. The
// second parents check must refuse it.
func TestLoadLockedParentsCheckedAfterCreate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// mode is the mode that the hook gives to the new ancestor. Zero
		// means that the hook does not change it.
		mode    os.FileMode
		wantErr bool
	}{
		{"new chain unchanged", 0, false},
		{"writable by group and others", 0o777, true},
		{"writable by group", 0o770, true},
		{"writable by all, sticky", os.ModeSticky | 0o777, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Only t.TempDir exists. LoadLocked creates new, chain and
			// mcpmoat, so the first parents check sees none of them. The
			// error names the path with its symlinks resolved (on macOS
			// t.TempDir is below the symlink /var), so resolve it here too.
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatalf("EvalSymlinks() error = %v", err)
			}
			ancestor := filepath.Join(base, "new")
			path := filepath.Join(ancestor, "chain", "mcpmoat", "pins.json")

			var hookRuns int
			s, release, err := pins.LoadLockedWith(t.Context(), path, pins.LockHooks{
				AfterEnsureDir: func() {
					hookRuns++
					if tt.mode == 0 {
						return
					}
					if err := os.Chmod(ancestor, tt.mode); err != nil {
						t.Errorf("chmod %s: %v", ancestor, err)
					}
				},
			})
			if release == nil {
				t.Fatal("LoadLocked() release = nil, want a function")
			}
			defer release()
			if hookRuns != 1 {
				t.Errorf("AfterEnsureDir ran %d times, want 1", hookRuns)
			}

			if !tt.wantErr {
				if err != nil {
					t.Fatalf("LoadLocked() error = %v, want nil", err)
				}
				if s.Existed() {
					t.Error("Existed() = true on a first run, want false")
				}
				return
			}
			if !errors.Is(err, pins.ErrInsecurePermissions) {
				t.Fatalf("LoadLocked() error = %v, want errors.Is ErrInsecurePermissions", err)
			}
			if !strings.Contains(err.Error(), "pins parent directory "+ancestor+" ") {
				t.Errorf("LoadLocked() error = %v, want it to name the parent %s", err, ancestor)
			}
			if s != nil {
				t.Errorf("LoadLocked() store = %v, want nil", s)
			}
		})
	}
}

// TestLoadLockedTryLockResult injects the result of one lock attempt.
func TestLoadLockedTryLockResult(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		tryErr             error
		wantErr            error // nil means success
		wantRanWithoutLock bool
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
			if s.RanWithoutLock() != tt.wantRanWithoutLock {
				t.Errorf("RanWithoutLock() = %v, want %v", s.RanWithoutLock(), tt.wantRanWithoutLock)
			}
			if !s.Existed() {
				t.Error("Existed() = false, want true")
			}
			// No lock was taken, so a real run gets the lock at once.
			lockTestMustLoad(t, path)
		})
	}
}

// lockTestFlock opens path read-only and tries a non-blocking exclusive
// flock(2) on it. The handle is a new open file description, so it competes
// with the lock of LoadLocked like another process would. It returns the open
// file and the error of flock; the file is closed at cleanup.
func lockTestFlock(t *testing.T, path string) (*os.File, error) {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: the test builds path under t.TempDir().
	if err != nil {
		t.Fatalf("Open(%q) error = %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

// lockTestWantFlock fails the test unless a new flock on path succeeds
// (wantFree) or finds the lock busy (!wantFree). A lock that it takes is
// released at once.
func lockTestWantFlock(t *testing.T, path string, wantFree bool) {
	t.Helper()
	f, err := lockTestFlock(t, path)
	defer func() { _ = f.Close() }()
	switch {
	case wantFree && err != nil:
		t.Errorf("flock(%q) error = %v, want the lock free", path, err)
	case !wantFree && !errors.Is(err, syscall.EWOULDBLOCK):
		t.Errorf("flock(%q) error = %v, want EWOULDBLOCK: the lock must be held", path, err)
	}
}

// lockTestHold takes a flock on path, as another process could, and fails the
// test when it cannot. Closing the returned file releases the lock.
func lockTestHold(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := lockTestFlock(t, path)
	if err != nil {
		t.Fatalf("flock(%q) error = %v, want the lock", path, err)
	}
	return f
}

// TestLoadLockedIgnoresDirFlock is the regression test of #218. The lock is on
// the lock file, not on the pins directory: any user who can read the
// directory can hold a flock on it, and that must not block a run.
func TestLoadLockedIgnoresDirFlock(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	storeTestMustSave(t, storeTestMustLoad(t, path))
	lockTestHold(t, filepath.Dir(path))

	s, release := lockTestMustLoad(t, path)
	if s.RanWithoutLock() {
		t.Error("RanWithoutLock() = true, want false")
	}
	lockTestWantFlock(t, path+".lock", false)
	release()
	lockTestWantFlock(t, path+".lock", true)
}

// TestLoadLockedLockFile checks the lock file that LoadLocked makes and locks:
// pins.json.lock, an empty regular file with mode 0600 that stays after the
// run. Another holder of a flock on it blocks LoadLocked, and release frees it.
func TestLoadLockedLockFile(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	lockPath := path + ".lock"
	_, release := lockTestMustLoad(t, path)

	info, err := os.Lstat(lockPath)
	if err != nil {
		t.Fatalf("Lstat(%q) error = %v, want the lock file", lockPath, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 0 {
		t.Errorf("lock file mode = %v, size = %d, want an empty regular file with mode 0600", info.Mode(), info.Size())
	}
	lockTestWantFlock(t, lockPath, false)

	// A second LoadLocked in the same process is a second open of the file, so
	// it finds the lock busy.
	if _, r, err := pins.LoadLocked(t.Context(), path, 0); !errors.Is(err, pins.ErrLocked) {
		t.Errorf("second LoadLocked() error = %v, want ErrLocked", err)
	} else {
		r()
	}

	// release frees the lock at once, and the lock file stays.
	release()
	lockTestWantFlock(t, lockPath, true)
	if _, err := os.Lstat(lockPath); err != nil {
		t.Errorf("Lstat(%q) after release error = %v, want the lock file to stay", lockPath, err)
	}

	// A flock on the lock file by another holder blocks LoadLocked.
	holder := lockTestHold(t, lockPath)
	if _, r, err := pins.LoadLocked(t.Context(), path, 0); !errors.Is(err, pins.ErrLocked) {
		t.Errorf("LoadLocked() while another handle holds the lock file error = %v, want ErrLocked", err)
	} else {
		r()
	}
	_ = holder.Close()
	lockTestMustLoad(t, path)
}

// TestLoadLockedRefusesUnsafeLockFile checks that LoadLocked refuses a lock
// file that another user could open or that is not the entry itself, with the
// rm fix hint, and never changes it.
func TestLoadLockedRefusesUnsafeLockFile(t *testing.T) {
	t.Parallel()
	// writeMode writes an empty lock file and sets its mode.
	writeMode := func(mode os.FileMode) func(*testing.T, string) {
		return func(t *testing.T, lockPath string) {
			t.Helper()
			if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(lockPath, mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	link := func(target string) func(*testing.T, string) {
		return func(t *testing.T, lockPath string) {
			t.Helper()
			if err := os.Symlink(target, lockPath); err != nil {
				t.Fatal(err)
			}
		}
	}
	tests := []struct {
		name  string
		setup func(t *testing.T, lockPath string)
		// after, when not nil, checks that the refusal changed nothing.
		after func(t *testing.T, lockPath string)
	}{
		{"mode 0644", writeMode(0o644), nil},
		{"mode 0640", writeMode(0o640), nil},
		{"mode 0604", writeMode(0o604), nil},
		{"mode 0660", writeMode(0o660), nil},
		{"mode 0606", writeMode(0o606), nil},
		{"mode 0611", writeMode(0o611), nil},
		{"symlink to a file in the directory", link("other"), nil},
		{"symlink to a missing target", link("missing"), func(t *testing.T, lockPath string) {
			t.Helper()
			// O_EXCL does not follow the symlink, so the target is not made.
			if _, err := os.Lstat(filepath.Join(filepath.Dir(lockPath), "missing")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("Lstat(missing) error = %v, want not exist", err)
			}
		}},
		{"absolute symlink outside the directory", func(t *testing.T, lockPath string) {
			t.Helper()
			link(filepath.Join(filepath.Dir(filepath.Dir(lockPath)), "outside"))(t, lockPath)
		}, nil},
		{"relative symlink outside the directory", link("../outside"), nil},
		{"named pipe", func(t *testing.T, lockPath string) {
			t.Helper()
			if err := syscall.Mkfifo(lockPath, 0o600); err != nil {
				t.Skipf("Mkfifo() error = %v", err)
			}
		}, nil},
		{"directory", func(t *testing.T, lockPath string) {
			t.Helper()
			if err := os.Mkdir(lockPath, 0o700); err != nil {
				t.Fatal(err)
			}
		}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// The pins directory is one level down, so "../outside" and the
			// absolute link leave it.
			base := t.TempDir()
			dir := filepath.Join(base, "mcpmoat")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "pins.json")
			lockPath := path + ".lock"
			for _, p := range []string{filepath.Join(dir, "other"), filepath.Join(base, "outside")} {
				if err := os.WriteFile(p, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			tt.setup(t, lockPath)
			before, err := os.Lstat(lockPath)
			if err != nil {
				t.Fatal(err)
			}

			// A goroutine with a time limit: a lock file that blocks the open
			// (a named pipe without O_NONBLOCK) must fail the test, not hang it.
			type result struct {
				s       *pins.Store
				release func()
				err     error
			}
			done := make(chan result, 1)
			go func() {
				s, release, err := pins.LoadLocked(t.Context(), path, 0)
				done <- result{s, release, err}
			}()
			var r result
			select {
			case r = <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("LoadLocked() did not return within 30s: the open of the lock file blocked")
			}
			if r.release == nil {
				t.Fatal("LoadLocked() release = nil, want a function")
			}
			r.release()
			if r.s != nil {
				t.Errorf("LoadLocked() store = %v, want nil", r.s)
			}
			if !errors.Is(r.err, pins.ErrInsecurePermissions) {
				t.Fatalf("LoadLocked() error = %v, want errors.Is ErrInsecurePermissions", r.err)
			}
			if errors.Is(r.err, pins.ErrLocked) {
				t.Errorf("LoadLocked() error = %v, must not wrap ErrLocked", r.err)
			}
			msg := r.err.Error()
			// rm without -r refuses a directory, so the hint says rmdir there.
			rm := "rm"
			if before.IsDir() {
				rm = "rmdir"
			}
			for _, want := range []string{"pins lock file " + lockPath + " is not safe", "(fix: " + rm + " -- '" + lockPath + "'"} {
				if !strings.Contains(msg, want) {
					t.Errorf("LoadLocked() error = %q, want it to contain %q", msg, want)
				}
			}
			if strings.Contains(msg, "chmod") {
				t.Errorf("LoadLocked() error = %q, the fix must be rm, never chmod", msg)
			}
			if strings.HasPrefix(msg, "read ") {
				t.Errorf("LoadLocked() error = %q, a refusal has no %q prefix", msg, "read <path>: ")
			}

			// The refusal never fixes the entry: same type and mode.
			after, err := os.Lstat(lockPath)
			if err != nil {
				t.Fatalf("Lstat(%q) after the refusal error = %v", lockPath, err)
			}
			if after.Mode() != before.Mode() {
				t.Errorf("lock file mode after the refusal = %v, want %v unchanged", after.Mode(), before.Mode())
			}
			for _, p := range []string{filepath.Join(dir, "other"), filepath.Join(base, "outside")} {
				info, err := os.Stat(p)
				if err != nil || info.Mode().Perm() != 0o600 || info.Size() != int64(len("keep")) {
					t.Errorf("Stat(%q) = %v, %v, want the file unchanged (mode 0600, 4 bytes)", p, info, err)
				}
			}
			if tt.after != nil {
				tt.after(t, lockPath)
			}
		})
	}
}

// TestLoadLockedErrorReleasesLock checks that an error after LoadLocked took
// the lock, here a corrupt pins.json, releases the lock and closes the lock
// file, also when the caller does not call release.
func TestLoadLockedErrorReleasesLock(t *testing.T) {
	t.Parallel()
	path := storeTestWrite(t, "{not json")
	s, _, err := pins.LoadLocked(t.Context(), path, 0)
	if err == nil || s != nil {
		t.Fatalf("LoadLocked() = %v, %v, want an error for a corrupt pins.json", s, err)
	}
	if errors.Is(err, pins.ErrLocked) {
		t.Fatalf("LoadLocked() error = %v, must not wrap ErrLocked", err)
	}
	// The release function of the failed call is not called on purpose.
	lockTestWantFlock(t, path+".lock", true)

	if err := os.WriteFile(path, []byte(`{"version":1,"servers":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ = lockTestMustLoad(t, path)
	if !s.Existed() {
		t.Error("Existed() = false, want true")
	}
}

// TestLoadLockedLockFileModeIgnoresUmask checks that a new lock file gets mode
// 0600 also when the umask removes owner bits: with umask 0277, the open
// alone would make it 0400, and the next run could not open it for writing.
func TestLoadLockedLockFileModeIgnoresUmask(t *testing.T) {
	// Not parallel: the umask belongs to the whole process. Parallel tests
	// start only after the sequential tests have finished.
	path := storeTestPath(t)
	old := syscall.Umask(0o277)
	_, release, err := pins.LoadLocked(t.Context(), path, 0)
	syscall.Umask(old)
	if err != nil {
		t.Fatalf("LoadLocked() error = %v, want nil", err)
	}
	release()
	info, err := os.Lstat(path + ".lock")
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("lock file mode = %v, want 0600 whatever the umask", info.Mode())
	}
	lockTestMustLoad(t, path)
}
