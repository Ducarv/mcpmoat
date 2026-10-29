//go:build unix

package pins

// These tests cover the rule of checkLockFile for the pins lock file. A
// foreign owner is faked with an injected uid, so no test needs root.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// lockFileInfo makes an empty file with the given mode in a new directory
// named dirName and returns its path and its Lstat result.
func lockFileInfo(t *testing.T, dirName string, mode os.FileMode) (string, fs.FileInfo) {
	t.Helper()
	path := filepath.Join(newNamedPinsDir(t, dirName, 0o700), lockName)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	chmodForTest(t, path, mode)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	return path, info
}

// wantLockRefused fails the test unless err is a refusal of the lock file at
// path whose fix is cmd ("rm", or "rmdir" for a directory), with the path
// quoted for a shell, and never chmod.
func wantLockRefused(t *testing.T, err error, path, cmd string, parts ...string) {
	t.Helper()
	wantInsecure(t, err, path, append(parts, "pins lock file {path} is not safe")...)
	if err == nil {
		return
	}
	if hint := "(fix: " + cmd + " -- " + shellQuote(path) + ", then mcpmoat makes a new one with mode 0600)"; !strings.Contains(err.Error(), hint) {
		t.Errorf("error = %q, want the hint %q", err, hint)
	}
	if strings.Contains(err.Error(), "chmod") {
		t.Errorf("error = %q, the fix must be rm, never chmod", err)
	}
}

func TestCheckLockFile(t *testing.T) {
	t.Parallel()
	me := os.Geteuid()
	const (
		msgOpen    = "accessible by group or others"
		msgNotFile = "not a regular file"
	)
	tests := []struct {
		name string
		mode os.FileMode
		uid  int      // the uid that checkLockFile checks for
		want []string // nil means no error
	}{
		{"0600", 0o600, me, nil},
		{"0400", 0o400, me, nil},
		{"0200", 0o200, me, nil},
		{"0000", 0, me, nil},
		// 0700 has no group or other bit, so the rule lets it pass.
		{"0700", 0o700, me, nil},
		{"0640", 0o640, me, []string{"mode 0640", msgOpen}},
		{"0604", 0o604, me, []string{"mode 0604", msgOpen}},
		{"0644", 0o644, me, []string{"mode 0644", msgOpen}},
		{"0660", 0o660, me, []string{"mode 0660", msgOpen}},
		{"0666", 0o666, me, []string{"mode 0666", msgOpen}},
		{"0777", 0o777, me, []string{"mode 0777", msgOpen}},
		{"foreign 0600", 0o600, me + 1, []string{"mode 0600", msgForeign}},
		{"foreign 0644", 0o644, me + 1, []string{"mode 0644", msgForeign + ", " + msgOpen}},
	}
	// Each group or other bit alone is enough: read is enough for flock.
	for _, bit := range []os.FileMode{0o040, 0o020, 0o010, 0o004, 0o002, 0o001} {
		mode := 0o600 | bit
		tests = append(tests, struct {
			name string
			mode os.FileMode
			uid  int
			want []string
		}{fmt.Sprintf("%04o", mode), mode, me, []string{fmt.Sprintf("mode %04o", mode), msgOpen}})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path, info := lockFileInfo(t, "pins", tt.mode)
			err := checkLockFile(path, info, tt.uid)
			if tt.want == nil {
				if err != nil {
					t.Errorf("checkLockFile() error = %v, want nil", err)
				}
				return
			}
			wantLockRefused(t, err, path, "rm", tt.want...)
			if tt.uid == me && strings.Contains(err.Error(), msgForeign) {
				t.Errorf("checkLockFile() error = %q, the owner is the current user", err)
			}
			if tt.uid != me && strings.Contains(err.Error(), msgOpen) != (tt.mode&0o077 != 0) {
				t.Errorf("checkLockFile() error = %q, says %q for mode %04o", err, msgOpen, tt.mode)
			}
		})
	}

	t.Run("exact text", func(t *testing.T) {
		t.Parallel()
		path, info := lockFileInfo(t, "pins", 0o644)
		want := "pins lock file " + path + " is not safe: mode 0644, accessible by group or others (fix: rm -- '" +
			path + "', then mcpmoat makes a new one with mode 0600): insecure permissions"
		if err := checkLockFile(path, info, me); err == nil || err.Error() != want {
			t.Errorf("error = %v\nwant    %q", err, want)
		}
	})

	t.Run("exact text of a directory", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(newPinsDir(t, 0o700), lockName)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("Lstat() error = %v", err)
		}
		want := "pins lock file " + path + " is not safe: not a regular file (fix: rmdir -- '" +
			path + "', then mcpmoat makes a new one with mode 0600): insecure permissions"
		if err := checkLockFile(path, info, me); err == nil || err.Error() != want {
			t.Errorf("error = %v\nwant    %q", err, want)
		}
	})

	// Not a regular file: refused whatever the owner and the mode.
	notRegular := []struct {
		name string
		make func(t *testing.T, path string)
		cmd  string // the command of the fix hint
	}{
		{"directory", func(t *testing.T, path string) {
			t.Helper()
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}, "rmdir"},
		{"symlink", func(t *testing.T, path string) {
			t.Helper()
			target := filepath.Join(filepath.Dir(path), "target")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}, "rm"},
		{"named pipe", func(t *testing.T, path string) {
			t.Helper()
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Skipf("Mkfifo() error = %v", err)
			}
		}, "rm"},
	}
	for _, tt := range notRegular {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(newPinsDir(t, 0o700), lockName)
			tt.make(t, path)
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("Lstat() error = %v", err)
			}
			wantLockRefused(t, checkLockFile(path, info, me), path, tt.cmd, msgNotFile)
		})
	}

	t.Run("unknown owner fails closed", func(t *testing.T) {
		t.Parallel()
		path, info := lockFileInfo(t, "pins", 0o600)
		wantInsecure(t, checkLockFile(path, fakeInfo{info, nil}, me), path, "pins lock file {path} is not safe: its owner is unknown")
	})

	// The hint quotes the path for a shell, also with a space and a quote.
	t.Run("odd path is quoted", func(t *testing.T) {
		t.Parallel()
		path, info := lockFileInfo(t, "my pins'dir", 0o644)
		err := checkLockFile(path, info, me)
		wantLockRefused(t, err, path, "rm", msgOpen)
		quoted := "rm -- '" + strings.ReplaceAll(path, "'", `'\''`) + "'"
		if !strings.Contains(err.Error(), quoted) {
			t.Errorf("error = %q, want the quoted hint %q", err, quoted)
		}
	})

	// The symlink refusal of openLockFile has the same hint: rm, or rmdir when
	// the entry is now a directory. A nil entry (the entry is gone) gives rm.
	t.Run("swapped error has the rm hint", func(t *testing.T) {
		t.Parallel()
		dir := newNamedPinsDir(t, "my pins'dir", 0o700)
		path := filepath.Join(dir, lockName)
		dirInfo, err := os.Lstat(dir)
		if err != nil {
			t.Fatalf("Lstat() error = %v", err)
		}
		_, fileInfo := lockFileInfo(t, "pins", 0o600)
		for _, tc := range []struct {
			name  string
			entry fs.FileInfo
			cmd   string
		}{
			{"gone", nil, "rm"},
			{"file", fileInfo, "rm"},
			{"directory", dirInfo, "rmdir"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := lockSwappedError(path, tc.entry)
				if !errors.Is(err, ErrInsecurePermissions) {
					t.Fatalf("lockSwappedError() = %v, want it to wrap ErrInsecurePermissions", err)
				}
				wantLockRefused(t, err, path, tc.cmd, "it is a symlink or was swapped")
			})
		}
	})
}

// TestLockFileFix pins the exact text of the fix hint for a pins lock file.
func TestLockFileFix(t *testing.T) {
	t.Parallel()
	_, fileInfo := lockFileInfo(t, "pins", 0o600)
	dirInfo, err := os.Lstat(newPinsDir(t, 0o700))
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	const path = "/home/u/.config/my pins'dir/" + lockName
	const quoted = `'/home/u/.config/my pins'\''dir/` + lockName + `'`
	tests := []struct {
		name string
		info fs.FileInfo
		want string
	}{
		{"unknown", nil, "rm -- " + quoted + ", then mcpmoat makes a new one with mode 0600"},
		{"regular file", fileInfo, "rm -- " + quoted + ", then mcpmoat makes a new one with mode 0600"},
		{"directory", dirInfo, "rmdir -- " + quoted + ", then mcpmoat makes a new one with mode 0600"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := lockFileFix(path, tt.info); got != tt.want {
				t.Errorf("lockFileFix() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestOpenOrCreateRace drives openOrCreate through the races with another run.
// The open function calls the real root.OpenFile, but first runs a hook that
// creates or removes the lock file, as another run could between two steps.
func TestOpenOrCreateRace(t *testing.T) {
	t.Parallel()
	// The hooks: what "another run" does right before a create (O_CREATE in
	// flag) or right before an open with no create.
	mkFile := func(t *testing.T, path string) {
		t.Helper()
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}
	rmFile := func(t *testing.T, path string) {
		t.Helper()
		if err := os.Remove(path); err != nil {
			t.Fatalf("Remove() error = %v", err)
		}
	}
	tests := []struct {
		name string
		// beforeCreate and beforeReopen, when not nil, run before the create
		// and before the open that follows a failed create.
		beforeCreate, beforeReopen func(t *testing.T, path string)
		wantCreated                bool
		wantErr                    bool
		// wantSteps is the flags of each call, as "open" or "create".
		wantSteps []string
	}{
		{name: "missing, created", wantCreated: true, wantSteps: []string{"open", "create"}},
		{
			name:         "another run created it",
			beforeCreate: mkFile,
			wantSteps:    []string{"open", "create", "open"},
		},
		{
			// The file is gone before the open after the first create, so
			// openOrCreate creates it again, and this time the create works.
			name:         "created and removed once",
			beforeCreate: once(mkFile), beforeReopen: once(rmFile),
			wantCreated: true,
			wantSteps:   []string{"open", "create", "open", "create"},
		},
		{
			name:         "created and removed each time",
			beforeCreate: mkFile, beforeReopen: rmFile,
			wantErr:   true,
			wantSteps: []string{"open", "create", "open", "create", "open", "create", "open"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, 0o700)
			path := filepath.Join(dir, lockName)
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("OpenRoot() error = %v", err)
			}
			t.Cleanup(func() { _ = root.Close() })

			var steps []string
			open := func(name string, flag int, perm fs.FileMode) (*os.File, error) {
				step := "open"
				if flag&os.O_CREATE != 0 {
					step = "create"
				}
				// A create, or an open after a create, runs a hook.
				switch {
				case step == "create" && tt.beforeCreate != nil:
					tt.beforeCreate(t, path)
				case step == "open" && len(steps) > 0 && tt.beforeReopen != nil:
					tt.beforeReopen(t, path)
				}
				steps = append(steps, step)
				return root.OpenFile(name, flag, perm)
			}

			f, created, err := openOrCreate(open, path, lockName)
			if f != nil {
				t.Cleanup(func() { _ = f.Close() })
			}

			if !slices.Equal(steps, tt.wantSteps) {
				t.Errorf("steps = %v, want %v", steps, tt.wantSteps)
			}
			if created != tt.wantCreated {
				t.Errorf("created = %t, want %t", created, tt.wantCreated)
			}
			if tt.wantErr {
				want := "open the pins lock file " + path + ": no such file or directory"
				if err == nil || err.Error() != want || f != nil || !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("openOrCreate() = %v, %v, want nil and %q (errors.Is fs.ErrNotExist)", f, err, want)
				}
				return
			}
			if err != nil || f == nil {
				t.Fatalf("openOrCreate() = %v, %v, want a file and no error", f, err)
			}
		})
	}
}

// once returns a hook that runs hook on its first call only. Each subtest has
// its own hook, so done needs no lock.
func once(hook func(*testing.T, string)) func(*testing.T, string) {
	done := false
	return func(t *testing.T, path string) {
		t.Helper()
		if !done {
			done = true
			hook(t, path)
		}
	}
}

// TestOpenOrCreateErrors checks that an error names the step that failed:
// "create" only when the create itself failed.
func TestOpenOrCreateErrors(t *testing.T) {
	t.Parallel()
	const path = "/home/u/.config/mcpmoat/" + lockName
	notExist := &fs.PathError{Op: "openat", Path: lockName, Err: syscall.ENOENT}
	denied := &fs.PathError{Op: "openat", Path: lockName, Err: syscall.EACCES}
	tests := []struct {
		name string
		// open returns the result of each call, in order.
		results []error
		want    string
	}{
		{"open denied", []error{denied}, "open the pins lock file " + path + ": permission denied"},
		{"create denied", []error{notExist, denied}, "create the pins lock file " + path + ": permission denied"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			open := func(string, int, fs.FileMode) (*os.File, error) {
				err := tt.results[calls]
				calls++
				return nil, err
			}
			f, created, err := openOrCreate(open, path, lockName)
			if f != nil || created || err == nil || err.Error() != tt.want {
				t.Errorf("openOrCreate() = %v, %t, %v, want nil, false, %q", f, created, err, tt.want)
			}
			if !errors.Is(err, fs.ErrPermission) {
				t.Errorf("openOrCreate() error = %v, want errors.Is fs.ErrPermission", err)
			}
			if calls != len(tt.results) {
				t.Errorf("open called %d times, want %d", calls, len(tt.results))
			}
		})
	}
}

// TestSameEntry checks the results of sameEntry with a fake lstat. "Not
// exist" and ENOTDIR both mean that the entry is gone (safefile.IsMissing),
// so readChecked and checkOpenLockFile refuse both as a swapped entry. Any
// other Lstat error is returned.
func TestSameEntry(t *testing.T) {
	t.Parallel()
	dir := newPinsDir(t, 0o700)
	file, other := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, p := range []string{file, other} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}
	info, err := os.Lstat(file)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	otherInfo, err := os.Lstat(other)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	pathErr := func(errno syscall.Errno) error { return &fs.PathError{Op: "fstatat", Path: "a", Err: errno} }
	tests := []struct {
		name      string
		entry     fs.FileInfo
		lstatErr  error
		wantEntry fs.FileInfo
		wantSame  bool
		wantErr   error // nil means no error
	}{
		{"same file", info, nil, info, true, nil},
		{"other file", otherInfo, nil, otherInfo, false, nil},
		{"not exist", nil, pathErr(syscall.ENOENT), nil, false, nil},
		{"not a directory", nil, pathErr(syscall.ENOTDIR), nil, false, nil},
		{"permission denied", nil, pathErr(syscall.EACCES), nil, false, syscall.EACCES},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lstat := func(string) (fs.FileInfo, error) { return tt.entry, tt.lstatErr }
			entry, same, err := sameEntry(lstat, "a", info)
			if entry != tt.wantEntry || same != tt.wantSame {
				t.Errorf("sameEntry() = %v, %t, want %v, %t", entry, same, tt.wantEntry, tt.wantSame)
			}
			if (err == nil) != (tt.wantErr == nil) || (tt.wantErr != nil && !errors.Is(err, tt.wantErr)) {
				t.Errorf("sameEntry() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestSwapCheckEntryGone removes the entry of an open file and runs the swap
// check of each caller of sameEntry on it, on the real file system: both
// refuse the file as swapped, with their exact text.
func TestSwapCheckEntryGone(t *testing.T) {
	t.Parallel()
	// openAndRemove makes the file name in a new pins directory, opens it
	// through an os.Root and removes the entry. The file stays open.
	openAndRemove := func(t *testing.T, name string) (root *os.Root, f *os.File, path string) {
		t.Helper()
		dir := newPinsDir(t, 0o700)
		path = filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(validPins), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatalf("OpenRoot() error = %v", err)
		}
		t.Cleanup(func() { _ = root.Close() })
		f, err = root.OpenFile(name, lockOpenFlags, 0)
		if err != nil {
			t.Fatalf("OpenFile() error = %v", err)
		}
		t.Cleanup(func() { _ = f.Close() })
		if err := os.Remove(path); err != nil {
			t.Fatalf("Remove() error = %v", err)
		}
		return root, f, path
	}

	t.Run("pins.json", func(t *testing.T) {
		t.Parallel()
		root, f, path := openAndRemove(t, "pins.json")
		_, err := readChecked(path, root, "pins.json", f)
		want := "pins file " + path + " is a symlink or was swapped while it was opened (fix: replace the symlink with the file): insecure permissions"
		if err == nil || err.Error() != want || !errors.Is(err, ErrInsecurePermissions) {
			t.Errorf("readChecked() error = %v, want %q", err, want)
		}
	})

	t.Run("lock file", func(t *testing.T) {
		t.Parallel()
		root, f, path := openAndRemove(t, lockName)
		err := checkOpenLockFile(root, path, lockName, f, false)
		want := "pins lock file " + path + " is not safe: it is a symlink or was swapped while it was opened (fix: rm -- " +
			shellQuote(path) + ", then mcpmoat makes a new one with mode 0600): insecure permissions"
		if err == nil || err.Error() != want || !errors.Is(err, ErrInsecurePermissions) {
			t.Errorf("checkOpenLockFile() error = %v, want %q", err, want)
		}
	})
}
