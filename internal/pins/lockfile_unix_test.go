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
	"strings"
	"syscall"
	"testing"
)

// lockFileInfo makes an empty file with the given mode in a new directory
// named dirName and returns its path and its Lstat result.
func lockFileInfo(t *testing.T, dirName string, mode os.FileMode) (string, fs.FileInfo) {
	t.Helper()
	path := filepath.Join(newNamedPinsDir(t, dirName, 0o700), "pins.json.lock")
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
// path whose fix is rm, with the path quoted for a shell, and never chmod.
func wantLockRefused(t *testing.T, err error, path string, parts ...string) {
	t.Helper()
	wantInsecure(t, err, path, append(parts, "pins lock file {path} is not safe")...)
	if err == nil {
		return
	}
	if hint := "(fix: rm -- " + shellQuote(path) + ", then mcpmoat makes a new one with mode 0600)"; !strings.Contains(err.Error(), hint) {
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
			wantLockRefused(t, err, path, tt.want...)
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

	// Not a regular file: refused whatever the owner and the mode.
	notRegular := []struct {
		name string
		make func(t *testing.T, path string)
	}{
		{"directory", func(t *testing.T, path string) {
			t.Helper()
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, path string) {
			t.Helper()
			target := filepath.Join(filepath.Dir(path), "target")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"named pipe", func(t *testing.T, path string) {
			t.Helper()
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Skipf("Mkfifo() error = %v", err)
			}
		}},
	}
	for _, tt := range notRegular {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(newPinsDir(t, 0o700), "pins.json.lock")
			tt.make(t, path)
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("Lstat() error = %v", err)
			}
			wantLockRefused(t, checkLockFile(path, info, me), path, msgNotFile)
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
		wantLockRefused(t, err, path, msgOpen)
		quoted := "rm -- '" + strings.ReplaceAll(path, "'", `'\''`) + "'"
		if !strings.Contains(err.Error(), quoted) {
			t.Errorf("error = %q, want the quoted hint %q", err, quoted)
		}
	})

	// The symlink refusal of openLockFile has the same rm hint.
	t.Run("swapped error has the rm hint", func(t *testing.T) {
		t.Parallel()
		path := "/home/u/.config/my pins'dir/pins.json.lock"
		err := lockSwappedError(path)
		if !errors.Is(err, ErrInsecurePermissions) {
			t.Fatalf("lockSwappedError() = %v, want it to wrap ErrInsecurePermissions", err)
		}
		wantLockRefused(t, err, path, "it is a symlink or was swapped")
	})
}
