package inspect

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testRunRoot returns a runRoot for workDir that uses a new directory of the
// test, so that no test writes to the cache directory of the user. It runs
// privateDir, but not the parent chain check: a test directory is below
// /tmp on Linux.
func testRunRoot(t *testing.T) (root string, runRoot func() (string, error)) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "run")
	return root, func() (string, error) { return privateDir(root) }
}

// mkdirMode makes dir and its parents, and sets the mode of dir to perm, also
// when the umask would clear some bits.
func mkdirMode(t *testing.T, dir string, perm fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, perm); err != nil {
		t.Fatal(err)
	}
}

// TestWorkDir checks the three outcomes of workDir: no directory for an
// absolute Dir, a new private directory below the run root otherwise, and
// an error when the run root fails.
func TestWorkDir(t *testing.T) {
	t.Parallel()

	t.Run("absolute Dir needs no run root", func(t *testing.T) {
		t.Parallel()
		runRoot := func() (string, error) {
			t.Error("runRoot called for a server with an absolute Dir")
			return "", errors.New("unexpected")
		}
		dir, cleanup, err := workDir(t.TempDir(), runRoot)
		cleanup()
		if err != nil || dir != "" {
			t.Errorf("workDir() = %q, %v, want \"\", nil", dir, err)
		}
	})

	for _, configDir := range []string{"", "sub", "./sub", "../sub", "."} {
		t.Run("Dir "+configDir+" gets a new directory", func(t *testing.T) {
			t.Parallel()
			root, runRoot := testRunRoot(t)

			dir, cleanup, err := workDir(configDir, runRoot)
			t.Cleanup(cleanup)
			if err != nil {
				t.Fatalf("workDir() error = %v, want nil", err)
			}
			realRoot, err := filepath.EvalSymlinks(root)
			if err != nil {
				t.Fatal(err)
			}
			if got := filepath.Dir(dir); got != realRoot {
				t.Errorf("parent of the work directory = %q, want the run root %q", got, realRoot)
			}
			if base := filepath.Base(dir); !strings.HasPrefix(base, "mcpmoat-server-") {
				t.Errorf("work directory name = %q, want prefix %q", base, "mcpmoat-server-")
			}
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatalf("os.Stat(work directory) error = %v", err)
			}
			if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o700 {
				t.Errorf("work directory mode = %v, want %v", perm, fs.FileMode(0o700))
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Errorf("work directory has %d entries (error %v), want an empty directory", len(entries), err)
			}

			cleanup()
			if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("after cleanup, os.Stat(work directory) error = %v, want fs.ErrNotExist", err)
			}
		})
	}

	t.Run("each call makes a new directory", func(t *testing.T) {
		t.Parallel()
		_, runRoot := testRunRoot(t)
		a, cleanupA, errA := workDir("", runRoot)
		t.Cleanup(cleanupA)
		b, cleanupB, errB := workDir("", runRoot)
		t.Cleanup(cleanupB)
		if errA != nil || errB != nil {
			t.Fatalf("workDir() errors = %v, %v", errA, errB)
		}
		if a == b {
			t.Errorf("two calls gave the same directory %q", a)
		}
	})

	errRoot := errors.New("no run root")
	failures := []struct {
		name    string
		runRoot func(t *testing.T) func() (string, error)
	}{
		{
			name: "run root fails",
			runRoot: func(*testing.T) func() (string, error) {
				return func() (string, error) { return "", errRoot }
			},
		},
		{
			name: "run root does not exist",
			runRoot: func(t *testing.T) func() (string, error) {
				missing := filepath.Join(t.TempDir(), "missing")
				return func() (string, error) { return missing, nil }
			},
		},
	}
	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, cleanup, err := workDir("", tt.runRoot(t))
			if cleanup == nil {
				t.Fatal("workDir() cleanup = nil, want non-nil")
			}
			cleanup()
			if err == nil {
				t.Error("workDir() error = nil, want an error")
			}
			if dir != "" {
				t.Errorf("workDir() dir = %q, want \"\" on error", dir)
			}
		})
	}
}

// TestPrivateDir checks that privateDir makes a new directory with mode
// 0o700, resolves symbolic links, and refuses a path that is not a private
// directory.
func TestPrivateDir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string) (want string) // "" means dir itself
		unix    bool                                         // needs Unix permission bits or symbolic links
		wantErr bool
	}{
		{name: "new directory and parents"},
		{name: "existing private directory", setup: func(t *testing.T, dir string) string { mkdirMode(t, dir, 0o700); return "" }},
		{name: "group can read", unix: true, wantErr: true, setup: func(t *testing.T, dir string) string { mkdirMode(t, dir, 0o750); return "" }},
		{name: "others can write", unix: true, wantErr: true, setup: func(t *testing.T, dir string) string { mkdirMode(t, dir, 0o707); return "" }},
		{
			name: "symbolic link to a private directory is resolved", unix: true,
			setup: func(t *testing.T, dir string) string {
				target := filepath.Join(t.TempDir(), "target")
				mkdirMode(t, target, 0o700)
				mkdirMode(t, filepath.Dir(dir), 0o700)
				if err := os.Symlink(target, dir); err != nil {
					t.Fatal(err)
				}
				return target
			},
		},
		{
			name: "symbolic link to a shared directory", unix: true, wantErr: true,
			setup: func(t *testing.T, dir string) string {
				target := filepath.Join(t.TempDir(), "target")
				mkdirMode(t, target, 0o777)
				mkdirMode(t, filepath.Dir(dir), 0o700)
				if err := os.Symlink(target, dir); err != nil {
					t.Fatal(err)
				}
				return ""
			},
		},
		{
			name: "regular file", wantErr: true,
			setup: func(t *testing.T, dir string) string {
				mkdirMode(t, filepath.Dir(dir), 0o700)
				if err := os.WriteFile(dir, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				return ""
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.unix && runtime.GOOS == "windows" {
				t.Skip("needs Unix permission bits and symbolic links")
			}

			dir := filepath.Join(t.TempDir(), "cache", "mcpmoat", "run")
			want := dir
			if tt.setup != nil {
				if w := tt.setup(t, dir); w != "" {
					want = w
				}
			}

			got, err := privateDir(dir)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("privateDir() = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("privateDir() error = %v, want nil", err)
			}
			realWant, err := filepath.EvalSymlinks(want)
			if err != nil {
				t.Fatal(err)
			}
			if got != realWant {
				t.Errorf("privateDir() = %q, want %q", got, realWant)
			}
			info, err := os.Lstat(got)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o700 {
				t.Errorf("mode = %v, want %v", perm, fs.FileMode(0o700))
			}
		})
	}
}

// TestRunRootIn checks that the run root is <cache>/mcpmoat/run and that the
// parent chain check gets the resolved run root and can refuse it.
func TestRunRootIn(t *testing.T) {
	t.Parallel()

	cache := t.TempDir()
	var checked string
	got, err := runRootIn(cache, func(dir string) error { checked = dir; return nil })
	if err != nil {
		t.Fatalf("runRootIn() error = %v, want nil", err)
	}
	want, err := filepath.EvalSymlinks(filepath.Join(cache, "mcpmoat", "run"))
	if err != nil {
		t.Fatal(err)
	}
	if got != want || checked != want {
		t.Errorf("runRootIn() = %q, chain check got %q, want %q for both", got, checked, want)
	}

	errChain := errors.New("shared parent")
	if _, err := runRootIn(t.TempDir(), func(string) error { return errChain }); !errors.Is(err, errChain) {
		t.Errorf("runRootIn() error = %v, want the chain check error", err)
	}
}
