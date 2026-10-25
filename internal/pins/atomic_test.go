package pins

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// dirNames returns the sorted names of the entries in dir.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q) error = %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// readFile reads path. It is the one place that carries the gosec exception.
func readFile(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	return os.ReadFile(path) //nolint:gosec // G304: the test builds path under t.TempDir().
}

// wantPerm fails the test if the mode bits of path differ from want.
// Windows has no Unix mode bits, so the check is skipped there.
func wantPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("mode of %q = %#o, want %#o", path, got, want)
	}
}

func TestWriteFileAtomicCreatesDirAndFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "a", "b")
	path := filepath.Join(dir, "pins.json")
	data := []byte(`{"version":1}`)

	if err := writeFileAtomic(path, data); err != nil {
		t.Fatalf("writeFileAtomic() error = %v", err)
	}

	got, err := readFile(t, path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("content = %q, want %q", got, data)
	}
	wantPerm(t, path, fileMode)
	// MkdirAll gives every directory it creates the same mode.
	wantPerm(t, dir, dirMode)
	wantPerm(t, filepath.Join(root, "a"), dirMode)
	if names, want := dirNames(t, dir), []string{"pins.json"}; !slices.Equal(names, want) {
		t.Errorf("dir entries = %v, want %v", names, want)
	}
}

func TestWriteFileAtomicKeepsExistingDirMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Chmod directly: the umask can change the mode that Mkdir sets.
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: the test needs a mode that is more open than 0o700.
		t.Fatalf("Chmod() error = %v", err)
	}

	if err := writeFileAtomic(filepath.Join(dir, "pins.json"), []byte("x")); err != nil {
		t.Fatalf("writeFileAtomic() error = %v", err)
	}

	wantPerm(t, dir, 0o755)
}

func TestWriteFileAtomicReplacesExistingFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		oldMode os.FileMode
		oldData []byte
		newData []byte
	}{
		{name: "old file 0644", oldMode: 0o644, oldData: []byte("old content that is longer"), newData: []byte("new")},
		{name: "old file 0600", oldMode: 0o600, oldData: []byte("old"), newData: []byte("new content that is longer")},
		{name: "old file 0666", oldMode: 0o666, oldData: []byte("old"), newData: []byte("new")},
		{name: "new data is empty", oldMode: 0o644, oldData: []byte("old"), newData: []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "pins.json")
			if err := os.WriteFile(path, tt.oldData, 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			if err := os.Chmod(path, tt.oldMode); err != nil {
				t.Fatalf("Chmod() error = %v", err)
			}

			if err := writeFileAtomic(path, tt.newData); err != nil {
				t.Fatalf("writeFileAtomic() error = %v", err)
			}

			got, err := readFile(t, path)
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			if !bytes.Equal(got, tt.newData) {
				t.Errorf("content = %q, want %q", got, tt.newData)
			}
			wantPerm(t, path, fileMode)
			if names, want := dirNames(t, dir), []string{"pins.json"}; !slices.Equal(names, want) {
				t.Errorf("dir entries = %v, want %v", names, want)
			}
		})
	}
}

func TestWriteFileAtomicHookFailure(t *testing.T) {
	t.Parallel()
	errBoom := errors.New("simulated crash")
	tests := []struct {
		name string
		// writer builds the writer under test. It stores the temp path in *tmp.
		writer func(tmp *string) atomicWriter
	}{
		{
			name: "beforeWrite fails",
			writer: func(tmp *string) atomicWriter {
				return atomicWriter{beforeWrite: func(p string) error { *tmp = p; return errBoom }}
			},
		},
		{
			name: "beforeRename fails",
			writer: func(tmp *string) atomicWriter {
				return atomicWriter{beforeRename: func(p string) error { *tmp = p; return errBoom }}
			},
		},
	}
	for _, tt := range tests {
		for _, existing := range []bool{true, false} {
			name := tt.name + "/no existing target"
			if existing {
				name = tt.name + "/existing target"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				path := filepath.Join(dir, "pins.json")
				oldData := []byte(`{"old":true}`)
				if existing {
					if err := os.WriteFile(path, oldData, fileMode); err != nil {
						t.Fatalf("WriteFile() error = %v", err)
					}
				}

				var tmp string
				err := tt.writer(&tmp).writeFile(path, []byte(`{"new":true}`))

				if !errors.Is(err, errBoom) {
					t.Fatalf("writeFile() error = %v, want it to wrap %v", err, errBoom)
				}
				if tmp == "" {
					t.Fatal("hook was not called")
				}
				if _, statErr := os.Stat(tmp); !errors.Is(statErr, os.ErrNotExist) {
					t.Errorf("temp file %q still exists (Stat error = %v)", tmp, statErr)
				}
				if existing {
					got, readErr := readFile(t, path)
					if readErr != nil {
						t.Fatalf("ReadFile() error = %v", readErr)
					}
					if !bytes.Equal(got, oldData) {
						t.Errorf("target = %q, want old content %q", got, oldData)
					}
					if names, want := dirNames(t, dir), []string{"pins.json"}; !slices.Equal(names, want) {
						t.Errorf("dir entries = %v, want %v", names, want)
					}
					return
				}
				if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
					t.Errorf("target exists after failure (Stat error = %v)", statErr)
				}
				if names := dirNames(t, dir); len(names) != 0 {
					t.Errorf("dir entries = %v, want none", names)
				}
			})
		}
	}
}

// TestWriteFileAtomicTempFileState checks the temp file at each hook point.
// A temp file that sits in the target directory and holds all the data is what
// makes the final rename atomic.
func TestWriteFileAtomicTempFileState(t *testing.T) {
	t.Parallel()
	data := []byte(`{"version":1,"pins":{"a":"sha256:abc"}}`)
	oldData := []byte(`{"old":true}`)

	t.Run("beforeWrite", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "pins.json")
		called := false
		w := atomicWriter{beforeWrite: func(tmp string) error {
			called = true
			if got := filepath.Dir(tmp); got != dir {
				t.Errorf("temp dir = %q, want %q", got, dir)
			}
			if tmp == path {
				t.Error("temp path equals target path")
			}
			info, err := os.Stat(tmp)
			if err != nil {
				t.Errorf("Stat(tmp) error = %v", err)
				return nil
			}
			if info.Size() != 0 {
				t.Errorf("temp size = %d before write, want 0", info.Size())
			}
			return nil
		}}
		if err := w.writeFile(path, data); err != nil {
			t.Fatalf("writeFile() error = %v", err)
		}
		if !called {
			t.Fatal("beforeWrite was not called")
		}
	})

	t.Run("beforeRename", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "pins.json")
		if err := os.WriteFile(path, oldData, fileMode); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		called := false
		w := atomicWriter{beforeRename: func(tmp string) error {
			called = true
			if got := filepath.Dir(tmp); got != filepath.Dir(path) {
				t.Errorf("temp dir = %q, want %q", got, filepath.Dir(path))
			}
			if tmp == path {
				t.Error("temp path equals target path")
			}
			got, err := readFile(t, tmp)
			if err != nil {
				t.Errorf("ReadFile(tmp) error = %v", err)
				return nil
			}
			if !bytes.Equal(got, data) {
				t.Errorf("temp content = %q, want the full data %q", got, data)
			}
			// The reader still sees the old file until the rename.
			old, err := readFile(t, path)
			if err != nil {
				t.Errorf("ReadFile(target) error = %v", err)
				return nil
			}
			if !bytes.Equal(old, oldData) {
				t.Errorf("target = %q before rename, want old content %q", old, oldData)
			}
			wantPerm(t, tmp, fileMode)
			return nil
		}}
		if err := w.writeFile(path, data); err != nil {
			t.Fatalf("writeFile() error = %v", err)
		}
		if !called {
			t.Fatal("beforeRename was not called")
		}
		got, err := readFile(t, path)
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("target = %q after rename, want %q", got, data)
		}
	})
}

func TestWriteFileAtomicParentIsFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		rel  string
	}{
		{name: "direct parent is a file", rel: filepath.Join("blocker", "pins.json")},
		{name: "ancestor is a file", rel: filepath.Join("blocker", "sub", "pins.json")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			blocker := filepath.Join(root, "blocker")
			if err := os.WriteFile(blocker, []byte("not a dir"), fileMode); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}

			err := writeFileAtomic(filepath.Join(root, tt.rel), []byte("x"))

			if err == nil {
				t.Fatal("writeFileAtomic() error = nil, want error when the parent is a regular file")
			}
			got, readErr := readFile(t, blocker)
			if readErr != nil {
				t.Fatalf("ReadFile() error = %v", readErr)
			}
			if string(got) != "not a dir" {
				t.Errorf("blocker file = %q, want it unchanged", got)
			}
			if names, want := dirNames(t, root), []string{"blocker"}; !slices.Equal(names, want) {
				t.Errorf("dir entries = %v, want %v", names, want)
			}
		})
	}
}

// TestWriteFileAtomicTargetIsDir checks that the rename error path also removes
// the temp file and keeps the directory in place.
func TestWriteFileAtomicTargetIsDir(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("rename over a directory behaves differently on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "pins.json")
	if err := os.Mkdir(path, dirMode); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}

	if err := writeFileAtomic(path, []byte("x")); err == nil {
		t.Fatal("writeFileAtomic() error = nil, want error when the target is a directory")
	}

	if names, want := dirNames(t, dir), []string{"pins.json"}; !slices.Equal(names, want) {
		t.Errorf("dir entries = %v, want %v (no temp file)", names, want)
	}
}
