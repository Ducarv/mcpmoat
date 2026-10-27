package pins

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
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

// readFile reads path and fails the test on an error. It is the one place
// that carries the gosec exception; store_test.go uses it as pins.ReadFile. The hooks run on the test goroutine, so
// they can call it too: t.Fatal there still runs the cleanup in writeFile.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: the test builds path under t.TempDir().
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	return data
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

// tempNameRE is the name of a temp file of writeFile.
var tempNameRE = regexp.MustCompile(`^\.pins-[0-9a-f]{16}\.tmp$`)

// openDir opens dir as an os.Root and a handle of the directory itself, as
// openPinsDir does, and closes both at the end of the test.
func openDir(t *testing.T, dir string) (*os.Root, *os.File) {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot(%q) error = %v", dir, err)
	}
	d, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		t.Fatalf("root.Open(\".\") error = %v", err)
	}
	t.Cleanup(func() { closeDir(root, d) })
	return root, d
}

// countVerify returns a verifyDir function that counts its calls in *n and
// returns err.
func countVerify(n *int, err error) func() error {
	return func() error {
		*n++
		return err
	}
}

// writeTestFile runs w.writeFile on pins.json in dir with a verifyDir that
// passes, and fails the test on an error.
func writeTestFile(t *testing.T, w atomicWriter, dir string, data []byte) {
	t.Helper()
	root, d := openDir(t, dir)
	var calls int
	if err := w.writeFile(root, d, "pins.json", data, countVerify(&calls, nil)); err != nil {
		t.Fatalf("writeFile() error = %v", err)
	}
	if calls != 1 {
		t.Errorf("verifyDir calls = %d, want 1", calls)
	}
}

func TestWriteFileCreatesFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "pins.json")
	data := []byte(`{"version":1}`)

	writeTestFile(t, atomicWriter{}, dir, data)

	if got := readFile(t, path); !bytes.Equal(got, data) {
		t.Errorf("content = %q, want %q", got, data)
	}
	wantPerm(t, path, 0o600)
	if names, want := dirNames(t, dir), []string{"pins.json"}; !slices.Equal(names, want) {
		t.Errorf("dir entries = %v, want %v", names, want)
	}
}

func TestWriteFileReplacesExistingFile(t *testing.T) {
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

			writeTestFile(t, atomicWriter{}, dir, tt.newData)

			if got := readFile(t, path); !bytes.Equal(got, tt.newData) {
				t.Errorf("content = %q, want %q", got, tt.newData)
			}
			wantPerm(t, path, 0o600)
			if names, want := dirNames(t, dir), []string{"pins.json"}; !slices.Equal(names, want) {
				t.Errorf("dir entries = %v, want %v", names, want)
			}
		})
	}
}

// TestWriteFileFailureKeepsOldFile checks every failure after the temp file
// exists: a hook or verifyDir fails. The temp file is removed, and the old file
// (when there is one) is not touched.
func TestWriteFileFailureKeepsOldFile(t *testing.T) {
	t.Parallel()
	errBoom := errors.New("simulated crash")
	tests := []struct {
		name string
		// writer builds the writer under test. Its hooks store the temp path in
		// *tmp. verify is the verifyDir function: it may use *tmp too.
		writer func(tmp *string) atomicWriter
		verify func(t *testing.T, tmp *string) func() error
		// wantExact means the error is errBoom itself, not a wrap of it.
		wantExact bool
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
		{
			name: "verifyDir fails",
			writer: func(tmp *string) atomicWriter {
				return atomicWriter{beforeRename: func(p string) error { *tmp = p; return nil }}
			},
			// verifyDir runs after beforeRename: the temp file holds the full
			// data then.
			verify: func(t *testing.T, tmp *string) func() error {
				return func() error {
					if *tmp == "" {
						t.Error("verifyDir ran before beforeRename")
					} else if got := readFile(t, *tmp); string(got) != `{"new":true}` {
						t.Errorf("temp content at verifyDir = %q, want the full data", got)
					}
					return errBoom
				}
			},
			wantExact: true,
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
				root, d := openDir(t, dir)
				var tmp string
				verify := func() error { return nil }
				if tt.verify != nil {
					verify = tt.verify(t, &tmp)
				}

				err := tt.writer(&tmp).writeFile(root, d, "pins.json", []byte(`{"new":true}`), verify)

				if !errors.Is(err, errBoom) {
					t.Fatalf("writeFile() error = %v, want it to wrap %v", err, errBoom)
				}
				if tt.wantExact && err.Error() != errBoom.Error() {
					t.Errorf("writeFile() error = %q, want the verifyDir error as it is", err)
				}
				if tmp == "" {
					t.Fatal("hook was not called")
				}
				if _, statErr := os.Lstat(tmp); !errors.Is(statErr, os.ErrNotExist) {
					t.Errorf("temp file %q still exists (Lstat error = %v)", tmp, statErr)
				}
				if existing {
					if got := readFile(t, path); !bytes.Equal(got, oldData) {
						t.Errorf("target = %q, want old content %q", got, oldData)
					}
					if names, want := dirNames(t, dir), []string{"pins.json"}; !slices.Equal(names, want) {
						t.Errorf("dir entries = %v, want %v", names, want)
					}
					return
				}
				if names := dirNames(t, dir); len(names) != 0 {
					t.Errorf("dir entries = %v, want none", names)
				}
			})
		}
	}
}

// TestWriteFileTempFileState checks the temp file at each hook point.
// A temp file that sits in the target directory and holds all the data is what
// makes the final rename atomic.
func TestWriteFileTempFileState(t *testing.T) {
	t.Parallel()
	data := []byte("new content")
	oldData := []byte("old content")

	// wantTempName checks that tmp is a temp file name of writeFile in dir.
	wantTempName := func(t *testing.T, dir, tmp string) {
		t.Helper()
		if got := filepath.Dir(tmp); got != dir {
			t.Errorf("temp dir = %q, want %q", got, dir)
		}
		if base := filepath.Base(tmp); !tempNameRE.MatchString(base) {
			t.Errorf("temp name = %q, want it to match %s", base, tempNameRE)
		}
	}

	t.Run("beforeWrite", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		called := false
		w := atomicWriter{beforeWrite: func(tmp string) error {
			called = true
			wantTempName(t, dir, tmp)
			info, err := os.Lstat(tmp)
			if err != nil {
				t.Errorf("Lstat(tmp) error = %v", err)
				return nil
			}
			if !info.Mode().IsRegular() || info.Size() != 0 {
				t.Errorf("temp file mode = %v, size = %d before write, want an empty regular file", info.Mode(), info.Size())
			}
			wantPerm(t, tmp, 0o600)
			return nil
		}}
		writeTestFile(t, w, dir, data)
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
			wantTempName(t, dir, tmp)
			if got := readFile(t, tmp); !bytes.Equal(got, data) {
				t.Errorf("temp content = %q, want the full data %q", got, data)
			}
			// The reader still sees the old file until the rename.
			if old := readFile(t, path); !bytes.Equal(old, oldData) {
				t.Errorf("target = %q before rename, want old content %q", old, oldData)
			}
			wantPerm(t, tmp, 0o600)
			return nil
		}}
		writeTestFile(t, w, dir, data)
		if !called {
			t.Fatal("beforeRename was not called")
		}
		if got := readFile(t, path); !bytes.Equal(got, data) {
			t.Errorf("target = %q after rename, want %q", got, data)
		}
		if names, want := dirNames(t, dir), []string{"pins.json"}; !slices.Equal(names, want) {
			t.Errorf("dir entries = %v, want %v", names, want)
		}
	})
}

// TestWriteFileCreateFails checks that a failed create of the temp file runs
// verifyDir, and that an error of verifyDir wins: a removed directory then
// gets the real cause, not "no such file or directory".
func TestWriteFileCreateFails(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot remove a directory that is open")
	}
	errChanged := errors.New("the directory changed")
	tests := []struct {
		name      string
		verifyErr error
		wantText  string
		wantIs    error
	}{
		{name: "verifyDir error wins", verifyErr: errChanged, wantText: errChanged.Error(), wantIs: errChanged},
		{name: "verifyDir passes", verifyErr: nil, wantText: "create temp file: ", wantIs: fs.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join(t.TempDir(), "pins")
			if err := os.Mkdir(dir, dirMode); err != nil {
				t.Fatalf("Mkdir() error = %v", err)
			}
			root, d := openDir(t, dir)
			// A removed directory cannot hold a new file, also through an open
			// handle.
			if err := os.Remove(dir); err != nil {
				t.Fatalf("Remove() error = %v", err)
			}
			hook := func(string) error {
				t.Error("a hook ran after a failed create")
				return nil
			}
			w := atomicWriter{beforeWrite: hook, beforeRename: hook}
			var calls int

			err := w.writeFile(root, d, "pins.json", []byte("x"), countVerify(&calls, tt.verifyErr))

			if err == nil {
				t.Fatal("writeFile() error = nil, want error")
			}
			if calls != 1 {
				t.Errorf("verifyDir calls = %d, want 1", calls)
			}
			if !strings.HasPrefix(err.Error(), tt.wantText) {
				t.Errorf("writeFile() error = %q, want it to start with %q", err, tt.wantText)
			}
			if !errors.Is(err, tt.wantIs) {
				t.Errorf("writeFile() error = %v, want errors.Is %v", err, tt.wantIs)
			}
		})
	}
}

// TestWriteFileFollowsOpenDir checks that writeFile writes to the directory
// that root opened, not to whatever the path names at the time of the write.
func TestWriteFileFollowsOpenDir(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot rename a directory that is open")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "pins")
	moved := filepath.Join(base, "moved")
	if err := os.Mkdir(dir, dirMode); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	root, d := openDir(t, dir)
	if err := os.Rename(dir, moved); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if err := os.Mkdir(dir, dirMode); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}

	// verifyDir passes on purpose: the test checks only where the write goes.
	if err := (atomicWriter{}).writeFile(root, d, "pins.json", []byte("x"), func() error { return nil }); err != nil {
		t.Fatalf("writeFile() error = %v", err)
	}

	if got := readFile(t, filepath.Join(moved, "pins.json")); string(got) != "x" {
		t.Errorf("content in the opened directory = %q, want %q", got, "x")
	}
	if names := dirNames(t, dir); len(names) != 0 {
		t.Errorf("entries of the new directory at the path = %v, want none", names)
	}
}

// TestWriteFileTargetIsDir checks that the rename error path also removes
// the temp file and keeps the directory in place.
func TestWriteFileTargetIsDir(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("rename over a directory behaves differently on Windows")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "pins.json"), dirMode); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	root, d := openDir(t, dir)

	err := (atomicWriter{}).writeFile(root, d, "pins.json", []byte("x"), func() error { return nil })

	if err == nil || !strings.HasPrefix(err.Error(), "rename temp file: ") {
		t.Fatalf("writeFile() error = %v, want a rename error when the target is a directory", err)
	}
	if names, want := dirNames(t, dir), []string{"pins.json"}; !slices.Equal(names, want) {
		t.Errorf("dir entries = %v, want %v (no temp file)", names, want)
	}
}
