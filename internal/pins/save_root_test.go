//go:build unix

package pins

// These tests cover Save through the os.Root of the pins directory (#225):
// Save writes to the directory that LoadLocked (or, for a Store from Load,
// Save itself) opened and checked, and fails with ErrPinsDirChanged when the
// path names another directory before the rename. They move, remove and
// replace open directories, which Windows does not allow, so they are unix
// only.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// saveRootSeed makes the pins directory base/pins (mode 0o700) with a valid
// pins.json and returns the directory and the path of pins.json.
func saveRootSeed(t *testing.T) (dir, path string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "pins")
	if err := os.Mkdir(dir, dirMode); err != nil {
		t.Fatalf("Mkdir(%q) error = %v", dir, err)
	}
	return dir, seedPins(t, dir, fileMode)
}

// saveRootLoadLocked runs LoadLocked on path and releases the lock at the end
// of the test. It returns the release function too, for a test that releases
// earlier (a second call does nothing).
func saveRootLoadLocked(t *testing.T, path string) (*Store, func()) {
	t.Helper()
	s, release, err := LoadLocked(t.Context(), path, 0)
	if err != nil {
		t.Fatalf("LoadLocked(%q) error = %v", path, err)
	}
	t.Cleanup(release)
	return s, release
}

// saveRootLoad runs Load on path. It has the shape of saveRootLoadLocked, so a
// table can hold both.
func saveRootLoad(t *testing.T, path string) (*Store, func()) {
	t.Helper()
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q) error = %v", path, err)
	}
	return s, noop
}

// saveRootSet adds a pin for the server name to s.
func saveRootSet(t *testing.T, s *Store, name string) {
	t.Helper()
	id := Identity{Client: "cursor", Source: "/home/u/.cursor/mcp.json", Name: name}
	if err := s.Set(id, ServerPins{"t": {Hash: "h-" + name, Canonical: "c-" + name}}); err != nil {
		t.Fatalf("Set(%q) error = %v", name, err)
	}
}

// saveRootHas reports whether the Store at path (read with Load) has the
// server name.
func saveRootHas(t *testing.T, path, name string) bool {
	t.Helper()
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q) error = %v", path, err)
	}
	_, ok := s.Get(Identity{Client: "cursor", Source: "/home/u/.cursor/mcp.json", Name: name})
	return ok
}

// wantDirChanged fails the test unless err wraps ErrPinsDirChanged and has the
// exact text of verifyPinsDir, with the "save <path>: " prefix.
func wantDirChanged(t *testing.T, err error, path string) {
	t.Helper()
	if !errors.Is(err, ErrPinsDirChanged) {
		t.Fatalf("Save() error = %v, want it to wrap ErrPinsDirChanged", err)
	}
	want := "save " + path + ": the pins directory " + filepath.Dir(path) +
		" was moved, removed or replaced while this command ran, and nothing was saved: " + ErrPinsDirChanged.Error()
	if err.Error() != want {
		t.Errorf("Save() error = %q, want %q", err, want)
	}
}

// wantEntries fails the test unless the entries of dir are exactly want. A
// leftover temp file of the writer makes the list differ.
func wantEntries(t *testing.T, dir string, want ...string) {
	t.Helper()
	if got := dirNames(t, dir); !slices.Equal(got, want) {
		t.Errorf("entries of %s = %v, want %v", dir, got, want)
	}
}

// TestSaveLockedDirReplaced covers a pins directory that is moved away after
// LoadLocked, while something else takes its path. Save must not write to the
// new directory, and must not write the moved one either.
func TestSaveLockedDirReplaced(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// replace puts something at dir and returns the directory that the
		// path now names, or "" when nothing is there.
		replace func(t *testing.T, dir string) string
	}{
		{name: "symlink to another directory", replace: func(t *testing.T, dir string) string {
			other := filepath.Join(filepath.Dir(dir), "other")
			if err := os.Mkdir(other, dirMode); err != nil {
				t.Fatalf("Mkdir() error = %v", err)
			}
			if err := os.Symlink(other, dir); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
			return other
		}},
		{name: "new directory", replace: func(t *testing.T, dir string) string {
			if err := os.Mkdir(dir, dirMode); err != nil {
				t.Fatalf("Mkdir() error = %v", err)
			}
			return dir
		}},
		{name: "nothing", replace: func(*testing.T, string) string { return "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, path := saveRootSeed(t)
			s, _ := saveRootLoadLocked(t, path)
			saveRootSet(t, s, "beta")
			moved := filepath.Join(filepath.Dir(dir), "moved")
			if err := os.Rename(dir, moved); err != nil {
				t.Fatalf("Rename() error = %v", err)
			}
			now := tt.replace(t, dir)

			wantDirChanged(t, s.Save(), path)

			if now != "" {
				wantEntries(t, now)
			}
			wantEntries(t, moved, "pins.json", lockName)
			if got := readFile(t, filepath.Join(moved, "pins.json")); string(got) != validPins {
				t.Errorf("moved pins.json = %q, want the old content %q", got, validPins)
			}
		})
	}
}

// TestSaveAfterOtherRunRemovedDir is the case of the issue: run A holds the
// lock, the pins directory is removed, and run B creates a new one and locks
// its new lock file. B saves; A must then fail and must not overwrite B.
func TestSaveAfterOtherRunRemovedDir(t *testing.T) {
	t.Parallel()
	dir, path := saveRootSeed(t)
	a, _ := saveRootLoadLocked(t, path)
	saveRootSet(t, a, "from-a")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll() error = %v", err)
	}

	b, _ := saveRootLoadLocked(t, path)
	if b.Existed() {
		t.Error("run B: Existed() = true, want false: the directory is new")
	}
	saveRootSet(t, b, "from-b")
	if err := b.Save(); err != nil {
		t.Fatalf("run B: Save() error = %v", err)
	}
	written := readFile(t, path)

	wantDirChanged(t, a.Save(), path)

	if got := readFile(t, path); string(got) != string(written) {
		t.Errorf("pins.json after the Save of run A = %q, want the file of run B %q", got, written)
	}
	if !saveRootHas(t, path, "from-b") || saveRootHas(t, path, "from-a") {
		t.Error("pins.json must hold the server of run B and not the server of run A")
	}
	wantEntries(t, dir, "pins.json", lockName)
}

// TestSaveFromLoad covers case 2 of Save: a Store from Load keeps no
// directory, so Save opens the directory again with the checks of LoadLocked.
func TestSaveFromLoad(t *testing.T) {
	t.Parallel()

	t.Run("first run creates the directories", func(t *testing.T) {
		t.Parallel()
		base := t.TempDir()
		dir := filepath.Join(base, "a", "b")
		path := filepath.Join(dir, "pins.json")
		s, _ := saveRootLoad(t, path)
		saveRootSet(t, s, "beta")

		if err := s.Save(); err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		wantPerm(t, path, 0o600)
		// MkdirAll gives every directory it creates the same mode.
		wantPerm(t, dir, 0o700)
		wantPerm(t, filepath.Join(base, "a"), 0o700)
		// Load takes no lock, so there is no lock file.
		wantEntries(t, dir, "pins.json")
		if !saveRootHas(t, path, "beta") {
			t.Error("the saved file has no server beta")
		}
	})

	t.Run("keeps the mode of an existing directory", func(t *testing.T) {
		t.Parallel()
		dir := newPinsDir(t, 0o755)
		s, _ := saveRootLoad(t, filepath.Join(dir, "pins.json"))

		if err := s.Save(); err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		wantPerm(t, dir, 0o755)
	})

	// The pins directory did not exist at Load, and another process made it
	// with an unsafe mode before Save. Save checks the directory itself and
	// writes nothing.
	t.Run("refuses a directory that appeared unsafe after Load", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "pins")
		s, _ := saveRootLoad(t, filepath.Join(dir, "pins.json"))
		if err := os.Mkdir(dir, dirMode); err != nil {
			t.Fatalf("Mkdir() error = %v", err)
		}
		chmodForTest(t, dir, 0o777)
		t.Cleanup(func() { _ = os.Chmod(dir, dirMode) })

		err := s.Save()

		wantInsecure(t, err, dir, "pins directory {path}", "mode 0777", msgChmod, msgWritable)
		wantEntries(t, dir)
		wantPerm(t, dir, 0o777)
	})

	t.Run("refuses a directory that became group-writable after Load", func(t *testing.T) {
		t.Parallel()
		dir, path := saveRootSeed(t)
		s, _ := saveRootLoad(t, path)
		saveRootSet(t, s, "beta")
		chmodForTest(t, dir, 0o770)
		t.Cleanup(func() { _ = os.Chmod(dir, dirMode) })

		err := s.Save()

		wantInsecure(t, err, dir, "pins directory {path}", "mode 0770", msgChmod, msgWritable)
		if got := readFile(t, path); string(got) != validPins {
			t.Errorf("pins.json = %q, want the old content", got)
		}
		wantEntries(t, dir, "pins.json")
	})

	t.Run("cannot create the directory", func(t *testing.T) {
		t.Parallel()
		if os.Geteuid() == 0 {
			t.Skip("root can write a read-only directory")
		}
		parent := newNamedPinsDir(t, "parent", 0o500)
		path := filepath.Join(parent, "pins", "pins.json")
		s, _ := saveRootLoad(t, path)

		err := s.Save()

		if prefix := "save " + path + ": create the pins directory: "; err == nil || !strings.HasPrefix(err.Error(), prefix) {
			t.Fatalf("Save() error = %v, want the prefix %q", err, prefix)
		}
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("Save() error = %v, want errors.Is fs.ErrPermission", err)
		}
		wantEntries(t, parent)
	})

	// A file took the place of a directory after Load: the text of
	// checkFirstRun, with the "save" prefix.
	for _, rel := range []string{"blocker", filepath.Join("blocker", "sub")} {
		t.Run("parent is a file/"+rel, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			path := filepath.Join(base, rel, "pins.json")
			s, _ := saveRootLoad(t, path)
			blocker := filepath.Join(base, "blocker")
			if err := os.WriteFile(blocker, []byte("not a dir"), fileMode); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}

			err := s.Save()

			want := "save " + path + ": " + blocker + " is not a directory, or it is a symlink with a missing target"
			if err == nil || err.Error() != want {
				t.Errorf("Save() error = %v, want %q", err, want)
			}
			if got := readFile(t, blocker); string(got) != "not a dir" {
				t.Errorf("blocker file = %q, want it unchanged", got)
			}
			wantEntries(t, base, "blocker")
		})
	}
}

// TestSaveAfterRelease checks that a Save after the release function of
// LoadLocked fails with an error and does not panic, for the Store and for a
// Clone of it, and that it writes nothing.
func TestSaveAfterRelease(t *testing.T) {
	t.Parallel()
	for _, clone := range []bool{false, true} {
		name := "store"
		if clone {
			name = "clone"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir, path := saveRootSeed(t)
			s, release := saveRootLoadLocked(t, path)
			if clone {
				s = s.Clone()
			}
			saveRootSet(t, s, "beta")
			release()

			err := s.Save()

			if !errors.Is(err, os.ErrClosed) {
				t.Errorf("Save() error = %v, want errors.Is os.ErrClosed", err)
			}
			if prefix := "save " + path + ": "; err == nil || !strings.HasPrefix(err.Error(), prefix) {
				t.Errorf("Save() error = %v, want the prefix %q", err, prefix)
			}
			if got := readFile(t, path); string(got) != validPins {
				t.Errorf("pins.json = %q, want the old content", got)
			}
			wantEntries(t, dir, "pins.json", lockName)
		})
	}
}

// TestCloneOfLockedStoreSharesRoot checks that a Clone of a Store from
// LoadLocked saves through the directory that LoadLocked opened, not through
// the path.
func TestCloneOfLockedStoreSharesRoot(t *testing.T) {
	t.Parallel()
	dir, path := saveRootSeed(t)
	s, _ := saveRootLoadLocked(t, path)
	c := s.Clone()
	if c.root != s.root || c.dir != s.dir || c.dirInfo != s.dirInfo {
		t.Fatal("Clone() does not share the open pins directory of the Store")
	}
	saveRootSet(t, c, "beta")

	if err := c.Save(); err != nil {
		t.Fatalf("Save() of the clone error = %v", err)
	}
	if !saveRootHas(t, path, "beta") {
		t.Error("the saved file has no server beta")
	}
	wantEntries(t, dir, "pins.json", lockName)

	// The path now names another directory: the clone still writes through
	// the shared root, so the check before the rename refuses it.
	moved := filepath.Join(filepath.Dir(dir), "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if err := os.Mkdir(dir, dirMode); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	wantDirChanged(t, c.Save(), path)
	wantEntries(t, dir)
}

// TestSaveDirMovedBeforeRename moves the pins directory in the small window
// between the write of the temp file and the rename, with the beforeRename
// hook. The check right before the rename must stop the write, and the temp
// file must go away from the directory that holds it (the moved one).
func TestSaveDirMovedBeforeRename(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		load func(t *testing.T, path string) (*Store, func())
		// want are the entries of the moved directory after the Save.
		want []string
	}{
		{name: "LoadLocked", load: saveRootLoadLocked, want: []string{"pins.json", lockName}},
		{name: "Load", load: saveRootLoad, want: []string{"pins.json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, path := saveRootSeed(t)
			s, _ := tt.load(t, path)
			saveRootSet(t, s, "beta")
			moved := filepath.Join(filepath.Dir(dir), "moved")
			var tmpInMoved string
			w := atomicWriter{beforeRename: func(tmp string) error {
				if err := os.Rename(dir, moved); err != nil {
					t.Fatalf("Rename() error = %v", err)
				}
				if err := os.Mkdir(dir, dirMode); err != nil {
					t.Fatalf("Mkdir() error = %v", err)
				}
				// The temp file moved with its directory.
				tmpInMoved = filepath.Join(moved, filepath.Base(tmp))
				if _, err := os.Lstat(tmpInMoved); err != nil {
					t.Errorf("temp file not in the moved directory: %v", err)
				}
				return nil
			}}

			wantDirChanged(t, s.saveWith(w), path)

			if tmpInMoved == "" {
				t.Fatal("beforeRename was not called")
			}
			if _, err := os.Lstat(tmpInMoved); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("temp file %s still exists (Lstat error = %v)", tmpInMoved, err)
			}
			if got := dirNames(t, moved); !slices.Equal(got, tt.want) {
				t.Errorf("entries of the moved directory = %v, want %v", got, tt.want)
			}
			if got := readFile(t, filepath.Join(moved, "pins.json")); string(got) != validPins {
				t.Errorf("moved pins.json = %q, want the old content %q", got, validPins)
			}
			wantEntries(t, dir)
		})
	}
}
