package discovertest

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// CopyFixture copies <dir>/home and <dir>/work (each optional) into a new
// t.TempDir() and returns the paths of the copies. Both returned directories
// always exist, even when the fixture has no such subdirectory, so a test can
// pass them as Home and WorkDir. Tests use the copies, never the fixture
// itself, so a reader can never change the repository's testdata.
//
// The copy keeps dotfiles such as ".claude.json". A symbolic link in the
// fixture becomes a symbolic link in the copy with the same target text, so
// a relative link keeps working. A file that is not a regular file, a
// directory or a symbolic link (for example a socket) stops the copy, and the
// test fails.
func CopyFixture(t testing.TB, dir string) (home, work string) {
	t.Helper()
	root := t.TempDir()
	home = filepath.Join(root, "home")
	work = filepath.Join(root, "work")
	copyOrCreate(t, filepath.Join(dir, "home"), home)
	copyOrCreate(t, filepath.Join(dir, "work"), work)
	return home, work
}

// copyOrCreate copies the directory src to dst. If src does not exist, it
// creates an empty dst instead. Any other error fails the test.
func copyOrCreate(t testing.TB, src, dst string) {
	t.Helper()
	_, err := os.Stat(src)
	switch {
	case err == nil:
		// os.DirFS(src) is a read-only view of src. os.CopyFS creates dst
		// and everything below it, and it does not overwrite files.
		if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
			t.Fatalf("copy fixture directory %s: %v", src, err)
		}
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(dst, 0o700); err != nil {
			t.Fatalf("create directory %s: %v", dst, err)
		}
	default:
		t.Fatalf("stat fixture directory %s: %v", src, err)
	}
}
