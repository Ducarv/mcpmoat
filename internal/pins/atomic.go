package pins

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Directory and file modes of the pins store. Pass them explicitly: the
// default modes of the os package depend on the umask and are too open.
const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

// atomicWriter writes a file so that a reader sees the old content or the new
// content, never a mix of both.
//
// The two hook fields exist only so that a test can simulate a crash or an I/O
// failure in the middle of a write. The zero value has no hooks and is the
// value that production code uses. We pass the hooks in a struct instead of
// using package-level variables, so there is no global mutable state and the
// tests can run in parallel.
type atomicWriter struct {
	// beforeWrite runs after the temp file exists and before the data is
	// written. If it returns an error, the write step fails with that error.
	beforeWrite func(tmp string) error
	// beforeRename runs after the data is synced and the temp file is closed,
	// and before the rename. If it returns an error, the rename step fails with
	// that error.
	beforeRename func(tmp string) error
}

// writeFileAtomic writes data to path with the production settings: no hooks,
// directory mode 0o700 and file mode 0o600.
func writeFileAtomic(path string, data []byte) error {
	return atomicWriter{}.writeFile(path, data)
}

// writeFile writes data to path through a temp file in the same directory.
//
// The temp file is in the same directory, so the rename stays on one file
// system and is atomic. The name is random (os.CreateTemp), so two mcpmoat
// processes never write to the same temp file. When an error happens before
// the rename succeeds, the temp file is removed and the old file is not
// touched. An existing directory keeps its mode; a new directory gets 0o700.
func (w atomicWriter) writeFile(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	f, err := os.CreateTemp(dir, ".pins-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmp := f.Name()
	// The named result err lets this deferred function see a failure from any
	// return below. After a successful rename err is nil and the temp name no
	// longer exists, so we do not remove anything.
	defer func() {
		if err != nil {
			// A second Close on a closed file only returns an error, which we ignore.
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()

	if w.beforeWrite != nil {
		if err = w.beforeWrite(tmp); err != nil {
			return fmt.Errorf("write temp file: %w", err)
		}
	}
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	// os.CreateTemp already uses mode 0o600. The explicit Chmod keeps the mode
	// independent of that detail. It works on the open descriptor, so a path that
	// someone swapped cannot redirect it.
	if err = f.Chmod(fileMode); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if w.beforeRename != nil {
		if err = w.beforeRename(tmp); err != nil {
			return fmt.Errorf("rename temp file: %w", err)
		}
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	syncDir(dir)
	return nil
}

// syncDir flushes the directory entry of the new file to disk, so the rename
// survives a power loss. It is best effort: the data is already in place, and
// some platforms and file systems cannot sync a directory.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return // Windows cannot open a directory with os.Open.
	}
	d, err := os.Open(dir) //nolint:gosec // G304: dir is the parent of the pins path that the caller chose.
	if err != nil {
		return
	}
	// Ignore both errors: the rename is done, and a failed directory sync
	// must not report a failed save.
	_ = d.Sync()
	_ = d.Close()
}
