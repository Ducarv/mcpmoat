package pins

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Directory and file modes of the pins store. Pass them explicitly: the
// default modes of the os package depend on the umask and are too open.
const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

// tempAttempts is how many random temp names writeFile tries before it gives
// up. With 64 random bits, a second attempt is already very unlikely: it
// happens only when a file with the same name exists, for example a planted
// one.
const tempAttempts = 5

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
	// written. tmp is the path of the temp file (the name of the root joined
	// to the temp name), for the test only: the write itself never uses a
	// path. If it returns an error, the write step fails with that error.
	beforeWrite func(tmp string) error
	// beforeRename runs after the data is synced and the temp file is closed,
	// and before the check of the directory and the rename. tmp is as in
	// beforeWrite. If it returns an error, the rename step fails with that
	// error.
	beforeRename func(tmp string) error
}

// writeFile writes data to the file name in root, through a temp file in the
// same directory. root is the open pins directory, and d is a handle of the
// same directory (root.Open(".")), used only to sync the directory entry.
// name is a base name, for example "pins.json".
//
// Every step goes through root or an open file, never through the path of the
// directory. So when the path names another directory meanwhile, the write
// still goes to the directory that the caller opened and checked (for
// LoadLocked, the directory that holds the lock file pins.json.lock that
// LoadLocked locked; the directory itself is not locked).
//
// The steps are:
//   - Create a temp file with a random name (.pins-<26 base32 chars>.tmp) and
//     O_EXCL, so two mcpmoat processes never write to the same temp file and
//     an existing file or symlink with that name is never followed.
//   - Write the data, set mode 0o600 on the open file, sync and close it.
//   - verifyDir: the caller checks that the path still names the directory
//     of root. When it does not, the write stops and the old file stays.
//   - Rename the temp file to name. The temp file is in the same directory,
//     so the rename stays on one file system and is atomic.
//   - Sync d, so the rename survives a power loss (best effort).
//
// When an error happens before the rename succeeds, the temp file is removed
// and the old file is not touched. writeFile does not create the directory and
// does not check its owner or mode: the caller opened and checked root.
//
// The error of verifyDir is returned as it is. When the temp file cannot be
// created, writeFile also calls verifyDir and returns its error, if any: a
// directory that was removed fails at the create already. The other errors
// name the step that failed, not the path: the caller adds it.
func (w atomicWriter) writeFile(root *os.Root, d *os.File, name string, data []byte, verifyDir func() error) (err error) {
	f, tmp, err := createTemp(root)
	if err != nil {
		// A removed directory cannot hold a new file, so the create fails with
		// "no such file or directory". verifyDir then names the real cause
		// (for example ErrPinsDirChanged) instead.
		if verifyErr := verifyDir(); verifyErr != nil {
			return verifyErr
		}
		return fmt.Errorf("create temp file: %w", err)
	}
	// The named result err lets this deferred function see a failure from any
	// return below. After a successful rename err is nil and the temp name no
	// longer exists, so we do not remove anything.
	defer func() {
		if err != nil {
			// A second Close on a closed file only returns an error, which we ignore.
			_ = f.Close()
			_ = root.Remove(tmp)
		}
	}()

	// hookPath is the path that the hooks get. root.Name is the path that the
	// root was opened with.
	hookPath := filepath.Join(root.Name(), tmp)
	if w.beforeWrite != nil {
		if err = w.beforeWrite(hookPath); err != nil {
			return fmt.Errorf("write temp file: %w", err)
		}
	}
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	// OpenFile already used mode 0o600, but the umask can only remove bits from
	// it, and a file system can ignore it. The explicit Chmod keeps the mode
	// independent of that detail. It works on the open descriptor, so a name
	// that someone swapped cannot redirect it.
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
		if err = w.beforeRename(hookPath); err != nil {
			return fmt.Errorf("rename temp file: %w", err)
		}
	}
	// Check the directory as late as possible, right before the rename. A
	// small window remains between this check and the rename (see
	// verifyPinsDir).
	if err = verifyDir(); err != nil {
		return err
	}
	if err = root.Rename(tmp, name); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	// Flush the directory entry of the new file to disk, so the rename survives
	// a power loss. It is best effort: the data is already in place, some
	// platforms (Windows) and file systems cannot sync a directory, and a
	// failed directory sync must not report a failed save. So the error is
	// ignored.
	_ = d.Sync()
	return nil
}

// createTemp creates a new temp file in root for writing, with mode 0o600, and
// returns it with its name. The name is ".pins-" plus 26 base32 characters from
// crypto/rand.Text, plus ".tmp". O_EXCL makes the create fail when the name exists,
// also as a symlink, so the file is always new. On such a collision createTemp
// tries again with a new name, up to tempAttempts times.
func createTemp(root *os.Root) (*os.File, string, error) {
	var err error
	for range tempAttempts {
		name := ".pins-" + rand.Text() + ".tmp"
		var f *os.File
		f, err = root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
		if err == nil {
			return f, name, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", err
}
