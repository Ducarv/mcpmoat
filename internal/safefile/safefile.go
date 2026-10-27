// Package safefile is the shared hardened read of a file that mcpmoat does not
// trust, for example a config file, an ignore file or a rule file from a cloned
// repository.
//
// The read has four protections:
//   - os.Root confinement: a symlink cannot make the open leave the directory.
//   - No blocking on a FIFO: OpenRoot refuses a directory path that is not a
//     directory before it opens it (see OpenRoot for the race that we accept),
//     and the file open uses O_NONBLOCK. For a regular file the flag changes
//     nothing.
//   - Regular file only: a FIFO, a device or a directory is refused.
//   - A size cap, checked on Stat and checked again on the bytes read, so a
//     file that grew after Stat is still caught.
//
// ReadBoundedRegularFile does all four steps from a directory path. A caller
// that must check the directory on its open handle opens it with OpenRoot,
// checks it, and then opens the file with OpenIfExistsInRoot in the same root.
//
// The helpers return OS errors and the sentinel errors below, and no error
// holds file content. The OS errors are *fs.PathError values that hold the path
// and the errno only. The sentinels hold no path, so the caller adds the path
// and its own text.
package safefile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"syscall"
)

// OpenFlags are the flags of every open of an untrusted file. O_NONBLOCK makes
// the open of a FIFO return at once, also when no process writes to it, so the
// type check of the open file can refuse it.
const OpenFlags = os.O_RDONLY | syscall.O_NONBLOCK

// ErrNotRegular means that the file is not a regular file (for example a FIFO,
// a device or a directory).
var ErrNotRegular = errors.New("not a regular file")

// ErrTooLarge means that the file is larger than the size cap.
var ErrTooLarge = errors.New("file is too large")

// ErrOutsideRoot means that the path leaves the directory, for example through
// a symlink or a ".." element.
var ErrOutsideRoot = errors.New("path leaves the directory")

// ReadBoundedRegularFile reads the file called name in the directory dir.
//
// The file is opened through os.Root, so name and any symlink below dir cannot
// leave dir. found is false, with a nil error, when no file can exist at the
// path: dir or the file does not exist, or dir or a parent in the path is not a
// directory (see IsMissing and OpenRoot). A path that leaves dir gives
// ErrOutsideRoot. Other OS errors come back as they are, so callers can still
// use errors.As with *fs.PathError and errors.Is with fs.ErrPermission.
// ReadOpened gives the other errors: ErrNotRegular and ErrTooLarge.
//
// maxSize is the largest file size in bytes that is read. It must not be
// negative: with a negative maxSize every file gives ErrTooLarge.
func ReadBoundedRegularFile(dir, name string, maxSize int64) (data []byte, found bool, err error) {
	data, _, found, err = ReadBoundedRegularFileInfo(dir, name, maxSize)
	return data, found, err
}

// ReadBoundedRegularFileInfo works as ReadBoundedRegularFile and also returns
// the fs.FileInfo of the file that it read. The info comes from Stat on the
// open file, not from the path, so a caller that checks the owner or the mode
// of the info checks the same file as the data. found is true exactly when
// info is not nil. Both are zero when err is not nil. found stays in the result
// for symmetry with ReadBoundedRegularFile.
func ReadBoundedRegularFileInfo(dir, name string, maxSize int64) (data []byte, info fs.FileInfo, found bool, err error) {
	root, err := OpenRoot(dir)
	if err != nil {
		if IsMissing(err) {
			return nil, nil, false, nil
		}
		return nil, nil, false, err
	}
	defer func() {
		// Closing the root does not close the files opened through it.
		_ = root.Close()
	}()

	f, found, err := OpenIfExistsInRoot(root, name)
	if err != nil || !found {
		return nil, nil, false, err
	}
	defer func() {
		// The file is read-only, so a close error is not useful.
		_ = f.Close()
	}()

	data, info, err = readOpenedInfo(f, maxSize)
	if err != nil {
		return nil, nil, false, err
	}
	return data, info, true, nil
}

// ReadOpened reads the open file f with a hard size cap. It checks the open
// file, not the path, so the checks and the read use the same file. The caller
// opens f and closes it. f must not be nil.
//
// It returns ErrNotRegular when f is not a regular file, and ErrTooLarge when f
// is larger than maxSize bytes. maxSize must not be negative (see
// ReadBoundedRegularFile). The errors of Stat and of the read come back as they
// are.
func ReadOpened(f fs.File, maxSize int64) ([]byte, error) {
	data, _, err := readOpenedInfo(f, maxSize)
	return data, err
}

// readOpenedInfo works as ReadOpened and also returns the fs.FileInfo from the
// Stat of f. info is nil when err is not nil.
func readOpenedInfo(f fs.File, maxSize int64) ([]byte, fs.FileInfo, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, ErrNotRegular
	}
	if info.Size() > maxSize {
		return nil, nil, ErrTooLarge
	}

	// Read one byte more than the limit, so we can tell if the file grew after
	// Stat. maxSize+1 would overflow for math.MaxInt64, and no file is larger.
	readMax := maxSize
	if readMax < math.MaxInt64 {
		readMax++
	}
	data, err := io.ReadAll(io.LimitReader(f, readMax))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, nil, ErrTooLarge
	}
	return data, info, nil
}

// OpenRoot opens the directory dir as an os.Root without blocking.
//
// os.OpenRoot opens dir with a plain open(2), which blocks on a FIFO until a
// writer appears, so OpenRoot first checks dir with os.Stat, which does not
// block and follows symlinks as os.OpenRoot does. A dir that is not a
// directory gives a *fs.PathError with ENOTDIR, which IsMissing accepts.
//
// os.OpenRoot takes a path, not an open directory, so the check and the open
// can see different files. A local process that swaps dir between them wins a
// race that we accept: a FIFO blocks the open, and a regular file gives the
// "not a directory" error of os.OpenRoot, which has no ENOTDIR. A cloned
// repository cannot do this alone, because its files do not change while the
// scan runs.
func OpenRoot(dir string) (*os.Root, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &fs.PathError{Op: "open", Path: dir, Err: syscall.ENOTDIR}
	}
	return os.OpenRoot(dir)
}

// OpenInRoot opens the file called name, below root, for reading with
// OpenFlags, so opening a FIFO returns at once and does not wait for a writer;
// ReadOpened then refuses the FIFO. The file is nil when the error is not nil.
// A path that leaves root gives the os.Root error as it is, not ErrOutsideRoot.
// OpenIfExistsInRoot gives ErrOutsideRoot and the found result.
func OpenInRoot(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, OpenFlags, 0)
}

// OpenIfExistsInRoot opens the file called name, below root, with OpenInRoot
// and sorts the error the same way as ReadBoundedRegularFile. Use it when the
// caller already holds root, so the directory checks and the file open use the
// same directory handle and no path race is possible between them. Unlike
// OpenInRoot, it returns found, and it turns a path that leaves root into
// ErrOutsideRoot.
//
// found is false, with a nil file and a nil error, when no file can exist at
// the path (see IsMissing). A path that leaves root gives ErrOutsideRoot. Other
// OS errors come back as they are, so callers can still use errors.As with
// *fs.PathError and errors.Is with fs.ErrPermission. f is nil when found is
// false or err is not nil.
//
// OpenIfExistsInRoot does not check the file type or the size. The caller must
// Stat the returned file (ReadOpened does this) before it trusts the file, and
// the caller must close it.
func OpenIfExistsInRoot(root *os.Root, name string) (f *os.File, found bool, err error) {
	f, err = OpenInRoot(root, name)
	switch {
	case err == nil:
		return f, true, nil
	case IsMissing(err):
		return nil, false, nil
	case !isOSError(err):
		// os.Root refuses a path that leaves the root with an error that has no
		// OS error number (the error type is not exported, so we cannot test
		// for it with errors.Is). A few other refusals have no number either,
		// for example an empty name, so the cause is kept in the error.
		return nil, false, fmt.Errorf("%w: %w", ErrOutsideRoot, err)
	default:
		return nil, false, err
	}
}

// IsMissing reports whether err means that no file exists at the path: the
// path does not exist, or a parent in the path is not a directory (ENOTDIR).
func IsMissing(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// isOSError reports whether err holds an OS error number.
func isOSError(err error) bool {
	_, ok := errors.AsType[syscall.Errno](err)
	return ok
}
