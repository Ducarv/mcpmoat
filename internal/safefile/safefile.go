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
// The helpers return OS errors and the sentinel errors below. They hold the
// path and the errno only, never file content. The caller adds the path to the
// error and its own text.
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
// maxSize is the largest file size in bytes that is read.
func ReadBoundedRegularFile(dir, name string, maxSize int64) (data []byte, found bool, err error) {
	root, err := OpenRoot(dir)
	if err != nil {
		if IsMissing(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer func() {
		// Closing the root does not close the files opened through it.
		_ = root.Close()
	}()

	f, err := OpenInRoot(root, name)
	switch {
	case err == nil:
		// Go on below.
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
	defer func() {
		// The file is read-only, so a close error is not useful.
		_ = f.Close()
	}()

	data, err = ReadOpened(f, maxSize)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// ReadOpened reads the open file f with a hard size cap. It checks the open
// file, not the path, so the checks and the read use the same file. The caller
// opens f and closes it. f must not be nil.
//
// It returns ErrNotRegular when f is not a regular file, and ErrTooLarge when f
// is larger than maxSize bytes. The errors of Stat and of the read come back as
// they are.
func ReadOpened(f fs.File, maxSize int64) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	if info.Size() > maxSize {
		return nil, ErrTooLarge
	}

	// Read one byte more than the limit, so we can tell if the file grew after
	// Stat. maxSize+1 would overflow for math.MaxInt64, and no file is larger.
	limit := maxSize
	if limit < math.MaxInt64 {
		limit++
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, ErrTooLarge
	}
	return data, nil
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
func OpenInRoot(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, OpenFlags, 0)
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
