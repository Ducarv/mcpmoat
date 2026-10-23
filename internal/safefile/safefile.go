// Package safefile is the shared hardened read of a file that mcpmoat does not
// trust, for example a config file, an ignore file or a rule file from a cloned
// repository.
//
// The read has four protections:
//   - os.Root confinement: a symlink cannot make the open leave the directory.
//   - O_NONBLOCK: opening a FIFO returns at once, so a FIFO cannot block the
//     scan. For a regular file the flag changes nothing.
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
	"io"
	"io/fs"
	"os"
	"syscall"
)

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
// leave dir. found is false, with a nil error, when dir or the file does not
// exist (see IsMissing). A dir that is not a directory is an error, not a
// missing file. A path that leaves dir gives ErrOutsideRoot. Other OS
// errors come back as they are, so callers can still use errors.As with
// *fs.PathError and errors.Is with fs.ErrPermission. ReadOpened gives the other
// errors: ErrNotRegular and ErrTooLarge.
//
// maxSize is the largest file size in bytes that is read.
func ReadBoundedRegularFile(dir, name string, maxSize int64) (data []byte, found bool, err error) {
	root, err := os.OpenRoot(dir)
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
		// for it with errors.Is). Every OS problem has a number and is handled
		// by the other cases.
		return nil, false, ErrOutsideRoot
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
	// Stat.
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, ErrTooLarge
	}
	return data, nil
}

// OpenInRoot opens the file called name, below root, for reading. It uses
// O_NONBLOCK, so opening a FIFO returns at once and does not wait for a writer;
// ReadOpened then refuses the FIFO. The file is nil when the error is not nil.
func OpenInRoot(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
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
