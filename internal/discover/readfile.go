package discover

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// maxConfigSize is the largest config file that discovery reads: 32 MiB.
// ~/.claude.json holds chat history and can grow to many MiB. The cap stops a
// huge file or a device from using all memory.
const maxConfigSize = 32 << 20

// maxProjectConfigSize is the largest project config file that discovery
// reads: 4 MiB. Project files (<WorkDir>/.mcp.json and <WorkDir>/.cursor/mcp.json)
// come from cloned repositories and are untrusted. Real ones are a few KiB. A
// 30 MiB file can cost seconds and hundreds of MiB to decode. ~/.claude.json
// keeps the 32 MiB cap because it holds chat history.
const maxProjectConfigSize = 4 << 20

// maxServersPerFile is the largest number of entries that one config file may
// hold. An entry is a server, or a project in ~/.claude.json. A file can be
// 32 MiB (maxConfigSize), and that is room for millions of tiny entries. Every
// entry costs memory and time, so a file with more entries gets a "too many
// servers" error and gives no servers. The cap bounds the result. It does not
// stop the decode of the file: the readers decode the whole map of entries
// before they count them, and the file size caps bound that memory. All
// readers use it.
const maxServersPerFile = 10000

// readConfigFile reads the config file at path.
//
// It returns found=false and no error when the file does not exist. A
// dangling symlink counts as missing, and so does a path whose parent is not
// a directory (ENOTDIR): no config file can exist below a regular file. Every
// other problem comes back as a *FileError.
//
// root is the project directory for a project file, and "" for any other
// file. With a root, the file is opened through os.Root and a path or symlink
// that leaves root is refused with reasonOutsideProject. readConfigFile never
// sets FileError.Untrusted: the reader that calls it does. See the package
// doc, Symlinks and Untrusted files.
//
// maxSize is a parameter, not a global variable, so each reader passes its
// own limit and tests can use a small one.
//
// The OS errors stored in FileError.Err are *fs.PathError values. They hold
// the path and the errno only, never file content, so they are safe to print.
func readConfigFile(ctx context.Context, path string, maxSize int64, root string) (data []byte, found bool, fe *FileError) {
	if err := ctx.Err(); err != nil {
		fe = canceledError(path, err)
		return nil, false, fe
	}

	// Open first, then check the open file. A check of the path before the
	// open could see another file than the one that is opened. O_NONBLOCK
	// makes the open of a FIFO return at once, also when no process writes to
	// it; the type check below then rejects it. For a regular file the flag
	// changes nothing.
	var f *os.File
	var err error
	if root != "" {
		f, fe = openInRoot(root, path)
	} else {
		f, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: path is a config file chosen by discovery or --config.
		if err != nil && !isMissing(err) {
			fe = readError(path, reasonCannotRead, err)
		}
	}
	if fe != nil || f == nil {
		// f is nil without an error when the file is missing.
		return nil, false, fe
	}
	defer func() {
		// The file is read-only, so a close error is not useful.
		_ = f.Close()
	}()

	info, err := f.Stat()
	if err != nil {
		return nil, false, readError(path, reasonCannotRead, err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, readError(path, reasonNotRegular, nil)
	}
	if info.Size() > maxSize {
		return nil, false, readError(path, reasonTooLarge, nil)
	}

	// Read one byte more than the limit, so we can tell if the file grew
	// after Stat.
	data, err = io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, false, readError(path, reasonCannotRead, err)
	}
	if int64(len(data)) > maxSize {
		return nil, false, readError(path, reasonTooLarge, nil)
	}
	return data, true, nil
}

// openInRoot opens path, which must be below the directory root, through
// os.Root. It returns a nil file and a nil error when the file is missing
// (see isMissing); a missing root directory counts as a missing file.
func openInRoot(root, path string) (*os.File, *FileError) {
	rel, err := filepath.Rel(root, path)
	if err != nil || !filepath.IsLocal(rel) {
		return nil, readError(path, reasonOutsideProject, nil)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		if isMissing(err) {
			return nil, nil
		}
		return nil, readError(path, reasonCannotRead, err)
	}
	defer func() {
		// Closing the root does not close the files opened through it.
		_ = r.Close()
	}()

	f, err := r.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	switch {
	case err == nil:
		return f, nil
	case isMissing(err):
		return nil, nil
	case isOSError(err):
		return nil, readError(path, reasonCannotRead, err)
	default:
		// os.Root refuses a path that leaves root with an error that has no
		// OS error number (it is not exported, so we cannot test for it with
		// errors.Is). Every OS problem has a number and is handled above.
		return nil, readError(path, reasonOutsideProject, nil)
	}
}

// readError returns the FileError of a read of path with the reason r and
// the OS error err (nil for none).
func readError(path string, r reason, err error) *FileError {
	return &FileError{Path: path, Reason: string(r), Err: err}
}

// isOSError reports whether err holds an OS error number.
func isOSError(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno)
}

// isMissing reports whether err means that no file exists at the path: the
// path does not exist, or a parent in the path is not a directory (ENOTDIR).
func isMissing(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}
