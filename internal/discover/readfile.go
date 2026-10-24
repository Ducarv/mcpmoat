package discover

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/Ducarv/mcpmoat/internal/safefile"
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

// maxServersPerFile is the largest number of entries (servers, and projects
// in ~/.claude.json) that one config file may hold. All readers use it. See
// the package doc, Reading configs.
const maxServersPerFile = 10000

// readConfigFile reads the config file at path.
//
// It returns found=false and no error when the file does not exist. A
// dangling symlink counts as missing, and so does a path whose parent is not
// a directory (ENOTDIR): no config file can exist below a regular file. Every
// other problem comes back as a *FileError.
//
// root is the project directory for a project file. root == "" is only for a
// trusted global config file (a file of the user under Home): that file is
// opened with symlinks followed and no confinement. With a root, the file is opened through os.Root and a path or symlink
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
		return nil, false, canceledError(path, err)
	}

	if root != "" {
		return readInRoot(path, maxSize, root)
	}
	return readTrusted(path, maxSize)
}

// readInRoot reads path, which must be below the directory root, through
// safefile.ReadBoundedRegularFile. A path that is not below root is refused
// before any file is opened. A root that is missing or is not a directory
// counts as a missing file.
func readInRoot(path string, maxSize int64, root string) (data []byte, found bool, fe *FileError) {
	rel, err := filepath.Rel(root, path)
	if err != nil || !filepath.IsLocal(rel) {
		return nil, false, readError(path, reasonOutsideProject, nil)
	}
	data, found, err = safefile.ReadBoundedRegularFile(root, rel, maxSize)
	if err != nil {
		return nil, false, toFileError(path, err)
	}
	return data, found, nil
}

// readTrusted reads path and follows symlinks, with no confinement. It is only
// for a trusted global config file (see readConfigFile).
func readTrusted(path string, maxSize int64) (data []byte, found bool, fe *FileError) {
	// Open first, then check the open file, so the checks and the read use the
	// same file. See safefile.OpenFlags for why the open cannot block.
	f, err := os.OpenFile(path, safefile.OpenFlags, 0) //nolint:gosec // G304: root == "" only for a trusted global config file under Home.
	if err != nil {
		if safefile.IsMissing(err) {
			return nil, false, nil
		}
		return nil, false, readError(path, reasonCannotRead, err)
	}
	defer func() {
		// The file is read-only, so a close error is not useful.
		_ = f.Close()
	}()

	data, err = safefile.ReadOpened(f, maxSize)
	if err != nil {
		return nil, false, toFileError(path, err)
	}
	return data, true, nil
}

// toFileError turns an error of the safefile package into a FileError for
// path. An OS error is kept as it is in FileError.Err, so errors.As with
// *fs.PathError and errors.Is with fs.ErrPermission still work.
func toFileError(path string, err error) *FileError {
	switch {
	case errors.Is(err, safefile.ErrOutsideRoot):
		return readError(path, reasonOutsideProject, nil)
	case errors.Is(err, safefile.ErrNotRegular):
		return readError(path, reasonNotRegular, nil)
	case errors.Is(err, safefile.ErrTooLarge):
		return readError(path, reasonTooLarge, nil)
	default:
		return readError(path, reasonCannotRead, err)
	}
}
