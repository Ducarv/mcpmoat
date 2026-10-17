package discover

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
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
// entry costs memory and time, so a larger file gets a "too many servers" error
// and the rest is not decoded. All readers use it.
const maxServersPerFile = 10000

// readConfigFile reads the config file at path.
//
// It returns found=false and no error when the file does not exist. A dangling
// symlink counts as missing. Every other problem comes back as a *FileError.
//
// maxSize is a parameter, not a global variable, so tests can use a small
// limit. Production code passes maxConfigSize.
//
// The OS errors stored in FileError.Err are *fs.PathError values. They hold
// the path and the errno only, never file content, so they are safe to print.
func readConfigFile(ctx context.Context, path string, maxSize int64) (data []byte, found bool, fe *FileError) {
	if err := ctx.Err(); err != nil {
		return nil, false, &FileError{Path: path, Reason: reasonCanceled, Err: err}
	}

	// os.Stat follows symlinks, so a symlink to a regular file is accepted.
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, &FileError{Path: path, Reason: reasonCannotRead, Err: err}
	}

	// Check the type before Open: opening a FIFO could block forever.
	//
	// A small race stays. This check runs on the path, before Open. If a local
	// process swaps the path for a FIFO between Stat and Open, Open can block.
	// A static cloned repository cannot do this.
	if !info.Mode().IsRegular() {
		return nil, false, &FileError{Path: path, Reason: reasonNotRegular}
	}
	if info.Size() > maxSize {
		return nil, false, &FileError{Path: path, Reason: reasonTooLarge}
	}

	f, err := os.Open(path) //nolint:gosec // G304: path is a config file chosen by discovery or --config.
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The file was removed after Stat. Treat it as missing.
			return nil, false, nil
		}
		return nil, false, &FileError{Path: path, Reason: reasonCannotRead, Err: err}
	}
	defer func() {
		// The file is read-only, so a close error is not useful.
		_ = f.Close()
	}()

	// Read one byte more than the limit, so we can tell if the file grew
	// after Stat.
	data, err = io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, false, &FileError{Path: path, Reason: reasonCannotRead, Err: err}
	}
	if int64(len(data)) > maxSize {
		return nil, false, &FileError{Path: path, Reason: reasonTooLarge}
	}
	return data, true, nil
}
