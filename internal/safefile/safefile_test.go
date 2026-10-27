package safefile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// canary is content that must never appear in an error string.
const canary = "CANARY-SECRET-VALUE-9f3a"

// limit is the size cap that most tests use.
const limit = 8

// skipOnWindows skips a test that needs Unix file semantics.
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs Unix file semantics")
	}
}

// writeFile writes data to name below dir and creates parent directories.
func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// symlinkTo creates the symlink name below dir that points at target.
func symlinkTo(t *testing.T, target, dir, name string) {
	t.Helper()
	skipOnWindows(t)
	if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
		t.Skipf("cannot create a symlink: %v", err)
	}
}

// makeFIFO creates a named pipe at path, or skips the test if it cannot.
func makeFIFO(t *testing.T, path string) {
	t.Helper()
	skipOnWindows(t)
	// The mkfifo program is used because syscall.Mkfifo does not exist on every
	// OS, and a call to it would stop the package from compiling there.
	mkfifo, err := exec.LookPath("mkfifo")
	if err != nil {
		t.Skip("mkfifo not available")
	}
	if out, err := exec.CommandContext(t.Context(), mkfifo, path).CombinedOutput(); err != nil { //nolint:gosec // G204: mkfifo is found by LookPath, path is under t.TempDir()
		t.Skipf("mkfifo failed: %v: %s", err, out)
	}
}

func TestReadBoundedRegularFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup returns the directory to read and the file name in it.
		setup     func(t *testing.T) (dir, name string)
		wantData  string
		wantFound bool
		wantErr   error // nil means no error
	}{
		{
			name: "regular file",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				writeFile(t, dir, "a.json", []byte(`{"a":1}`))
				return dir, "a.json"
			},
			wantData:  `{"a":1}`,
			wantFound: true,
		},
		{
			name: "empty file is found",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				writeFile(t, dir, "empty", nil)
				return dir, "empty"
			},
			wantData:  "",
			wantFound: true,
		},
		{
			name: "file in a subdirectory",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				writeFile(t, dir, "sub/a.json", []byte("{}"))
				return dir, filepath.Join("sub", "a.json")
			},
			wantData:  "{}",
			wantFound: true,
		},
		{
			name: "size exactly at the cap",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				writeFile(t, dir, "exact", bytes.Repeat([]byte("x"), limit))
				return dir, "exact"
			},
			wantData:  "xxxxxxxx",
			wantFound: true,
		},
		{
			name: "size one byte over the cap",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				writeFile(t, dir, "big", bytes.Repeat([]byte("x"), limit+1))
				return dir, "big"
			},
			wantErr: ErrTooLarge,
		},
		{
			name: "directory",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				return dir, "d"
			},
			wantErr: ErrNotRegular,
		},
		{
			name: "symlink to a directory inside the root",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				symlinkTo(t, "d", dir, "link")
				return dir, "link"
			},
			wantErr: ErrNotRegular,
		},
		{
			name: "relative symlink inside the root is followed",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				writeFile(t, dir, "config/real.json", []byte("{}"))
				symlinkTo(t, filepath.Join("config", "real.json"), dir, "link.json")
				return dir, "link.json"
			},
			wantData:  "{}",
			wantFound: true,
		},
		{
			name: "relative symlink that leaves the root",
			setup: func(t *testing.T) (string, string) {
				parent := t.TempDir()
				dir := filepath.Join(parent, "project")
				writeFile(t, parent, "secret.json", []byte(canary))
				writeFile(t, dir, "keep", nil)
				symlinkTo(t, filepath.Join("..", "secret.json"), dir, "link.json")
				return dir, "link.json"
			},
			wantErr: ErrOutsideRoot,
		},
		{
			name: "absolute symlink that leaves the root",
			setup: func(t *testing.T) (string, string) {
				target := writeFile(t, t.TempDir(), "secret.json", []byte(canary))
				dir := t.TempDir()
				symlinkTo(t, target, dir, "link.json")
				return dir, "link.json"
			},
			wantErr: ErrOutsideRoot,
		},
		{
			// os.Root refuses every absolute symlink, even one that points
			// back into the root.
			name: "absolute symlink to a file inside the root",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				target := writeFile(t, dir, "real.json", []byte("{}"))
				symlinkTo(t, target, dir, "link.json")
				return dir, "link.json"
			},
			wantErr: ErrOutsideRoot,
		},
		{
			name: "symlinked directory that leaves the root",
			setup: func(t *testing.T) (string, string) {
				outside := t.TempDir()
				writeFile(t, outside, "mcp.json", []byte(canary))
				dir := t.TempDir()
				symlinkTo(t, outside, dir, ".cursor")
				return dir, filepath.Join(".cursor", "mcp.json")
			},
			wantErr: ErrOutsideRoot,
		},
		{
			name: "dangling symlink that leaves the root",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				symlinkTo(t, filepath.Join("..", "gone", "x.json"), dir, "link.json")
				return dir, "link.json"
			},
			wantErr: ErrOutsideRoot,
		},
		{
			name: "name with a dot-dot element",
			setup: func(t *testing.T) (string, string) {
				parent := t.TempDir()
				writeFile(t, parent, "x", []byte(canary))
				dir := filepath.Join(parent, "project")
				writeFile(t, dir, "keep", nil)
				return dir, filepath.Join("..", "x")
			},
			wantErr: ErrOutsideRoot,
		},
		{
			name: "missing file",
			setup: func(t *testing.T) (string, string) {
				return t.TempDir(), "missing.json"
			},
		},
		{
			name: "missing directory",
			setup: func(t *testing.T) (string, string) {
				return filepath.Join(t.TempDir(), "gone"), "a.json"
			},
		},
		{
			name: "missing subdirectory",
			setup: func(t *testing.T) (string, string) {
				return t.TempDir(), filepath.Join("no-dir", "a.json")
			},
		},
		{
			// ENOTDIR: no file can exist below a regular file.
			name: "path component is a regular file",
			setup: func(t *testing.T) (string, string) {
				skipOnWindows(t)
				dir := t.TempDir()
				writeFile(t, dir, ".cursor", []byte("x"))
				return dir, filepath.Join(".cursor", "mcp.json")
			},
		},
		{
			name: "dangling symlink inside the root counts as missing",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				symlinkTo(t, "gone.json", dir, "link.json")
				return dir, "link.json"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, name := tt.setup(t)

			data, found, err := ReadBoundedRegularFile(dir, name, limit)

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("error = %v, want nil", err)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want errors.Is %v", err, tt.wantErr)
			}
			if found != tt.wantFound {
				t.Errorf("found = %v, want %v", found, tt.wantFound)
			}
			if string(data) != tt.wantData {
				t.Errorf("data = %q, want %q", data, tt.wantData)
			}
			if !tt.wantFound && data != nil {
				t.Errorf("data = %q, want nil when not found", data)
			}
			if err != nil && strings.Contains(err.Error(), canary) {
				t.Errorf("error %q holds file content", err)
			}
		})
	}
}

// TestReadBoundedRegularFileDirNotDirectory checks a dir that is not a
// directory. No file can exist below it, so it counts as missing. A FIFO as dir
// must not block: a plain os.OpenRoot waits for a writer for ever.
func TestReadBoundedRegularFileDirNotDirectory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T) string // returns dir
	}{
		{
			name: "regular file",
			setup: func(t *testing.T) string {
				skipOnWindows(t)
				return writeFile(t, t.TempDir(), "file", []byte(canary))
			},
		},
		{
			name: "fifo",
			setup: func(t *testing.T) string {
				dir := filepath.Join(t.TempDir(), ".cursor")
				makeFIFO(t, dir)
				return dir
			},
		},
		{
			name: "symlink to a fifo",
			setup: func(t *testing.T) string {
				parent := t.TempDir()
				makeFIFO(t, filepath.Join(parent, "pipe"))
				symlinkTo(t, "pipe", parent, ".cursor")
				return filepath.Join(parent, ".cursor")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := tt.setup(t)

			type result struct {
				data    []byte
				found   bool
				err     error
				rootErr error
			}
			done := make(chan result, 1)
			go func() {
				var r result
				r.data, r.found, r.err = ReadBoundedRegularFile(dir, "mcp.json", limit)
				root, err := OpenRoot(dir)
				if err == nil {
					_ = root.Close()
				}
				r.rootErr = err
				done <- r
			}()

			select {
			case got := <-done:
				if got.err != nil || got.found || got.data != nil {
					t.Errorf("ReadBoundedRegularFile() = (%q, %v, %v), want (nil, false, nil)", got.data, got.found, got.err)
				}
				if !errors.Is(got.rootErr, syscall.ENOTDIR) {
					t.Errorf("OpenRoot() error = %v, want errors.Is ENOTDIR", got.rootErr)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("blocked on a dir that is not a directory")
			}
		})
	}
}

// TestReadBoundedRegularFileOutsideRootKeepsCause checks that ErrOutsideRoot
// keeps the os.Root error, so the caller can still see the cause.
func TestReadBoundedRegularFileOutsideRootKeepsCause(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, _, err := ReadBoundedRegularFile(dir, filepath.Join("..", "x"), limit)

	if !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("error = %v, want errors.Is ErrOutsideRoot", err)
	}
	if _, ok := errors.AsType[*fs.PathError](err); !ok {
		t.Errorf("errors.AsType[*fs.PathError] = false, error is %v", err)
	}
}

// TestReadBoundedRegularFileDirPermissionDenied checks a dir that exists but
// cannot be opened. The OS error comes back as it is, not as a missing file.
func TestReadBoundedRegularFileDirPermissionDenied(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)
	if os.Geteuid() == 0 {
		t.Skip("root can open directories with mode 0")
	}

	dir := filepath.Join(t.TempDir(), "locked")
	writeFile(t, dir, "a.json", []byte(canary))
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() {
		// Restore the mode so the t.TempDir cleanup can remove the directory.
		_ = os.Chmod(dir, 0o700) //nolint:gosec // G302: a directory needs the execute bit; it is under t.TempDir()
	})

	data, found, err := ReadBoundedRegularFile(dir, "a.json", 1024)

	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("error = %v, want errors.Is fs.ErrPermission", err)
	}
	if IsMissing(err) {
		t.Error("IsMissing(err) = true, want false")
	}
	if found || data != nil {
		t.Errorf("found = %v, data = %q, want false and nil", found, data)
	}
}

func TestReadBoundedRegularFilePermissionDenied(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)
	if os.Geteuid() == 0 {
		t.Skip("root can read files with mode 0")
	}

	dir := t.TempDir()
	path := writeFile(t, dir, "locked.json", []byte(canary))
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() {
		// Restore the mode so the t.TempDir cleanup can remove the file.
		_ = os.Chmod(path, 0o600)
	})

	data, found, err := ReadBoundedRegularFile(dir, "locked.json", 1024)

	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("error = %v, want errors.Is fs.ErrPermission", err)
	}
	if _, ok := errors.AsType[*fs.PathError](err); !ok {
		t.Errorf("errors.AsType[*fs.PathError] = false, error is %T", err)
	}
	if IsMissing(err) {
		t.Error("IsMissing(err) = true, want false")
	}
	if found || data != nil {
		t.Errorf("found = %v, data = %q, want false and nil", found, data)
	}
	if strings.Contains(err.Error(), canary) {
		t.Errorf("error %q holds file content", err)
	}
}

// TestReadBoundedRegularFileFIFO checks that a named pipe with no writer is
// opened without blocking and then refused. A blocking open of a FIFO waits
// for a writer for ever, so the open uses O_NONBLOCK.
func TestReadBoundedRegularFileFIFO(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	makeFIFO(t, filepath.Join(dir, "pipe.json"))

	type result struct {
		data  []byte
		found bool
		err   error
	}
	done := make(chan result, 1)
	go func() {
		data, found, err := ReadBoundedRegularFile(dir, "pipe.json", 1024)
		done <- result{data, found, err}
	}()

	select {
	case got := <-done:
		if !errors.Is(got.err, ErrNotRegular) {
			t.Errorf("error = %v, want errors.Is ErrNotRegular", got.err)
		}
		if got.found || got.data != nil {
			t.Errorf("found = %v, data = %q, want false and nil", got.found, got.data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadBoundedRegularFile blocked on a FIFO")
	}
}

// fakeInfo is an fs.FileInfo with a fixed mode and size.
type fakeInfo struct {
	mode fs.FileMode
	size int64
}

func (fakeInfo) Name() string        { return "fake" }
func (i fakeInfo) Size() int64       { return i.size }
func (i fakeInfo) Mode() fs.FileMode { return i.mode }
func (fakeInfo) ModTime() time.Time  { return time.Time{} }
func (i fakeInfo) IsDir() bool       { return i.mode.IsDir() }
func (fakeInfo) Sys() any            { return nil }

// fakeFile is an fs.File whose Stat answer and content are set by the test, so
// a test can make Stat and Read disagree.
type fakeFile struct {
	info    fakeInfo
	statErr error
	content io.Reader
}

func (f fakeFile) Stat() (fs.FileInfo, error) {
	if f.statErr != nil {
		return nil, f.statErr
	}
	return f.info, nil
}

func (f fakeFile) Read(p []byte) (int, error) { return f.content.Read(p) }
func (fakeFile) Close() error                 { return nil }

// errReader returns some bytes and then an error.
type errReader struct {
	data []byte
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestReadOpened(t *testing.T) {
	t.Parallel()

	errStat := errors.New("stat failed")
	errRead := errors.New("read failed")

	tests := []struct {
		name     string
		file     fakeFile
		wantData string
		wantErr  error // nil means no error
	}{
		{
			name:     "regular file",
			file:     fakeFile{info: fakeInfo{size: 2}, content: strings.NewReader("ok")},
			wantData: "ok",
		},
		{
			name:     "size exactly at the cap",
			file:     fakeFile{info: fakeInfo{size: limit}, content: strings.NewReader("12345678")},
			wantData: "12345678",
		},
		{
			name:    "stat reports a size over the cap",
			file:    fakeFile{info: fakeInfo{size: limit + 1}, content: strings.NewReader("123456789")},
			wantErr: ErrTooLarge,
		},
		{
			// The file grew after Stat: Stat says 2 bytes, Read gives 9.
			name:    "grew after stat",
			file:    fakeFile{info: fakeInfo{size: 2}, content: strings.NewReader("123456789")},
			wantErr: ErrTooLarge,
		},
		{
			name:    "grew after stat, far over the cap",
			file:    fakeFile{info: fakeInfo{size: 2}, content: strings.NewReader(strings.Repeat("x", 1000))},
			wantErr: ErrTooLarge,
		},
		{
			name:    "stat error",
			file:    fakeFile{statErr: errStat},
			wantErr: errStat,
		},
		{
			name:    "read error",
			file:    fakeFile{info: fakeInfo{size: 2}, content: &errReader{data: []byte("ab"), err: errRead}},
			wantErr: errRead,
		},
		{
			name:    "named pipe",
			file:    fakeFile{info: fakeInfo{mode: fs.ModeNamedPipe}, content: strings.NewReader("")},
			wantErr: ErrNotRegular,
		},
		{
			name:    "directory",
			file:    fakeFile{info: fakeInfo{mode: fs.ModeDir}, content: strings.NewReader("")},
			wantErr: ErrNotRegular,
		},
		{
			name:    "device",
			file:    fakeFile{info: fakeInfo{mode: fs.ModeDevice}, content: strings.NewReader("")},
			wantErr: ErrNotRegular,
		},
		{
			name:    "symlink mode",
			file:    fakeFile{info: fakeInfo{mode: fs.ModeSymlink}, content: strings.NewReader("")},
			wantErr: ErrNotRegular,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := ReadOpened(tt.file, limit)

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("error = %v, want nil", err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want errors.Is %v", err, tt.wantErr)
				}
				if data != nil {
					t.Errorf("data = %q, want nil with an error", data)
				}
			}
			if string(data) != tt.wantData {
				t.Errorf("data = %q, want %q", data, tt.wantData)
			}
		})
	}
}

func TestReadOpenedRealFile(t *testing.T) {
	t.Parallel()

	path := writeFile(t, t.TempDir(), "a", []byte("hello"))
	f, err := os.Open(path) //nolint:gosec // G304: path is under t.TempDir()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	data, err := ReadOpened(f, limit)
	if err != nil {
		t.Fatalf("ReadOpened() error = %v, want nil", err)
	}
	if string(data) != "hello" {
		t.Errorf("data = %q, want %q", data, "hello")
	}
}

// TestReadOpenedMaxCap checks that the largest cap still reads the file. The
// read limit is maxSize+1, which would overflow to a negative limit and read
// nothing.
func TestReadOpenedMaxCap(t *testing.T) {
	t.Parallel()

	f := fakeFile{info: fakeInfo{size: 2}, content: strings.NewReader("ok")}

	data, err := ReadOpened(f, math.MaxInt64)

	if err != nil {
		t.Fatalf("ReadOpened() error = %v, want nil", err)
	}
	if string(data) != "ok" {
		t.Errorf("data = %q, want %q", data, "ok")
	}
}

func TestOpenInRoot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, dir, "a.json", []byte("{}"))
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })

	t.Run("existing file", func(t *testing.T) {
		t.Parallel()
		f, err := OpenInRoot(root, "a.json")
		if err != nil {
			t.Fatalf("OpenInRoot() error = %v, want nil", err)
		}
		defer func() { _ = f.Close() }()
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		f, err := OpenInRoot(root, "missing.json")
		if !IsMissing(err) {
			t.Errorf("IsMissing(%v) = false, want true", err)
		}
		if f != nil {
			t.Error("file != nil, want nil with an error")
		}
	})

	t.Run("dot-dot name", func(t *testing.T) {
		t.Parallel()
		f, err := OpenInRoot(root, "../x")
		if err == nil {
			t.Fatal("OpenInRoot() error = nil, want an error")
		}
		if IsMissing(err) {
			t.Errorf("IsMissing(%v) = true, want false", err)
		}
		if f != nil {
			t.Error("file != nil, want nil with an error")
		}
	})
}

func TestIsMissing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "ErrNotExist", err: fs.ErrNotExist, want: true},
		{name: "ENOENT", err: syscall.ENOENT, want: true},
		{name: "ENOTDIR", err: syscall.ENOTDIR, want: true},
		{name: "PathError with ErrNotExist", err: &fs.PathError{Op: "open", Path: "p", Err: fs.ErrNotExist}, want: true},
		{name: "PathError with ENOENT", err: &fs.PathError{Op: "open", Path: "p", Err: syscall.ENOENT}, want: true},
		{name: "PathError with ENOTDIR", err: &fs.PathError{Op: "open", Path: "p", Err: syscall.ENOTDIR}, want: true},
		{name: "wrapped ErrNotExist", err: fmt.Errorf("read: %w", fs.ErrNotExist), want: true},
		{name: "wrapped PathError with ENOTDIR", err: fmt.Errorf("read: %w", &fs.PathError{Op: "open", Path: "p", Err: syscall.ENOTDIR}), want: true},
		{name: "ErrPermission", err: fs.ErrPermission, want: false},
		{name: "EACCES", err: syscall.EACCES, want: false},
		{name: "PathError with ErrPermission", err: &fs.PathError{Op: "open", Path: "p", Err: fs.ErrPermission}, want: false},
		{name: "ErrNotRegular", err: ErrNotRegular, want: false},
		{name: "ErrOutsideRoot", err: ErrOutsideRoot, want: false},
		{name: "other error", err: errors.New("boom"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsMissing(tt.err); got != tt.want {
				t.Errorf("IsMissing(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestErrorsHoldNoContent checks that the errors for a bad file never hold the
// content of the file. It is the regression guard for that rule: one case per
// error kind, each with the canary as content. Some cases overlap with
// TestReadBoundedRegularFile on purpose, so the rule has one test to look at.
func TestErrorsHoldNoContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T) (dir, name string)
		wantErr error
	}{
		{
			name: "too large",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				writeFile(t, dir, "big", []byte(canary))
				return dir, "big"
			},
			wantErr: ErrTooLarge,
		},
		{
			name: "outside the root",
			setup: func(t *testing.T) (string, string) {
				target := writeFile(t, t.TempDir(), "secret", []byte(canary))
				dir := t.TempDir()
				symlinkTo(t, target, dir, "link")
				return dir, "link"
			},
			wantErr: ErrOutsideRoot,
		},
		{
			name: "not regular",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				// d holds a canary file; refusing d must not read or quote it.
				writeFile(t, dir, "d/secret", []byte(canary))
				return dir, "d"
			},
			wantErr: ErrNotRegular,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, name := tt.setup(t)

			// The cap is smaller than the canary, so a regular file is too large.
			_, _, err := ReadBoundedRegularFile(dir, name, 4)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want errors.Is %v", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), canary) {
				t.Errorf("error %q holds file content", err)
			}
		})
	}

	t.Run("grew after stat", func(t *testing.T) {
		t.Parallel()
		f := fakeFile{info: fakeInfo{size: 1}, content: strings.NewReader(canary)}

		_, err := ReadOpened(f, 4)

		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("error = %v, want errors.Is ErrTooLarge", err)
		}
		if strings.Contains(err.Error(), canary) {
			t.Errorf("error %q holds file content", err)
		}
	})
}

// openRootT opens dir as an os.Root and closes it when the test ends.
func openRootT(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

// openIfExistsInRootT calls OpenIfExistsInRoot and closes a returned file when
// the test ends.
func openIfExistsInRootT(t *testing.T, root *os.Root, name string) (*os.File, bool, error) {
	t.Helper()
	f, found, err := OpenIfExistsInRoot(root, name)
	if f != nil {
		t.Cleanup(func() { _ = f.Close() })
	}
	return f, found, err
}

func TestOpenIfExistsInRoot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup fills dir, the root, and returns the name to open.
		setup     func(t *testing.T, dir string) string
		wantFound bool
		wantErr   error // nil means no error
		// check, when set, checks the file that was found.
		check func(t *testing.T, f *os.File)
	}{
		{
			name: "regular file",
			setup: func(t *testing.T, dir string) string {
				writeFile(t, dir, "pins.json", []byte(`{"a":1}`))
				return "pins.json"
			},
			wantFound: true,
			check: func(t *testing.T, f *os.File) {
				fi, err := f.Stat()
				if err != nil {
					t.Fatalf("Stat() error = %v", err)
				}
				if !fi.Mode().IsRegular() || fi.Size() != int64(len(`{"a":1}`)) {
					t.Errorf("Stat() mode = %v, size = %d, want a regular file of 7 bytes", fi.Mode(), fi.Size())
				}
				data, err := io.ReadAll(f)
				if err != nil {
					t.Fatalf("ReadAll() error = %v", err)
				}
				if string(data) != `{"a":1}` {
					t.Errorf("data = %q, want %q", data, `{"a":1}`)
				}
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, dir string) string {
				if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				return "d"
			},
			wantFound: true,
			check: func(t *testing.T, f *os.File) {
				fi, err := f.Stat()
				if err != nil {
					t.Fatalf("Stat() error = %v", err)
				}
				if !fi.IsDir() {
					t.Errorf("Stat().IsDir() = false, mode %v, want a directory", fi.Mode())
				}
			},
		},
		{
			name:  "missing file",
			setup: func(*testing.T, string) string { return "pins.json" },
		},
		{
			name:  "missing directory component",
			setup: func(*testing.T, string) string { return filepath.Join("sub", "pins.json") },
		},
		{
			// ENOTDIR: no file can exist below a regular file.
			name: "parent is a regular file",
			setup: func(t *testing.T, dir string) string {
				skipOnWindows(t)
				writeFile(t, dir, "file", []byte(canary))
				return filepath.Join("file", "pins.json")
			},
		},
		{
			name: "absolute symlink that leaves the root",
			setup: func(t *testing.T, dir string) string {
				target := writeFile(t, t.TempDir(), "secret.json", []byte(canary))
				symlinkTo(t, target, dir, "pins.json")
				return "pins.json"
			},
			wantErr: ErrOutsideRoot,
		},
		{
			name: "dot-dot symlink that leaves the root",
			setup: func(t *testing.T, dir string) string {
				writeFile(t, filepath.Dir(dir), "secret.json", []byte(canary))
				symlinkTo(t, filepath.Join("..", "secret.json"), dir, "pins.json")
				return "pins.json"
			},
			wantErr: ErrOutsideRoot,
		},
		{
			name: "dot-dot name",
			setup: func(t *testing.T, dir string) string {
				writeFile(t, filepath.Dir(dir), "secret.json", []byte(canary))
				return filepath.Join("..", "secret.json")
			},
			wantErr: ErrOutsideRoot,
		},
		{
			// An OS error with an errno comes back as it is, not as
			// ErrOutsideRoot and not as missing.
			name: "permission denied",
			setup: func(t *testing.T, dir string) string {
				skipOnWindows(t)
				if os.Geteuid() == 0 {
					t.Skip("root can read files with mode 0")
				}
				path := writeFile(t, dir, "pins.json", []byte(canary))
				if err := os.Chmod(path, 0o000); err != nil {
					t.Fatalf("chmod: %v", err)
				}
				t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
				return "pins.json"
			},
			wantErr: fs.ErrPermission,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// dir is one level below a private parent, so a ".." target stays
			// inside this test's temp space.
			dir := filepath.Join(t.TempDir(), "root")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			name := tt.setup(t, dir)
			root := openRootT(t, dir)

			f, found, err := openIfExistsInRootT(t, root, name)

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("error = %v, want nil", err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want errors.Is %v", err, tt.wantErr)
				}
				if !errors.Is(tt.wantErr, ErrOutsideRoot) && errors.Is(err, ErrOutsideRoot) {
					t.Errorf("error = %v, want no ErrOutsideRoot", err)
				}
				if IsMissing(err) {
					t.Errorf("IsMissing(%v) = true, want false", err)
				}
				if strings.Contains(err.Error(), canary) {
					t.Errorf("error %q holds file content", err)
				}
			}
			if found != tt.wantFound {
				t.Errorf("found = %v, want %v", found, tt.wantFound)
			}
			if found != (f != nil) {
				t.Errorf("found = %v, file = %v, want a file exactly when found", found, f)
			}
			if tt.check != nil && f != nil {
				tt.check(t, f)
			}
		})
	}
}

// TestOpenIfExistsInRootFollowsSymlinkInsideRoot records that
// OpenIfExistsInRoot follows a symlink that stays inside the root. A caller
// that must refuse a symlink has to check it itself, for example with
// root.Lstat and os.SameFile.
func TestOpenIfExistsInRootFollowsSymlinkInsideRoot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, dir, "real.json", []byte("{}"))
	symlinkTo(t, "real.json", dir, "pins.json")
	root := openRootT(t, dir)

	f, found, err := openIfExistsInRootT(t, root, "pins.json")
	if err != nil || !found {
		t.Fatalf("OpenIfExistsInRoot() = (found %v, error %v), want (true, nil)", found, err)
	}

	opened, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !opened.Mode().IsRegular() {
		t.Errorf("opened mode = %v, want a regular file", opened.Mode())
	}
	target, err := root.Stat("real.json")
	if err != nil {
		t.Fatalf("root.Stat() error = %v", err)
	}
	if !os.SameFile(opened, target) {
		t.Error("os.SameFile(opened, real.json) = false, want true: the symlink is followed")
	}
	link, err := root.Lstat("pins.json")
	if err != nil {
		t.Fatalf("root.Lstat() error = %v", err)
	}
	if link.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("Lstat mode = %v, want a symlink", link.Mode())
	}
	// This difference is what a caller uses to refuse the symlink.
	if os.SameFile(opened, link) {
		t.Error("os.SameFile(opened, Lstat of the link) = true, want false")
	}
}

// TestOpenIfExistsInRootFIFO checks that a FIFO with no writer opens at once
// (O_NONBLOCK) and that the handle shows it is not a regular file. The caller
// must refuse it after Stat.
func TestOpenIfExistsInRootFIFO(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	makeFIFO(t, filepath.Join(dir, "pins.json"))
	root := openRootT(t, dir)

	type result struct {
		f     *os.File
		found bool
		err   error
	}
	done := make(chan result, 1)
	go func() {
		f, found, err := OpenIfExistsInRoot(root, "pins.json")
		done <- result{f, found, err}
	}()

	var got result
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("OpenIfExistsInRoot blocked on a FIFO")
	}
	if got.f != nil {
		t.Cleanup(func() { _ = got.f.Close() })
	}
	if got.err != nil || !got.found || got.f == nil {
		t.Fatalf("OpenIfExistsInRoot() = (%v, %v, %v), want an open file, true, nil", got.f, got.found, got.err)
	}
	fi, err := got.f.Stat()
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if fi.Mode().IsRegular() {
		t.Errorf("Stat() mode = %v, want not regular", fi.Mode())
	}
	if fi.Mode()&fs.ModeNamedPipe == 0 {
		t.Errorf("Stat() mode = %v, want a named pipe", fi.Mode())
	}
}
