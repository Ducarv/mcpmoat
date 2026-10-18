package discover

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

func TestReadConfigFile(t *testing.T) {
	t.Parallel()

	const limit = 8

	tests := []struct {
		name       string
		setup      func(t *testing.T) string // returns the path to read
		maxSize    int64
		wantData   string
		wantFound  bool
		wantReason string // empty means no FileError
	}{
		{
			name: "regular file",
			setup: func(t *testing.T) string {
				return writeFile(t, t.TempDir(), "a.json", []byte(`{"a":1}`))
			},
			maxSize:   limit * 2,
			wantData:  `{"a":1}`,
			wantFound: true,
		},
		{
			name: "empty file is found",
			setup: func(t *testing.T) string {
				return writeFile(t, t.TempDir(), "empty.json", nil)
			},
			maxSize:   limit,
			wantData:  "",
			wantFound: true,
		},
		{
			name: "size exactly at the limit",
			setup: func(t *testing.T) string {
				return writeFile(t, t.TempDir(), "exact.json", bytes.Repeat([]byte("x"), limit))
			},
			maxSize:   limit,
			wantData:  "xxxxxxxx",
			wantFound: true,
		},
		{
			name: "size one byte over the limit",
			setup: func(t *testing.T) string {
				return writeFile(t, t.TempDir(), "big.json", bytes.Repeat([]byte("x"), limit+1))
			},
			maxSize:    limit,
			wantReason: reasonTooLarge,
		},
		{
			name: "missing path",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing.json")
			},
			maxSize: limit,
		},
		{
			name: "missing parent directory",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "no-dir", "missing.json")
			},
			maxSize: limit,
		},
		{
			name: "parent is a regular file",
			setup: func(t *testing.T) string {
				// ENOTDIR: no config can exist below a regular file.
				skipOnWindows(t)
				parent := writeFile(t, t.TempDir(), "file", []byte("x"))
				return filepath.Join(parent, "config.json")
			},
			maxSize: limit,
		},
		{
			name: "directory",
			setup: func(t *testing.T) string {
				return t.TempDir()
			},
			maxSize:    limit,
			wantReason: reasonNotRegular,
		},
		{
			name: "valid symlink to a regular file",
			setup: func(t *testing.T) string {
				skipOnWindows(t)
				target := writeFile(t, t.TempDir(), "target.json", []byte("{}"))
				link := filepath.Join(t.TempDir(), "link.json")
				if err := os.Symlink(target, link); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				return link
			},
			maxSize:   limit,
			wantData:  "{}",
			wantFound: true,
		},
		{
			name: "dangling symlink counts as missing",
			setup: func(t *testing.T) string {
				skipOnWindows(t)
				link := filepath.Join(t.TempDir(), "dangling.json")
				if err := os.Symlink(filepath.Join(t.TempDir(), "gone.json"), link); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				return link
			},
			maxSize: limit,
		},
		{
			name: "symlink to a directory",
			setup: func(t *testing.T) string {
				skipOnWindows(t)
				link := filepath.Join(t.TempDir(), "dirlink.json")
				if err := os.Symlink(t.TempDir(), link); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				return link
			},
			maxSize:    limit,
			wantReason: reasonNotRegular,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := tt.setup(t)

			data, found, fe := readConfigFile(t.Context(), path, tt.maxSize)

			if tt.wantReason == "" {
				if fe != nil {
					t.Fatalf("fe = %v, want nil", fe)
				}
			} else {
				// A not-regular or too-large file has no OS error in Err.
				checkFileErrors(t, path, []*FileError{fe}, []errWant{{Reason: tt.wantReason}})
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
		})
	}
}

// skipOnWindows skips the test on Windows. The tests that call it use
// symlinks, FIFOs, file modes or path errors that behave differently there.
func skipOnWindows(t testing.TB) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("not supported on windows")
	}
}

// TestReadConfigFileFIFO checks that a named pipe is rejected without being
// opened. Opening a FIFO that has no writer blocks forever, so the call must
// return before Open.
func TestReadConfigFileFIFO(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	// The mkfifo program is used because syscall.Mkfifo does not exist on every
	// OS, and a call to it would stop the package from compiling there.
	mkfifo, err := exec.LookPath("mkfifo")
	if err != nil {
		t.Skip("mkfifo not available")
	}
	path := filepath.Join(t.TempDir(), "pipe.json")
	if out, err := exec.CommandContext(t.Context(), mkfifo, path).CombinedOutput(); err != nil { //nolint:gosec // G204: mkfifo is found by LookPath, path is under t.TempDir()
		t.Skipf("mkfifo failed: %v: %s", err, out)
	}

	type result struct {
		data  []byte
		found bool
		fe    *FileError
	}
	done := make(chan result, 1)
	go func() {
		data, found, fe := readConfigFile(t.Context(), path, 1024)
		done <- result{data, found, fe}
	}()

	select {
	case got := <-done:
		checkFileErrors(t, path, []*FileError{got.fe}, []errWant{{Reason: reasonNotRegular}})
		if got.found || got.data != nil {
			t.Errorf("found = %v, data = %q, want false and nil", got.found, got.data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readConfigFile blocked on a FIFO")
	}
}

func TestReadConfigFileUnreadable(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)
	if os.Geteuid() == 0 {
		t.Skip("root can read files with mode 0")
	}

	path := writeFile(t, t.TempDir(), "locked.json", []byte(discovertest.CanaryEnv))
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() {
		// Restore the mode so t.TempDir cleanup can remove the file.
		_ = os.Chmod(path, 0o600)
	})

	data, found, fe := readConfigFile(t.Context(), path, 1024)

	checkFileErrors(t, path, []*FileError{fe}, []errWant{{Reason: reasonCannotRead, HasErr: true}})
	if !errors.Is(fe, fs.ErrPermission) {
		t.Errorf("errors.Is(fe, fs.ErrPermission) = false, fe = %v", fe)
	}
	var pathErr *fs.PathError
	if !errors.As(fe, &pathErr) {
		t.Errorf("errors.As(fe, *fs.PathError) = false, fe.Err = %T", fe.Err)
	}
	if found || data != nil {
		t.Errorf("found = %v, data = %q, want false and nil", found, data)
	}
	discovertest.AssertNoLeak(t, "unreadable file error", fe.Error())
}

func TestReadConfigFileTooLargeNoLeak(t *testing.T) {
	t.Parallel()

	content := []byte(discovertest.CanaryEnv + discovertest.CanaryHeader)
	path := writeFile(t, t.TempDir(), "big.json", content)

	data, found, fe := readConfigFile(t.Context(), path, 8)

	checkFileErrors(t, path, []*FileError{fe}, []errWant{{Reason: reasonTooLarge}})
	if found || data != nil {
		t.Errorf("found = %v, data = %q, want false and nil", found, data)
	}
	discovertest.AssertNoLeak(t, "oversize file error", fe.Error())
}

func TestReadConfigFileCanceled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path func(t *testing.T) string
	}{
		{
			name: "existing file is not read",
			path: func(t *testing.T) string {
				return writeFile(t, t.TempDir(), "a.json", []byte(discovertest.CanaryEnv))
			},
		},
		{
			// The context check runs before Stat, so a missing file is still a
			// cancel error and not "missing".
			name: "missing file still reports cancel",
			path: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing.json")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := tt.path(t)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			data, found, fe := readConfigFile(ctx, path, 1024)

			checkFileErrors(t, path, []*FileError{fe}, []errWant{{Reason: reasonCanceled, HasErr: true}})
			if !errors.Is(fe, context.Canceled) {
				t.Errorf("errors.Is(fe, context.Canceled) = false, fe = %v", fe)
			}
			if found || data != nil {
				t.Errorf("found = %v, data = %q, want false and nil", found, data)
			}
			discovertest.AssertNoLeak(t, "canceled error", fe.Error())
		})
	}
}

func TestReadConfigFileDeadlineExceeded(t *testing.T) {
	t.Parallel()

	path := writeFile(t, t.TempDir(), "a.json", []byte("{}"))
	ctx, cancel := context.WithDeadline(t.Context(), time.Unix(0, 0))
	defer cancel()

	_, found, fe := readConfigFile(ctx, path, 1024)

	checkFileErrors(t, path, []*FileError{fe}, []errWant{{Reason: reasonCanceled, HasErr: true}})
	if !errors.Is(fe, context.DeadlineExceeded) {
		t.Errorf("errors.Is(fe, context.DeadlineExceeded) = false, fe = %v", fe)
	}
	if found {
		t.Error("found = true, want false")
	}
}
