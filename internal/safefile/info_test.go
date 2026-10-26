package safefile

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadBoundedRegularFileInfo(t *testing.T) {
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
			name: "empty file",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				writeFile(t, dir, "empty", nil)
				return dir, "empty"
			},
			wantFound: true,
		},
		{
			name: "size exactly at the cap",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				writeFile(t, dir, "exact", bytes.Repeat([]byte("x"), limit))
				return dir, "exact"
			},
			wantData:  strings.Repeat("x", limit),
			wantFound: true,
		},
		{
			name: "missing file",
			setup: func(t *testing.T) (string, string) {
				return t.TempDir(), "nope"
			},
		},
		{
			name: "missing directory",
			setup: func(t *testing.T) (string, string) {
				return filepath.Join(t.TempDir(), "nope"), "a.json"
			},
		},
		{
			name: "directory is a regular file",
			setup: func(t *testing.T) (string, string) {
				return writeFile(t, t.TempDir(), "plain", []byte("x")), "a.json"
			},
		},
		{
			name: "too large",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				writeFile(t, dir, "big", bytes.Repeat([]byte("x"), limit+1))
				return dir, "big"
			},
			wantErr: ErrTooLarge,
		},
		{
			name: "not regular: directory",
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
			name: "not regular: FIFO",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				makeFIFO(t, filepath.Join(dir, "fifo"))
				return dir, "fifo"
			},
			wantErr: ErrNotRegular,
		},
		{
			name: "outside the root",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, name := tt.setup(t)

			data, info, found, err := ReadBoundedRegularFileInfo(dir, name, limit)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if found != tt.wantFound || string(data) != tt.wantData {
				t.Errorf("found = %v, data = %q, want %v and %q", found, data, tt.wantFound, tt.wantData)
			}
			if tt.wantFound != (info != nil) {
				t.Fatalf("info = %v, want non-nil only when found (found = %v)", info, found)
			}
			if info != nil {
				if !info.Mode().IsRegular() {
					t.Errorf("info.Mode() = %v, want a regular file", info.Mode())
				}
				if got, want := info.Size(), int64(len(tt.wantData)); got != want {
					t.Errorf("info.Size() = %d, want %d", got, want)
				}
			}

			// The old function must give the same data, found flag and error.
			oldData, oldFound, oldErr := ReadBoundedRegularFile(dir, name, limit)
			if !bytes.Equal(oldData, data) || oldFound != found || !errors.Is(oldErr, tt.wantErr) {
				t.Errorf("ReadBoundedRegularFile() = (%q, %v, %v), want (%q, %v, %v)",
					oldData, oldFound, oldErr, data, found, err)
			}
		})
	}
}

// TestReadBoundedRegularFileInfoMode checks that the info holds the mode of the
// file on disk, and of the target when name is a symlink inside the root.
func TestReadBoundedRegularFileInfoMode(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("needs Unix mode bits")
	}

	tests := []struct {
		name     string
		viaLink  bool
		wantMode fs.FileMode
	}{
		{"file", false, 0o600},
		{"symlink to a file in the root", true, 0o600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeFile(t, dir, "real", []byte("abc")) // writeFile uses 0o600
			name := "real"
			if tt.viaLink {
				symlinkTo(t, "real", dir, "link")
				name = "link"
			}

			_, info, found, err := ReadBoundedRegularFileInfo(dir, name, limit)

			if err != nil || !found {
				t.Fatalf("found = %v, error = %v, want found and no error", found, err)
			}
			if got := info.Mode(); got != tt.wantMode {
				t.Errorf("info.Mode() = %v, want %v (the target, not the symlink)", got, tt.wantMode)
			}
			if got := info.Size(); got != 3 {
				t.Errorf("info.Size() = %d, want 3", got)
			}
		})
	}
}

func TestReadOpenedInfo(t *testing.T) {
	t.Parallel()

	statErr := errors.New("stat failed")
	readErr := errors.New("read failed")
	tests := []struct {
		name     string
		file     fakeFile
		maxSize  int64
		wantData string
		wantInfo fakeInfo // checked when wantErr is nil
		wantErr  error    // nil means no error
	}{
		{
			name:     "regular file",
			file:     fakeFile{info: fakeInfo{mode: 0o640, size: 3}, content: strings.NewReader("abc")},
			maxSize:  limit,
			wantData: "abc",
			wantInfo: fakeInfo{mode: 0o640, size: 3},
		},
		{
			name:    "stat error",
			file:    fakeFile{statErr: statErr, content: strings.NewReader("abc")},
			maxSize: limit,
			wantErr: statErr,
		},
		{
			name:    "not regular",
			file:    fakeFile{info: fakeInfo{mode: fs.ModeNamedPipe | 0o600}, content: strings.NewReader("")},
			maxSize: limit,
			wantErr: ErrNotRegular,
		},
		{
			name:    "too large on Stat",
			file:    fakeFile{info: fakeInfo{mode: 0o600, size: limit + 1}, content: strings.NewReader("")},
			maxSize: limit,
			wantErr: ErrTooLarge,
		},
		{
			name:    "grew after Stat",
			file:    fakeFile{info: fakeInfo{mode: 0o600, size: 2}, content: strings.NewReader(strings.Repeat("x", limit+1))},
			maxSize: limit,
			wantErr: ErrTooLarge,
		},
		{
			name:    "read error",
			file:    fakeFile{info: fakeInfo{mode: 0o600, size: 3}, content: &errReader{data: []byte("ab"), err: readErr}},
			maxSize: limit,
			wantErr: readErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, info, err := ReadOpenedInfo(tt.file, tt.maxSize)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				if info != nil || data != nil {
					t.Errorf("data = %q, info = %v, want nil and nil on an error", data, info)
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			if string(data) != tt.wantData {
				t.Errorf("data = %q, want %q", data, tt.wantData)
			}
			if info == nil || info.Mode() != tt.wantInfo.mode || info.Size() != tt.wantInfo.size {
				t.Errorf("info = %v, want mode %v and size %d", info, tt.wantInfo.mode, tt.wantInfo.size)
			}
		})
	}
}

// TestReadOpenedMatchesReadOpenedInfo checks that the old function gives the
// data and the error of the new one for the same input.
func TestReadOpenedMatchesReadOpenedInfo(t *testing.T) {
	t.Parallel()

	newFile := func(info fakeInfo, content string) fakeFile {
		return fakeFile{info: info, content: strings.NewReader(content)}
	}
	tests := []struct {
		name string
		mk   func() fakeFile
	}{
		{"regular", func() fakeFile { return newFile(fakeInfo{mode: 0o600, size: 3}, "abc") }},
		{"not regular", func() fakeFile { return newFile(fakeInfo{mode: fs.ModeDevice}, "") }},
		{"too large", func() fakeFile { return newFile(fakeInfo{mode: 0o600, size: limit + 1}, "") }},
		{"grew", func() fakeFile { return newFile(fakeInfo{mode: 0o600, size: 1}, strings.Repeat("x", limit+1)) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			newData, _, newErr := ReadOpenedInfo(tt.mk(), limit)
			oldData, oldErr := ReadOpened(tt.mk(), limit)
			if !bytes.Equal(oldData, newData) || !errors.Is(oldErr, newErr) || !errors.Is(newErr, oldErr) {
				t.Errorf("ReadOpened() = (%q, %v), want (%q, %v)", oldData, oldErr, newData, newErr)
			}
		})
	}
}

// TestReadOpenedInfoRealFile checks that the info is the Stat of the open file.
func TestReadOpenedInfoRealFile(t *testing.T) {
	t.Parallel()

	path := writeFile(t, t.TempDir(), "a", []byte("hello"))
	f, err := os.Open(path) //nolint:gosec // G304: path is under t.TempDir()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	want, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	data, info, err := ReadOpenedInfo(f, limit)

	if err != nil {
		t.Fatalf("ReadOpenedInfo() error = %v, want nil", err)
	}
	if string(data) != "hello" {
		t.Errorf("data = %q, want %q", data, "hello")
	}
	if !os.SameFile(info, want) || info.Mode() != want.Mode() || info.Size() != 5 {
		t.Errorf("info = %v (size %d), want the Stat of the open file %v", info.Mode(), info.Size(), want.Mode())
	}
}
