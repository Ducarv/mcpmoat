package safefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These tests check only what the info versions add. The data, found and error
// results are covered by the tests of ReadBoundedRegularFile and ReadOpened,
// which wrap the info versions.

func TestReadBoundedRegularFileInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup returns the directory to read and the file name in it.
		setup     func(t *testing.T) (dir, name string)
		wantFound bool
		wantErr   error // nil means no error
	}{
		{
			name: "regular file",
			setup: func(t *testing.T) (string, string) {
				return fileWithMode(t, t.TempDir(), "real")
			},
			wantFound: true,
		},
		{
			// The info is the one of the target, not of the link.
			name: "symlink to a file inside the root",
			setup: func(t *testing.T) (string, string) {
				dir, _ := fileWithMode(t, t.TempDir(), "real")
				symlinkTo(t, "real", dir, "link")
				return dir, "link"
			},
			wantFound: true,
		},
		{
			name: "missing file",
			setup: func(t *testing.T) (string, string) {
				return t.TempDir(), "nope"
			},
		},
		{
			name: "too large",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				writeFile(t, dir, "big", []byte(strings.Repeat("x", limit+1)))
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
			name: "outside the root",
			setup: func(t *testing.T) (string, string) {
				parent := t.TempDir()
				dir := filepath.Join(parent, "project")
				writeFile(t, parent, "secret.json", []byte("x"))
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

			_, info, found, err := ReadBoundedRegularFileInfo(dir, name, limit)

			if !errors.Is(err, tt.wantErr) || found != tt.wantFound {
				t.Fatalf("found = %v, error = %v, want %v and %v", found, err, tt.wantFound, tt.wantErr)
			}
			if !tt.wantFound {
				if info != nil {
					t.Errorf("info = %v, want nil", info)
				}
				return
			}
			if !info.Mode().IsRegular() || info.Size() != 3 {
				t.Errorf("info = (%v, %d), want a regular file of 3 bytes", info.Mode(), info.Size())
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0o400 {
				t.Errorf("info.Mode().Perm() = %v, want 0400", info.Mode().Perm())
			}
		})
	}
}

// fileWithMode writes a 3-byte file with mode 0400 and returns dir and name.
func fileWithMode(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	path := writeFile(t, dir, name, []byte("abc"))
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return dir, name
}

func TestReadOpenedInfo(t *testing.T) {
	t.Parallel()

	t.Run("info is the Stat of the open file", func(t *testing.T) {
		t.Parallel()
		want := fakeInfo{mode: 0o640, size: 3}
		f := fakeFile{info: want, content: strings.NewReader("abc")}

		data, info, err := readOpenedInfo(f, limit)

		if err != nil || string(data) != "abc" {
			t.Fatalf("data = %q, error = %v, want %q and nil", data, err, "abc")
		}
		if info != fs.FileInfo(want) {
			t.Errorf("info = %v, want the Stat result %v", info, want)
		}
	})

	errStat := errors.New("stat failed")
	tests := []struct {
		name    string
		file    fakeFile
		wantErr error
	}{
		{"stat error", fakeFile{statErr: errStat}, errStat},
		{"too large", fakeFile{info: fakeInfo{mode: 0o600, size: limit + 1}, content: strings.NewReader("")}, ErrTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, info, err := readOpenedInfo(tt.file, limit)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if info != nil || data != nil {
				t.Errorf("data = %q, info = %v, want nil and nil on an error", data, info)
			}
		})
	}
}
