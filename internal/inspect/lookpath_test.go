package inspect

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestLookPath checks how lookPath searches a PATH-style list. Each case
// builds its own directory tree under t.TempDir(). The cases cover the
// search order, the skip rules for empty and relative entries, the file
// checks (directory, no execute bit, symlinks) and the input guards.
//
// Expected paths are built with string concatenation, like the code under
// test. t.TempDir() returns a clean absolute path, so the text is exact.
func TestLookPath(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	sep := string(filepath.ListSeparator)

	tests := []struct {
		name string
		file string
		// setup builds the tree under root and returns the pathList and the
		// expected path. An empty want means errCommandNotFound.
		setup func(t *testing.T, root string) (pathList, want string)
	}{
		{
			name: "found in first entry",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				a, b := root+"/a", root+"/b"
				mustMkdir(t, a)
				mustMkdir(t, b)
				mustWriteFile(t, a+"/tool", 0o755)
				return a + sep + b, a + "/tool"
			},
		},
		{
			name: "found in later entry",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				a, b, c := root+"/a", root+"/b", root+"/c"
				mustMkdir(t, a)
				mustMkdir(t, b)
				mustMkdir(t, c)
				mustWriteFile(t, a+"/other", 0o755)
				mustWriteFile(t, c+"/tool", 0o755)
				return a + sep + b + sep + c, c + "/tool"
			},
		},
		{
			name: "first match wins",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				a, b := root+"/a", root+"/b"
				mustMkdir(t, a)
				mustMkdir(t, b)
				mustWriteFile(t, a+"/tool", 0o755)
				mustWriteFile(t, b+"/tool", 0o755)
				return a + sep + b, a + "/tool"
			},
		},
		{
			name: "missing directory entry is skipped",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				b := root + "/b"
				mustMkdir(t, b)
				mustWriteFile(t, b+"/tool", 0o755)
				return root + "/missing" + sep + b, b + "/tool"
			},
		},
		{
			name: "empty entries are skipped",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				a := root + "/a"
				mustMkdir(t, a)
				mustWriteFile(t, a+"/tool", 0o755)
				return sep + sep + a, a + "/tool"
			},
		},
		{
			name: "only dot entry gives not found",
			file: "tool",
			setup: func(_ *testing.T, _ string) (string, string) {
				return ".", ""
			},
		},
		{
			name: "only relative entry gives not found",
			file: "tool",
			setup: func(_ *testing.T, _ string) (string, string) {
				return "relative/bin", ""
			},
		},
		{
			name: "only empty entries give not found",
			file: "tool",
			setup: func(_ *testing.T, _ string) (string, string) {
				return sep + sep, ""
			},
		},
		{
			name: "dot and relative entries before absolute entry are skipped",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				a := root + "/a"
				mustMkdir(t, a)
				mustWriteFile(t, a+"/tool", 0o755)
				return "." + sep + "bin" + sep + a, a + "/tool"
			},
		},
		{
			name: "relative entry to real executable is skipped",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				// The relative entry points from the work directory to a
				// real executable. This proves the skip without a chdir,
				// which is not allowed in parallel tests.
				a := root + "/a"
				mustMkdir(t, a)
				mustWriteFile(t, a+"/tool", 0o755)
				cwd, err := os.Getwd()
				if err != nil {
					t.Fatalf("os.Getwd() error = %v", err)
				}
				// os.Getwd can return the logical $PWD (through a
				// symlink), but the kernel resolves ".." along the
				// physical path. Resolve both sides first, so the
				// relative path is correct for the kernel.
				physCwd, err := filepath.EvalSymlinks(cwd)
				if err != nil {
					t.Fatalf("filepath.EvalSymlinks(%q) error = %v", cwd, err)
				}
				physA, err := filepath.EvalSymlinks(a)
				if err != nil {
					t.Fatalf("filepath.EvalSymlinks(%q) error = %v", a, err)
				}
				rel, err := filepath.Rel(physCwd, physA)
				if err != nil {
					t.Fatalf("filepath.Rel(%q, %q) error = %v", physCwd, physA, err)
				}
				if !isExecutableFile(rel + "/tool") {
					t.Fatalf("setup: %q is not executable from the work directory", rel+"/tool")
				}
				return rel, ""
			},
		},
		{
			name: "dot-dot in entry is kept as written",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				// filepath.Join would clean "a/../b" to "b". lookPath keeps
				// the directory text exactly as configured.
				a, b := root+"/a", root+"/b"
				mustMkdir(t, a)
				mustMkdir(t, b)
				mustWriteFile(t, b+"/tool", 0o755)
				dir := a + "/../b"
				return dir, dir + "/tool"
			},
		},
		{
			name: "directory with target name is skipped",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				a, b := root+"/a", root+"/b"
				mustMkdir(t, a+"/tool")
				mustMkdir(t, b)
				mustWriteFile(t, b+"/tool", 0o755)
				return a + sep + b, b + "/tool"
			},
		},
		{
			name: "directory with target name only gives not found",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				a := root + "/a"
				mustMkdir(t, a+"/tool")
				return a, ""
			},
		},
		{
			name: "file without execute bit is skipped",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				a, b := root+"/a", root+"/b"
				mustMkdir(t, a)
				mustMkdir(t, b)
				mustWriteFile(t, a+"/tool", 0o644)
				mustWriteFile(t, b+"/tool", 0o755)
				return a + sep + b, b + "/tool"
			},
		},
		{
			name: "file without execute bit only gives not found",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				a := root + "/a"
				mustMkdir(t, a)
				mustWriteFile(t, a+"/tool", 0o644)
				return a, ""
			},
		},
		{
			name: "any single execute bit is enough",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				a := root + "/a"
				mustMkdir(t, a)
				mustWriteFile(t, a+"/tool", 0o601)
				return a, a + "/tool"
			},
		},
		{
			name: "symlink to executable is accepted as built",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				realDir, a := root+"/real", root+"/a"
				mustMkdir(t, realDir)
				mustMkdir(t, a)
				mustWriteFile(t, realDir+"/target", 0o755)
				mustSymlink(t, realDir+"/target", a+"/tool")
				return a, a + "/tool"
			},
		},
		{
			name: "dangling symlink is skipped",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				a, b := root+"/a", root+"/b"
				mustMkdir(t, a)
				mustMkdir(t, b)
				mustSymlink(t, root+"/nowhere", a+"/tool")
				mustWriteFile(t, b+"/tool", 0o755)
				return a + sep + b, b + "/tool"
			},
		},
		{
			name: "dangling symlink only gives not found",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				a := root + "/a"
				mustMkdir(t, a)
				mustSymlink(t, root+"/nowhere", a+"/tool")
				return a, ""
			},
		},
		{
			name: "trailing slash gives single slash",
			file: "tool",
			setup: func(t *testing.T, root string) (string, string) {
				a := root + "/a"
				mustMkdir(t, a)
				mustWriteFile(t, a+"/tool", 0o755)
				return a + "/", a + "/tool"
			},
		},
		{
			name: "empty pathList gives not found",
			file: "tool",
			setup: func(_ *testing.T, _ string) (string, string) {
				return "", ""
			},
		},
		{
			name: "empty file gives not found",
			file: "",
			setup: func(t *testing.T, root string) (string, string) {
				a := root + "/a"
				mustMkdir(t, a)
				return a, ""
			},
		},
		{
			name: "file with slash gives not found",
			file: "a/b",
			setup: func(t *testing.T, root string) (string, string) {
				// An executable exists at root+"/a/b". lookPath must not
				// find it, because file is not a bare name.
				a := root + "/a"
				mustMkdir(t, a)
				mustWriteFile(t, a+"/b", 0o755)
				return root, ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pathList, want := tt.setup(t, t.TempDir())
			got, err := lookPath(tt.file, pathList)

			if want == "" {
				if !errors.Is(err, errCommandNotFound) {
					t.Fatalf("lookPath(%q, %q) error = %v, want errCommandNotFound", tt.file, pathList, err)
				}
				if got != "" {
					t.Errorf("lookPath(%q, %q) = %q, want empty path", tt.file, pathList, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("lookPath(%q, %q) error = %v, want nil", tt.file, pathList, err)
			}
			if got != want {
				t.Errorf("lookPath(%q, %q) = %q, want %q", tt.file, pathList, got, want)
			}
		})
	}
}
