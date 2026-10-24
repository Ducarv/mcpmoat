package rules_test

// Import checks for the server fixtures of issue #57. The fixtures under
// testdata/servers must make no network call. The test reads the import list
// of each main.go without compiling it, so a new import fails the test at once.

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// forbiddenImport reports whether the fixture in folder dir must not import
// path.
//
//   - "net" and "net/..." open sockets. "plugin" and "unsafe" load or reach
//     code outside the fixture. No fixture may import them.
//   - "os/exec" starts a program. Only "benign" may import it: its test-only
//     -spawn flag starts a copy of itself for the inspect tests. It starts no
//     other program.
//   - "syscall" is allowed. All four fixtures import it only for
//     syscall.SIGTERM.
func forbiddenImport(dir, path string) bool {
	switch {
	case path == "net", strings.HasPrefix(path, "net/"):
		return true
	case path == "plugin", path == "unsafe":
		return true
	case path == "os/exec":
		return dir != "benign"
	}
	return false
}

// importPaths returns the import paths of a Go source file. If src is nil,
// it reads the file at filename.
func importPaths(filename string, src any) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), filename, src, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// TestFixtureImports checks that no Go file of a server fixture imports a
// package that opens a network connection or starts a program (issue #57:
// fixtures make no network call).
func TestFixtureImports(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("../../testdata/servers/*/*.go")
	if err != nil {
		t.Fatal(err)
	}
	// benign, mailer, poisoned and shadowing.
	folders := map[string]bool{}
	for _, file := range files {
		folders[filepath.Base(filepath.Dir(file))] = true
	}
	if len(folders) < 4 {
		t.Fatalf("found %d fixture folders %v, want at least 4", len(folders), files)
	}
	for _, file := range files {
		dir := filepath.Base(filepath.Dir(file))
		t.Run(dir+"/"+filepath.Base(file), func(t *testing.T) {
			t.Parallel()
			paths, err := importPaths(file, nil)
			if err != nil {
				t.Fatalf("parse %s: %v", file, err)
			}
			for _, p := range paths {
				if forbiddenImport(dir, p) {
					t.Errorf("%s imports %q, which a fixture must not import", file, p)
				}
			}
		})
	}
}

// TestForbiddenImport covers the import decision and shows that a fixture
// source with a forbidden import fails the check.
func TestForbiddenImport(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		dir  string
		path string
		want bool
	}{
		{name: "net", dir: "mailer", path: "net", want: true},
		{name: "net/http", dir: "mailer", path: "net/http", want: true},
		{name: "net/netip", dir: "poisoned", path: "net/netip", want: true},
		{name: "net/http in benign", dir: "benign", path: "net/http", want: true},
		{name: "netx is not net", dir: "mailer", path: "netx", want: false},
		{name: "network folder is not net", dir: "mailer", path: "example.com/net", want: false},
		{name: "os/exec in benign", dir: "benign", path: "os/exec", want: false},
		{name: "os/exec in poisoned", dir: "poisoned", path: "os/exec", want: true},
		{name: "os/exec in shadowing", dir: "shadowing", path: "os/exec", want: true},
		{name: "os in poisoned", dir: "poisoned", path: "os", want: false},
		{name: "syscall", dir: "mailer", path: "syscall", want: false},
		{name: "plugin", dir: "benign", path: "plugin", want: true},
		{name: "unsafe", dir: "benign", path: "unsafe", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := forbiddenImport(tt.dir, tt.path); got != tt.want {
				t.Errorf("forbiddenImport(%q, %q) = %v, want %v", tt.dir, tt.path, got, tt.want)
			}
		})
	}

	// A fixture source with a blank import of "net" must be caught.
	t.Run("blank import of net in source", func(t *testing.T) {
		t.Parallel()
		src := "package main\n\nimport (\n\t\"os\"\n\t_ \"net\"\n)\n"
		paths, err := importPaths("main.go", src)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"os", "net"}; !slices.Equal(paths, want) {
			t.Fatalf("importPaths() = %v, want %v", paths, want)
		}
		if !slices.ContainsFunc(paths, func(p string) bool { return forbiddenImport("mailer", p) }) {
			t.Error("no import of the source is forbidden, want net to be forbidden")
		}
	})
}
