package discovertest_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// writeTree creates the files of a fixture below root. The keys of files are
// slash-separated paths relative to root, for example "home/.cursor/mcp.json".
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("create directory for %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

// listFiles returns every non-directory entry below root as a map from the
// slash-separated relative path to the file content. A missing or empty
// directory gives an empty map.
func listFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	got := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: path comes from walking a test temp dir
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		got[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return got
}

// assertDir fails the test unless path is an existing directory.
func assertDir(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", path)
	}
}

// splitByRoot splits a fixture file map into the files of home/ and work/.
func splitByRoot(files map[string]string) (home, work map[string]string) {
	home = map[string]string{}
	work = map[string]string{}
	for rel, content := range files {
		switch {
		case strings.HasPrefix(rel, "home/"):
			home[strings.TrimPrefix(rel, "home/")] = content
		case strings.HasPrefix(rel, "work/"):
			work[strings.TrimPrefix(rel, "work/")] = content
		}
	}
	return home, work
}

func TestCopyFixture(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		files map[string]string
	}{
		{
			name: "home and work",
			files: map[string]string{
				"home/.cursor/mcp.json": `{"mcpServers":{"a":{"command":"x"}}}`,
				"work/.mcp.json":        `{"mcpServers":{"b":{"url":"https://example.com"}}}`,
			},
		},
		{
			name: "dotfiles and nested directories",
			files: map[string]string{
				"home/.claude.json":                `{"mcpServers":{}}`,
				"home/.codex/config.toml":          "[mcp_servers.a]\ncommand = \"x\"\n",
				"home/deep/er/and/deeper/file.txt": "deep",
				"work/.cursor/mcp.json":            `{"mcpServers":{}}`,
				"work/.mcp.json":                   "",
				"work/sub/dir/.hidden":             "hidden",
			},
		},
		{
			name: "only home",
			files: map[string]string{
				"home/.claude.json": `{"mcpServers":{}}`,
			},
		},
		{
			name: "only work",
			files: map[string]string{
				"work/.mcp.json": `{"mcpServers":{}}`,
			},
		},
		{
			name:  "neither home nor work",
			files: map[string]string{},
		},
		{
			name: "files outside home and work are not copied",
			files: map[string]string{
				"home/.claude.json": "{}",
				"other/file.json":   "not copied",
				"README.md":         "not copied",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := t.TempDir()
			writeTree(t, fixture, tt.files)

			home, work := discovertest.CopyFixture(t, fixture)

			// Both directories exist, even when the fixture lacks them.
			assertDir(t, home)
			assertDir(t, work)

			wantHome, wantWork := splitByRoot(tt.files)
			if got := listFiles(t, home); !reflect.DeepEqual(got, wantHome) {
				t.Errorf("home files = %v, want %v", got, wantHome)
			}
			if got := listFiles(t, work); !reflect.DeepEqual(got, wantWork) {
				t.Errorf("work files = %v, want %v", got, wantWork)
			}
		})
	}
}

func TestCopyFixtureMissingSideIsEmptyDir(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		files     map[string]string
		emptyDirs []string // "home" or "work": must exist and have no entries
	}{
		{
			name:      "only home gives an empty work",
			files:     map[string]string{"home/.claude.json": "{}"},
			emptyDirs: []string{"work"},
		},
		{
			name:      "only work gives an empty home",
			files:     map[string]string{"work/.mcp.json": "{}"},
			emptyDirs: []string{"home"},
		},
		{
			name:      "neither gives two empty directories",
			files:     map[string]string{},
			emptyDirs: []string{"home", "work"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := t.TempDir()
			writeTree(t, fixture, tt.files)

			home, work := discovertest.CopyFixture(t, fixture)

			dirs := map[string]string{"home": home, "work": work}
			for _, side := range tt.emptyDirs {
				entries, err := os.ReadDir(dirs[side])
				if err != nil {
					t.Fatalf("read %s directory: %v", side, err)
				}
				if len(entries) != 0 {
					t.Errorf("%s directory has %d entries, want 0", side, len(entries))
				}
			}
		})
	}
}

func TestCopyFixturePaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		files map[string]string
	}{
		{name: "both sides", files: map[string]string{"home/a.json": "{}", "work/b.json": "{}"}},
		{name: "only home", files: map[string]string{"home/a.json": "{}"}},
		{name: "neither", files: map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := t.TempDir()
			writeTree(t, fixture, tt.files)

			home, work := discovertest.CopyFixture(t, fixture)

			if home == work {
				t.Errorf("home and work are the same path %q", home)
			}
			for label, p := range map[string]string{"home": home, "work": work} {
				if !filepath.IsAbs(p) {
					t.Errorf("%s = %q, want an absolute path", label, p)
				}
				rel, err := filepath.Rel(fixture, p)
				if err != nil {
					// No relative path exists, so p cannot be inside fixture.
					continue
				}
				if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
					t.Errorf("%s = %q is inside the fixture directory %q", label, p, fixture)
				}
			}
			// The copy must not be the fixture's own home/work either.
			if home == filepath.Join(fixture, "home") {
				t.Errorf("home is the fixture's own home directory")
			}
			if work == filepath.Join(fixture, "work") {
				t.Errorf("work is the fixture's own work directory")
			}
		})
	}
}

func TestCopyFixtureTwiceGivesSeparateCopies(t *testing.T) {
	t.Parallel()
	fixture := t.TempDir()
	writeTree(t, fixture, map[string]string{"home/a.json": "{}"})

	home1, work1 := discovertest.CopyFixture(t, fixture)
	home2, work2 := discovertest.CopyFixture(t, fixture)

	if home1 == home2 || work1 == work2 {
		t.Errorf("two calls returned the same paths: %q %q / %q %q", home1, home2, work1, work2)
	}
}

func TestCopyFixtureWriteDoesNotChangeOriginal(t *testing.T) {
	t.Parallel()
	const original = `{"mcpServers":{"a":{"command":"x"}}}`
	tests := []struct {
		name string
		rel  string // slash-separated path inside the fixture
	}{
		{name: "home file", rel: "home/.cursor/mcp.json"},
		{name: "work file", rel: "work/.mcp.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := t.TempDir()
			writeTree(t, fixture, map[string]string{
				"home/.cursor/mcp.json": original,
				"work/.mcp.json":        original,
			})

			home, work := discovertest.CopyFixture(t, fixture)

			root := home
			rel := strings.TrimPrefix(tt.rel, "home/")
			if strings.HasPrefix(tt.rel, "work/") {
				root = work
				rel = strings.TrimPrefix(tt.rel, "work/")
			}
			copyPath := filepath.Join(root, filepath.FromSlash(rel))
			if err := os.WriteFile(copyPath, []byte("changed"), 0o600); err != nil {
				t.Fatalf("write copy: %v", err)
			}
			extra := filepath.Join(root, "new-file.json")
			if err := os.WriteFile(extra, []byte("new"), 0o600); err != nil {
				t.Fatalf("write new file in copy: %v", err)
			}

			data, err := os.ReadFile(filepath.Join(fixture, filepath.FromSlash(tt.rel))) //nolint:gosec // G304: path is inside a test temp dir
			if err != nil {
				t.Fatalf("read original: %v", err)
			}
			if string(data) != original {
				t.Errorf("original = %q, want %q", data, original)
			}
			if _, err := os.Stat(filepath.Join(fixture, filepath.Dir(filepath.FromSlash(tt.rel)), "new-file.json")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("new file in the copy appeared in the fixture (stat error = %v)", err)
			}
		})
	}
}

func TestCopyFixtureRecreatesRelativeSymlink(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need extra privileges on Windows")
	}
	const content = `{"mcpServers":{}}`
	fixture := t.TempDir()
	writeTree(t, fixture, map[string]string{"home/real/mcp.json": content})
	// The link target is relative, so the link stays valid in the copy.
	if err := os.Symlink(filepath.Join("real", "mcp.json"), filepath.Join(fixture, "home", "link.json")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	home, _ := discovertest.CopyFixture(t, fixture)

	link := filepath.Join(home, "link.json")
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat %s: %v", link, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("mode of %s = %v, want a symbolic link", link, info.Mode())
	}
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if want := filepath.Join("real", "mcp.json"); target != want {
		t.Errorf("link target = %q, want %q", target, want)
	}
	// The link must resolve inside the copy, not back to the fixture.
	data, err := os.ReadFile(link) //nolint:gosec // G304: path is inside a test temp dir
	if err != nil {
		t.Fatalf("read through link: %v", err)
	}
	if string(data) != content {
		t.Errorf("content through link = %q, want %q", data, content)
	}
}
