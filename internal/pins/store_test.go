package pins_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/safefile"
)

// leakToken is a distinctive text that tests put in file content. No error
// from Load may contain it, because file content comes from an untrusted
// source and must not reach the terminal through an error.
const leakToken = "LEAKTOKEN"

var (
	idA = pins.Identity{Client: "claude-code", Source: "/home/u/.claude.json", Name: "alpha"}
	idB = pins.Identity{Client: "claude-code", Source: "/home/u/.claude.json", ProjectPath: "/work/p", Name: "beta"}
	idC = pins.Identity{Client: "cursor", Source: "/home/u/.cursor/mcp.json", Name: "gamma"}
)

// storeTestPin returns the pin of a hash. The canonical text derives from the
// hash, so two different hashes always give two different pins.
func storeTestPin(hash string) pins.Pin {
	return pins.Pin{Hash: hash, Canonical: "c-" + hash}
}

// storeTestPinJSON returns the pins.json text of storeTestPin(hash).
func storeTestPinJSON(hash string) string {
	return `{"hash":"` + hash + `","canonical":"c-` + hash + `"}`
}

// storeTestPins returns a fresh pins map from name, hash pairs. Each call
// gives a new map, so tests do not share state. The canonical text of each
// tool is "c-" plus its hash.
func storeTestPins(pairs ...string) pins.ServerPins {
	if len(pairs)%2 != 0 {
		panic("storeTestPins needs name, hash pairs")
	}
	p := pins.ServerPins{}
	for kv := range slices.Chunk(pairs, 2) {
		p[kv[0]] = storeTestPin(kv[1])
	}
	return p
}

// storeTestPath returns a pins.json path in a new temp directory.
func storeTestPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "pins.json")
}

// storeTestWrite writes content to a new pins.json and returns its path.
func storeTestWrite(t *testing.T, content string) string {
	t.Helper()
	p := storeTestPath(t)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// storeTestMustLoad loads path and fails the test on an error.
func storeTestMustLoad(t *testing.T, path string) *pins.Store {
	t.Helper()
	s, err := pins.Load(path)
	if err != nil {
		t.Fatalf("Load(%q) error = %v, want nil", path, err)
	}
	return s
}

// storeTestMustSet sets the pins of id and fails the test on an error.
func storeTestMustSet(t *testing.T, s *pins.Store, id pins.Identity, p pins.ServerPins) {
	t.Helper()
	if err := s.Set(id, p); err != nil {
		t.Fatalf("Set(%+v) error = %v, want nil", id, err)
	}
}

// storeTestMustSave saves s and fails the test on an error.
func storeTestMustSave(t *testing.T, s *pins.Store) {
	t.Helper()
	if err := s.Save(); err != nil {
		t.Fatalf("Save() error = %v, want nil", err)
	}
}

// storeTestWantPins checks that s holds exactly want for id.
func storeTestWantPins(t *testing.T, s *pins.Store, id pins.Identity, want pins.ServerPins) {
	t.Helper()
	got, ok := s.Get(id)
	if !ok {
		t.Errorf("Get(%+v) ok = false, want true", id)
		return
	}
	if !maps.Equal(got, want) {
		t.Errorf("Get(%+v) = %v, want %v", id, got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	s := storeTestMustLoad(t, path)
	storeTestMustSet(t, s, idA, storeTestPins("read", "h1", "write", "h2"))
	storeTestMustSet(t, s, idB, storeTestPins("search", "h3"))
	storeTestMustSet(t, s, idC, storeTestPins())
	storeTestMustSave(t, s)

	got := storeTestMustLoad(t, path)
	storeTestWantPins(t, got, idA, storeTestPins("read", "h1", "write", "h2"))
	storeTestWantPins(t, got, idB, storeTestPins("search", "h3"))
	storeTestWantPins(t, got, idC, storeTestPins())

	if _, ok := got.Get(pins.Identity{Client: "other", Name: "alpha"}); ok {
		t.Error("Get(unknown identity) ok = true, want false")
	}
}

func TestSaveFormat(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	s := storeTestMustLoad(t, path)
	// "<b>&" also shows that <, > and & are not escaped as \u003c and so on.
	storeTestMustSet(t, s, pins.Identity{Client: "c", Source: "s", Name: "n"}, storeTestPins("<b>&", "2", "a", "1"))
	storeTestMustSave(t, s)

	want := `{
  "version": 1,
  "servers": [
    {
      "client": "c",
      "source": "s",
      "project_path": "",
      "name": "n",
      "tools": {
        "<b>&": {
          "hash": "2",
          "canonical": "c-2"
        },
        "a": {
          "hash": "1",
          "canonical": "c-1"
        }
      }
    }
  ]
}
`
	if got := string(pins.ReadFile(t, path)); got != want {
		t.Errorf("file =\n%s\nwant\n%s", got, want)
	}
}

func TestFirstRun(t *testing.T) {
	t.Parallel()
	// The directory does not exist yet: Save must create it.
	path := filepath.Join(t.TempDir(), "new", "mcpmoat", "pins.json")

	s := storeTestMustLoad(t, path)
	if _, ok := s.Get(idA); ok {
		t.Error("Get() on an empty store ok = true, want false")
	}
	storeTestMustSave(t, s)

	pins.WantPerm(t, path, 0o600)
	pins.WantPerm(t, filepath.Dir(path), 0o700)

	// An empty store is a valid file.
	storeTestMustLoad(t, path)
}

func TestLoadMissing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path func(t *testing.T) string
	}{
		{"missing file", storeTestPath},
		{"missing directory", func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "no", "such", "pins.json")
		}},
		{"directory symlink with no pins file", func(t *testing.T) string {
			root := t.TempDir()
			link := filepath.Join(root, "link")
			if err := os.Symlink(t.TempDir(), link); err != nil {
				t.Skipf("symlinks not available: %v", err)
			}
			return filepath.Join(link, "pins.json")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := storeTestMustLoad(t, tt.path(t))
			if _, ok := s.Get(idA); ok {
				t.Error("Get() ok = true, want false")
			}
		})
	}
}

// TestLoadNotFirstRun checks the paths that safefile reports as not found
// but that are not a first run: the real file is gone, so Load must not
// return an empty store.
func TestLoadNotFirstRun(t *testing.T) {
	t.Parallel()
	symlink := func(t *testing.T, target, link string) {
		t.Helper()
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks not available: %v", err)
		}
	}
	// The pins directory and its parent, as the part of the path that the
	// error names.
	pinsDir := filepath.Dir
	parentDir := func(path string) string { return filepath.Dir(filepath.Dir(path)) }
	const notDir = "is not a directory, or it is a symlink with a missing target"
	tests := []struct {
		name string
		path func(t *testing.T) string
		// named, when set, is the part of the path that is not a directory. The
		// error must then be exactly "read <path>: <named> " + notDir.
		named func(path string) string
		want  string // used when named is nil
	}{
		{name: "pins.json symlink with a missing target", path: func(t *testing.T) string {
			path := storeTestPath(t)
			symlink(t, "gone.json", path)
			return path
		}, want: "the target of the symlink is missing"},
		{name: "directory symlink with a missing target", path: func(t *testing.T) string {
			link := filepath.Join(t.TempDir(), "mcpmoat")
			symlink(t, filepath.Join(t.TempDir(), "gone"), link)
			return filepath.Join(link, "pins.json")
		}, named: pinsDir},
		{name: "directory is a file", path: func(t *testing.T) string {
			dir := filepath.Join(t.TempDir(), "mcpmoat")
			if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "pins.json")
		}, named: pinsDir},
		{name: "a parent of the directory is a symlink with a missing target", path: func(t *testing.T) string {
			link := filepath.Join(t.TempDir(), "config")
			symlink(t, filepath.Join(t.TempDir(), "gone"), link)
			return filepath.Join(link, "mcpmoat", "pins.json")
		}, named: parentDir},
		// The same text as "directory is a file" (#157): ENOTDIR below the file
		// keeps the walk going up to the file.
		{name: "a parent of the directory is a file", path: func(t *testing.T) string {
			file := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(file, "mcpmoat", "pins.json")
		}, named: parentDir},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := tt.path(t)
			s, err := pins.Load(path)
			if err == nil {
				t.Fatal("Load() error = nil, want error")
			}
			if tt.named != nil {
				want := "read " + path + ": " + tt.named(path) + " " + notDir
				if err.Error() != want {
					t.Errorf("Load() error = %q, want %q", err, want)
				}
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load() error = %v, want text %q", err, tt.want)
			}
			if s != nil {
				t.Errorf("Load() store = %v, want nil", s)
			}
		})
	}
}

// TestCheckFirstRunWith fakes lstat and stat for file system states that are
// hard to make on disk.
func TestCheckFirstRunWith(t *testing.T) {
	t.Parallel()
	missing := func(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist }
	denied := func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	path := filepath.Join(string(filepath.Separator)+"a", "b", "pins.json")
	tests := []struct {
		name        string
		path        string
		lstat, stat func(string) (fs.FileInfo, error)
		wantText    string   // text the error must hold
		wantIs      error    // optional
		wantNotText []string // texts the error must not hold
	}{
		{
			name: "nothing on the path exists", path: path, lstat: missing, stat: missing,
			wantText: "read " + path + ": no directory on the path exists",
		},
		{
			name: "ENOTDIR all the way up", path: path,
			lstat: func(string) (fs.FileInfo, error) { return nil, syscall.ENOTDIR }, stat: missing,
			wantText: "no directory on the path exists",
		},
		{
			name: "lstat error that is not missing", path: path, lstat: denied, stat: missing,
			wantText: "read " + path + ": ", wantIs: fs.ErrPermission, wantNotText: []string{"no directory"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := pins.CheckFirstRunWith(tt.path, tt.lstat, tt.stat)
			if err == nil || !strings.Contains(err.Error(), tt.wantText) {
				t.Fatalf("CheckFirstRunWith() error = %v, want text %q", err, tt.wantText)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("CheckFirstRunWith() error = %v, want errors.Is %v", err, tt.wantIs)
			}
			for _, bad := range tt.wantNotText {
				if strings.Contains(err.Error(), bad) {
					t.Errorf("CheckFirstRunWith() error = %q, must not hold %q", err, bad)
				}
			}
		})
	}

	t.Run("real first run", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "no", "such", "pins.json")
		if err := pins.CheckFirstRunWith(path, os.Lstat, os.Stat); err != nil {
			t.Errorf("CheckFirstRunWith() error = %v, want nil", err)
		}
	})
}

func TestDefaultPath(t *testing.T) {
	t.Parallel()
	xdg := t.TempDir()
	home := t.TempDir()
	homeAt := func(dir string) func() (string, error) {
		return func() (string, error) { return dir, nil }
	}
	noHome := func() (string, error) { return "", errors.New("no home") }
	inXDG := filepath.Join(xdg, "mcpmoat", "pins.json")
	inHome := filepath.Join(home, ".config", "mcpmoat", "pins.json")

	tests := []struct {
		name    string
		xdg     string
		homeDir func() (string, error)
		want    string
		wantErr string
	}{
		{name: "absolute XDG", xdg: xdg, homeDir: homeAt(home), want: inXDG},
		// The home directory is not needed, so its error does not matter.
		{name: "absolute XDG does not read home", xdg: xdg, homeDir: noHome, want: inXDG},
		{name: "relative XDG is ignored", xdg: filepath.Join("rel", "dir"), homeDir: homeAt(home), want: inHome},
		{name: "empty XDG", xdg: "", homeDir: homeAt(home), want: inHome},
		{
			name: "relative home", xdg: "", homeDir: homeAt(filepath.Join("relative", "dir")),
			wantErr: fmt.Sprintf("the home directory %q for pins.json is not an absolute path", filepath.Join("relative", "dir")),
		},
		{name: "home error", xdg: "", homeDir: noHome, wantErr: "find the home directory for pins.json: no home"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			getenv := func(key string) string {
				if key == "XDG_CONFIG_HOME" {
					return tt.xdg
				}
				return ""
			}
			got, err := pins.DefaultPath(getenv, tt.homeDir)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("DefaultPath() = %q, error = %v, want error %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DefaultPath() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("DefaultPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDefaultPathEndToEnd(t *testing.T) {
	// No t.Parallel: t.Setenv panics in a parallel test.
	xdg := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", xdg)

	// The production arguments: this test checks that the real environment
	// reaches the path.
	path, err := pins.DefaultPath(os.Getenv, os.UserHomeDir)
	if err != nil {
		t.Fatal(err)
	}
	s := storeTestMustLoad(t, path)
	storeTestMustSet(t, s, idA, storeTestPins("read", "h1"))
	storeTestMustSave(t, s)

	want := filepath.Join(xdg, "mcpmoat", "pins.json")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("pins file not created at %s: %v", want, err)
	}
	storeTestWantPins(t, storeTestMustLoad(t, want), idA, storeTestPins("read", "h1"))
}

func TestLoadValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content string
		want    pins.ServerPins // nil means idA must be absent
	}{
		{"empty servers", `{"version":1,"servers":[]}`, nil},
		{"trailing whitespace", "{\"version\":1,\"servers\":[]}\n\n  ", nil},
		{
			"no tools",
			`{"version":1,"servers":[{"client":"claude-code","source":"/home/u/.claude.json","project_path":"","name":"alpha","tools":{}}]}`,
			storeTestPins(),
		},
		{
			"one server",
			`{"version":1,"servers":[{"client":"claude-code","source":"/home/u/.claude.json","project_path":"","name":"alpha","tools":{"t":` + storeTestPinJSON("h") + `}}]}`,
			storeTestPins("t", "h"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := storeTestMustLoad(t, storeTestWrite(t, tt.content))
			got, ok := s.Get(idA)
			if tt.want == nil {
				if ok {
					t.Error("Get() ok = true, want false")
				}
				return
			}
			if !ok || got == nil || !maps.Equal(got, tt.want) {
				t.Errorf("Get() = %v, %v; want a non-nil %v", got, ok, tt.want)
			}
		})
	}
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()
	server := `{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":` + storeTestPinJSON("h") + `}}`
	tests := []struct {
		name     string
		content  string
		wantIs   error  // optional sentinel
		wantText string // optional text in the error
	}{
		{"future version", `{"version":2,"servers":[]}`, pins.ErrUnsupportedVersion, "upgrade"},
		{"future version with other shape", `{"version":2,"x":1,"` + leakToken + `":[1]}`, pins.ErrUnsupportedVersion, "upgrade"},
		// Invalid JSON wins over a future version: the probe decode fails first.
		{"future version with invalid JSON", `{"version":99,"servers":` + leakToken + `}`, nil, "invalid JSON"},
		{"version zero", `{"version":0,"servers":[]}`, nil, "invalid version"},
		{"version negative", `{"version":-1,"servers":[]}`, nil, "invalid version"},
		{"version missing", `{"servers":[]}`, nil, "version"},
		{"version null", `{"version":null,"servers":[]}`, nil, "version"},
		{"version string", `{"version":"` + leakToken + `","servers":[]}`, nil, ""},
		{"version fraction", `{"version":1.5,"servers":[]}`, nil, ""},
		{"version bool", `{"version":true}`, nil, ""},
		{"top level array", `[1,"` + leakToken + `"]`, nil, ""},
		{"top level null", `null`, nil, "version"},
		{"empty file", ``, nil, ""},
		{"corrupt JSON", `{not json ` + leakToken, nil, ""},
		{"truncated JSON", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":{"hash":"` + leakToken, nil, ""},
		{"truncated mid key", `{"version":1,"serv`, nil, ""},
		{"unknown top-level field", `{"version":1,"servers":[],"` + leakToken + `":true}`, nil, ""},
		{"unknown server field", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{},"` + leakToken + `":"x"}]}`, nil, ""},
		{"trailing data", `{"version":1,"servers":[]} ` + leakToken, nil, ""},
		{"second document", `{"version":1,"servers":[]}{"version":1,"servers":[]}`, nil, ""},
		{"servers wrong type", `{"version":1,"servers":{"` + leakToken + `":1}}`, nil, ""},
		{"tools wrong type", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"` + leakToken + `":5}}]}`, nil, ""},
		{"tool is a string (old shape)", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":"` + leakToken + `"}}]}`, nil, "invalid value at byte"},
		{"tool is an array", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":["` + leakToken + `"]}}]}`, nil, "invalid value at byte"},
		{"tool has an unknown field", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":{"hash":"h","canonical":"c","` + leakToken + `":"x"}}}]}`, nil, "unknown field at byte"},
		{"tool hash is a number", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":{"hash":` + `5,"canonical":"` + leakToken + `"}}}]}`, nil, "invalid value at byte"},
		{"tool canonical is an object", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":{"hash":"h","canonical":{"` + leakToken + `":1}}}}]}`, nil, "invalid value at byte"},
		{"duplicate hash key", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":{"hash":"h","hash":"` + leakToken + `","canonical":"c"}}}]}`, nil, "duplicate key"},
		{"duplicate identity", `{"version":1,"servers":[` + server + `,` + server + `]}`, nil, "duplicate"},
		{
			"duplicate identity with token name",
			`{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"` + leakToken + `","tools":{}},{"client":"c","source":"s","project_path":"","name":"` + leakToken + `","tools":{}}]}`,
			nil, "duplicate",
		},
		{"duplicate top-level key", `{"version":1,"servers":[],"servers":[]}`, nil, "duplicate key"},
		{"duplicate server key", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"` + leakToken + `","tools":{},"name":"m"}]}`, nil, "duplicate key"},
		{"duplicate tool name", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"` + leakToken + `":` + storeTestPinJSON("1") + `,"` + leakToken + `":` + storeTestPinJSON("2") + `}}]}`, nil, "duplicate key"},
		{"key in other case", `{"version":1,"servers":[{"CLIENT":"c","source":"s","project_path":"","name":"n","tools":{}}]}`, nil, "unknown field"},
		{"version key in other case", `{"VERSION":1,"servers":[]}`, nil, "version field is missing"},
		{"invalid UTF-8", "{\"version\":1,\"servers\":[{\"client\":\"c\",\"source\":\"s\",\"name\":\"n\xff\",\"tools\":{}}]}", nil, "invalid JSON"},
		{"lone surrogate", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n\ud800","tools":{}}]}`, nil, "invalid JSON"},
		{"top level array type", `[1]`, nil, "invalid value at byte 0"},
		{"version not an integer", `{"version":2.0,"servers":[]}`, nil, "invalid value"},
		{"version too large", `{"version":99999999999999999999,"servers":[]}`, nil, "invalid value"},
		{"servers missing", `{"version":1}`, nil, "servers field is missing or null"},
		{"servers null", `{"version":1,"servers":null}`, nil, "servers field is missing or null"},
		{"client missing", `{"version":1,"servers":[{"source":"s","project_path":"","name":"n","tools":{}}]}`, nil, "servers[0]: a field is missing or null"},
		{"source missing", `{"version":1,"servers":[{"client":"c","project_path":"","name":"n","tools":{}}]}`, nil, "a field is missing or null"},
		{"project path missing", `{"version":1,"servers":[{"client":"c","source":"s","name":"n","tools":{}}]}`, nil, "a field is missing or null"},
		{"tools missing", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n"}]}`, nil, "a field is missing or null"},
		{"tools null", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":null}]}`, nil, "a field is missing or null"},
		{"name null", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":null,"tools":{}}]}`, nil, "a field is missing or null"},
		{"empty server name", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"","tools":{"` + leakToken + `":` + storeTestPinJSON("h") + `}}]}`, nil, "name is empty"},
		{"missing server name", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","tools":{"` + leakToken + `":` + storeTestPinJSON("h") + `}}]}`, nil, "a field is missing or null"},
		{"empty tool name", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"":{"hash":"h","canonical":"` + leakToken + `"}}}]}`, nil, "tool name is empty"},
		{"canonical invalid UTF-8", "{\"version\":1,\"servers\":[{\"client\":\"c\",\"source\":\"s\",\"project_path\":\"\",\"name\":\"n\",\"tools\":{\"t\":{\"hash\":\"h\",\"canonical\":\"" + leakToken + "\xff\"}}}]}", nil, "invalid JSON at byte"},
		{"canonical lone surrogate", `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":{"hash":"h","canonical":"` + leakToken + `\ud800"}}}]}`, nil, "invalid JSON at byte"},
		{"hash invalid UTF-8", "{\"version\":1,\"servers\":[{\"client\":\"c\",\"source\":\"s\",\"project_path\":\"\",\"name\":\"n\",\"tools\":{\"t\":{\"hash\":\"" + leakToken + "\xff\",\"canonical\":\"c\"}}}]}", nil, "invalid JSON at byte"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := storeTestWrite(t, tt.content)
			s, err := pins.Load(path)
			if err == nil {
				t.Fatalf("Load() error = nil, want error")
			}
			if s != nil {
				t.Errorf("Load() store = %v, want nil on error", s)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("Load() error = %v, want errors.Is %v", err, tt.wantIs)
			}
			if tt.wantIs == nil && errors.Is(err, pins.ErrUnsupportedVersion) {
				t.Errorf("Load() error = %v, must not wrap ErrUnsupportedVersion", err)
			}
			if tt.wantText != "" && !strings.Contains(err.Error(), tt.wantText) {
				t.Errorf("Load() error = %q, want text %q", err, tt.wantText)
			}
			if strings.Contains(err.Error(), leakToken) {
				t.Errorf("Load() error echoes file content: %q", err)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("Load() error = %q, want the path", err)
			}
		})
	}
}

func TestLoadBadFileDoesNotChangeIt(t *testing.T) {
	t.Parallel()
	content := `{"version":2,"servers":[]}`
	path := storeTestWrite(t, content)
	if _, err := pins.Load(path); !errors.Is(err, pins.ErrUnsupportedVersion) {
		t.Fatalf("Load() error = %v, want ErrUnsupportedVersion", err)
	}
	if got := string(pins.ReadFile(t, path)); got != content {
		t.Errorf("file changed to %q", got)
	}
}

func TestLoadTooLarge(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	// One byte over the cap. Zero bytes are not valid JSON, but the size check
	// comes first.
	if err := os.WriteFile(path, make([]byte, pins.MaxFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pins.Load(path); !errors.Is(err, safefile.ErrTooLarge) {
		t.Errorf("Load() error = %v, want errors.Is safefile.ErrTooLarge", err)
	}
}

func TestLoadAtSizeCap(t *testing.T) {
	t.Parallel()
	// Valid JSON of exactly the cap must pass the size check.
	head := `{"version":1,"servers":[]}`
	content := head + strings.Repeat(" ", pins.MaxFileSize-len(head))
	storeTestMustLoad(t, storeTestWrite(t, content))
}

func TestLoadDirectory(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := pins.Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want error for a directory")
	}
	if s != nil {
		t.Errorf("Load() store = %v, want nil", s)
	}
	if !errors.Is(err, safefile.ErrNotRegular) {
		t.Errorf("Load() error = %v, want errors.Is safefile.ErrNotRegular", err)
	}
}

func TestIdentitiesAreSeparate(t *testing.T) {
	t.Parallel()
	base := pins.Identity{Client: "claude-code", Source: "/a.json", ProjectPath: "/p1", Name: "srv"}
	ids := []pins.Identity{
		base,
		{Client: base.Client, Source: base.Source, ProjectPath: "/p2", Name: base.Name},
		{Client: base.Client, Source: base.Source, ProjectPath: "", Name: base.Name},
		{Client: base.Client, Source: "/b.json", ProjectPath: base.ProjectPath, Name: base.Name},
		{Client: "cursor", Source: base.Source, ProjectPath: base.ProjectPath, Name: base.Name},
		{Client: base.Client, Source: base.Source, ProjectPath: base.ProjectPath, Name: "srv2"},
	}

	path := storeTestPath(t)
	s := storeTestMustLoad(t, path)
	for i, id := range ids {
		storeTestMustSet(t, s, id, storeTestPins("tool", fmt.Sprintf("hash-%d", i)))
	}
	storeTestMustSave(t, s)

	got := storeTestMustLoad(t, path)
	for i, id := range ids {
		storeTestWantPins(t, got, id, storeTestPins("tool", fmt.Sprintf("hash-%d", i)))
	}
}

func TestSetReplacesOneServer(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	s := storeTestMustLoad(t, path)
	storeTestMustSet(t, s, idA, storeTestPins("old", "h1", "keep", "h2"))
	storeTestMustSet(t, s, idB, storeTestPins("b", "h3"))
	storeTestMustSet(t, s, idC, storeTestPins("c", "h4"))
	storeTestMustSave(t, s)

	s = storeTestMustLoad(t, path)
	storeTestMustSet(t, s, idA, storeTestPins("new", "h9"))
	storeTestMustSave(t, s)

	got := storeTestMustLoad(t, path)
	storeTestWantPins(t, got, idA, storeTestPins("new", "h9")) // "old" and "keep" are gone.
	storeTestWantPins(t, got, idB, storeTestPins("b", "h3"))
	storeTestWantPins(t, got, idC, storeTestPins("c", "h4"))
}

func TestSetNilClearsPins(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	s := storeTestMustLoad(t, path)
	storeTestMustSet(t, s, idA, storeTestPins("t", "h"))
	storeTestMustSet(t, s, idA, nil)
	storeTestMustSave(t, s)
	storeTestWantPins(t, storeTestMustLoad(t, path), idA, storeTestPins())
}

func TestZeroValueStore(t *testing.T) {
	t.Parallel()
	var s pins.Store
	storeTestMustSet(t, &s, idA, storeTestPins("t", "h"))
	storeTestWantPins(t, &s, idA, storeTestPins("t", "h"))
	// The empty path is refused before anything is written, so no temp file
	// reaches the working directory.
	if err := s.Save(); err == nil || !strings.Contains(err.Error(), "no path") {
		t.Errorf("Save() of a zero-value Store error = %v, want the no-path error", err)
	}
}

func TestGetReturnsCopy(t *testing.T) {
	t.Parallel()
	s := storeTestMustLoad(t, storeTestPath(t))
	storeTestMustSet(t, s, idA, storeTestPins("t", "h", "u", "h2"))

	got, _ := s.Get(idA)
	got["t"] = storeTestPin("changed")
	got["extra"] = storeTestPin("x")
	delete(got, "u")

	storeTestWantPins(t, s, idA, storeTestPins("t", "h", "u", "h2"))
}

func TestSetStoresCopy(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	s := storeTestMustLoad(t, path)
	in := storeTestPins("t", "h")
	storeTestMustSet(t, s, idA, in)
	in["t"] = storeTestPin("changed")
	in["extra"] = storeTestPin("x")

	storeTestWantPins(t, s, idA, storeTestPins("t", "h"))
	storeTestMustSave(t, s)
	storeTestWantPins(t, storeTestMustLoad(t, path), idA, storeTestPins("t", "h"))
}

func TestSaveDeterministic(t *testing.T) {
	t.Parallel()
	type entry struct {
		id pins.Identity
		p  pins.ServerPins
	}
	entries := []entry{
		{idA, storeTestPins("z", "1", "a", "2", "m", "3")},
		{idB, storeTestPins("b", "4")},
		{idC, storeTestPins("c", "5")},
		{pins.Identity{Client: "claude-code", Source: "/home/u/.claude.json", ProjectPath: "/work/a", Name: "alpha"}, storeTestPins("q", "6")},
	}
	save := func(order []int) []byte {
		path := storeTestPath(t)
		s := storeTestMustLoad(t, path)
		for _, i := range order {
			storeTestMustSet(t, s, entries[i].id, entries[i].p)
		}
		storeTestMustSave(t, s)
		return pins.ReadFile(t, path)
	}
	first := save([]int{0, 1, 2, 3})
	for _, order := range [][]int{{3, 2, 1, 0}, {2, 0, 3, 1}, {1, 3, 0, 2}} {
		if got := save(order); !bytes.Equal(first, got) {
			t.Errorf("order %v gives different bytes:\n%s\nwant\n%s", order, got, first)
		}
	}

	// The servers are sorted by client, source, project path and name.
	var f struct {
		Servers []struct {
			Client      string `json:"client"`
			ProjectPath string `json:"project_path"`
			Name        string `json:"name"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(first, &f); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range f.Servers {
		got = append(got, s.Client+"|"+s.ProjectPath+"|"+s.Name)
	}
	want := []string{
		"claude-code||alpha",
		"claude-code|/work/a|alpha",
		"claude-code|/work/p|beta",
		"cursor||gamma",
	}
	if !slices.Equal(got, want) {
		t.Errorf("server order = %v, want %v", got, want)
	}
}

func TestSaveIsStableAcrossLoad(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	s := storeTestMustLoad(t, path)
	storeTestMustSet(t, s, idA, storeTestPins("t", "h"))
	storeTestMustSet(t, s, idB, storeTestPins())
	storeTestMustSave(t, s)
	first := pins.ReadFile(t, path)

	storeTestMustSave(t, storeTestMustLoad(t, path))
	if second := pins.ReadFile(t, path); !bytes.Equal(first, second) {
		t.Errorf("Load+Save changed the file:\n%s\nwant\n%s", second, first)
	}
}

func TestSetRefusesInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		id   pins.Identity
		p    pins.ServerPins
		want string
	}{
		{"empty server name", pins.Identity{Client: "c", Source: "s"}, storeTestPins("t", "h"), "name is empty"},
		{"empty tool name", idA, storeTestPins("", "h"), "a tool name is empty"},
		{"empty hash", idA, storeTestPins("t", ""), "hash is empty"},
		{"client not UTF-8", pins.Identity{Client: "c\xff", Source: "s", Name: "n"}, storeTestPins("t", "h"), "server identity is not valid UTF-8"},
		{"source not UTF-8", pins.Identity{Client: "c", Source: "s\xff", Name: "n"}, storeTestPins("t", "h"), "server identity is not valid UTF-8"},
		{"project path not UTF-8", pins.Identity{Client: "c", Source: "s", ProjectPath: "p\xff", Name: "n"}, storeTestPins("t", "h"), "server identity is not valid UTF-8"},
		{"server name not UTF-8", pins.Identity{Client: "c", Source: "s", Name: "n\xff"}, storeTestPins("t", "h"), "server identity is not valid UTF-8"},
		{"tool name not UTF-8", idA, storeTestPins("t\xff", "h"), "a tool name is not valid UTF-8"},
		{"hash not UTF-8", idA, storeTestPins("t", "h\xff"), "a tool hash is not valid UTF-8"},
		{"empty canonical", idA, pins.ServerPins{"t": {Hash: "h"}}, "canonical text is empty"},
		{"empty hash and canonical", idA, pins.ServerPins{"t": {}}, "hash is empty"},
		{"canonical not UTF-8", idA, pins.ServerPins{"t": {Hash: "h", Canonical: "c\xff"}}, "a tool canonical text is not valid UTF-8"},
		{"truncated multibyte canonical", idA, pins.ServerPins{"t": {Hash: "h", Canonical: "c\xe2\x82"}}, "a tool canonical text is not valid UTF-8"},
		{"one bad pin among good ones", idA, pins.ServerPins{"a": storeTestPin("1"), "b": {Hash: "2"}, "c": storeTestPin("3")}, "canonical text is empty"},
		{"truncated multibyte tool name", idA, storeTestPins("t\xe2\x82", "h"), "a tool name is not valid UTF-8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := storeTestMustLoad(t, storeTestPath(t))
			err := s.Set(tt.id, tt.p)
			if err == nil {
				t.Fatal("Set() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Set() error = %q, want text %q", err, tt.want)
			}
			// The bad value must not reach the error text.
			if strings.Contains(err.Error(), "\xff") || strings.Contains(err.Error(), "\xe2") {
				t.Errorf("Set() error echoes the bad value: %q", err)
			}
			if _, ok := s.Get(tt.id); ok {
				t.Error("Get() ok = true after a refused Set, want false")
			}
		})
	}
}

func TestLoadServerTooLarge(t *testing.T) {
	t.Parallel()
	// Load applies the cap of one server, as Set does.
	name := strings.Repeat("a", pins.MaxServerSize)
	content := `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"` + name + `":` + storeTestPinJSON("h") + `}}]}`
	_, err := pins.Load(storeTestWrite(t, content))
	if err == nil || !strings.Contains(err.Error(), "servers[0]: server pins are") {
		t.Fatalf("Load() error = %v, want the size error for servers[0]", err)
	}
}

func TestSetRefusalKeepsOldPins(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		p    pins.ServerPins
	}{
		{"empty hash", pins.ServerPins{"t": {Canonical: "c"}}},
		{"empty canonical", pins.ServerPins{"t": {Hash: "h"}}},
		{"canonical not UTF-8", pins.ServerPins{"t": {Hash: "h", Canonical: "\xff"}}},
		{"empty tool name", pins.ServerPins{"": storeTestPin("h")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := storeTestPath(t)
			s := storeTestMustLoad(t, path)
			storeTestMustSet(t, s, idA, storeTestPins("t", "h"))
			storeTestMustSet(t, s, idB, storeTestPins("u", "h2"))
			if err := s.Set(idA, tt.p); err == nil {
				t.Fatal("Set() error = nil, want error")
			}
			// A refused Set of a new server adds nothing.
			if err := s.Set(idC, tt.p); err == nil {
				t.Fatal("Set() of a new server error = nil, want error")
			}
			if _, ok := s.Get(idC); ok {
				t.Error("Get() of the refused new server ok = true, want false")
			}
			storeTestWantPins(t, s, idA, storeTestPins("t", "h"))
			storeTestWantPins(t, s, idB, storeTestPins("u", "h2"))
			storeTestMustSave(t, s)
			got := storeTestMustLoad(t, path)
			storeTestWantPins(t, got, idA, storeTestPins("t", "h"))
			storeTestWantPins(t, got, idB, storeTestPins("u", "h2"))
		})
	}
}

func TestRoundTripPinContent(t *testing.T) {
	t.Parallel()
	// The canonical text is JSON, so it holds quotes and backslashes. It also
	// holds characters that a JSON encoder may escape.
	canonical := `{"description":"say \"hi\" <b>&</b>\n\tline\u0007","inputSchema":{"type":"object"},"name":"read \u2603 \U0001F600"}`
	in := pins.ServerPins{
		"read":            {Hash: "sha256-v1:aaaa", Canonical: canonical},
		"<b>&\"q\"\n\x07": {Hash: "sha256-v1:bbbb", Canonical: "x"},
		"unicode \u2603":  {Hash: "sha256-v1:cccc", Canonical: "\u2028\u2029\u00e9\U0001F600"},
	}
	path := storeTestPath(t)
	s := storeTestMustLoad(t, path)
	storeTestMustSet(t, s, idA, in)
	storeTestMustSave(t, s)

	storeTestWantPins(t, storeTestMustLoad(t, path), idA, in)
	// The file shows the stored fields under their keys.
	var doc struct {
		Servers []struct {
			Tools map[string]struct {
				Hash      string `json:"hash"`
				Canonical string `json:"canonical"`
			} `json:"tools"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(pins.ReadFile(t, path), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Servers) != 1 || doc.Servers[0].Tools["read"].Hash != "sha256-v1:aaaa" || doc.Servers[0].Tools["read"].Canonical != canonical {
		t.Errorf("file tools = %+v, want hash and canonical of %q", doc.Servers, "read")
	}
}

func TestLoadIncompletePin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		tool string // the JSON value of the tool
		want string
	}{
		{"hash missing", `{"canonical":"c"}`, "hash is empty or missing"},
		{"hash null", `{"hash":null,"canonical":"c"}`, "hash is empty or missing"},
		{"hash empty", `{"hash":"","canonical":"c"}`, "hash is empty or missing"},
		{"canonical missing", `{"hash":"h"}`, "canonical text is empty or missing"},
		{"canonical null", `{"hash":"h","canonical":null}`, "canonical text is empty or missing"},
		{"canonical empty", `{"hash":"h","canonical":""}`, "canonical text is empty or missing"},
		{"both missing", `{}`, "hash is empty or missing"},
		{"tool null", `null`, "hash is empty or missing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			content := `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"` + leakToken + `":` + tt.tool + `}}]}`
			path := storeTestWrite(t, content)
			s, err := pins.Load(path)
			if err == nil {
				t.Fatal("Load() error = nil, want error")
			}
			if s != nil {
				t.Errorf("Load() store = %v, want nil on error", s)
			}
			if !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "servers[0]") {
				t.Errorf("Load() error = %q, want servers[0] and %q", err, tt.want)
			}
			if strings.Contains(err.Error(), leakToken) {
				t.Errorf("Load() error echoes the tool name: %q", err)
			}
		})
	}
}

// TestLoadOldShape checks a file in the earlier format, where a tool maps to
// its hash string. Load must refuse it and never replace it with an empty
// store.
func TestLoadOldShape(t *testing.T) {
	t.Parallel()
	content := `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"read":"sha256-v1:` + leakToken + `"}}]}`
	path := storeTestWrite(t, content)
	s, err := pins.Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want error for the old shape")
	}
	if s != nil {
		t.Errorf("Load() store = %v, want nil", s)
	}
	if errors.Is(err, pins.ErrUnsupportedVersion) {
		t.Errorf("Load() error = %v, must not wrap ErrUnsupportedVersion", err)
	}
	for _, leak := range []string{leakToken, "read", "sha256"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("Load() error echoes file content %q: %q", leak, err)
		}
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("Load() error = %q, want the path", err)
	}
	if got := string(pins.ReadFile(t, path)); got != content {
		t.Errorf("Load changed the file to %q", got)
	}
}

// serverSizeCases are the two ways that one server grows: a long tool name and
// a long canonical text (the usual way). overhead is the size of the entry of
// the server n with no growth, as compact JSON. pins(n) adds n bytes to it.
var serverSizeCases = []struct {
	name     string
	overhead int
	pins     func(n int) pins.ServerPins
}{
	{
		"tool name",
		len(`{"client":"c","source":"s","project_path":"","name":"n","tools":{"":{"hash":"h","canonical":"c"}}}`),
		func(n int) pins.ServerPins {
			return pins.ServerPins{strings.Repeat("a", n): {Hash: "h", Canonical: "c"}}
		},
	},
	{
		"canonical",
		len(`{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":{"hash":"h","canonical":""}}}`),
		func(n int) pins.ServerPins {
			return pins.ServerPins{"t": {Hash: "h", Canonical: strings.Repeat("a", n)}}
		},
	},
}

func TestSetSizeLimit(t *testing.T) {
	t.Parallel()
	id := pins.Identity{Client: "c", Source: "s", Name: "n"}
	for _, tt := range serverSizeCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			atCap := tt.pins(pins.MaxServerSize - tt.overhead)
			path := storeTestPath(t)
			s := storeTestMustLoad(t, path)
			storeTestMustSet(t, s, idA, storeTestPins("t", "h"))
			storeTestMustSet(t, s, id, atCap)

			// One byte over is refused, the old pins of the server stay, and the
			// other servers still save.
			err := s.Set(id, tt.pins(pins.MaxServerSize-tt.overhead+1))
			want := fmt.Sprintf("server pins are %d bytes as JSON, larger than the %d byte limit", pins.MaxServerSize+1, pins.MaxServerSize)
			if err == nil || err.Error() != want {
				t.Fatalf("Set() error = %v, want %q", err, want)
			}
			storeTestWantPins(t, s, id, atCap)
			storeTestMustSave(t, s)
			got := storeTestMustLoad(t, path)
			storeTestWantPins(t, got, idA, storeTestPins("t", "h"))
			storeTestWantPins(t, got, id, atCap)
		})
	}
}

// TestLoadServerSizeLimit checks the cap of one server in Load: exactly the
// cap loads, one byte over does not.
func TestLoadServerSizeLimit(t *testing.T) {
	t.Parallel()
	for _, tt := range serverSizeCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			write := func(n int) string {
				// Compact JSON, as ValidateServer measures the entry.
				data, err := json.Marshal(map[string]any{
					"version": 1,
					"servers": []any{map[string]any{
						"client": "c", "source": "s", "project_path": "", "name": "n",
						"tools": tt.pins(n),
					}},
				})
				if err != nil {
					t.Fatal(err)
				}
				return storeTestWrite(t, string(data))
			}
			if _, err := pins.Load(write(pins.MaxServerSize - tt.overhead)); err != nil {
				t.Errorf("Load() at the cap error = %v, want nil", err)
			}
			_, err := pins.Load(write(pins.MaxServerSize - tt.overhead + 1))
			if err == nil || !strings.Contains(err.Error(), "servers[0]: server pins are") {
				t.Errorf("Load() one byte over error = %v, want the size error for servers[0]", err)
			}
		})
	}
}

// TestLimits pins the two caps, so a change of a limit is a visible decision.
func TestLimits(t *testing.T) {
	t.Parallel()
	if pins.MaxServerSize != 2<<20 {
		t.Errorf("MaxServerSize = %d, want %d", pins.MaxServerSize, 2<<20)
	}
	if pins.MaxFileSize != 32<<20 {
		t.Errorf("MaxFileSize = %d, want %d", pins.MaxFileSize, 32<<20)
	}
}

func TestSaveSizeLimit(t *testing.T) {
	t.Parallel()
	const limit = pins.MaxFileSize
	// Set caps each server below the file limit, so the test fills the file
	// with many servers of one tool each. The tool names are "a" repeated, so
	// each extra name byte adds one byte to the file.
	const servers = 64
	sizeID := func(i int) pins.Identity {
		return pins.Identity{Client: "c", Source: "s", Name: fmt.Sprintf("n%03d", i)}
	}
	// nameLen is the tool name length of server i: one byte plus an even share
	// of extra.
	nameLen := func(extra, i int) int {
		n := 1 + extra/servers
		if i < extra%servers {
			n++
		}
		return n
	}
	sizePins := func(n int) pins.ServerPins { return storeTestPins(strings.Repeat("a", n), "h") }
	// fill returns a Store for path with all servers, whose tool names hold
	// extra bytes on top of one byte each.
	fill := func(t *testing.T, path string, extra int) *pins.Store {
		t.Helper()
		s := storeTestMustLoad(t, path)
		for i := range servers {
			storeTestMustSet(t, s, sizeID(i), sizePins(nameLen(extra, i)))
		}
		return s
	}
	newID := pins.Identity{Client: "c", Source: "s", Name: "new"}
	probe := storeTestPath(t)
	storeTestMustSave(t, fill(t, probe, 0))
	base := len(pins.ReadFile(t, probe))
	full := limit - base // the extra bytes that fill the file exactly

	// The subtests are not parallel: each one holds a store and a file of
	// about 32 MiB, so they run one at a time to keep memory modest.

	t.Run("exactly at the limit saves and loads", func(t *testing.T) {
		path := storeTestPath(t)
		storeTestMustSave(t, fill(t, path, full))
		if got := len(pins.ReadFile(t, path)); got != limit {
			t.Fatalf("file size = %d, want %d", got, limit)
		}
		storeTestMustLoad(t, path)
	})

	t.Run("Set refuses one byte over with ErrStoreFull", func(t *testing.T) {
		path := storeTestPath(t)
		s := fill(t, path, full)
		storeTestMustSave(t, s)
		before := sha256.Sum256(pins.ReadFile(t, path))
		old0, _ := s.Get(sizeID(0))

		refusals := []struct {
			name string
			id   pins.Identity
			p    pins.ServerPins
		}{
			{"a new server", newID, storeTestPins("t", "h")},
			{"one more byte in a server", sizeID(0), sizePins(nameLen(full, 0) + 1)},
		}
		for _, r := range refusals {
			err := s.Set(r.id, r.p)
			if !errors.Is(err, pins.ErrStoreFull) {
				t.Errorf("Set(%s) error = %v, want errors.Is ErrStoreFull", r.name, err)
			}
		}
		// The growth by one byte gives a file one byte over the limit.
		err := s.Set(sizeID(0), sizePins(nameLen(full, 0)+1))
		if want := fmt.Sprintf("%d bytes with this server", limit+1); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Set() error = %v, want text %q", err, want)
		}

		// The refusals changed nothing.
		if _, ok := s.Get(newID); ok {
			t.Error("Get() of the refused new server ok = true, want false")
		}
		storeTestWantPins(t, s, sizeID(0), old0)
		if got := s.TrackedFileSize(); got != limit {
			t.Errorf("TrackedFileSize() after the refusals = %d, want %d", got, limit)
		}
		storeTestMustSave(t, s)
		if after := sha256.Sum256(pins.ReadFile(t, path)); after != before {
			t.Error("Save after the refused Sets wrote other bytes")
		}

		// A smaller replacement is accepted, and the new server then fits in
		// the bytes it gave back.
		storeTestMustSet(t, s, sizeID(1), sizePins(1))
		storeTestMustSet(t, s, newID, storeTestPins("t", "h"))
		storeTestMustSave(t, s)
		got := storeTestMustLoad(t, path)
		storeTestWantPins(t, got, newID, storeTestPins("t", "h"))
		storeTestWantPins(t, got, sizeID(1), sizePins(1))
		storeTestWantPins(t, got, sizeID(2), sizePins(nameLen(full, 2)))
		if names, want := pins.DirNames(t, filepath.Dir(path)), []string{"pins.json"}; !slices.Equal(names, want) {
			t.Errorf("dir entries = %v, want %v", names, want)
		}
	})

	// A hand-edited compact file can be under the limit while the indented
	// file that Save writes is over it. Save's own check is the backstop.
	t.Run("compact file over the limit once indented", func(t *testing.T) {
		compact := func(extra int) string {
			var b strings.Builder
			b.WriteString(`{"version":1,"servers":[`)
			for i := range servers {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `{"client":"c","source":"s","project_path":"","name":%q,"tools":{%q:%s}}`,
					sizeID(i).Name, strings.Repeat("a", nameLen(extra, i)), storeTestPinJSON("h"))
			}
			b.WriteString("]}")
			return b.String()
		}
		const under = 1000 // the compact file is this many bytes under the limit
		path := storeTestWrite(t, compact(limit-under-len(compact(0))))
		fileSum := sha256.Sum256(pins.ReadFile(t, path))
		s := storeTestMustLoad(t, path)
		over := s.TrackedFileSize() - limit
		if over <= 1 {
			t.Fatalf("setup: the indented file is %d bytes over the limit, want more than 1", over)
		}

		wantSaveErr := func(t *testing.T, size int) {
			t.Helper()
			err := s.Save()
			want := fmt.Sprintf("save %s: pins data is %d bytes, larger than the 32 MiB limit", path, size)
			if err == nil || err.Error() != want {
				t.Errorf("Save() error = %v, want %q", err, want)
			}
			if got := sha256.Sum256(pins.ReadFile(t, path)); got != fileSum {
				t.Error("a failed Save changed the old file")
			}
		}
		wantSaveErr(t, limit+over)

		// Growth is refused; a shrink is accepted, also while still over.
		if err := s.Set(newID, storeTestPins("t", "h")); !errors.Is(err, pins.ErrStoreFull) {
			t.Errorf("Set() of a new server error = %v, want errors.Is ErrStoreFull", err)
		}
		storeTestMustSet(t, s, sizeID(0), sizePins(nameLen(limit-under-len(compact(0)), 0)-1))
		wantSaveErr(t, limit+over-1)

		// Shrink under the limit: Save works and writes the tracked size.
		storeTestMustSet(t, s, sizeID(1), sizePins(1))
		tracked := s.TrackedFileSize()
		storeTestMustSave(t, s)
		if got := len(pins.ReadFile(t, path)); got != tracked || got > limit {
			t.Errorf("file size = %d, want the tracked size %d, at most %d", got, tracked, limit)
		}
	})
}

// TestTrackedSizeMatchesSave checks that the size that the Store tracks for
// ErrStoreFull is exactly the size of the file that Save writes.
func TestTrackedSizeMatchesSave(t *testing.T) {
	t.Parallel()
	awkwardPins := pins.ServerPins{
		"ctl \x00\x01\x1f\x7f\n\t\"\\": {Hash: "h\"q\\", Canonical: "<b>&amp;</b> \u2028\u2029"},
		"emoji \U0001F600 \u00e9 <>&":  {Hash: "sha256-v1:x", Canonical: `{"a":"\"q\"","b":"\u0007"}`},
		"plain":                        storeTestPin("h"),
	}
	awkwardID := pins.Identity{Client: "c<&>\x1b", Source: "/p/\u2028\"q\"", ProjectPath: "\U0001F600\\", Name: "n\t\u2029"}
	set := func(id pins.Identity, p pins.ServerPins) func(*testing.T, *pins.Store) {
		return func(t *testing.T, s *pins.Store) {
			t.Helper()
			storeTestMustSet(t, s, id, p)
		}
	}
	tests := []struct {
		name    string
		content string // pins.json to load first; empty means none
		steps   []func(*testing.T, *pins.Store)
	}{
		{name: "empty store"},
		{name: "one server", steps: []func(*testing.T, *pins.Store){set(idA, storeTestPins("t", "h"))}},
		{name: "server with no tools", steps: []func(*testing.T, *pins.Store){set(idA, nil)}},
		{name: "several servers with awkward strings", steps: []func(*testing.T, *pins.Store){
			set(idA, awkwardPins), set(awkwardID, awkwardPins), set(idB, storeTestPins("t", "h")),
		}},
		{name: "replace with a bigger server", steps: []func(*testing.T, *pins.Store){
			set(idA, storeTestPins("t", "h")), set(idB, nil), set(idA, awkwardPins),
		}},
		{name: "replace with a smaller server", steps: []func(*testing.T, *pins.Store){
			set(idA, awkwardPins), set(idB, nil), set(idA, storeTestPins("t", "h")),
		}},
		{name: "replace the only server with no tools", steps: []func(*testing.T, *pins.Store){
			set(idA, awkwardPins), set(idA, nil),
		}},
		{
			name: "compact hand-written file",
			// Escapes that Save writes in another form, and no whitespace.
			content: `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n\u0041",` +
				`"tools":{"t\u2028\u00e9":{"hash":"h\/x","canonical":"\u003cb\u003e\ud83d\ude00"}}},` +
				`{"client":"c","source":"s","project_path":"","name":"m","tools":{}}]}`,
		},
		{
			name:    "compact file, then a change",
			content: `{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"m","tools":{}}]}`,
			steps:   []func(*testing.T, *pins.Store){set(idA, awkwardPins)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := storeTestPath(t)
			if tt.content != "" {
				path = storeTestWrite(t, tt.content)
			}
			s := storeTestMustLoad(t, path)
			for _, step := range tt.steps {
				step(t, s)
			}
			tracked := s.TrackedFileSize()
			storeTestMustSave(t, s)
			if got := len(pins.ReadFile(t, path)); got != tracked {
				t.Errorf("TrackedFileSize() = %d, Save wrote %d bytes", tracked, got)
			}
			// Load of the saved file tracks the same size.
			if got := storeTestMustLoad(t, path).TrackedFileSize(); got != tracked {
				t.Errorf("TrackedFileSize() after Load = %d, want %d", got, tracked)
			}
		})
	}
}

func TestClone(t *testing.T) {
	t.Parallel()

	t.Run("changes do not cross", func(t *testing.T) {
		t.Parallel()
		path := storeTestPath(t)
		s := storeTestMustLoad(t, path)
		storeTestMustSet(t, s, idA, storeTestPins("t", "h"))
		origSize := s.TrackedFileSize()

		c := s.Clone()
		if got := c.TrackedFileSize(); got != origSize {
			t.Errorf("clone TrackedFileSize() = %d, want %d", got, origSize)
		}
		storeTestWantPins(t, c, idA, storeTestPins("t", "h"))

		// Set on the clone: a new server and a replaced one.
		storeTestMustSet(t, c, idB, storeTestPins("u", "h2"))
		storeTestMustSet(t, c, idA, storeTestPins("t", "h", "v", "h3"))
		cloneSize := c.TrackedFileSize()
		if _, ok := s.Get(idB); ok {
			t.Error("original Get(idB) ok = true after Set on the clone, want false")
		}
		storeTestWantPins(t, s, idA, storeTestPins("t", "h"))
		if got := s.TrackedFileSize(); got != origSize {
			t.Errorf("original TrackedFileSize() = %d after Set on the clone, want %d", got, origSize)
		}

		// Set on the original.
		storeTestMustSet(t, s, idC, storeTestPins("w", "h4"))
		if _, ok := c.Get(idC); ok {
			t.Error("clone Get(idC) ok = true after Set on the original, want false")
		}
		if got := c.TrackedFileSize(); got != cloneSize {
			t.Errorf("clone TrackedFileSize() = %d after Set on the original, want %d", got, cloneSize)
		}

		// The clone saves to the same path, with its own content.
		storeTestMustSave(t, c)
		got := storeTestMustLoad(t, path)
		storeTestWantPins(t, got, idB, storeTestPins("u", "h2"))
		if _, ok := got.Get(idC); ok {
			t.Error("the saved clone holds idC from the original")
		}

		// The clone replaced idA. When the two shared their size records, the
		// original would now subtract the size of the clone's idA.
		storeTestMustSet(t, s, idA, storeTestPins("x", "h5"))
		tracked := s.TrackedFileSize()
		storeTestMustSave(t, s)
		if got := len(pins.ReadFile(t, path)); got != tracked {
			t.Errorf("original TrackedFileSize() = %d, Save wrote %d bytes", tracked, got)
		}
	})

	t.Run("copies Existed and RanWithoutLock", func(t *testing.T) {
		t.Parallel()
		existing := storeTestPath(t)
		storeTestMustSave(t, storeTestMustLoad(t, existing))
		unlocked, release, err := pins.LoadLockedWith(t.Context(), storeTestPath(t), pins.LockHooks{
			TryLock: func(*os.File) (bool, error) { return false, pins.ErrLockUnsupported },
		})
		if err != nil {
			t.Fatalf("LoadLockedWith() error = %v", err)
		}
		defer release()

		tests := []struct {
			name                            string
			s                               *pins.Store
			wantExisted, wantRanWithoutLock bool
		}{
			{"first run", storeTestMustLoad(t, storeTestPath(t)), false, false},
			{"existing file", storeTestMustLoad(t, existing), true, false},
			{"unlocked", unlocked, false, true},
		}
		for _, tt := range tests {
			c := tt.s.Clone()
			if c.Existed() != tt.wantExisted || c.RanWithoutLock() != tt.wantRanWithoutLock {
				t.Errorf("%s: clone Existed() = %v, RanWithoutLock() = %v; want %v, %v",
					tt.name, c.Existed(), c.RanWithoutLock(), tt.wantExisted, tt.wantRanWithoutLock)
			}
		}
	})

	t.Run("zero-value Store", func(t *testing.T) {
		t.Parallel()
		var s pins.Store
		c := s.Clone()
		storeTestMustSet(t, c, idA, storeTestPins("t", "h"))
		if _, ok := s.Get(idA); ok {
			t.Error("zero-value Get(idA) ok = true after Set on the clone, want false")
		}
		if c.Existed() || c.RanWithoutLock() {
			t.Error("clone of a zero-value Store has Existed or RanWithoutLock set")
		}
		if err := c.Save(); err == nil || !strings.Contains(err.Error(), "no path") {
			t.Errorf("Save() of the clone error = %v, want the no-path error", err)
		}
	})
}

func TestExisted(t *testing.T) {
	t.Parallel()
	loaders := []struct {
		name string
		load func(t *testing.T, path string) *pins.Store
	}{
		{"Load", storeTestMustLoad},
		{"LoadLocked", func(t *testing.T, path string) *pins.Store {
			t.Helper()
			s, release, err := pins.LoadLocked(t.Context(), path, 0)
			if err != nil {
				t.Fatalf("LoadLocked(%q) error = %v, want nil", path, err)
			}
			t.Cleanup(release)
			return s
		}},
	}
	tests := []struct {
		name string
		path func(t *testing.T) string
		want bool
	}{
		{"first run, missing file", storeTestPath, false},
		{"first run, missing directory", func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "no", "such", "pins.json")
		}, false},
		{"deleted file in an existing directory", func(t *testing.T) string {
			path := storeTestPath(t)
			storeTestMustSave(t, storeTestMustLoad(t, path))
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			return path
		}, false},
		{"after Save", func(t *testing.T) string {
			path := storeTestPath(t)
			s := storeTestMustLoad(t, path)
			storeTestMustSet(t, s, idA, storeTestPins("t", "h"))
			storeTestMustSave(t, s)
			return path
		}, true},
	}
	for _, l := range loaders {
		for _, tt := range tests {
			t.Run(l.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				s := l.load(t, tt.path(t))
				if got := s.Existed(); got != tt.want {
					t.Errorf("Existed() = %v, want %v", got, tt.want)
				}
				if l.name == "Load" && s.RanWithoutLock() {
					t.Error("RanWithoutLock() = true for Load, want false")
				}
			})
		}
	}

	var zero pins.Store
	if zero.Existed() || zero.RanWithoutLock() {
		t.Error("zero-value Store has Existed or RanWithoutLock set")
	}
}

// TestPath checks that Path returns the path that the Store was loaded from,
// for Load and LoadLocked, on a first run and with an existing file, and for
// a Clone.
func TestPath(t *testing.T) {
	t.Parallel()
	existing := storeTestPath(t)
	storeTestMustSave(t, storeTestMustLoad(t, existing))

	tests := []struct {
		name string
		path string
	}{
		{"first run", storeTestPath(t)},
		{"first run, missing directory", filepath.Join(t.TempDir(), "no", "such", "pins.json")},
		{"existing file", existing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := storeTestMustLoad(t, tt.path)
			if got := s.Path(); got != tt.path {
				t.Errorf("Load: Path() = %q, want %q", got, tt.path)
			}
			if got := s.Clone().Path(); got != tt.path {
				t.Errorf("Clone: Path() = %q, want %q", got, tt.path)
			}

			locked, release, err := pins.LoadLocked(t.Context(), tt.path, 0)
			if err != nil {
				t.Fatalf("LoadLocked(%q) error = %v, want nil", tt.path, err)
			}
			defer release()
			if got := locked.Path(); got != tt.path {
				t.Errorf("LoadLocked: Path() = %q, want %q", got, tt.path)
			}
		})
	}

	var zero pins.Store
	if got := zero.Path(); got != "" {
		t.Errorf("zero-value Store: Path() = %q, want empty", got)
	}
}

// TestLoadLockedDanglingSymlink checks that LoadLocked, like Load, does not
// treat a pins.json symlink with a missing target as a first run.
func TestLoadLockedDanglingSymlink(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	if err := os.Symlink("gone.json", path); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}
	s, release, err := pins.LoadLocked(t.Context(), path, 0)
	if release == nil {
		t.Fatal("LoadLocked() release = nil, want a function")
	}
	release()
	if want := "read " + path + ": the target of the symlink is missing"; err == nil || err.Error() != want {
		t.Errorf("LoadLocked() error = %v, want %q", err, want)
	}
	if s != nil {
		t.Errorf("LoadLocked() store = %v, want nil", s)
	}
	// The symlink is still there: nothing replaced it.
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("pins.json is no longer a symlink (err = %v)", err)
	}
}

func TestSymlinkedConfigDir(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	link := filepath.Join(root, "link")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}

	path := filepath.Join(link, "pins.json")
	s := storeTestMustLoad(t, path) // Missing file through the link.
	storeTestMustSet(t, s, idA, storeTestPins("t", "h"))
	storeTestMustSave(t, s)

	if _, err := os.Stat(filepath.Join(realDir, "pins.json")); err != nil {
		t.Errorf("pins.json not in the real directory: %v", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("Save replaced the symlinked directory (err = %v)", err)
	}
	storeTestWantPins(t, storeTestMustLoad(t, path), idA, storeTestPins("t", "h"))
}

// TestFileHasNoSecrets checks the format, not a server config: Identity has
// no field for a secret (args, URL, env, headers, command), so no secret can
// reach the file. The test checks that the file holds only the documented
// keys at each level. A test that builds an Identity from a real server
// config belongs with the caller that does it.
func TestFileHasNoSecrets(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	s := storeTestMustLoad(t, path)
	storeTestMustSet(t, s, pins.Identity{Client: "claude-code", Source: "/home/u/.claude.json", Name: "alpha"},
		storeTestPins("read", "sha256:3f2a", "write", "sha256:9c1b"))
	storeTestMustSave(t, s)
	data := pins.ReadFile(t, path)

	// Only the documented keys appear, at each level.
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if got, want := slices.Sorted(maps.Keys(doc)), []string{"servers", "version"}; !slices.Equal(got, want) {
		t.Errorf("top-level keys = %v, want %v", got, want)
	}
	servers, ok := doc["servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("servers = %v, want one entry", doc["servers"])
	}
	srv, ok := servers[0].(map[string]any)
	if !ok {
		t.Fatalf("server entry = %T, want object", servers[0])
	}
	wantKeys := []string{"client", "name", "project_path", "source", "tools"}
	if got := slices.Sorted(maps.Keys(srv)); !slices.Equal(got, wantKeys) {
		t.Errorf("server keys = %v, want %v", got, wantKeys)
	}
	tools, ok := srv["tools"].(map[string]any)
	if !ok {
		t.Fatalf("tools = %T, want object", srv["tools"])
	}
	for name, v := range tools {
		pin, ok := v.(map[string]any)
		if !ok {
			t.Errorf("tool %q value = %T, want object", name, v)
			continue
		}
		if got, want := slices.Sorted(maps.Keys(pin)), []string{"canonical", "hash"}; !slices.Equal(got, want) {
			t.Errorf("tool %q keys = %v, want %v", name, got, want)
		}
	}
}

func FuzzLoad(f *testing.F) {
	const server = `{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":{"hash":"h","canonical":"c"}}}`
	seeds := []string{
		`{"version":1,"servers":[` + server + `]}`,
		`{"version":1,"servers":[` + server + `,{"client":"c","source":"s","project_path":"/p","name":"n","tools":{}}]}`,
		`{"version":1,"servers":[]}`,
		`{"version":1}`,
		`{"version":1,"servers":null}`,
		`{"version":1,"servers":[{"client":"c","source":"s","name":"n","tools":null}]}`,
		`{"version":2,"x":1}`,
		`{"version":0}`,
		`{"servers":[]}`,
		`{"version":1,"servers":[` + server + `,` + server + `]}`,
		`{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"","tools":{}}]}`,
		`{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"":{"hash":"h","canonical":"c"}}}]}`,
		`{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":""}}]}`,
		`{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":{"hash":"","canonical":"c"}}}]}`,
		`{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":{"hash":"h","canonical":""}}}]}`,
		`{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":{"hash":"h"}}}]}`,
		`{"version":1,"servers":[{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":{"hash":null,"canonical":"c"}}}]}`,
		`{"version":1,"servers":[],"extra":1}`,
		`{"version":1,"servers":[]} trailing`,
		`{"version":1,"servers":[` + server,
		`{"version":"1"}`,
		`[]`,
		`null`,
		``,
		`{`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip("input too large to be useful")
		}
		dir := t.TempDir()
		src := filepath.Join(dir, "pins.json")
		if err := os.WriteFile(src, data, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := pins.Load(src)
		if err != nil {
			if s != nil {
				t.Fatal("Load() returned a store and an error")
			}
			return
		}

		// Load accepted the file, so it is a valid document: read the identities
		// with a plain decode and compare the pins after a Save and a Load.
		var doc struct {
			Servers []struct {
				Client      string `json:"client"`
				Source      string `json:"source"`
				ProjectPath string `json:"project_path"`
				Name        string `json:"name"`
			} `json:"servers"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("Load accepted data that json.Unmarshal rejects: %v", err)
		}
		ids := make([]pins.Identity, 0, len(doc.Servers))
		for _, srv := range doc.Servers {
			ids = append(ids, pins.Identity{Client: srv.Client, Source: srv.Source, ProjectPath: srv.ProjectPath, Name: srv.Name})
		}

		dst := filepath.Join(dir, "sub", "copy.json")
		saved, err := pins.Load(dst)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			p, ok := s.Get(id)
			if !ok {
				t.Fatalf("Get(%+v) ok = false for an identity in the file", id)
			}
			storeTestMustSet(t, saved, id, p)
		}
		if err := saved.Save(); err != nil {
			t.Fatalf("Save() of a loaded store: %v", err)
		}
		again, err := pins.Load(dst)
		if err != nil {
			t.Fatalf("Load() of a saved store: %v", err)
		}
		for _, id := range ids {
			want, _ := s.Get(id)
			got, ok := again.Get(id)
			if !ok || !maps.Equal(got, want) {
				t.Fatalf("Get(%+v) after the round trip = %v, %v; want %v", id, got, ok, want)
			}
		}

		// Save is a fixed point: Load then Save gives the same bytes.
		first := pins.ReadFile(t, dst)
		if err := again.Save(); err != nil {
			t.Fatal(err)
		}
		second := pins.ReadFile(t, dst)
		if !bytes.Equal(first, second) {
			t.Fatalf("Save is not stable:\n%s\nvs\n%s", first, second)
		}
	})
}
