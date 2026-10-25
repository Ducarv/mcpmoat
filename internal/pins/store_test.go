package pins_test

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	tests := []struct {
		name string
		path func(t *testing.T) string
		want string
	}{
		{"pins.json symlink with a missing target", func(t *testing.T) string {
			path := storeTestPath(t)
			symlink(t, "gone.json", path)
			return path
		}, "the target of the symlink is missing"},
		{"directory symlink with a missing target", func(t *testing.T) string {
			link := filepath.Join(t.TempDir(), "mcpmoat")
			symlink(t, filepath.Join(t.TempDir(), "gone"), link)
			return filepath.Join(link, "pins.json")
		}, "is not a directory, or it is a symlink with a missing target"},
		{"directory is a file", func(t *testing.T) string {
			dir := filepath.Join(t.TempDir(), "mcpmoat")
			if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "pins.json")
		}, "is not a directory, or it is a symlink with a missing target"},
		{"a parent of the directory is a symlink with a missing target", func(t *testing.T) string {
			link := filepath.Join(t.TempDir(), "config")
			symlink(t, filepath.Join(t.TempDir(), "gone"), link)
			return filepath.Join(link, "mcpmoat", "pins.json")
		}, "is not a directory, or it is a symlink with a missing target"},
		{"a parent of the directory is a file", func(t *testing.T) string {
			file := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(file, "mcpmoat", "pins.json")
		}, "not a directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := tt.path(t)
			s, err := pins.Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want text %q", err, tt.want)
			}
			if s != nil {
				t.Errorf("Load() store = %v, want nil", s)
			}
		})
	}
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
	saveWithExtra := func(t *testing.T, path string, extra int) error {
		t.Helper()
		s := storeTestMustLoad(t, path)
		share := 1 + extra/servers // Each name has one byte plus an even share of extra.
		for i := range servers {
			n := share
			if i < extra%servers {
				n++
			}
			storeTestMustSet(t, s, sizeID(i), storeTestPins(strings.Repeat("a", n), "h"))
		}
		return s.Save()
	}
	probe := storeTestPath(t)
	if err := saveWithExtra(t, probe, 0); err != nil {
		t.Fatal(err)
	}
	base := len(pins.ReadFile(t, probe))

	t.Run("exactly at the limit saves and loads", func(t *testing.T) {
		t.Parallel()
		path := storeTestPath(t)
		if err := saveWithExtra(t, path, limit-base); err != nil {
			t.Fatalf("Save() at the limit error = %v, want nil", err)
		}
		if got := len(pins.ReadFile(t, path)); got != limit {
			t.Fatalf("file size = %d, want %d", got, limit)
		}
		storeTestMustLoad(t, path)
	})

	t.Run("one byte over is refused", func(t *testing.T) {
		t.Parallel()
		path := storeTestPath(t)
		old := storeTestMustLoad(t, path)
		// The oversized save replaces this server, so the size is exact.
		storeTestMustSet(t, old, sizeID(0), storeTestPins("t", "h"))
		storeTestMustSave(t, old)
		before := pins.ReadFile(t, path)

		err := saveWithExtra(t, path, limit-base+1)
		if err == nil {
			t.Fatal("Save() error = nil, want error over the limit")
		}
		want := fmt.Sprintf("save %s: pins data is %d bytes, larger than the %d byte limit", path, limit+1, limit)
		if err.Error() != want {
			t.Errorf("Save() error = %q, want %q", err, want)
		}
		if after := pins.ReadFile(t, path); !bytes.Equal(before, after) {
			t.Error("failed Save changed the old file")
		}
		if names, want := pins.DirNames(t, filepath.Dir(path)), []string{"pins.json"}; !slices.Equal(names, want) {
			t.Errorf("dir entries = %v, want %v", names, want)
		}
	})
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
