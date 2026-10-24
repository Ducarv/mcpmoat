package pins_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
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

// storeTestPins returns a fresh pins map. Each call gives a new map, so tests
// do not share state.
func storeTestPins(pairs ...string) pins.ServerPins {
	p := pins.ServerPins{}
	for i := 0; i+1 < len(pairs); i += 2 {
		p[pairs[i]] = pairs[i+1]
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

// storeTestMustSave saves s and fails the test on an error.
func storeTestMustSave(t *testing.T, s *pins.Store) {
	t.Helper()
	if err := s.Save(); err != nil {
		t.Fatalf("Save() error = %v, want nil", err)
	}
}

// storeTestRead returns the content of path.
func storeTestRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: the test builds path under t.TempDir().
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// storeTestWantPins checks that s holds exactly want for id.
func storeTestWantPins(t *testing.T, s *pins.Store, id pins.Identity, want pins.ServerPins) {
	t.Helper()
	got, ok := s.Get(id)
	if !ok {
		t.Errorf("Get(%+v) ok = false, want true", id)
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Get(%+v) = %v, want %v", id, got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	s := storeTestMustLoad(t, path)
	s.Set(idA, storeTestPins("read", "h1", "write", "h2"))
	s.Set(idB, storeTestPins("search", "h3"))
	s.Set(idC, storeTestPins())
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
	s.Set(pins.Identity{Client: "c", Source: "s", Name: "n"}, storeTestPins("b", "2", "a", "1"))
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
        "a": "1",
        "b": "2"
      }
    }
  ]
}
`
	if got := string(storeTestRead(t, path)); got != want {
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

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("file mode = %o, want 600", got)
		}
		di, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if got := di.Mode().Perm(); got != 0o700 {
			t.Errorf("directory mode = %o, want 700", got)
		}
	}

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
		{"parent is a file", func(t *testing.T) string {
			parent := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(parent, "pins.json")
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

func TestDefaultPath(t *testing.T) {
	// No t.Parallel: t.Setenv panics in a parallel test.
	xdg := t.TempDir()
	home := t.TempDir()

	tests := []struct {
		name string
		xdg  string
		want string
	}{
		{"absolute XDG", xdg, filepath.Join(xdg, "mcpmoat", "pins.json")},
		{"relative XDG is ignored", filepath.Join("rel", "dir"), filepath.Join(home, ".config", "mcpmoat", "pins.json")},
		{"empty XDG", "", filepath.Join(home, ".config", "mcpmoat", "pins.json")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("XDG_CONFIG_HOME", tt.xdg)
			got, err := pins.DefaultPath()
			if err != nil {
				t.Fatalf("DefaultPath() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("DefaultPath() = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("relative home", func(t *testing.T) {
		t.Setenv("HOME", filepath.Join("relative", "dir"))
		t.Setenv("USERPROFILE", filepath.Join("relative", "dir"))
		t.Setenv("XDG_CONFIG_HOME", "")
		got, err := pins.DefaultPath()
		if err == nil {
			t.Fatalf("DefaultPath() = %q, error = nil, want error for a relative home", got)
		}
		if want := "the home directory for pins.json is not an absolute path"; err.Error() != want {
			t.Errorf("DefaultPath() error = %q, want %q", err, want)
		}
	})

	t.Run("unset XDG", func(t *testing.T) {
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		// t.Setenv registers the restore; Unsetenv then removes the variable.
		t.Setenv("XDG_CONFIG_HOME", "")
		if err := os.Unsetenv("XDG_CONFIG_HOME"); err != nil {
			t.Fatal(err)
		}
		got, err := pins.DefaultPath()
		if err != nil {
			t.Fatalf("DefaultPath() error = %v", err)
		}
		if want := filepath.Join(home, ".config", "mcpmoat", "pins.json"); got != want {
			t.Errorf("DefaultPath() = %q, want %q", got, want)
		}
	})
}

func TestDefaultPathEndToEnd(t *testing.T) {
	// No t.Parallel: t.Setenv panics in a parallel test.
	xdg := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", xdg)

	path, err := pins.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	s := storeTestMustLoad(t, path)
	s.Set(idA, storeTestPins("read", "h1"))
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
		id      pins.Identity
		want    pins.ServerPins // nil means the server must be absent
	}{
		{"no servers key", `{"version":1}`, idA, nil},
		{"servers null", `{"version":1,"servers":null}`, idA, nil},
		{"empty servers", `{"version":1,"servers":[]}`, idA, nil},
		{"trailing whitespace", "{\"version\":1,\"servers\":[]}\n\n  ", idA, nil},
		{
			"tools null",
			`{"version":1,"servers":[{"client":"claude-code","source":"/home/u/.claude.json","name":"alpha","tools":null}]}`,
			idA, storeTestPins(),
		},
		{
			"one server",
			`{"version":1,"servers":[{"client":"claude-code","source":"/home/u/.claude.json","name":"alpha","tools":{"t":"h"}}]}`,
			idA, storeTestPins("t", "h"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := storeTestMustLoad(t, storeTestWrite(t, tt.content))
			if tt.want == nil {
				if _, ok := s.Get(tt.id); ok {
					t.Error("Get() ok = true, want false")
				}
				return
			}
			storeTestWantPins(t, s, tt.id, tt.want)
		})
	}
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()
	const server = `{"client":"c","source":"s","name":"n","tools":{"t":"h"}}`
	tests := []struct {
		name     string
		content  string
		wantIs   error  // optional sentinel
		wantText string // optional text in the error
	}{
		{"future version", `{"version":2,"servers":[]}`, pins.ErrUnsupportedVersion, "upgrade"},
		{"future version with other shape", `{"version":2,"x":1,"` + leakToken + `":[1]}`, pins.ErrUnsupportedVersion, "upgrade"},
		{"far future version", `{"version":99,"servers":` + leakToken + `}`, nil, ""},
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
		{"truncated JSON", `{"version":1,"servers":[{"client":"c","source":"s","name":"n","tools":{"t":"` + leakToken, nil, ""},
		{"truncated mid key", `{"version":1,"serv`, nil, ""},
		{"unknown top-level field", `{"version":1,"servers":[],"` + leakToken + `":true}`, nil, ""},
		{"unknown server field", `{"version":1,"servers":[{"client":"c","source":"s","name":"n","tools":{},"` + leakToken + `":"x"}]}`, nil, ""},
		{"trailing data", `{"version":1,"servers":[]} ` + leakToken, nil, ""},
		{"second document", `{"version":1,"servers":[]}{"version":1,"servers":[]}`, nil, ""},
		{"servers wrong type", `{"version":1,"servers":{"` + leakToken + `":1}}`, nil, ""},
		{"tools wrong type", `{"version":1,"servers":[{"client":"c","source":"s","name":"n","tools":{"` + leakToken + `":5}}]}`, nil, ""},
		{"duplicate identity", `{"version":1,"servers":[` + server + `,` + server + `]}`, nil, "duplicate"},
		{
			"duplicate identity with token name",
			`{"version":1,"servers":[{"client":"c","source":"s","name":"` + leakToken + `","tools":{}},{"client":"c","source":"s","name":"` + leakToken + `","tools":{}}]}`,
			nil, "duplicate",
		},
		{"empty server name", `{"version":1,"servers":[{"client":"c","source":"s","name":"","tools":{"` + leakToken + `":"h"}}]}`, nil, "name is empty"},
		{"missing server name", `{"version":1,"servers":[{"client":"c","source":"s","tools":{"` + leakToken + `":"h"}}]}`, nil, "name is empty"},
		{"empty tool name", `{"version":1,"servers":[{"client":"c","source":"s","name":"n","tools":{"":"` + leakToken + `"}}]}`, nil, "tool name is empty"},
		{"empty hash", `{"version":1,"servers":[{"client":"c","source":"s","name":"n","tools":{"` + leakToken + `":""}}]}`, nil, "hash is empty"},
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
	if got := string(storeTestRead(t, path)); got != content {
		t.Errorf("file changed to %q", got)
	}
}

func TestLoadTooLarge(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	// One byte over the cap of 8 MiB. Zero bytes are not valid JSON, but the
	// size check comes first.
	if err := os.WriteFile(path, make([]byte, 8<<20+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pins.Load(path); !errors.Is(err, safefile.ErrTooLarge) {
		t.Errorf("Load() error = %v, want errors.Is safefile.ErrTooLarge", err)
	}
}

func TestLoadAtSizeCap(t *testing.T) {
	t.Parallel()
	// Exactly 8 MiB of valid JSON must pass the size check.
	const limit = 8 << 20
	head := `{"version":1,"servers":[]}`
	content := head + strings.Repeat(" ", limit-len(head))
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
		s.Set(id, storeTestPins("tool", fmt.Sprintf("hash-%d", i)))
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
	s.Set(idA, storeTestPins("old", "h1", "keep", "h2"))
	s.Set(idB, storeTestPins("b", "h3"))
	s.Set(idC, storeTestPins("c", "h4"))
	storeTestMustSave(t, s)

	s = storeTestMustLoad(t, path)
	s.Set(idA, storeTestPins("new", "h9"))
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
	s.Set(idA, storeTestPins("t", "h"))
	s.Set(idA, nil)
	storeTestMustSave(t, s)
	storeTestWantPins(t, storeTestMustLoad(t, path), idA, storeTestPins())
}

func TestGetReturnsCopy(t *testing.T) {
	t.Parallel()
	s := storeTestMustLoad(t, storeTestPath(t))
	s.Set(idA, storeTestPins("t", "h"))

	got, _ := s.Get(idA)
	got["t"] = "changed"
	got["extra"] = "x"
	delete(got, "nothing")

	storeTestWantPins(t, s, idA, storeTestPins("t", "h"))
}

func TestSetStoresCopy(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	s := storeTestMustLoad(t, path)
	in := storeTestPins("t", "h")
	s.Set(idA, in)
	in["t"] = "changed"
	in["extra"] = "x"

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
			s.Set(entries[i].id, entries[i].p)
		}
		storeTestMustSave(t, s)
		return storeTestRead(t, path)
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
	s.Set(idA, storeTestPins("t", "h"))
	s.Set(idB, storeTestPins())
	storeTestMustSave(t, s)
	first := storeTestRead(t, path)

	storeTestMustSave(t, storeTestMustLoad(t, path))
	if second := storeTestRead(t, path); !bytes.Equal(first, second) {
		t.Errorf("Load+Save changed the file:\n%s\nwant\n%s", second, first)
	}
}

func TestSaveRefusesInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		id   pins.Identity
		p    pins.ServerPins
		want string
	}{
		{"empty server name", pins.Identity{Client: "c", Source: "s"}, storeTestPins("t", "h"), "name is empty"},
		{"empty tool name", idA, storeTestPins("", "h"), "tool name is empty"},
		{"empty hash", idA, storeTestPins("t", ""), "hash is empty"},
		{"client not UTF-8", pins.Identity{Client: "c\xff", Source: "s", Name: "n"}, storeTestPins("t", "h"), "server identity is not valid UTF-8"},
		{"source not UTF-8", pins.Identity{Client: "c", Source: "s\xff", Name: "n"}, storeTestPins("t", "h"), "server identity is not valid UTF-8"},
		{"project path not UTF-8", pins.Identity{Client: "c", Source: "s", ProjectPath: "p\xff", Name: "n"}, storeTestPins("t", "h"), "server identity is not valid UTF-8"},
		{"server name not UTF-8", pins.Identity{Client: "c", Source: "s", Name: "n\xff"}, storeTestPins("t", "h"), "server identity is not valid UTF-8"},
		{"tool name not UTF-8", idA, storeTestPins("t\xff", "h"), "a tool name is not valid UTF-8"},
		{"hash not UTF-8", idA, storeTestPins("t", "h\xff"), "a tool hash is not valid UTF-8"},
		{"truncated multibyte tool name", idA, storeTestPins("t\xe2\x82", "h"), "a tool name is not valid UTF-8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := storeTestPath(t)
			s := storeTestMustLoad(t, path)
			s.Set(tt.id, tt.p)
			err := s.Save()
			if err == nil {
				t.Fatal("Save() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Save() error = %q, want text %q", err, tt.want)
			}
			// The bad value must not reach the error text.
			if strings.Contains(err.Error(), "\xff") || strings.Contains(err.Error(), "\xe2") {
				t.Errorf("Save() error echoes the bad value: %q", err)
			}
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("Save() wrote a file despite the error (stat error = %v)", statErr)
			}
		})
	}
}

func TestSaveRefusalKeepsOldFile(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	s := storeTestMustLoad(t, path)
	s.Set(idA, storeTestPins("t", "h"))
	storeTestMustSave(t, s)
	before := storeTestRead(t, path)

	s.Set(idB, storeTestPins("t", ""))
	if err := s.Save(); err == nil {
		t.Fatal("Save() error = nil, want error")
	}
	if after := storeTestRead(t, path); !bytes.Equal(before, after) {
		t.Errorf("failed Save changed the file:\n%s\nwant\n%s", after, before)
	}
}

func TestSaveSizeLimit(t *testing.T) {
	t.Parallel()
	const limit = 8 << 20
	// One tool with a long name: the file size grows by one byte for each name
	// byte. Measure the fixed overhead with a one-byte name.
	saveWithToolName := func(t *testing.T, path string, n int) error {
		t.Helper()
		s := storeTestMustLoad(t, path)
		s.Set(idA, storeTestPins(strings.Repeat("a", n), "h"))
		return s.Save()
	}
	probe := storeTestPath(t)
	if err := saveWithToolName(t, probe, 1); err != nil {
		t.Fatal(err)
	}
	overhead := len(storeTestRead(t, probe)) - 1

	t.Run("exactly at the limit saves and loads", func(t *testing.T) {
		t.Parallel()
		path := storeTestPath(t)
		if err := saveWithToolName(t, path, limit-overhead); err != nil {
			t.Fatalf("Save() at the limit error = %v, want nil", err)
		}
		if got := len(storeTestRead(t, path)); got != limit {
			t.Fatalf("file size = %d, want %d", got, limit)
		}
		storeTestMustLoad(t, path)
	})

	t.Run("one byte over is refused", func(t *testing.T) {
		t.Parallel()
		path := storeTestPath(t)
		old := storeTestMustLoad(t, path)
		old.Set(idA, storeTestPins("t", "h")) // The oversized save replaces idA, so the size is exact.
		storeTestMustSave(t, old)
		before := storeTestRead(t, path)

		err := saveWithToolName(t, path, limit-overhead+1)
		if err == nil {
			t.Fatal("Save() error = nil, want error over the limit")
		}
		want := fmt.Sprintf("save %s: pins data is %d bytes, larger than the %d byte limit", path, limit+1, limit)
		if err.Error() != want {
			t.Errorf("Save() error = %q, want %q", err, want)
		}
		if after := storeTestRead(t, path); !bytes.Equal(before, after) {
			t.Error("failed Save changed the old file")
		}
		entries, readErr := os.ReadDir(filepath.Dir(path))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(entries) != 1 || entries[0].Name() != "pins.json" {
			t.Errorf("directory has %d entries, want only pins.json", len(entries))
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
	s.Set(idA, storeTestPins("t", "h"))
	storeTestMustSave(t, s)

	if _, err := os.Stat(filepath.Join(realDir, "pins.json")); err != nil {
		t.Errorf("pins.json not in the real directory: %v", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("Save replaced the symlinked directory (err = %v)", err)
	}
	storeTestWantPins(t, storeTestMustLoad(t, path), idA, storeTestPins("t", "h"))
}

// TestFileHasNoSecrets checks the format, not the server config: Identity has
// no field for a secret, so a secret cannot reach the file. The test builds a
// fake server config with canary values, saves a pin for it with the identity
// fields only, and checks the JSON keys and the canary values.
func TestFileHasNoSecrets(t *testing.T) {
	t.Parallel()
	const apiKey = "sk-CANARY-SECRET"
	serverConfig := struct {
		Command string
		Args    []string
		URL     string
		Env     map[string]string
		Headers map[string]string
	}{
		Command: "npx",
		Args:    []string{"--token", discovertest.CanaryArgs},
		URL:     "https://example.test/mcp?key=" + discovertest.CanaryURL,
		Env:     map[string]string{"API_KEY": apiKey, "OTHER": discovertest.CanaryEnv},
		Headers: map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader},
	}
	_ = serverConfig // Nothing below can take it: that is the point.

	path := storeTestPath(t)
	s := storeTestMustLoad(t, path)
	s.Set(pins.Identity{Client: "claude-code", Source: "/home/u/.claude.json", Name: "alpha"},
		storeTestPins("read", "sha256:3f2a", "write", "sha256:9c1b"))
	storeTestMustSave(t, s)
	data := storeTestRead(t, path)

	secrets := append(discovertest.Canaries(), apiKey)
	discovertest.AssertNoLeak(t, "pins.json", string(data), secrets...)

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
	for name, h := range tools {
		if _, isString := h.(string); !isString {
			t.Errorf("tool %q value = %T, want string hash", name, h)
		}
	}
}

func FuzzLoad(f *testing.F) {
	const server = `{"client":"c","source":"s","project_path":"","name":"n","tools":{"t":"h"}}`
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
		`{"version":1,"servers":[{"client":"c","source":"s","name":"","tools":{}}]}`,
		`{"version":1,"servers":[{"client":"c","source":"s","name":"n","tools":{"":"h"}}]}`,
		`{"version":1,"servers":[{"client":"c","source":"s","name":"n","tools":{"t":""}}]}`,
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

		dst := filepath.Join(dir, "sub", "copy.json")
		saved, err := pins.Load(dst)
		if err != nil {
			t.Fatal(err)
		}
		for _, srv := range doc.Servers {
			id := pins.Identity{Client: srv.Client, Source: srv.Source, ProjectPath: srv.ProjectPath, Name: srv.Name}
			p, ok := s.Get(id)
			if !ok {
				t.Fatalf("Get(%+v) ok = false for an identity in the file", id)
			}
			saved.Set(id, p)
		}
		if err := saved.Save(); err != nil {
			t.Fatalf("Save() of a loaded store: %v", err)
		}
		again, err := pins.Load(dst)
		if err != nil {
			t.Fatalf("Load() of a saved store: %v", err)
		}
		for _, srv := range doc.Servers {
			id := pins.Identity{Client: srv.Client, Source: srv.Source, ProjectPath: srv.ProjectPath, Name: srv.Name}
			want, _ := s.Get(id)
			got, ok := again.Get(id)
			if !ok || !reflect.DeepEqual(got, want) {
				t.Fatalf("Get(%+v) after the round trip = %v, %v; want %v", id, got, ok, want)
			}
		}

		// Save is a fixed point: Load then Save gives the same bytes.
		first := storeTestRead(t, dst)
		if err := again.Save(); err != nil {
			t.Fatal(err)
		}
		second := storeTestRead(t, dst)
		if !bytes.Equal(first, second) {
			t.Fatalf("Save is not stable:\n%s\nvs\n%s", first, second)
		}
	})
}
