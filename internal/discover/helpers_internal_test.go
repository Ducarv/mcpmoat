package discover

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// serverView is a test-only view of a Server with the secret values revealed.
// Server is not comparable with == (Secret and URL are not), so tests compare
// serverView values with reflect.DeepEqual and get readable want tables.
//
// serverView holds real secret values. Use it only to compare against
// fixtures. Never print it for a secrets fixture; print Server instead, which
// masks the values.
type serverView struct {
	Name        string
	Client      Client
	Scope       Scope
	ProjectPath string
	Source      string
	Transport   Transport
	Command     string
	Args        []string
	Env         map[string]string
	Headers     map[string]string
	URL         string
}

// viewOf returns the view of s with all secret values revealed. A nil or
// empty Env or Headers gives a nil map, so a want value can leave them unset.
func viewOf(s Server) serverView {
	return serverView{
		Name:        s.Name,
		Client:      s.Client,
		Scope:       s.Scope,
		ProjectPath: s.ProjectPath,
		Source:      s.Source,
		Transport:   s.Transport,
		Command:     s.Command,
		Args:        s.Args.Values(),
		Env:         reveal(s.Env),
		Headers:     reveal(s.Headers),
		URL:         s.URL.Reveal(),
	}
}

// viewsOf returns viewOf for each server, in the same order.
func viewsOf(ss []Server) []serverView {
	if len(ss) == 0 {
		return nil
	}
	views := make([]serverView, 0, len(ss))
	for _, s := range ss {
		views = append(views, viewOf(s))
	}
	return views
}

// reveal returns the plain values of m, or nil if m is empty. It walks the
// keys with Keys, so the result does not depend on map iteration order.
func reveal(m SecretMap) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for _, k := range m.Keys() {
		out[k] = m[k].Reveal()
	}
	return out
}

// fixtureDir returns the absolute path of testdata/discover/<parts...> in the
// repository. Tests run in internal/discover, so the repository root is ../..
// It fails the test if the directory does not exist.
func fixtureDir(t testing.TB, parts ...string) string {
	t.Helper()
	rel := filepath.Join(append([]string{"..", "..", "testdata", "discover"}, parts...)...)
	dir, err := filepath.Abs(rel)
	if err != nil {
		t.Fatalf("absolute path of fixture %s: %v", rel, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("fixture %s: %v", dir, err)
	}
	if !info.IsDir() {
		t.Fatalf("fixture %s is not a directory", dir)
	}
	return dir
}

// copyFixture copies the fixture testdata/discover/<parts...> into a temporary
// directory and returns the copies of its home and work directories. Readers
// run on the copies, never on the repository's testdata.
func copyFixture(t testing.TB, parts ...string) (home, work string) {
	t.Helper()
	return discovertest.CopyFixture(t, fixtureDir(t, parts...))
}

// assertNoLeakErrors fails the test if the text of any error in errs holds a
// canary value. It checks Error and the fmt verbs %v, %+v and %#v.
func assertNoLeakErrors(t testing.TB, errs []*FileError) {
	t.Helper()
	for i, e := range errs {
		discovertest.AssertNoLeak(t, fmt.Sprintf("errs[%d].Error()", i), e.Error())
		discovertest.AssertNoLeak(t, fmt.Sprintf("errs[%d] formatted", i), fmt.Sprintf("%v %+v %#v", e, e, e))
	}
}

// assertNoLeakServers fails the test if the formatted or JSON-encoded form of
// servers holds a canary value.
func assertNoLeakServers(t testing.TB, servers []Server) {
	t.Helper()
	discovertest.AssertNoLeak(t, "servers formatted", fmt.Sprintf("%v %+v %#v", servers, servers, servers))
	data, err := json.Marshal(servers)
	if err != nil {
		t.Fatalf("json.Marshal(servers): %v", err)
	}
	discovertest.AssertNoLeak(t, "servers JSON", string(data))
}

// assertFixtureHasCanaries fails the test unless the files at paths together
// hold every canary value at least once. A leak test on a secrets fixture only
// means something if the fixture really holds the canaries; this check proves
// it. The files are repository testdata, not user config.
func assertFixtureHasCanaries(t testing.TB, paths ...string) {
	t.Helper()
	var all strings.Builder
	for _, p := range paths {
		data, err := os.ReadFile(p) //nolint:gosec // G304: test reads a fixture path chosen by the test
		if err != nil {
			t.Fatalf("read fixture file: %v", err)
		}
		all.Write(data)
	}
	content := all.String()
	for _, canary := range discovertest.Canaries() {
		if !strings.Contains(content, canary) {
			t.Fatalf("fixture files %v do not hold canary %q", paths, canary)
		}
	}
}

// serverNames returns the server names in ss, in order.
func serverNames(ss []Server) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.Name)
	}
	return out
}

// TestHelpers checks the helpers in this file, so a wrong helper does not hide
// a reader bug.
func TestHelpers(t *testing.T) {
	t.Parallel()

	t.Run("viewOf reveals values and keeps nil maps nil", func(t *testing.T) {
		t.Parallel()
		s := Server{
			Name:      "api",
			Client:    ClientCursor,
			Scope:     ScopeProject,
			Transport: TransportHTTP,
			Args:      NewArgs([]string{"a"}),
			URL:       NewURL("https://example.com/mcp"),
			Headers:   SecretMap{"X-Key": NewSecret("v1")},
		}
		want := serverView{
			Name:      "api",
			Client:    ClientCursor,
			Scope:     ScopeProject,
			Transport: TransportHTTP,
			Args:      []string{"a"},
			URL:       "https://example.com/mcp",
			Headers:   map[string]string{"X-Key": "v1"},
		}
		got := viewOf(s)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("viewOf() = %+v, want %+v", got, want)
		}
		if got.Env != nil {
			t.Errorf("viewOf().Env = %v, want nil", got.Env)
		}
	})

	t.Run("viewsOf and serverNames keep order", func(t *testing.T) {
		t.Parallel()
		ss := []Server{{Name: "b"}, {Name: "a"}}
		if got := serverNames(ss); !reflect.DeepEqual(got, []string{"b", "a"}) {
			t.Errorf("serverNames() = %v, want [b a]", got)
		}
		views := viewsOf(ss)
		if len(views) != 2 || views[0].Name != "b" || views[1].Name != "a" {
			t.Errorf("viewsOf() names = %v, want [b a]", views)
		}
		if got := viewsOf(nil); got != nil {
			t.Errorf("viewsOf(nil) = %v, want nil", got)
		}
	})

	t.Run("fixtureDir and canaries in the secrets fixture", func(t *testing.T) {
		t.Parallel()
		valid := fixtureDir(t, "claude-code", "valid")
		if !filepath.IsAbs(valid) {
			t.Errorf("fixtureDir() = %q, want an absolute path", valid)
		}
		secrets := fixtureDir(t, "claude-code", "secrets")
		assertFixtureHasCanaries(t,
			filepath.Join(secrets, "home", ".claude.json"),
			filepath.Join(secrets, "work", ".mcp.json"),
		)
	})

	t.Run("no leak assertions pass on masked values", func(t *testing.T) {
		t.Parallel()
		servers := []Server{{
			Name:    "api",
			Env:     SecretMap{"K": NewSecret(discovertest.CanaryEnv)},
			Headers: SecretMap{"H": NewSecret(discovertest.CanaryHeader)},
			URL:     NewURL("https://u:" + discovertest.CanaryURL + "@example.com/mcp"),
		}}
		assertNoLeakServers(t, servers)
		assertNoLeakErrors(t, []*FileError{{Path: "/p", Server: "api", Reason: reasonBadEntry}})
	})

	t.Run("copyFixture returns existing directories", func(t *testing.T) {
		t.Parallel()
		home, work := copyFixture(t, "claude-code", "valid")
		for _, dir := range []string{home, work} {
			if info, err := os.Stat(dir); err != nil || !info.IsDir() {
				t.Errorf("copyFixture() directory %s: stat error %v", dir, err)
			}
		}
	})
}
