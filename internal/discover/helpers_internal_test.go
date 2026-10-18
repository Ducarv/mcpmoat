package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
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
	Untrusted   bool
	Transport   Transport
	Command     string
	Args        []string
	Dir         string
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
		Untrusted:   s.Untrusted,
		Transport:   s.Transport,
		Command:     s.Command,
		Args:        s.Args.Values(),
		Dir:         s.Dir,
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
// The fixtures live in the root testdata/ and not in internal/discover/testdata,
// because the project layout (see CLAUDE.md) keeps all fixtures there: the
// fixture MCP servers and the e2e tests use the same directory. It fails the
// test if the directory does not exist.
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

// assertFixtureFilesHaveCanaries is assertFixtureHasCanaries for the files
// rel (with forward slashes) below the fixture directory dir.
func assertFixtureFilesHaveCanaries(t testing.TB, dir string, rel ...string) {
	t.Helper()
	paths := make([]string, 0, len(rel))
	for _, r := range rel {
		paths = append(paths, filepath.Join(dir, filepath.FromSlash(r)))
	}
	assertFixtureHasCanaries(t, paths...)
}

// checkServers compares the views of got with want. A nil and an empty list
// are equal. With hideValues set, a mismatch prints the server names only,
// because the views can hold secret values (canaries).
func checkServers(t testing.TB, label string, got []Server, want []serverView, hideValues bool) {
	t.Helper()
	gotViews := viewsOf(got)
	if len(gotViews) == 0 && len(want) == 0 {
		return
	}
	if reflect.DeepEqual(gotViews, want) {
		return
	}
	if hideValues {
		t.Errorf("%s: servers differ from the want list (values hidden); got names %v", label, serverNames(got))
		return
	}
	t.Errorf("%s: servers =\n got  %+v\n want %+v", label, gotViews, want)
}

// errWant is the part of a *FileError that a test checks. Path is not here:
// checkFileErrors compares it with the path that the reader got.
type errWant struct {
	ProjectPath string
	Server      string
	Reason      string
	// Line is the exact 1-based line. 0 means that the error has no position.
	// Col must be set exactly when Line is set.
	Line int
	// HasErr is true when the error must wrap an OS or context error in Err.
	// Parse problems have no Err.
	HasErr bool
}

// checkFileErrors compares got with want, in order. Each error must name
// path and match its errWant. A nil error in got fails the test.
func checkFileErrors(t testing.TB, path string, got []*FileError, want []errWant) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d errors, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		e := got[i]
		if e == nil {
			t.Fatalf("errors[%d] = nil, want reason %q", i, w.Reason)
		}
		if e.Path != path {
			t.Errorf("errors[%d].Path = %q, want %q", i, e.Path, path)
		}
		if e.ProjectPath != w.ProjectPath {
			t.Errorf("errors[%d].ProjectPath = %q, want %q", i, e.ProjectPath, w.ProjectPath)
		}
		if e.Server != w.Server {
			t.Errorf("errors[%d].Server = %q, want %q", i, e.Server, w.Server)
		}
		if e.Reason != w.Reason {
			t.Errorf("errors[%d].Reason = %q, want %q", i, e.Reason, w.Reason)
		}
		if e.Line != w.Line {
			t.Errorf("errors[%d].Line = %d, want %d", i, e.Line, w.Line)
		}
		if (e.Line > 0) != (e.Col > 0) {
			t.Errorf("errors[%d] has Line %d and Col %d, want both set or both zero", i, e.Line, e.Col)
		}
		if (e.Err != nil) != w.HasErr {
			t.Errorf("errors[%d].Err = %v, want an Err: %v", i, e.Err, w.HasErr)
		}
	}
}

// writeFile writes data to dir/rel and returns the path. rel uses forward
// slashes; the parent directories are created with mode 0o700 and the file
// with mode 0o600.
func writeFile(t testing.TB, dir, rel string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// symlinkTo creates a symlink at dir/rel (rel with forward slashes) that
// points to target, and returns the path of the link. It creates the parent
// directories of the link with mode 0o700. target is stored as given, so a
// relative target is relative to the directory of the link. It fails the test
// if the link cannot be created.
func symlinkTo(t testing.TB, target, dir, rel string) string {
	t.Helper()
	link := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatalf("create directory for %s: %v", link, err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s: %v", link, err)
	}
	return link
}

// makeDir creates the directory dir/name and returns its path.
func makeDir(t testing.TB, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("create directory %s: %v", path, err)
	}
	return path
}

// skipOnWindows skips the test on Windows. The tests that call it use
// symlinks, FIFOs, file modes or path errors that behave differently there.
func skipOnWindows(t testing.TB) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("not supported on windows")
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

// allReasons lists every reason constant of fileerror.go. Keep it in sync
// with the constants: TestAllReasonsInSync fails when a constant is missing
// here. It is an array, not a slice, so no test can change it. Tests use it
// to check that a FileError has a known reason.
var allReasons = [...]reason{
	reasonCannotRead,
	reasonNotRegular,
	reasonTooLarge,
	reasonOutsideProject,
	reasonInvalidJSON,
	reasonInvalidTOML,
	reasonBadShape,
	reasonBadServers,
	reasonBadEntry,
	reasonUnknownTransport,
	reasonNoCommandOrURL,
	reasonStdioNoCommand,
	reasonRemoteNoURL,
	reasonCanceled,
	reasonTooDeep,
	reasonKeyTooLong,
	reasonTooManyServers,
	reasonAmbiguousKey,
	reasonEmptyName,
	reasonEmptyProject,
	reasonBadString,
	reasonNotFound,
	reasonUnknownFormat,
}

// codexConfigRel is the path of the Codex config file inside a home
// directory, with forward slashes.
const codexConfigRel = ".codex/config.toml"

// keyParts returns a key with n parts separated by dots, for example "a.a.a"
// for n = 3.
func keyParts(n int) string {
	return strings.TrimSuffix(strings.Repeat("a.", n), ".")
}

// jsonFixtureCase is one fixture test of a JSON reader (ReadClaudeCode or
// ReadCursor). The fixture directory testdata/discover/<client>/<name> has a
// home directory with the global file and a work directory with the project
// file.
//
// The want servers are static. runJSONFixtureCases fills in Client, Source,
// Scope, ProjectPath and Untrusted:
//   - a global server (home) gets ScopeGlobal, or ScopeProject when the want
//     sets ProjectPath (a projects.<path> server of ~/.claude.json), and
//     Untrusted false;
//   - a project server (work) gets ScopeProject, the work directory as
//     ProjectPath, and Untrusted true.
type jsonFixtureCase struct {
	name string
	// hideValues is set for fixtures that hold canaries or are malformed
	// next to a canary. On a mismatch the test then prints only the server
	// names, never the values.
	hideValues bool
	// canaryFiles are the fixture files, relative to the fixture directory
	// and with forward slashes, that must hold every canary. The leak checks
	// only mean something if the input holds the canaries.
	canaryFiles []string

	home, work         []serverView
	homeErrs, workErrs []errWant
}

// jsonReader is the signature of ReadClaudeCode and ReadCursor.
type jsonReader func(ctx context.Context, path string, scope Scope, projectPath string) Result

// jsonFixtureFiles names the config files of one client inside the home and
// work directories of a fixture, with forward slashes.
type jsonFixtureFiles struct {
	client  Client
	fixture string // the directory under testdata/discover
	home    string
	work    string
}

// runJSONFixtureCases runs every case with read, on a copy of the fixture.
// It checks the servers, the errors, Untrusted on every error, and that no
// result holds a canary.
func runJSONFixtureCases(t *testing.T, files jsonFixtureFiles, read jsonReader, cases []jsonFixtureCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if len(tc.canaryFiles) > 0 {
				assertFixtureFilesHaveCanaries(t, fixtureDir(t, files.fixture, tc.name), tc.canaryFiles...)
			}
			home, work := copyFixture(t, files.fixture, tc.name)
			homePath := filepath.Join(home, filepath.FromSlash(files.home))
			workPath := filepath.Join(work, filepath.FromSlash(files.work))

			global := read(ctx, homePath, ScopeGlobal, "")
			project := read(ctx, workPath, ScopeProject, work)

			checkServers(t, "global", global.Servers, fixtureWants(tc.home, files.client, homePath, ""), tc.hideValues)
			checkServers(t, "project", project.Servers, fixtureWants(tc.work, files.client, workPath, work), tc.hideValues)
			checkFileErrors(t, homePath, global.Errors, tc.homeErrs)
			checkFileErrors(t, workPath, project.Errors, tc.workErrs)
			checkErrorsUntrusted(t, global.Errors, false)
			checkErrorsUntrusted(t, project.Errors, true)

			// No result may hold a canary, in any form.
			for _, res := range []Result{global, project} {
				assertNoLeakServers(t, res.Servers)
				assertNoLeakErrors(t, res.Errors)
			}
		})
	}
}

// fixtureWants returns copies of wants with Client, Source, Scope, ProjectPath
// and Untrusted filled in (see jsonFixtureCase). work is "" for the global
// file and the work directory for the project file.
func fixtureWants(wants []serverView, client Client, source, work string) []serverView {
	out := make([]serverView, 0, len(wants))
	for _, w := range wants {
		w.Client = client
		w.Source = source
		switch {
		case work != "":
			w.Scope = ScopeProject
			w.ProjectPath = work
			w.Untrusted = true
		case w.ProjectPath != "":
			w.Scope = ScopeProject
		default:
			w.Scope = ScopeGlobal
		}
		out = append(out, w)
	}
	return out
}

// checkServersUntrusted fails the test if a server in servers has another
// Untrusted value than want.
func checkServersUntrusted(t testing.TB, servers []Server, want bool) {
	t.Helper()
	for _, s := range servers {
		if s.Untrusted != want {
			t.Errorf("server %q: Untrusted = %v, want %v", s.Name, s.Untrusted, want)
		}
	}
}

// checkErrorsUntrusted fails the test if an error in errs has another
// Untrusted value than want.
func checkErrorsUntrusted(t testing.TB, errs []*FileError, want bool) {
	t.Helper()
	for i, e := range errs {
		if e.Untrusted != want {
			t.Errorf("errors[%d] (%s): Untrusted = %v, want %v", i, e.Reason, e.Untrusted, want)
		}
	}
}

// recordTB is a testing.TB that records a failure instead of failing the
// real test. Fatalf ends the goroutine, as testing.T does. Only Helper,
// Errorf and Fatalf are implemented; the embedded nil TB panics on any other
// call.
type recordTB struct {
	testing.TB
	failed bool
}

func (r *recordTB) Helper()               {}
func (r *recordTB) Errorf(string, ...any) { r.failed = true }
func (r *recordTB) Fatalf(string, ...any) {
	r.failed = true
	runtime.Goexit()
}

// helperFails runs check with a recordTB in a new goroutine and reports
// whether check failed.
func helperFails(check func(tb testing.TB)) bool {
	r := &recordTB{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		check(r)
	}()
	<-done
	return r.failed
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
			Untrusted: true,
			Transport: TransportHTTP,
			Args:      NewArgs([]string{"a"}),
			Dir:       "/work/dir",
			URL:       NewURL("https://example.com/mcp"),
			Headers:   SecretMap{"X-Key": NewSecret("v1")},
		}
		want := serverView{
			Name:      "api",
			Client:    ClientCursor,
			Scope:     ScopeProject,
			Untrusted: true,
			Transport: TransportHTTP,
			Args:      []string{"a"},
			Dir:       "/work/dir",
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
		if got := serverNames(ss); !slices.Equal(got, []string{"b", "a"}) {
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
		assertFixtureFilesHaveCanaries(t, secrets, "home/.claude.json", "work/.mcp.json")
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
		assertNoLeakErrors(t, []*FileError{newFileError("/p", reasonBadEntry).forServer("api")})
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

	t.Run("checkFileErrors fails on each mismatch", func(t *testing.T) {
		t.Parallel()
		const path = "/home/u/.claude.json"
		// good returns an error that matches want exactly. Offset 4 of data is
		// line 2, column 3.
		data := []byte("{\n  x")
		good := func() *FileError {
			return newFileError(path, reasonBadEntry).inProject("/a").forServer("s").atOffset(data, 4)
		}
		want := []errWant{{ProjectPath: "/a", Server: "s", Reason: reasonBadEntry, Line: 2}}

		tests := []struct {
			name     string
			path     string
			got      func() []*FileError
			want     []errWant
			wantFail bool
		}{
			{name: "match", path: path, got: func() []*FileError { return []*FileError{good()} }, want: want},
			{name: "both empty", path: path, got: func() []*FileError { return nil }},
			{
				name: "Err set when HasErr",
				path: path,
				got: func() []*FileError {
					return []*FileError{canceledError(path, context.Canceled)}
				},
				want: []errWant{{Reason: reasonCanceled, HasErr: true}},
			},
			{name: "other path", path: "/other", got: func() []*FileError { return []*FileError{good()} }, want: want, wantFail: true},
			{name: "fewer errors", path: path, got: func() []*FileError { return nil }, want: want, wantFail: true},
			{name: "more errors", path: path, got: func() []*FileError { return []*FileError{good(), good()} }, want: want, wantFail: true},
			{name: "nil error", path: path, got: func() []*FileError { return []*FileError{nil} }, want: want, wantFail: true},
			{name: "ProjectPath", path: path, got: mutate(good, func(e *FileError) { e.ProjectPath = "/b" }), want: want, wantFail: true},
			{name: "Server", path: path, got: mutate(good, func(e *FileError) { e.Server = "t" }), want: want, wantFail: true},
			{name: "Reason", path: path, got: mutate(good, func(e *FileError) { e.Reason = reasonBadShape }), want: want, wantFail: true},
			{name: "Line", path: path, got: mutate(good, func(e *FileError) { e.Line = 5 }), want: want, wantFail: true},
			{name: "Line without Col", path: path, got: mutate(good, func(e *FileError) { e.Col = 0 }), want: want, wantFail: true},
			{
				name:     "Col without Line",
				path:     path,
				got:      mutate(good, func(e *FileError) { e.Line = 0 }),
				want:     []errWant{{ProjectPath: "/a", Server: "s", Reason: reasonBadEntry}},
				wantFail: true,
			},
			{name: "Err set without HasErr", path: path, got: mutate(good, func(e *FileError) { e.Err = context.Canceled }), want: want, wantFail: true},
			{
				name:     "HasErr without Err",
				path:     path,
				got:      func() []*FileError { return []*FileError{good()} },
				want:     []errWant{{ProjectPath: "/a", Server: "s", Reason: reasonBadEntry, Line: 2, HasErr: true}},
				wantFail: true,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				failed := helperFails(func(tb testing.TB) { checkFileErrors(tb, tt.path, tt.got(), tt.want) })
				if failed != tt.wantFail {
					t.Errorf("checkFileErrors failed = %v, want %v", failed, tt.wantFail)
				}
			})
		}
	})

	t.Run("checkServers fails on a mismatch", func(t *testing.T) {
		t.Parallel()
		got := []Server{{Name: "a", Command: "x", Dir: "/d"}}
		tests := []struct {
			name       string
			got        []Server
			want       []serverView
			hideValues bool
			wantFail   bool
		}{
			{name: "match", got: got, want: []serverView{{Name: "a", Command: "x", Dir: "/d"}}},
			{name: "nil and empty are equal", got: nil, want: []serverView{}},
			{name: "other Dir", got: got, want: []serverView{{Name: "a", Command: "x"}}, wantFail: true},
			{name: "other Untrusted", got: got, want: []serverView{{Name: "a", Command: "x", Dir: "/d", Untrusted: true}}, wantFail: true},
			{name: "other Command", got: got, want: []serverView{{Name: "a", Command: "y", Dir: "/d"}}, wantFail: true},
			{name: "missing server", got: got, want: nil, wantFail: true},
			{name: "hidden values still fail", got: got, want: nil, hideValues: true, wantFail: true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				failed := helperFails(func(tb testing.TB) { checkServers(tb, "label", tt.got, tt.want, tt.hideValues) })
				if failed != tt.wantFail {
					t.Errorf("checkServers failed = %v, want %v", failed, tt.wantFail)
				}
			})
		}
	})

	t.Run("writeFile creates parents and writes the data", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := writeFile(t, dir, "a/b/c.json", []byte("{}"))
		if want := filepath.Join(dir, "a", "b", "c.json"); path != want {
			t.Errorf("writeFile() = %q, want %q", path, want)
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: test reads the file it just wrote under t.TempDir()
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if string(data) != "{}" {
			t.Errorf("file content = %q, want %q", data, "{}")
		}
		if runtime.GOOS == "windows" {
			return // Windows has no Unix permission bits.
		}
		for p, want := range map[string]os.FileMode{path: 0o600, filepath.Join(dir, "a", "b"): 0o700} {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatalf("stat %s: %v", p, err)
			}
			if got := info.Mode().Perm(); got != want {
				t.Errorf("mode of %s = %v, want %v", p, got, want)
			}
		}
	})
}

// mutate returns a function that gives a one-error list: the error from good
// with change applied.
func mutate(good func() *FileError, change func(*FileError)) func() []*FileError {
	return func() []*FileError {
		e := good()
		change(e)
		return []*FileError{e}
	}
}
