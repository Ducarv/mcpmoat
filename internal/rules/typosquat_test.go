package rules

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// npxServer builds a stdio server that runs pkg with "npx -y".
func npxServer(name, pkg string) discover.Server {
	s := stdioServer("npx", "-y", pkg)
	s.Name = name
	return s
}

func TestOSADistance(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "equal", a: "filesystem", b: "filesystem", want: 0},
		{name: "both empty", a: "", b: "", want: 0},
		{name: "empty vs abc", a: "", b: "abc", want: 3},
		{name: "abc vs empty", a: "abc", b: "", want: 3},
		{name: "substitution", a: "github", b: "githab", want: 1},
		{name: "insertion", a: "github", b: "githubb", want: 1},
		{name: "deletion", a: "github", b: "githb", want: 1},
		{name: "transposition", a: "ab", b: "ba", want: 1},
		{name: "transposition in word", a: "filesytem", b: "filesystem", want: 1},
		{name: "two substitutions", a: "abcd", b: "axcy", want: 2},
		// OSA never edits a substring twice, so "ca" -> "abc" costs 3.
		// Full Damerau-Levenshtein would give 2.
		{name: "OSA property", a: "ca", b: "abc", want: 3},
		{name: "unicode rune is one edit", a: "café", b: "cafe", want: 1},
		{name: "unicode transposition", a: "éa", b: "aé", want: 1},
		{name: "unicode vs ascii equal length", a: "日本語", b: "日本人", want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := osaDistance(tt.a, tt.b); got != tt.want {
				t.Errorf("osaDistance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
			if got := osaDistance(tt.b, tt.a); got != tt.want {
				t.Errorf("osaDistance(%q, %q) = %d, want %d (symmetry)", tt.b, tt.a, got, tt.want)
			}
		})
	}
}

// errReader fails on the first read.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestParsePopular(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "empty", input: "", want: nil},
		{name: "only comments and blanks", input: "# a\n\n   \n# b\n", want: nil},
		{name: "names", input: "one-name\ntwo-name\n", want: []string{"one-name", "two-name"}},
		{name: "comment and blank lines skipped", input: "# c\n\nfoo-bar\n\n# d\nbaz-qux\n", want: []string{"foo-bar", "baz-qux"}},
		{name: "surrounding space trimmed", input: "  \tfoo-bar \t\n", want: []string{"foo-bar"}},
		{name: "indented comment skipped", input: "   # not a name\nfoo-bar\n", want: []string{"foo-bar"}},
		{name: "uppercase lowercased", input: "@Scope/Server-Foo\n", want: []string{"@scope/server-foo"}},
		{name: "CRLF line endings", input: "foo-bar\r\nbaz-qux\r\n", want: []string{"foo-bar", "baz-qux"}},
		{name: "no trailing newline", input: "foo-bar", want: []string{"foo-bar"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParsePopular(strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("ParsePopular() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePopular() = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("read error is wrapped", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("boom")
		got, err := ParsePopular(errReader{err: boom})
		if !errors.Is(err, boom) {
			t.Fatalf("ParsePopular() error = %v, want it to wrap %v", err, boom)
		}
		if got != nil {
			t.Errorf("ParsePopular() names = %q, want nil on error", got)
		}
	})

	t.Run("line too long is an error", func(t *testing.T) {
		t.Parallel()
		// bufio.Scanner refuses a token above 64 KiB; the error must surface.
		_, err := ParsePopular(strings.NewReader(strings.Repeat("a", 70*1024)))
		if err == nil {
			t.Fatal("ParsePopular() error = nil, want error for an over-long line")
		}
	})
}

// readPopular parses the embedded popular list once for all tests.
var readPopular = sync.OnceValues(func() ([]string, error) {
	return builtinPopular()
})

// loadPopular returns the real popular list, or stops the test when it
// cannot be read.
func loadPopular(t *testing.T) []string {
	t.Helper()
	names, err := readPopular()
	if err != nil {
		t.Fatalf("load popular list: %v", err)
	}
	return names
}

func TestPopularListFile(t *testing.T) {
	t.Parallel()
	names := loadPopular(t)

	if len(names) < 30 {
		t.Errorf("popular list has %d names, want at least 30", len(names))
	}
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if seen[n] {
			t.Errorf("duplicate name %q", n)
		}
		seen[n] = true
		if n != strings.ToLower(n) {
			t.Errorf("name %q is not lowercase", n)
		}
		if n != strings.TrimSpace(n) {
			t.Errorf("name %q has surrounding space", n)
		}
		if utf8.RuneCountInString(n) < minTyposquatNameLen {
			t.Errorf("name %q is shorter than %d runes", n, minTyposquatNameLen)
		}
		if strings.ContainsAny(n, " \t") {
			t.Errorf("name %q contains a space", n)
		}
	}

	// An exact popular name is the legitimate server: it must never be flagged,
	// as a server name or as a package of any runner.
	ts := NewTyposquat(names)
	for _, n := range names {
		servers := map[string]discover.Server{
			"name":   {Name: n},
			"npx":    {Name: "x-local", Command: "npx", Args: discover.NewArgs([]string{"-y", n})},
			"uvx":    {Name: "x-local", Command: "uvx", Args: discover.NewArgs([]string{n})},
			"docker": {Name: "x-local", Command: "docker", Args: discover.NewArgs([]string{"run", "-i", "--rm", n})},
		}
		for kind, s := range servers {
			if got := ts.Check(s); len(got) != 0 {
				t.Errorf("popular name %q as %s gave findings %+v, want none", n, kind, got)
			}
		}
	}
}

func TestTyposquatCheck(t *testing.T) {
	t.Parallel()
	ts := NewTyposquat(loadPopular(t))

	type want struct{ field, related string }

	tests := []struct {
		name   string
		server discover.Server
		want   []want
	}{
		// Positives.
		{
			name:   "npx scoped package, transposed letters",
			server: npxServer("files", "@modelcontextprotocol/server-filesytem"),
			want:   []want{{FieldArgs, "@modelcontextprotocol/server-filesystem"}},
		},
		{
			name:   "npx scoped package githbu",
			server: npxServer("gh", "@modelcontextprotocol/server-githbu"),
			want:   []want{{FieldArgs, "@modelcontextprotocol/server-github"}},
		},
		{
			name:   "npx package with version",
			server: npxServer("files", "@modelcontextprotocol/server-filesytem@1.2.3"),
			want:   []want{{FieldArgs, "@modelcontextprotocol/server-filesystem"}},
		},
		{
			name:   "server name typo",
			server: discover.Server{Name: "mcp-server-fecth"},
			want:   []want{{FieldName, "mcp-server-fetch"}},
		},
		{
			name:   "server name matches bare name of a scoped package",
			server: discover.Server{Name: "server-filesytem"},
			want:   []want{{FieldName, "@modelcontextprotocol/server-filesystem"}},
		},
		{
			name:   "uvx package with pinned version",
			server: discover.Server{Name: "fetcher", Command: "uvx", Args: discover.NewArgs([]string{"mcp-server-fethc==1.0"})},
			want:   []want{{FieldArgs, "mcp-server-fetch"}},
		},
		{
			name:   "uppercase name is compared in lowercase",
			server: discover.Server{Name: "MCP-Server-Fecth"},
			want:   []want{{FieldName, "mcp-server-fetch"}},
		},
		{
			name:   "server name close to the flat form of a scoped popular name",
			server: discover.Server{Name: "playwrigth-mcp"},
			want:   []want{{FieldName, "@playwright/mcp"}},
		},
		{
			// PyPI reads "mcp_server_fetcj" as "mcp-server-fetcj" (PEP 503).
			name:   "uvx package with PyPI separators, one edit off",
			server: stdioServer("uvx", "mcp_server_fetcj"),
			want:   []want{{FieldArgs, "mcp-server-fetch"}},
		},
		{
			name:   "docker image with the Docker Hub prefix, one edit off",
			server: stdioServer("docker", "run", "-i", "docker.io/mcp/fetcj"),
			want:   []want{{FieldArgs, "mcp/fetch"}},
		},
		{
			name:   "docker image typo",
			server: discover.Server{Name: "gh", Command: "docker", Args: discover.NewArgs([]string{"run", "-i", "--rm", "ghcr.io/github/github-mcp-sever"})},
			want:   []want{{FieldArgs, "ghcr.io/github/github-mcp-server"}},
		},
		{
			name:   "server name and package both typo give two findings",
			server: npxServer("mcp-server-fecth", "mcp-server-fethc"),
			want:   []want{{FieldName, "mcp-server-fetch"}, {FieldArgs, "mcp-server-fetch"}},
		},
		{
			// Full and bare form of the package are both close to the same
			// popular entry: still one finding for the package.
			name:   "package full and bare both close give one finding",
			server: npxServer("unrelated-local-thing", "@modelcontextprotocol/server-filesytem"),
			want:   []want{{FieldArgs, "@modelcontextprotocol/server-filesystem"}},
		},
		{
			name:   "scope squatting: other scope, same bare name",
			server: npxServer("files", "@evil/server-filesystem"),
			want:   []want{{FieldArgs, "@modelcontextprotocol/server-filesystem"}},
		},
		{
			name:   "scope squatting: scope dropped",
			server: npxServer("files", "server-filesystem"),
			want:   []want{{FieldArgs, "@modelcontextprotocol/server-filesystem"}},
		},
		{
			name:   "scope squatting with version",
			server: npxServer("gh", "@evil/server-github@1.0.0"),
			want:   []want{{FieldArgs, "@modelcontextprotocol/server-github"}},
		},
		{
			name:   "scope squatting on a vendor package",
			server: npxServer("pw", "@evil/playwright-mcp-server"),
			want:   []want{{FieldArgs, "@executeautomation/playwright-mcp-server"}},
		},
		{
			name:   "scope squatting on an unscoped popular name",
			server: npxServer("remote", "@evil/mcp-remote"),
			want:   []want{{FieldArgs, "mcp-remote"}},
		},
		{
			name:   "scope squatting on an unscoped popular name, with version",
			server: npxServer("fc", "@evil/firecrawl-mcp@1.0.0"),
			want:   []want{{FieldArgs, "firecrawl-mcp"}},
		},
		{
			name:   "scope squatting on an unscoped popular name, scope with xox prefix",
			server: npxServer("remote", "@xoxo/mcp-remote"),
			want:   []want{{FieldArgs, "mcp-remote"}},
		},
		{
			// The list mixes registries: a scoped npm package with the name
			// of a PyPI entry also fires.
			name:   "scope squatting on a PyPI popular name",
			server: npxServer("fetcher", "@evil/mcp-server-fetch"),
			want:   []want{{FieldArgs, "mcp-server-fetch"}},
		},
		{
			name:   "scope squatting with xox scope",
			server: npxServer("files", "@xoxo/server-filesystem"),
			want:   []want{{FieldArgs, "@modelcontextprotocol/server-filesystem"}},
		},
		{
			name:   "scope squatting with eyj scope",
			server: npxServer("gh", "@eyjay/server-github"),
			want:   []want{{FieldArgs, "@modelcontextprotocol/server-github"}},
		},

		{
			// A different scope, one letter off, is a new scope: normal
			// threshold applies. The bare name is exact, so it is also
			// scope squatting.
			name:   "typo inside the scope part",
			server: npxServer("files", "@modelcontextprotoco1/server-filesystem"),
			want:   []want{{FieldArgs, "@modelcontextprotocol/server-filesystem"}},
		},
		{
			name:   "other scope with a typo in the bare name",
			server: npxServer("files", "@evil/server-filesytem"),
			want:   []want{{FieldArgs, "@modelcontextprotocol/server-filesystem"}},
		},

		// Negatives.
		// Same scope as a popular package: only the scope owner can publish
		// there, so a sibling that is two edits from a popular name (gitlab
		// against github) is not a typosquat. A one-edit typo in the same scope
		// still fires (see the positives above): it is a config mistake.
		{name: "official sibling in the same scope", server: npxServer("gl", "@modelcontextprotocol/server-gitlab")},
		{name: "server name of an official sibling", server: discover.Server{Name: "server-gitlab"}},
		{name: "official sibling with version", server: npxServer("gl", "@modelcontextprotocol/server-gitlab@1.0.0")},
		{name: "ambiguous bare name shared by two popular packages", server: npxServer("m", "@acme/mcp-server")},
		{name: "scope squatting does not apply to a server name", server: discover.Server{Name: "server-filesystem"}},
		{name: "exact unscoped popular package", server: npxServer("remote", "mcp-remote")},
		{name: "exact unscoped popular package with version", server: npxServer("remote", "mcp-remote@1.0.0")},
		{name: "scoped package with an unrelated bare name", server: npxServer("remote", "@evil/mcp-remote-extra-long-name")},
		{name: "exact scoped package", server: npxServer("files", "@modelcontextprotocol/server-filesystem")},
		{name: "exact package with version", server: npxServer("files", "@modelcontextprotocol/server-filesystem@1.0.0")},
		{name: "exact server name", server: discover.Server{Name: "mcp-server-fetch"}},
		{name: "exact name in other case", server: discover.Server{Name: "MCP-Server-Fetch"}},
		{name: "exact bare name of a scoped package", server: discover.Server{Name: "server-filesystem"}},
		{name: "internal tools name", server: discover.Server{Name: "my-company-internal-tools"}},
		{name: "short word memory", server: discover.Server{Name: "memory"}},
		{name: "short name gist", server: discover.Server{Name: "gist"}},
		{name: "short name git", server: discover.Server{Name: "git"}},
		{name: "empty name", server: discover.Server{}},
		{name: "200 rune name", server: discover.Server{Name: strings.Repeat("a", 200)}},
		{name: "200 rune package", server: npxServer("x", strings.Repeat("a", 200))},
		{name: "unrelated scoped package", server: npxServer("notes", "@example-corp/notes-mcp")},
		// A user who names a server after a scoped package writes it flat.
		// "_" and "." in a server name count as "-".
		{name: "underscore flat name", server: discover.Server{Name: "playwright_mcp"}},
		{name: "underscore bare name", server: discover.Server{Name: "server_github"}},
		{name: "underscore PyPI name", server: discover.Server{Name: "mcp_server_fetch"}},
		{name: "underscore unscoped npm name", server: discover.Server{Name: "context7_mcp"}},
		{name: "server name mcp-fetch for the image mcp/fetch", server: discover.Server{Name: "mcp-fetch"}},
		{name: "server name written as the scoped package", server: discover.Server{Name: "@modelcontextprotocol/server-github"}},
		// A server that runs a popular package exactly is that server.
		{name: "name typo on an exact popular package", server: npxServer("mcp-server-gitt", "@playwright/mcp@1.0.0")},
		{name: "flat name of @playwright/mcp", server: npxServer("playwright-mcp", "@playwright/mcp@latest")},
		{name: "flat name of @stripe/mcp", server: npxServer("stripe-mcp", "@stripe/mcp")},
		{name: "flat name of @sentry/mcp-server", server: npxServer("sentry-mcp-server", "@sentry/mcp-server")},
		{name: "flat name of @mapbox/mcp-server", server: npxServer("mapbox-mcp-server", "@mapbox/mcp-server")},
		// Scopes exist only in npm: a PyPI package with the bare name of a
		// scoped npm package is not scope squatting.
		{name: "PyPI package with the bare name of a scoped npm package", server: stdioServer("uvx", "notion-mcp-server")},
		{name: "PyPI name with underscores is the real package", server: stdioServer("uvx", "mcp_server_fetch")},
		{name: "PyPI name with dots and case is the real package", server: stdioServer("pipx", "run", "MCP.Server.Fetch")},
		{name: "Docker Hub prefix is the real image", server: stdioServer("docker", "run", "-i", "docker.io/mcp/fetch")},
		{name: "index.docker.io prefix is the real image", server: stdioServer("docker", "run", "-i", "index.docker.io/mcp/fetch:1.0")},
		{name: "Docker Hub library prefix", server: stdioServer("docker", "run", "-i", "docker.io/library/mcp/fetch")},
		// "mcp-server" is the bare name of two popular packages, so it proves
		// nothing in the edit distance either.
		{name: "server name close to an ambiguous bare name", server: discover.Server{Name: "my-server"}},
		{name: "server name plural of an ambiguous bare name", server: discover.Server{Name: "mcp-servers"}},
		{name: "server name with suffix on an ambiguous bare name", server: discover.Server{Name: "mcp-server-1"}},
		{name: "package close to an ambiguous bare name", server: npxServer("x", "@someone/mcp-servers")},
		{
			name:   "docker with unrelated image",
			server: discover.Server{Name: "db", Command: "docker", Args: discover.NewArgs([]string{"run", "-i", "--rm", "postgres:16"})},
		},
		{name: "no command", server: discover.Server{Name: "remote-thing", Transport: discover.TransportHTTP}},
		{name: "unknown command", server: discover.Server{Name: "x-local", Command: "node", Args: discover.NewArgs([]string{"mcp-server-fecth"})}},
		{name: "local path is not a package", server: discover.Server{Name: "x-local", Command: "npx", Args: discover.NewArgs([]string{"./mcp-server-fecth"})}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ts.Check(tt.server)
			if len(got) != len(tt.want) {
				t.Fatalf("Check() gave %d findings %+v, want %d", len(got), got, len(tt.want))
			}
			for i, w := range tt.want {
				f := got[i]
				if f.RuleID != RuleTyposquat {
					t.Errorf("finding %d RuleID = %q, want %q", i, f.RuleID, RuleTyposquat)
				}
				if f.Server != tt.server.Name {
					t.Errorf("finding %d Server = %q, want %q", i, f.Server, tt.server.Name)
				}
				if f.Field != w.field {
					t.Errorf("finding %d Field = %q, want %q", i, f.Field, w.field)
				}
				if f.Related != w.related {
					t.Errorf("finding %d Related = %q, want %q", i, f.Related, w.related)
				}
				if f.Message == "" {
					t.Errorf("finding %d has an empty Message", i)
				}
			}
		})
	}
}

func TestTyposquatExactNameBeatsNeighbour(t *testing.T) {
	t.Parallel()
	// "server-gitlab" and "server-github" are one edit apart, and both are
	// popular. Each one is legitimate and must not be reported as a typo of
	// the other.
	ts := NewTyposquat([]string{"@scope/server-gitlab", "@scope/server-github", "plain-gitlab-mcp", "plain-github-mcp"})
	tests := []struct {
		name   string
		server discover.Server
	}{
		{name: "package gitlab", server: npxServer("x-local", "@scope/server-gitlab")},
		{name: "package github", server: npxServer("x-local", "@scope/server-github")},
		{name: "plain package gitlab", server: npxServer("x-local", "plain-gitlab-mcp")},
		{name: "plain package github", server: npxServer("x-local", "plain-github-mcp")},
		{name: "server name gitlab", server: discover.Server{Name: "@scope/server-gitlab"}},
		{name: "server bare name gitlab", server: discover.Server{Name: "server-gitlab"}},
		{name: "server name plain github", server: discover.Server{Name: "plain-github-mcp"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ts.Check(tt.server); len(got) != 0 {
				t.Errorf("Check() = %+v, want no findings", got)
			}
		})
	}

	// A real typo of one of them is still reported.
	got := ts.Check(npxServer("x-local", "@scope/server-githbu"))
	if len(got) != 1 || got[0].Related != "@scope/server-github" {
		t.Errorf("Check() = %+v, want one finding related to @scope/server-github", got)
	}
}

func TestNewTyposquatAmbiguousBareNames(t *testing.T) {
	t.Parallel()
	ts := NewTyposquat([]string{
		"@aaa/shared-server", "@bbb/shared-server", // two scopes, one bare name
		"@ccc/unique-server",
		"@ddd/repeat-server", "@ddd/repeat-server", // same entry twice is not ambiguous
	})
	want := map[string]bool{"shared-server": true}
	if !reflect.DeepEqual(ts.ambiguous, want) {
		t.Errorf("ambiguous = %v, want %v", ts.ambiguous, want)
	}

	if got := ts.Check(npxServer("x-local", "@evil/shared-server")); len(got) != 0 {
		t.Errorf("ambiguous bare name gave %+v, want none", got)
	}
	if got := ts.Check(npxServer("x-local", "@evil/unique-server")); len(got) != 1 || got[0].Related != "@ccc/unique-server" {
		t.Errorf("unique bare name gave %+v, want one finding related to @ccc/unique-server", got)
	}
	if got := ts.Check(npxServer("x-local", "@evil/repeat-server")); len(got) != 1 || got[0].Related != "@ddd/repeat-server" {
		t.Errorf("repeated entry gave %+v, want one finding related to @ddd/repeat-server", got)
	}
	// A bare name under the minimum length is skipped.
	short := NewTyposquat([]string{"@aaa/mcp"})
	if got := short.Check(npxServer("x-local", "@evil/mcp")); len(got) != 0 {
		t.Errorf("short bare name gave %+v, want none", got)
	}
}

func TestTyposquatNeverEchoesArgValues(t *testing.T) {
	t.Parallel()
	// Args can hold secrets next to the package. A finding must name the
	// popular entry only, never other argument text.
	ts := NewTyposquat(loadPopular(t))
	s := discover.Server{
		Name:    "x-local",
		Command: "npx",
		Args:    discover.NewArgs([]string{"-y", "@modelcontextprotocol/server-filesytem", "--token=s3cr3t-value"}),
	}
	got := ts.Check(s)
	// The check must really fire, or the leak assert proves nothing.
	if len(got) != 1 {
		t.Fatalf("Check() = %+v, want one finding", got)
	}
	assertFindingNoLeak(t, got[0], "s3cr3t-value")
}

func TestNewTyposquatNormalizesInput(t *testing.T) {
	t.Parallel()
	in := []string{"  Mcp-Server-Fetch ", "", "   "}
	ts := NewTyposquat(in)
	in[0] = "changed-after-construction"

	got := ts.Check(discover.Server{Name: "mcp-server-fecth"})
	if len(got) != 1 || got[0].Related != "mcp-server-fetch" {
		t.Errorf("Check() = %+v, want one finding related to mcp-server-fetch", got)
	}
	if len(ts.popular) != 1 {
		t.Errorf("popular = %+v, want the blank entries skipped", ts.popular)
	}
}
