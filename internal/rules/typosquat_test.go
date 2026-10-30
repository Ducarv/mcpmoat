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

func TestCloseDistance(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		a, b     string
		want     bool
		wantDist int // checked only when want is true
	}{
		// The distinctive word is the part of the name after the last
		// separator in the shared prefix. A word of fewer than 5 runes allows
		// one edit only.
		{name: "2 edits in a 4 rune word", a: "mcp-server-abcd", b: "mcp-server-aXcX", want: false},
		{name: "2 edits in a 5 rune word", a: "mcp-server-abcde", b: "mcp-server-XbcXe", want: true, wantDist: 2},
		{name: "2 edits in a long word", a: "mcp-server-fexxh", b: "mcp-server-fetch", want: true, wantDist: 2},
		{name: "2 runes removed from a long word", a: "mcp-server-kubernet", b: "mcp-server-kubernetes", want: true, wantDist: 2},
		{name: "2 edits in a long word after a scope", a: "@modelcontextprotocol/server-filesysxxm", b: "@modelcontextprotocol/server-filesystem", want: true, wantDist: 2},
		// Accepted false negative: a short word cannot tell a typo from a
		// different product.
		{name: "2 edits in a 3 rune word", a: "mcp-server-gxx", b: "mcp-server-git", want: false},
		{name: "1 edit in a short tail", a: "mcp-server-fetcX", b: "mcp-server-fetch", want: true, wantDist: 1},
		{name: "transposition in a short tail", a: "mcp-server-gti", b: "mcp-server-git", want: true, wantDist: 1},
		{name: "issue case gcp vs git", a: "mcp-server-gcp", b: "mcp-server-git", want: false},
		{name: "issue case tidb vs time", a: "mcp-server-tidb", b: "mcp-server-time", want: false},
		{name: "prefix typo plus tail typo", a: "mcp-sever-fecth", b: "mcp-server-fetch", want: true, wantDist: 2},
		{name: "extra rune at the end", a: "mcp-server-fetchx", b: "mcp-server-fetch", want: true, wantDist: 1},
		{name: "two extra runes at the end", a: "mcp-server-fetchxx", b: "mcp-server-fetch", want: true, wantDist: 2},
		// Runes added or dropped at the end of the whole shorter name allow two
		// edits, even when the last word is short.
		{name: "two extra runes after a 3 rune word", a: "mcp-server-gitxx", b: "mcp-server-git", want: true, wantDist: 2},
		{name: "two extra runes after a -mcp suffix", a: "tavily-mcpjs", b: "tavily-mcp", want: true, wantDist: 2},
		{name: "two runes dropped from a 3 rune word", a: "mcp-server-g", b: "mcp-server-git", want: true, wantDist: 2},
		{name: "one change plus one extra rune in a 3 rune word", a: "mcp-server-gixx", b: "mcp-server-git", want: false},

		// Names of at most 8 runes allow one edit.
		{name: "8 runes, 1 edit", a: "abcdefgh", b: "abXdefgh", want: true, wantDist: 1},
		{name: "8 runes, 2 edits", a: "abcdefgh", b: "abXdeXgh", want: false},
		{name: "9 runes, 2 edits, long tail", a: "abcdefghi", b: "aXcdefgXi", want: true, wantDist: 2},
		{name: "9 runes, 3 edits", a: "abcdefghi", b: "aXcdXfgXi", want: false},
		{name: "shorter name decides: 8 vs 10 runes", a: "abcdefgh", b: "abcdefghXY", want: false},

		// Length caps.
		{name: "below the minimum length", a: "abcd", b: "abce", want: false},
		{name: "minimum length, 1 edit", a: "abcde", b: "abcdX", want: true, wantDist: 1},
		{name: "at the maximum length", a: strings.Repeat("a", 128), b: strings.Repeat("a", 127) + "b", want: true, wantDist: 1},
		{name: "above the maximum length", a: strings.Repeat("a", 129), b: strings.Repeat("a", 128) + "b", want: false},

		{name: "identical names", a: "mcp-server-fetch", b: "mcp-server-fetch", want: false},
		{name: "unicode runes count as one edit", a: "café-mcp", b: "cafe-mcp", want: true, wantDist: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, pair := range [][2]string{{tt.a, tt.b}, {tt.b, tt.a}} {
				d, ok := closeDistance(pair[0], pair[1])
				if ok != tt.want {
					t.Errorf("closeDistance(%q, %q) ok = %v, want %v", pair[0], pair[1], ok, tt.want)
				}
				if ok && d != tt.wantDist {
					t.Errorf("closeDistance(%q, %q) distance = %d, want %d", pair[0], pair[1], d, tt.wantDist)
				}
			}
		})
	}
}

func TestDistinctiveTailRunes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "short word after a long prefix", a: "mcp-server-gcp", b: "mcp-server-git", want: 3},
		{name: "typo in the prefix", a: "mcp-sever-fecth", b: "mcp-server-fetch", want: 11},
		{name: "extra runes at the end", a: "mcp-server-fetchxx", b: "mcp-server-fetch", want: 5},
		{name: "no shared prefix", a: "abcdef", b: "xbcdef", want: 6},
		{name: "separator at index 0", a: "@abcd", b: "@abXd", want: 4},
		{name: "scoped names", a: "@scope/server-abc", b: "@scope/server-abd", want: 3},
		{name: "multi-byte rune before a separator", a: "café-abc", b: "café-abd", want: 3},
		{name: "no separator in the shared prefix", a: "abcdef", b: "abcdXf", want: 6},
		{name: "both empty", a: "", b: "", want: 0},
		{name: "one empty", a: "abc", b: "", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			short := min(utf8.RuneCountInString(tt.a), utf8.RuneCountInString(tt.b))
			for _, pair := range [][2]string{{tt.a, tt.b}, {tt.b, tt.a}} {
				if got := distinctiveTailRunes(pair[0], pair[1], short); got != tt.want {
					t.Errorf("distinctiveTailRunes(%q, %q, %d) = %d, want %d", pair[0], pair[1], short, got, tt.want)
				}
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
		want  []PopularEntry
	}{
		{name: "empty", input: "", want: nil},
		{name: "only comments and blanks", input: "# a\n\n   \n# b\n", want: nil},
		{
			name:  "all three kinds",
			input: "npm:one-name\npypi:two-name\ndocker:mcp/three\n",
			want: []PopularEntry{
				{Kind: KindNPM, Name: "one-name"},
				{Kind: KindPyPI, Name: "two-name"},
				{Kind: KindDocker, Name: "mcp/three"},
			},
		},
		{name: "comment and blank lines skipped", input: "# c\n\nnpm:foo-bar\n\n# d\npypi:baz-qux\n", want: []PopularEntry{{KindNPM, "foo-bar"}, {KindPyPI, "baz-qux"}}},
		{name: "surrounding space trimmed", input: "  \tnpm:foo-bar \t\n", want: npmEntries("foo-bar")},
		{name: "space around the colon trimmed", input: "npm : foo-bar\n", want: npmEntries("foo-bar")},
		{name: "indented comment skipped", input: "   # not a name\nnpm:foo-bar\n", want: npmEntries("foo-bar")},
		{name: "name and kind lowercased", input: "NPM:@Scope/Server-Foo\n", want: npmEntries("@scope/server-foo")},
		{name: "CRLF line endings", input: "npm:foo-bar\r\npypi:baz-qux\r\n", want: []PopularEntry{{KindNPM, "foo-bar"}, {KindPyPI, "baz-qux"}}},
		{name: "no trailing newline", input: "npm:foo-bar", want: npmEntries("foo-bar")},
		{name: "split at the first colon only", input: "docker:host:5000/mcp/fetch\n", want: []PopularEntry{{KindDocker, "host:5000/mcp/fetch"}}},
		{name: "same name under two kinds is kept", input: "npm:shared-name\npypi:shared-name\n", want: []PopularEntry{{KindNPM, "shared-name"}, {KindPyPI, "shared-name"}}},
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

	errTests := []struct {
		name  string
		input string
		line  string // "line N" that the error must name
		want  string // a phrase that the error must hold
	}{
		{name: "no colon", input: "just-a-name\n", line: "line 1", want: "no colon"},
		{name: "no colon after valid lines", input: "# c\nnpm:ok-name\n\nbare-name\n", line: "line 4", want: "no colon"},
		{name: "empty kind", input: ":some-name\n", line: "line 1", want: "kind is empty"},
		{name: "blank kind", input: "npm:ok-name\n  :some-name\n", line: "line 2", want: "kind is empty"},
		{name: "unknown kind", input: "npm:ok-name\nnuget:some-name\n", line: "line 2", want: "unknown kind"},
		{name: "empty name", input: "npm:\n", line: "line 1", want: "name is empty"},
		{name: "blank name", input: "# c\npypi:   \n", line: "line 2", want: "name is empty"},
		{name: "CRLF empty name", input: "npm:ok-name\r\ndocker:\r\n", line: "line 2", want: "name is empty"},
	}
	for _, tt := range errTests {
		t.Run("error: "+tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParsePopular(strings.NewReader(tt.input))
			if err == nil {
				t.Fatalf("ParsePopular() = %q, error = nil, want an error", got)
			}
			if got != nil {
				t.Errorf("ParsePopular() entries = %q, want nil on error", got)
			}
			for _, part := range []string{"popular server list " + tt.line, tt.want} {
				if !strings.Contains(err.Error(), part) {
					t.Errorf("error = %q, want it to contain %q", err, part)
				}
			}
		})
	}

	t.Run("error does not repeat the line", func(t *testing.T) {
		t.Parallel()
		_, err := ParsePopular(strings.NewReader("nuget:secret-looking-name\n"))
		if err == nil {
			t.Fatal("ParsePopular() error = nil, want error for an unknown kind")
		}
		if strings.Contains(err.Error(), "secret-looking-name") {
			t.Errorf("error = %q, must not repeat the line", err)
		}
	})

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
		_, err := ParsePopular(strings.NewReader("npm:" + strings.Repeat("a", 70*1024)))
		if err == nil {
			t.Fatal("ParsePopular() error = nil, want error for an over-long line")
		}
	})
}

// npmEntries builds npm popular entries from names.
func npmEntries(names ...string) []PopularEntry {
	entries := make([]PopularEntry, len(names))
	for i, n := range names {
		entries[i] = PopularEntry{Kind: KindNPM, Name: n}
	}
	return entries
}

// dockerEntries builds docker popular entries from names.
func dockerEntries(names ...string) []PopularEntry {
	entries := npmEntries(names...)
	for i := range entries {
		entries[i].Kind = KindDocker
	}
	return entries
}

// runnerServer builds a server that runs pkg with the runner of the given
// registry kind: npx, uvx or "docker run".
func runnerServer(t *testing.T, kind RegistryKind, name, pkg string) discover.Server {
	t.Helper()
	var s discover.Server
	switch kind {
	case KindNPM:
		s = stdioServer("npx", "-y", pkg)
	case KindPyPI:
		s = stdioServer("uvx", pkg)
	case KindDocker:
		s = stdioServer("docker", "run", "-i", "--rm", pkg)
	default:
		t.Fatalf("runnerServer: unknown kind %q", kind)
	}
	s.Name = name
	return s
}

// readPopular parses the embedded popular list once for all tests.
var readPopular = sync.OnceValues(builtinPopular)

// loadPopular returns the real popular list, or stops the test when it
// cannot be read.
func loadPopular(t *testing.T) []PopularEntry {
	t.Helper()
	entries, err := readPopular()
	if err != nil {
		t.Fatalf("load popular list: %v", err)
	}
	return entries
}

func TestPopularListFile(t *testing.T) {
	t.Parallel()
	entries := loadPopular(t)

	if len(entries) < 30 {
		t.Errorf("popular list has %d entries, want at least 30", len(entries))
	}
	type key struct {
		kind RegistryKind
		name string
	}
	seen := make(map[key]bool, len(entries))
	for _, e := range entries {
		k := key{e.Kind, e.Name}
		if seen[k] {
			t.Errorf("duplicate entry %s:%s", e.Kind, e.Name)
		}
		seen[k] = true
		if !validPopularKind(e.Kind) {
			t.Errorf("entry %q has unknown kind %q", e.Name, e.Kind)
		}
		n := e.Name
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

	// Two docker entries with the same last component make that base ambiguous:
	// NewTyposquat then skips the owner-squat check for it, so a squat of
	// either image gives no finding.
	dockerBases := make(map[string]string)
	for _, e := range entries {
		if e.Kind != KindDocker {
			continue
		}
		if strings.Contains(e.Name, "@") || strings.Contains(e.Name[strings.LastIndex(e.Name, "/")+1:], ":") {
			t.Errorf("docker entry %q has a tag or digest, want the image name only", e.Name)
		}
		base := dockerBase(e.Name)
		if first, ok := dockerBases[base]; ok {
			t.Errorf("docker entries %q and %q share the last component %q: the namespace squat check skips an ambiguous base, so a squat of either image would go unseen. Keep one entry for each last component", first, e.Name, base)
		}
		dockerBases[base] = e.Name
	}

	ts := NewTyposquat(entries)
	for _, e := range entries {
		// An exact popular name is the legitimate server: it must never be
		// flagged, as a server name or as a package under the runner of its
		// own kind.
		servers := map[string]discover.Server{
			"server name": {Name: e.Name},
			"own runner":  runnerServer(t, e.Kind, "x-local", e.Name),
		}
		for label, s := range servers {
			if got := ts.Check(s); len(got) != 0 {
				t.Errorf("popular %s:%s as %s gave findings %+v, want none", e.Kind, e.Name, label, got)
			}
		}

		// The same npm or PyPI name under the runner of the other registry
		// is a kind mismatch (unless the list has it under that kind too).
		other := KindPyPI
		if e.Kind == KindPyPI {
			other = KindNPM
		}
		if e.Kind == KindDocker || seen[key{other, e.Name}] {
			continue
		}
		got := ts.Check(runnerServer(t, other, "x-local", e.Name))
		if strings.HasPrefix(e.Name, "@") {
			// A scoped name is not a valid PyPI name: the runner extracts no
			// package, so there is nothing to compare.
			if len(got) != 0 {
				t.Errorf("scoped popular %s:%s under the %s runner gave %+v, want none", e.Kind, e.Name, other, got)
			}
			continue
		}
		if len(got) != 1 {
			t.Errorf("popular %s:%s under the %s runner gave %+v, want one kind-mismatch finding", e.Kind, e.Name, other, got)
			continue
		}
		if got[0].Message != typosquatKindMessage || got[0].Related != e.Name || got[0].Field != FieldArgs {
			t.Errorf("popular %s:%s under the %s runner gave %+v, want a kind-mismatch finding related to %q", e.Kind, e.Name, other, got[0], e.Name)
		}
	}
}

func TestTyposquatCheck(t *testing.T) {
	t.Parallel()
	ts := NewTyposquat(loadPopular(t))

	type want struct{ field, related string }
	// kindMismatch is the finding for a name that is popular on another registry.
	// Related is the plain popular name.
	kindMismatch := func(related string) []want { return []want{{FieldArgs, related}} }

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
		{
			name:   "uvx package with a typo in the prefix and in the tail",
			server: stdioServer("uvx", "mcp-sever-fecth"),
			want:   []want{{FieldArgs, "mcp-server-fetch"}},
		},
		{
			name:   "uvx package with two edits in a long word",
			server: stdioServer("uvx", "mcp-server-fexxh"),
			want:   []want{{FieldArgs, "mcp-server-fetch"}},
		},
		{
			name:   "uvx package with two extra runes at the end",
			server: stdioServer("uvx", "mcp-server-fetchxx"),
			want:   []want{{FieldArgs, "mcp-server-fetch"}},
		},
		{
			name:   "uvx package with two extra runes after a short word",
			server: stdioServer("uvx", "mcp-server-gitxx"),
			want:   []want{{FieldArgs, "mcp-server-git"}},
		},
		{
			name:   "npx package with two extra runes after a -mcp suffix",
			server: npxServer("t", "tavily-mcpjs"),
			want:   []want{{FieldArgs, "tavily-mcp"}},
		},

		// Docker namespace squatting: same last component, other owner.
		{
			name:   "docker owner squat of a Docker Hub image",
			server: stdioServer("docker", "run", "-i", "--rm", "evil/fetch"),
			want:   []want{{FieldArgs, "mcp/fetch"}},
		},
		{
			name:   "docker owner squat of a ghcr.io image, same host",
			server: stdioServer("docker", "run", "-i", "--rm", "ghcr.io/evil/github-mcp-server"),
			want:   []want{{FieldArgs, "ghcr.io/github/github-mcp-server"}},
		},
		{
			name:   "docker owner squat of a ghcr.io image, no host",
			server: stdioServer("docker", "run", "-i", "--rm", "evil/github-mcp-server"),
			want:   []want{{FieldArgs, "ghcr.io/github/github-mcp-server"}},
		},
		{
			name:   "docker owner squat with a tag",
			server: stdioServer("docker", "run", "-i", "--rm", "evil/github-mcp-server:latest"),
			want:   []want{{FieldArgs, "ghcr.io/github/github-mcp-server"}},
		},
		{
			// The host differs, so the image is another one.
			name:   "docker same owner and name on another registry",
			server: stdioServer("docker", "run", "-i", "--rm", "ghcr.io/mcp/fetch"),
			want:   []want{{FieldArgs, "mcp/fetch"}},
		},

		// Kind mismatches: a popular name on the wrong registry.
		{
			name:   "npx runs a popular PyPI name",
			server: npxServer("fetcher", "mcp-server-fetch"),
			want:   kindMismatch("mcp-server-fetch"),
		},
		{
			name:   "bunx runs a popular PyPI name",
			server: stdioServer("bunx", "mcp-server-git"),
			want:   kindMismatch("mcp-server-git"),
		},
		{
			name:   "npx runs a popular PyPI name with a version",
			server: npxServer("fetcher", "mcp-server-fetch@1.0.0"),
			want:   kindMismatch("mcp-server-fetch"),
		},
		{
			name:   "uvx runs a popular unscoped npm name",
			server: stdioServer("uvx", "firecrawl-mcp"),
			want:   kindMismatch("firecrawl-mcp"),
		},
		{
			name:   "pipx runs a popular unscoped npm name",
			server: stdioServer("pipx", "run", "mcp-remote"),
			want:   kindMismatch("mcp-remote"),
		},
		{
			name:   "uvx runs a popular unscoped npm name with PyPI separators",
			server: stdioServer("uvx", "Firecrawl_MCP"),
			want:   kindMismatch("firecrawl-mcp"),
		},

		// Docker squats with a registry host: the owner is the component after
		// the host.
		{
			name:   "ghcr.io host with an owner is a squat",
			server: stdioServer("docker", "run", "-i", "ghcr.io/evil/github-mcp-server"),
			want:   []want{{FieldArgs, "ghcr.io/github/github-mcp-server"}},
		},
		{
			name:   "localhost with a port and an owner is a squat",
			server: stdioServer("docker", "run", "-i", "localhost:5000/evil/fetch"),
			want:   []want{{FieldArgs, "mcp/fetch"}},
		},

		// Negatives.
		// Two edits in a short word after a long shared prefix are two
		// different products, not a typo.
		{name: "npx package gcp next to git", server: npxServer("x", "mcp-server-gcp")},
		{name: "uvx package gcp next to git", server: stdioServer("uvx", "mcp-server-gcp")},
		{name: "uvx package tidb next to time", server: stdioServer("uvx", "mcp-server-tidb")},
		{name: "server name gcp next to git", server: discover.Server{Name: "mcp-server-gcp"}},
		// Accepted false negative: two edits in a 3 rune word.
		{name: "uvx package gxx next to git", server: stdioServer("uvx", "mcp-server-gxx")},
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
		{name: "registry.hub.docker.com prefix is the real image", server: stdioServer("docker", "run", "-i", "registry.hub.docker.com/mcp/fetch")},
		// A registry host plus a bare name has no owner: no docker squat.
		{name: "ghcr.io host with a bare name has no owner", server: stdioServer("docker", "run", "-i", "ghcr.io/fetch")},
		{name: "localhost with a port and a bare name has no owner", server: stdioServer("docker", "run", "-i", "localhost:5000/fetch")},
		{name: "localhost without a port and a bare name has no owner", server: stdioServer("docker", "run", "-i", "localhost/fetch")},
		{name: "ghcr.io host with a long bare name has no owner", server: stdioServer("docker", "run", "-i", "ghcr.io/github-mcp-server")},
		// "mcp-server" is the bare name of two popular packages, so it proves
		// nothing in the edit distance either.
		{name: "server name close to an ambiguous bare name", server: discover.Server{Name: "my-server"}},
		{name: "server name plural of an ambiguous bare name", server: discover.Server{Name: "mcp-servers"}},
		{name: "server name with suffix on an ambiguous bare name", server: discover.Server{Name: "mcp-server-1"}},
		{name: "package close to an ambiguous bare name", server: npxServer("x", "@someone/mcp-servers")},
		// Docker names that are not squats.
		{name: "docker Hub image, exact", server: stdioServer("docker", "run", "-i", "--rm", "mcp/fetch")},
		{name: "docker Hub image with a tag, exact", server: stdioServer("docker", "run", "-i", "--rm", "mcp/fetch:latest")},
		{name: "docker.io host, exact", server: stdioServer("docker", "run", "-i", "--rm", "docker.io/mcp/fetch")},
		{name: "docker ghcr.io image, exact", server: stdioServer("docker", "run", "-i", "--rm", "ghcr.io/github/github-mcp-server")},
		{name: "docker official image without an owner", server: stdioServer("docker", "run", "-i", "--rm", "postgres:16")},
		{name: "docker official image with the base of a popular image", server: stdioServer("docker", "run", "-i", "--rm", "fetch")},
		{name: "docker official image with the base of a ghcr.io image", server: stdioServer("docker", "run", "-i", "--rm", "github-mcp-server")},
		{name: "docker image of an unrelated owner", server: stdioServer("docker", "run", "-i", "--rm", "acme/postgres")},
		{name: "docker owner squat of a short base is skipped", server: stdioServer("docker", "run", "-i", "--rm", "evil/mcps")},
		{name: "docker image with a typo in the last component", server: stdioServer("docker", "run", "-i", "--rm", "evil/fecth")},
		// A docker image and an npm or PyPI name are separate namespaces: a
		// docker candidate is never a kind mismatch.
		{name: "docker image named like a popular PyPI name", server: stdioServer("docker", "run", "-i", "--rm", "mcp-server-fetch")},
		{name: "docker image named like a popular npm name", server: stdioServer("docker", "run", "-i", "--rm", "firecrawl-mcp")},
		// An npm package is not a kind mismatch of an npm entry, and a docker
		// name under npx is not one either.
		{name: "npx runs a docker entry name", server: npxServer("x", "mcp/fetch")},
		{name: "uvx runs an unrelated name", server: stdioServer("uvx", "my-private-tool")},
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
	ts := NewTyposquat(npmEntries("@scope/server-gitlab", "@scope/server-github", "plain-gitlab-mcp", "plain-github-mcp"))
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
	ts := NewTyposquat(npmEntries(
		"@aaa/shared-server", "@bbb/shared-server", // two scopes, one bare name
		"@ccc/unique-server",
		"@ddd/repeat-server", "@ddd/repeat-server", // same entry twice is not ambiguous
	))
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
	short := NewTyposquat(npmEntries("@aaa/mcp"))
	if got := short.Check(npxServer("x-local", "@evil/mcp")); len(got) != 0 {
		t.Errorf("short bare name gave %+v, want none", got)
	}
}

func TestNewTyposquatAmbiguousDockerBases(t *testing.T) {
	t.Parallel()
	ts := NewTyposquat(dockerEntries(
		"aaa/shared-image", "bbb/shared-image", // two owners, one base
		"ccc/unique-image",
		"ddd/repeat-image", "ddd/repeat-image", // same entry twice is not ambiguous
	))
	want := map[string]bool{"shared-image": true}
	if !reflect.DeepEqual(ts.ambiguousBase, want) {
		t.Errorf("ambiguousBase = %v, want %v", ts.ambiguousBase, want)
	}
	// ambiguous keys the npm bare names: docker entries must not fill it.
	if len(ts.ambiguous) != 0 {
		t.Errorf("ambiguous = %v, want it empty for docker entries with distinct bare names", ts.ambiguous)
	}

	tests := []struct {
		name        string
		image       string
		wantRelated string // empty means no finding
	}{
		{name: "ambiguous base is quiet", image: "evil/shared-image"},
		{name: "ambiguous base with a host is quiet", image: "ghcr.io/evil/shared-image"},
		{name: "unique base fires", image: "evil/unique-image", wantRelated: "ccc/unique-image"},
		{name: "repeated entry is one owner", image: "evil/repeat-image", wantRelated: "ddd/repeat-image"},
		{name: "exact ambiguous image is quiet", image: "aaa/shared-image"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ts.Check(stdioServer("docker", "run", "-i", "--rm", tt.image))
			if tt.wantRelated == "" {
				if len(got) != 0 {
					t.Errorf("Check() = %+v, want none", got)
				}
				return
			}
			if len(got) != 1 || got[0].Related != tt.wantRelated || got[0].Message != typosquatMessage {
				t.Errorf("Check() = %+v, want one finding related to %q", got, tt.wantRelated)
			}
		})
	}
}

func TestNewTyposquatSkipsInvalidKind(t *testing.T) {
	t.Parallel()
	for _, kind := range []RegistryKind{"", "cargo", "oci"} {
		t.Run("kind "+string(kind), func(t *testing.T) {
			t.Parallel()
			ts := NewTyposquat([]PopularEntry{
				{Kind: kind, Name: "mcp-server-alpha"},
				{Kind: kind, Name: "aaa/shared-image"},
				{Kind: kind, Name: "bbb/shared-image"},
				// A valid docker entry with the same base: an invalid entry must
				// not make the base ambiguous, so this squat stays visible.
				{Kind: KindDocker, Name: "ccc/shared-image"},
			})
			if len(ts.popular) != 1 {
				t.Errorf("popular = %+v, want only the valid docker entry", ts.popular)
			}
			if len(ts.ambiguousBase) != 0 {
				t.Errorf("ambiguousBase = %v, want it empty", ts.ambiguousBase)
			}
			if len(ts.ambiguous) != 0 {
				t.Errorf("ambiguous = %v, want it empty", ts.ambiguous)
			}

			quiet := map[string]discover.Server{
				"server name": {Name: "mcp-server-alpha"},
				"npx runner":  npxServer("x-local", "mcp-server-alpha"),
				"uvx runner":  stdioServer("uvx", "mcp-server-alpha"),
			}
			for label, s := range quiet {
				if got := ts.Check(s); len(got) != 0 {
					t.Errorf("%s of an invalid-kind entry gave %+v, want none", label, got)
				}
			}
			got := ts.Check(stdioServer("docker", "run", "-i", "--rm", "evil/shared-image"))
			if len(got) != 1 || got[0].Related != "ccc/shared-image" {
				t.Errorf("Check() = %+v, want one finding related to ccc/shared-image", got)
			}
		})
	}
}

func TestTyposquatDockerBaseLength(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", maxTyposquatNameLen)
	tooLong := long + "a"
	ts := NewTyposquat(dockerEntries("mcp/four", "mcp/fives", "mcp/"+long, "mcp/"+tooLong))
	tests := []struct {
		name        string
		image       string
		wantRelated string
	}{
		{name: "base under the minimum", image: "evil/four"},
		{name: "base at the minimum", image: "evil/fives", wantRelated: "mcp/fives"},
		{name: "base at the maximum", image: "evil/" + long, wantRelated: "mcp/" + long},
		{name: "base over the maximum", image: "evil/" + tooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ts.Check(stdioServer("docker", "run", "-i", "--rm", tt.image))
			if tt.wantRelated == "" {
				if len(got) != 0 {
					t.Errorf("Check() = %+v, want none", got)
				}
				return
			}
			if len(got) != 1 || got[0].Related != tt.wantRelated {
				t.Errorf("Check() = %+v, want one finding related to %q", got, tt.wantRelated)
			}
		})
	}
}

func TestTyposquatKindAware(t *testing.T) {
	t.Parallel()
	ts := NewTyposquat([]PopularEntry{
		{Kind: KindPyPI, Name: "only-on-pypi"},
		{Kind: KindNPM, Name: "only-on-npm"},
		{Kind: KindNPM, Name: "on-both-registries"},
		{Kind: KindPyPI, Name: "on-both-registries"},
		{Kind: KindDocker, Name: "mcp/dockeronly"},
	})
	tests := []struct {
		name        string
		server      discover.Server
		wantMessage string // empty means no finding
		wantRelated string
	}{
		{name: "npx runs a PyPI entry", server: npxServer("x-local", "only-on-pypi"), wantMessage: typosquatKindMessage, wantRelated: "only-on-pypi"},
		{name: "bunx runs a PyPI entry", server: stdioServer("bunx", "only-on-pypi"), wantMessage: typosquatKindMessage, wantRelated: "only-on-pypi"},
		{name: "uvx runs an npm entry", server: stdioServer("uvx", "only-on-npm"), wantMessage: typosquatKindMessage, wantRelated: "only-on-npm"},
		{name: "pipx runs an npm entry", server: stdioServer("pipx", "run", "only-on-npm"), wantMessage: typosquatKindMessage, wantRelated: "only-on-npm"},
		{name: "own kind npm", server: npxServer("x-local", "only-on-npm")},
		{name: "own kind PyPI", server: stdioServer("uvx", "only-on-pypi")},
		{name: "entry on both registries, npx", server: npxServer("x-local", "on-both-registries")},
		{name: "entry on both registries, uvx", server: stdioServer("uvx", "on-both-registries")},
		{name: "docker runs an npm entry", server: stdioServer("docker", "run", "--rm", "only-on-npm")},
		{name: "npx runs a docker entry", server: npxServer("x-local", "mcp/dockeronly")},
		{name: "uvx runs a docker entry", server: stdioServer("uvx", "mcp/dockeronly")},
		// A server name has no registry: it may equal a popular name of any kind.
		{name: "server name equals a PyPI entry", server: discover.Server{Name: "only-on-pypi"}},
		{name: "server name equals an npm entry", server: discover.Server{Name: "only-on-npm"}},
		{name: "server name equals a docker entry", server: discover.Server{Name: "mcp/dockeronly"}},
		{name: "server name of a kind mismatch is still free", server: npxServer("only-on-npm", "only-on-pypi"), wantMessage: typosquatKindMessage, wantRelated: "only-on-pypi"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ts.Check(tt.server)
			if tt.wantMessage == "" {
				if len(got) != 0 {
					t.Fatalf("Check() = %+v, want none", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("Check() = %+v, want one finding", got)
			}
			f := got[0]
			if f.RuleID != RuleTyposquat || f.Field != FieldArgs || f.Message != tt.wantMessage || f.Related != tt.wantRelated {
				t.Errorf("Check() = %+v, want rule %s, field %s, message %q, related %q", f, RuleTyposquat, FieldArgs, tt.wantMessage, tt.wantRelated)
			}
		})
	}

	t.Run("kind mismatch message differs from the typo message", func(t *testing.T) {
		t.Parallel()
		if typosquatKindMessage == typosquatMessage || typosquatKindMessage == "" {
			t.Errorf("typosquatKindMessage = %q, want a text of its own", typosquatKindMessage)
		}
	})

	t.Run("several entries with the name give one finding", func(t *testing.T) {
		t.Parallel()
		// Several entries have the name, none of the kind of the runner: still one
		// finding, and Related is the plain name.
		tie := NewTyposquat([]PopularEntry{{Kind: KindDocker, Name: "tie-name"}, {Kind: KindPyPI, Name: "tie-name"}, {Kind: KindPyPI, Name: "tie-name"}})
		got := tie.Check(npxServer("x-local", "tie-name"))
		if len(got) != 1 || got[0].Related != "tie-name" || got[0].Message != typosquatKindMessage {
			t.Errorf("Check() = %+v, want one kind-mismatch finding related to tie-name", got)
		}
	})
}

func TestTyposquatNeverEchoesArgValues(t *testing.T) {
	t.Parallel()
	// Args can hold secrets next to the package. A finding must name the
	// popular entry only, never other argument text.
	ts := NewTyposquat(loadPopular(t))
	tests := []struct {
		name        string
		command     string
		args        []string
		wantRelated string
		wantMessage string
	}{
		{
			name:        "typo",
			command:     "npx",
			args:        []string{"-y", "@modelcontextprotocol/server-filesytem", "--token=s3cr3t-value"},
			wantRelated: "@modelcontextprotocol/server-filesystem",
			wantMessage: typosquatMessage,
		},
		{
			name:        "kind mismatch",
			command:     "npx",
			args:        []string{"-y", "mcp-server-fetch@1.0.0", "--token=s3cr3t-value"},
			wantRelated: "mcp-server-fetch",
			wantMessage: typosquatKindMessage,
		},
		{
			name:        "docker namespace squat",
			command:     "docker",
			args:        []string{"run", "-i", "--rm", "-e", "API_KEY=s3cr3t-value", "evil/github-mcp-server:s3cr3t-value"},
			wantRelated: "ghcr.io/github/github-mcp-server",
			wantMessage: typosquatMessage,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ts.Check(discover.Server{Name: "x-local", Command: tt.command, Args: discover.NewArgs(tt.args)})
			// The check must really fire, or the leak assert proves nothing.
			if len(got) != 1 {
				t.Fatalf("Check() = %+v, want one finding", got)
			}
			if got[0].Related != tt.wantRelated || got[0].Message != tt.wantMessage {
				t.Errorf("Check() = %+v, want related %q and message %q", got[0], tt.wantRelated, tt.wantMessage)
			}
			assertFindingNoLeak(t, got[0], "s3cr3t-value")
		})
	}
}

func TestNewTyposquatNormalizesInput(t *testing.T) {
	t.Parallel()
	in := []PopularEntry{{Kind: KindNPM, Name: "  Mcp-Server-Fetch "}, {Kind: KindNPM, Name: ""}, {Kind: KindNPM, Name: "   "}}
	ts := NewTyposquat(in)
	in[0].Name = "changed-after-construction"

	got := ts.Check(discover.Server{Name: "mcp-server-fecth"})
	if len(got) != 1 || got[0].Related != "mcp-server-fetch" {
		t.Errorf("Check() = %+v, want one finding related to mcp-server-fetch", got)
	}
	if len(ts.popular) != 1 {
		t.Errorf("popular = %+v, want the blank entries skipped", ts.popular)
	}
}

func TestNewBuiltinTyposquat(t *testing.T) {
	t.Parallel()
	builtin, err := NewBuiltinTyposquat()
	if err != nil {
		t.Fatalf("NewBuiltinTyposquat() error = %v, want nil", err)
	}
	if builtin == nil {
		t.Fatal("NewBuiltinTyposquat() = nil, want a check")
	}
	reference := NewTyposquat(loadPopular(t))

	tests := []struct {
		name        string
		server      discover.Server
		wantRelated string // empty means no finding
	}{
		{
			name:        "typo of the filesystem server",
			server:      npxServer("files", "@modelcontextprotocol/server-filesytem"),
			wantRelated: "@modelcontextprotocol/server-filesystem",
		},
		{
			name:   "exact filesystem server",
			server: npxServer("files", "@modelcontextprotocol/server-filesystem"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := builtin.Check(tt.server)
			want := 0
			if tt.wantRelated != "" {
				want = 1
			}
			if len(got) != want {
				t.Fatalf("Check() gave %d findings, want %d: %+v", len(got), want, got)
			}
			if want == 1 {
				if got[0].RuleID != RuleTyposquat {
					t.Errorf("RuleID = %q, want %q", got[0].RuleID, RuleTyposquat)
				}
				if got[0].Related != tt.wantRelated {
					t.Errorf("Related = %q, want %q", got[0].Related, tt.wantRelated)
				}
			}
			if want := reference.Check(tt.server); !reflect.DeepEqual(got, want) {
				t.Errorf("builtin findings = %+v, want same as NewTyposquat(popular): %+v", got, want)
			}
		})
	}
}
