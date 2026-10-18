package discover

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// Fuzz tests for the config readers. A fuzz test feeds random-looking input to
// a function and checks properties that must always hold. Without the -fuzz
// flag, "go test" runs only the seed inputs (the f.Add values), so these tests
// are cheap in normal runs.
//
// To fuzz for real, run one target at a time:
//
//	go test -run '^$' -fuzz=FuzzReadClaudeCode -fuzztime=30s ./internal/discover/
//	go test -run '^$' -fuzz=FuzzReadCodex -fuzztime=30s ./internal/discover/
//
// Properties checked for any input:
//   - the reader does not panic;
//   - no FileError text holds the env canary (a config value must not leak);
//   - every FileError names the file and has one of the known reasons;
//   - every Server has Source equal to the file and a known transport.

// maxFuzzInput is the largest input a fuzz iteration accepts. Bigger inputs
// only make an iteration slow and find no new bugs.
const maxFuzzInput = 64 << 10

// knownReasons is the set of fixed reason texts a FileError may have.
var knownReasons = map[string]bool{
	reasonCannotRead:       true,
	reasonNotRegular:       true,
	reasonTooLarge:         true,
	reasonInvalidJSON:      true,
	reasonInvalidTOML:      true,
	reasonBadShape:         true,
	reasonBadServers:       true,
	reasonBadEntry:         true,
	reasonUnknownTransport: true,
	reasonNoCommandOrURL:   true,
	reasonStdioNoCommand:   true,
	reasonRemoteNoURL:      true,
	reasonCanceled:         true,
	reasonTooDeep:          true,
	reasonTooManyServers:   true,
	reasonNotFound:         true,
	reasonUnknownFormat:    true,
}

// fixtureSeeds returns the content of every fixture file with the given
// extension under testdata/discover/<dirs...>. The "missing" fixtures only
// hold a .gitkeep, so the extension filter skips them.
func fixtureSeeds(t testing.TB, ext string, dirs ...string) [][]byte {
	t.Helper()
	var seeds [][]byte
	for _, d := range dirs {
		root := fixtureDir(t, d)
		err := filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.IsDir() || filepath.Ext(p) != ext {
				return nil
			}
			data, err := os.ReadFile(p) //nolint:gosec // G304: test reads a repository fixture
			if err != nil {
				return err
			}
			seeds = append(seeds, data)
			return nil
		})
		if err != nil {
			t.Fatalf("walk fixtures %s: %v", root, err)
		}
	}
	if len(seeds) == 0 {
		t.Fatalf("no %s fixture files under %v", ext, dirs)
	}
	return seeds
}

// checkFuzzResult fails the test if res breaks a property listed at the top of
// this file. path is the file that the reader was given.
func checkFuzzResult(t *testing.T, path string, res Result) {
	t.Helper()
	for _, e := range res.Errors {
		if e == nil {
			t.Fatal("Result.Errors holds a nil *FileError")
		}
		if e.Path != path {
			t.Errorf("FileError.Path = %q, want %q", e.Path, path)
		}
		if e.Reason == "" || !knownReasons[e.Reason] {
			t.Errorf("FileError.Reason = %q, want one of the reason constants", e.Reason)
		}
		// A server name comes from the file, so it can legitimately hold the
		// canary. Everything else in the message is fixed text or the path.
		if !strings.Contains(e.Server, discovertest.CanaryEnv) {
			if leaks := discovertest.Leaks(e.Error(), discovertest.CanaryEnv); len(leaks) > 0 {
				t.Errorf("FileError text leaks the env canary: %q", e.Error())
			}
		}
	}
	for _, s := range res.Servers {
		if s.Source != path {
			t.Errorf("Server %q: Source = %q, want %q", s.Name, s.Source, path)
		}
		if !slices.Contains([]Transport{TransportStdio, TransportHTTP, TransportSSE}, s.Transport) {
			t.Errorf("Server %q: Transport = %q, want stdio, http or sse", s.Name, s.Transport)
		}
	}
}

// writeFuzzInput writes data to a new file in a temporary directory and
// returns its path. It skips the iteration if data is too large.
func writeFuzzInput(t *testing.T, name string, data []byte) string {
	t.Helper()
	if len(data) > maxFuzzInput {
		t.Skip("input larger than 64 KiB")
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fuzz input: %v", err)
	}
	return path
}

// FuzzReadClaudeCode fuzzes the JSON reader. Cursor files have the same JSON
// shape, so their fixtures are seeds too.
func FuzzReadClaudeCode(f *testing.F) {
	for _, seed := range fixtureSeeds(f, ".json", "claude-code", "cursor", "all") {
		f.Add(seed)
	}
	c := discovertest.CanaryEnv
	for _, seed := range []string{
		// Unterminated string that holds the canary.
		`{"mcpServers":{"a":{"command":"x","env":{"K":"` + c,
		// Bad escape right before the canary.
		`{"mcpServers":{"a":{"command":"x","env":{"K":"\q` + c + `"}}}}`,
		// Number where a string is expected, then the canary.
		`{"mcpServers":{"a":{"command":"x","env":{"K":12345},"url":"` + c + `"}}}`,
		// Unquoted value.
		`{"mcpServers":{"a":{"command":"x","env":{"K":` + c + `}}}}`,
		// Canary in the wrong place for every field type.
		`{"mcpServers":{"` + c + `":{"type":"` + c + `","args":"` + c + `"}}}`,
		`{"projects":{"/p":{"mcpServers":{"a":{"url":"http://u:` + c + `@h","headers":["` + c + `"]}}}}}`,
		`["` + c + `"]`,
		`{"mcpServers":"` + c + `"}`,
		`{"mcpServers":{"a":"` + c + `"}}`,
		// Raw newline inside a string (invalid JSON), before the canary.
		"{\"mcpServers\":{\"a\":{\"command\":\"x\\ny\n\",\"env\":{\"K\":\"" + c + "\"}}}}",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		path := writeFuzzInput(t, ".claude.json", data)
		res := ReadClaudeCode(t.Context(), path, ScopeGlobal, "")
		checkFuzzResult(t, path, res)
	})
}

// FuzzReadCodex fuzzes the TOML reader.
func FuzzReadCodex(f *testing.F) {
	for _, seed := range fixtureSeeds(f, ".toml", "codex", "all") {
		f.Add(seed)
	}
	c := discovertest.CanaryEnv
	for _, seed := range []string{
		// Unterminated string that holds the canary.
		"[mcp_servers.a]\ncommand = \"x\"\nenv = { K = \"" + c,
		// Bad escape right before the canary.
		"[mcp_servers.a]\ncommand = \"x\"\n[mcp_servers.a.env]\nK = \"\\q" + c + "\"\n",
		// Number where a string is expected.
		"[mcp_servers.a]\ncommand = \"x\"\n[mcp_servers.a.env]\nK = 12345\nL = \"" + c + "\"\n",
		// Unquoted value.
		"[mcp_servers.a]\ncommand = \"x\"\n[mcp_servers.a.env]\nK = " + c + "\n",
		// Wrong types for every field.
		"[mcp_servers.a]\ncommand = [\"" + c + "\"]\nargs = \"" + c + "\"\nurl = 1\n",
		"mcp_servers = \"" + c + "\"\n",
		"[mcp_servers]\na = \"" + c + "\"\n",
		"[mcp_servers.a]\nurl = \"http://u:" + c + "@h\"\nhttp_headers = { H = true }\n",
		// Deep nesting: the reader must return reasonTooDeep, not crash.
		"[mcp_servers.a]\ncommand = \"x\"\nargs = " + strings.Repeat("[", 100) + strings.Repeat("]", 100) + "\n",
		"[mcp_servers.a]\ncommand = \"x\"\nenv = " + strings.Repeat("{ k = ", 100) + "1" + strings.Repeat(" }", 100) + "\n",
		// Very long keys: the reader must return reasonTooDeep, not spend seconds.
		"[mcp_servers." + keyParts(200) + "]\n",
		"mcp_servers." + keyParts(200) + " = 1\n",
		// The key path adds up over nested inline tables: the reader must return
		// reasonTooDeep, not spend seconds.
		"x0 = " + strings.Repeat("{"+keyParts(63)+"=", 63) + "1" + strings.Repeat("}", 63) + "\n",
		"x0 = " + strings.Repeat("{"+keyParts(8)+"=", 8) + "1" + strings.Repeat("}", 8) + "\n",
		"[a.b.c.d.e]\nf.g.h.i = { j.k.l.m.n.o.p.q = 1 }\n",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		path := writeFuzzInput(t, "config.toml", data)
		res := ReadCodex(t.Context(), path)
		checkFuzzResult(t, path, res)
	})
}
