package pins

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"flag"
	"os"
	"strconv"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// update rewrites the golden files of package pins. Other golden tests in
// this package must reuse this flag; do not define a second one. Run
// "go test ./internal/pins/ -run TestHashGolden -update", then read
// "git diff" before you commit.
var update = flag.Bool("update", false, "rewrite golden files")

// The fixtures are in the root testdata/, like the fixtures of the other
// packages (see docs/ARCHITECTURE.md).
const (
	hashFixturesPath = "../../testdata/pins/hash/tools.json"
	hashGoldenPath   = "../../testdata/pins/hash/golden.txt"
)

// hashFixture is one named tool from testdata/pins/hash/tools.json.
type hashFixture struct {
	Name string
	Tool inspect.Tool
}

// hashFixtureFile is the JSON shape of one entry in tools.json. inspect.Tool
// has no json tags, so the file is decoded into this local shape first. It
// does not use the canonical types, so a new HashVersion does not change the
// fixture format.
type hashFixtureFile struct {
	Fixture string `json:"fixture"`
	Tool    struct {
		Name        string `json:"name"`
		Title       string `json:"title"`
		Description string `json:"description"`
		// A jsontext.Value keeps the raw schema bytes exactly as in the file
		// (spaces and number forms included). An absent schema stays nil.
		InputSchema  jsontext.Value          `json:"inputSchema"`
		OutputSchema jsontext.Value          `json:"outputSchema"`
		Annotations  *hashFixtureAnnotations `json:"annotations"`
	} `json:"tool"`
}

// hashFixtureAnnotations has the fields of inspect.ToolAnnotations, with json
// tags. A type conversion ignores tags, so it turns one into the other.
type hashFixtureAnnotations struct {
	Title           string `json:"title"`
	ReadOnlyHint    *bool  `json:"readOnlyHint"`
	DestructiveHint *bool  `json:"destructiveHint"`
	IdempotentHint  *bool  `json:"idempotentHint"`
	OpenWorldHint   *bool  `json:"openWorldHint"`
}

// loadHashFixtures reads the tools in testdata/pins/hash/tools.json, in file
// order. Each fixture name must be unique.
func loadHashFixtures(t testing.TB) []hashFixture {
	t.Helper()
	data, err := os.ReadFile(hashFixturesPath)
	if err != nil {
		t.Fatalf("read hash fixtures: %v", err)
	}
	var entries []hashFixtureFile
	// Reject unknown keys, so a typo in the file does not silently drop a field.
	if err := json.Unmarshal(data, &entries, json.RejectUnknownMembers(true)); err != nil {
		t.Fatalf("decode %s: %v", hashFixturesPath, err)
	}
	fixtures := make([]hashFixture, 0, len(entries))
	seen := map[string]bool{}
	for _, e := range entries {
		if seen[e.Fixture] {
			t.Fatalf("%s: fixture %q appears more than once", hashFixturesPath, e.Fixture)
		}
		seen[e.Fixture] = true
		tool := inspect.Tool{
			Name:         e.Tool.Name,
			Title:        e.Tool.Title,
			Description:  e.Tool.Description,
			InputSchema:  []byte(e.Tool.InputSchema),
			OutputSchema: []byte(e.Tool.OutputSchema),
		}
		if e.Tool.Annotations != nil {
			ann := inspect.ToolAnnotations(*e.Tool.Annotations)
			tool.Annotations = &ann
		}
		fixtures = append(fixtures, hashFixture{Name: e.Fixture, Tool: tool})
	}
	if len(fixtures) == 0 {
		t.Fatalf("%s holds no fixtures", hashFixturesPath)
	}
	return fixtures
}

// TestHashGolden compares the canonical form and the hash of every fixture
// with testdata/pins/hash/golden.txt. Each line is
// "fixture<TAB>hash<TAB>quoted canonical form", with the canonical form quoted
// by strconv.QuoteToASCII so that invisible characters stay visible.
//
// A change in golden.txt means that the hash algorithm changed: every stored
// pin then gets a different hash. That needs a new HashVersion (see hash.go).
// Review the diff of golden.txt with care before you accept it with -update.
func TestHashGolden(t *testing.T) {
	t.Parallel()
	var got bytes.Buffer
	for _, f := range loadHashFixtures(t) {
		canon, err := Canonical(f.Tool)
		if err != nil {
			t.Fatalf("Canonical(%s): %v", f.Name, err)
		}
		h, err := Hash(f.Tool)
		if err != nil {
			t.Fatalf("Hash(%s): %v", f.Name, err)
		}
		got.WriteString(f.Name + "\t" + h + "\t" + strconv.QuoteToASCII(string(canon)) + "\n")
	}

	if *update {
		if err := os.WriteFile(hashGoldenPath, got.Bytes(), 0o644); err != nil { //nolint:gosec // G306: golden.txt is a checked-in fixture, not a secret
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(hashGoldenPath)
	if err != nil {
		t.Fatalf("read golden (run the test with -update to create it): %v", err)
	}
	for i, b := range want {
		if b >= 0x80 {
			t.Fatalf("%s: non-ASCII byte 0x%02x at offset %d; the file must be ASCII only", hashGoldenPath, b, i)
		}
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("hashes differ from %s. A change needs a new HashVersion; run the test with -update and review the diff\n--- got ---\n%s\n--- want ---\n%s",
			hashGoldenPath, got.Bytes(), want)
	}
}
