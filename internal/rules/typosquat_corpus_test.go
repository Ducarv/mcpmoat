package rules

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// corpusCase is one parsed line of the typosquat corpus.
type corpusCase struct {
	line     int
	hit      bool
	registry string
	name     string
	related  string
}

// corpusServer builds the server that the registry kind of a case describes.
func corpusServer(registry, name string) discover.Server {
	switch registry {
	case "npm":
		return npxServer("srv", name)
	case "pypi":
		return stdioServer("uvx", name)
	case "docker":
		return stdioServer("docker", "run", "-i", name)
	default: // "name": a server name with no package behind it
		return discover.Server{Name: name, Transport: discover.TransportStdio, Command: "true"}
	}
}

// parseCorpus reads the corpus file. A malformed line is an error that names
// its line number.
func parseCorpus(path string) ([]corpusCase, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a constant fixture path from the test
	if err != nil {
		return nil, err
	}

	var cases []corpusCase
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for n := 1; sc.Scan(); n++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) < 3 || len(fields) > 4 {
			return nil, fmt.Errorf("line %d: want 3 or 4 fields, got %d", n, len(fields))
		}
		c := corpusCase{line: n, registry: fields[1], name: fields[2]}
		switch fields[0] {
		case "hit":
			c.hit = true
		case "ok":
		default:
			return nil, fmt.Errorf("line %d: unknown expectation %q", n, fields[0])
		}
		switch c.registry {
		case "npm", "pypi", "docker", "name":
		default:
			return nil, fmt.Errorf("line %d: unknown registry %q", n, c.registry)
		}
		if len(fields) == 4 {
			c.related = fields[3]
		}
		if c.hit != (c.related != "") {
			return nil, fmt.Errorf("line %d: a hit needs a related name and an ok line must not have one", n)
		}
		cases = append(cases, c)
	}
	return cases, sc.Err()
}

// TestTyposquatCorpus runs the typosquat rule over testdata/typosquat/names.txt
// with the built-in popular list. The corpus holds real package names that
// must stay clean and made-up typos that must raise one finding. To add a
// case, add one line to that file. Its header explains the line format.
func TestTyposquatCorpus(t *testing.T) {
	t.Parallel()
	cases, err := parseCorpus("../../testdata/typosquat/names.txt")
	if err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	// A parser that skips every line would make the test pass for nothing.
	if len(cases) == 0 {
		t.Fatal("corpus has no cases")
	}
	ts := NewTyposquat(loadPopular(t))

	for _, c := range cases {
		t.Run(fmt.Sprintf("%03d_%s_%s", c.line, c.registry, c.name), func(t *testing.T) {
			t.Parallel()
			got := ts.Check(corpusServer(c.registry, c.name))
			if !c.hit {
				if len(got) != 0 {
					t.Errorf("%s %q: got %d findings (first related %q), want none", c.registry, c.name, len(got), got[0].Related)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("%s %q: got %d findings, want 1 with related %q", c.registry, c.name, len(got), c.related)
			}
			if got[0].Related != c.related {
				t.Errorf("%s %q: related = %q, want %q", c.registry, c.name, got[0].Related, c.related)
			}
		})
	}
}
