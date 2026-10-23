package rules

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode"
)

// textAdapterDetail is the fixed Hit.Detail of each text adapter.
var textAdapterDetail = map[string]string{
	HeuristicInsecureURL:     "insecure_url matched",
	HeuristicPlaintextSecret: "plaintext_secret matched",
	HeuristicUnpinnedPackage: "unpinned_package matched",
	HeuristicAutoInstall:     "auto_install matched",
	HeuristicTyposquat:       "typosquat matched",
}

// TestTextAdapters runs each text adapter, compiled by compileHeuristic, on
// the text grammar: spaces, tabs, blank lines and the two forms of
// plaintext_secret. A hit must be one Hit with NoOffset and the fixed Detail.
func TestTextAdapters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		heuristic string
		input     string
		wantHit   bool
	}{
		// insecure_url: the text is one URL.
		{name: "insecure_url http", heuristic: HeuristicInsecureURL, input: "http://mcp.example.com/sse", wantHit: true},
		{name: "insecure_url spaces around", heuristic: HeuristicInsecureURL, input: "  http://mcp.example.com/sse  ", wantHit: true},
		{name: "insecure_url tabs around", heuristic: HeuristicInsecureURL, input: "\thttp://mcp.example.com/sse\t", wantHit: true},
		{name: "insecure_url https", heuristic: HeuristicInsecureURL, input: "https://mcp.example.com/sse"},
		{name: "insecure_url loopback", heuristic: HeuristicInsecureURL, input: "http://localhost:8080/sse"},
		{name: "insecure_url empty", heuristic: HeuristicInsecureURL, input: ""},
		{name: "insecure_url spaces only", heuristic: HeuristicInsecureURL, input: "   "},

		// plaintext_secret: env form "KEY=VALUE" and header form "Name: value".
		{name: "env token prefix", heuristic: HeuristicPlaintextSecret, input: "GITHUB_TOKEN=" + testGHToken, wantHit: true},
		{name: "env value with base64 padding", heuristic: HeuristicPlaintextSecret, input: "CLIENT_SECRET=ZmFrZS1jYW5hcnktRVhBTVBMRS1zZWNyZXQteA==", wantHit: true},
		{name: "env empty value", heuristic: HeuristicPlaintextSecret, input: "GITHUB_TOKEN="},
		{name: "env non-secret name", heuristic: HeuristicPlaintextSecret, input: "LOG_LEVEL=debug"},
		{name: "header with space", heuristic: HeuristicPlaintextSecret, input: "Authorization: Bearer " + testGHToken, wantHit: true},
		{name: "header no space after colon", heuristic: HeuristicPlaintextSecret, input: "Authorization:Bearer " + testGHToken, wantHit: true},
		{name: "header name with underscore", heuristic: HeuristicPlaintextSecret, input: "X_Auth: Bearer " + testGHToken, wantHit: true},
		{name: "URL is not a header", heuristic: HeuristicPlaintextSecret, input: "https://mcp.example.com/" + testGHToken},
		{name: "empty key", heuristic: HeuristicPlaintextSecret, input: "=value"},
		{name: "no equals and no colon", heuristic: HeuristicPlaintextSecret, input: "just some text"},
		{name: "plaintext empty line", heuristic: HeuristicPlaintextSecret, input: ""},
		{name: "plaintext spaces only", heuristic: HeuristicPlaintextSecret, input: "  \t "},

		// unpinned_package: the text is a command line, split at white space.
		{name: "unpinned no version", heuristic: HeuristicUnpinnedPackage, input: "npx @modelcontextprotocol/server-filesystem", wantHit: true},
		{name: "unpinned tabs as separators", heuristic: HeuristicUnpinnedPackage, input: "npx\t@modelcontextprotocol/server-filesystem", wantHit: true},
		{name: "unpinned spaces around", heuristic: HeuristicUnpinnedPackage, input: "  npx @scope/server  ", wantHit: true},
		{name: "unpinned pinned version", heuristic: HeuristicUnpinnedPackage, input: "npx @modelcontextprotocol/server-filesystem@1.2.3"},
		{name: "unpinned empty", heuristic: HeuristicUnpinnedPackage, input: ""},
		{name: "unpinned whitespace only", heuristic: HeuristicUnpinnedPackage, input: " \t "},

		// auto_install: npx with -y or --yes before the package.
		{name: "auto_install -y", heuristic: HeuristicAutoInstall, input: "npx -y @modelcontextprotocol/server-filesystem", wantHit: true},
		{name: "auto_install --yes", heuristic: HeuristicAutoInstall, input: "npx --yes @modelcontextprotocol/server-filesystem", wantHit: true},
		{name: "auto_install tabs as separators", heuristic: HeuristicAutoInstall, input: "npx\t-y\t@modelcontextprotocol/server-filesystem", wantHit: true},
		{name: "auto_install no flag", heuristic: HeuristicAutoInstall, input: "npx @modelcontextprotocol/server-filesystem"},
		{name: "auto_install flag after package", heuristic: HeuristicAutoInstall, input: "npx @modelcontextprotocol/server-filesystem -y"},
		{name: "auto_install empty", heuristic: HeuristicAutoInstall, input: ""},
		{name: "auto_install whitespace only", heuristic: HeuristicAutoInstall, input: "\t\t"},

		// typosquat: a bare package name, or a command line.
		{name: "typosquat bare name", heuristic: HeuristicTyposquat, input: "@modelcontextprotocol/server-filesytem", wantHit: true},
		{name: "typosquat command line", heuristic: HeuristicTyposquat, input: "npx -y @modelcontextprotocol/server-filesytem", wantHit: true},
		{name: "typosquat tabs as separators", heuristic: HeuristicTyposquat, input: "npx\t@modelcontextprotocol/server-filesytem", wantHit: true},
		{name: "typosquat exact popular bare name", heuristic: HeuristicTyposquat, input: "@modelcontextprotocol/server-filesystem"},
		{name: "typosquat exact popular command line", heuristic: HeuristicTyposquat, input: "npx @modelcontextprotocol/server-filesystem"},
		{name: "typosquat unrelated name", heuristic: HeuristicTyposquat, input: "@acme/zq-internal-tool"},
		{name: "typosquat empty", heuristic: HeuristicTyposquat, input: ""},
		{name: "typosquat whitespace only", heuristic: HeuristicTyposquat, input: " \t "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fn, err := compileHeuristic(tt.heuristic, nil)
			if err != nil {
				t.Fatalf("compileHeuristic(%q) error = %v", tt.heuristic, err)
			}
			hits := fn(tt.input)
			if !tt.wantHit {
				if len(hits) != 0 {
					t.Errorf("hits = %+v, want none", hits)
				}
				return
			}
			if len(hits) != 1 {
				t.Fatalf("got %d hits, want exactly 1: %+v", len(hits), hits)
			}
			if hits[0].Offset != NoOffset {
				t.Errorf("Offset = %d, want NoOffset (%d)", hits[0].Offset, NoOffset)
			}
			if want := textAdapterDetail[tt.heuristic]; hits[0].Detail != want {
				t.Errorf("Detail = %q, want %q", hits[0].Detail, want)
			}
		})
	}
}

// TestTextAdaptersNoLeak checks that no Hit.Detail holds the canary or a word
// of the input line. Each input holds the canary, so each one must hit: a
// missing hit would make the check pass for the wrong reason.
func TestTextAdaptersNoLeak(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		heuristic string
		input     string
	}{
		{name: "plaintext env", heuristic: HeuristicPlaintextSecret, input: "GITHUB_TOKEN=" + testGHToken},
		{name: "plaintext header with space", heuristic: HeuristicPlaintextSecret, input: "Authorization: Bearer " + testGHToken},
		{name: "plaintext header no space", heuristic: HeuristicPlaintextSecret, input: "Authorization:Bearer " + testGHToken},
		{name: "insecure_url with token in user info", heuristic: HeuristicInsecureURL, input: "http://" + testGHToken + "@mcp.example.com/sse"},
		{name: "unpinned with canary arg", heuristic: HeuristicUnpinnedPackage, input: "npx -y @scope/server " + testGHToken},
		{name: "auto_install with canary arg", heuristic: HeuristicAutoInstall, input: "npx -y @scope/server " + testGHToken},
		{name: "typosquat command line with canary arg", heuristic: HeuristicTyposquat, input: "npx -y @modelcontextprotocol/server-filesytem " + testGHToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fn, err := compileHeuristic(tt.heuristic, nil)
			if err != nil {
				t.Fatalf("compileHeuristic(%q) error = %v", tt.heuristic, err)
			}
			hits := fn(tt.input)
			if len(hits) != 1 {
				t.Fatalf("got %d hits, want exactly 1 (the leak check needs a hit): %+v", len(hits), hits)
			}
			detail := hits[0].Detail
			if strings.Contains(detail, testGHToken) {
				t.Errorf("Detail %q contains the canary", detail)
			}
			// Every word of the input, split at non-letters and non-digits.
			words := strings.FieldsFunc(tt.input, func(r rune) bool {
				return !unicode.IsLetter(r) && !unicode.IsDigit(r)
			})
			for _, w := range words {
				if len(w) >= 4 && strings.Contains(detail, w) {
					t.Errorf("Detail %q contains input word %q", detail, w)
				}
			}
		})
	}
}

// TestCompileHeuristicConfigParams checks that each config heuristic rejects
// parameters. It returns a *FieldError that names the params field.
func TestCompileHeuristicConfigParams(t *testing.T) {
	t.Parallel()
	names := []string{
		HeuristicInsecureURL,
		HeuristicPlaintextSecret,
		HeuristicUnpinnedPackage,
		HeuristicAutoInstall,
		HeuristicTyposquat,
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := compileHeuristic(name, map[string]any{"x": 1})
			if err == nil {
				t.Fatalf("compileHeuristic(%q, params) error = nil, want error", name)
			}
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("error = %T %v, want *FieldError", err, err)
			}
			if fe.Field != "params" {
				t.Errorf("Field = %q, want %q", fe.Field, "params")
			}
		})
	}
}

// TestHeuristicNames checks that heuristicNames, the list in the unknown
// heuristic error, is sorted and that each name in it compiles.
func TestHeuristicNames(t *testing.T) {
	t.Parallel()
	names := strings.Split(heuristicNames, ", ")
	if !slices.IsSorted(names) {
		t.Errorf("heuristicNames = %q, want sorted", heuristicNames)
	}
	for _, name := range names {
		if _, err := compileHeuristic(name, nil); err != nil {
			t.Errorf("compileHeuristic(%q, nil) error = %v, want nil", name, err)
		}
	}
	// Every heuristic must be in the list.
	all := []string{HeuristicInvisibleUnicode, HeuristicMaxLength, HeuristicBase64Blob, HeuristicTyposquat}
	for name := range configTextChecks {
		all = append(all, name)
	}
	for _, name := range all {
		if !slices.Contains(names, name) {
			t.Errorf("heuristicNames = %q, want it to hold %q", heuristicNames, name)
		}
	}
}
