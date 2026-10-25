// Package reporttest has test helpers for the JSON report of internal/report:
// they load the JSON Schema of the current schema_version, and check that
// output holds no raw byte that can act on a terminal.
//
// Import this package only from _test.go files, so the testing package and
// the schema validator never reach the mcpmoat binary.
package reporttest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// SchemaName returns the repo-relative path of the schema file for
// report.SchemaVersion, for example "docs/schema/scan-output.v1.json".
func SchemaName() string {
	return fmt.Sprintf("docs/schema/scan-output.v%d.json", report.SchemaVersion)
}

// SchemaBytes returns the schema file for report.SchemaVersion. It finds the
// repo root from the working directory of the test (the directory that holds
// go.mod), so any package of the module can call it.
func SchemaBytes(t testing.TB) []byte {
	t.Helper()
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(SchemaName()))) //nolint:gosec // G304: a fixed schema file in the repo
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("schema_version is %d but %s does not exist; add the new schema file", report.SchemaVersion, SchemaName())
	}
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	return b
}

// Schema returns the schema for report.SchemaVersion, parsed and resolved, so
// a test can validate a document with it.
func Schema(t testing.TB) *jsonschema.Resolved {
	t.Helper()
	var s jsonschema.Schema
	if err := json.Unmarshal(SchemaBytes(t), &s); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	rs, err := s.Resolve(nil)
	if err != nil {
		t.Fatalf("resolve schema: %v", err)
	}
	return rs
}

// repoRoot returns the first directory, from the working directory up, that
// holds go.mod.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("find the repo root: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("find the repo root: no go.mod above the working directory")
		}
		dir = parent
	}
}

// UnsafeBytes describes each raw byte or rune of out that could act on a
// terminal: invalid UTF-8, a control byte other than newline, or a non-ASCII
// rune for which termsafe.NeedsEscape is true. It returns nil when out is
// safe. WriteJSON writes all of them as \uXXXX escapes.
func UnsafeBytes(out []byte) []string {
	var problems []string
	if !utf8.Valid(out) {
		problems = append(problems, "invalid UTF-8")
	}
	for i, r := range string(out) {
		switch {
		case r == '\n':
		case r < 0x20 || r == 0x7f:
			problems = append(problems, fmt.Sprintf("raw control character %U at offset %d", r, i))
		case r >= utf8.RuneSelf && termsafe.NeedsEscape(r):
			problems = append(problems, fmt.Sprintf("raw unsafe rune %U at offset %d", r, i))
		}
	}
	return problems
}

// AssertSafeBytes fails the test for each problem that UnsafeBytes finds in
// out.
func AssertSafeBytes(t testing.TB, out []byte) {
	t.Helper()
	for _, p := range UnsafeBytes(out) {
		t.Errorf("output holds %s", p)
	}
}
