package main

import (
	"path"
	"strings"
	"testing"
	"testing/fstest"
)

// The helpers below build and change the repositories of the table-driven
// tests of the GoReleaser and govulncheck rules. A mutation changes a copy of a
// good repository (see grGoodRepo and goodGovulncheckSet).

// parseWorkflows parses every .yml file directly in .github/workflows of fsys.
func parseWorkflows(t *testing.T, fsys fstest.MapFS) map[string]*workflow {
	t.Helper()
	wfs := make(map[string]*workflow)
	for p, f := range fsys {
		if path.Dir(p) == workflowDir && isWorkflowName(p) {
			wfs[p] = mustParse(t, p, string(f.Data))
		}
	}
	return wfs
}

// mutation changes the repository of one case.
type mutation func(t *testing.T, fsys fstest.MapFS)

// replaceOnce replaces old with repl in the file p. old must occur exactly once,
// so that the case changes exactly the place it names.
func replaceOnce(p, old, repl string) mutation {
	return func(t *testing.T, fsys fstest.MapFS) {
		t.Helper()
		data := string(fsys[p].Data)
		if n := strings.Count(data, old); n != 1 {
			t.Fatalf("%s has %d copies of %q, want 1", p, n, old)
		}
		fsys[p] = &fstest.MapFile{Data: []byte(strings.Replace(data, old, repl, 1))}
	}
}

// setFile adds the file p, or replaces it.
func setFile(p string, f *fstest.MapFile) mutation {
	return func(_ *testing.T, fsys fstest.MapFS) { fsys[p] = f }
}

// deleteFile removes the file p.
func deleteFile(p string) mutation {
	return func(_ *testing.T, fsys fstest.MapFS) { delete(fsys, p) }
}

// applyAll applies the mutations in order. Use it for one change that touches
// two places, such as a move.
func applyAll(ms ...mutation) mutation {
	return func(t *testing.T, fsys fstest.MapFS) {
		t.Helper()
		for _, m := range ms {
			m(t, fsys)
		}
	}
}
