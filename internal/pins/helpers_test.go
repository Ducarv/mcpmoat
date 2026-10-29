package pins

// This file holds the test helpers that more than one test file uses, except
// shuffleJSON, which stays in jsonshuffle_test.go next to its own test.

import (
	"bytes"
	"encoding/json/jsontext"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// lockName is the name of the pins lock file next to pins.json.
const lockName = "pins.json" + lockSuffix

// testSeed is the fixed seed of the test shuffles. Any value works; a fixed
// one makes a failure reproducible.
const testSeed = 1

// hashHints are the four hints of inspect.ToolAnnotations. falseIsNull marks
// the hints that the canonical form writes as null when they are false.
var hashHints = []struct {
	field       string
	ptr         func(*inspect.ToolAnnotations) **bool
	falseIsNull bool
}{
	{"readOnlyHint", func(a *inspect.ToolAnnotations) **bool { return &a.ReadOnlyHint }, true},
	{"destructiveHint", func(a *inspect.ToolAnnotations) **bool { return &a.DestructiveHint }, false},
	{"idempotentHint", func(a *inspect.ToolAnnotations) **bool { return &a.IdempotentHint }, true},
	{"openWorldHint", func(a *inspect.ToolAnnotations) **bool { return &a.OpenWorldHint }, false},
}

// cloneTool returns a copy of tool with its own annotations, so a change to
// the annotations of the copy cannot alter tool. The schemas are shared:
// replace them, never write into their bytes.
func cloneTool(tool inspect.Tool) inspect.Tool {
	c := tool
	if tool.Annotations != nil {
		ann := *tool.Annotations
		c.Annotations = &ann
	}
	return c
}

// ensureAnnotations returns the annotations of c, and first adds empty ones
// when c has none.
func ensureAnnotations(c *inspect.Tool) *inspect.ToolAnnotations {
	if c.Annotations == nil {
		c.Annotations = &inspect.ToolAnnotations{}
	}
	return c.Annotations
}

// mustCanonical returns Canonical(tool) and fails the test on an error.
func mustCanonical(t testing.TB, tool inspect.Tool) string {
	t.Helper()
	got, err := Canonical(tool)
	if err != nil {
		t.Fatalf("Canonical() error = %v, want nil", err)
	}
	return string(got)
}

// canonicalForm returns the RFC 8785 (JCS) form of v.
func canonicalForm(t testing.TB, v []byte) string {
	t.Helper()
	c := jsontext.Value(bytes.Clone(v))
	if err := c.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize(%q): %v", v, err)
	}
	return string(c)
}
