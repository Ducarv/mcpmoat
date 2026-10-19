package inspecttest_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

// TestBenignResultIsNewEachCall checks that a change to one returned value,
// also to nested slices and annotation hints, does not reach the next call.
func TestBenignResultIsNewEachCall(t *testing.T) {
	t.Parallel()
	want := inspecttest.BenignResult()

	got := inspecttest.BenignResult()
	got.Tools[0].Name = "changed"
	got.Tools[0].InputSchema[0] = 'X'
	*got.Tools[0].Annotations.ReadOnlyHint = false
	*got.Tools[1].Annotations.IdempotentHint = false
	*got.Tools[1].Annotations.OpenWorldHint = true
	got.Tools[0].Annotations.Title = "changed"
	got.Prompts[0].Arguments[0].Name = "changed"
	got.Resources[0].URI = "changed"
	got.ResourceTemplates[0].URITemplate = "changed"

	again := inspecttest.BenignResult()
	if !reflect.DeepEqual(again, want) {
		t.Errorf("BenignResult() after a change to an earlier result = %+v, want %+v", again, want)
	}

	// DeepEqual alone does not find a shared pointer: a change through it
	// would change want too. So check the hint values against constants.
	checkHint(t, "add ReadOnlyHint", again.Tools[0].Annotations.ReadOnlyHint, new(true))
	checkHint(t, "echo IdempotentHint", again.Tools[1].Annotations.IdempotentHint, new(true))
	checkHint(t, "echo OpenWorldHint", again.Tools[1].Annotations.OpenWorldHint, new(false))
	if got := again.Tools[0].Annotations.Title; got != "" {
		t.Errorf("add annotation Title = %q, want empty", got)
	}
	if got, wantURI := again.ResourceTemplates[0].URITemplate, "mcpmoat://benign/notes/{name}"; got != wantURI {
		t.Errorf("ResourceTemplates[0].URITemplate = %q, want %q", got, wantURI)
	}
}

// TestBenignResultSharesNoPointers checks that two calls share no annotation
// pointer, so no caller can change a hint of another result. It also checks
// that the two tools do not share a pointer inside one result.
func TestBenignResultSharesNoPointers(t *testing.T) {
	t.Parallel()
	a := inspecttest.BenignResult()
	b := inspecttest.BenignResult()

	seen := map[*bool]string{}
	for _, r := range []struct {
		name   string
		result inspect.Result
	}{{"first", a}, {"second", b}} {
		for _, tool := range r.result.Tools {
			if tool.Annotations == nil {
				t.Fatalf("%s result: tool %q has nil Annotations", r.name, tool.Name)
			}
			hints := []struct {
				name string
				p    *bool
			}{
				{"ReadOnlyHint", tool.Annotations.ReadOnlyHint},
				{"DestructiveHint", tool.Annotations.DestructiveHint},
				{"IdempotentHint", tool.Annotations.IdempotentHint},
				{"OpenWorldHint", tool.Annotations.OpenWorldHint},
			}
			for _, h := range hints {
				if h.p == nil {
					continue
				}
				where := r.name + " " + tool.Name + "." + h.name
				if other, ok := seen[h.p]; ok {
					t.Errorf("%s shares its pointer with %s", where, other)
				}
				seen[h.p] = where
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no annotation hint pointers found, want some")
	}
	if &a.ResourceTemplates[0] == &b.ResourceTemplates[0] {
		t.Error("the two results share the ResourceTemplates backing array")
	}
}

// TestBenignResultAnnotations checks the annotation values that the
// inspector reads from the benign server for "add" and "echo".
func TestBenignResultAnnotations(t *testing.T) {
	t.Parallel()
	for _, tool := range inspecttest.BenignResult().Tools {
		t.Run(tool.Name, func(t *testing.T) {
			t.Parallel()
			ann := tool.Annotations
			if ann == nil {
				t.Fatal("Annotations = nil, want non-nil")
			}
			if ann.Title != "" {
				t.Errorf("Title = %q, want empty", ann.Title)
			}
			checkHint(t, "ReadOnlyHint", ann.ReadOnlyHint, new(true))
			checkHint(t, "DestructiveHint", ann.DestructiveHint, nil)
			checkHint(t, "IdempotentHint", ann.IdempotentHint, new(true))
			checkHint(t, "OpenWorldHint", ann.OpenWorldHint, new(false))
		})
	}
}

// checkHint reports an error when got and want differ: one nil and one not,
// or two different values.
func checkHint(t *testing.T, name string, got, want *bool) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil:
		t.Errorf("%s = nil, want %t", name, *want)
	case want == nil:
		t.Errorf("%s = %t, want nil", name, *got)
	case *got != *want:
		t.Errorf("%s = %t, want %t", name, *got, *want)
	}
}

// TestBenignResultSchemasAreCanonical checks that each input schema is valid
// JSON in the form that the inspector makes: encoding/json output of the
// decoded schema, with sorted keys, no spaces and no HTML escaping.
func TestBenignResultSchemasAreCanonical(t *testing.T) {
	t.Parallel()
	for _, tool := range inspecttest.BenignResult().Tools {
		t.Run(tool.Name, func(t *testing.T) {
			t.Parallel()
			var v any
			if err := json.Unmarshal(tool.InputSchema, &v); err != nil {
				t.Fatalf("InputSchema is not valid JSON: %v", err)
			}
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(v); err != nil {
				t.Fatalf("encode schema: %v", err)
			}
			want := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
			if !bytes.Equal(tool.InputSchema, want) {
				t.Errorf("InputSchema =\n%s\nwant the canonical form\n%s", tool.InputSchema, want)
			}
			if tool.OutputSchema != nil {
				t.Errorf("OutputSchema = %s, want nil", tool.OutputSchema)
			}
		})
	}
}
