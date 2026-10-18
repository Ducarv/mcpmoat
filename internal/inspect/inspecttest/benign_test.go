package inspecttest_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

// TestBenignResultIsNewEachCall checks that a change to one returned value,
// also to nested slices, does not reach the next call.
func TestBenignResultIsNewEachCall(t *testing.T) {
	t.Parallel()
	want := inspecttest.BenignResult()

	got := inspecttest.BenignResult()
	got.Tools[0].Name = "changed"
	got.Tools[0].InputSchema[0] = 'X'
	got.Prompts[0].Arguments[0].Name = "changed"
	got.Resources[0].URI = "changed"

	if again := inspecttest.BenignResult(); !reflect.DeepEqual(again, want) {
		t.Errorf("BenignResult() after a change to an earlier result = %+v, want %+v", again, want)
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
