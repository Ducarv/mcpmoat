package report_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/report/reporttest"
)

// TestSchemaMatchesGoTypes is the guard for FR-15: the json tags of ScanReport
// and its nested types must match the schema file. Changing a field name
// without a new schema_version and a new schema file fails here.
func TestSchemaMatchesGoTypes(t *testing.T) {
	t.Parallel()

	var root map[string]any
	if err := json.Unmarshal(reporttest.SchemaBytes(t), &root); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	props := mapOf(root["properties"])
	if sv := mapOf(props["schema_version"]); !reflect.DeepEqual(sv["const"], float64(report.SchemaVersion)) {
		t.Errorf("schema_version in the schema is %v, want {const: %d}", props["schema_version"], report.SchemaVersion)
	}

	visited := map[string]bool{}
	checkSchemaObject(t, root, reflect.TypeFor[report.ScanReport](), root, visited)

	// Every definition must be used by some Go type. An orphan is a stale one.
	for name := range mapOf(root["$defs"]) {
		if !visited[name] {
			t.Errorf("$defs/%s is not used by any field of ScanReport", name)
		}
	}
}

// checkSchemaObject compares the json tags of struct type typ with the object
// schema s (a "$ref" is followed), then walks into its struct fields.
func checkSchemaObject(t *testing.T, root map[string]any, typ reflect.Type, s any, visited map[string]bool) {
	t.Helper()
	obj := deref(t, root, s, visited)
	if obj["additionalProperties"] != false {
		t.Errorf("schema of %s must set additionalProperties to false", typ.Name())
	}
	props := mapOf(obj["properties"])
	var wantNames, wantRequired []string // from the Go type
	for f := range typ.Fields() {
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			t.Fatalf("%s.%s has no json tag name", typ.Name(), f.Name)
		}
		wantNames = append(wantNames, name)
		if !slices.Contains(strings.Split(opts, ","), "omitempty") {
			wantRequired = append(wantRequired, name)
		}
	}
	var gotNames, gotRequired []string // from the schema
	for name := range props {
		gotNames = append(gotNames, name)
	}
	required, ok := obj["required"].([]any)
	if !ok {
		t.Fatalf("schema of %s has no required list", typ.Name())
	}
	for _, v := range required {
		name, ok := v.(string)
		if !ok {
			t.Fatalf("schema of %s has a required entry that is not a string: %v", typ.Name(), v)
		}
		gotRequired = append(gotRequired, name)
	}

	file := reporttest.SchemaName()
	const bumpHint = "Adding, renaming, removing or changing a field needs a schema_version bump and a new schema file."
	if d := setDiff(wantNames, gotNames); d != "" {
		t.Errorf("field set of %s differs from %s: %s. %s", typ.Name(), file, d, bumpHint)
	}
	if d := setDiff(wantRequired, gotRequired); d != "" {
		t.Errorf("required fields of %s differ from %s: %s. %s", typ.Name(), file, d, bumpHint)
	}

	// Walk into nested structs and slices of structs.
	for f := range typ.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		sub, ok := props[name].(map[string]any)
		if !ok {
			continue // already reported above
		}
		ft := f.Type
		if ft.Kind() == reflect.Slice {
			ft, sub = ft.Elem(), mapOf(sub["items"])
		}
		if ft.Kind() == reflect.Struct {
			checkSchemaObject(t, root, ft, sub, visited)
		}
	}
}

// mapOf returns v as a JSON object, or nil when it is not one.
func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// deref follows a "$ref" to "#/$defs/<name>" and records the name as visited.
func deref(t *testing.T, root map[string]any, s any, visited map[string]bool) map[string]any {
	t.Helper()
	m, _ := s.(map[string]any)
	ref, ok := m["$ref"].(string)
	if !ok {
		return m
	}
	name, found := strings.CutPrefix(ref, "#/$defs/")
	if !found {
		t.Fatalf("unsupported $ref %q", ref)
	}
	visited[name] = true
	def := mapOf(mapOf(root["$defs"])[name])
	if def == nil {
		t.Fatalf("$ref %q has no definition", ref)
	}
	return def
}

// setDiff describes how the sets want and got differ. It is "" when equal.
func setDiff(want, got []string) string {
	var parts []string
	for _, w := range want {
		if !slices.Contains(got, w) {
			parts = append(parts, fmt.Sprintf("%q is in the Go type but not in the schema", w))
		}
	}
	for _, g := range got {
		if !slices.Contains(want, g) {
			parts = append(parts, fmt.Sprintf("%q is in the schema but not in the Go type", g))
		}
	}
	slices.Sort(parts)
	return strings.Join(parts, "; ")
}

// richReport covers every inspection status, every diff kind, a truncated
// diff, a diff note, a file error, findings, stdio and http servers, and both scopes.
func richReport() report.ScanReport {
	stdio := func(name string, scope discover.Scope, state discover.State, status report.InspectionStatus) report.JSONServer {
		s := discover.Server{
			Name: name, Client: discover.ClientClaudeCode, Scope: scope, State: state,
			Source: "/home/u/.claude.json", Transport: discover.TransportStdio,
			Command: "npx", Args: discover.NewArgs([]string{"-y", "pkg", "--token", "tok-123"}),
		}
		if scope == discover.ScopeProject {
			s.ProjectPath, s.Untrusted = "/work/proj", true
			s.Source = "/work/proj/.mcp.json"
		}
		return report.NewJSONServer(s, status)
	}
	remote := func(name string, tr discover.Transport, status report.InspectionStatus) report.JSONServer {
		return report.NewJSONServer(discover.Server{
			Name: name, Client: discover.ClientCursor, Scope: discover.ScopeGlobal,
			Source: "/home/u/.cursor/mcp.json", Transport: tr,
			URL: discover.NewURL("https://user:pw@example.com/mcp?token=abc"),
		}, status)
	}
	return report.ScanReport{
		SchemaVersion: report.SchemaVersion,
		Tool:          report.ToolInfo{Name: "mcpmoat", Version: "1.2.3"},
		Mode:          report.ModeConnect,
		Complete:      true,
		Servers: []report.JSONServer{
			stdio("a", discover.ScopeGlobal, discover.StateEnabled, report.InspectionOK),
			stdio("b", discover.ScopeProject, discover.StateUnapproved, report.InspectionRefused),
			stdio("c", discover.ScopeProject, discover.StateProjectApproved, report.InspectionTimeout),
			stdio("d", discover.ScopeGlobal, discover.StateDisabled, report.InspectionFailed),
			remote("e", discover.TransportHTTP, report.InspectionNotRun),
			remote("f", discover.TransportSSE, report.InspectionOK),
		},
		Findings: []report.JSONFinding{
			report.NewJSONFinding(report.FindingRow{RuleID: "MOAT-T2-004", Severity: "high", Server: "a", Field: "env", Key: "API_KEY"}),
			report.NewJSONFinding(report.FindingRow{RuleID: "MOAT-T4-001", Severity: "medium", Server: "b", Related: "a"}),
			report.NewJSONFinding(report.FindingRow{RuleID: "X", Severity: "custom-severity"}),
		},
		Diffs: []report.JSONDiff{
			report.NewJSONDiff(report.ToolDiff{Server: "a", Tool: "t1", Kind: report.DiffChanged, Diff: "--- a\n+++ b\n@@\n-x\n+y\n"}),
			report.NewJSONDiff(report.ToolDiff{Server: "a", Tool: "t2", Kind: report.DiffNew, Diff: "+x\n"}),
			report.NewJSONDiff(report.ToolDiff{Server: "a", Tool: "t3", Kind: report.DiffUnverified, Diff: "+x\n", Truncated: true}),
			report.NewJSONDiff(report.ToolDiff{Server: "a", Tool: "t4", Kind: report.DiffChanged, Diff: "a fixed note", IsNote: true}),
		},
		Errors: []report.JSONFileError{
			report.NewJSONFileError(&discover.FileError{Path: "/p/mcp.json", ProjectPath: "/p", Server: "s", Line: 3, Col: 9, Reason: "invalid JSON", Untrusted: true}),
			report.NewJSONFileError(&discover.FileError{Path: "/q/mcp.json", Reason: "cannot read file"}),
		},
	}
}

// decodeAny unmarshals JSON into the generic form that the validator expects.
func decodeAny(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, b)
	}
	return v
}

func TestWriteJSONValidatesAgainstSchema(t *testing.T) {
	t.Parallel()
	rs := reporttest.Schema(t)

	empty := report.ScanReport{
		SchemaVersion: report.SchemaVersion,
		Tool:          report.ToolInfo{Name: "mcpmoat", Version: "dev"},
		Mode:          report.ModeNoConnect,
	}
	tests := []struct {
		name string
		r    report.ScanReport
	}{
		{"rich report", richReport()},
		{"empty report", empty},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := writeJSON(t, tt.r)
			if err := rs.Validate(decodeAny(t, out)); err != nil {
				t.Errorf("output does not match the schema: %v\n%s", err, out)
			}
		})
	}
}

func TestSchemaRejectsBadDocuments(t *testing.T) {
	t.Parallel()
	rs := reporttest.Schema(t)
	valid := writeJSON(t, richReport())

	// first returns the first element of the list at doc[key].
	first := func(doc map[string]any, key string) map[string]any {
		return doc[key].([]any)[0].(map[string]any)
	}
	tests := []struct {
		name   string
		mutate func(doc map[string]any)
	}{
		{"unknown top-level field", func(d map[string]any) { d["extra"] = 1 }},
		{"unknown server field", func(d map[string]any) { first(d, "servers")["env"] = map[string]any{} }},
		{"missing required field", func(d map[string]any) { delete(d, "mode") }},
		{"missing nested required field", func(d map[string]any) { delete(first(d, "diffs"), "diff_truncated") }},
		{"schema_version 2", func(d map[string]any) { d["schema_version"] = 2 }},
		{"unknown diff kind", func(d map[string]any) { first(d, "diffs")["kind"] = "renamed" }},
		{"diff kind unknown is not allowed", func(d map[string]any) { first(d, "diffs")["kind"] = "unknown" }},
		{"state unknown is not allowed", func(d map[string]any) { first(d, "servers")["state"] = "unknown" }},
		{"missing complete", func(d map[string]any) { delete(d, "complete") }},
		{"missing diff_is_note", func(d map[string]any) { delete(first(d, "diffs"), "diff_is_note") }},
		{"unknown inspection status", func(d map[string]any) {
			first(d, "servers")["inspection"].(map[string]any)["status"] = "skipped"
		}},
		{"unknown mode", func(d map[string]any) { d["mode"] = "offline" }},
		{"null list", func(d map[string]any) { d["findings"] = nil }},
		{"negative line", func(d map[string]any) { first(d, "errors")["line"] = -1 }},
		{"fractional line", func(d map[string]any) { first(d, "errors")["line"] = 1.5 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			doc := decodeAny(t, valid).(map[string]any)
			tt.mutate(doc)
			if err := rs.Validate(doc); err == nil {
				t.Errorf("Validate() = nil, want an error for %s", tt.name)
			}
		})
	}

	// Control: the unmutated document is valid, so the cases above fail for
	// their own reason.
	if err := rs.Validate(decodeAny(t, valid)); err != nil {
		t.Fatalf("control document is invalid: %v", err)
	}
}
