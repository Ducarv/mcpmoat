package report

// This file is in package report, not report_test, because it calls the
// unexported boundReport and escapeUnsafeRunes. It proves that the streaming
// WriteJSON writes the same bytes as the old whole-document version.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// writeJSONReference is the old WriteJSON: it encodes the whole document into one
// buffer and escapes it in one pass. It needs memory of several times the output
// size, which is why WriteJSON now streams. It stays here as the reference that
// the output of WriteJSON must match byte for byte.
func writeJSONReference(r ScanReport) ([]byte, error) {
	if r.Servers == nil {
		r.Servers = []JSONServer{}
	}
	if r.Findings == nil {
		r.Findings = []JSONFinding{}
	}
	if r.Diffs == nil {
		r.Diffs = []JSONDiff{}
	}
	if r.Errors == nil {
		r.Errors = []JSONFileError{}
	}
	if r.Ignored.Rules == nil {
		r.Ignored.Rules = map[string]int{}
	}

	bounded, truncated := boundReport(r)
	bounded.FieldsTruncated = truncated || r.FieldsTruncated
	r = bounded

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, fmt.Errorf("encode scan report: %w", err)
	}
	return escapeUnsafeRunes(buf.Bytes()), nil
}

// streamRichReport has data in every list, nested optional fields (Argv, URL,
// Accept) and a filled Ignored.
func streamRichReport() ScanReport {
	return ScanReport{
		SchemaVersion: SchemaVersion,
		Tool:          ToolInfo{Name: "mcpmoat", Version: "v1.2.3"},
		Mode:          ModeConnect,
		Complete:      true,
		Servers: []JSONServer{
			{
				Name: "stdio-srv", Client: "claude-code", Scope: "project", ProjectPath: "/p",
				State: "enabled", Transport: "stdio", Source: "/p/.mcp.json",
				Argv:       []string{"npx", "-y", "pkg <a&b>"},
				Inspection: JSONInspection{Status: InspectionOK},
				Accept:     &JSONAccept{Digest: "sha256:abc", Command: "mcpmoat accept stdio-srv"},
			},
			{
				Name: "http-srv", Client: "cursor", Scope: "user", State: "enabled",
				Transport: "http", Source: "/h/mcp.json", URL: "https://example.com/mcp?a=1&b=2",
				Untrusted:  true,
				Inspection: JSONInspection{Status: InspectionTimeout},
				Accept:     &JSONAccept{Digest: "sha256:def"},
			},
			{
				Name: "plain", Client: "vscode", Scope: "user", State: "disabled",
				Transport: "stdio", Source: "/s", Inspection: JSONInspection{Status: InspectionNotRun},
			},
		},
		Findings: []JSONFinding{
			{RuleID: "MM001", Severity: "high", Server: "stdio-srv", Field: "description", Key: "t1", Related: "t2", Source: SourceRule},
			{RuleID: "MM900", Severity: "info", Server: "http-srv", Field: "name", Key: "t3", Source: SourceLLM},
		},
		Diffs: []JSONDiff{
			{Server: "stdio-srv", Tool: "t1", Kind: "changed", Diff: "-a\n+b <c>\n", Truncated: true},
			{Server: "stdio-srv", Tool: "t2", Kind: "new", Diff: "note", IsNote: true},
		},
		Errors: []JSONFileError{
			{Path: "/p/.mcp.json", ProjectPath: "/p", Server: "x", Line: 3, Col: 7, Reason: "invalid JSON", Untrusted: true},
		},
		Ignored: JSONIgnored{Total: 3, Rules: map[string]int{"MM002": 2, "MM001": 1}, FileEntries: 2},
	}
}

// TestWriteJSONMatchesReference checks that the streaming WriteJSON writes the
// same bytes as writeJSONReference.
func TestWriteJSONMatchesReference(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("n", jsonMaxNameRunes+10)
	longPath := strings.Repeat("p", jsonMaxPathRunes+10)

	unsafe := streamRichReport()
	unsafe.Servers[0].Name = "a\u2028b\u2029c"
	unsafe.Servers[0].Argv = []string{"x\x00y", "bell\a", "del\x7f", "bidi\u202eevil\u2066"}
	unsafe.Servers[1].Name = "bad\xffutf8\xc3"
	unsafe.Servers[1].URL = "https://e.com/\u200b\ufeff\u00ad"
	unsafe.Findings[0].Key = "emoji \U0001F600 tag \U000E0041 noncharacter \U0010FFFF"
	unsafe.Findings[1].Related = "esc\x1b[31mred\x1b[0m\r\n\ttab"
	unsafe.Diffs[0].Diff = "line\u2028two\u0085three\u00a0nbsp\u00e9ok"
	unsafe.Errors[0].Path = "/p/\u202e/x"

	cut := streamRichReport()
	cut.Servers[0].Name = long
	cut.Servers[0].Source = longPath
	cut.Servers[0].ProjectPath = longPath
	cut.Findings[0].Key = long
	cut.Findings[1].Related = long
	cut.Diffs[0].Tool = long
	cut.Errors[0].Path = longPath
	cut.Errors[0].Server = long

	accept := streamRichReport()
	accept.Servers[0].Accept = &JSONAccept{Digest: "sha256:" + strings.Repeat("0", 64), Command: "mcpmoat scan --accept 'a b'"}
	accept.Servers[1].Accept = &JSONAccept{Digest: "d"}
	accept.Servers[2].Accept = nil

	tests := []struct {
		name string
		r    ScanReport
	}{
		{"empty report", ScanReport{}},
		{"nil lists and nil rules map", ScanReport{SchemaVersion: SchemaVersion, Mode: ModeNoConnect, Complete: true}},
		{"empty non-nil lists", ScanReport{
			Servers: []JSONServer{}, Findings: []JSONFinding{}, Diffs: []JSONDiff{}, Errors: []JSONFileError{},
			Ignored: JSONIgnored{Rules: map[string]int{}},
		}},
		{"rich report", streamRichReport()},
		{"only one list filled", ScanReport{Findings: []JSONFinding{{RuleID: "MM001", Source: SourceRule}}}},
		{"caller set fields_truncated", ScanReport{FieldsTruncated: true}},
		{"unsafe runes", unsafe},
		{"long fields that are cut", cut},
		{"accept set", accept},
		{"hostile report", hostileReport(64<<10, 20)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			want, err := writeJSONReference(tt.r)
			if err != nil {
				t.Fatalf("writeJSONReference() error = %v, want nil", err)
			}
			var got bytes.Buffer
			if err := WriteJSON(&got, tt.r); err != nil {
				t.Fatalf("WriteJSON() error = %v, want nil", err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Errorf("WriteJSON() differs from the reference output\ngot  (%d bytes): %.300q\nwant (%d bytes): %.300q",
					got.Len(), got.Bytes(), len(want), want)
			}
		})
	}
}

// stopWriter accepts the first limit bytes of writes, then every Write fails
// with err.
type stopWriter struct {
	limit int
	n     int
	err   error
}

func (s *stopWriter) Write(p []byte) (int, error) {
	if s.n+len(p) > s.limit {
		return 0, s.err
	}
	s.n += len(p)
	return len(p), nil
}

// A write error from w must come back from WriteJSON, whether it happens in
// the first piece or in a later one, and the error must wrap the cause.
func TestWriteJSONStreamReturnsWriteError(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	r := hostileReport(64<<10, 200)
	for _, limit := range []int{0, 10, 100_000, 200_000} {
		t.Run(fmt.Sprintf("limit %d", limit), func(t *testing.T) {
			t.Parallel()
			err := WriteJSON(&stopWriter{limit: limit, err: boom}, r)
			if !errors.Is(err, boom) {
				t.Errorf("WriteJSON() error = %v, want it to wrap %v", err, boom)
			}
		})
	}
}
